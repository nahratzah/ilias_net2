/*
 * Copyright (c) 2012 Ariane van der Steldt <ariane@stack.nl>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <ilias/net2/workq_io.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/datapipe.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/promise.h>
#include <ilias/net2/sockdgram.h>
#include <assert.h>
#include <ev.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef EV_C
#include EV_C
#endif


/* Dgram tx/rx event. */
struct net2_workq_io {
	/* TX datapipe, accepts promise of net2_dgram_tx_promdata. */
	struct net2_datapipe_in	*tx;
	/* RX datapipe, generates net2_dgram_rx. */
	struct net2_datapipe_out*rx;
	/* Internal half of the TX datapipe. */
	struct net2_datapipe_out*tx_internal;
	/* Internal half of the RX datapipe. */
	struct net2_datapipe_in	*rx_internal;

	net2_socket_t		 socket;	/* IO socket. */
	struct net2_workq_evbase*wqev;		/* Event base. */

	ev_io			 rx_watcher;	/* RX IO watcher. */
	ev_io			 tx_watcher;	/* TX IO watcher. */

	struct net2_datapipe_event
				 rx_avail_ev,	/* Datapipe wakeup. */
				 tx_avail_ev;	/* Datapipe wakeup. */
};


/* Pointer magic. */
#define DGRAM_EVRX_OFFSET						\
	((size_t)(&((struct net2_workq_io*)0)->rx_watcher))
#define DGRAM_EVTX_OFFSET						\
	((size_t)(&((struct net2_workq_io*)0)->tx_watcher))
#define EVRX_2_DGRAM(_ev)						\
	((struct net2_workq_io*)((char*)(_ev) - DGRAM_EVRX_OFFSET))
#define EVTX_2_DGRAM(_ev)						\
	((struct net2_workq_io*)((char*)(_ev) - DGRAM_EVTX_OFFSET))

/* Max number of unprocessed input buffers. */
#define MAX_RX		128
/* Max number of outstanding tx promises. */
#define MAX_TX		128


static void	promfree(void*, void*);
static void	rxfree(void*, void*);
static void	enable_watcher(void*, void*);
static int	create_tx_pipe(struct net2_datapipe_in**,
		    struct net2_datapipe_out**, struct net2_workq_evbase*);
static int	create_rx_pipe(struct net2_datapipe_in**,
		    struct net2_datapipe_out**, struct net2_workq_evbase*);
static void	rx_evcb(struct ev_loop*, struct ev_io*, int);
static void	tx_evcb(struct ev_loop*, struct ev_io*, int);


/* Free promise (element destructor on datapipe). */
static void
promfree(void *prom_ptr, void *unused ILIAS_NET2__unused)
{
	net2_promise_release(prom_ptr);
}
/* Free rx data. */
static void
rxfree(void *rx_ptr, void *unused ILIAS_NET2__unused)
{
	struct net2_dgram_rx *rx = rx_ptr;

	if (rx != NULL) {
		net2_buffer_free(rx->data);
		net2_free(rx);
	}
}
/* Enable a lib-ev io watcher. */
static void
enable_watcher(void *wqev_ptr, void *watcher_ptr)
{
	struct net2_workq_evbase*wqev = wqev_ptr;
	ev_io			*watcher = watcher_ptr;
	struct ev_loop		*loop;

	loop = net2_workq_get_evloop(wqev);
	ev_io_start(loop, watcher);
	net2_workq_evbase_evloop_changed(wqev);
}
/*
 * Create the TX datapipe.
 * The TX datapipe consumes promises and will always keep a few of them ready.
 */
static int
create_tx_pipe(struct net2_datapipe_in **in, struct net2_datapipe_out **out,
    struct net2_workq_evbase *wqev)
{
	struct net2_datapipe_in *proc_in, *plain_in;
	struct net2_datapipe_out *proc_out, *plain_out;
	int			 error;

	if ((error = net2_dp_new(&plain_in, &plain_out, wqev, &promfree, NULL)) != 0)
		goto fail_0;
	if ((error = net2_dp_new(&proc_in, &proc_out, wqev, &promfree, NULL)) != 0)
		goto fail_1;
	if ((error = net2_datapipe_prom_glue(plain_out, proc_in, wqev)) != 0)
		goto fail_2;
	net2_dpout_set_maxlen(proc_out, MAX_TX);

	*in = plain_in;
	*out = proc_out;
	net2_dpout_release(plain_out);
	net2_dpin_release(proc_in);
	return 0;

fail_2:
	net2_dpin_release(proc_in);
	net2_dpout_release(proc_out);
fail_1:
	net2_dpin_release(plain_in);
	net2_dpout_release(plain_out);
fail_0:
	assert(error != 0);
	return error;
}
/*
 * Create the RX datapipe.
 * The RX datapipe is filled from the socket.
 */
static int
create_rx_pipe(struct net2_datapipe_in **in, struct net2_datapipe_out **out,
    struct net2_workq_evbase *wqev)
{
	int	 error;

	if ((error = net2_dp_new(in, out, wqev, &rxfree, NULL)) != 0)
		return error;
	net2_dpin_set_maxlen(*in, MAX_RX);
	return 0;
}

ILIAS_NET2_EXPORT struct net2_workq_io*
net2_workq_io_new(struct net2_workq *wq, net2_socket_t socket)
{
	struct net2_workq_io	*io;
	struct net2_workq_evbase*wqev;

	if (wq == NULL || socket == -1)
		return NULL;
	wqev = net2_workq_evbase(wq);
	assert(wqev != NULL);

	/* Create io object. */
	if ((io = net2_malloc(sizeof(*io))) == NULL)
		goto fail_0;

	/* Initialize socket and events. */
	io->wqev = wqev;
	net2_workq_evbase_ref(io->wqev);
	io->socket = socket;
	ev_io_init(&io->rx_watcher, &rx_evcb, socket, EV_READ);
	ev_io_init(&io->tx_watcher, &tx_evcb, socket, EV_WRITE);

	/* Create datapipes. */
	if (create_tx_pipe(&io->tx, &io->tx_internal, wqev) != 0)
		goto fail_1;
	if (create_rx_pipe(&io->rx_internal, &io->rx, wqev) != 0)
		goto fail_2;

	/* Initialize datapipe events.
	 * These events enable the watchers, which will ultimately pull/push
	 * data from/to the datapipe. */
	if (net2_datapipe_event_init_out(&io->tx_avail_ev, io->tx_internal,
	    NET2_DP_EVTYPE_AVAIL, wq,
	    &enable_watcher, wqev, &io->tx_watcher) != 0)
		goto fail_3;
	if (net2_datapipe_event_init_in(&io->rx_avail_ev, io->rx_internal,
	    NET2_DP_EVTYPE_AVAIL, wq,
	    &enable_watcher, wqev, &io->rx_watcher) != 0)
		goto fail_4;

	return io;


fail_5:
	net2_datapipe_event_deinit(&io->rx_avail_ev);
fail_4:
	net2_datapipe_event_deinit(&io->tx_avail_ev);
fail_3:
	net2_dpout_release(io->rx);
	net2_dpin_release(io->rx_internal);
fail_2:
	net2_dpout_release(io->tx_internal);
	net2_dpin_release(io->tx);
fail_1:
	net2_workq_evbase_release(io->wqev);
	net2_free(io);
fail_0:
	return NULL;
}
/* Destroy the IO handler. */
ILIAS_NET2_EXPORT void
net2_workq_io_destroy(struct net2_workq_io *io)
{
	struct ev_loop		*loop;

	/* Release events. */
	net2_datapipe_event_deinit(&io->rx_avail_ev);
	net2_datapipe_event_deinit(&io->tx_avail_ev);

	/* Release public side of queues. */
	net2_dpout_release(io->rx);
	io->rx = NULL;
	net2_dpin_release(io->tx);
	io->tx = NULL;

	/* Cancel watchers. */
	loop = net2_workq_get_evloop(io->wqev);
	ev_io_stop(loop, &io->rx_watcher);
	ev_io_stop(loop, &io->tx_watcher);
	net2_workq_evbase_evloop_changed(io->wqev);

	/* Release private side of queues. */
	net2_dpin_release(io->rx_internal);
	net2_dpout_release(io->tx_internal);

	/* Release wqev and free io. */
	net2_workq_evbase_release(io->wqev);
	net2_free(io);
}
/*
 * Activate the receive side.
 * New packets that arrive will be queued.
 */
ILIAS_NET2_EXPORT void
net2_workq_io_activate_rx(struct net2_workq_io *io)
{
	struct net2_workq_evbase*wqev;
	struct ev_loop		*loop;

	wqev = io->wqev;
	loop = net2_workq_get_evloop(wqev);

	ev_io_start(loop, &io->rx_watcher);
	net2_workq_evbase_evloop_changed(wqev);
}
/*
 * Deactivate the receive side.
 * No new packets will be queued on the receive side until the rx
 * is activated.
 */
ILIAS_NET2_EXPORT void
net2_workq_io_deactivate_rx(struct net2_workq_io *io)
{
	struct net2_workq_evbase*wqev;
	struct ev_loop		*loop;

	wqev = io->wqev;
	loop = net2_workq_get_evloop(wqev);

	ev_io_stop(loop, &io->rx_watcher);
	net2_workq_evbase_evloop_changed(wqev);
}
/* Place a promise of tx on the IO queue. */
ILIAS_NET2_EXPORT int
net2_workq_io_tx(struct net2_workq_io *io, struct net2_promise *p)
{
	int	 error;

	net2_promise_ref(p);
	if ((error = net2_dp_push(io->tx, p)) != 0)
		net2_promise_release(p);
	return error;
}
/* Free tx promise data. */
ILIAS_NET2_EXPORT void
net2_workq_io_tx_pdata_free(void *pd_ptr, void * ILIAS_NET2__unused unused)
{
	struct net2_dgram_tx_promdata
				*pd = pd_ptr;

	if (pd->data != NULL)
		net2_buffer_free(pd->data);
	if (pd->tx_done != NULL) {
		net2_promise_set_cancel(pd->tx_done, 0);
		net2_promise_release(pd->tx_done);
	}
	net2_free(pd);
}

/*
 * Return the TX datapipe.
 * Does not increment the reference counter.
 */
ILIAS_NET2_EXPORT struct net2_datapipe_in*
net2_workq_io_txpipe(struct net2_workq_io *io)
{
	return io->tx;
}
/*
 * Return the RX datapipe.
 * Does not increment the reference counter.
 */
ILIAS_NET2_EXPORT struct net2_datapipe_out*
net2_workq_io_rxpipe(struct net2_workq_io *io)
{
	return io->rx;
}

/* Callback for rx. */
static void
rx_evcb(struct ev_loop *loop ILIAS_NET2__unused, struct ev_io *ev,
    int revents ILIAS_NET2__unused)
{
	struct net2_workq_io	*dg = EVRX_2_DGRAM(ev);
	struct net2_dgram_rx	*dgrx;
	struct net2_datapipe_in_prepare prep;
	int			 rv;

	if (net2_dp_push_prepare(&prep, dg->rx_internal) != 0)
		return;
	if ((dgrx = net2_malloc(sizeof(*dgrx))) == NULL)
		goto fail;

	dgrx->data = NULL;
	dgrx->addrlen = sizeof(dgrx->addr);
	if (net2_sockdgram_recv(dg->socket, &dgrx->error, &dgrx->data,
	    (struct sockaddr*)&dgrx->data, &dgrx->addrlen) != 0)
		goto fail;
	if (dgrx->error == 0 && dgrx->data == NULL)
		goto fail;

	/* Put datagram on the queue. */
	rv = net2_dp_push_commit(&prep, dgrx);
	assert(rv == 0);
	return;


fail:
	if (dgrx != NULL)
		net2_free(dgrx);
	net2_dp_push_rollback(&prep);
}
/* Callback for tx. */
static void
tx_evcb(struct ev_loop *loop ILIAS_NET2__unused, struct ev_io *ev,
    int revents ILIAS_NET2__unused)
{
	struct net2_workq_io	*dg = EVTX_2_DGRAM(ev);
	struct net2_dgram_rx	*dgrx;
	int			 fin, send_err;
	struct net2_promise	*prom;
	struct net2_dgram_tx_promdata
				*pdata;
	struct sockaddr		*sa;

restart:
	/*
	 * Acquire prom to send.
	 * If none are available, stop the watcher.
	 * Slightly complicated because both are lockless.
	 */
	prom = net2_dp_pop(dg->tx_internal);
	if (prom == NULL) {
		ev_io_stop(loop, &dg->tx_watcher);
		prom = net2_dp_pop(dg->tx_internal);
		if (prom != NULL)
			ev_io_start(loop, &dg->tx_watcher);
		net2_workq_evbase_evloop_changed(dg->wqev);
		if (prom == NULL)
			return;
	}

	/*
	 * Test if the promise completed without error.
	 * Promises with errors are ignored.
	 */
	fin = net2_promise_get_result(prom, (void**)&pdata, NULL);
	assert(fin != NET2_PROM_FIN_UNFINISHED);
	if (fin != NET2_PROM_FIN_OK) {
		net2_promise_release(prom);
		goto restart;
	}

	/* Transmit datagram. */
	sa = (pdata->addrlen > 0 ? (struct sockaddr*)&pdata->addr : NULL);
	send_err = net2_sockdgram_send(dg->socket, pdata->data,
	    sa, pdata->addrlen);

	/*
	 * If completion notification is requested,
	 * inform via pdata->tx_done.
	 */
	if (pdata->tx_done != NULL) {
		assert(net2_promise_is_running(pdata->tx_done));
		if (send_err == 0) {
			net2_promise_set_finok(pdata->tx_done,
			    NULL, NULL, NULL, NET2_PROMFLAG_RELEASE);
		} else {
			net2_promise_set_error(pdata->tx_done, send_err,
			    NET2_PROMFLAG_RELEASE);
		}
		pdata->tx_done = NULL;
	}

	/* Destroy promise (and thus pdata). */
	net2_promise_release(prom);
}
