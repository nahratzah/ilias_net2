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
#include <ilias/net2/memory.h>
#include <ilias/net2/mutex.h>
#include <ilias/net2/promise.h>
#include <ilias/net2/sockdgram.h>
#include <assert.h>
#include <ev.h>
#include <errno.h>

#ifdef EV_C
#include EV_C
#endif

#ifdef WIN32
#include <WinSock2.h>
#include <ws2def.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#endif


/* rx workq job. */
struct dgram_rx {
	struct net2_workq_job	 impl;

	struct sockaddr_storage	 addr;
	socklen_t		 addrlen;

	int			 error;
	struct net2_buffer	*data;

	TAILQ_ENTRY(dgram_rx)	 q;
};

/* tx workq job. */
struct dgram_tx {
	struct net2_promise_event
				 tx_promdata_ready;
	struct net2_promise	*tx_promdata;

	TAILQ_ENTRY(dgram_tx)	 q;
};

/* Dgram tx/rx event. */
struct net2_workq_io {
	struct net2_workq_job	 ask_for_tx;	/* Ask for more send data. */

	net2_workq_io_recv	 rx_cb;		/* Receive callback. */
	net2_workq_io_send	 tx_cb;		/* Transmit callback. */
	void			*cb_arg;	/* Callback argument. */

	net2_socket_t		 socket;	/* IO socket. */
	struct net2_workq	*wq;		/* Workq. */

	ev_io			 rx_watcher;	/* RX IO watcher. */
	struct net2_mutex	*rx_guard;	/* Protect rx queues. */
	TAILQ_HEAD(, dgram_rx)	 rx_queue;	/* Outstanding requests. */
	TAILQ_HEAD(, dgram_rx)	 rx_spare;	/* Unused/avail. */

	ev_io			 tx_watcher;	/* TX IO watcher. */
	struct net2_mutex	*tx_guard;	/* Protect tx queues. */
	TAILQ_HEAD(, dgram_tx)	 tx_queue;	/* Outstanding requests. */
	TAILQ_HEAD(, dgram_tx)	 tx_rts;	/* Ready to send. */
	TAILQ_HEAD(, dgram_tx)	 tx_spare;	/* Unused/avail. */

	struct net2_mutex	*fguard;	/* Protect flags. */
	int			 flags;		/* Flags. */
#define IO_FLAG_RX		0x00000001	/* RX active. */
#define IO_FLAG_TX		0x00000002	/* TX active. */
#define IO_FLAG_DYING		0x00000004	/* Destructor is active. */
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


static struct net2_promise*
		 dgram_get_tx_promise(struct net2_workq_io*);
static void	 dgram_rx_activate(struct net2_workq_io*);
static void	 dgram_rx_deactivate(struct net2_workq_io*);
static void	 dgram_tx_activate(struct net2_workq_io*);
static void	 dgram_tx_deactivate(struct net2_workq_io*);
static void	 rx_evcb(struct ev_loop*, struct ev_io*, int);
static void	 rx_callback(void*, void*);
static int	 rx_new(struct net2_workq_io*, size_t);
static void	 rx_free(struct dgram_rx*);
static void	 tx_evcb(struct ev_loop*, struct ev_io*, int);
static void	 tx_callback(void*, void*);
static int	 tx_new(struct net2_workq_io*, size_t);
static void	 tx_free(struct dgram_tx*);
static void	 tx_ask(void*, void*);


/* Acquire transmission promise. */
static struct net2_promise*
dgram_get_tx_promise(struct net2_workq_io *dg)
{
	struct net2_promise	*p;

	net2_mutex_lock(dg->fguard);
	if ((dg->flags & (IO_FLAG_TX | IO_FLAG_DYING)) == IO_FLAG_TX)
		p = (*dg->tx_cb)(dg->cb_arg, NET2_WORKQ_IO_MAXLEN);
	else
		p = NULL;
	net2_mutex_unlock(dg->fguard);

	return p;
}
/* Enable RX io. */
static void
dgram_rx_activate(struct net2_workq_io *dg)
{
	struct net2_workq_evbase*wqev;
	struct ev_loop		*loop;

	wqev = net2_workq_evbase(dg->wq);
	loop = net2_workq_get_evloop(dg->wq);

	net2_mutex_lock(dg->fguard);
	if ((dg->flags & (IO_FLAG_RX | IO_FLAG_DYING)) == IO_FLAG_RX) {
		ev_io_start(loop, &dg->rx_watcher);
		net2_workq_evbase_evloop_changed(wqev);
	}
	net2_mutex_unlock(dg->fguard);
}
/* Disable RX io. */
static void
dgram_rx_deactivate(struct net2_workq_io *dg)
{
	struct net2_workq_evbase*wqev;
	struct ev_loop		*loop;

	wqev = net2_workq_evbase(dg->wq);
	loop = net2_workq_get_evloop(dg->wq);

	net2_mutex_lock(dg->fguard);
	ev_io_stop(loop, &dg->rx_watcher);
	net2_workq_evbase_evloop_changed(wqev);
	net2_mutex_unlock(dg->fguard);
}
/* Enable TX io. */
static void
dgram_tx_activate(struct net2_workq_io *dg)
{
	struct net2_workq_evbase*wqev;
	struct ev_loop		*loop;

	wqev = net2_workq_evbase(dg->wq);
	loop = net2_workq_get_evloop(dg->wq);

	net2_mutex_lock(dg->fguard);
	if ((dg->flags & IO_FLAG_DYING) == 0) {
		ev_io_start(loop, &dg->tx_watcher);
		net2_workq_evbase_evloop_changed(wqev);
	}
	net2_mutex_unlock(dg->fguard);
}
/* Disable RX io. */
static void
dgram_tx_deactivate(struct net2_workq_io *dg)
{
	struct net2_workq_evbase*wqev;
	struct ev_loop		*loop;

	wqev = net2_workq_evbase(dg->wq);
	loop = net2_workq_get_evloop(dg->wq);

	net2_mutex_lock(dg->fguard);
	ev_io_stop(loop, &dg->tx_watcher);
	net2_workq_evbase_evloop_changed(wqev);
	net2_mutex_unlock(dg->fguard);
}


/* Lib-ev callback for rx. */
static void
rx_evcb(struct ev_loop * ILIAS_NET2__unused loop, struct ev_io *ev,
    int ILIAS_NET2__unused revents)
{
	struct net2_workq_io	*dg = EVRX_2_DGRAM(ev);
	struct dgram_rx		*dgrx;

	/* Acquire spare rx event. */
	net2_mutex_lock(dg->rx_guard);
	dgrx = TAILQ_FIRST(&dg->rx_spare);
	if (dgrx == NULL) {
		/* Ran out of RX buffers. */
		dgram_rx_deactivate(dg);
		net2_mutex_unlock(dg->rx_guard);
		return;
	}
	TAILQ_REMOVE(&dg->rx_spare, dgrx, q);
	net2_mutex_unlock(dg->rx_guard);

	/* Read datagram from socket. */
	dgrx->data = NULL;
	dgrx->addrlen = sizeof(dgrx->addr);
	if (net2_sockdgram_recv(dg->socket, &dgrx->error, &dgrx->data,
	    (struct sockaddr*)&dgrx->addr, &dgrx->addrlen) != 0)
		goto put_back;
	if (dgrx->error == 0 && dgrx->data == NULL)
		goto put_back;

	/* Put datagram on execution queue. */
	net2_mutex_lock(dg->rx_guard);
	TAILQ_INSERT_TAIL(&dg->rx_queue, dgrx, q);
	net2_mutex_unlock(dg->rx_guard);

	/* Activate event. */
	net2_workq_activate(&dgrx->impl);

	return;


put_back:
	net2_mutex_lock(dg->rx_guard);
	if (TAILQ_EMPTY(&dg->rx_spare))
		dgram_rx_activate(dg);
	TAILQ_INSERT_HEAD(&dg->rx_spare, dgrx, q);
	net2_mutex_unlock(dg->rx_guard);
	return;
}
/* Event callback. */
static void
rx_callback(void *dg_ptr, void *dgrx_ptr)
{
	struct net2_workq_io	*dg = dg_ptr;
	struct dgram_rx		*dgrx = dgrx_ptr;
	struct net2_dgram_rx	 invoc;

	assert(dgrx->addrlen <= sizeof(invoc.addr));

	/* Setup invocation. */
	memcpy(&invoc.addr, &dgrx->addr, dgrx->addrlen);
	invoc.addrlen = dgrx->addrlen;
	invoc.error = dgrx->error;
	invoc.data = dgrx->data;
	dgrx->data = NULL;

	/* Actual invocation. */
	(*dg->rx_cb)(dg->cb_arg, &invoc);

	/* Clean up. */
	if (invoc.data != NULL)
		net2_buffer_free(invoc.data);

	/* Put dgrx on the spare queue, so a new invocation can use it. */
	net2_mutex_lock(dg->rx_guard);
	TAILQ_REMOVE(&dg->rx_queue, dgrx, q);
	if (TAILQ_EMPTY(&dg->rx_spare))
		dgram_rx_activate(dg);
	TAILQ_INSERT_TAIL(&dg->rx_spare, dgrx, q);
	net2_mutex_unlock(dg->rx_guard);
}
/*
 * Create count new rx events.
 * New events are added to rx_spare.
 */
static int
rx_new(struct net2_workq_io *dg, size_t count)
{
	struct dgram_rx		*dgrx;
	size_t			 i;
	int			 error;

	for (i = 0; i < count; i++) {
		if ((dgrx = net2_malloc(sizeof(*dgrx))) == NULL) {
			error = ENOMEM;
			goto fail_0;
		}
		if ((error = net2_workq_init_work(&dgrx->impl, dg->wq,
		    &rx_callback, dg, dgrx, 0)) != 0)
			goto fail_1;
		dgrx->data = NULL;

		TAILQ_INSERT_HEAD(&dg->rx_spare, dgrx, q);
	}
	return 0;

fail_2:
	net2_workq_deinit_work(&dgrx->impl);
fail_1:
	net2_free(dgrx);
fail_0:

	/* Clean up any succesful dgrx's. */
	while ((dgrx = TAILQ_FIRST(&dg->rx_spare)) != NULL) {
		TAILQ_REMOVE(&dg->rx_spare, dgrx, q);
		rx_free(dgrx);
	}
	return error;
}
/* Free rx event. */
static void
rx_free(struct dgram_rx *dgrx)
{
	net2_workq_deinit_work(&dgrx->impl);
	if (dgrx->data)
		net2_buffer_free(dgrx->data);
	net2_free(dgrx);
	return;
}


/* Lib-ev callback for rx. */
static void
tx_evcb(struct ev_loop * ILIAS_NET2__unused loop, struct ev_io *ev,
    int ILIAS_NET2__unused revents)
{
	struct net2_workq_io	*dg = EVTX_2_DGRAM(ev);
	struct dgram_tx		*dgtx;
	struct net2_dgram_tx_promdata
				*result;
	int			 fin;
	int			 send_err;

	/* Acquire spare rx event. */
	net2_mutex_lock(dg->tx_guard);
	dgtx = TAILQ_FIRST(&dg->tx_rts);
	if (dgtx == NULL) {
		/* Ran out of RX buffers. */
		dgram_tx_deactivate(dg);
		net2_mutex_unlock(dg->tx_guard);
		return;
	}
	TAILQ_REMOVE(&dg->tx_rts, dgtx, q);
	net2_mutex_unlock(dg->tx_guard);

	/* Acquire promised tx data. */
	fin = net2_promise_get_result(dgtx->tx_promdata,
	    (void**)&result, NULL);
	assert(fin == NET2_PROM_FIN_OK);
	assert(result != NULL);

	/* Put buffer on the wire. */
	send_err = net2_sockdgram_send(dg->socket, result->data,
	    (struct sockaddr*)&result->addr, result->addrlen);
	if (result->tx_done != NULL) {
		assert(net2_promise_is_running(result->tx_done));
		if (send_err == 0) {
			net2_promise_set_finok(result->tx_done, NULL,
			    NULL, NULL, 1);
		} else
			net2_promise_set_error(result->tx_done, send_err, 1);
		result->tx_done = NULL;
	}

	/* Free buffer. */
	net2_buffer_free(result->data);

	/*
	 * Put this tx back on tx_spare.
	 * If the tx_spare was empty, ask for more data.
	 */
	net2_mutex_lock(dg->tx_guard);
	if (TAILQ_EMPTY(&dg->tx_spare))
		net2_workq_activate(&dg->ask_for_tx);
	TAILQ_INSERT_HEAD(&dg->tx_spare, dgtx, q);
	net2_mutex_unlock(dg->tx_guard);
}
/* Event callback. */
static void
tx_callback(void *dg_ptr, void *dgtx_ptr)
{
	struct net2_workq_io	*dg = dg_ptr;
	struct dgram_tx		*dgtx = dgtx_ptr;
	int			 fin;
	struct net2_dgram_tx_promdata
				*result;

	assert(dgtx->tx_promdata != NULL);

	/* Remove event. */
	net2_promise_event_deinit(&dgtx->tx_promdata_ready);
	/* Acquire result. */
	fin = net2_promise_get_result(dgtx->tx_promdata,
	    (void**)&result, NULL);
	assert(fin != NET2_PROM_FIN_UNFINISHED);

	if (fin == NET2_PROM_FIN_OK) {
ready_to_send:
		assert(result != NULL && result->data != NULL);

#ifdef WIN32
		/*
		 * Windows cannot handle IO vectors, compress the buffer now.
		 *
		 * This code will be repeated later on, at sending, so we don't
		 * care about succes or failure now.
		 * In other words: it's an optimization to do it here.
		 */
		net2_buffer_pullup(result->data,
		    net2_buffer_length(result->data));
#endif

		/* Mark conclusion as progressing. */
		if (result->tx_done != NULL)
			net2_promise_set_running(result->tx_done);

		/* Place on ready-to-send queue. */
		net2_mutex_lock(dg->tx_guard);
		TAILQ_REMOVE(&dg->tx_queue, dgtx, q);
		if (TAILQ_EMPTY(&dg->tx_rts))
			dgram_tx_activate(dg);
		TAILQ_INSERT_TAIL(&dg->tx_rts, dgtx, q);
		net2_mutex_unlock(dg->tx_guard);

		return;
	}
	/* Promise is no longer needed. */
	net2_promise_release(dgtx->tx_promdata);

	/* Attempt to acquire a new promise. */
	if ((dgtx->tx_promdata = dgram_get_tx_promise(dg)) != NULL) {
		/*
		 * If this promise is already completed succesfully,
		 * push it onto the ready-queue immediately.
		 */
		if (net2_promise_get_result(dgtx->tx_promdata,
		    (void**)&result, NULL) == NET2_PROM_FIN_OK)
			goto ready_to_send;

		/*
		 * dgtx is still enqueued on the tx_queue.
		 * No need for queue modification.
		 */

		/* Add event callback. */
		if ((net2_promise_event_init(&dgtx->tx_promdata_ready,
		    dgtx->tx_promdata, NET2_PROM_ON_FINISH, dg->wq,
		    &tx_callback, dg, dgtx)) != 0) {
			/*
			 * Adding the event callback failed.
			 *
			 * Recover by throwing away this packet and
			 * activating the ask_for_tx callback.
			 */
			net2_promise_cancel(dgtx->tx_promdata);
			net2_promise_release(dgtx->tx_promdata);
			dgtx->tx_promdata = NULL;

			net2_workq_activate(&dg->ask_for_tx);

			goto no_new_tx;
		}
		return;
	}

no_new_tx:
	/* Put dgtx on spare queue. */
	net2_mutex_lock(dg->tx_guard);
	TAILQ_REMOVE(&dg->tx_queue, dgtx, q);
	TAILQ_REMOVE(&dg->tx_spare, dgtx, q);
	net2_mutex_unlock(dg->tx_guard);
}
/*
 * Create count new tx events.
 * New events are added to tx_spare.
 */
static int
tx_new(struct net2_workq_io *dg, size_t count)
{
	struct dgram_tx		*dgtx;
	size_t			 i;
	int			 error;

	for (i = 0; i < count; i++) {
		if ((dgtx = net2_malloc(sizeof(*dgtx))) == NULL) {
			error = ENOMEM;
			goto fail_0;
		}

		dgtx->tx_promdata = NULL;
		TAILQ_INSERT_HEAD(&dg->tx_spare, dgtx, q);
	}
	return 0;


fail_0:

	/* Clean up any succesful dgtx's. */
	while ((dgtx = TAILQ_FIRST(&dg->tx_spare)) != NULL) {
		TAILQ_REMOVE(&dg->tx_spare, dgtx, q);
		tx_free(dgtx);
	}
	return error;
}
/* Free tx event. */
static void
tx_free(struct dgram_tx *dgtx)
{
	struct net2_dgram_tx_promdata
				*result;

	if (dgtx->tx_promdata) {
		net2_promise_event_deinit(&dgtx->tx_promdata_ready);
		net2_promise_cancel(dgtx->tx_promdata);

		if (net2_promise_get_result(dgtx->tx_promdata,
		    (void**)&result, NULL) == NET2_PROM_FIN_OK) {
			/*
			 * Try to set tx_done to canceled.
			 * While incorrect, it hopefully prevents dangling
			 * promises.
			 */
			if (result->tx_done != NULL)
				net2_promise_set_cancel(result->tx_done, 0);
		}

		net2_promise_release(dgtx->tx_promdata);
	}

	net2_free(dgtx);
}
static void
tx_ask(void *dg_ptr, void * ILIAS_NET2__unused unused)
{
	struct net2_workq_io	*dg = dg_ptr;
	struct dgram_tx		*dgtx;

	/* Acquire dgtx if available. */
	net2_mutex_lock(dg->tx_guard);
	if ((dgtx = TAILQ_FIRST(&dg->tx_spare)) == NULL) {
		net2_workq_deactivate(&dg->ask_for_tx);
		net2_mutex_unlock(dg->tx_guard);
		return;
	}
	TAILQ_REMOVE(&dg->tx_spare, dgtx, q);
	net2_mutex_unlock(dg->tx_guard);

	/* Acquire promise for more tx data. */
	if ((dgtx->tx_promdata = dgram_get_tx_promise(dg)) == NULL) {
no_new_tx:
		net2_mutex_lock(dg->tx_guard);
		net2_workq_deactivate(&dg->ask_for_tx);
		net2_mutex_unlock(dg->tx_guard);
		return;
	}
	/* If the promise is already completed, skip the queued phase. */
	if (net2_promise_is_finished(dgtx->tx_promdata) == NET2_PROM_FIN_OK) {
		net2_mutex_lock(dg->tx_guard);
		if (TAILQ_EMPTY(&dg->tx_rts))
			dgram_tx_activate(dg);
		TAILQ_INSERT_TAIL(&dg->tx_rts, dgtx, q);
		net2_mutex_unlock(dg->tx_guard);
		return;
	}
	/* Attach promise completion event and add dgtx to tx_queue. */
	if ((net2_promise_event_init(&dgtx->tx_promdata_ready,
	    dgtx->tx_promdata, NET2_PROM_ON_FINISH, dg->wq,
	    &tx_callback, dg, dgtx)) != 0) {
		/*
		 * Adding the event callback failed.
		 *
		 * Recover by throwing away this packet and
		 * activating the ask_for_tx callback.
		 */
		net2_promise_cancel(dgtx->tx_promdata);
		net2_promise_release(dgtx->tx_promdata);
		dgtx->tx_promdata = NULL;

		net2_workq_activate(&dg->ask_for_tx);

		goto no_new_tx;
	}

	return;
}


/* Create a new workq IO event. */
ILIAS_NET2_EXPORT struct net2_workq_io*
net2_workq_io_new(struct net2_workq *wq, net2_socket_t socket,
    net2_workq_io_recv rx_cb, net2_workq_io_send tx_cb, void *cb_arg)
{
	struct net2_workq_io	*dg;
	struct dgram_rx		*dgrx;
	struct dgram_tx		*dgtx;

	/* Argument validation. */
	if (wq == NULL)
		goto fail_0;
	if (tx_cb == NULL && rx_cb == NULL)
		goto fail_0;
#ifdef WIN32
	if (socket == NULL)
		goto fail_0;
#else
	if (socket == -1)
		goto fail_0;
#endif

	/* Create new workq_io. */
	if ((dg = net2_malloc(sizeof(*dg))) == NULL)
		goto fail_0;
	if ((dg->rx_guard = net2_mutex_alloc()) == NULL)
		goto fail_1;
	if ((dg->tx_guard = net2_mutex_alloc()) == NULL)
		goto fail_2;

	dg->socket = socket;
	dg->flags = 0;
	dg->rx_cb = rx_cb;
	dg->tx_cb = tx_cb;
	dg->cb_arg = cb_arg;
	TAILQ_INIT(&dg->rx_queue);
	TAILQ_INIT(&dg->rx_spare);
	TAILQ_INIT(&dg->tx_queue);
	TAILQ_INIT(&dg->tx_rts);
	TAILQ_INIT(&dg->tx_spare);

	ev_io_init(&dg->rx_watcher, &rx_evcb, socket, EV_READ);
	ev_io_init(&dg->tx_watcher, &tx_evcb, socket, EV_WRITE);
	dg->wq = wq;
	net2_workq_ref(wq);

	/* Add tx, rx. */
	if (tx_new(dg, MAX_TX) != 0 || rx_new(dg, MAX_RX) != 0)
		goto fail_5;
	/* Initialize ask-for-tx event. */
	if (net2_workq_init_work(&dg->ask_for_tx, wq, &tx_ask, dg, NULL, NET2_WORKQ_PERSIST) != 0)
		goto fail_5;

	/* Flag mutex. */
	if ((dg->fguard = net2_mutex_alloc()) == NULL)
		goto fail_6;

	return dg;


fail_7:
	net2_mutex_free(dg->fguard);
fail_6:
	net2_workq_deinit_work(&dg->ask_for_tx);
fail_5:
	/* Clean up any succesful dgrx's. */
	while ((dgrx = TAILQ_FIRST(&dg->rx_spare)) != NULL) {
		TAILQ_REMOVE(&dg->rx_spare, dgrx, q);
		rx_free(dgrx);
	}
	/* Clean up any succesful dgtx's. */
	while ((dgtx = TAILQ_FIRST(&dg->tx_spare)) != NULL) {
		TAILQ_REMOVE(&dg->tx_spare, dgtx, q);
		tx_free(dgtx);
	}
fail_4:
	net2_workq_release(dg->wq);
fail_3:
	net2_mutex_free(dg->tx_guard);
fail_2:
	net2_mutex_free(dg->rx_guard);
fail_1:
	net2_free(dg);
fail_0:
	return NULL;
}
/* Destroy a workq IO event. */
ILIAS_NET2_EXPORT void
net2_workq_io_destroy(struct net2_workq_io *dg)
{
	struct ev_loop		*loop;
	struct dgram_tx		*dgtx;
	struct dgram_rx		*dgrx;
	int			 workq_acquired;

	/* Synchronize into the workq. */
	workq_acquired = net2_workq_want(dg->wq, 0);
	assert(workq_acquired == 0 || workq_acquired == EDEADLK);

	/* Mark as dying. */
	net2_mutex_lock(dg->fguard);
	dg->flags |= IO_FLAG_DYING;
	net2_mutex_unlock(dg->fguard);

	/* Stop IO. */
	dgram_rx_deactivate(dg);
	dgram_tx_deactivate(dg);

	/* Stop ask-for-tx. */
	net2_workq_deinit_work(&dg->ask_for_tx);

	/*
	 * Release rx items.
	 */
	net2_mutex_lock(dg->rx_guard);
	while ((dgrx = TAILQ_FIRST(&dg->rx_queue)) != NULL) {
		TAILQ_REMOVE(&dg->rx_queue, dgrx, q);
		rx_free(dgrx);
	}
	while ((dgrx = TAILQ_FIRST(&dg->rx_spare)) != NULL) {
		TAILQ_REMOVE(&dg->rx_spare, dgrx, q);
		rx_free(dgrx);
	}
	net2_mutex_unlock(dg->rx_guard);
	/*
	 * Release tx items.
	 */
	net2_mutex_lock(dg->tx_guard);
	while ((dgtx = TAILQ_FIRST(&dg->tx_queue)) != NULL) {
		TAILQ_REMOVE(&dg->tx_queue, dgtx, q);
		tx_free(dgtx);
	}
	while ((dgtx = TAILQ_FIRST(&dg->tx_spare)) != NULL) {
		TAILQ_REMOVE(&dg->tx_spare, dgtx, q);
		tx_free(dgtx);
	}
	while ((dgtx = TAILQ_FIRST(&dg->tx_rts)) != NULL) {
		TAILQ_REMOVE(&dg->tx_rts, dgtx, q);
		tx_free(dgtx);
	}
	net2_mutex_unlock(dg->tx_guard);

	/* Release the locks. */
	net2_mutex_free(dg->tx_guard);
	net2_mutex_free(dg->rx_guard);
	net2_mutex_free(dg->fguard);

	/* Allow workq to continue. */
	if (workq_acquired == 0)
		net2_workq_unwant(dg->wq);
	net2_workq_release(dg->wq);

	net2_free(dg);
}
/* Enable listening for read events. */
ILIAS_NET2_EXPORT void
net2_workq_io_activate_rx(struct net2_workq_io *dg)
{
	struct ev_loop		*loop;

	if (dg->rx_cb == NULL)
		return;
	loop = net2_workq_get_evloop(dg->wq);

	net2_mutex_lock(dg->rx_guard);
	net2_mutex_lock(dg->fguard);
	dg->flags |= IO_FLAG_RX;
	if (!TAILQ_EMPTY(&dg->rx_spare))
		dgram_rx_activate(dg);
	net2_mutex_unlock(dg->fguard);
	net2_mutex_unlock(dg->rx_guard);
}
/* Disable listening for read events. */
ILIAS_NET2_EXPORT void
net2_workq_io_deactivate_rx(struct net2_workq_io *dg)
{
	struct ev_loop		*loop;

	loop = net2_workq_get_evloop(dg->wq);

	net2_mutex_lock(dg->rx_guard);
	net2_mutex_lock(dg->fguard);
	dg->flags &= ~IO_FLAG_RX;
	net2_mutex_unlock(dg->fguard);
	dgram_rx_deactivate(dg);
	net2_mutex_unlock(dg->rx_guard);
}
/* Enable listening for write events. */
ILIAS_NET2_EXPORT void
net2_workq_io_activate_tx(struct net2_workq_io *dg)
{
	if (dg->tx_cb == NULL)
		return;

	net2_mutex_lock(dg->fguard);
	dg->flags |= IO_FLAG_TX;
	net2_workq_activate(&dg->ask_for_tx);
	net2_mutex_unlock(dg->fguard);
}
/* Disable listening for write events. */
ILIAS_NET2_EXPORT void
net2_workq_io_deactivate_tx(struct net2_workq_io *dg)
{
	net2_mutex_lock(dg->fguard);
	dg->flags &= ~IO_FLAG_TX;
	net2_workq_deactivate(&dg->ask_for_tx);
	net2_mutex_unlock(dg->fguard);
}

/* Free tx promise data. */
ILIAS_NET2_EXPORT void
net2_workq_io_tx_pdata_free(void *pd_ptr, void * ILIAS_NET2__unused unused)
{
	struct net2_dgram_tx_promdata
				*pd = pd_ptr;

	if (pd->data != NULL)
		net2_free(pd->data);
	if (pd->tx_done != NULL) {
		net2_promise_set_cancel(pd->tx_done, 0);
		net2_promise_release(pd->tx_done);
	}
	net2_free(pd);
}
