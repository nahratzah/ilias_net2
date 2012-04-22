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
#include <ilias/net2/connection.h> /* For net2_conn_receive (TODO: kill the bastard). */
#include <ilias/net2/memory.h>
#include <ilias/net2/mutex.h>
#include <ilias/net2/sockdgram.h>
#include <assert.h>

/* Pointer magic. */
#define DGRAM_EV_OFFSET							\
	((size_t)(&((struct net2_workq_dgram*)0)->watcher))
#define EV_2_DGRAM(_ev)							\
	((struct net2_workq_dgram*)((char*)(_ev) - DGRAM_EV_OFFSET))
#define DGRAM_WQJ_OFFSET						\
	((size_t)(&((struct net2_workq_dgram*)0)->job))
#define WQJ_2_DGRAM(_ev)						\
	((struct net2_workq_dgram*)((char*)(_ev) - DGRAM_WQJ_OFFSET))

/* Max number of unprocessed input buffers. */
#define MAX_BUFLEN	128

static void
dgram_start(struct net2_workq_job *j)
{
	struct net2_workq_dgram	*ev;

	ev = WQJ_2_DGRAM(j);
	if (ev->loop != NULL)
		ev_io_start(ev->loop, &ev->watcher);
}
static void
dgram_stop(struct net2_workq_job *j)
{
	struct net2_workq_dgram	*ev;

	ev = WQJ_2_DGRAM(j);
	if (ev->loop != NULL)
		ev_io_stop(ev->loop, &ev->watcher);
}
static void
dgram_destroy(struct net2_workq_job *j)
{
	struct net2_workq_dgram	*ev;

	ev = WQJ_2_DGRAM(j);
	if (ev->loop != NULL) {
		ev_io_stop(ev->loop, &ev->watcher);
		ev->loop = NULL;
	}
}

/* Datagram callbacks. */
static const struct net2_workq_job_cb dgram_job_cb = {
	&dgram_start,
	&dgram_stop,
	&dgram_destroy,
	&dgram_destroy
};

/*
 * Callback on workq, invokes real event with second parameter being
 * the buffer.
 */
static void
dgram_wqcb(void *ev_ptr, void *arg0)
{
	struct net2_workq_dgram	*ev = ev_ptr;
	struct net2_dgram	*b;

	net2_mutex_lock(ev->bufmtx);
	if ((b = TAILQ_FIRST(&ev->buffers)) != NULL) {
		TAILQ_REMOVE(&ev->buffers, b, bufq);
		ev->buflen--;

		/* Cease backoff. */
		if (ev->buflen <= MAX_BUFLEN && !ev_is_active(&ev->watcher))
			ev_io_start(ev->loop, &ev->watcher);
	}
	if (TAILQ_EMPTY(&ev->buffers))
		net2_workq_deactivate(&ev->job);
	net2_mutex_unlock(ev->bufmtx);

	if (b != NULL) {
		assert(ev->recv != NULL);
		(*ev->recv)(arg0, b);
		net2_buffer_free(b->data);
		free(b);
	}
}

/* Event loop callback, writes a packet and dequeues it. */
static void
dgram_evcb_write(struct ev_loop *loop, ev_io *w, int revents)
{
	assert(0); /* TODO: implement. */
}

/* Event loop callback, reads a packet and dequeues it. */
static void
dgram_evcb_read(struct ev_loop *loop, ev_io *w, int revents)
{
	struct net2_workq_dgram	*ev;
	struct net2_conn_receive*recv;
	struct net2_dgram	*b;
	int			 err;

	/* Allocate buffer space. */
	if ((b = net2_malloc(sizeof(*b))) == NULL) {
		assert(0); /* TODO: handle out-of-memory condition. */
		return;
	}

	/* Read datagram from socket. */
	ev = EV_2_DGRAM(w);
	b->addrlen = sizeof(b->addr);
	recv = NULL;
	err = net2_sockdgram_recv(w->fd, &recv, (struct sockaddr*)&b->addr,
	    &b->addrlen);
	b->data = recv->buf;
	b->error = recv->error;

	/* Handle failure. */
	if (err != 0) {
		net2_free(b);
		assert(0); /* TODO: handle error from net2_sockdgram_recv. */
		return;
	}

	if (recv == NULL)
		net2_free(b);
	else {
		/* Add the received packet to the queue. */
		net2_mutex_lock(ev->bufmtx);
		if (TAILQ_EMPTY(&ev->buffers))
			net2_workq_activate(&ev->job);
		TAILQ_INSERT_TAIL(&ev->buffers, b, bufq);
		ev->buflen++;
		net2_mutex_unlock(ev->bufmtx);

		/* Back off. */
		if (ev->buflen >= MAX_BUFLEN && ev_is_active(&ev->watcher))
			ev_io_stop(ev->loop, &ev->watcher);
	}
}

/* Event loop callback. */
static void
dgram_evcb(struct ev_loop *loop, ev_io *w, int revents)
{
	if (revents & EV_WRITE)
		dgram_evcb_write(loop, w, revents);
	if (revents & EV_READ)
		dgram_evcb_read(loop, w, revents);
}

/* Initialize the datagram IO. */
ILIAS_NET2_EXPORT int
net2_workq_dgram_init(struct net2_workq_dgram *dg, int fd,
    struct net2_workq *wq, net2_workq_io_recv recv, net2_workq_io_send send,
    void *arg0)
{
	int			 err;
	int			 evio_flags = 0;

	if (dg == NULL || wq == NULL || (recv == NULL && send == NULL))
		return EINVAL;
	if (recv != NULL)
		evio_flags |= EV_READ;
	if (send != NULL)
		evio_flags |= EV_WRITE;

	dg->recv = recv;
	dg->send = send;
	dg->loop = net2_workq_get_evloop(wq);
	if ((err = net2_workq_init_work(&dg->job, wq, &dgram_wqcb, dg, arg0,
	    NET2_WORKQ_PERSIST)) != 0)
		return err;

	dg->job.callbacks = &dgram_job_cb;
	ev_io_init(&dg->watcher, dgram_evcb, fd, EV_READ);
	return 0;
}

/* Release resources held by datagram IO. */
ILIAS_NET2_EXPORT void
net2_workq_dgram_deinit(struct net2_workq_dgram *dg)
{
	struct net2_dgram	*b;

	net2_workq_deinit_work(&dg->job);

	net2_mutex_lock(dg->bufmtx);
	while ((b = TAILQ_FIRST(&dg->buffers)) != NULL) {
		TAILQ_REMOVE(&dg->buffers, b, bufq);
		if (b->data != NULL)
			net2_buffer_free(b->data);
		net2_free(b);
	}
	net2_mutex_unlock(dg->bufmtx);
	net2_mutex_free(dg->bufmtx);
}
