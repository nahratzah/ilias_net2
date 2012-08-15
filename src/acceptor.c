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
#include <ilias/net2/acceptor.h>
#include <ilias/net2/workq.h>
#include <assert.h>

/* Initialize acceptor socket. */
ILIAS_NET2_EXPORT int
net2_acceptor_socket_init(struct net2_acceptor_socket *self,
    struct net2_workq *workq, const struct net2_acceptor_socket_fn *fn)
{
	if (workq == NULL || fn == NULL)
		return EINVAL;

	self->fn = fn;
	self->acceptor = NULL;
	self->workq = workq;
	self->state = 0;
	net2_workq_ref(self->workq);
	return 0;
}

/* Destroy acceptor socket. */
ILIAS_NET2_EXPORT void
net2_acceptor_socket_deinit(struct net2_acceptor_socket *self)
{
	net2_acceptor_detach(self);
	net2_workq_release(self->workq);
}

/* Acceptor socket destructor. */
ILIAS_NET2_EXPORT void
net2_acceptor_socket_destroy(struct net2_acceptor_socket *s)
{
	int		 want;
	struct net2_workq
			*wq;

	assert(s->fn->destroy != NULL);
	wq = s->workq;
	net2_workq_ref(wq);
	want = net2_workq_want(wq, 0);
	assert(want == 0 || want == EDEADLK);
	(*s->fn->destroy)(s);
	if (want == 0)
		net2_workq_unwant(wq);
	net2_workq_release(wq);
}

/* Attach acceptor. */
ILIAS_NET2_EXPORT int
net2_acceptor_attach(struct net2_acceptor_socket *self,
    struct net2_acceptor *acceptor)
{
	int		 rv;

	if (self->acceptor != NULL || acceptor == NULL)
		return EINVAL;

	if (acceptor->fn->attach) {
		if ((rv = (*acceptor->fn->attach)(self, acceptor)) != 0)
			return rv;
	}
	self->acceptor = acceptor;
	acceptor->socket = self;
	return 0;
}

/* Detach current acceptor. */
ILIAS_NET2_EXPORT void
net2_acceptor_detach(struct net2_acceptor_socket *self)
{
	if (self->acceptor == NULL)
		return;

	if (self->acceptor->fn->detach)
		(*self->acceptor->fn->detach)(self, self->acceptor);
	self->acceptor->socket = NULL;
	self->acceptor = NULL;
}

/* Mark acceptor_socket as ready to send. */
ILIAS_NET2_EXPORT void
net2_acceptor_socket_ready_to_send(struct net2_acceptor_socket *s)
{
	if (s->fn->ready_to_send)
		s->fn->ready_to_send(s);
}

/* Mark acceptor as ready to send. */
ILIAS_NET2_EXPORT void
net2_acceptor_ready_to_send(struct net2_acceptor *a)
{
	if (a->socket != NULL)
		net2_acceptor_socket_ready_to_send(a->socket);
}

/* Retrieve transmit data from acceptor. */
ILIAS_NET2_EXPORT int
net2_acceptor_get_transmit(struct net2_acceptor *a, struct net2_buffer **buf,
    struct net2_tx_callback *cwtx, int first, size_t maxlen)
{
	return (*a->fn->get_transmit)(a, buf, cwtx, first, maxlen);
}

/* Retrieve transmit data from acceptor socket. */
ILIAS_NET2_EXPORT int
net2_acceptor_socket_get_transmit(struct net2_acceptor_socket *s,
    struct net2_buffer **buf,
    struct net2_tx_callback *cwtx, int first, size_t maxlen)
{
	if (s->state & NET2_ACCSOCK_CLOSED)
		return 0;
	if (s->fn->get_transmit != NULL)
		return (*s->fn->get_transmit)(s, buf, cwtx, first, maxlen);
	else if (s->acceptor != NULL) {
		return net2_acceptor_get_transmit(s->acceptor, buf, cwtx,
		    first, maxlen);
	}
	return 0;
}

/* Make acceptor process received data. */
ILIAS_NET2_EXPORT void
net2_acceptor_accept(struct net2_acceptor *a, struct net2_buffer *buf)
{
	(*a->fn->accept)(a, buf);
}

/* Make acceptor socket process received data. */
ILIAS_NET2_EXPORT void
net2_acceptor_socket_accept(struct net2_acceptor_socket *s,
    struct net2_buffer *buf)
{
	if (s->fn->accept != NULL)
		(*s->fn->accept)(s, buf);
	else if (s->acceptor != NULL)
		net2_acceptor_accept(s->acceptor, buf);
}

/* Initialize acceptor. */
ILIAS_NET2_EXPORT int
net2_acceptor_init(struct net2_acceptor *a, const struct net2_acceptor_fn *fn)
{
	a->fn = fn;
	a->socket = NULL;
	return 0;
}

/* Release acceptor resources. */
ILIAS_NET2_EXPORT void
net2_acceptor_deinit(struct net2_acceptor *a)
{
	assert(a->socket == NULL);	/* TODO detach now? */
}

/* Extract pvlist for acceptor. */
ILIAS_NET2_EXPORT int
net2_acceptor_pvlist(struct net2_acceptor *a, struct net2_pvlist *pv)
{
	if (a->socket != NULL)
		return net2_acceptor_socket_pvlist(a->socket, pv);
	return 0;
}

/* Extract pvlist for acceptor socket. */
ILIAS_NET2_EXPORT int
net2_acceptor_socket_pvlist(struct net2_acceptor_socket *s,
    struct net2_pvlist *pv)
{
	if (s->fn->get_pvlist != NULL)
		return (*s->fn->get_pvlist)(s, pv);
	return 0;
}

/*
 * Returns a pointer to the workq of this acceptor socket.
 * Does not increment the reference counter.
 */
ILIAS_NET2_EXPORT struct net2_workq*
net2_acceptor_socket_workq(struct net2_acceptor_socket *s)
{
	return s->workq;
}

/*
 * Returns a pointer to the workq of this acceptor.
 * Does not increment the reference counter.
 */
ILIAS_NET2_EXPORT struct net2_workq*
net2_acceptor_workq(struct net2_acceptor *a)
{
	if (a->socket != NULL)
		return net2_acceptor_socket_workq(a->socket);
	return NULL;
}

ILIAS_NET2_EXPORT struct net2_acceptor_socket*
net2_acceptor_socket(struct net2_acceptor *a)
{
	return a->socket;
}

ILIAS_NET2_EXPORT struct net2_acceptor*
net2_acceptor(struct net2_acceptor_socket *s)
{
	return s->acceptor;
}

/*
 * Mark acceptor socket as closed.
 */
ILIAS_NET2_EXPORT void
net2_acceptor_socket_close(struct net2_acceptor_socket *s)
{
	if (s->state & NET2_ACCSOCK_CLOSED)
		return;

	s->state |= NET2_ACCSOCK_CLOSED;
	if (s->acceptor != NULL) {
		if (s->acceptor->fn->on_close != NULL)
			s->acceptor->fn->on_close(s->acceptor);
	}
}
