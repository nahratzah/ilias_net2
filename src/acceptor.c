#include <ilias/net2/acceptor.h>
#include <assert.h>

/*
 * Initialize acceptor socket.
 *
 * Steals the reference to the evbase.
 */
ILIAS_NET2_EXPORT int
net2_acceptor_socket_init(struct net2_acceptor_socket *self,
    struct net2_evbase *evbase, const struct net2_acceptor_socket_fn *fn)
{
	self->fn = fn;
	self->acceptor = NULL;
	self->evbase = evbase;
	return 0;
}

/* Destroy acceptor socket. */
ILIAS_NET2_EXPORT void
net2_acceptor_socket_deinit(struct net2_acceptor_socket *self)
{
	net2_acceptor_detach(self);
}

/* Acceptor socket destructor. */
ILIAS_NET2_EXPORT void
net2_acceptor_socket_destroy(struct net2_acceptor_socket *s)
{
	assert(s->fn->destroy != NULL);
	(*s->fn->destroy)(s);
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
    struct net2_cw_tx *cwtx, int first, size_t maxlen)
{
	return (*a->fn->get_transmit)(a, buf, cwtx, first, maxlen);
}

/* Retrieve transmit data from acceptor socket. */
ILIAS_NET2_EXPORT int
net2_acceptor_socket_get_transmit(struct net2_acceptor_socket *s,
    struct net2_buffer **buf,
    struct net2_cw_tx *cwtx, int first, size_t maxlen)
{
	if (s->fn->get_transmit != NULL)
		return (*s->fn->get_transmit)(s, buf, cwtx, first, maxlen);
	else if (s->acceptor != NULL) {
		return net2_acceptor_get_transmit(s->acceptor, buf, cwtx,
		    first, maxlen);
	}
}

/* Make acceptor process received data. */
ILIAS_NET2_EXPORT void
net2_acceptor_accept(struct net2_acceptor *a, struct net2_buffer *buf)
{
	return (*a->fn->accept)(a, buf);
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
 * Returns a pointer to the evbase of this acceptor socket.
 * Does not increment the reference counter.
 */
ILIAS_NET2_EXPORT struct net2_evbase*
net2_acceptor_socket_evbase(struct net2_acceptor_socket *s)
{
	return s->evbase;
}

/*
 * Returns a pointer to the evbase of this acceptor.
 * Does not increment the reference counter.
 */
ILIAS_NET2_EXPORT struct net2_evbase*
net2_acceptor_evbase(struct net2_acceptor *a)
{
	if (a->socket != NULL)
		return net2_acceptor_socket_evbase(a->socket);
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
