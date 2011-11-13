#include <ilias/net2/connection.h>
#include <ilias/net2/evbase.h>
#include <ilias/net2/context.h>
#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/cp.h>
#include <ilias/net2/packet.h>
#include <ilias/net2/hash.h>
#include <ilias/net2/enc.h>
#include <ilias/net2/types.h>
#include <ilias/net2/mutex.h>
#include <ilias/net2/buffer.h>
#include <bsd_compat/error.h>
#include <bsd_compat/minmax.h>
#include <bsd_compat/secure_random.h>
#include <string.h>
#include <stdlib.h>
#include <event2/event.h>
#include <sys/types.h>
#include <assert.h>

#ifdef WIN32
#include <malloc.h>
#endif


ILIAS_NET2_LOCAL
void		 net2_conn_handle_recv(int, short, void*);


/*
 * Initialize base connection struct.
 *
 * Takes ownership of evbase.
 * Evbase is released on failure.
 */
ILIAS_NET2_EXPORT int
net2_connection_init(struct net2_connection *conn, struct net2_ctx *ctx,
    struct net2_evbase *evbase, const struct net2_conn_functions *functions)
{
	memset(conn, 0, sizeof(*conn));

	if (evbase == NULL)
		goto fail_0;
	net2_evbase_ref(evbase);
	if (functions == NULL)
		goto fail_1;
	conn->n2c_functions = functions;
	conn->n2c_evbase = evbase;
	conn->n2c_ctx = ctx;
	conn->n2c_version = 0;

	conn->n2c_sign.algorithm = 0;
	conn->n2c_sign.key = NULL;
	conn->n2c_sign.keylen = 0;
	conn->n2c_sign.allow_unsigned = 1;

	conn->n2c_enc.algorithm = 0;
	conn->n2c_enc.key = NULL;
	conn->n2c_enc.keylen = 0;
	conn->n2c_enc.allow_unencrypted = 1;

	conn->n2c_acceptor = NULL;
	TAILQ_INIT(&conn->n2c_recvq);
	conn->n2c_recvqsz = 0;

	if ((conn->n2c_recv_ev = event_new(evbase->evbase, -1, 0,
	    &net2_conn_handle_recv, conn)) == NULL)
		goto fail_1;
	if (net2_objmanager_init(conn))
		goto fail_2;
	if (net2_winmanager_init(conn))
		goto fail_3;
	if ((conn->n2c_recvmtx = net2_mutex_alloc()) == NULL)
		goto fail_4;
	if (net2_connwindow_init(&conn->n2c_window, conn))
		goto fail_5;
	if (net2_connstats_init(&conn->n2c_stats, conn))
		goto fail_6;
	if (ctx)
		TAILQ_INSERT_TAIL(&ctx->conn, conn, n2c_ctxconns);

	return 0;

fail_6:
	net2_connwindow_deinit(&conn->n2c_window);
fail_5:
	net2_mutex_free(conn->n2c_recvmtx);
fail_4:
	net2_winmanager_destroy(conn);
fail_3:
	net2_objmanager_destroy(conn);
fail_2:
	event_free(conn->n2c_recv_ev);
fail_1:
	net2_evbase_release(evbase);
fail_0:
	return -1;
}

/*
 * Destroy base connection only.
 * Called by connection specific destruction code.
 */
ILIAS_NET2_EXPORT void
net2_connection_deinit(struct net2_connection *conn)
{
	struct net2_conn_receive	*r;

	if (conn->n2c_acceptor) {
		(*conn->n2c_acceptor->ca_fn->detach)(conn, conn->n2c_acceptor);
		conn->n2c_acceptor = NULL;
	}
	net2_connstats_deinit(&conn->n2c_stats);
	net2_connwindow_deinit(&conn->n2c_window);
	net2_winmanager_destroy(conn);
	net2_objmanager_destroy(conn);
	event_free(conn->n2c_recv_ev);
	net2_evbase_release(conn->n2c_evbase);
	if (conn->n2c_ctx)
		TAILQ_REMOVE(&conn->n2c_ctx->conn, conn, n2c_ctxconns);
	while ((r = TAILQ_FIRST(&conn->n2c_recvq)) != NULL) {
		TAILQ_REMOVE(&conn->n2c_recvq, r, recvq);
		if (r->buf)
			net2_buffer_free(r->buf);
		free(r);
	}

	if (conn->n2c_sign.key) {
		net2_secure_zero(conn->n2c_sign.key, conn->n2c_sign.keylen);
		free(conn->n2c_sign.key);
	}
	if (conn->n2c_enc.key) {
		net2_secure_zero(conn->n2c_enc.key, conn->n2c_enc.keylen);
		free(conn->n2c_enc.key);
	}
	net2_mutex_free(conn->n2c_recvmtx);
}

/*
 * Handle a packet received on a connection.
 * Called by specific implementations of connection.
 *
 * Connection takes ownership of buf and destroys it afterwards.
 */
ILIAS_NET2_EXPORT void
net2_connection_recv(struct net2_connection *conn,
    struct net2_conn_receive *r)
{
	struct timeval now = { 0, 0 };

	/* Argument validation. */
	assert(r != NULL && conn != NULL);

	net2_mutex_lock(conn->n2c_recvmtx);
	if (conn->n2c_recvqsz < 128) {
		TAILQ_INSERT_TAIL(&conn->n2c_recvq, r, recvq);
		conn->n2c_recvqsz++;
	} else {
		if (r->buf)
			net2_buffer_free(r->buf);
		free(r);
	}
	if (!event_pending(conn->n2c_recv_ev, EV_TIMEOUT, NULL)) {
		if (event_add(conn->n2c_recv_ev, &now)) {
			warnx("event_add fail");
			/* TODO: kill connection */
		}
	}
	net2_mutex_unlock(conn->n2c_recvmtx);
}

/* Destroy a connection by invoking its destructor from the dispatch table. */
ILIAS_NET2_EXPORT void
net2_connection_destroy(struct net2_connection *conn)
{
	assert(conn->n2c_functions->destroy);
	(*conn->n2c_functions->destroy)(conn);
}


ILIAS_NET2_EXPORT int
net2_conn_acceptor_attach(struct net2_connection *conn,
    struct net2_conn_acceptor *a)
{
	struct net2_conn_acceptor
				*old;
	int			 rv;

	if (conn == NULL || a == NULL)
		return -1;
	a->ca_conn = conn;
	old = conn->n2c_acceptor;
	conn->n2c_acceptor = NULL;
	rv = a->ca_fn->attach(conn, a);
	if (rv == 0) {
		if (old != NULL)
			(*old->ca_fn->detach)(conn, old);
		conn->n2c_acceptor = a;
	} else
		conn->n2c_acceptor = old;
	return rv;
}

ILIAS_NET2_EXPORT void
net2_conn_acceptor_detach(struct net2_connection *conn,
    struct net2_conn_acceptor *a)
{
	if (conn == NULL || a == NULL)
		return;
	if (conn->n2c_acceptor != a)
		return;

	conn->n2c_acceptor = NULL;
	(*a->ca_fn->detach)(conn, a);
}

/* Handle each received datagram in receive queue. */
ILIAS_NET2_LOCAL void
net2_conn_handle_recv(int fd, short what, void *cptr)
{
	struct net2_connection	*c = cptr;
	struct net2_conn_receive*r;
	struct packet_header	 ph;
	struct net2_encdec_ctx	*ctx;
	struct net2_buffer	*buf;
	int			 decode_err;
	size_t			 wire_sz;

	if ((ctx = net2_encdec_ctx_new(c)) == NULL) {
		warn("net2_encdec_ctx_new fail");
		return;
	}

	net2_mutex_lock(c->n2c_recvmtx);
	while ((r = TAILQ_FIRST(&c->n2c_recvq)) != NULL) {
		assert(c->n2c_recvqsz > 0);
		TAILQ_REMOVE(&c->n2c_recvq, r, recvq);
		c->n2c_recvqsz--;
		net2_mutex_unlock(c->n2c_recvmtx);

		/* TODO: handle r->error */

		if (r->buf == NULL)
			goto release;

		buf = r->buf;
		r->buf = NULL;
		wire_sz = net2_buffer_length(buf);
		decode_err = net2_packet_decode(ctx, &ph, &buf, 1);
		switch (decode_err) {
		case NET2_PDECODE_RESOURCE:
			warnx("insufficient resources to process packet");
			break;
		case NET2_PDECODE_BAD:		/* Ignore bad packet. */
		case NET2_PDECODE_UNSAFE:	/* Ignore unsafe packet. */
		case NET2_PDECODE_WINDOW:	/* Window doesn't want this. */
			break;
		case NET2_PDECODE_OK:
			if (c->n2c_acceptor == NULL) {
				warnx("c->n2c_acceptor = NULL "
				    "-> dropping succesfully decoded datagram");
				break;
			}
			if (net2_connwindow_update(&c->n2c_window, &ph,
			    buf, wire_sz)) {
				warnx("failed to update window "
				    "-> dropping succesfully decoded datagram");
				/* Kill connection? */
				break;
			}
			(*c->n2c_acceptor->ca_fn->accept)(c->n2c_acceptor,
			    &ph, &buf);

			if (net2_cp_destroy(ctx, &cp_packet_header, &ph,
			    NULL))
				warnx("net2_cp_destroy fail");
			break;
		default:
			warnx("net2_packet_decode returned undocumented "
			    "error %d", decode_err);
		}

		if (buf)
			net2_buffer_free(buf);
release:
		free(r);
		net2_mutex_lock(c->n2c_recvmtx);
	}
	net2_mutex_unlock(c->n2c_recvmtx);

	net2_encdec_ctx_release(ctx);
}

/*
 * Gather transmit data from acceptor.
 *
 * On return: if an error occurs, *bptr will be NULL.
 * Otherwise, *bptr will be NULL iff there is no data to send.
 * *bptr will have at most maxlen bytes in it.
 */
ILIAS_NET2_EXPORT int
net2_conn_gather_tx(struct net2_connection *c,
    struct net2_buffer **bptr, size_t maxlen)
{
	struct packet_header		 ph;
	size_t				 avail;
	struct net2_buffer		*b, *to_add;
	struct net2_conn_acceptor	*acceptor;
	size_t				 count;
	struct net2_encdec_ctx		*ctx;
	int				 rv = -1;
	size_t				 winoverhead;
	struct net2_cw_tx		*tx;

	*bptr = NULL;
	winoverhead = net2_connwindow_overhead;
	avail = maxlen - net2_ph_overhead -
	    net2_hash_gethashlen(c->n2c_sign.algorithm) -
	    net2_enc_getoverhead(c->n2c_enc.algorithm);

	if ((acceptor = c->n2c_acceptor) == NULL)
		goto fail_0;
	if ((b = net2_buffer_new()) == NULL)
		goto fail_0;
	if ((ctx = net2_encdec_ctx_new(c)) == NULL)
		goto fail_1;

	/* Initialize packet header. */
	ph.flags = 0;
	if (c->n2c_sign.algorithm != 0)
		ph.flags |= PH_ENCRYPTED;
	if (c->n2c_enc.algorithm != 0)
		ph.flags |= PH_SIGNED;
	/* Fill in ph.seq and acquire a transmission context. */
	if ((tx = net2_connwindow_tx_prepare(&c->n2c_window, &ph)) == NULL)
		goto fail_2;
	/* Don't add payload to stalled state: these packets are not acked. */
	count = 0;
	if (ph.flags & PH_STALLED)
		goto write_window_buf;

fill_up:
	for (; avail > winoverhead; count++) {
		to_add = NULL;
		/* Get more data from acceptor. */
		if (acceptor->ca_fn->get_transmit(acceptor, &to_add, tx,
		    count == 0, avail - winoverhead)) {
			warnx("acceptor get_transmit fail");
			break;
		}

		/* Check if acceptor indeed had more data. */
		if (to_add == NULL)
			break;
		/*
		 * Acceptor may not provide empty buffers,
		 * unless its the first datagram.
		 */
		assert(count == 0 || net2_buffer_length(to_add) > 0);
		assert(net2_buffer_length(to_add) <= avail);

		/* Staple on top of b. */
		if (net2_buffer_append(b, to_add)) {
			/*
			 * We lack an undo operation on the acceptor,
			 * so if this triggers, the acceptor will have to
			 * use its own timeout routines to know of the
			 * failure.
			 */
			warnx("buffer_append fail");
			break;
		}

		/* Acceptor only wants to send a keep-alive. */
		avail -= net2_buffer_length(to_add);
		if (net2_buffer_length(to_add) == 0)
			break;
	}

	/*
	 * Prepend window once.
	 * After that, issue requests for more data to fill up what the window
	 * left over afterwards.
	 */
	if (winoverhead > 0) {
write_window_buf:
		to_add = net2_connwindow_writebuf(&c->n2c_window, &ph, avail);
		if (to_add == NULL)
			goto fail_2;
		avail -= net2_buffer_length(to_add);
		if (net2_buffer_prepend(b, to_add)) {
			net2_buffer_free(to_add);
			goto fail_2;
		}
		net2_buffer_free(to_add);
		winoverhead = 0;
		if (!(ph.flags & PH_STALLED))
			goto fill_up;
	}

	/* Nothing to send. */
	if (net2_buffer_empty(b) && count == 0) {
		/*
		 * Undo transmission: no transmission implies rollback
		 * instead of commit.
		 */
		net2_connwindow_tx_rollback(tx);
		tx = NULL;
		net2_encdec_ctx_rollback(ctx);

		rv = 0;
		goto fail_2;	/* not a failure: rv has been set to 0. */
	}

	if (count > 0)
		ph.flags |= PH_PAYLOAD;

	if (net2_packet_encode(ctx, &ph, bptr, b))
		goto fail_2;

	/* Succes!. */
	rv = 0;

fail_2:
	if (tx != NULL) {
		if (rv == 0)
			net2_connwindow_tx_commit(tx, net2_buffer_length(b));
		else
			net2_connwindow_tx_rollback(tx);
	}
	if (rv != 0)
		net2_encdec_ctx_rollback(ctx);
	net2_encdec_ctx_release(ctx);
fail_1:
	if (b != NULL)
		net2_buffer_free(b);
fail_0:
	if (rv != 0) {
		net2_buffer_free(*bptr);
		*bptr = NULL;
	}
	return rv;
}

/*
 * Inform implementation that the connection has pending data
 * (i.e. needs net2_conn_gather_tx to be executed, followed by a transmit
 * of its result.
 */
ILIAS_NET2_EXPORT void
net2_conn_ready_to_send(struct net2_connection *c)
{
	c->n2c_functions->ready_to_send(c);
}
