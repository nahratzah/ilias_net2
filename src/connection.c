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
    struct net2_evbase *evbase,
    const struct net2_acceptor_socket_fn *functions)
{
	memset(conn, 0, sizeof(*conn));

	if (evbase == NULL)
		goto fail_0;
	if (functions == NULL)
		goto fail_1;
	conn->n2c_ctx = ctx;

	conn->n2c_sign.algorithm = 0;
	conn->n2c_sign.key = NULL;
	conn->n2c_sign.keylen = 0;
	conn->n2c_sign.allow_unsigned = 1;

	conn->n2c_enc.algorithm = 0;
	conn->n2c_enc.key = NULL;
	conn->n2c_enc.keylen = 0;
	conn->n2c_enc.allow_unencrypted = 1;

	TAILQ_INIT(&conn->n2c_recvq);
	conn->n2c_recvqsz = 0;

	conn->n2c_stealth_bytes = 0;
	conn->n2c_stealth = 0;

	if (net2_acceptor_socket_init(&conn->n2c_socket, evbase, functions))
		goto fail_0;
	if (net2_cneg_init(&conn->n2c_negotiator))
		goto fail_1;
	if ((conn->n2c_recv_ev = event_new(evbase->evbase, -1, 0,
	    &net2_conn_handle_recv, conn)) == NULL)
		goto fail_2;
	if ((conn->n2c_recvmtx = net2_mutex_alloc()) == NULL)
		goto fail_3;
	if (net2_connwindow_init(&conn->n2c_window, conn))
		goto fail_4;
	if (net2_connstats_init(&conn->n2c_stats, conn))
		goto fail_5;

	return 0;

fail_6:
	net2_connstats_deinit(&conn->n2c_stats);
fail_5:
	net2_connwindow_deinit(&conn->n2c_window);
fail_4:
	net2_mutex_free(conn->n2c_recvmtx);
fail_3:
	event_free(conn->n2c_recv_ev);
fail_2:
	net2_cneg_deinit(&conn->n2c_negotiator);
fail_1:
	net2_acceptor_socket_deinit(&conn->n2c_socket);
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

	net2_acceptor_socket_deinit(&conn->n2c_socket);
	net2_cneg_deinit(&conn->n2c_negotiator);
	net2_connstats_deinit(&conn->n2c_stats);
	net2_connwindow_deinit(&conn->n2c_window);
	event_free(conn->n2c_recv_ev);
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
	TAILQ_INSERT_TAIL(&conn->n2c_recvq, r, recvq);
	conn->n2c_recvqsz++;

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
	/* TODO: inline */
	net2_acceptor_socket_destroy(&conn->n2c_socket);
}


/* Handle each received datagram in receive queue. */
ILIAS_NET2_LOCAL void
net2_conn_handle_recv(int fd, short what, void *cptr)
{
	struct net2_connection	*c = cptr;
	struct net2_conn_receive*r;
	struct packet_header	 ph;
	struct net2_encdec_ctx	 ctx;
	struct net2_buffer	*buf;
	int			 decode_err;
	size_t			 wire_sz;
	int			 error;

	if ((net2_encdec_ctx_newaccsocket(&ctx, &c->n2c_socket)) != 0) {
		warn("net2_encdec_ctx fail");
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
		decode_err = net2_packet_decode(c, &ctx, &ph, &buf, 1);
		switch (decode_err) {
		case NET2_PDECODE_RESOURCE:
			warnx("insufficient resources to process packet");
			break;
		case NET2_PDECODE_BAD:		/* Ignore bad packet. */
		case NET2_PDECODE_UNSAFE:	/* Ignore unsafe packet. */
			break;
		case NET2_PDECODE_WINDOW:	/* Window doesn't want this. */
			c->n2c_stealth_bytes += wire_sz;
			c->n2c_stealth |= NET2_CONN_STEALTH_SEND_OK;
			if (c->n2c_stealth & (NET2_CONN_STEALTH_WANTSEND |
			    NET2_CONN_STEALTH_ENABLED)) {
				net2_acceptor_socket_ready_to_send(
				    &c->n2c_socket);
			}
			break;
		case NET2_PDECODE_OK:
			c->n2c_stealth_bytes += wire_sz;
			c->n2c_stealth |= NET2_CONN_STEALTH_SEND_OK;
			if (c->n2c_stealth & (NET2_CONN_STEALTH_WANTSEND |
			    NET2_CONN_STEALTH_ENABLED)) {
				net2_acceptor_socket_ready_to_send(
				    &c->n2c_socket);
			}

			if (net2_connwindow_update(&c->n2c_window, &ph,
			    buf, wire_sz)) {
				warnx("failed to update window "
				    "-> dropping succesfully decoded datagram");
				/* Kill connection? */
				break;
			}
			if ((error = net2_cneg_accept(&c->n2c_negotiator, &ph,
			    buf)) != 0) {
				warnx("failed to process negotiation "
				    "(%d) -> dropping succefully "
				    "decoded datagram", error);
				/* TODO: kill connection */
				break;
			}
			net2_acceptor_socket_accept(&c->n2c_socket, buf);

			if (net2_cp_destroy(&ctx, &cp_packet_header, &ph,
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

	net2_encdec_ctx_deinit(&ctx);
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
	struct net2_encdec_ctx		 ctx;
	int				 rv = -1;
	size_t				 winoverhead;
	struct net2_cw_tx		*tx;
	int				 want_payload, has_payload;
	int				 negotiation_ready;
	int				 stealth;

	has_payload = 0;
	*bptr = NULL;
	stealth = 0;

	/* Check if stealth mode allows transmission. */
	if ((c->n2c_stealth &
	    (NET2_CONN_STEALTH_ENABLED | NET2_CONN_STEALTH_UNSTEALTH)) ==
	    NET2_CONN_STEALTH_ENABLED) {
		c->n2c_stealth |= NET2_CONN_STEALTH_WANTSEND;
		if (!(c->n2c_stealth & NET2_CONN_STEALTH_SEND_OK))
			goto fail_0;
		maxlen = MIN(c->n2c_stealth_bytes, maxlen);
		stealth = 1;
	}

	winoverhead = net2_connwindow_overhead;
	avail = maxlen - net2_ph_overhead -
	    net2_hash_gethashlen(c->n2c_sign.algorithm) -
	    net2_enc_getoverhead(c->n2c_enc.algorithm);
	if (maxlen < avail)	/* Overflow. */
		goto fail_0;

	if ((b = net2_buffer_new()) == NULL)
		goto fail_0;
	if ((net2_encdec_ctx_newaccsocket(&ctx, &c->n2c_socket)) != 0)
		goto fail_1;

	/* Initialize packet header. */
	ph.flags = 0;
	if (c->n2c_sign.algorithm != 0)
		ph.flags |= PH_ENCRYPTED;
	if (c->n2c_enc.algorithm != 0)
		ph.flags |= PH_SIGNED;
	/* Fill in ph.seq and acquire a transmission context. */
	if ((tx = net2_connwindow_tx_prepare(&c->n2c_window, &ph,
	    &want_payload)) == NULL) {
		net2_encdec_ctx_rollback(&ctx);
		rv = 0;
		goto fail_2;
	}
	/* Don't add payload to stalled state: these packets are not acked. */
	count = 0;
	negotiation_ready = !stealth &&
	    net2_cneg_allow_payload(&c->n2c_negotiator, ph.seq);
	if (ph.flags & PH_STALLED)
		goto write_window_buf;

	/*
	 * Fetch data from negotiator.
	 */
	to_add = NULL;
	if (avail > winoverhead &&
	    (rv = net2_cneg_get_transmit(&c->n2c_negotiator, &ph, &to_add, tx,
	    avail - winoverhead)) != 0)
		goto fail_2;	/* TODO: double check if this is correct. */
	if (to_add != NULL) {
		if (net2_buffer_append(b, to_add)) {
			net2_buffer_free(to_add);
			warnx("buffer_append fail for cneg");
			goto fail_2;
		}
		avail -= net2_buffer_length(to_add);
		net2_buffer_free(to_add);
		has_payload = 1;
	}
	if (!negotiation_ready)
		goto write_window_buf;

fill_up:
	/*
	 * Fetch payload data from acceptor.
	 */
	for (; avail > winoverhead; count++) {
		to_add = NULL;
		/* Get more data from acceptor. */
		if (net2_acceptor_socket_get_transmit(&c->n2c_socket,
		    &to_add, tx, count == 0, avail - winoverhead)) {
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
			net2_buffer_free(to_add);
			warnx("buffer_append fail");
			break;
		}

		/* Acceptor only wants to send a keep-alive. */
		avail -= net2_buffer_length(to_add);
		if (net2_buffer_length(to_add) == 0) {
			net2_buffer_free(to_add);
			break;
		}
		net2_buffer_free(to_add);
		to_add = NULL;
		has_payload = 1;
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
		if (negotiation_ready && !(ph.flags & PH_STALLED))
			goto fill_up;
	}

	/* Nothing to send. */
	if (!has_payload && (want_payload || net2_buffer_empty(b))) {
		/*
		 * Undo transmission: no transmission implies rollback
		 * instead of commit.
		 */
		net2_connwindow_tx_rollback(tx);
		tx = NULL;
		net2_encdec_ctx_rollback(&ctx);

		rv = 0;
		goto fail_2;	/* not a failure: rv has been set to 0. */
	}

	if (count > 0)
		ph.flags |= PH_PAYLOAD;

	if (net2_packet_encode(c, &ctx, &ph, bptr, b))
		goto fail_2;

	/* Succes!. */
	rv = 0;
	/* Deduct from stealth allowance. */
	c->n2c_stealth_bytes -= MIN(c->n2c_stealth_bytes, net2_buffer_length(*bptr));
	c->n2c_stealth &= ~NET2_CONN_STEALTH_SEND_OK;
	c->n2c_stealth |= NET2_CONN_STEALTH_WANTSEND;

fail_2:
	if (tx != NULL) {
		if (rv == 0) {
			net2_connwindow_tx_commit(tx, &ph,
			    net2_buffer_length(b));
		} else
			net2_connwindow_tx_rollback(tx);
	}
	if (rv != 0)
		net2_encdec_ctx_rollback(&ctx);
	net2_encdec_ctx_deinit(&ctx);
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
 * Implementation of get_pvlist.
 */
ILIAS_NET2_EXPORT int
net2_conn_get_pvlist(struct net2_acceptor_socket *c, struct net2_pvlist *pv)
{
	struct net2_connection	*conn = (struct net2_connection*)c;

	return net2_cneg_pvlist(&conn->n2c_negotiator, pv);
}

/*
 * Enable stealth modus.
 *
 * When stealth modus is enabled, communication will be reduced so that
 * an attacker attempting to use this machine as a deflector, will need
 * to send at least as much data as is being deflected towards the real
 * target.
 *
 * - Whenever a packet is received, the code may send exactly one outgoing
 *   packet.
 * - The total number of transmitted bytes will be limited to the number
 *   of received bytes.
 *
 * Once the negotiation has been completed, the stealth mode is disabled
 * and the communication will happen unimpeded.
 */
ILIAS_NET2_EXPORT void
net2_conn_set_stealth(struct net2_connection *c)
{
	c->n2c_stealth |= NET2_CONN_STEALTH_ENABLED;
}
