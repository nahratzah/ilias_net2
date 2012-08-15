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
#include <ilias/net2/conn_keys.h>
#include <ilias/net2/context.h>
#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/cp.h>
#include <ilias/net2/hash.h>
#include <ilias/net2/enc.h>
#include <ilias/net2/types.h>
#include <ilias/net2/mutex.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/tx_callback.h>
#include <ilias/net2/bsd_compat/error.h>
#include <ilias/net2/bsd_compat/minmax.h>
#include <ilias/net2/bsd_compat/secure_random.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <assert.h>

#ifdef WIN32
#include <malloc.h>
#endif

#include "packet.h"


ILIAS_NET2_LOCAL
void		 net2_conn_handle_recv(void*, void*);


/*
 * Initialize base connection struct.
 */
ILIAS_NET2_EXPORT int
net2_connection_init(struct net2_connection *conn, struct net2_ctx *ctx,
    struct net2_workq *workq,
    const struct net2_acceptor_socket_fn *functions)
{
	int			 error;

	memset(conn, 0, sizeof(*conn));

	TAILQ_INIT(&conn->n2c_recvq);
	TAILQ_INIT(&conn->n2c_sendq);
	conn->n2c_recvqsz = 0;

	conn->n2c_stealth_bytes = 0;
	conn->n2c_stealth = 0;

	if ((error = net2_acceptor_socket_init(&conn->n2c_socket, workq,
	    functions)) != 0)
		goto fail_0;
	if ((error = net2_cneg_init(&conn->n2c_negotiator, ctx)) != 0)
		goto fail_1;
	if ((error = net2_workq_init_work(&conn->n2c_recv_ev, workq,
	    &net2_conn_handle_recv, conn, NULL, 0)) != 0)
		goto fail_2;
	if ((conn->n2c_recvmtx = net2_mutex_alloc()) == NULL) {
		error = ENOMEM;
		goto fail_3;
	}
	if ((conn->n2c_sendmtx = net2_mutex_alloc()) == NULL) {
		error = ENOMEM;
		goto fail_4;
	}
	if ((error = net2_connwindow_init(&conn->n2c_window, conn)) != 0)
		goto fail_5;
	if ((error = net2_connstats_init(&conn->n2c_stats, conn)) != 0)
		goto fail_6;
	if ((error = net2_ck_init(&conn->n2c_keys, workq, conn)) != 0)
		goto fail_7;

	return 0;


fail_8:
	net2_ck_deinit(&conn->n2c_keys);
fail_7:
	net2_connstats_deinit(&conn->n2c_stats);
fail_6:
	net2_connwindow_deinit(&conn->n2c_window);
fail_5:
	net2_mutex_free(conn->n2c_sendmtx);
fail_4:
	net2_mutex_free(conn->n2c_recvmtx);
fail_3:
	net2_workq_deinit_work(&conn->n2c_recv_ev);
fail_2:
	net2_cneg_deinit(&conn->n2c_negotiator);
fail_1:
	net2_acceptor_socket_deinit(&conn->n2c_socket);
fail_0:
	return error;
}

/*
 * Destroy base connection only.
 * Called by connection specific destruction code.
 */
ILIAS_NET2_EXPORT void
net2_connection_deinit(struct net2_connection *conn)
{
	struct net2_conn_receive	*r;

	net2_ck_deinit(&conn->n2c_keys);
	net2_cneg_deinit(&conn->n2c_negotiator);
	net2_connstats_deinit(&conn->n2c_stats);
	net2_connwindow_deinit(&conn->n2c_window);
	net2_workq_deinit_work(&conn->n2c_recv_ev);
	while ((r = TAILQ_FIRST(&conn->n2c_recvq)) != NULL) {
		TAILQ_REMOVE(&conn->n2c_recvq, r, recvq);
		if (r->buf)
			net2_buffer_free(r->buf);
		net2_free(r);
	}

	net2_acceptor_socket_deinit(&conn->n2c_socket);
	net2_mutex_free(conn->n2c_recvmtx);
	net2_mutex_free(conn->n2c_sendmtx);
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
	/* Argument validation. */
	assert(r != NULL && conn != NULL);

	net2_mutex_lock(conn->n2c_recvmtx);
	TAILQ_INSERT_TAIL(&conn->n2c_recvq, r, recvq);
	conn->n2c_recvqsz++;

	net2_workq_activate(&conn->n2c_recv_ev, 0);
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
net2_conn_handle_recv(void *cptr, void *unused ILIAS_NET2__unused)
{
	struct net2_connection	*c = cptr;
	struct net2_conn_receive*r;
	struct packet_header	 ph;
	struct net2_buffer	*buf;
	int			 decode_err;
	size_t			 wire_sz;
	int			 error;

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

		/* Record receival. */
		net2_connstats_record_recv(&c->n2c_stats, wire_sz);

		decode_err = net2_packet_decode(c, &net2_encdec_proto0, &ph,
		    &buf, 1);
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

			if (net2_cp_destroy(&cp_packet_header, &ph, NULL))
				warnx("net2_cp_destroy fail");
			break;
		default:
			warnx("net2_packet_decode returned undocumented "
			    "error %d", decode_err);
		}

		if (buf)
			net2_buffer_free(buf);
release:
		net2_free(r);
		net2_mutex_lock(c->n2c_recvmtx);
	}
	net2_mutex_unlock(c->n2c_recvmtx);
}

/*
 * Gather transmit data from acceptor.
 *
 * On return: if an error occurs, *bptr will be NULL.
 * Otherwise, *bptr will be NULL iff there is no data to send.
 * *bptr will have at most maxlen bytes in it.
 */
static int
gather(struct net2_connection *c, struct net2_buffer **bptr, size_t maxlen)
{
	struct packet_header		 ph;
	size_t				 avail;
	struct net2_buffer		*b, *to_add;
	size_t				 count;
	int				 rv = -1;
	size_t				 winoverhead;
	struct net2_cw_tx		*tx;
	int				 want_payload, has_payload;
	int				 negotiation_ready;
	int				 stealth;
	struct net2_tx_callback		 callbacks;
	net2_ck_keys			*keys;

	has_payload = 0;
	*bptr = NULL;
	stealth = 0;

	/* Check if stealth mode allows transmission. */
	if ((c->n2c_stealth &
	    (NET2_CONN_STEALTH_ENABLED | NET2_CONN_STEALTH_UNSTEALTH)) ==
	    NET2_CONN_STEALTH_ENABLED) {
		c->n2c_stealth |= NET2_CONN_STEALTH_WANTSEND;
		if (!(c->n2c_stealth & NET2_CONN_STEALTH_SEND_OK)) {
			rv = 0;
			goto fail_0;
		}
		maxlen = MIN(c->n2c_stealth_bytes, maxlen);
		stealth = 1;
	}

	/*
	 * Clamp winoverhead if stealth:
	 * otherwise the window update might gobble up the entire packet.
	 */
	if (stealth)
		winoverhead = net2_connwindow_min_overhead;
	else
		winoverhead = net2_connwindow_overhead;

	avail = maxlen - net2_ph_overhead;
	if (maxlen < avail)	/* Overflow. */
		goto fail_0;
	/* Reduce small packet transmission. */
	if (stealth && avail < 128) {
		c->n2c_stealth |= NET2_CONN_STEALTH_WANTSEND;
		rv = 0;
		goto fail_0;
	}

	if ((b = net2_buffer_new()) == NULL)
		goto fail_0;
	if ((rv = net2_txcb_init(&callbacks)) != 0)
		goto fail_1;

	/* Initialize packet header. */
	ph.flags = 0;
	/* Fill in ph.seq and acquire a transmission context. */
	if ((tx = net2_connwindow_tx_prepare(&c->n2c_window, &ph,
	    &want_payload)) == NULL) {
		rv = 0;
		goto fail_2;
	}

	/* Find keys. */
	if (net2_ck_tx_key(&keys, &c->n2c_keys, &c->n2c_window, &ph) != 0)
		goto fail_2;
	if ((*keys)[NET2_CNEG_S2_HASH].alg != 0) {
		ph.flags |= PH_SIGNED;
		avail -= net2_hash_gethashlen((*keys)[NET2_CNEG_S2_HASH].alg);
	}
	if ((*keys)[NET2_CNEG_S2_ENC].alg != 0) {
		ph.flags |= PH_ENCRYPTED;
		avail -= net2_enc_getoverhead((*keys)[NET2_CNEG_S2_ENC].alg);
	}
	if (maxlen < avail)	/* Overflow. */
		goto fail_2;	/* TODO: double check if this is correct. */

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
	    (rv = net2_cneg_get_transmit(&c->n2c_negotiator, &ph, &to_add,
	    &callbacks, avail - winoverhead, stealth, want_payload)) != 0)
		goto fail_2;	/* TODO: double check if this is correct. */
	if (to_add != NULL) {
		assert(!net2_buffer_empty(to_add));
		if (net2_buffer_append(b, to_add)) {
			rv = ENOMEM;
			net2_buffer_free(to_add);
			warnx("buffer_append fail for cneg");
			goto fail_2;
		}
		avail -= net2_buffer_length(to_add);
		net2_buffer_free(to_add);
		has_payload = 1;
	}
	if (!negotiation_ready) {
		if (want_payload && !has_payload) {
			rv = 0; /* Not an error, just no data to read. */
			goto fail_2;
		}
		goto write_window_buf;
	}

fill_up:
	/*
	 * Fetch payload data from acceptor.
	 */
	for (; avail > winoverhead; count++) {
		to_add = NULL;
		/* Get more data from acceptor. */
		if (net2_acceptor_socket_get_transmit(&c->n2c_socket,
		    &to_add, &callbacks, count == 0, avail - winoverhead)) {
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
		net2_txcb_nack(&callbacks);
		tx = NULL;

		rv = 0;
		goto fail_2;	/* not a failure: rv has been set to 0. */
	}

	if (count > 0)
		ph.flags |= PH_PAYLOAD;

	if (net2_packet_encode(c, &net2_encdec_proto0, &ph, bptr, b, keys))
		goto fail_2;

	/* Succes!. */
	rv = 0;
	/* Deduct from stealth allowance. */
	c->n2c_stealth_bytes -= MIN(c->n2c_stealth_bytes, net2_buffer_length(*bptr));
	c->n2c_stealth &= ~NET2_CONN_STEALTH_SEND_OK;
	c->n2c_stealth |= NET2_CONN_STEALTH_WANTSEND;

	/* Record transmission. */
	net2_connstats_record_transmit(&c->n2c_stats,
	    net2_buffer_length(*bptr));

fail_2:
	if (tx != NULL) {
		if (rv == 0) {
			net2_connwindow_tx_commit(tx, &ph,
			    net2_buffer_length(b), &callbacks);
		} else {
			net2_connwindow_tx_rollback(tx);
			net2_txcb_nack(&callbacks);
		}
	}
	assert(net2_txcb_empty(&callbacks));
	net2_txcb_deinit(&callbacks);
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

struct net2_conn_txgather {
	TAILQ_ENTRY(net2_conn_txgather)
				 queue;
	size_t			 maxlen;
	struct net2_promise	*prom;
	struct net2_promise_event
				 prom_ev;
};

/* Free buffer on promise. */
static void
buffree2(void *buf, void * unused ILIAS_NET2__unused)
{
	net2_free((struct net2_buffer*)buf);
}
/* Destroy gather data. */
static void
txgather_destroy(void *c_ptr, void *gd_ptr)
{
	struct net2_connection		*c = c_ptr;
	struct net2_conn_txgather	*gd = gd_ptr;

	/*
	 * Don't destroy prom: its destruction is the reason the destructor
	 * got called.
	 */
	net2_promise_event_deinit(&gd->prom_ev);

	/* Remove from connection. */
	net2_mutex_lock(c->n2c_sendmtx);
	TAILQ_REMOVE(&c->n2c_sendq, gd, queue);
	net2_mutex_unlock(c->n2c_sendmtx);

	net2_free(gd);
}
/* Invoke connection data gathering. */
static void
txgather_invoke(void *c_ptr, void *gd_ptr)
{
	struct net2_connection		*c = c_ptr;
	struct net2_conn_txgather	*gd = gd_ptr;
	struct net2_buffer		*buf = NULL;
	int				 error;

	/* Don't do any work if the promise was canceled. */
	if (net2_promise_is_cancelreq(gd->prom)) {
		net2_promise_set_cancel(gd->prom, 0);
		goto out;
	}

	/* Invoke actual gathering of data. */
	if ((error = gather(c, &buf, gd->maxlen)) != 0) {
		net2_promise_set_error(gd->prom, error, 0);
		return;
	} else if (buf == NULL) {
		/* If there is no data, pretend we were canceled. */
		net2_promise_set_cancel(gd->prom, 0);
		goto out;
	}

	/* Assign buffer as output. */
	if (net2_promise_set_finok(gd->prom, buf, buffree2, NULL, 0)) {
		net2_buffer_free(buf);
		net2_promise_set_error(gd->prom, EIO, 0);
		goto out;
	}

	/* We succesfully acquired a packet,
	 * invoke wantsend to get asked again. */
	net2_acceptor_socket_ready_to_send(&c->n2c_socket);

	/*
	 * Destroy gd.
	 */

out:
	/* Cancel promise bound destruction. */
	net2_promise_destroy_cb(gd->prom, NULL, NULL, NULL);
	/* Remove gd from connection. */
	net2_mutex_lock(c->n2c_sendmtx);
	TAILQ_REMOVE(&c->n2c_sendq, gd, queue);
	net2_mutex_unlock(c->n2c_sendmtx);
	/* Destroy event callback (aka this function). */
	net2_promise_event_deinit(&gd->prom_ev);
	net2_free(gd);
}

/*
 * Yield a promise that will generate the to-be-transmitted datagram.
 */
ILIAS_NET2_EXPORT struct net2_promise*
net2_conn_gather_tx(struct net2_connection *c, size_t maxlen)
{
	struct net2_conn_txgather	*gd;
	int				 error;

	if ((gd = net2_malloc(sizeof(*gd))) == NULL)
		return NULL;

	gd->prom = net2_promise_new();
	gd->maxlen = maxlen;
	if ((error = net2_promise_event_init(&gd->prom_ev, gd->prom,
	    NET2_PROM_ON_RUN, net2_acceptor_socket_workq(&c->n2c_socket),
	    &txgather_invoke, c, gd)) != 0) {
		net2_promise_cancel(gd->prom);
		net2_promise_release(gd->prom);
		net2_free(gd);
		return NULL;
	}
	net2_promise_destroy_cb(gd->prom, &txgather_destroy, c, gd);

	/* Attach to connection. */
	net2_mutex_lock(c->n2c_sendmtx);
	TAILQ_INSERT_TAIL(&c->n2c_sendq, gd, queue);
	net2_mutex_unlock(c->n2c_sendmtx);

	return gd->prom;
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
