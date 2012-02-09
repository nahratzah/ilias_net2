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
#ifndef ILIAS_NET2_CONNECTION_H
#define ILIAS_NET2_CONNECTION_H

#include <ilias/net2/types.h>
#include <ilias/net2/connstats.h>
#include <ilias/net2/connwindow.h>
#include <ilias/net2/conn_negotiator.h>
#include <ilias/net2/acceptor.h>

struct packet_header;

/*
 * A net2_connection receive datagram.
 *
 * Iff error is set, buf is NULL.
 * Iff buf is set, error is OK (no error).
 */
struct net2_conn_receive {
	/* Buffer that is received. */
	struct net2_buffer	*buf;
	/* Error that is received. */
	int			 error;

#define NET2_CONNRECV_OK	0	/* No error, buf is set. */
#define NET2_CONNRECV_REJECT	1	/* Connection closed.
					 * - host down
					 * - host unreachable
					 * - network unreachable
					 * - connection refused
					 * - not connected
					 */

	TAILQ_ENTRY(net2_conn_receive)
				 recvq;	/* Link into connection receive list. */
};

/* Basic properties of a connection. */
struct net2_connection {
	struct net2_acceptor_socket
				 n2c_socket;	/* Acceptor socket base. */
	struct net2_conn_negotiator
				 n2c_negotiator; /* Protocol negotiator. */

	struct net2_ctx		*n2c_ctx;	/* Network context. */

	TAILQ_ENTRY(net2_connection)
				 n2c_ctxconns;	/* Link into context. */

	struct net2_mutex	*n2c_recvmtx;	/* Protect recvq. */
	TAILQ_HEAD(, net2_conn_receive)
				 n2c_recvq;	/* List of received data. */
	size_t			 n2c_recvqsz;	/* Size of n2c_recvq. */
	struct event		*n2c_recv_ev;	/* Handle received data. */

	struct {
		int		 algorithm;	/* Signing algorithm. */
		void		*key;		/* Signing key. */
		size_t		 keylen;	/* Signing key length. */
		int		 allow_unsigned;/* Allow unsigned packets.
						 * Turned off on the first
						 * signed packet. */
	}			 n2c_sign;	/* Signing algorithm. */

	struct {
		int		 algorithm;	/* Signing algorithm. */
		void		*key;		/* Signing key. */
		size_t		 keylen;	/* Signing key length. */
		int		 allow_unencrypted;
						/* Allow unencrypted packets.
						 * Turned off on the first
						 * encrypted packet. */
	}			 n2c_enc;	/* Signing algorithm. */

	struct net2_connwindow	 n2c_window;	/* Low level window. */
	struct net2_connstats	 n2c_stats;	/* Connection stats. */

	/* XXX more members as required. */
};


ILIAS_NET2_EXPORT
int	net2_connection_init(struct net2_connection*,
	    struct net2_ctx*, struct net2_evbase*,
	    const struct net2_acceptor_socket_fn*);
ILIAS_NET2_EXPORT
void	net2_connection_deinit(struct net2_connection*);
ILIAS_NET2_EXPORT
void	net2_connection_destroy(struct net2_connection*);
ILIAS_NET2_EXPORT
void	net2_connection_recv(struct net2_connection*,
	    struct net2_conn_receive*);

ILIAS_NET2_EXPORT
int	net2_conn_gather_tx(struct net2_connection*,
	    struct net2_buffer**, size_t);
ILIAS_NET2_EXPORT
int	net2_conn_get_pvlist(struct net2_acceptor_socket*,
	    struct net2_pvlist*);

#endif /* ILIAS_NET2_CONNECTION_H */
