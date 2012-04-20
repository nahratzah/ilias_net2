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
#ifndef ILIAS_NET2_ACCEPTOR_H
#define ILIAS_NET2_ACCEPTOR_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/tx_callback.h>
#include <sys/types.h>
#include <stdint.h>
#include <errno.h>

struct net2_acceptor_socket;
struct net2_acceptor;
struct net2_buffer;	/* From ilias/net2/buffer.h */
struct net2_tx_callback; /* From ilias/net2/tx_callback.h */
struct net2_pvlist;	/* From ilias/net2/protocol.h */

/* Acceptor socket function table. */
struct net2_acceptor_socket_fn {
	int	 flags;			/* Acceptor socket flags. */
#define NET2_SOCKET_RELIABLE	0x01	/* Reliable transmission: each
					 * datagram will arrive exactly
					 * once. */
#define NET2_SOCKET_SEQUENTIAL	0x02	/* Sequential delivery: each
					 * datagram will arrive in the
					 * order they were provided. */
#define NET2_SOCKET_SECURE	0x10	/* Socket is secure: communication
					 * is protected from tampering
					 * and eavesdropping.
					 *
					 * This is commonly implemented by
					 * a connection negotiating signing
					 * and encryption, but as an
					 * alternative, a loopback connection
					 * could be marked as secure. */

	/* Destructor. */
	void	(*destroy)(struct net2_acceptor_socket*);
	/* Mark acceptor socket as having data ready. */
	void	(*ready_to_send)(struct net2_acceptor_socket*);

	/* Optional accept processor. */
	void	(*accept)(struct net2_acceptor_socket*, struct net2_buffer*);
	/* Optional get_transmit processor. */
	int	(*get_transmit)(struct net2_acceptor_socket*,
		    struct net2_buffer**,
		    struct net2_tx_callback*, int first, size_t maxlen);

	/* Acquire PVlist. */
	int	(*get_pvlist)(struct net2_acceptor_socket*,
		    struct net2_pvlist*);
};

/* Acceptor function table. */
struct net2_acceptor_fn {
	/* Detach function. */
	void	(*detach)(struct net2_acceptor_socket*, struct net2_acceptor*);
	/* Attach function. */
	int	(*attach)(struct net2_acceptor_socket*, struct net2_acceptor*);
	/* Datagram acceptor. */
	void	(*accept)(struct net2_acceptor*, struct net2_buffer*);
	/* Check if the acceptor has pending transmissions. */
	int	(*get_transmit)(struct net2_acceptor*, struct net2_buffer**,
		    struct net2_tx_callback*, int first, size_t maxlen);
};

/*
 * Acceptor socket.
 *
 * Holds on to a single acceptor.
 * Interfaces with that acceptor.
 */
struct net2_acceptor_socket {
	const struct net2_acceptor_socket_fn
				*fn;		/* Implementation functions. */
	struct net2_acceptor	*acceptor;	/* Current acceptor. */
	struct net2_workq	*workq;		/* Workq. */
};

/*
 * Acceptor.
 *
 * Generates messages to send and processes received messages.
 */
struct net2_acceptor {
	const struct net2_acceptor_fn
				*fn;		/* Acceptor function table. */
	struct net2_acceptor_socket
				*socket;	/* Socket implementation. */
};


ILIAS_NET2_EXPORT
int	 net2_acceptor_socket_init(struct net2_acceptor_socket*,
	    struct net2_workq*, const struct net2_acceptor_socket_fn*);
ILIAS_NET2_EXPORT
void	 net2_acceptor_socket_deinit(struct net2_acceptor_socket*);
ILIAS_NET2_EXPORT
void	 net2_acceptor_socket_destroy(struct net2_acceptor_socket*);
ILIAS_NET2_EXPORT
int	 net2_acceptor_attach(struct net2_acceptor_socket*,
	    struct net2_acceptor*);
ILIAS_NET2_EXPORT
void	 net2_acceptor_detach(struct net2_acceptor_socket*);
ILIAS_NET2_EXPORT
void	 net2_acceptor_socket_ready_to_send(struct net2_acceptor_socket*);
ILIAS_NET2_EXPORT
void	 net2_acceptor_ready_to_send(struct net2_acceptor*);
ILIAS_NET2_EXPORT
int	 net2_acceptor_get_transmit(struct net2_acceptor*,
	    struct net2_buffer**, struct net2_tx_callback*, int, size_t);
ILIAS_NET2_EXPORT
int	 net2_acceptor_socket_get_transmit(struct net2_acceptor_socket*,
	    struct net2_buffer**, struct net2_tx_callback*, int, size_t);
ILIAS_NET2_EXPORT
void	 net2_acceptor_accept(struct net2_acceptor*, struct net2_buffer*);
ILIAS_NET2_EXPORT
void	 net2_acceptor_socket_accept(struct net2_acceptor_socket*,
	    struct net2_buffer*);
ILIAS_NET2_EXPORT
int	 net2_acceptor_init(struct net2_acceptor*,
	    const struct net2_acceptor_fn*);
ILIAS_NET2_EXPORT
void	 net2_acceptor_deinit(struct net2_acceptor*);

ILIAS_NET2_EXPORT
int	 net2_acceptor_pvlist(struct net2_acceptor*, struct net2_pvlist*);
ILIAS_NET2_EXPORT
int	 net2_acceptor_socket_pvlist(struct net2_acceptor_socket*,
	    struct net2_pvlist*);
ILIAS_NET2_EXPORT
struct net2_workq
	*net2_acceptor_socket_workq(struct net2_acceptor_socket*);
ILIAS_NET2_EXPORT
struct net2_workq
	*net2_acceptor_workq(struct net2_acceptor*);

ILIAS_NET2_EXPORT
struct net2_acceptor_socket
	*net2_acceptor_socket(struct net2_acceptor*);
ILIAS_NET2_EXPORT
struct net2_acceptor
	*net2_acceptor(struct net2_acceptor_socket*);

#endif /* ILIAS_NET2_ACCEPTOR_H */
