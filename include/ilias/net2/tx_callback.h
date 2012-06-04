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
#ifndef ILIAS_NET2_TX_CALLBACK_H
#define ILIAS_NET2_TX_CALLBACK_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/workq.h>
#include <ilias/net2/config.h>
#include <stdlib.h>

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <ilias/net2/bsd_compat/queue.h>
#endif

struct net2_workq;	/* From ilias/net2/workq.h */

typedef void (*net2_tx_callback_fn)(void*, void*);

/*
 * Optional entry queue.
 *
 * Can be used to cancel outstanding txcb.
 */
struct net2_txcb_entryq {
	struct net2_mutex	*mtx;
	TAILQ_HEAD(, net2_txcb_entry)
				 entries;
};

/* TX callbacks. */
struct net2_tx_callback {
	struct net2_mutex	*mtx;
	TAILQ_HEAD(, net2_txcb_entry)
				 entries;
};


ILIAS_NET2_EXPORT
int	net2_txcb_init(struct net2_tx_callback*);
ILIAS_NET2_EXPORT
void	net2_txcb_deinit(struct net2_tx_callback*);
ILIAS_NET2_EXPORT
void	net2_txcb_ack(struct net2_tx_callback*);
ILIAS_NET2_EXPORT
void	net2_txcb_nack(struct net2_tx_callback*);
ILIAS_NET2_EXPORT
void	net2_txcb_timeout(struct net2_tx_callback*);
ILIAS_NET2_EXPORT
void	net2_txcb_merge(struct net2_tx_callback*, struct net2_tx_callback*);
ILIAS_NET2_EXPORT
int	net2_txcb_add(struct net2_tx_callback*, struct net2_workq*,
	    struct net2_txcb_entryq*,
	    net2_tx_callback_fn, net2_tx_callback_fn, net2_tx_callback_fn,
	    net2_tx_callback_fn, void*, void*);

ILIAS_NET2_EXPORT
int	 net2_txcb_entryq_init(struct net2_txcb_entryq*);
ILIAS_NET2_EXPORT
void	 net2_txcb_entryq_deinit(struct net2_txcb_entryq*);
ILIAS_NET2_EXPORT
int	 net2_txcb_entryq_empty(struct net2_txcb_entryq*);
ILIAS_NET2_EXPORT
void	 net2_txcb_entryq_clear(struct net2_txcb_entryq*, int which);
ILIAS_NET2_EXPORT
void	 net2_txcb_entryq_merge(struct net2_txcb_entryq*,
	    struct net2_txcb_entryq*);

#define NET2_TXCB_EQ_TIMEOUT	0x00000001
#define NET2_TXCB_EQ_ACK	0x00000002
#define NET2_TXCB_EQ_NACK	0x00000004
#define NET2_TXCB_EQ_DESTROY	0x00000008
#define NET2_TXCB_EQ_ALL						\
	(NET2_TXCB_EQ_TIMEOUT |						\
	 NET2_TXCB_EQ_ACK |						\
	 NET2_TXCB_EQ_NACK |						\
	 NET2_TXCB_EQ_DESTROY)

ILIAS_NET2_EXPORT
int	net2_txcb_empty(struct net2_tx_callback*);

#endif /* ILIAS_NET2_TX_CALLBACK_H */
