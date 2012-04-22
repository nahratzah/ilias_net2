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

struct net2_tx_callback {
	struct net2_txcbq	*queue[4];
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
	    net2_tx_callback_fn, net2_tx_callback_fn, net2_tx_callback_fn,
	    net2_tx_callback_fn, void*, void*);

ILIAS_NET2_EXPORT
int	net2_txcbq_empty(struct net2_tx_callback*);

static __inline int
net2_txcb_empty(struct net2_tx_callback *tx)
{
	unsigned int		 i;

	for (i = 0; i < sizeof(tx->queue) / sizeof(tx->queue[0]); i++) {
		if (tx->queue[i] != NULL)
			return net2_txcbq_empty(tx);
	}
	return 1;
}

#endif /* ILIAS_NET2_TX_CALLBACK_H */
