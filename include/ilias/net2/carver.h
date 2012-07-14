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
#ifndef ILIAS_NET2_CARVER_H
#define ILIAS_NET2_CARVER_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/workq.h>
#include <ilias/net2/config.h>
#include <sys/types.h>
#include <stdint.h>

#ifdef HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include <ilias/net2/bsd_compat/tree.h>
#endif

struct net2_carver_range;	/* Internal. */
struct net2_buffer;		/* From ilias/net2/buffer.h */
struct net2_encdec_ctx;		/* From ilias/net2/encdec_ctx.h */
struct net2_tx_callback;	/* From ilias/net2/tx_callback.h */
struct net2_workq;		/* From ilias/net2/workq.h */

RB_HEAD(net2_carver_ranges, net2_carver_range);

enum net2_carver_type {
	NET2_CARVER_16BIT,
	NET2_CARVER_32BIT,
	NET2_CARVER_INVAL = 0xffffffff
};

/*
 * Carver type.
 *
 * Handles splitting up of buffer and transmitting.
 */
struct net2_carver {
	int			 flags;
	struct net2_carver_ranges
				 ranges;
	size_t			 size;		/* Carver message size. */

	struct net2_promise	*ready;		/* Carver ready promise. */
	struct net2_workq_job	 rts;		/* Ready to send. */
};

/*
 * Combiner type.
 *
 * Reassembles buffer from carver generated messages.
 */
struct net2_combiner {
	int			 flags;
	struct net2_carver_ranges
				 ranges;
	size_t			 expected_size;

	struct net2_promise	*ready;		/* Combiner ready promise. */
};


ILIAS_NET2_EXPORT
enum net2_carver_type	 net2_carver_gettype(struct net2_carver*);
ILIAS_NET2_EXPORT
enum net2_carver_type	 net2_combiner_gettype(struct net2_combiner*);

ILIAS_NET2_EXPORT
int			 net2_carver_init(struct net2_carver*,
			    enum net2_carver_type, struct net2_buffer*);
ILIAS_NET2_EXPORT
void			 net2_carver_deinit(struct net2_carver*);
ILIAS_NET2_EXPORT
int			 net2_combiner_init(struct net2_combiner*,
			    enum net2_carver_type);
ILIAS_NET2_EXPORT
void			 net2_combiner_deinit(struct net2_combiner*);

ILIAS_NET2_EXPORT
int			 net2_carver_is_done(struct net2_carver*);
ILIAS_NET2_EXPORT
int			 net2_combiner_is_done(struct net2_combiner*);
ILIAS_NET2_EXPORT
struct net2_buffer	*net2_combiner_data(struct net2_combiner*);

ILIAS_NET2_EXPORT
int			 net2_carver_get_transmit(struct net2_carver*,
			    struct net2_encdec_ctx*, struct net2_workq*,
			    struct net2_buffer*, struct net2_tx_callback*,
			    size_t);
ILIAS_NET2_EXPORT
int			 net2_combiner_accept(struct net2_combiner*,
			    struct net2_encdec_ctx*, struct net2_buffer*);

/* Set carver ready-to-send callback. */
static __inline void
net2_carver_set_rts(struct net2_carver *c, struct net2_workq *wq,
    net2_workq_cb fn, void *arg0, void *arg1)
{
	net2_workq_deinit_work(&c->rts);
	net2_workq_init_work(&c->rts, wq, fn, arg0, arg1, NET2_WORKQ_PERSIST);
}

/* Retrieve the carver completion promise. */
static __inline struct net2_promise*
net2_carver_prom_ready(struct net2_carver *c)
{
	return c->ready;
}
/* Retrieve the combiner completion promise. */
static __inline struct net2_promise*
net2_combiner_prom_ready(struct net2_combiner *c)
{
	return c->ready;
}

#endif /* ILIAS_NET2_CARVER_H */
