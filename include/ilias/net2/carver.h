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
#include <bsd_compat/bsd_compat.h>
#include <sys/types.h>
#include <stdint.h>

#ifdef HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include <bsd_compat/tree.h>
#endif

struct net2_carver_range;	/* Internal. */
struct net2_buffer;		/* From ilias/net2/buffer.h */
struct net2_encdec_ctx;		/* From ilias/net2/encdec_ctx.h */
struct net2_tx_callback;	/* From ilias/net2/tx_callback.h */
struct net2_evbase;		/* From ilias/net2/evbase.h */

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

	void			(*rts_fn)(void*, void*);
						/* Ready-to-send callback. */
	void			*rts_arg0;	/* Argument 1 to rts_fn. */
	void			*rts_arg1;	/* Argument 2 to rts_fn. */

	void			(*ready_fn)(void*, void*);
						/* Carver ready callback. */
	void			*ready_arg0;	/* Argument 1 to ready_fn. */
	void			*ready_arg1;	/* Argument 2 to ready_fn. */
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

	void			(*ready_fn)(void*, void*);
						/* Combiner ready callback. */
	void			*ready_arg0;	/* Argument 1 to ready_fn. */
	void			*ready_arg1;	/* Argument 2 to ready_fn. */
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
			    struct net2_encdec_ctx*, struct net2_evbase*,
			    struct net2_buffer*, struct net2_tx_callback*,
			    size_t);
ILIAS_NET2_EXPORT
int			 net2_combiner_accept(struct net2_combiner*,
			    struct net2_encdec_ctx*, struct net2_buffer*);

/* Set carver ready-to-send callback. */
static __inline void
net2_carver_set_rts(struct net2_carver *c, void (*fn)(void*, void*),
    void *arg0, void *arg1)
{
	c->rts_fn = fn;
	c->rts_arg0 = arg0;
	c->rts_arg1 = arg1;
}

/* Set carver ready callback. */
static __inline void
net2_carver_set_ready(struct net2_carver *c, void (*fn)(void*, void*),
    void *arg0, void *arg1)
{
	c->ready_fn = fn;
	c->ready_arg0 = arg0;
	c->ready_arg1 = arg1;
}

/* Set Combiner ready callback. */
static __inline void
net2_combiner_set_ready(struct net2_combiner *c, void (*fn)(void*, void*),
    void *arg0, void *arg1)
{
	c->ready_fn = fn;
	c->ready_arg0 = arg0;
	c->ready_arg1 = arg1;
}

#endif /* ILIAS_NET2_CARVER_H */
