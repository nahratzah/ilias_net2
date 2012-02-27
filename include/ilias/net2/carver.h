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
struct net2_cw_tx;		/* From ilias/net2/connection.h */

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
#define NET2_CARVER_F_16BIT	0x00000000	/* 16 bit carver. */
#define NET2_CARVER_F_32BIT	0x00000001	/* 32 bit carver. */
#define NET2_CARVER_F_BITS	0x0000000f	/* Carver bit mask. */
#define NET2_CARVER_F_KNOWN_SZ	0x00000010	/* Expected size is knwon. */

	struct net2_carver_ranges
				 ranges;
	size_t			 size;		/* Carver message size. */
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
			    struct net2_encdec_ctx*, struct net2_buffer*,
			    struct net2_cw_tx*, size_t);
ILIAS_NET2_EXPORT
int			 net2_combiner_accept(struct net2_combiner*,
			    struct net2_encdec_ctx*, struct net2_buffer*);

#endif /* ILIAS_NET2_CARVER_H */
