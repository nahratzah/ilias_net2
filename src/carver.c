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
#include <ilias/net2/carver.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/cp.h>
#include <ilias/net2/connwindow.h>
#include <bsd_compat/bsd_compat.h>
#include <assert.h>
#include <errno.h>

#ifdef HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include <bsd_compat/tree.h>
#endif

#include "carver_msg.h"


struct net2_carver_range {
	RB_ENTRY(net2_carver_range)
				 tree;		/* Link into tree. */

	size_t			 offset;	/* Offset of this range. */
	struct net2_buffer	*data;		/* Data in this range. */
	int			 flags;		/* State flags. */

/* Carver only flags. */
#define RANGE_TRANSMITTED	0x00010000	/* Range is on the wire. */
#define RANGE_DETACHED		0x00020000	/* Carver was destroyed. */
};

/* Flags shared by carver and combiner. */
#define NET2_CARVER_F_16BIT	0x00000000	/* 16 bit carver. */
#define NET2_CARVER_F_32BIT	0x00000001	/* 32 bit carver. */
#define NET2_CARVER_F_BITS	0x0000000f	/* Carver bit mask. */
#define NET2_CARVER_F_KNOWN_SZ	0x00000010	/* Expected size is knwon. */

/* Carver only flags. */
#define NET2_CARVER_F_SZ_TX	0x00010000	/* Size is on wire. */


static __inline int
carver_range_cmp(struct net2_carver_range *r1, struct net2_carver_range *r2)
{
	return (r1->offset < r2->offset ? -1 : r1->offset > r2->offset);
}

RB_PROTOTYPE_STATIC(net2_carver_ranges, net2_carver_range, tree, carver_range_cmp);
RB_GENERATE_STATIC(net2_carver_ranges, net2_carver_range, tree, carver_range_cmp);


static int	 carver_range_to_msg(struct net2_carver*,
		    struct net2_carver_range*, struct net2_encdec_ctx*,
		    struct net2_buffer*);
static int	 carver_setup_msg(struct net2_carver*, struct net2_encdec_ctx*,
		    struct net2_buffer*);
static int	 carver_range_split(struct net2_carver*,
		    struct net2_carver_range*, size_t);

static int	 combiner_msg_to_range(struct net2_combiner*,
		    struct net2_carver_range*, struct net2_encdec_ctx*,
		    struct net2_buffer*);
static int	 combiner_setup_msg(struct net2_combiner*,
		    struct net2_encdec_ctx*, struct net2_buffer*);
static int	 combiner_msg_combine(struct net2_combiner*,
		    struct net2_carver_range*);
static struct net2_buffer
		*combiner_data(struct net2_combiner*);

static enum net2_carver_type
		 flags_to_type(int);

static void	carver_txcb_ack(void*, void*);
static void	carver_txcb_nack(void*, void*);
#define carver_txcb_destroy	carver_txcb_nack
static void	carver_setup_ack(void*, void*);
static void	carver_setup_nack(void*, void*);


/* Return the type of carver. */
ILIAS_NET2_EXPORT enum net2_carver_type
net2_carver_gettype(struct net2_carver *c)
{
	return flags_to_type(c->flags);
}

/* Return the type of combiner. */
ILIAS_NET2_EXPORT enum net2_carver_type
net2_combiner_gettype(struct net2_combiner *c)
{
	return flags_to_type(c->flags);
}

/* Initialize carver. */
ILIAS_NET2_EXPORT int
net2_carver_init(struct net2_carver *c, enum net2_carver_type type,
    struct net2_buffer *data)
{
	size_t			 maxbyte;
	struct net2_carver_range*r;

	if (c == NULL || data == NULL)
		return EINVAL;

	c->flags = 0;
	RB_INIT(&c->ranges);
	c->size = net2_buffer_length(data);

	switch (type) {
	case NET2_CARVER_16BIT:
		c->flags |= NET2_CARVER_F_16BIT;
		maxbyte = 0xffffU;
		break;
	case NET2_CARVER_32BIT:
		c->flags |= NET2_CARVER_F_32BIT;
		maxbyte = 0xffffffffU;
		break;
	default:
		return EINVAL;
	}

	/* Entire data must fit in the carver transport messages. */
	if (c->size != 0 && c->size - 1U > maxbyte)
		return EINVAL;

	/* Create ranges in carver. */
	if (!net2_buffer_empty(data)) {
		if ((r = net2_malloc(sizeof(*r))) == NULL)
			return ENOMEM;
		r->offset = 0;
		r->flags = 0;
		if ((r->data = net2_buffer_copy(data)) == NULL) {
			net2_free(r);
			return ENOMEM;
		}
		RB_INSERT(net2_carver_ranges, &c->ranges, r);
	}

	return 0;
}

/* Release carver resources. */
ILIAS_NET2_EXPORT void
net2_carver_deinit(struct net2_carver *c)
{
	struct net2_carver_range*r;

	while ((r = RB_ROOT(&c->ranges)) != NULL) {
		RB_REMOVE(net2_carver_ranges, &c->ranges, r);

		if (r->flags & RANGE_TRANSMITTED) {
			/* Callback must perform cleanup. */
			r->flags |= RANGE_DETACHED;
		} else {
			if (r->data)
				net2_buffer_free(r->data);
			net2_free(r);
		}
	}
}

/* Initialize combiner. */
ILIAS_NET2_EXPORT int
net2_combiner_init(struct net2_combiner *c, enum net2_carver_type type)
{
	c->flags = 0;
	RB_INIT(&c->ranges);

	switch (type) {
	case NET2_CARVER_16BIT:
		c->flags |= NET2_CARVER_F_16BIT;
		break;
	case NET2_CARVER_32BIT:
		c->flags |= NET2_CARVER_F_32BIT;
		break;
	default:
		return EINVAL;
	}

	return 0;
}

/* Release combiner resources. */
ILIAS_NET2_EXPORT void
net2_combiner_deinit(struct net2_combiner *c)
{
	struct net2_carver_range*r;

	while ((r = RB_ROOT(&c->ranges)) != NULL) {
		RB_REMOVE(net2_carver_ranges, &c->ranges, r);
		if (r->data)
			net2_buffer_free(r->data);
		net2_free(r);
	}
}

/* Test if the carver has sent all data. */
ILIAS_NET2_EXPORT int
net2_carver_is_done(struct net2_carver *c)
{
	return (c->flags & NET2_CARVER_F_KNOWN_SZ) && RB_EMPTY(&c->ranges);
}

/* Test if the combiner has received all data. */
ILIAS_NET2_EXPORT int
net2_combiner_is_done(struct net2_combiner *c)
{
	struct net2_carver_range*root;

	/* Return false if expected size has not been initialized. */
	if (!(c->flags & NET2_CARVER_F_KNOWN_SZ))
		return 0;

	/* Empty data completes as soon as size message was received. */
	if (c->expected_size == 0)
		return 1;

	/*
	 * The combiner is not complete until the range tree contains exactly
	 * one node.
	 */
	root = RB_ROOT(&c->ranges);
	if (root == NULL || RB_LEFT(root, tree) != NULL || RB_RIGHT(root, tree) != NULL)
		return 0;

	/* Root must span the entire data to have completed. */
	return root->offset == 0 &&
	    c->expected_size == net2_buffer_length(root->data);
}

/* Return the combiner data, if the combiner completed. */
ILIAS_NET2_EXPORT struct net2_buffer*
net2_combiner_data(struct net2_combiner *c)
{
	struct net2_carver_range*root;

	if (!net2_combiner_is_done(c))
		return NULL;
	if (c->expected_size == 0)
		return net2_buffer_new();

	root = RB_ROOT(&c->ranges);
	assert(root != NULL && root->offset == 0);
	return net2_buffer_copy(root->data);
}


/*
 * Stores a transmit message in the buffer, that will be at most maxsz bytes.
 */
ILIAS_NET2_EXPORT int
net2_carver_get_transmit(struct net2_carver *c, struct net2_encdec_ctx *ctx,
    struct net2_evbase *evbase,
    struct net2_buffer *out, struct net2_cw_tx *tx, size_t maxsz)
{
	size_t			 setup_overhead;
	size_t			 msg_overhead;
	struct net2_carver_range*r;
	int			 error;
	struct carver_msg_header header;

	if (out == NULL || !net2_buffer_empty(out))
		return EINVAL;

	/* Figure out overhead. */
	switch (c->flags & NET2_CARVER_F_BITS) {
	default:
		return EINVAL;
	case NET2_CARVER_F_16BIT:
		setup_overhead = OVERHEAD_HEADER + OVERHEAD16_SETUP;
		msg_overhead = OVERHEAD_HEADER + OVERHEAD16_MSG;
		break;
	case NET2_CARVER_F_32BIT:
		setup_overhead = OVERHEAD_HEADER + OVERHEAD32_SETUP;
		msg_overhead = OVERHEAD_HEADER + OVERHEAD32_MSG;
		break;
	}

	header.reserved = 0;
	/* Setup message fits and is untransmitted, so send it now. */
	if (!(c->flags & NET2_CARVER_F_SZ_TX) && maxsz >= setup_overhead) {
		/* Encode header for SETUP. */
		header.msg_type = CARVER_MSGTYPE_SETUP;
		if ((error = net2_cp_encode(ctx, &cp_carver_msg_header, out,
		    &header, NULL)) != 0)
			return error;

		if ((error = carver_setup_msg(c, ctx, out)) != 0)
			return error;
		/* Install callback. */
		if ((error = net2_connwindow_txcb_register(tx, evbase, NULL,
		    &carver_setup_ack, &carver_setup_nack, NULL,
		    c, NULL)) != 0)
			return error;

		c->flags |= NET2_CARVER_F_SZ_TX;
		return 0;
	}

	/* Find untransmitted message. */
	RB_FOREACH(r, net2_carver_ranges, &c->ranges) {
		if (!(r->flags & RANGE_TRANSMITTED))
			break;
	}
	/* Nothing to send. */
	if (r == NULL)
		return 0;

	/* Encode header for DATA. */
	header.msg_type = CARVER_MSGTYPE_DATA;
	if ((error = net2_cp_encode(ctx, &cp_carver_msg_header, out,
	    &header, NULL)) != 0)
		return error;

	if ((error = carver_range_split(c, r,
	    maxsz - msg_overhead)) != 0)
		return error;
	if ((error = carver_range_to_msg(c, r, ctx, out)) != 0)
		return error;

	/* Install callback. */
	if ((error = net2_connwindow_txcb_register(tx, evbase, NULL,
	    &carver_txcb_ack, &carver_txcb_nack, &carver_txcb_destroy,
	    c, r)) != 0)
		return error;

	r->flags |= RANGE_TRANSMITTED;
	return 0;
}

/* Accept a message for the combiner. */
ILIAS_NET2_EXPORT int
net2_combiner_accept(struct net2_combiner *c, struct net2_encdec_ctx *ctx,
    struct net2_buffer *in)
{
	int			 error;
	struct carver_msg_header header;
	uint32_t		 msg_type;
	struct net2_carver_range*r;

	/* Decode header to read message type. */
	if ((error = net2_cp_init(ctx, &cp_carver_msg_header, &header,
	    NULL)) != 0)
		return error;
	error = net2_cp_decode(ctx, &cp_carver_msg_header, &header, in, NULL);
	msg_type = header.msg_type;
	if (error != 0) {
		net2_cp_destroy(ctx, &cp_carver_msg_header, &header, NULL);
		return error;
	}

	switch (header.msg_type) {
	default:
		return EINVAL;
	case CARVER_MSGTYPE_SETUP:
		return combiner_setup_msg(c, ctx, in);
	case CARVER_MSGTYPE_DATA:
		if ((r = net2_malloc(sizeof(*r))) == NULL)
			return ENOMEM;
		r->flags = 0;
		r->offset = 0;
		r->data = NULL;
		if ((error = combiner_msg_to_range(c, r, ctx, in)) != 0) {
			net2_free(r);
			return error;
		}
		if ((error = combiner_msg_combine(c, r)) != 0) {
			if (r->data)
				net2_buffer_free(r->data);
			net2_free(r);
			return error;
		}
		/*
		 * Don't free r: combiner_msg_combine will have done this,
		 * or inserted r directly into the tree.
		 */
		return 0;
	}
}


/* Convert carver range into message buffer. */
static int
carver_range_to_msg(struct net2_carver *c, struct net2_carver_range *r,
    struct net2_encdec_ctx *ctx, struct net2_buffer *out)
{
	union {
		struct carver_msg_16
				 msg16;
		struct carver_msg_32
				 msg32;
	}			 msg;
	size_t			 last_byte_offset;
	void			*msg_ptr;
	const struct command_param
				*cp;
	int			 error;

	if (net2_buffer_length(r->data) == 0 ||
	    r->offset + net2_buffer_length(r->data) < r->offset)
		return ENOSPC;	/* Overflow. */
	last_byte_offset = r->offset + net2_buffer_length(r->data) - 1;

	switch (c->flags & NET2_CARVER_F_BITS) {
	default:
		return EINVAL;
	case NET2_CARVER_F_16BIT:
		if (last_byte_offset > 0xffffU)
			return ENOSPC;	/* Too large. */
		cp = &cp_carver_msg_16;
		msg.msg16.offset = r->offset;
		msg.msg16.payload = r->data;
		msg_ptr = &msg.msg16;
		break;
	case NET2_CARVER_F_32BIT:
		if (last_byte_offset > 0xffffffffU)
			return ENOSPC;	/* Too large. */
		cp = &cp_carver_msg_32;
		msg.msg32.offset = r->offset;
		msg.msg32.payload = r->data;
		msg_ptr = &msg.msg32;
		break;
	}

	error = net2_cp_encode(ctx, cp, out, msg_ptr, NULL);
	return error;
}

/* Create carver setup message. */
static int
carver_setup_msg(struct net2_carver *c, struct net2_encdec_ctx *ctx,
    struct net2_buffer *out)
{
	union {
		struct carver_msg_setup_16
				 msg_16;
		struct carver_msg_setup_32
				 msg_32;
	}			 msg;
	void			*msg_ptr;
	const struct command_param
				*cp;
	size_t			 sz;

	sz = c->size;
	switch (c->flags & NET2_CARVER_F_BITS) {
	default:
		return EINVAL;
	case NET2_CARVER_F_16BIT:
		cp = &cp_carver_msg_setup_16;
		msg_ptr = &msg.msg_16;

		msg.msg_16.pad = 0;
		msg.msg_16.flags = 0;
		if (sz == 0) {
			msg.msg_16.flags |= NET2_CARVER_SETUP_EMPTY;
			msg.msg_16.size = 0;
		} else {
			if (sz - 1 > 0xffffU)
				return ENOSPC;
			msg.msg_16.size = sz - 1;
		}
		break;
	case NET2_CARVER_F_32BIT:
		cp = &cp_carver_msg_setup_32;
		msg_ptr = &msg.msg_32;

		msg.msg_32.flags = 0;
		if (sz == 0) {
			msg.msg_32.flags |= NET2_CARVER_SETUP_EMPTY;
			msg.msg_32.size = 0;
		} else {
			if (sz - 1 > 0xffffffffU)
				return ENOSPC;
			msg.msg_32.size = sz - 1;
		}
		break;
	}

	return net2_cp_encode(ctx, cp, out, msg_ptr, NULL);
}

/* Ensure carver range is at most maxsz bytes. */
static int
carver_range_split(struct net2_carver *c, struct net2_carver_range *r,
    size_t maxsz)
{
	struct net2_carver_range*sibling;

	if (net2_buffer_length(r->data) <= maxsz)
		return 0;

	/* Allocate sibling as a copy or r. */
	if ((sibling = net2_malloc(sizeof(*sibling))) == NULL)
		return ENOMEM;
	sibling->offset = r->offset;
	sibling->flags = r->flags;
	if ((sibling->data = net2_buffer_copy(r->data)) == NULL) {
		net2_free(sibling);
		return ENOMEM;
	}

	/* Adjust buffers and sibling offset. */
	sibling->offset += maxsz;
	net2_buffer_drain(sibling->data, maxsz);
	net2_buffer_truncate(r->data, maxsz);
	/* Update ranges tree. */
	RB_INSERT(net2_carver_ranges, &c->ranges, r);
	return 0;
}

/* Read back carver range message into r. */
static int
combiner_msg_to_range(struct net2_combiner *c, struct net2_carver_range *r,
    struct net2_encdec_ctx *ctx, struct net2_buffer *in)
{
	union {
		struct carver_msg_16
				 msg16;
		struct carver_msg_32
				 msg32;
	}			 msg;
	void			*msg_ptr;
	const struct command_param
				*cp;
	struct net2_buffer	*data = NULL;
	size_t			 offset;
	int			 error;
	size_t			 max;

	/* Decide on which decoder to use. */
	switch (c->flags & NET2_CARVER_F_BITS) {
	default:
		return EINVAL;
	case NET2_CARVER_F_16BIT:
		cp = &cp_carver_msg_16;
		msg_ptr = &msg.msg16;
		max = 0xffffU;
		break;
	case NET2_CARVER_F_32BIT:
		cp = &cp_carver_msg_32;
		msg_ptr = &msg.msg32;
		max = 0xffffffffU;
		break;
	}

	/* Decode message. */
	if ((error = net2_cp_init(ctx, cp, msg_ptr, NULL)) != 0)
		return error;
	if ((error = net2_cp_decode(ctx, cp, msg_ptr, in, NULL)) != 0)
		goto out;

	/* Extract data from decoded message. */
	switch (c->flags & NET2_CARVER_F_BITS) {
	case NET2_CARVER_F_16BIT:
		data = msg.msg16.payload;
		msg.msg32.payload = NULL;	/* Claim ownership. */
		offset = msg.msg16.offset;
		break;
	case NET2_CARVER_F_32BIT:
		data = msg.msg32.payload;
		msg.msg32.payload = NULL;	/* Claim ownership. */
		offset = msg.msg32.offset;
		break;
	}
	assert(data != NULL);

	r->offset = offset;
	r->data = data;
	error = 0;

	/*
	 * Use expected size instead of max, if expected size data has
	 * been received.
	 */
	if (c->flags & NET2_CARVER_F_KNOWN_SZ)
		max = c->expected_size;

	/* Validation: may not overflow. */
	if (r->offset + net2_buffer_length(data) < r->offset) {
		net2_buffer_free(data);
		return EINVAL;
	}
	/* Validation: must fit within 16/32 bit. */
	if (r->offset + net2_buffer_length(data) - 1 > max) {
		net2_buffer_free(data);
		return EINVAL;
	}

out:
	net2_cp_destroy(ctx, cp, msg_ptr, NULL);
	return error;
}

/* Decode carver setup message. */
static int
combiner_setup_msg(struct net2_combiner *c, struct net2_encdec_ctx *ctx,
    struct net2_buffer *in)
{
	union {
		struct carver_msg_setup_16
				 msg_16;
		struct carver_msg_setup_32
				 msg_32;
	}			 msg;
	void			*msg_ptr;
	const struct command_param
				*cp;
	size_t			 sz;
	int			 error;
	uint32_t		 flags;
	struct net2_carver_range*r;

	/* Setup decoding information. */
	switch (c->flags & NET2_CARVER_F_BITS) {
	default:
		return EINVAL;
	case NET2_CARVER_F_16BIT:
		cp = &cp_carver_msg_setup_16;
		msg_ptr = &msg.msg_16;
		break;
	case NET2_CARVER_F_32BIT:
		cp = &cp_carver_msg_setup_32;
		msg_ptr = &msg.msg_32;
		break;
	}

	/* Decoding stage. */
	if ((error = net2_cp_init(ctx, cp, msg_ptr, NULL)) != 0)
		return error;
	if ((error = net2_cp_decode(ctx, cp, msg_ptr, in, NULL)) != 0)
		goto out;

	switch (c->flags & NET2_CARVER_F_BITS) {
	case NET2_CARVER_F_16BIT:
		if (msg.msg_16.pad != 0) {
			error = EINVAL;
			goto out;
		}
		sz = msg.msg_16.size;
		flags = msg.msg_16.flags;
		break;
	case NET2_CARVER_F_32BIT:
		sz = msg.msg_32.size;
		flags = msg.msg_32.flags;
		break;
	}

	/* Fixup sz information. */
	if (flags & NET2_CARVER_SETUP_EMPTY) {
		if (sz != 0) {
			error = EINVAL;
			goto out;
		}
	} else
		sz++;

	/* Apply size message. */
	if (c->flags & NET2_CARVER_F_KNOWN_SZ) {
		/*
		 * Duplicate receival, confirm new receival confirms previous
		 * setup message.
		 */
		if (sz != c->expected_size) {
			error = EINVAL;
			goto out;
		}
	} else {
		c->expected_size = sz;
		c->flags |= NET2_CARVER_F_KNOWN_SZ;
	}

	/* Check that already received data doesn't exceed expected size. */
	r = RB_MAX(net2_carver_ranges, &c->ranges);
	if (r != NULL && r->offset + net2_buffer_length(r->data) > sz) {
		error = EINVAL;
		goto out;
	}

	error = 0;

out:
	net2_cp_destroy(ctx, cp, msg_ptr, NULL);
	return error;
}

/*
 * Place message into combiner.
 * Will take full ownership of r (possibly freeing it).
 */
static int
combiner_msg_combine(struct net2_combiner *c, struct net2_carver_range *r)
{
	struct net2_carver_range search, *next, *prev;
	size_t			 prev_end;
	size_t			 r_end;
	size_t			 add_len;

	r_end = r->offset + net2_buffer_length(r->data);
	search.offset = r->offset + 1;
	next = RB_NFIND(net2_carver_ranges, &c->ranges, &search);
	if (next == NULL)
		prev = RB_MAX(net2_carver_ranges, &c->ranges);
	else
		prev = RB_PREV(net2_carver_ranges, &c->ranges, next);

	assert(prev == NULL || prev->offset <= r->offset);
	assert(next == NULL || next->offset > r->offset);

	/* Break intersection with prev. */
	if (prev != NULL) {
		prev_end = prev->offset + net2_buffer_length(prev->data);
		if (prev_end >= r->offset) {
			net2_buffer_drain(r->data, prev_end - r->offset);
			r->offset = prev_end;
		} else
			prev = NULL;
	}

	/* Merge next into r. */
	while (next != NULL && next->offset <= r_end) {
		/* Prepare for next step in this loop. */
		struct net2_carver_range
				*next_next;
		next_next = RB_NEXT(net2_carver_ranges, &c->ranges, next);

		/* Remove next, since we'll ditch it in favour of r. */
		RB_REMOVE(net2_carver_ranges, &c->ranges, next);

		/* Merge non-intersecting part of next into r. */
		if (net2_buffer_length(next->data) > r_end - next->offset) {
			net2_buffer_drain(next->data, r_end - next->offset);
			next->offset = r_end;
			if (net2_buffer_append(r->data, next->data)) {
				/* TODO: prevent modification until succes. */
				RB_INSERT(net2_carver_ranges, &c->ranges,
				    next);
				return ENOMEM;
			}
			r_end += net2_buffer_length(next->data);
		}

		/* Release next. */
		net2_buffer_free(next->data);
		net2_free(next);

		/* Keep going by eating the next entry as well. */
		next = next_next;
	}

	/* Update combiner ranges. */
	if (prev == NULL) {
		/* r does not connect with any previous range. */
		RB_INSERT(net2_carver_ranges, &c->ranges, r);
	} else {
		/* r merges with prev. */
		if (net2_buffer_append(prev->data, r->data))
			return ENOMEM;
		net2_free(r);
	}

	return 0;
}

/* Extract carver/combiner type from flags. */
static enum net2_carver_type
flags_to_type(int flags)
{
	switch (flags & NET2_CARVER_F_BITS) {
	case NET2_CARVER_F_16BIT:
		return NET2_CARVER_16BIT;
	case NET2_CARVER_F_32BIT:
		return NET2_CARVER_32BIT;
	}
	return NET2_CARVER_INVAL;
}

/* Carver range callback: receival acknowledged. */
static void
carver_txcb_ack(void *c_ptr, void *r_ptr)
{
	struct net2_carver_range*r = r_ptr;
	struct net2_carver	*c = c_ptr;

	if (!(r->flags & RANGE_DETACHED))
		RB_REMOVE(net2_carver_ranges, &c->ranges, r);

	net2_buffer_free(r->data);
	net2_free(r);
}

/* Carver range callback: receival failed. */
static void
carver_txcb_nack(void *c_ptr, void *r_ptr)
{
	struct net2_carver_range*r = r_ptr;
	struct net2_carver	*c = c_ptr;

	if (!(r->flags & RANGE_DETACHED))
		r->flags &= ~RANGE_TRANSMITTED;
	else {
		net2_buffer_free(r->data);
		net2_free(r);
	}
}

/* Ack setup receival. */
static void
carver_setup_ack(void *c_ptr, void *unusued)
{
	struct net2_carver	*c = c_ptr;

	c->flags |= NET2_CARVER_F_KNOWN_SZ;
}

/* Setup receival failed. */
static void
carver_setup_nack(void *c_ptr, void *unusued)
{
	struct net2_carver	*c = c_ptr;

	c->flags &= ~NET2_CARVER_F_SZ_TX;
}
