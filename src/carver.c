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
#include <ilias/net2/tx_callback.h>
#include <ilias/net2/promise.h>
#include <ilias/net2/config.h>
#include <ilias/net2/bsd_compat/minmax.h>
#include <assert.h>
#include <errno.h>

#ifdef HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include <ilias/net2/bsd_compat/tree.h>
#endif

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <ilias/net2/bsd_compat/queue.h>
#endif

#include "carver_msg.h"


struct net2_carver_range {
	RB_ENTRY(net2_carver_range)
				 tree;		/* Link into tree. */
	TAILQ_ENTRY(net2_carver_range)
				 txq;		/* Ready to send. */

	size_t			 offset;	/* Offset of this range. */
	struct net2_buffer	*data;		/* Data in this range. */
	int			 flags;		/* State flags. */

	struct net2_txcb_entryq	 txcbeq;	/* Delivery callbacks. */

/* Carver only flags. */
#define RANGE_ON_TXQ		0x00010000	/* Range on tx queue. */
};

/* Flags shared by carver and combiner. */
#define NET2_CARVER_F_16BIT	0x00000000	/* 16 bit carver. */
#define NET2_CARVER_F_32BIT	0x00000001	/* 32 bit carver. */
#define NET2_CARVER_F_BITS	0x0000000f	/* Carver bit mask. */
#define NET2_CARVER_F_KNOWN_SZ	0x00000010	/* Expected size is knwon. */

/* Carver only flags. */
#define NET2_CARVER_F_SZ_TX	0x00010000	/* Size is on wire. */
#define NET2_CARVER_F_SZ_TX_TIMEOUT					\
				0x00020000	/* Size tx timeout. */


#define MAX_MSG_PAYLOAD		65535


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
static void	 combiner_result_free(void*, void*);

static enum net2_carver_type
		 flags_to_type(int);

static void	carver_txcb_timeout(void*, void*);
static void	carver_txcb_ack(void*, void*);
static void	carver_txcb_nack(void*, void*);
#define carver_txcb_destroy	carver_txcb_nack
static void	carver_setup_timeout(void*, void*);
static void	carver_setup_ack(void*, void*);
static void	carver_setup_nack(void*, void*);

static void	fire_rts(struct net2_carver*);


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
	struct net2_carver_range*r = NULL;
	int			 err;

	if (c == NULL || data == NULL)
		return EINVAL;

	c->flags = 0;
	RB_INIT(&c->ranges);
	TAILQ_INIT(&c->ranges_tx);
	c->size = net2_buffer_length(data);

	/* Clean callback. */
	net2_workq_init_work_null(&c->rts);

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
		if ((r = net2_malloc(sizeof(*r))) == NULL) {
			err = ENOMEM;
			goto fail_0;
		}
		r->offset = 0;
		r->flags = 0;
		if ((r->data = net2_buffer_copy(data)) == NULL) {
			err = ENOMEM;
			goto fail_1;
		}
		if ((err = net2_txcb_entryq_init(&r->txcbeq)) != 0) {
			err = ENOMEM;
			goto fail_2;
		}
		RB_INSERT(net2_carver_ranges, &c->ranges, r);
		TAILQ_INSERT_HEAD(&c->ranges_tx, r, txq);
		r->flags |= RANGE_ON_TXQ;
	}

	/* Initialize completion promise. */
	if ((c->ready = net2_promise_new()) == NULL) {
		err = ENOMEM;
		goto fail_3;
	}

	/* Initialize size callbacks. */
	if ((err = net2_txcb_entryq_init(&c->size_txq)) != 0)
		goto fail_4;

	/* Mark the promise as having started. */
	net2_promise_set_running(c->ready);

	return 0;

fail_4:
	net2_promise_release(c->ready);
fail_3:
	if (r != NULL)
		net2_txcb_entryq_deinit(&r->txcbeq);
fail_2:
	if (r != NULL)
		net2_buffer_free(r->data);
fail_1:
	if (r != NULL)
		net2_free(r);
fail_0:
	return err;
}

/* Release carver resources. */
ILIAS_NET2_EXPORT void
net2_carver_deinit(struct net2_carver *c)
{
	struct net2_carver_range	*r, *child;
	TAILQ_HEAD(, net2_carver_range)	 x;

	/* Destroy tree in O(n). */
	TAILQ_INIT(&x);
	if ((r = RB_ROOT(&c->ranges)) != NULL)
		TAILQ_INSERT_TAIL(&x, r, txq);
	while ((r = TAILQ_FIRST(&x)) != NULL) {
		/* Detach from list. */
		TAILQ_REMOVE(&x, r, txq);

		/* Add children to list. */
		if ((child = RB_LEFT(r, tree)) != NULL)
			TAILQ_INSERT_HEAD(&x, child, txq);
		if ((child = RB_RIGHT(r, tree)) != NULL)
			TAILQ_INSERT_HEAD(&x, child, txq);

		/* Destroy r. */
		net2_txcb_entryq_deinit(&r->txcbeq);
		net2_buffer_free(r->data);
		net2_free(r);
	}

	if (net2_promise_is_running(c->ready))
		net2_promise_set_cancel(c->ready, NET2_PROMFLAG_RELEASE);
	else
		net2_promise_release(c->ready);

	net2_txcb_entryq_deinit(&c->size_txq);
}

/* Initialize combiner. */
ILIAS_NET2_EXPORT int
net2_combiner_init(struct net2_combiner *c, enum net2_carver_type type)
{
	c->flags = 0;
	c->expected_size = (size_t)-1;
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

	if ((c->ready = net2_promise_new()) == NULL)
		return ENOMEM;
	net2_promise_set_running(c->ready);

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

	if (net2_promise_is_running(c->ready))
		net2_promise_set_cancel(c->ready, NET2_PROMFLAG_RELEASE);
	else
		net2_promise_release(c->ready);
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
    struct net2_workq *workq,
    struct net2_buffer *out, struct net2_tx_callback *tx, size_t maxsz)
{
	size_t			 setup_overhead;
	size_t			 msg_overhead;
	struct net2_carver_range*r;
	int			 error;
	struct carver_msg_header header;

	if (out == NULL || !net2_buffer_empty(out)) {
		error = EINVAL;
		goto out;
	}

	/* Figure out overhead. */
	switch (c->flags & NET2_CARVER_F_BITS) {
	default:
		error = EINVAL;
		goto out;
	case NET2_CARVER_F_16BIT:
		setup_overhead = OVERHEAD_HEADER + OVERHEAD16_SETUP;
		msg_overhead = OVERHEAD_HEADER + OVERHEAD16_MSG;
		break;
	case NET2_CARVER_F_32BIT:
		setup_overhead = OVERHEAD_HEADER + OVERHEAD32_SETUP;
		msg_overhead = OVERHEAD_HEADER + OVERHEAD32_MSG;
		break;
	}

	/* Setup message fits and is untransmitted, so send it now. */
	if ((!(c->flags & NET2_CARVER_F_SZ_TX) ||
	     (c->flags & NET2_CARVER_F_SZ_TX_TIMEOUT)) &&
	    maxsz >= setup_overhead &&
	    net2_txcb_entryq_empty(&c->size_txq, NET2_TXCB_EQ_TIMEOUT)) {
		/* Encode header for SETUP. */
		header.msg_type = CARVER_MSGTYPE_SETUP;
		if ((error = net2_cp_encode(ctx, &cp_carver_msg_header, out,
		    &header, NULL)) != 0)
			goto out;

		if ((error = carver_setup_msg(c, ctx, out)) != 0)
			goto out;
		/* Install callback. */
		if ((error = net2_txcb_add(tx, workq, &c->size_txq,
		    &carver_setup_timeout,
		    &carver_setup_ack, &carver_setup_nack, NULL,
		    c, NULL)) != 0)
			goto out;

		c->flags |= NET2_CARVER_F_SZ_TX;
		c->flags &= ~NET2_CARVER_F_SZ_TX_TIMEOUT;

		error = 0;
		goto out;
	}

	/* Cannot fit message. */
	if (maxsz <= msg_overhead) {
		error = 0;
		goto out;
	}

	/* Find untransmitted message. */
	TAILQ_FOREACH(r, &c->ranges_tx, txq) {
		if (net2_txcb_entryq_empty(&r->txcbeq, NET2_TXCB_EQ_ALL))
			break;
		if (net2_buffer_length(r->data) <= maxsz - msg_overhead)
			break;
	}
	/* Nothing to send. */
	if (r == NULL) {
		error = 0;
		goto out;
	}

	/* Encode header for DATA. */
	header.msg_type = CARVER_MSGTYPE_DATA;
	if ((error = net2_cp_encode(ctx, &cp_carver_msg_header, out,
	    &header, NULL)) != 0)
		goto out;

	if ((error = carver_range_split(c, r,
	    MIN(maxsz - msg_overhead, MAX_MSG_PAYLOAD))) != 0)
		goto out;
	if ((error = carver_range_to_msg(c, r, ctx, out)) != 0)
		goto out;

	/* Install callback. */
	if ((error = net2_txcb_add(tx, workq, &r->txcbeq, &carver_txcb_timeout,
	    &carver_txcb_ack, &carver_txcb_nack, &carver_txcb_destroy,
	    c, r)) != 0)
		goto out;
	TAILQ_REMOVE(&c->ranges_tx, r, txq);
	r->flags &= ~RANGE_ON_TXQ;

	error = 0;	/* Success. */

out:
	fire_rts(c);
	return error;
}

/* Fire ready-to-send event if we have something to transmit. */
static void
fire_rts(struct net2_carver *c)
{
	if (!(c->flags & NET2_CARVER_F_SZ_TX) ||
	    (c->flags & NET2_CARVER_F_SZ_TX_TIMEOUT) ||
	    !TAILQ_EMPTY(&c->ranges_tx))
		net2_workq_activate(&c->rts, 0);
	else
		net2_workq_deactivate(&c->rts);
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
	if ((error = net2_cp_init(cp, msg_ptr, NULL)) != 0)
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
	net2_cp_destroy(cp, msg_ptr, NULL);
	return error;
}

/*
 * Place message into combiner.
 * Will take full ownership of r (possibly freeing it).
 */
static __inline int
combiner_msg_combine(struct net2_combiner *c, struct net2_carver_range *r)
{
	struct net2_carver_range search, *next, *prev;
	size_t			 prev_end;
	size_t			 r_end;

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
		net2_buffer_free(r->data);
		net2_free(r);
	}

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
	struct net2_buffer	*result;

	/* Decode header to read message type. */
	if ((error = net2_cp_init(&cp_carver_msg_header, &header,
	    NULL)) != 0)
		return error;
	error = net2_cp_decode(ctx, &cp_carver_msg_header, &header, in, NULL);
	msg_type = header.msg_type;
	net2_cp_destroy(&cp_carver_msg_header, &header, NULL);
	if (error != 0)
		return error;

	switch (msg_type) {
	default:
		error = EINVAL;
		break;
	case CARVER_MSGTYPE_SETUP:
		error = combiner_setup_msg(c, ctx, in);
		break;
	case CARVER_MSGTYPE_DATA:
		if ((r = net2_malloc(sizeof(*r))) == NULL) {
			error = ENOMEM;
			break;
		}
		r->flags = 0;
		r->offset = 0;
		r->data = NULL;
		if ((error = combiner_msg_to_range(c, r, ctx, in)) != 0) {
			net2_free(r);
			break;
		}
		if ((error = combiner_msg_combine(c, r)) != 0) {
			if (r->data)
				net2_buffer_free(r->data);
			net2_free(r);
			break;
		}

		/*
		 * Don't free r: combiner_msg_combine will have done this,
		 * or inserted r directly into the tree.
		 */
		error = 0;
		break;
	}

out:
	/* Assign result or error to promise. */
	if (net2_promise_is_running(c->ready)) {
		if (error != 0)
			net2_promise_set_error(c->ready, error, 0);
		else if (net2_combiner_is_done(c)) {
			if ((result = net2_combiner_data(c)) == NULL) {
				error = ENOMEM;
				goto out; /* Assign error code to result. */
			}

			if ((error = net2_promise_set_finok(c->ready, result,
			    &combiner_result_free, NULL, 0)) != 0) {
				net2_buffer_free(result);
				goto out; /* Assign error code to result. */
			}
		}
	}
	return error;
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

		msg.msg_16.flags = 0;
		if (sz == 0) {
			msg.msg_16.flags |= NET2_CARVER_SETUP_EMPTY;
			msg.msg_16.size = 0;
		} else {
			if (sz - 1 > 0xffffU)
				return ENOSPC;
			msg.msg_16.size = sz - 1U;
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
			msg.msg_32.size = sz - 1U;
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
	int			 error;

	assert(r != NULL);
	assert(maxsz > 0);
	if (net2_buffer_length(r->data) <= maxsz)
		return 0;
	assert(net2_txcb_entryq_empty(&r->txcbeq, NET2_TXCB_EQ_ALL));

	/* Allocate sibling as a copy or r. */
	if ((sibling = net2_malloc(sizeof(*sibling))) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	sibling->flags = 0;
	sibling->offset = r->offset;
	sibling->flags = r->flags;
	if ((sibling->data = net2_buffer_copy(r->data)) == NULL) {
		error = ENOMEM;
		goto fail_1;
	}
	if ((error = net2_txcb_entryq_init(&sibling->txcbeq)) != 0)
		goto fail_2;

	/* Adjust buffers and sibling offset. */
	sibling->offset += maxsz;
	net2_buffer_drain(sibling->data, maxsz);
	net2_buffer_truncate(r->data, maxsz);
	/* Update ranges tree. */
	RB_INSERT(net2_carver_ranges, &c->ranges, sibling);
	TAILQ_INSERT_HEAD(&c->ranges_tx, sibling, txq);
	sibling->flags |= RANGE_ON_TXQ;
	return 0;


fail_3:
	net2_txcb_entryq_deinit(&sibling->txcbeq);
fail_2:
	net2_buffer_free(sibling->data);
fail_1:
	net2_free(sibling);
fail_0:
	assert(error != 0);
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
	if ((error = net2_cp_init(cp, msg_ptr, NULL)) != 0)
		return error;
	if ((error = net2_cp_decode(ctx, cp, msg_ptr, in, NULL)) != 0)
		goto out;

	switch (c->flags & NET2_CARVER_F_BITS) {
	case NET2_CARVER_F_16BIT:
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
	net2_cp_destroy(cp, msg_ptr, NULL);
	return error;
}

/* Combiner promise data release function. */
static void
combiner_result_free(void *bufptr, void *unused ILIAS_NET2__unused )
{
	struct net2_buffer	*buf = bufptr;

	net2_buffer_free(buf);
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
carver_txcb_timeout(void *c_ptr, void *r_ptr)
{
	struct net2_carver_range*r = r_ptr;
	struct net2_carver	*c = c_ptr;

	if (!(r->flags & RANGE_ON_TXQ)) {
		TAILQ_INSERT_TAIL(&c->ranges_tx, r, txq);
		r->flags |= RANGE_ON_TXQ;
	}
}

/* Carver range callback: receival acknowledged. */
static void
carver_txcb_ack(void *c_ptr, void *r_ptr)
{
	struct net2_carver_range*r = r_ptr;
	struct net2_carver	*c = c_ptr;

	assert(c != NULL && r != NULL);
	assert(RB_FIND(net2_carver_ranges, &c->ranges, r) == r);

	RB_REMOVE(net2_carver_ranges, &c->ranges, r);
	if (r->flags & RANGE_ON_TXQ) {
		r->flags &= ~RANGE_ON_TXQ;
		TAILQ_REMOVE(&c->ranges_tx, r, txq);
	}
	if (net2_promise_is_running(c->ready) &&
	    net2_carver_is_done(c))
		net2_promise_set_finok(c->ready, NULL, NULL, NULL, 0);

	net2_txcb_entryq_deinit(&r->txcbeq);
	net2_buffer_free(r->data);
	net2_free(r);
}

/* Carver range callback: receival failed. */
static void
carver_txcb_nack(void *c_ptr, void *r_ptr)
{
	struct net2_carver_range*r = r_ptr;
	struct net2_carver	*c = c_ptr;

	net2_workq_activate(&c->rts, 0);
	if (!(r->flags & RANGE_ON_TXQ)) {
		TAILQ_INSERT_HEAD(&c->ranges_tx, r, txq);
		r->flags |= RANGE_ON_TXQ;
	}
}

/* Setup receival ack timeout. */
static void
carver_setup_timeout(void *c_ptr, void *unusued ILIAS_NET2__unused)
{
	struct net2_carver	*c = c_ptr;

	c->flags |= NET2_CARVER_F_SZ_TX_TIMEOUT;
	net2_workq_activate(&c->rts, 0);
}

/* Ack setup receival. */
static void
carver_setup_ack(void *c_ptr, void *unusued ILIAS_NET2__unused)
{
	struct net2_carver	*c = c_ptr;

	c->flags |= NET2_CARVER_F_KNOWN_SZ;
	if (net2_promise_is_running(c->ready) && net2_carver_is_done(c))
		net2_promise_set_finok(c->ready, NULL, NULL, NULL, 0);
}

/* Setup receival failed. */
static void
carver_setup_nack(void *c_ptr, void *unusued ILIAS_NET2__unused)
{
	struct net2_carver	*c = c_ptr;

	c->flags &= ~NET2_CARVER_F_SZ_TX;
	net2_workq_activate(&c->rts, 0);
}

/* Set carver ready-to-send callback. */
ILIAS_NET2_EXPORT int
net2_carver_set_rts(struct net2_carver *c, struct net2_workq *wq,
    net2_workq_cb fn, void *arg0, void *arg1)
{
	int		 err;

	net2_workq_deinit_work(&c->rts);
	if (fn == NULL) {
		net2_workq_init_work_null(&c->rts);
		return 0;
	}

	err = net2_workq_init_work(&c->rts, wq, fn, arg0, arg1, 0);
	if (err != 0)
		net2_workq_init_work_null(&c->rts);

	fire_rts(c);
	return err;
}
