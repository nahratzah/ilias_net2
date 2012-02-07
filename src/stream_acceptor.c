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
#include <ilias/net2/stream_acceptor.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/acceptor.h>
#include <ilias/net2/connwindow.h>
#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/cp.h>
#include <ilias/net2/mutex.h>
#include <ilias/net2/packet.h>
#include <bsd_compat/minmax.h>
#include <bsd_compat/error.h>
#include <bsd_compat/bsd_compat.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include "stream_packet.h"

#ifdef HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include <bsd_compat/tree.h>
#endif


/*
 * Selective acknowledgement range.
 *
 * A range uses array semantics: start is the first item in
 * an imaginary array of sequence numbers,
 * while end is the first item outside that array.
 */
struct range {
	RB_ENTRY(range)			 entry;		/* link into tree */
	struct net2_sa_tx		*sa;		/* owner */
	uint32_t			 start;		/* first ack */
	uint32_t			 end;		/* first nack */
	int				 stream_end;	/* last packet? */
};
RB_HEAD(range_tree, range);

/*
 * Transmission side of the stream.
 *
 * Breaks up and encodes a buffer.
 */
struct net2_sa_tx {
	void	(*ready_to_send)(struct net2_sa_tx*);	/* ready callback */

	struct range_tree		 ack;		/* TX sel acks */
	struct range_tree		 transit;	/* TX in progress */
	struct range_tree		 retrans;	/* retransmit queue */
	struct net2_buffer		*sendbuf;	/* TX buffer */
	struct net2_mutex		*sendbuf_mtx;	/* protect sendbuf */
	size_t				 low_watermark;	/* sendbuf low water */
	uint32_t			 win_start;	/* TX start */
	int				 flags;		/* state flags */
#define SATX_CLOSING			0x00000001	/* no more tx */
#define SATX_RESEND_CLOSE		0x00000002	/* close tx timeout */
#define SATX_CLOSED			0x00000004	/* close received */
#define SATX_LOWBUFFER_FIRED		0x01000000	/* low buffer event */

	struct event			*event[NET2_SATX__NUM_EVENTS];
							/* events */
};


/*
 * Receive fragments.
 */
struct fragment {
	RB_ENTRY(fragment)		 entry;		/* link into tree */
	struct net2_sa_rx		*sa;		/* owner */
	uint32_t			 start;		/* first ack */
	uint32_t			 end;		/* first nack */
	struct net2_buffer		*payload;	/* payload */
	int				 stream_end;	/* last packet? */
};
RB_HEAD(fragment_tree, fragment);

/*
 * Receive side of the stream.
 */
struct net2_sa_rx {
	struct fragment_tree		 recv;		/* Received data */
	uint32_t			 win_start;	/* sequence start */
	uint32_t			 win_close;	/* close sequence */

	struct net2_buffer		*recvbuf;	/* recv buffer */
	struct net2_mutex		*recvbuf_mtx;	/* protect recvbuf */
	int				 flags;		/* state flags */
#define SARX_CLOSING			0x00000001	/* close detected */

	struct event			*event[NET2_SARX__NUM_EVENTS];
							/* events */
};


/*
 * Stream acceptor datastructure.
 */
struct net2_stream_acceptor {
	struct net2_acceptor		 base;		/* acceptor */

	struct net2_sa_tx		 tx;		/* TX side of stream */
	struct net2_sa_rx		 rx;		/* RX side of stream */

	int				 flags;		/* stream flags */
#define SA_ATTACHED			0x80000000	/* attached */
};

/* Allow conversion between sa_tx and net2_stream_acceptor. */
#define SA_TX_OFF	((size_t)&((struct net2_stream_acceptor*)0)->tx)
#define SA_TX__SA(_tx)	((struct net2_stream_acceptor*)			\
			 ((uint8_t*)(_tx) - SA_TX_OFF))


/* Calculate the window offset of a sequence number. */
#define WIN_OFF(sa, val)		((val) - (sa)->win_start)
/* The maximum allowed window size. */
#define MAX_WINDOW_SIZE			16000000


ILIAS_NET2_LOCAL
void	sa_ack_close(struct net2_sa_tx*);
ILIAS_NET2_LOCAL
void	sa_timeout_close(struct net2_sa_tx*);
ILIAS_NET2_LOCAL
int	sa_ack(struct net2_sa_tx*, uint32_t, uint32_t);
ILIAS_NET2_LOCAL
int	sa_timeout(struct net2_sa_tx*, uint32_t, uint32_t);
ILIAS_NET2_LOCAL
int	sa_merge(struct net2_sa_tx*, struct range_tree*,
	    uint32_t, uint32_t);
ILIAS_NET2_LOCAL
void	sa_transit_update(struct net2_sa_tx*, uint32_t);
ILIAS_NET2_LOCAL
void	sa_update_winstart(struct net2_sa_tx*, uint32_t);
ILIAS_NET2_LOCAL
void	sa_ready_to_send(struct net2_sa_tx*);

ILIAS_NET2_LOCAL
void	sa_on_finish(struct net2_sa_tx*);
ILIAS_NET2_LOCAL
void	sa_on_detach(struct net2_sa_tx*);

ILIAS_NET2_LOCAL
void	nsa_ready_to_send(struct net2_sa_tx*);
ILIAS_NET2_LOCAL
int	nsa_attach(struct net2_acceptor_socket*, struct net2_acceptor*);
ILIAS_NET2_LOCAL
void	nsa_detach(struct net2_acceptor_socket*, struct net2_acceptor*);
ILIAS_NET2_LOCAL
void	nsa_accept(struct net2_acceptor*, struct net2_buffer*);
ILIAS_NET2_LOCAL
int	nsa_get_transmit(struct net2_acceptor*, struct net2_buffer**,
	    struct net2_cw_tx*, int, size_t);

ILIAS_NET2_LOCAL
int	sa_tx_init(struct net2_sa_tx*, void (*)(struct net2_sa_tx*));
ILIAS_NET2_LOCAL
void	sa_tx_deinit(struct net2_sa_tx*);

ILIAS_NET2_LOCAL
void	sa_rx_deliver(struct net2_sa_rx*, struct net2_buffer*);
ILIAS_NET2_LOCAL
int	sa_rx_recvbuf(struct net2_sa_rx*, struct net2_acceptor_socket*,
	    struct net2_buffer*);
ILIAS_NET2_LOCAL
int	sa_rx_recv(struct net2_sa_rx*, struct stream_packet*);

ILIAS_NET2_LOCAL
void	sa_rx_on_recv(struct net2_sa_rx*);
ILIAS_NET2_LOCAL
void	sa_rx_on_finish(struct net2_sa_rx*);
ILIAS_NET2_LOCAL
void	sa_rx_on_detach(struct net2_sa_rx*);

ILIAS_NET2_LOCAL
int	sa_rx_init(struct net2_sa_rx*);
ILIAS_NET2_LOCAL
void	sa_rx_deinit(struct net2_sa_rx*);


/* Function dispatch table for stream acceptor. */
static const struct net2_acceptor_fn nsa_fn = {
	&nsa_detach,
	&nsa_attach,
	&nsa_accept,
	&nsa_get_transmit
};

/* Create a new stream acceptor. */
ILIAS_NET2_EXPORT struct net2_stream_acceptor*
net2_stream_acceptor_new()
{
	struct net2_stream_acceptor	*nsa;

	if ((nsa = malloc(sizeof(*nsa))) == NULL)
		goto fail_0;
	if (net2_acceptor_init(&nsa->base, &nsa_fn))
		goto fail_1;
	nsa->flags = 0;

	if (sa_tx_init(&nsa->tx, &nsa_ready_to_send))
		goto fail_2;
	if (sa_rx_init(&nsa->rx))
		goto fail_3;
	return nsa;

fail_3:
	sa_tx_deinit(&nsa->tx);
fail_2:
	net2_acceptor_deinit(&nsa->base);
fail_1:
	free(nsa);
fail_0:
	return NULL;
}

/* Destroy a stream acceptor. */
ILIAS_NET2_EXPORT void
net2_stream_acceptor_destroy(struct net2_stream_acceptor *nsa)
{
	sa_rx_deinit(&nsa->rx);
	sa_tx_deinit(&nsa->tx);
	free(nsa);
}


/* Range comparator. */
static int
sa_range_cmp(struct range *r1, struct range *r2)
{
	uint32_t			 off1, off2;
	struct net2_sa_tx		*sa;
	int				 cmp;

	assert(r1->sa == r2->sa);
	sa = r1->sa;
	off1 = WIN_OFF(sa, r1->start);
	off2 = WIN_OFF(sa, r2->start);
	cmp = (off1 < off2 ? -1 : off1 > off2);

	/*
	 * Allow duplicates.
	 * (Required for transits.)
	 */
	if (cmp == 0 && r1 != r2)
		cmp = (r1 < r2 ? -1 : 1);

	return cmp;
}
RB_PROTOTYPE_STATIC(range_tree, range, entry, sa_range_cmp);
RB_GENERATE_STATIC(range_tree, range, entry, sa_range_cmp);

/* Fragment comparator. */
static inline int
sa_fragment_cmp(struct fragment *f1, struct fragment *f2)
{
	uint32_t			 off1, off2;
	struct net2_sa_rx		*sa;

	assert(f1->sa == f2->sa);
	sa = f1->sa;
	off1 = WIN_OFF(sa, f1->start);
	off2 = WIN_OFF(sa, f2->start);
	return (off1 < off2 ? -1 : off1 > off2);
}
RB_PROTOTYPE_STATIC(fragment_tree, fragment, entry, sa_fragment_cmp);
RB_GENERATE_STATIC(fragment_tree, fragment, entry, sa_fragment_cmp);


/* Create a new range. */
static struct range*
sa_range_new(struct net2_sa_tx *sa, uint32_t start, uint32_t end)
{
	struct range			*r;

	if ((r = malloc(sizeof(*r))) == NULL)
		return NULL;

	r->sa = sa;
	r->start = start;
	r->end = end;
	r->stream_end = 0;
	return r;
}

/* Free a range. */
static void
sa_range_free(struct range *r)
{
	free(r);
}

/*
 * Find the left-most mergeable entry.
 *
 * The left-most mergeable entry will be the first entry for which end >= start
 * and start <= end.
 * If no such entry exists, NULL will be returned.
 */
static struct range*
sa_range_merge_left(struct net2_sa_tx *sa,
    struct range_tree *tree, uint32_t start, uint32_t end)
{
	struct range			*r, *result;

	result = NULL;

	r = RB_ROOT(tree);
	while (r != NULL) {
		if (WIN_OFF(sa, r->end) >= WIN_OFF(sa, start)) {
			if (WIN_OFF(sa, r->start) <= WIN_OFF(sa, end))
				result = r;
			r = RB_LEFT(r, entry);
		} else
			r = RB_RIGHT(r, entry);
	}
	return result;
}

/*
 * Find the right-most mergeable entry.
 *
 * The right-most mergeable entry will be the last entry for which end >= start
 * and start <= end.
 * If no such entry exists, NULL will be returned.
 */
static struct range*
sa_range_merge_right(struct net2_sa_tx *sa,
    struct range_tree *tree, uint32_t start, uint32_t end)
{
	struct range			*r, *result;

	result = NULL;

	r = RB_ROOT(tree);
	while (r != NULL) {
		if (WIN_OFF(sa, r->start) <= WIN_OFF(sa, end)) {
			if (WIN_OFF(sa, r->end) >= WIN_OFF(sa, start))
				result = r;
			r = RB_RIGHT(r, entry);
		} else
			r = RB_LEFT(r, entry);
	}
	return result;
}


/* Create a new fragment. */
static struct fragment*
sa_fragment_new(struct net2_sa_rx *sa, uint32_t start, uint32_t end,
    struct net2_buffer *payload)
{
	struct fragment			*f;

	assert(end - start == net2_buffer_length(payload));
	if ((f = malloc(sizeof(*f))) == NULL)
		return NULL;

	f->sa = sa;
	f->start = start;
	f->end = end;
	f->payload = payload;
	return f;
}

/* Free a fragment. */
static void
sa_fragment_free(struct fragment *f)
{
	if (f->payload)
		net2_buffer_free(f->payload);
	free(f);
}

/*
 * Find the left-most mergeable entry.
 *
 * The left-most mergeable entry will be the first entry for which end >= start
 * and start <= end.
 * If no such entry exists, NULL will be returned.
 */
static struct fragment*
sa_fragment_merge_left(struct net2_sa_rx *sa,
    uint32_t start, uint32_t end)
{
	struct fragment			*r, *result;
	struct fragment_tree		*tree;

	tree = &sa->recv;
	result = NULL;

	r = RB_ROOT(tree);
	while (r != NULL) {
		if (WIN_OFF(sa, r->end) >= WIN_OFF(sa, start)) {
			if (WIN_OFF(sa, r->start) <= WIN_OFF(sa, end))
				result = r;
			r = RB_LEFT(r, entry);
		} else
			r = RB_RIGHT(r, entry);
	}
	return result;
}

/*
 * Find the right-most mergeable entry.
 *
 * The right-most mergeable entry will be the last entry for which end >= start
 * and start <= end.
 * If no such entry exists, NULL will be returned.
 */
static struct fragment*
sa_fragment_merge_right(struct net2_sa_rx *sa,
    uint32_t start, uint32_t end)
{
	struct fragment			*r, *result;
	struct fragment_tree		*tree;

	tree = &sa->recv;
	result = NULL;

	r = RB_ROOT(tree);
	while (r != NULL) {
		if (WIN_OFF(sa, r->start) <= WIN_OFF(sa, end)) {
			if (WIN_OFF(sa, r->end) >= WIN_OFF(sa, start))
				result = r;
			r = RB_RIGHT(r, entry);
		} else
			r = RB_LEFT(r, entry);
	}
	return result;
}


/* Handle transmission timeout. */
static void
sa_transit_timeout(void *arg0, void *arg1)
{
	struct net2_sa_tx		*sa = arg0;
	struct range			*t = arg1;

	if (t->start != t->end || t->stream_end) {
		sa_timeout(sa, t->start, t->end);
		if (t->stream_end)
			sa_timeout_close(sa);
	}
}

/* Handle transmission ack. */
static void
sa_transit_ack(void *arg0, void *arg1)
{
	struct net2_sa_tx		*sa = arg0;
	struct range			*t = arg1;

	if (t->start != t->end || t->stream_end) {
		assert(RB_FIND(range_tree, &sa->transit, t) == t);
		RB_REMOVE(range_tree, &sa->transit, t);

		if (t->start != t->end)
			sa_ack(sa, t->start, t->end);
		if (t->stream_end)
			sa_ack_close(sa);
	}
	sa_range_free(t);
}

/*
 * Handle transmission nack.
 *
 * This must be handled, since it can arrive before the timout fires.
 */
static void
sa_transit_nack(void *arg0, void *arg1)
{
	struct net2_sa_tx		*sa = arg0;
	struct range			*t = arg1;

	if (t->start != t->end || t->stream_end) {
		assert(RB_FIND(range_tree, &sa->transit, t) == t);
		RB_REMOVE(range_tree, &sa->transit, t);

		if (t->start != t->end)
			sa_timeout(sa, t->start, t->end);
		if (t->stream_end)
			sa_timeout_close(sa);
	}
	sa_range_free(t);
}

/*
 * Handle connection destruction.
 *
 * Since once the connection is destroyed, the stream can no longer transmit,
 * there is no need to register the transmission failure using sa_timeout.
 */
static void
sa_transit_destroy(void *arg0, void *arg1)
{
	struct net2_sa_tx		*sa = arg0;
	struct range			*t = arg1;

	if (t->start != t->end || t->stream_end) {
		assert(RB_FIND(range_tree, &sa->transit, t) == t);
		RB_REMOVE(range_tree, &sa->transit, t);
	}
	sa_range_free(t);
}


/*
 * Acknowledged receival of closing bit.
 */
ILIAS_NET2_LOCAL void
sa_ack_close(struct net2_sa_tx *sa)
{
	int				 do_event;

	net2_mutex_lock(sa->sendbuf_mtx);
	assert(sa->flags & SATX_CLOSING);

	/* Set to closed, clear resend_close bit. */
	sa->flags |= SATX_CLOSED;
	sa->flags &= ~SATX_RESEND_CLOSE;

	do_event = net2_buffer_empty(sa->sendbuf);
	net2_mutex_unlock(sa->sendbuf_mtx);

	if (do_event)
		sa_on_finish(sa);
}

/*
 * Stream-end command timed out.
 */
ILIAS_NET2_LOCAL void
sa_timeout_close(struct net2_sa_tx *sa)
{
	net2_mutex_lock(sa->sendbuf_mtx);
	assert(sa->flags & SATX_CLOSING);

	/* Already acked. */
	if (sa->flags & SATX_CLOSED) {
		net2_mutex_unlock(sa->sendbuf_mtx);
		return;
	}

	sa->flags |= SATX_RESEND_CLOSE;
	net2_mutex_unlock(sa->sendbuf_mtx);

	/* Send a new stream-end command. */
	sa_ready_to_send(sa);
}

/*
 * Update the acks in the given sa to include start, with len bytes.
 *
 * Returns -1 if insufficient memory was available to complete the task.
 */
ILIAS_NET2_LOCAL int
sa_ack(struct net2_sa_tx *sa, uint32_t start, uint32_t end)
{
	struct range			*r, *next, *mrl, *mrr;

	/* Skip empty range. */
	if (start == end)
		return 0;

	/*
	 * Shortcut: if this was the first entry in the window,
	 * simply move the window forward.
	 */
	if (start == sa->win_start) {
		/* Merge and remove any overlapping acks. */
		next = sa_range_merge_right(sa, &sa->ack, start, end);
		if (next != NULL) {
			/* Update the end to include next->end. */
			if (WIN_OFF(sa, next->end) > WIN_OFF(sa, end))
				end = next->end;

			/* Remove everything up and including next. */
			for (;;) {
				r = RB_MIN(range_tree, &sa->ack);
				RB_REMOVE(range_tree, &sa->ack, r);
				sa_range_free(r);

				/* GUARD */
				if (r == next)
					break;
			}
		}

		/* Remove any overlapping retrans. */
		mrr = sa_range_merge_right(sa, &sa->retrans, start, end);
		if (mrr != NULL) {
			/* Remove everything up to mrr. */
			while ((r = RB_MIN(range_tree, &sa->retrans)) != mrr) {
				RB_REMOVE(range_tree, &sa->retrans, r);
				sa_range_free(r);
			}

			/* Make mrr fall outside the acked range. */
			RB_REMOVE(range_tree, &sa->retrans, r);
			if (WIN_OFF(sa, mrr->end) > WIN_OFF(sa, end)) {
				mrr->start = end;
				RB_INSERT(range_tree, &sa->retrans, r);
			} else {
				sa_range_free(r);
			}
		}

		sa_update_winstart(sa, end);
		return 0;
	}

	/*
	 * Remove intersecting retrans.
	 */
	mrl = sa_range_merge_left(sa, &sa->retrans, start, end);
	if (mrl == NULL)
		goto skip_retrans;
	mrr = sa_range_merge_left(sa, &sa->retrans, start, end);
	assert(mrr != NULL);

	if (mrl == mrr) {
		if (WIN_OFF(sa, mrl->start) < WIN_OFF(sa, start) &&
		    WIN_OFF(sa, mrr->end  ) > WIN_OFF(sa, end  )) {
			/* This ack punched a hole in the retrans. */
			if ((r = sa_range_new(sa, end, mrr->end)) == NULL)
				return -1;
			mrl->end = start;
			RB_INSERT(range_tree, &sa->retrans, r);
		} else if (WIN_OFF(sa, mrl->start) < WIN_OFF(sa, start)) {
			mrl->end = start;
		} else if (WIN_OFF(sa, mrr->end  ) > WIN_OFF(sa, end  )) {
			RB_REMOVE(range_tree, &sa->retrans, mrr);
			mrr->start = end;
			RB_INSERT(range_tree, &sa->retrans, mrr);
		} else {
			/* Completely covered by this ack. */
			RB_REMOVE(range_tree, &sa->retrans, mrl);
			sa_range_free(mrl);
		}
	} else {
		/* Remove everything between mrl and mrr. */
		for (r = RB_NEXT(range_tree, &sa->retrans, mrl);
		    r != mrr; r = next) {
			next = RB_NEXT(range_tree, &sa->retrans, r);

			RB_REMOVE(range_tree, &sa->retrans, r);
			sa_range_free(r);
		}

		/* Only keep mrl if it doesn't fully overlap. */
		if (WIN_OFF(sa, mrl->start) < WIN_OFF(sa, start))
			mrl->end = start;
		else {
			RB_REMOVE(range_tree, &sa->retrans, mrl);
			sa_range_free(mrl);
		}

		/* Only keep mrr if it doesn't fully overlap. */
		if (WIN_OFF(sa, mrr->end) > WIN_OFF(sa, end)) {
			RB_REMOVE(range_tree, &sa->retrans, mrr);
			mrr->start = end;
			RB_INSERT(range_tree, &sa->retrans, mrr);
		} else {
			RB_REMOVE(range_tree, &sa->retrans, mrr);
			sa_range_free(mrr);
		}
	}

skip_retrans:
	return sa_merge(sa, &sa->ack, start, end);
}

/*
 * Update the retransmit data to include start, end.
 *
 * Ensures the retransmit data will not contain already acked data.
 */
ILIAS_NET2_LOCAL int
sa_timeout(struct net2_sa_tx *sa, uint32_t start, uint32_t end)
{
	struct range			*mleft, *mright;

	/* Skip empty range. */
	if (start == end)
		return 0;

	/*
	 * Check if there are any acks colliding with this timeout.
	 */
	mleft = sa_range_merge_left(sa, &sa->ack, start, end);
	if (mleft == NULL) {
		/* No collisions in acks, merge in the whole range. */
		assert(sa_range_merge_right(sa, &sa->ack, start, end) == NULL);
		if (sa_merge(sa, &sa->retrans, start, end))
			return -1;
		sa_ready_to_send(sa);
		return 0;
	}

	/* Find the right-most merge. */
	mright = sa_range_merge_right(sa, &sa->ack, start, end);
	assert(mright != NULL);

	/*
	 * First, merge in the area between start and mleft->start.
	 */
	if (WIN_OFF(sa, mleft->start) > WIN_OFF(sa, start)) {
		if (sa_merge(sa, &sa->retrans, start, mleft->start))
			return -1;
		start = mleft->end;
	}

	/*
	 * Unconditionally merge in the start, mleft->start area of each
	 * subsequent entry.
	 */
	while (mleft != mright) /* Implies mleft != NULL. */ {
		/* First, increment. */
		mleft = RB_NEXT(range_tree, &sa->ack, mleft);

		/*
		 * Merge in the area between start and mleft->start.
		 * This is always non-empty, since the current mleft
		 * is after the initial mleft and therefore has a
		 * larger start than the to-be-merged range.
		 */
		if (sa_merge(sa, &sa->retrans, start, mleft->start))
			return -1;

		/* Start subsequent merge after this acked range. */
		start = mleft->end;
	}

	/*
	 * Merge in mright->end to end.
	 */
	if (WIN_OFF(sa, mright->end) < WIN_OFF(sa, end)) {
		if (sa_merge(sa, &sa->retrans, mright->end, end))
			return -1;
	}

	if (!RB_EMPTY(&sa->retrans))
		sa_ready_to_send(sa);
	return 0;
}

/* Merge start, end into the given tree. */
ILIAS_NET2_LOCAL int
sa_merge(struct net2_sa_tx *sa, struct range_tree *tree,
    uint32_t start, uint32_t end)
{
	struct range			*r, *next, *prev;

	/* Lookup left-most and right-most mergeable entries. */
	prev = sa_range_merge_left(sa, tree, start, end);
	next = sa_range_merge_right(sa, tree, start, end);

	/*
	 * Validate algorithm internals.
	 */
	assert(prev == NULL ||
	    (WIN_OFF(sa, prev->start) <= WIN_OFF(sa, end) &&
	     WIN_OFF(sa, prev->end)   >= WIN_OFF(sa, start)));
	assert(next == NULL ||
	    (WIN_OFF(sa, next->start) <= WIN_OFF(sa, end) &&
	     WIN_OFF(sa, next->end)   >= WIN_OFF(sa, start)));
	assert((prev == NULL) == (next == NULL));
	if (prev != NULL && next != NULL) {
		assert(prev == next ||
		    WIN_OFF(sa, prev->end) < WIN_OFF(sa, next->start));
	}

	/* If prev is present, simply merge the entry into prev. */
	if (prev != NULL) {
		prev->end = next->end;
		if (WIN_OFF(sa, prev->start) > WIN_OFF(sa, start))
			prev->start = start;
		if (WIN_OFF(sa, prev->end) < WIN_OFF(sa, end))
			prev->end = end;

		/* Remove remaining entries. */
		while (next != prev) {
			r = next;
			next = RB_PREV(range_tree, tree, next);
			RB_REMOVE(range_tree, tree, r);
			sa_range_free(r);
		}
	} else {
		/* No overlap. Create a new entry. */
		if ((r = sa_range_new(sa, start, end)) == NULL)
			return -1;		/* Only failure case. */
		RB_INSERT(range_tree, tree, r);
	}

	return 0;
}

/*
 * Update transits on window update.
 */
ILIAS_NET2_LOCAL void
sa_transit_update(struct net2_sa_tx *sa, uint32_t new_window_start)
{
	struct range			*t, *next;

	for (t = RB_MIN(range_tree, &sa->transit); t != NULL; t = next) {
		next = RB_NEXT(range_tree, &sa->transit, t);

		/* We're done here. */
		if (WIN_OFF(sa, t->start) >= WIN_OFF(sa, new_window_start))
			break;

		/*
		 * If the full datagram falls outside, inform the callbacks.
		 *
		 * Else, eat the bytes at the front so the whole thing falls
		 * within the window again.
		 */
		RB_REMOVE(range_tree, &sa->transit, t);
		if (WIN_OFF(sa, t->end) <= WIN_OFF(sa, new_window_start)) {
			if (!t->stream_end || t->end != new_window_start)
				t->stream_end = 0;
			t->start = t->end = new_window_start;
			if (t->stream_end)
				RB_INSERT(range_tree, &sa->transit, t);
		} else {
			t->start = new_window_start;
			RB_INSERT(range_tree, &sa->transit, t);
		}
	}
}

/*
 * Update the start of the transission window.
 */
ILIAS_NET2_LOCAL void
sa_update_winstart(struct net2_sa_tx *sa, uint32_t new_window_start)
{
	int				 do_event;

	/* Update transits. */
	sa_transit_update(sa, new_window_start);

	/* Drain transmission buffer. */
	net2_mutex_lock(sa->sendbuf_mtx);
	net2_buffer_drain(sa->sendbuf, WIN_OFF(sa, new_window_start));
	do_event = (sa->flags & SATX_CLOSED) && net2_buffer_empty(sa->sendbuf);
	net2_mutex_unlock(sa->sendbuf_mtx);

	/* Finally, update the sa value. */
	sa->win_start = new_window_start;

	if (do_event)
		sa_on_finish(sa);
}

/* Notify that this stream has data to transmit. */
ILIAS_NET2_LOCAL void
sa_ready_to_send(struct net2_sa_tx *sa)
{
	if (sa->ready_to_send)
		(*sa->ready_to_send)(sa);
}

/* Execute on-detach event. */
ILIAS_NET2_LOCAL void
sa_on_detach(struct net2_sa_tx *sa)
{
	struct timeval now = { 0, 0 };

	net2_mutex_lock(sa->sendbuf_mtx);

	if (sa->event[NET2_SATX_ON_DETACH])
		event_add(sa->event[NET2_SATX_ON_DETACH], &now);
	sa->event[NET2_SATX_ON_DETACH] = NULL;

	net2_mutex_unlock(sa->sendbuf_mtx);
}

/* Execute on-finish event. */
ILIAS_NET2_LOCAL void
sa_on_finish(struct net2_sa_tx *sa)
{
	struct timeval now = { 0, 0 };

	net2_mutex_lock(sa->sendbuf_mtx);

	if (sa->event[NET2_SATX_ON_FINISH])
		event_add(sa->event[NET2_SATX_ON_FINISH], &now);
	sa->event[NET2_SATX_ON_FINISH] = NULL;

	net2_mutex_unlock(sa->sendbuf_mtx);
}

/* Execute low-buffer event. */
ILIAS_NET2_LOCAL void
sa_on_lowbuffer(struct net2_sa_tx *sa)
{
	struct timeval now = { 0, 0 };

	/*
	 * No locking: this event is always invoked from within a locked
	 * context (sa_get_transmit).
	 */

	if (!(sa->flags & SATX_LOWBUFFER_FIRED)) {
		if (sa->event[NET2_SATX_ON_LOWBUFFER]) {
			if (!event_pending(sa->event[NET2_SATX_ON_LOWBUFFER],
			    EV_TIMEOUT, NULL))
				event_add(sa->event[NET2_SATX_ON_LOWBUFFER],
				    &now);
		}
		sa->flags |= SATX_LOWBUFFER_FIRED;
	}
}

/*
 * Gather data to transmit.
 *
 * Retransmits take priority over new transmissions.
 */
ILIAS_NET2_LOCAL int
sa_get_transmit(struct net2_sa_tx *sa, struct net2_buffer **bufptr,
    struct net2_acceptor_socket *socket,
    struct net2_cw_tx *tx, int first, size_t maxlen)
{
	struct net2_encdec_ctx		 ctx;
	struct range			*r, *collide;
	size_t				 len;
	uint32_t			 wf_start, wf_end;
	int				 i;
	struct stream_packet		 data;
	int				 is_retrans = 0;
	int				 error;

	net2_mutex_lock(sa->sendbuf_mtx);
	data.payload = NULL;

	/* Cannot do any work. */
	if (maxlen < STREAM_PACKET_OVERHEAD + STREAM_PACKET_ALIGN)
		goto out;
	/* No work to be done. */
	if (!(sa->flags & SATX_RESEND_CLOSE) && net2_buffer_empty(sa->sendbuf))
		goto out;

	/*
	 * Calculate maximum payload for this transmission.
	 */
	len = maxlen - STREAM_PACKET_OVERHEAD;
	len &= ~((size_t)(STREAM_PACKET_ALIGN - 1));
	if (len > STREAM_PACKET_MAXLEN) {
		len = (size_t)STREAM_PACKET_MAXLEN &
		    ~((size_t)(STREAM_PACKET_ALIGN - 1));
	}

	/*
	 * Attempt to perform a retransmit, if any timed out.
	 */
	r = RB_MIN(range_tree, &sa->retrans);
	if (r != NULL) {
		assert(WIN_OFF(sa, r->start) < MAX_WINDOW_SIZE);
		wf_start = r->start;
		wf_end = r->end;
		if (wf_end - wf_start > len) {
			wf_end = wf_start + len;
			r->start = wf_end;
		} else {
			RB_REMOVE(range_tree, &sa->retrans, r);
			sa_range_free(r);
		}
		is_retrans = 1;
	} else {
		/*
		 * Find the first non-transmitted sequence.
		 */
		wf_start = sa->win_start;
		for (i = 0; i <= 2; i++) {
			switch (i) {
			case 0:
				r = RB_MAX(range_tree, &sa->ack);
				break;
			case 1:
				r = RB_MAX(range_tree, &sa->transit);
				break;
			case 2:
				r = RB_MAX(range_tree, &sa->retrans);
				break;
			default:
				assert(0);
			}

			assert(r == NULL ||
			    WIN_OFF(sa, r->end) <= MAX_WINDOW_SIZE);

			if (r != NULL &&
			    WIN_OFF(sa, wf_start) < WIN_OFF(sa, r->end))
				wf_start = r->end;
		}

		/* Cannot send yet: the buffer is fully transmit/acked. */
		if (net2_buffer_length(sa->sendbuf) <= WIN_OFF(sa, wf_start)) {
			/* Oh, close is not acked yet. */
			if (sa->flags & SATX_RESEND_CLOSE) {
				assert(net2_buffer_length(sa->sendbuf) <
				    MAX_WINDOW_SIZE);
				wf_start = wf_end = sa->win_start +
				    (uint32_t)net2_buffer_length(sa->sendbuf);
			} else
				goto out;
		}

		/*
		 * Clip wf_end to fall fully within MAX_WINDOW_SIZE and
		 * within the full contents of the buffer.
		 */
		wf_end = wf_start +
		    MIN(MAX_WINDOW_SIZE, net2_buffer_length(sa->sendbuf)) -
		    WIN_OFF(sa, wf_start);
		if (wf_end - wf_start > len)
			wf_end = wf_start + len;
	}

	/* Check that the above calculation was correct. */
	if ((sa->flags & SATX_RESEND_CLOSE) && wf_start == wf_end) {
		assert(WIN_OFF(sa, wf_start) ==
		    net2_buffer_length(sa->sendbuf));
	} else if (wf_start == wf_end) {
		/* Window is full. */
		goto out;
	} else {
		assert(WIN_OFF(sa, wf_end) > WIN_OFF(sa, wf_start));
	}
	assert(WIN_OFF(sa, wf_end) <= MAX_WINDOW_SIZE);
	assert(WIN_OFF(sa, wf_end) <= net2_buffer_length(sa->sendbuf));
	assert(wf_end - wf_start <= len);

	/*
	 * r is from now on the new range.
	 *
	 * Allocate it.
	 * If the allocation fails, return an error code if no progress
	 * was made.
	 */
	if ((r = sa_range_new(sa, wf_start, wf_end)) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}

	/*
	 * Create buffer with the selected range.
	 */
	data.seq = wf_start;
	data.flags = 0;

	/* Is this the last packet in the stream? */
	if ((sa->flags & SATX_CLOSING) &&
	    (size_t)WIN_OFF(sa, wf_end) == net2_buffer_length(sa->sendbuf)) {
		/* Mark this packet as the last in the stream. */
		data.flags |= STREAM_END;
		r->stream_end = 1;
	}

	data.payload = net2_buffer_subrange(sa->sendbuf,
	    WIN_OFF(sa, wf_start), wf_end - wf_start);
	if (data.payload == NULL) {
		error = ENOMEM;
		goto fail_1;
	}

	/* Allocate buffer to store encoded packet. */
	if ((*bufptr = net2_buffer_new()) == NULL) {
		error = ENOMEM;
		goto fail_2;
	}

	/* Encode stream packet. */
	if ((error = net2_encdec_ctx_newaccsocket(&ctx, socket)) != 0)
		goto fail_3;
	if ((error = net2_cp_encode(&ctx, &cp_stream_packet, *bufptr, &data,
	    NULL)) != 0) {
		net2_encdec_ctx_rollback(&ctx);
		net2_encdec_ctx_deinit(&ctx);
		goto fail_3;
	}
	net2_encdec_ctx_deinit(&ctx);

	/* Fire low buffer event. */
	if (!is_retrans && !(sa->flags & SATX_CLOSING) &&
	    net2_buffer_length(sa->sendbuf) - WIN_OFF(sa, wf_end) <=
	    sa->low_watermark)
		sa_on_lowbuffer(sa);

	/*
	 * Register delivery callbacks.
	 */
	if ((error = net2_connwindow_txcb_register(tx,
	    net2_acceptor_socket_evbase(socket),
	    sa_transit_timeout,
	    sa_transit_ack,
	    sa_transit_nack,
	    sa_transit_destroy,
	    sa, r)) != 0)
		goto fail_3;

	/* Transmitting close, remove as pending. */
	if (r->stream_end)
		sa->flags &= ~SATX_RESEND_CLOSE;
	collide = RB_INSERT(range_tree, &sa->transit, r);
	assert(collide == NULL);

out:
	if (data.payload != NULL)
		net2_buffer_free(data.payload);
	net2_mutex_unlock(sa->sendbuf_mtx);
	return 0;

fail_3:
	net2_buffer_free(*bufptr);
	*bufptr = NULL;
fail_2:
	net2_buffer_free(data.payload);
fail_1:
	sa_range_free(r);
fail_0:
	if (is_retrans) {
		if (sa_merge(sa, &sa->retrans, wf_start, wf_end)) {
			/*
			 * Insufficient memory to keep the connection state
			 * stable. Now we are forced to break an invariant.
			 */
			/* TODO: kill connection */
			abort();
		}
	}

	/*
	 * If progress was made (first != 0, aka at least one other payload
	 * was pushed into the connection) we let the error slide.
	 */
	net2_mutex_unlock(sa->sendbuf_mtx);
	assert(error != 0);
	return (first ? error : 0);
}


/*
 * Stream acceptor implementation for ready-to-send.
 */
ILIAS_NET2_LOCAL void
nsa_ready_to_send(struct net2_sa_tx *sa)
{
	struct net2_stream_acceptor	*nsa;

	nsa = SA_TX__SA(sa);
	net2_acceptor_ready_to_send(&nsa->base);
}

/*
 * Gather transmit data.
 */
ILIAS_NET2_LOCAL int
nsa_get_transmit(struct net2_acceptor *sa_ptr, struct net2_buffer **bufptr,
    struct net2_cw_tx *tx, int first, size_t maxlen)
{
	struct net2_stream_acceptor	*nsa;

	nsa = (struct net2_stream_acceptor*)sa_ptr;
	return sa_get_transmit(&nsa->tx, bufptr,
	    net2_acceptor_socket(&nsa->base), tx, first, maxlen);
}

/*
 * Attach to a connection.
 */
ILIAS_NET2_LOCAL int
nsa_attach(struct net2_acceptor_socket *s, struct net2_acceptor *sa_ptr)
{
	struct net2_stream_acceptor	*nsa;

	nsa = (struct net2_stream_acceptor*)sa_ptr;
	/* Prevent reattaching the stream. */
	if (nsa->flags & SA_ATTACHED)
		return -1;
	nsa->flags |= SA_ATTACHED;

	if (!net2_buffer_empty(nsa->tx.sendbuf))
		net2_acceptor_ready_to_send(sa_ptr);
	return 0;
}

/*
 * Detach from a connection.
 */
ILIAS_NET2_LOCAL void
nsa_detach(struct net2_acceptor_socket *s, struct net2_acceptor *sa_ptr)
{
	struct net2_stream_acceptor	*nsa;

	nsa = (struct net2_stream_acceptor*)sa_ptr;
	sa_on_detach(&nsa->tx);
	sa_rx_on_detach(&nsa->rx);

	return;
}

/*
 * Accept input from connection.
 */
ILIAS_NET2_LOCAL void
nsa_accept(struct net2_acceptor *sa_ptr, struct net2_buffer *buf)
{
	struct net2_stream_acceptor	*nsa;

	nsa = (struct net2_stream_acceptor*)sa_ptr;
	while (!net2_buffer_empty(buf)) {
		if (sa_rx_recvbuf(&nsa->rx, net2_acceptor_socket(sa_ptr),
		    buf)) {
			/* TODO: kill connection, since delivery failed */
		}
	}
}


/*
 * Returns the transmit logic in the stream acceptor.
 */
ILIAS_NET2_EXPORT struct net2_sa_tx*
net2_stream_acceptor_tx(struct net2_stream_acceptor *nsa)
{
	return &nsa->tx;
}

/*
 * Returns the receive logic in the stream acceptor.
 */
ILIAS_NET2_EXPORT struct net2_sa_rx*
net2_stream_acceptor_rx(struct net2_stream_acceptor *nsa)
{
	return &nsa->rx;
}


/*
 * Add to-be-transmitted data.
 *
 * Returns 0 on succes, -1 on failure.
 * Will fail if the close method has been called or when shortage of memory
 * makes the operation impossible.
 */
ILIAS_NET2_EXPORT int
net2_sa_tx_write(struct net2_sa_tx *sa, const struct net2_buffer *buf)
{
	int				rv = -1;

	net2_mutex_lock(sa->sendbuf_mtx);

	if (sa->flags & SATX_CLOSING)
		goto out;
	if (net2_buffer_append(sa->sendbuf, buf))
		goto out;

	/* Clear low buffer fired event. */
	sa->flags &= ~SATX_LOWBUFFER_FIRED;

	sa_ready_to_send(sa);
	rv = 0;

out:
	net2_mutex_unlock(sa->sendbuf_mtx);
	return rv;
}

/*
 * Close the local end of the stream.
 */
ILIAS_NET2_EXPORT void
net2_sa_tx_close(struct net2_sa_tx *sa)
{
	net2_mutex_lock(sa->sendbuf_mtx);

	sa->flags |= SATX_CLOSING;
	sa_ready_to_send(sa);

	net2_mutex_unlock(sa->sendbuf_mtx);
}

/*
 * Test if the tx is closed.
 */
ILIAS_NET2_EXPORT int
net2_sa_tx_isclosed(struct net2_sa_tx *sa)
{
	int				 rv;

	net2_mutex_lock(sa->sendbuf_mtx);
	rv = (sa->flags & SATX_CLOSING);
	net2_mutex_unlock(sa->sendbuf_mtx);

	return rv;
}

/*
 * Test if the remote end is up-to-date with the local state.
 *
 * This means that:
 * - all transmissions have been received
 * - if a close was set, it has been acknowledged
 */
ILIAS_NET2_EXPORT int
net2_sa_tx_uptodate(struct net2_sa_tx *sa)
{
	int				uptodate = 1;

	net2_mutex_lock(sa->sendbuf_mtx);
	if ((sa->flags & (SATX_CLOSING | SATX_CLOSED)) == SATX_CLOSING)
		uptodate = 0;
	else if (!net2_buffer_empty(sa->sendbuf))
		uptodate = 0;
	net2_mutex_unlock(sa->sendbuf_mtx);

	return uptodate;
}

/*
 * Return the current low water mark.
 */
size_t
net2_sa_tx_get_lowwatermark(struct net2_sa_tx *sa)
{
	size_t				 rv;

	net2_mutex_lock(sa->sendbuf_mtx);
	rv = sa->low_watermark;
	net2_mutex_unlock(sa->sendbuf_mtx);
	return rv;
}

/*
 * Set the low water mark.
 *
 * Once the buffer has less unsent bytes that the low water mark,
 * the lowbuffer event will fire.
 *
 * Note that the lowbuffer event will only fire once and then stay quiet until
 * at least one succesful net2_sa_tx_write or net2_sa_tx_set_lowatermark call
 * was made.
 *
 * Returns the old watermark.
 */
size_t
net2_sa_tx_set_lowwatermark(struct net2_sa_tx *sa, size_t new_lwm)
{
	size_t				 rv;

	net2_mutex_lock(sa->sendbuf_mtx);

	rv = sa->low_watermark;
	sa->low_watermark = new_lwm;
	sa->flags &= ~SATX_LOWBUFFER_FIRED;

	net2_mutex_unlock(sa->sendbuf_mtx);
	return rv;
}

/*
 * Initialize transmission context.
 */
ILIAS_NET2_LOCAL int
sa_tx_init(struct net2_sa_tx *sa, void (*ready_to_send)(struct net2_sa_tx*))
{
	int				 i;

	sa->ready_to_send = ready_to_send;

	/* Init trees. */
	RB_INIT(&sa->ack);
	RB_INIT(&sa->transit);
	RB_INIT(&sa->retrans);

	/* Create empty buffer. */
	if ((sa->sendbuf = net2_buffer_new()) == NULL)
		goto fail_0;
	/* Create mutex. */
	if ((sa->sendbuf_mtx = net2_mutex_alloc()) == NULL)
		goto fail_1;

	/* Setup window start and flags. */
	sa->low_watermark = 0;
	sa->win_start = 0;
	sa->flags = 0;

	/* Setup events. */
	for (i = 0; i < NET2_SATX__NUM_EVENTS; i++)
		sa->event[i] = NULL;

	return 0;

fail_1:
	net2_mutex_free(sa->sendbuf_mtx);
fail_0:
	return -1;
}

/*
 * Destroy transmission context.
 */
ILIAS_NET2_LOCAL void
sa_tx_deinit(struct net2_sa_tx *sa)
{
	struct range			*r;

	/* Remove all acks. */
	while ((r = RB_ROOT(&sa->ack)) != NULL) {
		RB_REMOVE(range_tree, &sa->ack, r);
		sa_range_free(r);
	}

	/* Remove all retransmission requests. */
	while ((r = RB_ROOT(&sa->retrans)) != NULL) {
		RB_REMOVE(range_tree, &sa->retrans, r);
		sa_range_free(r);
	}

	/* Callbacks will clean up transits. */
	RB_FOREACH(r, range_tree, &sa->transit) {
		/* Set values such that sa will not be touched. */
		r->start = r->end = 0;
		r->stream_end = 0;
	}

	/* Clear buffer and mutex. */
	net2_buffer_free(sa->sendbuf);
	net2_mutex_free(sa->sendbuf_mtx);
}


/*
 * Eat a single stream_packet from in and deliver it to the sa.
 */
ILIAS_NET2_LOCAL int
sa_rx_recvbuf(struct net2_sa_rx *sa, struct net2_acceptor_socket *socket,
    struct net2_buffer *in)
{
	struct stream_packet		 sp;
	struct net2_encdec_ctx		 ctx;
	int				 rv;

	if ((rv = net2_encdec_ctx_newaccsocket(&ctx, socket)) != 0)
		goto fail_0;
	if ((rv = net2_cp_init(&ctx, &cp_stream_packet, &sp, NULL)) != 0)
		goto fail_1;
	if ((rv = net2_cp_decode(&ctx, &cp_stream_packet, &sp, in, NULL)) != 0)
		goto fail_2;

	rv = sa_rx_recv(sa, &sp);

fail_2:
	if (net2_cp_destroy(&ctx, &cp_stream_packet, &sp, NULL))
		warnx("stream_packet destroy failed");
fail_1:
	if (rv != 0)
		net2_encdec_ctx_rollback(&ctx);
	net2_encdec_ctx_deinit(&ctx);
fail_0:
	return rv;
}

/*
 * Put received stream_packet on recv queue.
 */
ILIAS_NET2_LOCAL int
sa_rx_recv(struct net2_sa_rx *sa, struct stream_packet *sp)
{
	struct fragment			*f, *mleft, *mright;
	uint32_t			 start, end;
	uint32_t			 off;

	/*
	 * Check validity:
	 * only STREAM_END packets are allowed to have no payload.
	 */
	if (net2_buffer_empty(sp->payload) && !(sp->flags & STREAM_END))
		return -1;

	/* Ensure sp is within the window. */
	if (WIN_OFF(sa, sp->seq) >= MAX_WINDOW_SIZE) {
		/*
		 * If the buffer has no overlap with the window,
		 * it is simply ancient and should be discared.
		 */
		if (net2_buffer_length(sp->payload) <= sa->win_start - sp->seq)
			return 0;

		/*
		 * Received datagram is in part in old window.
		 * Fix this now.
		 */
		net2_buffer_drain(sp->payload, sa->win_start - sp->seq);
		sp->seq = sa->win_start;
	}

	/* Calculate start and end sequence numbers. */
	start = sp->seq;
	end = start + net2_buffer_length(sp->payload);


	/*
	 * STREAM_END handling.
	 */
	if (sp->flags & STREAM_END) {
		/* Check that other receives are in agreement. */
		if ((sa->flags & SARX_CLOSING) && sa->win_close != end)
			return -1;

		/* Mark the close point. */
		sa->flags |= SARX_CLOSING;
		sa->win_close = end;

		/*
		 * If the window is already at the close point,
		 * fire the event.
		 */
		if (sa->win_start == sa->win_close)
			sa_rx_on_finish(sa);
	}

	/*
	 * Due to dropping off the start of the window, or this packet
	 * being a STREAM_END packet, it can be empty.
	 * If that is the case, don't record its emptyness.
	 */
	if (start == end)
		return 0;

	/*
	 * If this fragment starts at the window start (i.e. WIN_OFF == 0)
	 * start delivery.
	 */
	if (sa->win_start == start) {
		mright = sa_fragment_merge_right(sa, start, end);

		if (mright != NULL) {
			if (WIN_OFF(sa, mright->end) > WIN_OFF(sa, end)) {
				/* Merge in mright: it extends sp->payload. */
				off = WIN_OFF(sa, end) -
				    WIN_OFF(sa, mright->start);
				net2_buffer_truncate(sp->payload,
				    end - start - off);
				if (net2_buffer_append(sp->payload,
				    mright->payload))
					return -1;
				end = mright->end;
			}

			/*
			 * Now eat all entries up to and including mright.
			 */
			do {
				f = RB_MIN(fragment_tree, &sa->recv);
				RB_REMOVE(fragment_tree, &sa->recv, f);
				sa_fragment_free(f);
			} while (f != mright);
		}

		/* Update window. */
		sa->win_start = end;
		/* Deliver sp->payload. */
		sa_rx_deliver(sa, sp->payload);

		/* Note that the stream is complete. */
		if ((sa->flags & SARX_CLOSING) &&
		    sa->win_start == sa->win_close)
			sa_rx_on_finish(sa);

		return 0;
	}


	/* Find first merge. */
	mleft = sa_fragment_merge_left(sa, start, end);
	if (mleft == NULL) {
		/*
		 * No merge. Insert the whole thing at once.
		 */
		f = sa_fragment_new(sa, start, end, sp->payload);
		if (f == NULL)
			return -1;
		sp->payload = NULL;
		RB_INSERT(fragment_tree, &sa->recv, f);
		return 0;
	}


	/* Find last merge. */
	mright = sa_fragment_merge_right(sa, start, end);
	assert(mright != NULL);

	/*
	 * If the entry fully overlaps, simply drop it.
	 */
	if (mleft == mright &&
	    WIN_OFF(sa, mleft->start) <= WIN_OFF(sa, start) &&
	    WIN_OFF(sa, mright->end ) >= WIN_OFF(sa, end))
		return 0;

	/*
	 * Merge mleft data with sp->payload.
	 */
	if (WIN_OFF(sa, mleft->start) < WIN_OFF(sa, start)) {
		off = mleft->end - start;
		net2_buffer_drain(sp->payload, off);

		if (net2_buffer_prepend(sp->payload, mleft->payload))
			return -1;
		start = mleft->start;
	}

	/*
	 * Merge mright data with sp->payload.
	 */
	if (WIN_OFF(sa, mright->end) > WIN_OFF(sa, end)) {
		off = end - mright->start;
		net2_buffer_truncate(sp->payload, end - start - off);

		if (net2_buffer_append(sp->payload, mright->payload))
			return -1;
		end = mright->end;
	}

	/*
	 * Remove every entry in (mleft..mright].
	 *
	 * Note that we don't remove mleft, since we will alter it to represent
	 * the new fragment at this position.
	 */
	while (mright != mleft) {
		f = mright;
		mright = RB_PREV(fragment_tree, &sa->recv, mright);

		RB_REMOVE(fragment_tree, &sa->recv, f);
		sa_fragment_free(f);
	}

	/*
	 * Morph prev.
	 */
	net2_buffer_free(mleft->payload);
	mleft->payload = sp->payload;
	sp->payload = NULL;
	mleft->start = start;
	mleft->end = end;
	return 0;
}

/*
 * Deliver buffer.
 *
 * Note while it is ok to modify the buffer, the buffer may not be freed.
 * Caller will do that.
 */
ILIAS_NET2_LOCAL void
sa_rx_deliver(struct net2_sa_rx *sa, struct net2_buffer *b)
{
	net2_mutex_lock(sa->recvbuf_mtx);
	net2_buffer_append(sa->recvbuf, b);
	sa_rx_on_recv(sa);
	net2_mutex_unlock(sa->recvbuf_mtx);
}

/* Fire on_recv event. */
ILIAS_NET2_LOCAL void
sa_rx_on_recv(struct net2_sa_rx *sa)
{
	struct timeval			 now = { 0, 0 };

	/* No locking: this is always called with recvbuf_mtx locked. */

	if (sa->event[NET2_SARX_ON_RECV]) {
		if (!event_pending(sa->event[NET2_SARX_ON_RECV],
		    EV_TIMEOUT, NULL))
			event_add(sa->event[NET2_SARX_ON_RECV], &now);
	}
}

/* Fire on_finish event. */
ILIAS_NET2_LOCAL void
sa_rx_on_finish(struct net2_sa_rx *sa)
{
	struct timeval			 now = { 0, 0 };

	net2_mutex_lock(sa->recvbuf_mtx);
	if (sa->event[NET2_SARX_ON_FINISH]) {
		event_add(sa->event[NET2_SARX_ON_FINISH], &now);
		sa->event[NET2_SARX_ON_FINISH] = NULL;
	}
	net2_mutex_unlock(sa->recvbuf_mtx);
}

/* Fire on_detach event. */
ILIAS_NET2_LOCAL void
sa_rx_on_detach(struct net2_sa_rx *sa)
{
	struct timeval			 now = { 0, 0 };

	net2_mutex_lock(sa->recvbuf_mtx);
	if (sa->event[NET2_SARX_ON_DETACH]) {
		event_add(sa->event[NET2_SARX_ON_DETACH], &now);
		sa->event[NET2_SARX_ON_DETACH] = NULL;
	}
	net2_mutex_unlock(sa->recvbuf_mtx);
}

/*
 * Initialize receiving end of stream.
 */
ILIAS_NET2_LOCAL int
sa_rx_init(struct net2_sa_rx *sa)
{
	int				 i;

	RB_INIT(&sa->recv);
	sa->win_start = 0;
	/* sa->win_close = uninitialized */
	if ((sa->recvbuf = net2_buffer_new()) == NULL)
		goto fail_0;
	if ((sa->recvbuf_mtx = net2_mutex_alloc()) == NULL)
		goto fail_1;
	sa->flags = 0;

	for (i = 0; i < NET2_SARX__NUM_EVENTS; i++)
		sa->event[i] = NULL;

	return 0;

fail_1:
	net2_buffer_free(sa->recvbuf);
fail_0:
	return -1;
}

/*
 * Destroy receiving end of stream.
 */
ILIAS_NET2_LOCAL void
sa_rx_deinit(struct net2_sa_rx *sa)
{
	struct fragment			*f;

	/* Remove all acks. */
	while ((f = RB_ROOT(&sa->recv)) != NULL) {
		RB_REMOVE(fragment_tree, &sa->recv, f);
		sa_fragment_free(f);
	}

	net2_buffer_free(sa->recvbuf);
	net2_mutex_free(sa->recvbuf_mtx);
}

/*
 * Read up to len bytes data from the receive stream.
 *
 * If NET2_SARX_READ_ALL is specified, the call will fail unless at least
 * len bytes are available for reading.
 * If NET2_SARX_PEEK is specified, the call will not modify the input buffer,
 * allowing a subsequent read to return the same data.
 */
ILIAS_NET2_EXPORT struct net2_buffer*
net2_sa_rx_read(struct net2_sa_rx *sa, size_t len, int flags)
{
	struct net2_buffer		*result;

	/* Initialize. */
	result = NULL;
	net2_mutex_lock(sa->recvbuf_mtx);

	/* Buffer must contain at least len bytes, if all is to be read. */
	if (flags & NET2_SARX_READ_ALL) {
		if (net2_buffer_length(sa->recvbuf) < len)
			goto out;
	}

	/* Peek at the data. */
	if (flags & NET2_SARX_PEEK) {
		result = net2_buffer_subrange(sa->recvbuf, 0, len);
	} else {
		/* Read the data. */
		if ((result = net2_buffer_new()) != NULL)
			net2_buffer_remove_buffer(sa->recvbuf, result, len);
	}

out:
	net2_mutex_unlock(sa->recvbuf_mtx);
	return result;
}

/*
 * Returns the number of bytes immediately available for reading.
 */
ILIAS_NET2_EXPORT size_t
net2_sa_rx_avail(struct net2_sa_rx *sa)
{
	size_t				 result;

	net2_mutex_lock(sa->recvbuf_mtx);
	result = net2_buffer_length(sa->recvbuf);
	net2_mutex_unlock(sa->recvbuf_mtx);

	return result;
}

/*
 * Test if the eof character has been reached.
 */
ILIAS_NET2_EXPORT int
net2_sa_rx_eof(struct net2_sa_rx *sa)
{
	int				 eof = 1;

	net2_mutex_lock(sa->recvbuf_mtx);
	if (!(sa->flags & SARX_CLOSING))
		eof = 0;
	else if (sa->win_start != sa->win_close)
		eof = 0;
	else if (!net2_buffer_empty(sa->recvbuf))
		eof = 0;
	net2_mutex_unlock(sa->recvbuf_mtx);

	return eof;
}

/*
 * Test if the eof character is reached once the input buffer is cleared.
 */
ILIAS_NET2_EXPORT int
net2_sa_rx_eof_pending(struct net2_sa_rx *sa)
{
	int				 eof = 1;

	net2_mutex_lock(sa->recvbuf_mtx);
	if (!(sa->flags & SARX_CLOSING))
		eof = 0;
	else if (sa->win_start != sa->win_close)
		eof = 0;
	net2_mutex_unlock(sa->recvbuf_mtx);

	return eof;
}


/*
 * Set the event bound to this specific action.
 * If old is not NULL, the old event will be returned.
 */
ILIAS_NET2_EXPORT int
net2_sa_tx_set_event(struct net2_sa_tx *sa, int evno, struct event *ev,
    struct event **old)
{
	if (evno < 0 || evno >= NET2_SATX__NUM_EVENTS)
		return -1;

	net2_mutex_lock(sa->sendbuf_mtx);
	if (old != NULL)
		*old = sa->event[evno];
	sa->event[evno] = ev;
	net2_mutex_unlock(sa->sendbuf_mtx);

	return 0;
}

/*
 * Return the event bound to this specific action.
 */
ILIAS_NET2_EXPORT struct event*
net2_sa_tx_get_event(struct net2_sa_tx *sa, int evno)
{
	struct event			*ev;

	if (evno < 0 || evno >= NET2_SATX__NUM_EVENTS)
		return NULL;

	net2_mutex_lock(sa->sendbuf_mtx);
	ev = sa->event[evno];
	net2_mutex_unlock(sa->sendbuf_mtx);
	return ev;
}


/*
 * Set the event bound to this specific action.
 * If old is not NULL, the old event will be returned.
 */
ILIAS_NET2_EXPORT int
net2_sa_rx_set_event(struct net2_sa_rx *sa, int evno, struct event *ev,
    struct event **old)
{
	if (evno < 0 || evno >= NET2_SARX__NUM_EVENTS)
		return -1;

	net2_mutex_lock(sa->recvbuf_mtx);
	if (old != NULL)
		*old = sa->event[evno];
	sa->event[evno] = ev;
	net2_mutex_unlock(sa->recvbuf_mtx);

	return 0;
}

/*
 * Return the event bound to this specific action.
 */
ILIAS_NET2_EXPORT struct event*
net2_sa_rx_get_event(struct net2_sa_rx *sa, int evno)
{
	struct event			*ev;

	if (evno < 0 || evno >= NET2_SARX__NUM_EVENTS)
		return NULL;

	net2_mutex_lock(sa->recvbuf_mtx);
	ev = sa->event[evno];
	net2_mutex_unlock(sa->recvbuf_mtx);
	return ev;
}
