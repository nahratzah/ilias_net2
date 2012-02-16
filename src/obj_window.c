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
#include <ilias/net2/obj_window.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/mutex.h>
#include <event2/event.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>

#include <bsd_compat/bsd_compat.h>
#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <bsd_compat/queue.h>
#endif

/*
 * Object window:
 *
 * Each packet contains a sequence, which is used to ensure reliable
 * transmission and prevent duplicate receival (introduced by retransmission
 * system).
 *
 * Each packet contains a barrier, which is used to synchronize objects.
 *
 * Each packet contains a request ID, which is used at response time.
 *
 *
 * Each window has:
 * - first barrier received, last barrier received
 * - first sequence received, last sequence received
 * - sequence window start
 *
 * The start of the window is the first sequence that has not reached
 * the finished or superseded state.
 *
 * Each entry has:
 * - state (IN_PROGRESS, SUPERSEDED, FINISHED)
 */

#define MAX_WINDOW			 65536U		/* Max window size. */

/*
 * Received objwin element.
 */
struct net2_objwin_recv {
	uint32_t		 e_seq;			/* recv sequence. */
	int			 flags;			/* recv state. */
#define E_IN_PROGRESS		0x00000001		/* Work in progress. */
#define E_SUPERSEDED		0x00000002		/* Work superseded. */
#define E_FINISHED		0x00000004		/* Work finished. */

	struct net2_objwin	*objwin;		/* objwin owner. */
	struct net2_objwin_barrier
				*barrier;		/* barrier owner. */

	RB_ENTRY(net2_objwin_recv)
				 tree;
	TAILQ_ENTRY(net2_objwin_recv)
				 barrierq;

	void			*data_ptr;		/* Caller defined. */
};
TAILQ_HEAD(net2_objwin_recvq, net2_objwin_recv);

/*
 * Objwin barrier.
 */
struct net2_objwin_barrier {
	uint32_t		 b_seq;			/* barrier sequence. */

	RB_ENTRY(net2_objwin_barrier)
				 tree;
	struct net2_objwin	*objwin;		/* objwin owner. */

	struct net2_objwin_recvq pending;		/* pending exec. */
	struct net2_objwin_recvq in_progress;		/* in progress. */
	struct net2_objwin_recvq finished;		/* exec finished. */
};


/* RB comparator: recv. */
static __inline int
recv_cmp(struct net2_objwin_recv *r1, struct net2_objwin_recv *r2)
{
	uint32_t		 s1, s2;

	assert(r1->objwin == r2->objwin);
	s1 = r1->e_seq - r1->objwin->window_start;
	s2 = r2->e_seq - r1->objwin->window_start;
	return (s1 < s2 ? -1 : s1 > s2);
}

/* RB comparator: barrier. */
static __inline int
barrier_cmp(struct net2_objwin_barrier *b1, struct net2_objwin_barrier *b2)
{
	uint32_t		 s1, s2;

	assert(b1->objwin == b2->objwin);
	s1 = b1->b_seq - b1->objwin->first_barrier;
	s2 = b2->b_seq - b1->objwin->first_barrier;
	return (s1 < s2 ? -1 : s1 > s2);
}


/* Tree implementations. */
RB_PROTOTYPE_STATIC(net2_objwin_barriers, net2_objwin_barrier, tree,
    barrier_cmp);
RB_GENERATE_STATIC(net2_objwin_barriers, net2_objwin_barrier, tree,
    barrier_cmp);
RB_PROTOTYPE_STATIC(net2_objwin_recvs, net2_objwin_recv, tree, recv_cmp);
RB_GENERATE_STATIC(net2_objwin_recvs, net2_objwin_recv, tree, recv_cmp);

/* Find recv by sequence. */
static struct net2_objwin_recv*
find_recv(struct net2_objwin *w, uint32_t seq)
{
	struct net2_objwin_recv	 search;

	search.e_seq = seq;
	search.objwin = w;
	return RB_FIND(net2_objwin_recvs, &w->recvs, &search);
}

/* Find barrier by sequence. */
static struct net2_objwin_barrier*
find_barrier(struct net2_objwin *w, uint32_t seq)
{
	struct net2_objwin_barrier
				 search;

	search.b_seq = seq;
	search.objwin = w;
	return RB_FIND(net2_objwin_barriers, &w->barriers, &search);
}

/*
 * Search for barrier.
 * If the barrier cannot be found, create one.
 */
static struct net2_objwin_barrier*
find_or_create_barrier(struct net2_objwin *w, uint32_t seq)
{
	struct net2_objwin_barrier
				*b;

	if ((b = find_barrier(w, seq)) != NULL)
		return b;

	b = malloc(sizeof(*b));
	b->b_seq = seq;
	b->objwin = w;
	TAILQ_INIT(&b->pending);
	TAILQ_INIT(&b->in_progress);
	TAILQ_INIT(&b->finished);

	RB_INSERT(net2_objwin_barriers, &w->barriers, b);
	if (seq - w->first_barrier > w->last_barrier - w->first_barrier)
		w->last_barrier = seq;
	return b;
}

/* Test if a barrier has finished execution. */
static int
barrier_finished(struct net2_objwin_barrier *b)
{
	struct net2_objwin	*w = b->objwin;

	/* Active barrier is never finished. */
	if (w->last_barrier == b->b_seq)
		return 0;
	/* Barrier can only be finished if it has no pending entries. */
	if (!TAILQ_EMPTY(&b->in_progress) || !TAILQ_EMPTY(&b->pending))
		return 0;
	/*
	 * Barrier can only keep pending empty if
	 * the lowest recv seq is not in this barrier.
	 */
	if (w->window_barrier - w->first_barrier >=
	    b->b_seq - w->first_barrier)
		return 0;

	/*
	 * All conditions are met. This barrier finished and cannot receive
	 * more entries.
	 */
	return 1;
}

/* Free all resources used by the given recv. */
static void
kill_recv(struct net2_objwin_recv *r, net2_objwin_dataptr_free data_ptr_free)
{
	struct net2_objwin	*w;
	struct net2_objwin_barrier
				*b;
	struct net2_objwin_recvq*q;

	if (r == NULL)
		return;

	w = r->objwin;
	b = r->barrier;
	if (r->data_ptr != NULL && data_ptr_free != NULL) {
		(*data_ptr_free)(r->data_ptr);
		r->data_ptr = NULL;
	}

	if (w != NULL)
		RB_REMOVE(net2_objwin_recvs, &w->recvs, r);
	if (b != NULL) {
		if (r->flags & (E_FINISHED | E_SUPERSEDED))
			q = &b->finished;
		else if (r->flags & E_IN_PROGRESS)
			q = &b->in_progress;
		else
			q = &b->pending;

		TAILQ_REMOVE(q, r, barrierq);
	}

	free(r);
}

/* Free all resources used by the given barrier. */
static void
kill_barrier(struct net2_objwin_barrier *b,
    net2_objwin_dataptr_free data_ptr_free)
{
	struct net2_objwin	*w;
	struct net2_objwin_recv	*r;

	if (b == NULL)
		return;

	w = b->objwin;

	while ((r = TAILQ_FIRST(&b->pending)) != NULL) {
		assert(r->flags & (E_FINISHED | E_SUPERSEDED));

		kill_recv(r, data_ptr_free);
	}
	while ((r = TAILQ_FIRST(&b->in_progress)) != NULL) {
		assert(r->flags & E_IN_PROGRESS);

		kill_recv(r, data_ptr_free);
	}
	while ((r = TAILQ_FIRST(&b->finished)) != NULL) {
		assert((r->flags &
		    (E_FINISHED | E_SUPERSEDED | E_IN_PROGRESS)) == 0);

		kill_recv(r, data_ptr_free);
	}

	if (w != NULL)
		RB_REMOVE(net2_objwin_barriers, &w->barriers, b);

	free(b);
}

/*
 * Iff the barrier is finished, remove it.
 *
 * Returns true if the barrier was removed.
 */
static int
barrier_test_finish(struct net2_objwin_barrier *b)
{
	struct net2_objwin	*w = b->objwin;
	uint32_t b_seq;

	if (barrier_finished(b)) {
		b_seq = b->b_seq;
		kill_barrier(b, w->data_ptr_free);

		if (w->first_barrier == b_seq) {
			assert(!RB_EMPTY(&w->barriers));

			b = RB_MIN(net2_objwin_barriers, &w->barriers);
			w->first_barrier = b->b_seq;
		}

		return 1;
	}
	return 0;
}

/* Calculate new start of window. */
static void
update_window_start(struct net2_objwin *w)
{
	struct net2_objwin_recv	*r, *next;
	uint32_t		 wbarrier;
	struct net2_objwin_barrier
				*b;

	for (r = RB_MIN(net2_objwin_recvs, &w->recvs);
	    r != NULL && r->e_seq == w->window_start &&
	      (r->flags & (E_FINISHED | E_SUPERSEDED));
	    r = next) {
		next = RB_NEXT(net2_objwin_recvs, &w->recvs, r);
		b = r->barrier;
		assert(b != NULL);

		if (next != NULL && next->e_seq == r->e_seq + 1)
			wbarrier = next->barrier->b_seq;
		else
			wbarrier = b->b_seq;

		kill_recv(r, w->data_ptr_free);
		w->window_barrier = wbarrier;
		w->window_start++;
		barrier_test_finish(b);
	}
}

/*
 * Inform the objwin of the specific starting position of the
 * window barrier.
 *
 * Will remove any barrier prior to this point.
 */
static void
update_wbarrier_start(struct net2_objwin *w, uint32_t barrier)
{
	struct net2_objwin_barrier
				*b;

	/* Already up to date. */
	if (w->window_barrier == barrier)
		return;

	w->window_barrier = barrier;
	while ((b = RB_MIN(net2_objwin_barriers, &w->barriers)) != NULL) {
		if (!barrier_test_finish(b))
			break;
	}
}


/*
 * Add or override a supersede.
 *
 * On return, accept will be true if the supersede succeeded.
 *
 * Superseding an already superseded command will not fail and
 * set the accept value.
 */
ILIAS_NET2_LOCAL int
n2ow_supersede(struct net2_objwin *w, uint32_t barrier, uint32_t seq,
    int *accept, void **data_ptr)
{
	struct net2_objwin_recv	*r;
	struct net2_objwin_barrier
				*b;

	/* Reset dataptr just in case. */
	if (data_ptr != NULL)
		*data_ptr = NULL;
	/*
	 * Check that the request falls within the recv window.
	 */
	if (seq - w->window_start >= MAX_WINDOW) {
		*accept = 0;
		return 0;
	} else
		*accept = 1;

	/*
	 * If the recv exists, attempt to alter it to the superseded state.
	 * If it doesn't exist, create one in the superseded state.
	 */
	if ((r = find_recv(w, seq)) != NULL) {
		b = r->barrier;
		assert(b != NULL);

		/* Check that the barrier is consistent. */
		if (b->b_seq != barrier)
			return EINVAL;

		if (r->flags & E_SUPERSEDED)
			return 0;
		if (r->flags & (E_IN_PROGRESS | E_FINISHED))
			return EBUSY;

		/* Superseded entries are immediately finished. */
		TAILQ_REMOVE(&b->pending, r, barrierq);
		r->flags |= E_SUPERSEDED;
		TAILQ_INSERT_TAIL(&b->finished, r, barrierq);
		/* Copy-out user-supplied data. */
		if (data_ptr)
			*data_ptr = r->data_ptr;
	} else {
		if ((b = find_or_create_barrier(w, barrier)) == NULL)
			return ENOMEM;

		if ((r = malloc(sizeof(*r))) == NULL)
			return ENOMEM;
		r->e_seq = seq;
		r->objwin = w;
		r->barrier = b;
		r->flags = E_SUPERSEDED;
		r->data_ptr = NULL;

		RB_INSERT(net2_objwin_recvs, &w->recvs, r);

		/* Test that the barrier ordering doesn't get broken. */
		{
			struct net2_objwin_recv	*prev, *next;

			prev = RB_PREV(net2_objwin_recvs, &w->recvs, r);
			next = RB_NEXT(net2_objwin_recvs, &w->recvs, r);
			if (prev != NULL && barrier_cmp(prev->barrier, b) > 0)
				goto barrier_misordering;
			if (next != NULL && barrier_cmp(next->barrier, b) < 0)
				goto barrier_misordering;
		}

		TAILQ_INSERT_TAIL(&b->finished, r, barrierq);
	}

	/* Update window start. */
	if (seq == w->window_start)
		update_window_start(w);

	return 0;

barrier_misordering:
	RB_REMOVE(net2_objwin_recvs, &w->recvs, r);
	free(r);
	return EINVAL;
}

/*
 * Add a recv.
 *
 * TODO: add payload argument
 */
ILIAS_NET2_LOCAL int
n2ow_receive(struct net2_objwin *w, uint32_t barrier, uint32_t seq,
    int *accept, void *data_ptr)
{
	struct net2_objwin_recv	*r;
	struct net2_objwin_barrier
				*b;

	/*
	 * Check that the request falls within the recv window.
	 */
	if (seq - w->window_start >= MAX_WINDOW) {
		*accept = 0;
		return 0;
	} else
		*accept = 1;

	/* Already received this. */
	if ((r = find_recv(w, seq)) != NULL) {
		if (r->barrier->b_seq != barrier)
			return EINVAL;

		*accept = 0;
		return 0;
	}

	if ((b = find_or_create_barrier(w, barrier)) == NULL)
		return ENOMEM;

	if ((r = malloc(sizeof(*r))) == NULL)
		return ENOMEM;
	r->e_seq = seq;
	r->flags = 0;
	r->objwin = w;
	r->barrier = b;
	r->data_ptr = data_ptr;

	/* Insert new recv. */
	RB_INSERT(net2_objwin_recvs, &w->recvs, r);

	/* Test that the barrier ordering doesn't get broken. */
	{
		struct net2_objwin_recv	*prev, *next;

		prev = RB_PREV(net2_objwin_recvs, &w->recvs, r);
		next = RB_NEXT(net2_objwin_recvs, &w->recvs, r);
		if (prev != NULL && barrier_cmp(prev->barrier, b) > 0)
			goto barrier_misordering;
		if (next != NULL && barrier_cmp(next->barrier, b) < 0)
			goto barrier_misordering;
	}

	TAILQ_INSERT_TAIL(&b->pending, r, barrierq);

	/*
	 * Only update the barrier start: the previous value for window_barrier
	 * was the last received barrier prior to window start;
	 * the newly received barrier may be a later one.
	 */
	if (seq == w->window_start)
		update_wbarrier_start(w, barrier);

	return 0;

barrier_misordering:
	RB_REMOVE(net2_objwin_recvs, &w->recvs, r);
	free(r);
	return EINVAL;
}

/*
 * Retrieve next pending object from objwin.
 *
 * The returned recv will be marked as in-progress.
 * Returns NULL if no pending recvs are ready to execute.
 */
ILIAS_NET2_LOCAL struct net2_objwin_recv*
n2ow_get_pending(struct net2_objwin *w)
{
	struct net2_objwin_recv	*r;
	struct net2_objwin_barrier
				*b;

	if ((b = RB_MIN(net2_objwin_barriers, &w->barriers)) == NULL)
		return NULL;
	if ((r = TAILQ_FIRST(&b->pending)) == NULL)
		return NULL;

	r->flags |= E_IN_PROGRESS;
	TAILQ_REMOVE(&b->pending, r, barrierq);
	TAILQ_INSERT_TAIL(&b->in_progress, r, barrierq);
	return r;
}

/*
 * Mark an in-progress object as finished.
 */
ILIAS_NET2_LOCAL void
n2ow_finished(struct net2_objwin_recv *r)
{
	struct net2_objwin	*w = r->objwin;
	struct net2_objwin_barrier
				*b = r->barrier;

	assert(r->flags & E_IN_PROGRESS);
	r->flags &= E_IN_PROGRESS;
	r->flags |= E_FINISHED;
	TAILQ_REMOVE(&b->in_progress, r, barrierq);
	TAILQ_INSERT_TAIL(&b->finished, r, barrierq);

	if (r->e_seq == w->window_start)
		update_window_start(w);
	return;
}

/*
 * Create a new objwin.
 */
ILIAS_NET2_LOCAL int
n2ow_init(struct net2_objwin *w, net2_objwin_dataptr_free data_ptr_free)
{
	RB_INIT(&w->recvs);
	RB_INIT(&w->barriers);
	w->window_start = 0;
	w->window_barrier = w->first_barrier = w->last_barrier = 0;
	w->data_ptr_free = data_ptr_free;
	return 0;
}

/*
 * Release all resources held by objwin.
 */
ILIAS_NET2_LOCAL void
n2ow_deinit(struct net2_objwin *w)
{
	struct net2_objwin_barrier
				*b;

	while ((b = RB_ROOT(&w->barriers)) != NULL)
		kill_barrier(b, w->data_ptr_free); /* Barrier kills recv. */
}

/* Return the datapointer. */
ILIAS_NET2_LOCAL void*
n2ow_data_ptr(struct net2_objwin_recv *w)
{
	return w->data_ptr;
}


/*
 * Transmit side of objwin.
 */
struct net2_objwin_stub {
	RB_HEAD(net2_objwin_txs, net2_objwin_tx)
				 txs;			/* Message transit. */
	TAILQ_HEAD(, net2_objwin_tx)
				 sendq;			/* Need transmit. */
	TAILQ_HEAD(, net2_objwin_tx)
				 unsentq;		/* To be sent. */
	int			 flags;			/* State flags. */
#define STUB_STALLED		0x00000001	/* Transfer stall. */
#define STUB_BARRIER_INC	0x00000002	/* Barrier is raised. */
	uint32_t		 window_start;		/* Oldest un-acked. */
	uint32_t		 window_end;		/* First unsent. */
	uint32_t		 barrier;		/* Current barrier. */

	struct net2_mutex	*mtx;			/* Guard. */
	size_t			 refcnt;

	struct event		*event[NET2_OBJWIN_STUB__NUM_EVENTS];
							/* Event list. */
};

/*
 * Description of objwin tx.
 */
struct net2_objwin_tx {
	uint32_t		 e_seq;
	uint32_t		 barrier;

	struct net2_objwin_stub	*owner;		/* Point back to owner. */

	RB_ENTRY(net2_objwin_tx) tree;
	TAILQ_ENTRY(net2_objwin_tx)
				 sendq;
	struct net2_buffer	*msg;
	int			 flags;
#define TX_SENT			0x00000001	/* Was sent. */
#define TX_SUPERSEDE		0x00000002	/* Supersede instead of
						 * retransmit. */
#define TX_ON_SENDQ		0x00000004	/* On sendq. */
#define TX_RELEASED		0x00000008	/* Not in objwin_stub. */
#define TX_BARRIER_PRE_INC	0x00000100	/* Raise prior to request. */
#define TX_BARRIER_POST_INC	0x00000200	/* Raise after request. */

	struct net2_mutex	*mtx;		/* Guard. */
	size_t			 refcnt;	/* # external references. */
};

/* ID comparator. */
static __inline int
objwin_tx_cmp(struct net2_objwin_tx *t1, struct net2_objwin_tx *t2)
{
	return (t1->e_seq < t2->e_seq ? -1 : t1->e_seq > t2->e_seq);
}

RB_PROTOTYPE_STATIC(net2_objwin_txs, net2_objwin_tx, tree, objwin_tx_cmp);
RB_GENERATE_STATIC(net2_objwin_txs, net2_objwin_tx, tree, objwin_tx_cmp);

/* Fire ready-to-send event; called with w locked. */
void
n2ow_stub_ready_to_send(struct net2_objwin_stub *w)
{
	if (w->event[NET2_OBJWIN_STUB_ON_READY_TO_SEND] != NULL)
		event_active(w->event[NET2_OBJWIN_STUB_ON_READY_TO_SEND], 0, 0);
}

/* Initialize stub. */
ILIAS_NET2_LOCAL struct net2_objwin_stub*
n2ow_new_stub()
{
	struct net2_objwin_stub *w;
	int			 i;

	if ((w = malloc(sizeof(*w))) == NULL)
		goto fail_0;
	if ((w->mtx = net2_mutex_alloc()) == NULL)
		goto fail_1;
	RB_INIT(&w->txs);
	TAILQ_INIT(&w->sendq);
	w->flags = STUB_BARRIER_INC;
	w->window_start = w->window_end = 0;
	w->barrier = 0;
	w->refcnt = 1;

	/* Initialize null events. */
	for (i = 0; i < NET2_OBJWIN_STUB__NUM_EVENTS; i++)
		w->event[i] = NULL;

	return w;

fail_1:
	free(w);
fail_0:
	return NULL;
}

/* Reference stub. */
ILIAS_NET2_LOCAL void
n2ow_ref_stub(struct net2_objwin_stub *w)
{
	net2_mutex_lock(w->mtx);
	w->refcnt++;
	net2_mutex_unlock(w->mtx);
}

/*
 * Special unlock function, tests if w became unreacheable while the lock
 * was held and, if so, frees it.
 */
static void
n2ow_unlock_stub(struct net2_objwin_stub *w)
{
	struct net2_objwin_tx	*tx;
	int			 do_free;

	if (w->refcnt == 0 && RB_EMPTY(&w->txs) && TAILQ_EMPTY(&w->unsentq))
		do_free = 1;
	else
		do_free = 0;
	net2_mutex_unlock(w->mtx);

	/*
	 * Destroy the objwin_stub.
	 */
	if (do_free) {
		/*
		 * No need to free w->txs and w->unsentq: they're already
		 * empty for reaching this point.
		 */
		net2_mutex_free(w->mtx);
		free(w);
	}
}

/* Release stub. */
ILIAS_NET2_LOCAL void
n2ow_release_stub(struct net2_objwin_stub *w)
{
	net2_mutex_lock(w->mtx);
	assert(w->refcnt > 0);
	w->refcnt--;
	n2ow_unlock_stub(w);
}

/* Release tx if unreferenced. Decrement refcnt iff decrement is set. */
static void
tx_release(struct net2_objwin_tx *tx, int decrement)
{
	int			 do_free;

	net2_mutex_lock(tx->mtx);
	if (decrement)
		tx->refcnt--;

	/* Release tx memory. */
	do_free = (tx->refcnt == 0 && (tx->flags & TX_RELEASED));
	net2_mutex_unlock(tx->mtx);

	if (do_free) {
		net2_buffer_free(tx->msg);
		net2_mutex_free(tx->mtx);
		free(tx);
	}
}

/*
 * Get a transmission from objwin_stub.
 *
 * txptr: will be set to the internal ID of the transmission.
 * seq: will be set to the sequence number of the transmission.
 * barrier: will be set to the barrier of the transmission.
 * payload_ptr: will be set to the payload of the transmission.
 * maxsz: max accepted message size.
 * nullsz: treat NULL payload as having this length.
 *
 * If the command has been superseded, payload_ptr will be set to NULL.
 * If no transmission is available, txptr is set to NULL and the other
 * values are undefined.
 *
 * Returns 0, unless an error occurs.
 * If an error occurs, the argument pointers are left undefined.
 */
ILIAS_NET2_LOCAL int
n2ow_transmit_get(struct net2_objwin_stub *w, struct net2_objwin_tx **txptr,
    uint32_t *seq, uint32_t *barrier, struct net2_buffer **payload_ptr,
    size_t maxsz, size_t nullsz)
{
	struct net2_objwin_tx	*tx;

	net2_mutex_lock(w->mtx);

	/* Attempt retransmit. */
	TAILQ_FOREACH(tx, &w->sendq, sendq) {
		if (tx->msg == NULL && nullsz <= maxsz)
			break;
		else if (net2_buffer_length(tx->msg) <= maxsz)
			break;
	}

	if (tx != NULL) {
		TAILQ_REMOVE(&w->sendq, tx, sendq);
		tx->flags &= ~TX_ON_SENDQ;
	} else for (;;) {
		/* Check if we are stalled. */
		if (w->window_end - w->window_start >= MAX_WINDOW) {
			w->flags |= STUB_STALLED;
			goto empty;
		}

		/* Attempt to send a new message. */
		tx = TAILQ_FIRST(&w->unsentq);
		if (tx == NULL)
			goto empty;
		TAILQ_REMOVE(&w->unsentq, tx, sendq);

		/* If the tx has been superseded by caller, drop it now. */
		if (tx->msg == NULL) {
			tx->flags |= TX_RELEASED;
			tx_release(tx, 0);
			continue;
		}

		/* Assign sequence to new message. */
		tx->e_seq = w->window_end++;
		/* Raise barrier prior to assignment, if requested. */
		if ((tx->flags & TX_BARRIER_PRE_INC) &&
		    !(w->flags & STUB_BARRIER_INC))
			w->barrier++;
		tx->barrier = w->barrier;
		w->flags &= ~STUB_BARRIER_INC;	/* Barrier no longer raised. */
		/* Raise barrier after assignment, if requested. */
		if (tx->flags & TX_BARRIER_POST_INC) {
			w->barrier++;
			w->flags |= STUB_BARRIER_INC;
		}

		/* Store in txs. */
		RB_INSERT(net2_objwin_txs, &w->txs, tx);
		tx->flags |= TX_SENT;

		/* Check if we can send this message. */
		assert(tx->msg != NULL);
		if (net2_buffer_length(tx->msg) <= maxsz)
			break;
	}

	/* Assign sequence and barrier args. */
	*seq = tx->e_seq;
	*barrier = tx->barrier;

	/* Set the payload. Null means the command was superseded. */
	if (tx->msg == NULL)
		*payload_ptr = NULL;
	else if (tx->flags & TX_SUPERSEDE) {
		*payload_ptr = tx->msg;
		tx->msg = NULL;
	} else {
		if ((*payload_ptr = net2_buffer_copy(tx->msg)) == NULL)
			goto fail;
	}

	/* Succes. */
	*txptr = tx;
	tx->refcnt++;

	net2_mutex_unlock(w->mtx);
	return 0;

empty:
	/* No transmission. */
	net2_mutex_unlock(w->mtx);
	*txptr = NULL;
	return 0;

fail:
	net2_mutex_unlock(w->mtx);
	return -1;
}

/* Handle transmission timeout. */
ILIAS_NET2_LOCAL void
n2ow_transmit_timeout(struct net2_objwin_tx *tx)
{
	struct net2_objwin_stub	*w;

	/* Check if the tx is still on the sendq. */
	if (tx->flags & TX_RELEASED)
		return;

	w = tx->owner;

	if (!(tx->flags & TX_ON_SENDQ)) {
		net2_mutex_lock(w->mtx);
		n2ow_stub_ready_to_send(w);
		tx->flags |= TX_ON_SENDQ;
		TAILQ_INSERT_TAIL(&w->sendq, tx, sendq);
		net2_mutex_unlock(w->mtx);
	}
}

/* Handle transmission ack and release tx. */
ILIAS_NET2_LOCAL void
n2ow_transmit_ack(struct net2_objwin_tx *tx)
{
	struct net2_objwin_stub	*w;
	struct net2_objwin_tx	*next;

	/* Check if the tx is still on the sendq. */
	if (tx->flags & TX_RELEASED)
		goto release;

	w = tx->owner;

	/* Take tx from sendq. */
	if (tx->flags & TX_ON_SENDQ) {
		tx->flags &= ~TX_ON_SENDQ;
		TAILQ_REMOVE(&w->sendq, tx, sendq);
	}

	/* Update window start. */
	if (tx->e_seq == w->window_start) {
		if ((next = RB_NEXT(net2_objwin_txs, &w->txs, tx)) == NULL)
			next = RB_MIN(net2_objwin_txs, &w->txs);

		if (next == NULL)
			w->window_start = w->window_end;
		else
			w->window_start = next->e_seq;
		w->flags &= ~STUB_STALLED;
	}
release:
	tx_release(tx, 1);
}

/* Handle transmission nack and release tx. */
ILIAS_NET2_LOCAL void
n2ow_transmit_nack(struct net2_objwin_tx *tx)
{
	/* Check if the tx is still on the sendq. */
	if (tx->flags & TX_RELEASED)
		goto release;

	n2ow_transmit_timeout(tx);
release:
	tx_release(tx, 1);
}

/* Increment the reference counter on the tx. */
ILIAS_NET2_LOCAL void
n2ow_transmit_ref(struct net2_objwin_tx *tx)
{
	net2_mutex_lock(tx->mtx);
	tx->refcnt++;
	net2_mutex_unlock(tx->mtx);
}

/* Release tx pointer. */
ILIAS_NET2_LOCAL void
n2ow_tx_release(struct net2_objwin_tx *tx)
{
	tx_release(tx, 1);
}

/* Supersede and release tx. */
ILIAS_NET2_LOCAL void
n2ow_tx_cancel(struct net2_objwin_tx *tx)
{
	struct net2_objwin_stub	*w;

	w = tx->owner;

	if (!(tx->flags & TX_RELEASED) && tx->msg != NULL) {
		net2_buffer_free(tx->msg);
		tx->msg = NULL;

		if ((tx->flags & (TX_SENT | TX_ON_SENDQ)) == TX_SENT) {
			/* Cancel the message and publish the cancellation. */
			net2_mutex_lock(w->mtx);
			tx->flags |= TX_ON_SENDQ;
			TAILQ_INSERT_HEAD(&w->sendq, tx, sendq);
			net2_mutex_unlock(w->mtx);
		} else if (!(tx->flags & TX_SENT)) {
			/* Unsent message: erase immediately. */
			net2_mutex_lock(w->mtx);
			tx->flags |= TX_RELEASED;
			TAILQ_REMOVE(&w->unsentq, tx, sendq);
			net2_mutex_unlock(w->mtx);
		}
	}
	tx_release(tx, 1);
}

/*
 * Mark the message as finished and release it.
 *
 * A message isn't finished until the remote end has finished executing it.
 * May only be called once.
 */
ILIAS_NET2_LOCAL void
n2ow_transmit_finished(struct net2_objwin_tx *tx)
{
	struct net2_objwin_stub	*w;

	w = tx->owner;

	net2_mutex_lock(w->mtx);

	/* Remove from txs. */
	assert(!(tx->flags & TX_RELEASED));
	RB_REMOVE(net2_objwin_txs, &w->txs, tx);
	tx->flags |= TX_RELEASED;

	n2ow_unlock_stub(w);

	tx_release(tx, 1);
}

/* Add a transmission to the set, returning referenced tx. */
ILIAS_NET2_LOCAL struct net2_objwin_tx*
n2ow_tx_add(struct net2_objwin_stub *w, const struct net2_buffer *payload,
    int flags)
{
	struct net2_objwin_tx	*tx;

	/* Check argument. */
	if (payload == NULL)
		return NULL;

	/* Create new tx. */
	if ((tx = malloc(sizeof(*tx))) == NULL)
		goto fail;
	tx->owner = w;
	if ((tx->mtx = net2_mutex_alloc()) == NULL)
		goto fail_1;
	if ((tx->msg = net2_buffer_copy(payload)) == NULL)
		goto fail_2;
	tx->refcnt = 1;
	tx->flags = 0;

	/* Convert argument flags to internal flags. */
	if (flags & N2OW_TXADD_BARRIER_PRE)
		tx->flags |= TX_BARRIER_PRE_INC;
	if (flags & N2OW_TXADD_BARRIER_POST)
		tx->flags |= TX_BARRIER_POST_INC;
	if (flags & N2OW_TXADD_AUTO_SUPERSEDE)
		tx->flags |= TX_SUPERSEDE;

	/* Insert tx into the window. */
	net2_mutex_lock(w->mtx);
	if (TAILQ_EMPTY(&w->sendq) && TAILQ_EMPTY(&w->unsentq))
		n2ow_stub_ready_to_send(w);
	TAILQ_INSERT_TAIL(&w->unsentq, tx, sendq);
	net2_mutex_unlock(w->mtx);

	return tx;

fail_3:
	net2_buffer_free(tx->msg);
fail_2:
	net2_mutex_free(tx->mtx);
fail_1:
	free(tx);
fail:
	return NULL;
}

/* Assign event. */
ILIAS_NET2_LOCAL int
n2ow_stub_set_event(struct net2_objwin_stub *w, int evno, struct event *ev,
    struct event **old)
{
	if (evno < 0 || evno >= NET2_OBJWIN_STUB__NUM_EVENTS)
		return -1;

	net2_mutex_lock(w->mtx);
	if (old != NULL)
		*old = w->event[evno];
	w->event[evno] = ev;
	net2_mutex_unlock(w->mtx);

	return 0;
}

/* Read event. */
ILIAS_NET2_LOCAL struct event*
n2ow_stub_get_event(struct net2_objwin_stub *w, int evno)
{
	struct event		*ev;

	if (evno < 0 || evno >= NET2_OBJWIN_STUB__NUM_EVENTS)
		return NULL;

	net2_mutex_lock(w->mtx);
	ev = w->event[evno];
	net2_mutex_unlock(w->mtx);
	return ev;
}
