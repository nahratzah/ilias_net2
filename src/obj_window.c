#include <ilias/net2/obj_window.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>

#include <bsd_compat.h>
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
kill_recv(struct net2_objwin_recv *r)
{
	struct net2_objwin	*w;
	struct net2_objwin_barrier
				*b;
	struct net2_objwin_recvq*q;

	if (r == NULL)
		return;

	w = r->objwin;
	b = r->barrier;

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
kill_barrier(struct net2_objwin_barrier *b)
{
	struct net2_objwin	*w;
	struct net2_objwin_recv	*r;

	if (b == NULL)
		return;

	w = b->objwin;

	while ((r = TAILQ_FIRST(&b->pending)) != NULL) {
		assert(r->flags & (E_FINISHED | E_SUPERSEDED));

		kill_recv(r);
	}
	while ((r = TAILQ_FIRST(&b->in_progress)) != NULL) {
		assert(r->flags & E_IN_PROGRESS);

		kill_recv(r);
	}
	while ((r = TAILQ_FIRST(&b->finished)) != NULL) {
		assert((r->flags &
		    (E_FINISHED | E_SUPERSEDED | E_IN_PROGRESS)) == 0);

		kill_recv(r);
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
		kill_barrier(b);

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

		kill_recv(r);
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
ILIAS_NET2_EXPORT int
n2ow_supersede(struct net2_objwin *w, uint32_t barrier, uint32_t seq,
    int *accept)
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
	} else {
		if ((b = find_or_create_barrier(w, barrier)) == NULL)
			return ENOMEM;

		if ((r = malloc(sizeof(*r))) == NULL)
			return ENOMEM;
		r->e_seq = seq;
		r->objwin = w;
		r->barrier = b;
		r->flags = E_SUPERSEDED;

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
ILIAS_NET2_EXPORT int
n2ow_receive(struct net2_objwin *w, uint32_t barrier, uint32_t seq,
    int *accept)
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
ILIAS_NET2_EXPORT struct net2_objwin_recv*
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
ILIAS_NET2_EXPORT void
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
ILIAS_NET2_EXPORT int
n2ow_init(struct net2_objwin *w)
{
	RB_INIT(&w->recvs);
	RB_INIT(&w->barriers);
	w->window_start = 0;
	w->window_barrier = w->first_barrier = w->last_barrier = 0;
	return 0;
}

/*
 * Release all resources held by objwin.
 */
ILIAS_NET2_EXPORT void
n2ow_deinit(struct net2_objwin *w)
{
	struct net2_objwin_barrier
				*b;

	while ((b = RB_ROOT(&w->barriers)) != NULL)
		kill_barrier(b);	/* Barrier kills recv. */
}
