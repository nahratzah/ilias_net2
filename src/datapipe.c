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
#include <ilias/net2/datapipe.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/promise.h>
#include <ilias/net2/workq.h>
#include <errno.h>


/* Define type for datapipe events. */
TAILQ_HEAD(dp_wqevents_q, net2_datapipe_event);

/* Input side of the datapipe. */
struct net2_datapipe_in {
	atomic_size_t		 refcnt;
	net2_spinlock		 event_spl;	/* Guard events. */
	TAILQ_HEAD(, net2_datapipe_event_in)
				 events;
	unsigned int		 generation;
	struct dp_wqevents_q	 wq_events[NET2_DP_EVTYPE__SIZE];
};

/* Output side of the datapipe. */
struct net2_datapipe_out {
	atomic_size_t		 refcnt;
	net2_spinlock		 event_spl;	/* Guard events. */
	TAILQ_HEAD(, net2_datapipe_event_out)
				 events;
	unsigned int		 generation;
	struct dp_wqevents_q	 wq_events[NET2_DP_EVTYPE__SIZE];
};

/* Element in datapipe queue. */
struct net2_dp_elem {
	TAILQ_ENTRY(net2_dp_elem) q;
	void			*item;
};
/* Datapipe queue. */
struct net2_dp_queue {
	net2_spinlock		 elems_spl;	/* Guard elems. */
	size_t			 len;		/* Actual len of queue. */
	size_t			 maxlen;	/* Maxlen of queue. */
	TAILQ_HEAD(, net2_dp_elem)
				 elems;		/* All elements in queue. */
	struct net2_workq	*wq;		/* Event workq. */

	struct net2_workq_job	 consume,	/* Consumer job. */
				 produce;	/* Generator job. */

	struct {
		net2_dp_free	 fn;
		void		*arg;
	}			 free;		/* Element release fn. */

	struct net2_datapipe_in	 in;		/* Input side. */
	struct net2_datapipe_out out;		/* Output side. */

	atomic_int		 flags;
#define DPQ_HAS_IN		0x01		/* in.refcnt > 0 */
#define DPQ_HAS_OUT		0x02		/* out.refcnt > 0 */

	atomic_size_t		 release_refcnt; /* queue_release running. */
};

/* Enumerator for EVENT_LOCK and EVENT_UNLOCK. */
enum dpq_io {
	DPQ_IO_IN = NET2_DP_EVTYPE_IN,
	DPQ_IO_OUT = NET2_DP_EVTYPE_OUT
};

#define QUEUE_LOCK(q)		net2_spinlock_lock(&(q)->elems_spl)
#define QUEUE_UNLOCK(q)		net2_spinlock_unlock(&(q)->elems_spl)

static __inline void
EVENT_LOCK(struct net2_dp_queue *q, enum dpq_io io)
{
	net2_spinlock		*spl;

	switch (io) {
	case DPQ_IO_IN:
		spl = &q->in.event_spl;
		break;
	case DPQ_IO_OUT:
		spl = &q->out.event_spl;
		break;
	}
	net2_spinlock_lock(spl);
}
static __inline void
EVENT_UNLOCK(struct net2_dp_queue *q, enum dpq_io io)
{
	net2_spinlock		*spl;

	switch (io) {
	case DPQ_IO_IN:
		spl = &q->in.event_spl;
		break;
	case DPQ_IO_OUT:
		spl = &q->out.event_spl;
		break;
	}
	net2_spinlock_unlock(spl);
}


#define IMPL_IN_OFFSET	((size_t)&((struct net2_dp_queue*)0)->in)
#define IMPL_OUT_OFFSET	((size_t)&((struct net2_dp_queue*)0)->out)

static __inline struct net2_dp_queue*
IMPL_IN(struct net2_datapipe_in *in)
{
	return (struct net2_dp_queue*)((uintptr_t)(in) - IMPL_IN_OFFSET);
}
static __inline struct net2_dp_queue*
IMPL_OUT(struct net2_datapipe_out *out)
{
	return (struct net2_dp_queue*)((uintptr_t)(out) - IMPL_OUT_OFFSET);
}

/* Look up the mask to mark specified event as having fired. */
static __inline int
evtype_to_flag(int evtype)
{
#define BITS			 4
#define OFFSET			 24
	int			 io;
	int			 idx;
	int			 shift;

#if NET2_DP_EVTYPE__SIZE > BITS
#error evtype_to_flag needs to have more bits to store settings!
#endif
#if OFFSET + 2 * BITS > 32
#error evtype_to_flag uses more bits than an int can hold!
#endif

	io = (evtype & NET2_DP_EVTYPE_MASK);
	idx = (evtype & ~NET2_DP_EVTYPE_MASK);

	/* evtype may not overflow. */
	assert(idx >= 0 && idx < NET2_DP_EVTYPE__SIZE);
	/* io must be valid. */
	assert(io == NET2_DP_EVTYPE_IN || io == NET2_DP_EVTYPE_OUT);

	shift = OFFSET + (io == NET2_DP_EVTYPE_IN ? 0 : BITS) + idx;
	return 1 << shift;
#undef BITS
}
/* Convert evtype to dpq_io. */
static __inline enum dpq_io
evtype_to_dpqio(int evtype)
{
	int			 io;

	io = (evtype & NET2_DP_EVTYPE_MASK);
	/* io must be valid. */
	assert(io == NET2_DP_EVTYPE_IN || io == NET2_DP_EVTYPE_OUT);
	/* EVTYPE and DPQ_IO must map to the same constants. */
	assert(DPQ_IO_IN == NET2_DP_EVTYPE_IN);
	assert(DPQ_IO_OUT == NET2_DP_EVTYPE_OUT);

	return io;
}


static void	queue_depleted(struct net2_dp_queue*);
static void	queue_drain_closed(struct net2_dp_queue*);
static void	queue_destroy(struct net2_dp_queue*);

static void	invoke_producers(void*, void*);
static void	invoke_consumers(void*, void*);

static int	dp_init_event(struct net2_datapipe_event*,
		    struct net2_dp_queue*, int, struct net2_workq*,
		    net2_workq_cb, void*, void*);
static void	dp_run_event(struct net2_dp_queue*, int);
static int	setup_events(struct net2_dp_queue*, enum dpq_io);
static void	clear_events(struct net2_dp_queue*, enum dpq_io);

static void	*tf_do(void*);
static void	 tf_out_avail(void*, void*);
static void	 tf_fin(void*, void*);

static void	dp_tfprom_fin(void*, void*);
static void	dp_tfprom_do(void*, void*);
static void	dp_tfprom_post(void*, void*);

/* Clear event bit. */
static __inline void
dp_clear_event(struct net2_dp_queue *q, int evtype)
{
	atomic_fetch_and(&q->flags, ~evtype_to_flag(evtype));
}


/*
 * Acquire the queue, preventing it from being totally destroyed
 * prematurely.  Must be matched by a call to queue_release.
 */
static __inline void
queue_acquire(struct net2_dp_queue *q)
{
	/* Prevent multiple destructors from executing in parallel. */
	atomic_fetch_add(&q->release_refcnt, 1);
}
/*
 * Release logic.
 *
 * Switches off bits in the net2_dp_queue->flags, until at least one end
 * (in or out) becomes entirely unreachable, at which point as many parts
 * will be disconnected (all events, but not active references).
 * Also releases the release_refcnt, which protects against destruction
 * running too early.
 *
 * This is inlined, so the switch statement will be optimized away.
 *
 * If dpq_flag is 0, no bits will be cleared.
 */
static __inline void
queue_release(struct net2_dp_queue *q, int dpq_flag)
{
	int			 flags;

	assert(dpq_flag == DPQ_HAS_IN || dpq_flag == DPQ_HAS_OUT ||
	    dpq_flag == 0);

	/* Remove the clear bit. */
	flags = atomic_fetch_and(&q->flags, ~dpq_flag);
	if (dpq_flag == 0)
		goto out;
	assert(flags & dpq_flag);
	flags &= ~dpq_flag;

	switch (dpq_flag) {
	case DPQ_HAS_IN:
		QUEUE_LOCK(q);
		if (q->len == 0) {
			/* Input is depleted. */
			queue_depleted(q);
		}
		QUEUE_UNLOCK(q);
		break;
	case DPQ_HAS_OUT:
		if ((flags & DPQ_HAS_OUT) == 0) {
			/* Output is closed. */
			queue_drain_closed(q);
		}
		break;
	}

out:
	/*
	 * Last one to leave turns off the lights.
	 */
	if (atomic_fetch_sub(&q->release_refcnt, 1) == 1 &&
	    !(atomic_load(&q->flags) & (DPQ_HAS_IN | DPQ_HAS_OUT))) {
		/* Datapipe is no longer referenced. */
		queue_destroy(q);
	}
}

/*
 * Wait until the state of an IO event becomes ACTIVE and switch it to
 * INACTIVE.
 *
 * Called with EVENT_LOCK, returns with EVENT_LOCK.
 */
static __inline void
event_io_wait_running(struct net2_dp_queue *q, atomic_int *state,
    volatile int **deadptr, enum dpq_io io)
{
	int			 st_want;

	assert(q != NULL && state != NULL && deadptr != NULL);

	/* First try without changing locks. */
	st_want = NET2_DPEV_ACTIVE;
	if (atomic_compare_exchange_strong(state, &st_want,
	    NET2_DPEV_INACTIVE))
		return;
	if (st_want == NET2_DPEV_INACTIVE)
		return;

	/* If we are invoked from within this event, mark it dead. */
	assert(st_want == NET2_DPEV_RUNNING);
	if (net2_workq_is_self(q->wq)) {
		assert(*deadptr != NULL);
		**deadptr = 1;
		return;
	}

	/* Spin until the job ceases to be runing. */
	EVENT_UNLOCK(q, io);
	for (;;) {
		st_want = NET2_DPEV_ACTIVE;
		if (atomic_compare_exchange_weak(state, &st_want,
		    NET2_DPEV_INACTIVE) || st_want == NET2_DPEV_INACTIVE) {
			EVENT_LOCK(q, io);
			if (atomic_load(state) == NET2_DPEV_INACTIVE)
				return;
			EVENT_UNLOCK(q, io);
		}
		SPINWAIT();
	}
}


/* Create a new datapipe. */
ILIAS_NET2_EXPORT int
net2_dp_new(struct net2_datapipe_in **in_ptr,
    struct net2_datapipe_out **out_ptr,
    struct net2_workq_evbase *wqev,
    net2_dp_free free_fn, void *free_arg)
{
	struct net2_dp_queue	*q;
	int			 error;
	size_t			 i;

	if (in_ptr == NULL || out_ptr == NULL)
		return EINVAL;

	/* Set up shared queue. */
	if ((q = net2_malloc(sizeof(*q))) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	if ((error = net2_spinlock_init(&q->elems_spl)) != 0)
		goto fail_1;
	if ((error = net2_spinlock_init(&q->in.event_spl)) != 0)
		goto fail_2;
	if ((error = net2_spinlock_init(&q->out.event_spl)) != 0)
		goto fail_3;
	q->len = 0;
	q->maxlen = SIZE_MAX;
	TAILQ_INIT(&q->elems);
	q->free.fn = free_fn;
	q->free.arg = free_arg;
	atomic_init(&q->flags, DPQ_HAS_IN | DPQ_HAS_OUT |
	    evtype_to_flag(NET2_DP_EVTYPE_AVAIL | NET2_DP_EVTYPE_IN));
	atomic_init(&q->release_refcnt, 0);

	/* Set up null produce/consume jobs. */
	net2_workq_init_work_null(&q->produce);
	net2_workq_init_work_null(&q->consume);

	/* Initialize input side. */
	atomic_init(&q->in.refcnt, 1);
	TAILQ_INIT(&q->in.events);
	/* Initialize output side. */
	atomic_init(&q->out.refcnt, 1);
	TAILQ_INIT(&q->out.events);

	for (i = 0; i < NET2_DP_EVTYPE__SIZE; i++) {
		TAILQ_INIT(&q->in.wq_events[i]);
		TAILQ_INIT(&q->out.wq_events[i]);
	}

	/* Allocate workq. */
	if ((q->wq = net2_workq_new(wqev)) == NULL) {
		error = ENOMEM;
		goto fail_4;
	}

	/* Publish result. */
	*in_ptr = &q->in;
	*out_ptr = &q->out;
	return 0;


fail_5:
	net2_workq_release(q->wq);
fail_4:
	net2_spinlock_deinit(&q->out.event_spl);
fail_3:
	net2_spinlock_deinit(&q->in.event_spl);
fail_2:
	net2_spinlock_deinit(&q->elems_spl);
fail_1:
	net2_free(q);
fail_0:
	*in_ptr = NULL;
	*out_ptr = NULL;
	return error;
}

/* Reference input. */
ILIAS_NET2_EXPORT void
net2_dpin_ref(struct net2_datapipe_in *in)
{
	atomic_fetch_add(&in->refcnt, 1);
}
/* Reference output. */
ILIAS_NET2_EXPORT void
net2_dpout_ref(struct net2_datapipe_out *out)
{
	atomic_fetch_add(&out->refcnt, 1);
}
/* Release input. */
ILIAS_NET2_EXPORT void
net2_dpin_release(struct net2_datapipe_in *in)
{
	struct net2_dp_queue	*q;
	int			 flags;

	q = IMPL_IN(in);
	queue_acquire(q);
	flags = (atomic_fetch_sub(&in->refcnt, 1) == 1 ? DPQ_HAS_IN : 0);
	queue_release(q, flags);
}
/* Release output. */
ILIAS_NET2_EXPORT void
net2_dpout_release(struct net2_datapipe_out *out)
{
	struct net2_dp_queue	*q;
	int			 flags;

	q = IMPL_OUT(out);
	queue_acquire(q);
	flags = (atomic_fetch_sub(&out->refcnt, 1) == 1 ? DPQ_HAS_OUT : 0);
	queue_release(q, flags);
}

/* Set the maxlen of a queue. */
ILIAS_NET2_EXPORT int
net2_dpin_set_maxlen(struct net2_datapipe_in *in, size_t maxlen)
{
	struct net2_dp_queue	*q;

	if (in == NULL || maxlen == 0)
		return EINVAL;

	q = IMPL_IN(in);
	QUEUE_LOCK(q);
	q->maxlen = maxlen;
	QUEUE_UNLOCK(q);
	return 0;
}
/* Set the maxlen of a queue. */
ILIAS_NET2_EXPORT int
net2_dpout_set_maxlen(struct net2_datapipe_out *out, size_t maxlen)
{
	struct net2_dp_queue	*q;

	if (out == NULL || maxlen == 0)
		return EINVAL;

	q = IMPL_OUT(out);
	QUEUE_LOCK(q);
	q->maxlen = maxlen;
	QUEUE_UNLOCK(q);
	return 0;
}

/*
 * Prepare insert of element.
 *
 * Returns 0 on succes.
 * On error:
 * - return EINVAL: p or in was null.
 * - return EAGAIN: datapipe is full.
 * - return ENOMEM: insufficient memory to reserve space.
 *
 * A succesful call of this function must be matched either by
 * net2_dp_push_commit() or net2_dp_push_rollback().
 */
ILIAS_NET2_EXPORT int
net2_dp_push_prepare(struct net2_datapipe_in_prepare *p,
    struct net2_datapipe_in *in)
{
	int			 error;
	struct net2_dp_queue	*q;

	if (p == NULL || in == NULL) {
		error = EINVAL;
		goto out;
	}

	/* Reserve space in datapipe. */
	q = IMPL_IN(in);
	QUEUE_LOCK(q);
	if (q->len >= q->maxlen) {
		QUEUE_UNLOCK(q);
		error = EAGAIN;
		goto out;
	}
	q->len++;
	QUEUE_UNLOCK(q);

	if ((p->elem = net2_malloc(sizeof(*p->elem))) == NULL) {
		error = ENOMEM;

		/* Undo q->len increment. */
		QUEUE_LOCK(q);
		q->len--;
		QUEUE_UNLOCK(q);

		goto out;
	}

	p->in = in;
	net2_dpin_ref(in);

	error = 0;

out:
	if (error != 0) {
		net2_free(p->elem);
		p->elem = NULL;
		p->in = NULL;
	}
	return error;
}
/*
 * Commit earlier prepared datapipe push.
 *
 * p: prepared push operation, from a previous call to net2_dp_push_prepare.
 * item: the item that is to be added to the queue.
 *
 * Unless p is invalid or item == NULL, this function will not fail.
 *
 * If the function fails to commit, the prepared insert is still valid and
 * will need to be released with a succesful call to net2_dp_push_commit()
 * or net2_dp_push_rollback().
 */
ILIAS_NET2_EXPORT int
net2_dp_push_commit(struct net2_datapipe_in_prepare *p, void *item)
{
	struct net2_dp_queue	*q;

	if (p == NULL || p->in == NULL || p->elem == NULL || item == NULL)
		return EINVAL;

	p->elem->item = item;
	q = IMPL_IN(p->in);

	/* Insert element into queue. */
	QUEUE_LOCK(q);
	if (TAILQ_EMPTY(&q->elems))
		net2_workq_activate(&q->consume, 0);
	TAILQ_INSERT_TAIL(&q->elems, p->elem, q);
	QUEUE_UNLOCK(q);

	p->elem = NULL;
	net2_dpin_release(p->in);
	p->in = NULL;
	return 0;
}
/*
 * Rollback earlier prepared datapipe push.
 *
 * p: prepared push operation, from a previous call to net2_dp_push_prepare.
 *
 * Unless p is invalid, this function will not fail.
 */
ILIAS_NET2_EXPORT int
net2_dp_push_rollback(struct net2_datapipe_in_prepare *p)
{
	struct net2_dp_queue	*q;

	if (p == NULL || p->in == NULL || p->elem == NULL)
		return EINVAL;

	q = IMPL_IN(p->in);

	/* Insert element into queue. */
	QUEUE_LOCK(q);
	assert(q->len > 0);
	q->len--;
	/* Activate producer workq job. */
	if (q->len == q->maxlen - 1)
		net2_workq_activate(&q->produce, 0);
	QUEUE_UNLOCK(q);

	net2_free(p->elem);
	p->elem = NULL;

	net2_dpin_release(p->in);
	p->in = NULL;

	return 0;
}
/*
 * Non-transactional push operation.
 */
ILIAS_NET2_EXPORT int
net2_dp_push(struct net2_datapipe_in *in, void *item)
{
	struct net2_dp_elem	*elem;
	struct net2_dp_queue	*q;
	int			 error;

	/* Argument check. */
	if (in == NULL || item == NULL) {
		error = EINVAL;
		goto out;
	}

	q = IMPL_IN(in);

	/* Create insert element. */
	if ((elem = net2_malloc(sizeof(*elem))) == NULL) {
		error = ENOMEM;
		goto out;
	}
	elem->item = item;

	/* Insert element. */
	QUEUE_LOCK(q);
	if (q->len < q->maxlen) {
		error = 0;
		q->len++;
		TAILQ_INSERT_TAIL(&q->elems, elem, q);
	} else
		error = EAGAIN;	/* Too many elements. */
	QUEUE_UNLOCK(q);

	/* Free elem unless insertion was succesful. */
	if (error != 0)
		net2_free(elem);

out:
	return error;
}
/*
 * Pop an item from the queue.
 *
 * Returns NULL if the queue is empty.
 */
ILIAS_NET2_EXPORT void*
net2_dp_pop(struct net2_datapipe_out *out)
{
	struct net2_dp_elem	*elem;
	struct net2_dp_queue	*q;
	void			*rv;

	/* Argument check. */
	if (out == NULL)
		return NULL;
	q = IMPL_OUT(out);

	/* Retrieve the first elem from the queue. */
	QUEUE_LOCK(q);
	if ((elem = TAILQ_FIRST(&q->elems)) != NULL) {
		TAILQ_REMOVE(&q->elems, elem, q);
		/* If the queue is no longer full, activate the producer. */
		if (q->len-- == q->maxlen)
			net2_workq_activate(&q->produce, 0);
		/*
		 * If the queue is empty, mark it empty.
		 * Since an empty queue may be depleted, check that case
		 * here.
		 *
		 * Note that we do not do the queue_{acquire,release} dance,
		 * since our active reference to out (by caller) will
		 * guarantee the queue will exist past our lifetime.
		 */
		if (q->len == 0 &&
		    (atomic_load(&q->flags) & DPQ_HAS_IN) == 0)
			queue_depleted(q);
	}
	QUEUE_UNLOCK(q);

	assert(elem == NULL || elem->item != NULL);
	rv = (elem == NULL ? NULL : elem->item);
	net2_free(elem);

	return rv;
}
/* Prepare a pop operation. */
ILIAS_NET2_EXPORT void*
net2_dp_pop_prepare(struct net2_datapipe_out_prepare *p,
    struct net2_datapipe_out *out)
{
	struct net2_dp_elem	*elem;
	struct net2_dp_queue	*q;

	/* Argument check. */
	if (p == NULL)
		return NULL;

	p->out = NULL;
	p->elem = NULL;

	/* Argument check. */
	if (out == NULL)
		return NULL;

	q = IMPL_OUT(out);

	/* Retrieve the first elem from the queue. */
	QUEUE_LOCK(q);
	if ((elem = TAILQ_FIRST(&q->elems)) != NULL)
		TAILQ_REMOVE(&q->elems, elem, q);
	QUEUE_UNLOCK(q);

	assert(elem == NULL || elem->item != NULL);
	if (elem == NULL)
		return NULL;

	p->elem = elem;
	p->out = out;
	net2_dpout_ref(out);

	return (elem == NULL ? NULL : elem->item);
}
/* Commit a pop operation. */
ILIAS_NET2_EXPORT int
net2_dp_pop_commit(struct net2_datapipe_out_prepare *p)
{
	struct net2_dp_queue	*q;

	/* Argument check. */
	if (p == NULL || p->out == NULL || p->elem == NULL)
		return EINVAL;

	q = IMPL_OUT(p->out);

	QUEUE_LOCK(q);
	/* If the queue is no longer full, activate the producer. */
	if (q->len-- == q->maxlen)
		net2_workq_activate(&q->produce, 0);
	/*
	 * If the queue is empty, mark it empty.
	 * Since an empty queue may be depleted, check that case
	 * here.
	 *
	 * Note that we do not do the queue_{acquire,release} dance,
	 * since out active reference to out (by p) will
	 * guarantee the queue will exist past our lifetime.
	 */
	if (q->len == 0 &&
	    (atomic_load(&q->flags) & DPQ_HAS_IN) == 0)
		queue_depleted(q);
	QUEUE_UNLOCK(q);

	net2_dpout_release(p->out);
	net2_free(p->elem);
	p->out = NULL;
	p->elem = NULL;
	return 0;
}
/* Rollback a pop operation. */
ILIAS_NET2_EXPORT int
net2_dp_pop_rollback(struct net2_datapipe_out_prepare *p)
{
	struct net2_dp_queue	*q;

	/* Argument check. */
	if (p == NULL || p->out == NULL || p->elem == NULL)
		return EINVAL;

	q = IMPL_OUT(p->out);

	QUEUE_LOCK(q);
	TAILQ_INSERT_HEAD(&q->elems, p->elem, q);
	QUEUE_UNLOCK(q);

	net2_dpout_release(p->out);
	p->out = NULL;
	p->elem = NULL;
	return 0;
}

/*
 * When the queue is empty and all sources are released,
 * release all consumers.
 */
static void
queue_depleted(struct net2_dp_queue *q)
{
	struct net2_datapipe_event_out
			*ev_out, *next;

	assert((atomic_load(&q->flags) & DPQ_HAS_IN) == 0);
	QUEUE_LOCK(q);
	assert(q->len == 0);
	QUEUE_UNLOCK(q);

	/*
	 * Remove all out events.
	 *
	 * This is done manually, since the event is not nulled and
	 * because net2_datapipe_event_out_deinit() could invoke
	 * queue_destroy() prematurely.
	 */
	EVENT_LOCK(q, DPQ_IO_OUT);
	for (ev_out = TAILQ_FIRST(&q->out.events); ev_out != NULL; ev_out = next) {
		next = TAILQ_NEXT(ev_out, q);

		/*
		 * The only reason our lock may fail is
		 * if the event is being destroyed from
		 * within another thread.
		 */
		if (!net2_spinlock_trylock(&ev_out->spl))
			continue;

		TAILQ_REMOVE(&q->out.events, ev_out, q);

		assert(ev_out->dp == &q->out);
		ev_out->dp = NULL;
		if (atomic_fetch_sub(&q->out.refcnt, 1) == 1)
			atomic_fetch_and(&q->flags, ~DPQ_HAS_OUT);

		net2_spinlock_unlock(&ev_out->spl);
	}

	dp_run_event(q, NET2_DP_EVTYPE_OUT | NET2_DP_EVTYPE_FIN);
	EVENT_UNLOCK(q, DPQ_IO_OUT);
}
/*
 * When the drain side of the datapipe becomes unreferenced,
 * release all producers.
 */
static void
queue_drain_closed(struct net2_dp_queue *q)
{
	struct net2_datapipe_event_in
			*ev_in, *next;

	assert((atomic_load(&q->flags) & DPQ_HAS_OUT) == 0);

	/*
	 * Remove all in events.
	 *
	 * This is done manually, since the event is not nulled and
	 * because net2_datapipe_event_in_deinit() could invoke
	 * queue_destroy() prematurely.
	 */
	EVENT_LOCK(q, DPQ_IO_IN);
	for (ev_in = TAILQ_FIRST(&q->in.events); ev_in != NULL; ev_in = next) {
		next = TAILQ_NEXT(ev_in, q);

		/*
		 * The only reason our lock may fail is
		 * if the event is being destroyed from
		 * within another thread.
		 */
		if (!net2_spinlock_trylock(&ev_in->spl))
			continue;

		TAILQ_REMOVE(&q->in.events, ev_in, q);

		assert(ev_in->dp == &q->in);
		ev_in->dp = NULL;
		if (atomic_fetch_sub(&q->in.refcnt, 1) == 1)
			atomic_fetch_and(&q->flags, ~DPQ_HAS_IN);

		net2_spinlock_unlock(&ev_in->spl);
	}

	dp_run_event(q, NET2_DP_EVTYPE_IN | NET2_DP_EVTYPE_FIN);
	EVENT_UNLOCK(q, DPQ_IO_IN);
}
/* Destroy an unreferenced queue. */
static void
queue_destroy(struct net2_dp_queue *q)
{
	struct net2_dp_elem	*elem;
	size_t			 i;

	/* Stop event subsystem. */
	net2_workq_deinit_work(&q->consume);
	net2_workq_deinit_work(&q->produce);
	net2_workq_release(q->wq);

	/* Release left-over elements. */
	net2_spinlock_deinit(&q->elems_spl);
	while ((elem = TAILQ_FIRST(&q->elems)) != NULL) {
		TAILQ_REMOVE(&q->elems, elem, q);
		if (q->free.fn != NULL)
			q->free.fn(elem->item, q->free.arg);
		net2_free(elem);
	}

	/* Check that the destroy operation won't leave dangling pointers. */
	assert(atomic_load(&q->in.refcnt) == 0);
	assert(TAILQ_EMPTY(&q->in.events));
	for (i = 0; i < NET2_DP_EVTYPE__SIZE; i++)
		assert(TAILQ_EMPTY(&q->in.wq_events[i]));
	assert(atomic_load(&q->out.refcnt) == 0);
	assert(TAILQ_EMPTY(&q->out.events));
	for (i = 0; i < NET2_DP_EVTYPE__SIZE; i++)
		assert(TAILQ_EMPTY(&q->out.wq_events[i]));

	/* Finally, free the datapipe. */
	net2_free(q);
}


/*
 * Create an event on the specified datapipe input.
 *
 * wq is allowed to be null, in which case the producer will not sync with
 * a workq.
 */
ILIAS_NET2_EXPORT int
net2_datapipe_event_in_init(struct net2_datapipe_event_in *in_ev,
    struct net2_datapipe_in *in, struct net2_workq *wq,
    net2_dp_producer fn, void *arg)
{
	struct net2_dp_queue	*q;
	int			 error;

	if (in_ev == NULL || in == NULL || fn == NULL)
		return EINVAL;

	if ((error = net2_spinlock_init(&in_ev->spl)) != 0)
		goto fail_0;
	net2_spinlock_lock(&in_ev->spl);	/* error -> fail_1 */

	in_ev->wq = wq;
	in_ev->dp = in;
	in_ev->producer.fn = fn;
	in_ev->producer.arg = arg;
	atomic_init(&in_ev->state, NET2_DPEV_INACTIVE);
	in_ev->dead = NULL;

	/* Lock the datapipe event subsystem. */
	q = IMPL_IN(in);
	EVENT_LOCK(q, DPQ_IO_IN);		/* error -> fail_2 */

	/* Insert the job. */
	if ((atomic_load(&q->flags) & DPQ_HAS_OUT) != 0) {
		/* Setup producer event. */
		if ((error = setup_events(q, DPQ_IO_IN)) != 0)
			goto fail_2;

		/* Assign generation. */
		in_ev->generation = in->generation;
		TAILQ_INSERT_TAIL(&in->events, in_ev, q);
	} else
		in_ev->dp = NULL;	/* Detached mode. */

	/*
	 * No errors past this point.
	 */

	if (in_ev->dp != NULL)
		net2_dpin_ref(in);
	if (wq != NULL)
		net2_workq_ref(wq);
	net2_spinlock_unlock(&in_ev->spl);

	/* Unlock the datapipe event subsystem. */
	EVENT_UNLOCK(q, DPQ_IO_IN);

	return 0;


fail_2:
	EVENT_UNLOCK(q, DPQ_IO_IN);
fail_1:
	net2_spinlock_unlock(&in_ev->spl);
	net2_spinlock_deinit(&in_ev->spl);
fail_0:
	assert(error != 0);
	in_ev->wq = NULL;
	in_ev->dp = NULL;
	return error;
}
/* Release a datapipe input event. */
ILIAS_NET2_EXPORT void
net2_datapipe_event_in_deinit(struct net2_datapipe_event_in *in_ev)
{
	struct net2_datapipe_in	*in;
	struct net2_workq	*wq;
	struct net2_dp_queue	*q;

	if (net2_datapipe_event_in_is_null(in_ev))
		return;

	net2_spinlock_lock(&in_ev->spl);

	in = in_ev->dp;
	wq = in_ev->wq;

	/*
	 * Release datapipe.
	 *
	 * Note that we sync on the workq of the datapipe, not the workq
	 * of the consumer job (the latter grants no exclusivity and
	 * may not be present).
	 */
	if (in != NULL) {
		q = IMPL_IN(in);
		EVENT_LOCK(q, DPQ_IO_IN);

		/* Event can only be running if we deadlock. */
		event_io_wait_running(q, &in_ev->state, &in_ev->dead,
		    DPQ_IO_IN);

		TAILQ_REMOVE(&in->events, in_ev, q);
		in_ev->dp = NULL;

		/* Remove producer event. */
		clear_events(q, DPQ_IO_IN);

		EVENT_UNLOCK(q, DPQ_IO_IN);
		net2_dpin_release(in);
	}

	/* Release workq. */
	if (wq != NULL) {
		net2_workq_release(wq);
		in_ev->wq = NULL;
	}

	net2_spinlock_unlock(&in_ev->spl);
	net2_spinlock_deinit(&in_ev->spl);
}
/*
 * Create an event on the specified datapipe output.
 *
 * wq is allowed to be null, in which case the producer will not sync with
 * a workq.
 */
ILIAS_NET2_EXPORT int
net2_datapipe_event_out_init(struct net2_datapipe_event_out *out_ev,
    struct net2_datapipe_out *out, struct net2_workq *wq,
    net2_dp_consumer fn, void *arg)
{
	struct net2_dp_queue	*q;
	int			 error;
	int			 depleted;

	if (out_ev == NULL || out == NULL || fn == NULL)
		return EINVAL;

	if ((error = net2_spinlock_init(&out_ev->spl)) != 0)
		goto fail_0;
	net2_spinlock_lock(&out_ev->spl);

	out_ev->wq = wq;
	out_ev->dp = out;
	out_ev->consumer.fn = fn;
	out_ev->consumer.arg = arg;
	atomic_init(&out_ev->state, NET2_DPEV_INACTIVE);
	out_ev->dead = NULL;

	/* Lock the datapipe event subsystem. */
	q = IMPL_OUT(out);
	EVENT_LOCK(q, DPQ_IO_OUT);		/* error -> fail_2 */

	/* Test if the datapipe is in depleted mode. */
	depleted = ((atomic_load(&q->flags) & DPQ_HAS_IN) == 0);
	if (depleted) {
		QUEUE_LOCK(q);
		depleted = (q->len == 0);
		QUEUE_UNLOCK(q);
	}

	/* Insert the job. */
	if (depleted) {
		/* Setup producer event. */
		if ((error = setup_events(q, DPQ_IO_OUT)) != 0)
			goto fail_2;

		/* Assign generation. */
		out_ev->generation = out->generation;
		TAILQ_INSERT_HEAD(&out->events, out_ev, q);
	} else
		out_ev->dp = NULL;	/* Detached mode. */

	/*
	 * No errors past this point.
	 */

	if (out_ev->dp != NULL)
		net2_dpout_ref(out);
	if (wq != NULL)
		net2_workq_ref(wq);
	net2_spinlock_unlock(&out_ev->spl);

	/* Unlock the datapipe event subsystem. */
	EVENT_UNLOCK(q, DPQ_IO_OUT);

	return 0;


fail_2:
	EVENT_UNLOCK(q, DPQ_IO_OUT);
fail_1:
	net2_spinlock_unlock(&out_ev->spl);
	net2_spinlock_deinit(&out_ev->spl);
fail_0:
	assert(error != 0);
	out_ev->wq = NULL;
	out_ev->dp = NULL;
	return error;
}

/* Release a datapipe input event. */
ILIAS_NET2_EXPORT void
net2_datapipe_event_out_deinit(struct net2_datapipe_event_out *out_ev)
{
	struct net2_datapipe_out*out;
	struct net2_workq	*wq;
	struct net2_dp_queue	*q;

	if (net2_datapipe_event_out_is_null(out_ev))
		return;

	net2_spinlock_lock(&out_ev->spl);

	out = out_ev->dp;
	wq = out_ev->wq;

	/*
	 * Release datapipe.
	 *
	 * Note that we sync on the workq of the datapipe, not the workq
	 * of the consumer job (the latter grants no exclusivity and
	 * may not be present).
	 */
	if (out != NULL) {
		q = IMPL_OUT(out);
		EVENT_LOCK(q, DPQ_IO_OUT);

		/*
		 * Wait until event ceases to be running, or mark it dead if
		 * we are the ones running.
		 */
		event_io_wait_running(q, &out_ev->state, &out_ev->dead,
		    DPQ_IO_OUT);

		TAILQ_REMOVE(&out->events, out_ev, q);
		out_ev->dp = NULL;

		/* Remove consumer event. */
		clear_events(q, DPQ_IO_OUT);

		EVENT_UNLOCK(q, DPQ_IO_OUT);
		net2_dpout_release(out);
	}

	/* Release workq. */
	if (wq != NULL) {
		net2_workq_release(wq);
		out_ev->wq = NULL;
	}

	net2_spinlock_unlock(&out_ev->spl);
	net2_spinlock_deinit(&out_ev->spl);
}

/* Activate input event. */
ILIAS_NET2_EXPORT void
net2_datapipe_event_in_activate(struct net2_datapipe_event_in *in_ev)
{
	struct net2_dp_queue	*q;
	struct net2_datapipe_in	*in;
	int			 state;

	if (net2_datapipe_event_in_is_null(in_ev))
		return;

	/*
	 * Change from inactive to active.
	 * If this fails, the event was already active (maybe even running)
	 * which means no work for us.
	 */
	state = NET2_DPEV_INACTIVE;
	if (!atomic_compare_exchange_strong(&in_ev->state, &state,
	    NET2_DPEV_ACTIVE))
		return;

	/* Lock event. */
	net2_spinlock_lock(&in_ev->spl);
	if (in_ev->dp == NULL) {
		net2_spinlock_unlock(&in_ev->spl);
		return;
	}
	in = in_ev->dp;
	q = IMPL_IN(in);
	/* Acquire datapipe event lock. */
	EVENT_LOCK(q, DPQ_IO_IN);
	net2_spinlock_unlock(&in_ev->spl);

	/* Ensure the event will run. */
	in_ev->generation = in->generation - 1;
	TAILQ_REMOVE(&in->events, in_ev, q);
	TAILQ_INSERT_HEAD(&in->events, in_ev, q);
	net2_workq_activate(&q->produce, 0);

	EVENT_UNLOCK(q, DPQ_IO_IN);
}
/* Deactivate input event. */
ILIAS_NET2_EXPORT void
net2_datapipe_event_in_deactivate(struct net2_datapipe_event_in *in_ev)
{
	struct net2_dp_queue	*q;
	struct net2_datapipe_in	*in;
	int			 state;

	if (net2_datapipe_event_in_is_null(in_ev))
		return;

	state = NET2_DPEV_ACTIVE;
	if (atomic_compare_exchange_strong(&in_ev->state, &state,
	    NET2_DPEV_INACTIVE))
		return;
	if (state == NET2_DPEV_INACTIVE)
		return;
	assert(state == NET2_DPEV_RUNNING);

	/* Lock event. */
	net2_spinlock_lock(&in_ev->spl);
	if (in_ev->dp == NULL) {
		net2_spinlock_unlock(&in_ev->spl);
		return;
	}
	in = in_ev->dp;
	q = IMPL_IN(in);
	/* Acquire datapipe event lock. */
	EVENT_LOCK(q, DPQ_IO_IN);
	net2_spinlock_unlock(&in_ev->spl);
	event_io_wait_running(q, &in_ev->state, &in_ev->dead, DPQ_IO_IN);
	EVENT_UNLOCK(q, DPQ_IO_IN);
}
/* Activate output event. */
ILIAS_NET2_EXPORT void
net2_datapipe_event_out_activate(struct net2_datapipe_event_out *out_ev)
{
	struct net2_dp_queue	*q;
	struct net2_datapipe_out*out;
	int			 state;

	if (net2_datapipe_event_out_is_null(out_ev))
		return;

	/*
	 * Change from inactive to active.
	 * If this fails, the event was already active (maybe even running)
	 * which means no work for us.
	 */
	state = NET2_DPEV_INACTIVE;
	if (!atomic_compare_exchange_strong(&out_ev->state, &state,
	    NET2_DPEV_ACTIVE))
		return;

	/* Lock event. */
	net2_spinlock_lock(&out_ev->spl);
	if (out_ev->dp == NULL) {
		net2_spinlock_unlock(&out_ev->spl);
		return;
	}
	out = out_ev->dp;
	q = IMPL_OUT(out);
	/* Acquire datapipe event lock. */
	EVENT_LOCK(q, DPQ_IO_OUT);
	net2_spinlock_unlock(&out_ev->spl);

	/* Ensure the event will run. */
	out_ev->generation = out->generation - 1;
	TAILQ_REMOVE(&out->events, out_ev, q);
	TAILQ_INSERT_HEAD(&out->events, out_ev, q);
	net2_workq_activate(&q->consume, 0);

	EVENT_UNLOCK(q, DPQ_IO_OUT);
}
/* Deactivate output event. */
ILIAS_NET2_EXPORT void
net2_datapipe_event_out_deactivate(struct net2_datapipe_event_out *out_ev)
{
	struct net2_dp_queue	*q;
	struct net2_datapipe_out*out;
	int			 state;

	if (net2_datapipe_event_out_is_null(out_ev))
		return;

	state = NET2_DPEV_ACTIVE;
	if (atomic_compare_exchange_strong(&out_ev->state, &state,
	    NET2_DPEV_INACTIVE))
		return;
	if (state == NET2_DPEV_INACTIVE)
		return;
	assert(state == NET2_DPEV_RUNNING);

	/* Lock event. */
	net2_spinlock_lock(&out_ev->spl);
	if (out_ev->dp == NULL) {
		net2_spinlock_unlock(&out_ev->spl);
		return;
	}
	out = out_ev->dp;
	q = IMPL_OUT(out);
	/* Acquire datapipe event lock. */
	EVENT_LOCK(q, DPQ_IO_OUT);
	net2_spinlock_unlock(&out_ev->spl);
	event_io_wait_running(q, &out_ev->state, &out_ev->dead, DPQ_IO_OUT);
	EVENT_UNLOCK(q, DPQ_IO_OUT);
}

/*
 * Invoke producers until the queue is full.
 *
 * This function is the implementation of net2_dp_queue->produce and
 * must run on net2_dp_queue->wq.  The workq job must have the persist flag.
 */
static void
invoke_producers(void *q_ptr, void *unused ILIAS_NET2__unused)
{
	struct net2_dp_queue	*q = q_ptr;
	struct net2_dp_elem	*elem;
	unsigned int		 generation;
	struct net2_datapipe_event_in
				*in_ev;
	void			*item;
	int			 state;
	volatile int		 dead;

	/*
	 * Ensure queue will be alive regardless of what invoked functions do
	 * with regard to changing events, releasing in/out etc.
	 */
	queue_acquire(q);

	/*
	 * If we ran out of memory, we need to sleep.  Unfortunately,
	 * we have no way of waking up once memory becomes available,
	 * so we'll just stop this run and hope any workqs running before
	 * our next invocation free up some memory.
	 *
	 * XXX this spins on oom, bad...
	 */
	if ((elem = net2_malloc(sizeof(*elem))) == NULL)
		goto out;

	/* Clear events. */
	dp_clear_event(q, NET2_DP_EVTYPE_AVAIL | NET2_DP_EVTYPE_IN);

	/* Reserve a position in the queue. */
	QUEUE_LOCK(q);
	if (q->len >= q->maxlen) {
		net2_workq_deactivate(&q->produce);
		QUEUE_UNLOCK(q);
		net2_free(elem);
		goto out;
	}
	q->len++;
	QUEUE_UNLOCK(q);

	/* Increment generation counter. */
	generation = ++q->in.generation;

	/* Iterate events. */
	item = NULL;
	EVENT_LOCK(q, DPQ_IO_IN);
	while (item == NULL && (in_ev = TAILQ_FIRST(&q->in.events)) != NULL) {
		/* Generation protects us against endless loops. */
		if (in_ev->generation == generation)
			break;
		in_ev->generation = generation;

		/* Expire element. */
		TAILQ_REMOVE(&q->in.events, in_ev, q);
		TAILQ_INSERT_TAIL(&q->in.events, in_ev, q);

		/* Change from active to running state. */
		state = NET2_DPEV_ACTIVE;
		if (!atomic_compare_exchange_strong(&in_ev->state, &state,
		    NET2_DPEV_RUNNING)) {
			/* Event is inactive. */
			assert(state == NET2_DPEV_INACTIVE);
			continue;
		}

		dead = 0;
		in_ev->dead = &dead;
		EVENT_UNLOCK(q, DPQ_IO_IN);

		/* Sync with event workq. */
		net2_workq_surf(in_ev->wq, 0);

		assert(in_ev->dp == &q->in);
		assert(in_ev->producer.fn != NULL);
		item = in_ev->producer.fn(in_ev->producer.arg);

		/* Release event workq. */
		net2_workq_surf(NULL, 0);

		EVENT_LOCK(q, DPQ_IO_IN);
		if (!dead) {
			in_ev->dead = NULL;
			state = NET2_DPEV_RUNNING;
			atomic_compare_exchange_strong(&in_ev->state, &state,
			    NET2_DPEV_ACTIVE);
		}
	}
	EVENT_UNLOCK(q, DPQ_IO_IN);

	/*
	 * Update queue, either pushing back the new element or
	 * rolling back the update.
	 */
	QUEUE_LOCK(q);
	if (item == NULL) {
		/*
		 * Rollback code if no item was created by any of the producers.
		 */
		assert(q->len > 0);
		q->len--;
		net2_workq_deactivate(&q->produce);

		/* Start all wq events. */
		dp_run_event(q, NET2_DP_EVTYPE_AVAIL | NET2_DP_EVTYPE_IN);
	} else {
		/*
		 * Commit code if item was created by any of the producers.
		 */
		elem->item = item;
		TAILQ_INSERT_TAIL(&q->elems, elem, q);
		elem = NULL;
	}
	QUEUE_UNLOCK(q);

	/* Free outside of locks. */
	if (elem != NULL)
		net2_free(elem);

	/*
	 * Activate consumer.
	 *
	 * This attempts to run the consumer immediately, which should reduce
	 * latency between production and consumption.
	 */
	if (item != NULL)
		net2_workq_activate(&q->consume, NET2_WQ_ACT_IMMED);

out:
	queue_release(q, 0);
	return;
}

/*
 * Invoke consumers until the queue is full.
 *
 * This function is the implementation of net2_dp_queue->consume and
 * must run on net2_dp_queue->wq.  The workq job must have the persist flag.
 */
static void
invoke_consumers(void *q_ptr, void *unused ILIAS_NET2__unused)
{
	struct net2_dp_queue	*q = q_ptr;
	struct net2_datapipe_event_out
				*ev_out;
	struct net2_dp_elem	*elem;
	void			*item;
	int			 state;
	unsigned int		 generation;
	volatile int		 dead;

	/*
	 * Ensure queue will be alive regardless of what invoked functions do
	 * with regard to changing events, releasing in/out etc.
	 */
	queue_acquire(q);

	/* Start a new generation. */
	generation = ++q->out.generation;

	/* Clear events. */
	dp_clear_event(q, NET2_DP_EVTYPE_AVAIL | NET2_DP_EVTYPE_OUT);

	/*
	 * Search for an out event that is willing to handle the event.
	 */
	EVENT_LOCK(q, DPQ_IO_OUT);
	while ((ev_out = TAILQ_FIRST(&q->out.events)) != NULL) {
		/* Generation protects against endless loops. */
		if (ev_out->generation == generation) {
			ev_out = NULL;
			break;
		}
		ev_out->generation = generation;

		/* Mark event as running. */
		state = NET2_DPEV_ACTIVE;
		if (atomic_compare_exchange_strong(&ev_out->state, &state,
		    NET2_DPEV_RUNNING)) {
			/* ev_out is willing to accept a new item. */
			break;
		}

		/* Move inactive event to the rear. */
		TAILQ_REMOVE(&q->out.events, ev_out, q);
		TAILQ_INSERT_TAIL(&q->out.events, ev_out, q);
	}
	/* Stop running workq job if nothing will accept data. */
	if (ev_out == NULL) {
		/* Deactivate this function. */
		net2_workq_deactivate(&q->consume);

		/* Start all wq events if the queue is not empty. */
		QUEUE_LOCK(q);
		if (q->len == 0)
			QUEUE_UNLOCK(q);
		else {
			QUEUE_UNLOCK(q);
			dp_run_event(q,
			    NET2_DP_EVTYPE_AVAIL | NET2_DP_EVTYPE_OUT);
		}
	}
	EVENT_UNLOCK(q, DPQ_IO_OUT);
	if (ev_out == NULL)
		goto out;

	/* Acquire an element from the queue. */
	QUEUE_LOCK(q);
	elem = TAILQ_FIRST(&q->elems);
	assert(elem == NULL || elem->item != NULL);
	if (elem != NULL) {
		/* Remove from queue, update length. */
		TAILQ_REMOVE(&q->elems, elem, q);

		if (q->len-- == q->maxlen)
			net2_workq_activate(&q->produce, 0);
		if (q->len == 0 &&
		    (atomic_load(&q->flags) & DPQ_HAS_IN) == 0)
			queue_depleted(q);
	} else {
		/* Deactivate this function. */
		net2_workq_deactivate(&q->consume);
	}
	QUEUE_UNLOCK(q);

	if (elem == NULL) {
		/*
		 * No item available.
		 *
		 * Note that the event may have deactivated, in which case
		 * we will not move it back (there's no difference between
		 * the deactivation now and it being spotted later).
		 */
		state = NET2_DPEV_RUNNING;
		atomic_compare_exchange_strong(&ev_out->state, &state,
		    NET2_DPEV_ACTIVE);
		goto out;
	}

	item = elem->item;
	net2_free(elem);

	/*
	 * We now have:
	 * - ev_out -- a running consume event
	 * - item -- an item from the datapipe
	 */

	dead = 0;
	ev_out->dead = &dead;

	/* Sync with event workq. */
	net2_workq_surf(ev_out->wq, 0);

	assert(ev_out->dp == &q->out);
	assert(ev_out->consumer.fn != NULL);
	ev_out->consumer.fn(item, ev_out->consumer.arg);

	/* Release event workq. */
	net2_workq_surf(NULL, 0);

	if (!dead) {
		EVENT_LOCK(q, DPQ_IO_OUT);

		/* Clear running state. */
		state = NET2_DPEV_RUNNING;
		atomic_compare_exchange_strong(&ev_out->state, &state,
		    NET2_DPEV_ACTIVE);
		/* Move the event to the rear. */
		TAILQ_REMOVE(&q->out.events, ev_out, q);
		TAILQ_INSERT_HEAD(&q->out.events, ev_out, q);

		EVENT_UNLOCK(q, DPQ_IO_OUT);
	}

out:
	queue_release(q, 0);
	return;
}

/* Look up the dp_wqevents_q that the given evtype resolves to. */
static __inline struct dp_wqevents_q*
get_wqevq(struct net2_dp_queue *q, int evtype)
{
	struct dp_wqevents_q	*evs;
	int			 io;
	int			 idx;

	io = (evtype & NET2_DP_EVTYPE_MASK);
	idx = (evtype & ~NET2_DP_EVTYPE_MASK);

	/* evtype may not overflow. */
	if (idx < 0 || idx >= NET2_DP_EVTYPE__SIZE)
		return NULL;

	/* Determine event side. */
	switch (io) {
	case NET2_DP_EVTYPE_IN:
		evs = q->in.wq_events;
		break;
	case NET2_DP_EVTYPE_OUT:
		evs = q->out.wq_events;
		break;
	default:
		return NULL;
	}

	return &evs[idx];
}
/*
 * Run events.
 *
 * EVENT_LOCK() must be active.
 */
static void
dp_run_event(struct net2_dp_queue *q, int evtype)
{
	struct dp_wqevents_q	*wqevq;
	struct net2_datapipe_event
				*ev;

	wqevq = get_wqevq(q, evtype);
	assert(wqevq != NULL);

	/* Mark event as active. */
	if (atomic_fetch_or(&q->flags, evtype_to_flag(evtype)) & evtype_to_flag(evtype))
		return;

	TAILQ_FOREACH(ev, wqevq, dpevq)
		net2_workq_activate(&ev->job, 0);

	/* Fin type events only fire once. */
	if ((evtype & ~NET2_DP_EVTYPE_MASK) == NET2_DP_EVTYPE_FIN) {
		while ((ev = TAILQ_FIRST(wqevq)) != NULL) {
			ev->owner = NULL;
			TAILQ_REMOVE(wqevq, ev, dpevq);
			atomic_fetch_sub(&q->release_refcnt, 1);
		}
	}
}
/* True if the specified event is active. */
static __inline int
dp_event_active(struct net2_dp_queue *q, int evtype)
{
	return atomic_load(&q->flags) & evtype_to_flag(evtype);
}
/*
 * Initialize event to the specified evno.
 */
static int
dp_init_event(struct net2_datapipe_event *ev, struct net2_dp_queue *q,
    int evtype, struct net2_workq *wq,
    net2_workq_cb cb, void *arg0, void *arg1)
{
	struct dp_wqevents_q	*wqevq;
	int			 error;
	int			 active;
	enum dpq_io		 io;

	assert(q != NULL);
	if (ev == NULL)
		return EINVAL;

	ev->evtype = evtype;
	ev->owner = NULL;

	/* Unimplemented event indices return ENOSYS. */
	if ((wqevq = get_wqevq(q, evtype)) == NULL) {
		error = ENOSYS;
		goto fail_0;
	}
	/* Derive dpq_io from evtype. */
	io = evtype_to_dpqio(evtype);

	/* Initialize callback. */
	if ((error = net2_workq_init_work(&ev->job, wq, cb, arg0, arg1, 0)) != 0)
		goto fail_0;

	/*
	 * Active fin event, bypass event lock and fire right now.
	 * Note that we do not cache the 'active' variable, since we don't hold
	 * a lock (EVENT_LOCK) that would prevent the bit from changing.
	 *
	 * This if-statement simply skips the locking overhead.
	 */
	if ((evtype & ~NET2_DP_EVTYPE_MASK) == NET2_DP_EVTYPE_FIN &&
	    dp_event_active(q, evtype)) {
fin_immed:
		net2_workq_activate(&ev->job, 0);
		return 0;
	}

	/*
	 * Link inactive or non-fin event into datapipe.
	 */
	EVENT_LOCK(q, io);
	active = dp_event_active(q, evtype);
	if ((evtype & ~NET2_DP_EVTYPE_MASK) == NET2_DP_EVTYPE_FIN && active) {
		/* Fin event became active during EVENT_LOCK(). */
		EVENT_UNLOCK(q, io);
		goto fin_immed;
	}

	if ((error = setup_events(q, io)) != 0) {
		EVENT_UNLOCK(q, io);
		goto fail_1;
	}

	queue_acquire(q);	/* Event holds reference to queue. */
	ev->owner = q;
	TAILQ_INSERT_TAIL(wqevq, ev, dpevq);

	if (active)
		net2_workq_activate(&ev->job, 0);
	EVENT_UNLOCK(q, io);
	return 0;


fail_1:
	net2_workq_deinit_work(&ev->job);
fail_0:
	assert(error != 0);
	return error;
}
/* Attach event to input side of queue. */
ILIAS_NET2_EXPORT int
net2_datapipe_event_init_in(struct net2_datapipe_event *ev,
    struct net2_datapipe_in *in, int evno, struct net2_workq *wq,
    net2_workq_cb cb, void *arg0, void *arg1)
{
	if (ev == NULL || in == NULL)
		return EINVAL;
	if (evno & NET2_DP_EVTYPE_MASK)
		return ENOSYS;

	return dp_init_event(ev, IMPL_IN(in), evno | NET2_DP_EVTYPE_IN,
	    wq, cb, arg0, arg1);
}
/* Attach event to input side of queue. */
ILIAS_NET2_EXPORT int
net2_datapipe_event_init_out(struct net2_datapipe_event *ev,
    struct net2_datapipe_out *out, int evno, struct net2_workq *wq,
    net2_workq_cb cb, void *arg0, void *arg1)
{
	if (ev == NULL || out == NULL)
		return EINVAL;
	if (evno & NET2_DP_EVTYPE_MASK)
		return ENOSYS;

	return dp_init_event(ev, IMPL_OUT(out), evno | NET2_DP_EVTYPE_OUT,
	    wq, cb, arg0, arg1);
}
/* Deinit event. */
ILIAS_NET2_EXPORT void
net2_datapipe_event_deinit(struct net2_datapipe_event *ev)
{
	struct net2_dp_queue	*q;
	struct dp_wqevents_q	*wqevq;
	enum dpq_io		 io;

	q = ev->owner;
	ev->owner = NULL;

	net2_workq_deinit_work(&ev->job);

	if (q != NULL) {
		wqevq = get_wqevq(q, ev->evtype);
		assert(wqevq != NULL);
		/* Derive dpq_io from evtype. */
		io = evtype_to_dpqio(ev->evtype);

		EVENT_LOCK(q, io);
		TAILQ_REMOVE(wqevq, ev, dpevq);
		clear_events(q, io);
		EVENT_UNLOCK(q, io);

		queue_release(q, 0);
	}
}

/*
 * Setup io event callback.
 * Called with EVENT_LOCK.
 */
static int
setup_events(struct net2_dp_queue *q, enum dpq_io io)
{
	int			 error;
	struct net2_workq_job	*job;
	net2_workq_cb		 fn;

	switch (io) {
	case DPQ_IO_IN:
		job = &q->produce;
		fn = &invoke_producers;
		break;
	case DPQ_IO_OUT:
		job = &q->consume;
		fn = &invoke_consumers;
		break;
	}

	/* Already done. */
	if (!net2_workq_work_is_null(job))
		return 0;

	QUEUE_LOCK(q);
	if (net2_workq_work_is_null(job))
		error = net2_workq_init_work(job, q->wq,
		    fn, q, NULL, NET2_WORKQ_PERSIST | NET2_WORKQ_PARALLEL);
	else
		error = 0;
	QUEUE_UNLOCK(q);
	return error;
}
/*
 * Clear io event callback.
 * Called with EVENT_LOCK.
 *
 * Will not clear if events are present.
 */
static void
clear_events(struct net2_dp_queue *q, enum dpq_io io)
{
	struct net2_workq_job	*job;

	switch (io) {
	case DPQ_IO_IN:
		if (!TAILQ_EMPTY(&q->in.events) ||
		    !TAILQ_EMPTY(&q->in.wq_events[NET2_DP_EVTYPE_AVAIL]))
			return;
		job = &q->produce;
		break;
	case DPQ_IO_OUT:
		if (!TAILQ_EMPTY(&q->out.events) ||
		    !TAILQ_EMPTY(&q->out.wq_events[NET2_DP_EVTYPE_AVAIL]))
			return;
		job = &q->consume;
		break;
	}

	if (!net2_workq_work_is_null(job)) {
		QUEUE_LOCK(q);
		net2_workq_deinit_work(job);
		QUEUE_UNLOCK(q);
	}
}


/*
 * Transformer data structure.
 * Handles transformation from one datapipe to another.
 */
struct dp_transform {
	struct net2_datapipe_out*tf_src;	/* Src of objs. */

	struct {
		net2_dp_transform fn;		/* Function pointer. */
		void		*arg;		/* First argument to fn. */
		void		(*arg_freefn)(void*);
						/* Free arg on
						 * transformer destruction. */
	}			 tf;		/* Transformation function. */

	struct net2_datapipe_event_in
				 tf_dstev;	/* Receive event. */
	struct net2_datapipe_event
				 tf_srcev,	/* Input avail. */
				 tf_srcfin_ev,	/* Input depleted. */
				 tf_dstfin_ev;	/* Output closed. */
};

/*
 * Glue two datapipes together using a transformation function.
 *
 * The transformation function may be null, in which case no transformation
 * will take place.  The transformation function may return NULL, in which
 * case the transformed element will be consumed only (useful for filtering).
 *
 * Errors:
 * - EINVAL:	invalid arguments (src, dst and wqev may not be NULL).
 * - ENOMEM:	insufficient memory to create data structures.
 */
ILIAS_NET2_EXPORT int
net2_datapipe_glue(struct net2_datapipe_out *src, struct net2_datapipe_in *dst,
    struct net2_workq_evbase *wqev,
    struct net2_workq *opt_wq, net2_dp_transform cb, void *cb_arg,
    void (*cb_arg_free)(void*))
{
	struct dp_transform	*tf;
	int			 error;
	struct net2_workq	*wq = NULL;

	/* Argument check. */
	if (src == NULL || dst == NULL || wqev == NULL)
		return EINVAL;

	/* Allocation. */
	if ((tf = net2_malloc(sizeof(*tf))) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	/* Create a workq for handling cleanup calls. */
	if ((wq = net2_workq_new(wqev)) == NULL) {
		error = ENOMEM;
		goto fail_1;
	}
	error = net2_workq_want(wq, 0);
	assert(error == 0);

	/* Initialize transformer. */
	tf->tf_src = src;
	tf->tf.fn = cb;
	tf->tf.arg = cb_arg;
	tf->tf.arg_freefn = cb_arg_free;

	if ((error = net2_datapipe_event_in_init(&tf->tf_dstev, dst,
	    opt_wq, &tf_do, tf)) != 0)
		goto fail_1;
	if ((error = net2_datapipe_event_init_out(&tf->tf_srcev, src,
	    NET2_DP_EVTYPE_AVAIL, wq, &tf_out_avail, tf, NULL)) != 0)
		goto fail_2;
	if ((error = net2_datapipe_event_init_out(&tf->tf_srcfin_ev, src,
	    NET2_DP_EVTYPE_FIN, wq, &tf_fin, tf, NULL)) != 0)
		goto fail_3;
	if ((error = net2_datapipe_event_init_in(&tf->tf_dstfin_ev, dst,
	    NET2_DP_EVTYPE_FIN, wq, &tf_fin, tf, NULL)) != 0)
		goto fail_4;

	net2_workq_unwant(wq);
	net2_workq_release(wq);
	wq = NULL;

	/* Reference src. */
	net2_dpout_ref(src);

	return 0;


fail_5:
	net2_datapipe_event_deinit(&tf->tf_dstfin_ev);
fail_4:
	net2_datapipe_event_deinit(&tf->tf_srcfin_ev);
fail_3:
	net2_datapipe_event_deinit(&tf->tf_srcev);
fail_2:
	net2_datapipe_event_in_deinit(&tf->tf_dstev);
fail_1:
	if (wq != NULL) {
		net2_workq_unwant(wq);
		net2_workq_release(wq);
	}
	net2_free(tf);
fail_0:
	assert(error != 0);
	return error;
}

/* Transformer producer.  Called when the source can read more input. */
static void*
tf_do(void *tf_ptr)
{
	struct dp_transform *tf = tf_ptr;
	void		*obj;

	net2_datapipe_event_in_deactivate(&tf->tf_dstev);
	do {
		obj = net2_dp_pop(tf->tf_src);
		if (obj == NULL)
			return NULL;

		if (tf->tf.fn != NULL)
			obj = tf->tf.fn(tf->tf.arg, obj);
	} while (obj == NULL);
	net2_datapipe_event_in_activate(&tf->tf_dstev);

	return obj;
}

/* Transformer source event, called when new data is available. */
static void
tf_out_avail(void *tf_ptr, void *unused ILIAS_NET2__unused)
{
	struct dp_transform *tf = tf_ptr;

	/* Activate destination event (producer function tf_do). */
	net2_datapipe_event_in_activate(&tf->tf_dstev);
}

/*
 * Transformer finish event.  Called when the source or destination of
 * the transformer is depleted/closed.
 */
static void
tf_fin(void *tf_ptr, void *unused ILIAS_NET2__unused)
{
	struct dp_transform *tf = tf_ptr;

	/* Release events. */
	net2_datapipe_event_deinit(&tf->tf_dstfin_ev);
	net2_datapipe_event_deinit(&tf->tf_srcfin_ev);
	net2_datapipe_event_deinit(&tf->tf_srcev);
	net2_datapipe_event_in_deinit(&tf->tf_dstev);
	/* Release source. */
	net2_dpout_release(tf->tf_src);
	/* Release callback argument. */
	if (tf->tf.arg_freefn != NULL)
		tf->tf.arg_freefn(tf->tf.arg);
	/* Free transformer datastructure. */
	net2_free(tf);
}


struct dp_tfprom {
	struct net2_datapipe_in_prepare
				 prep;
	struct net2_promise_event ev;
};
struct dp_tfpromq {
	struct net2_workq	*wq;
	struct net2_datapipe_in *dst;
	struct net2_datapipe_out*src;
	struct net2_datapipe_event
				 srcfin_ev,
				 dstfin_ev,
				 src_ev,
				 dst_ev;
};

/*
 * Transformer which takes promises and starts them.
 * Once the promise completes, the promise is added to the destination.
 */
ILIAS_NET2_EXPORT int
net2_datapipe_prom_glue(struct net2_datapipe_out *src,
    struct net2_datapipe_in *dst,
    struct net2_workq_evbase *wqev)
{
	struct dp_tfpromq	*pq;
	int			 error;

	/* Argument check. */
	if (src == NULL || dst == NULL || wqev == NULL)
		return EINVAL;

	if ((pq = net2_malloc(sizeof(*pq))) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	if ((pq->wq = net2_workq_new(wqev)) == NULL) {
		error = ENOMEM;
		goto fail_1;
	}
	pq->src = src;
	pq->dst = dst;
	net2_dpout_ref(src);
	net2_dpin_ref(dst);
	/* fail_2 */

	/* Attach events for queue depletion/close. */
	if ((error = net2_datapipe_event_init_out(&pq->srcfin_ev, src,
	    NET2_DP_EVTYPE_FIN, pq->wq, &dp_tfprom_fin, pq, NULL)) != 0)
		goto fail_3;
	if ((error = net2_datapipe_event_init_in(&pq->dstfin_ev, dst,
	    NET2_DP_EVTYPE_FIN, pq->wq, &dp_tfprom_fin, pq, NULL)) != 0)
		goto fail_4;

	/* Attach events for queue availability. */
	if ((net2_datapipe_event_init_out(&pq->src_ev, src,
	    NET2_DP_EVTYPE_AVAIL, pq->wq, &dp_tfprom_do, pq, NULL)) != 0)
		goto fail_5;
	if ((net2_datapipe_event_init_in(&pq->dst_ev, dst,
	    NET2_DP_EVTYPE_AVAIL, pq->wq, &dp_tfprom_do, pq, NULL)) != 0)
		goto fail_6;
	return 0;


fail_7:
	net2_datapipe_event_deinit(&pq->dst_ev);
fail_6:
	net2_datapipe_event_deinit(&pq->src_ev);
fail_5:
	net2_datapipe_event_deinit(&pq->dstfin_ev);
fail_4:
	net2_datapipe_event_deinit(&pq->srcfin_ev);
fail_3:
	net2_dpout_release(src);
	net2_dpin_release(dst);
fail_2:
	net2_workq_release(pq->wq);
fail_1:
	net2_free(pq);
fail_0:
	assert(error != 0);
	return error;
}

/* Handle finish of promise transformer. */
static void
dp_tfprom_fin(void *pq_ptr, void *unused ILIAS_NET2__unused)
{
	struct dp_tfpromq	*pq = pq_ptr;

	net2_datapipe_event_deinit(&pq->src_ev);
	net2_datapipe_event_deinit(&pq->dst_ev);
	net2_datapipe_event_deinit(&pq->srcfin_ev);
	net2_datapipe_event_deinit(&pq->dstfin_ev);
	net2_dpout_release(pq->src);
	net2_dpin_release(pq->dst);
	net2_workq_release(pq->wq);
	net2_free(pq);
}

/* Read a promise from the source datapipe. */
static __inline int
dp_tfprom_read(struct dp_tfpromq *pq)
{
	struct net2_datapipe_out_prepare prep;
	struct dp_tfprom	*tfp;
	struct net2_promise	*prom = NULL;
	int			 error, rv;

	/* Create an event/commit structure
	 * to handle promise completion. */
	if ((tfp = net2_malloc(sizeof(*tfp))) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	/* Prepare the pop operation on the promise.
	 * By using a prepare, we can undo the pop
	 * if calls below fail. */
	if ((prom = net2_dp_pop_prepare(&prep, pq->src)) == NULL) {
		net2_free(tfp);
		return 0;
		/* fail_1 */
	}
	/* Prepare the push operation. */
	if ((error = net2_dp_push_prepare(&tfp->prep, pq->dst)) != 0) {
		rv = net2_dp_pop_rollback(&prep);
		assert(rv == 0);
		net2_free(tfp);
		return 0;
		/* fail_2 */
	}

	/* Fast track if the promise has already completed. */
	if (net2_promise_is_finished(prom)) {
		rv = net2_dp_pop_commit(&prep);
		assert(rv == 0);
		rv = net2_dp_push_commit(&tfp->prep, prom);
		assert(rv == 0);
		net2_free(tfp);
		return 0;
		/* fail_3 */
	}

	/* Initialize promise completion callback. */
	if ((error = net2_promise_event_init(&tfp->ev, prom,
	    NET2_PROM_ON_FINISH, pq->wq,
	    &dp_tfprom_post, tfp, prom)) != 0)
		goto fail_3;

	/* Commit pop operation. */
	error = net2_dp_pop_commit(&prep);
	assert(error == 0);

	return 0;


fail_4:
	net2_promise_event_deinit(&tfp->ev);
fail_3:
	rv = net2_dp_push_rollback(&tfp->prep);
	assert(rv == 0);
fail_2:
	rv = net2_dp_pop_rollback(&prep);
	assert(rv == 0);
fail_1:
	net2_free(tfp);
fail_0:
	assert(error != 0);
	return error;
}

static void
dp_tfprom_do(void *pq_ptr, void *unused ILIAS_NET2__unused)
{
	struct dp_tfpromq	*pq = pq_ptr;

	while (dp_tfprom_read(pq) == 0);
}

/* Post a completed promise. */
static void
dp_tfprom_post(void *tfp_ptr, void *prom_ptr)
{
	struct dp_tfprom	*tfp = tfp_ptr;
	struct net2_promise	*prom = prom_ptr;
	int			 rv;

	rv = net2_dp_push_commit(&tfp->prep, prom);
	assert(rv == 0);

	net2_promise_event_deinit(&tfp->ev);
	net2_free(tfp);
}
