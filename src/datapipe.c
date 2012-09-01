#include <ilias/net2/datapipe.h>
#include <ilias/net2/bsd_compat/atomic.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/workq.h>


/* Input side of the datapipe. */
struct net2_datapipe_in {
	atomic_size_t		 refcnt;
	TAILQ_HEAD(, net2_datapipe_event_in)
				 events;
	unsigned int		 generation;
};

/* Output side of the datapipe. */
struct net2_datapipe_out {
	atomic_size_t		 refcnt;
	TAILQ_HEAD(, net2_datapipe_event_out)
				 events;
	unsigned int		 generation;
};

/* Element in datapipe queue. */
struct net2_dp_elem {
	TAILQ_ENTRY(net2_dp_elem) q;
	void			*item;
};
/* Datapipe queue. */
struct net2_dp_queue {
	net2_spinlock		 spl;		/* Spinlock guard. */
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
#define DPQ_EMPTY		0x10		/* queue is empty. */

	atomic_size_t		 release_refcnt; /* queue_release running. */
};

#define QUEUE_LOCK(q)		net2_spinlock_lock(&(q)->spl)
#define QUEUE_UNLOCK(q)		net2_spinlock_unlock(&(q)->spl)

/* Datapipe splice, combining two datapipes into a single queue. */
struct net2_datapipe_splice {
	struct net2_datapipe_in	*in;		/* Input side. */
	struct net2_datapipe_out*out;		/* Output side. */

	TAILQ_ENTRY(net2_datapipe_splice)
				 inq,
				 outq;

	struct {
		net2_dp_transform fn;
		void		*arg;
	}			 tf;		/* Element transform fn. */
};


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


static void queue_depleted(struct net2_dp_queue*);
static void queue_drain_closed(struct net2_dp_queue*);
static void queue_destroy(struct net2_dp_queue*);

static void invoke_producers(void*, void*);
static void invoke_consumers(void*, void*);


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
		if ((flags & (DPQ_EMPTY | DPQ_HAS_IN)) == DPQ_EMPTY) {
			/* Input is depleted. */
			queue_depleted(q);
		}
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


/* Create a new datapipe. */
ILIAS_NET2_EXPORT int
net2_dp_new(struct net2_datapipe_in **in_ptr,
    struct net2_datapipe_out **out_ptr,
    struct net2_workq_evbase *wqev,
    net2_dp_free free_fn, void *free_arg)
{
	struct net2_dp_queue	*q;
	int			 error;

	if (in_ptr == NULL || out_ptr == NULL)
		return EINVAL;

	/* Set up shared queue. */
	if ((q = net2_malloc(sizeof(*q))) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	if ((error = net2_spinlock_init(&q->spl)) != 0)
		goto fail_1;
	q->len = 0;
	q->maxlen = SIZE_MAX;
	TAILQ_INIT(&q->elems);
	q->free.fn = free_fn;
	q->free.arg = free_arg;
	atomic_init(&q->flags, DPQ_HAS_IN | DPQ_HAS_OUT);
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

	/* Allocate workq. */
	if ((q->wq = net2_workq_new(wqev)) == NULL) {
		error = ENOMEM;
		goto fail_2;
	}

	/* Publish result. */
	*in_ptr = &q->in;
	*out_ptr = &q->out;
	return 0;


fail_3:
	net2_workq_release(q->wq);
fail_2:
	net2_spinlock_deinit(&q->spl);
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
	TAILQ_INSERT_TAIL(&q->elems, p->elem, q);
	QUEUE_UNLOCK(q);

	/* Activate workq job. */
	if (atomic_fetch_and(&q->flags, ~DPQ_EMPTY) & DPQ_EMPTY)
		net2_workq_activate(&q->consume, 0);

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
	if (q->len == 0)
		atomic_fetch_or(&q->flags, DPQ_EMPTY);
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

	/*
	 * Quick test: if the queue is marked as empty, it is empty.
	 *
	 * Note that the queue may actually appear to be empty after we
	 * acquire the lock (since we may have had to wait to acquire it).
	 */
	if (atomic_load(&q->flags) & DPQ_EMPTY)
		return NULL;

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
		    (atomic_fetch_or(&q->flags, DPQ_EMPTY) & DPQ_HAS_IN) == 0)
			queue_depleted(q);
	}
	QUEUE_UNLOCK(q);

	assert(elem == NULL || elem->item != NULL);
	rv = (elem == NULL ? NULL : elem->item);
	net2_free(elem);

	return rv;
}

/*
 * When the queue is empty and all sources are released,
 * release all consumers.
 */
static void
queue_depleted(struct net2_dp_queue *q)
{
	int		 want;
	struct net2_datapipe_event_out
			*ev_out, *next;

	assert((atomic_load(&q->flags) & (DPQ_HAS_IN | DPQ_EMPTY)) ==
	    DPQ_EMPTY);

	/*
	 * Since the queue is depleted, no more output events can occur.
	 * Lock event subsystem to start removing all events and splices.
	 */
	want = net2_workq_want(q->wq, 0);
	assert(want == 0 || want == EDEADLK);

	/*
	 * Remove all out events.
	 *
	 * This is done manually, since the event is not nulled and
	 * because net2_datapipe_event_out_deinit() could invoke
	 * queue_destroy() prematurely.
	 */
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

	/* Unlock workq. */
	if (want == 0)
		net2_workq_unwant(q->wq);
}
/*
 * When the drain side of the datapipe becomes unreferenced,
 * release all producers.
 */
static void
queue_drain_closed(struct net2_dp_queue *q)
{
	int		 want;
	struct net2_datapipe_event_in
			*ev_in, *next;

	assert((atomic_load(&q->flags) & DPQ_HAS_OUT) == 0);

	/*
	 * Since the queue is depleted, no more output events can occur.
	 * Lock event subsystem to start removing all events.
	 */
	want = net2_workq_want(q->wq, 0);
	assert(want == 0 || want == EDEADLK);

	/*
	 * Remove all in events.
	 *
	 * This is done manually, since the event is not nulled and
	 * because net2_datapipe_event_in_deinit() could invoke
	 * queue_destroy() prematurely.
	 */
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

	/* Unlock workq. */
	if (want == 0)
		net2_workq_unwant(q->wq);
}
/* Destroy an unreferenced queue. */
static void
queue_destroy(struct net2_dp_queue *q)
{
	struct net2_dp_elem	*elem;

	/* Stop event subsystem. */
	net2_workq_deinit_work(&q->consume);
	net2_workq_deinit_work(&q->produce);
	net2_workq_release(q->wq);

	/* Release left-over elements. */
	net2_spinlock_deinit(&q->spl);
	while ((elem = TAILQ_FIRST(&q->elems)) != NULL) {
		TAILQ_REMOVE(&q->elems, elem, q);
		if (q->free.fn != NULL)
			q->free.fn(elem->item, q->free.arg);
		net2_free(elem);
	}

	/* Check that the destroy operation won't leave dangling pointers. */
	assert(atomic_load(&q->in.refcnt) == 0);
	assert(TAILQ_EMPTY(&q->in.events));
	assert(atomic_load(&q->out.refcnt) == 0);
	assert(TAILQ_EMPTY(&q->out.events));

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
	int			 want;
	int			 error;
	int			 was_empty;

	if (in_ev == NULL || in == NULL || fn == NULL)
		return EINVAL;

	if ((error = net2_spinlock_init(&in_ev->spl)) != 0)
		goto fail_0;
	net2_spinlock_lock(&in_ev->spl);

	in_ev->wq = wq;
	in_ev->dp = in;
	in_ev->producer.fn = fn;
	in_ev->producer.arg = arg;
	atomic_init(&in_ev->state, NET2_DPEV_INACTIVE);
	in_ev->dead = NULL;

	/* Lock the datapipe event subsystem. */
	q = IMPL_IN(in);
	want = net2_workq_want(q->wq, 0);	/* error -> fail_2 */
	if (!(want == 0 || want == EDEADLK)) {
		error = want;
		goto fail_1;
	}

	/* Insert the job. */
	if ((atomic_load(&q->flags) & DPQ_HAS_OUT) != 0) {
		was_empty = TAILQ_EMPTY(&in->events);
		TAILQ_INSERT_HEAD(&in->events, in_ev, q);

		/* Setup producer event. */
		if (was_empty) {
			QUEUE_LOCK(q);
			assert(net2_workq_work_is_null(&q->produce));
			error = net2_workq_init_work(&q->produce, q->wq,
			    &invoke_producers, q, NULL, NET2_WORKQ_PERSIST);
			QUEUE_UNLOCK(q);

			/*
			 * On workq activation error,
			 * undo the event initialization.
			 */
			if (error != 0) {
				TAILQ_REMOVE(&in->events, in_ev, q);
				goto fail_2;
			}
		}

		/* Assign generation. */
		in_ev->generation = in->generation;
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
	if (want == 0)
		net2_workq_unwant(q->wq);

	return 0;


fail_2:
	if (want == 0)
		net2_workq_unwant(q->wq);
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
	int			 want;

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
		want = net2_workq_want(q->wq, 0);
		assert(want == 0 || want == EDEADLK);

		/* Event can only be running if we deadlock. */
		assert(want != EDEADLK ||
		    atomic_load(&in_ev->state) != NET2_DPEV_RUNNING);
		if (want == EDEADLK &&
		    atomic_load(&in_ev->state) == NET2_DPEV_RUNNING) {
			assert(in_ev->dead != NULL);
			*in_ev->dead = 1;
		}

		TAILQ_REMOVE(&in->events, in_ev, q);
		in_ev->dp = NULL;

		/* Remove producer event. */
		if (TAILQ_EMPTY(&in->events)) {
			QUEUE_LOCK(q);
			net2_workq_deinit_work(&q->produce);
			assert(net2_workq_work_is_null(&q->produce));
			QUEUE_UNLOCK(q);
		}

		if (want == 0)
			net2_workq_unwant(q->wq);

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
	int			 want;
	int			 error;
	int			 was_empty;

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
	want = net2_workq_want(q->wq, 0);	/* error -> fail_2 */
	if (!(want == 0 || want == EDEADLK)) {
		error = want;
		goto fail_1;
	}

	/* Insert the job. */
	if ((atomic_load(&q->flags) & (DPQ_HAS_IN | DPQ_EMPTY)) != DPQ_EMPTY) {
		was_empty = TAILQ_EMPTY(&out->events);
		TAILQ_INSERT_HEAD(&out->events, out_ev, q);

		/* Setup producer event. */
		if (was_empty) {
			QUEUE_LOCK(q);
			assert(net2_workq_work_is_null(&q->consume));
			error = net2_workq_init_work(&q->consume, q->wq,
			    &invoke_consumers, q, NULL, NET2_WORKQ_PERSIST);
			QUEUE_UNLOCK(q);

			/*
			 * On workq activation error,
			 * undo the event initialization.
			 */
			if (error != 0) {
				TAILQ_REMOVE(&out->events, out_ev, q);
				goto fail_2;
			}
		}

		/* Assign generation. */
		out_ev->generation = out->generation;
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
	if (want == 0)
		net2_workq_unwant(q->wq);

	return 0;


fail_2:
	if (want == 0)
		net2_workq_unwant(q->wq);
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
	int			 want;

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
		want = net2_workq_want(q->wq, 0);
		assert(want == 0 || want == EDEADLK);

		/* Event can only be running if we deadlock. */
		assert(want != EDEADLK ||
		    atomic_load(&out_ev->state) != NET2_DPEV_RUNNING);
		if (want == EDEADLK &&
		    atomic_load(&out_ev->state) == NET2_DPEV_RUNNING) {
			assert(out_ev->dead != NULL);
			*out_ev->dead = 1;
		}

		TAILQ_REMOVE(&out->events, out_ev, q);
		out_ev->dp = NULL;

		/* Remove consumer event. */
		if (TAILQ_EMPTY(&out->events)) {
			QUEUE_LOCK(q);
			net2_workq_deinit_work(&q->consume);
			assert(net2_workq_work_is_null(&q->consume));
			QUEUE_UNLOCK(q);
		}

		if (want == 0)
			net2_workq_unwant(q->wq);

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
	int			 want;

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
	want = net2_workq_want(q->wq, 0);
	net2_spinlock_unlock(&in_ev->spl);
	assert(want == 0 || want == EDEADLK);

	/* Ensure the event will run. */
	in_ev->generation = in->generation - 1;
	TAILQ_REMOVE(&in->events, in_ev, q);
	TAILQ_INSERT_HEAD(&in->events, in_ev, q);
	net2_workq_activate(&q->produce, 0);

	if (want == 0)
		net2_workq_unwant(q->wq);
}
/* Deactivate input event. */
ILIAS_NET2_EXPORT void
net2_datapipe_event_in_deactivate(struct net2_datapipe_event_in *in_ev)
{
	struct net2_dp_queue	*q;
	struct net2_datapipe_in	*in;
	int			 state;
	int			 want;

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
	want = net2_workq_want(q->wq, 0);
	net2_spinlock_unlock(&in_ev->spl);
	assert(want == 0 || want == EDEADLK);

	state = NET2_DPEV_ACTIVE;
	atomic_compare_exchange_strong(&in_ev->state, &state,
	    NET2_DPEV_INACTIVE);

	if (want == 0)
		net2_workq_unwant(q->wq);
}
/* Activate output event. */
ILIAS_NET2_EXPORT void
net2_datapipe_event_out_activate(struct net2_datapipe_event_out *out_ev)
{
	struct net2_dp_queue	*q;
	struct net2_datapipe_out*out;
	int			 state;
	int			 want;

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
	want = net2_workq_want(q->wq, 0);
	net2_spinlock_unlock(&out_ev->spl);
	assert(want == 0 || want == EDEADLK);

	/* Ensure the event will run. */
	out_ev->generation = out->generation - 1;
	TAILQ_REMOVE(&out->events, out_ev, q);
	TAILQ_INSERT_HEAD(&out->events, out_ev, q);
	net2_workq_activate(&q->consume, 0);

	if (want == 0)
		net2_workq_unwant(q->wq);
}
/* Deactivate output event. */
ILIAS_NET2_EXPORT void
net2_datapipe_event_out_deactivate(struct net2_datapipe_event_out *out_ev)
{
	struct net2_dp_queue	*q;
	struct net2_datapipe_out*out;
	int			 state;
	int			 want;

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
	want = net2_workq_want(q->wq, 0);
	net2_spinlock_unlock(&out_ev->spl);
	assert(want == 0 || want == EDEADLK);

	state = NET2_DPEV_ACTIVE;
	atomic_compare_exchange_strong(&out_ev->state, &state,
	    NET2_DPEV_INACTIVE);

	if (want == 0)
		net2_workq_unwant(q->wq);
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
	int			 want;
	struct net2_workq	*ev_wq;
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

	/* If there are no events, there is nothing we can do. */
	if (TAILQ_EMPTY(&q->in.events)) {
		net2_workq_deactivate(&q->produce);
		goto out;
	}

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

		/* Sync with event workq. */
		ev_wq = in_ev->wq;
		if (ev_wq != NULL) {
			net2_workq_ref(ev_wq);
			want = net2_workq_want(ev_wq, 0);
			assert(want == 0 || want == EDEADLK);
		}

		assert(in_ev->dp == &q->in);
		assert(in_ev->producer.fn != NULL);
		item = in_ev->producer.fn(in_ev->producer.arg);

		if (!dead) {
			state = NET2_DPEV_RUNNING;
			atomic_compare_exchange_strong(&in_ev->state, &state,
			    NET2_DPEV_ACTIVE);
		}

		/* Release event workq. */
		if (ev_wq != NULL) {
			if (want == 0)
				net2_workq_unwant(ev_wq);
			net2_workq_release(ev_wq);
		}
	}

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
		net2_free(elem);
	} else {
		/*
		 * Commit code if item was created by any of the producers.
		 */
		elem->item = item;
		TAILQ_INSERT_TAIL(&q->elems, elem, q);
	}
	QUEUE_UNLOCK(q);

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
	int			 want;
	unsigned int		 generation;
	struct net2_workq	*ev_wq;
	volatile int		 dead;

	/*
	 * Ensure queue will be alive regardless of what invoked functions do
	 * with regard to changing events, releasing in/out etc.
	 */
	queue_acquire(q);

	/* If there are no events, we have nothing to do. */
	if (TAILQ_EMPTY(&q->out.events)) {
		net2_workq_deactivate(&q->consume);
		goto out;
	}

	/* Start a new generation. */
	generation = ++q->out.generation;

	/*
	 * Search for an out event that is willing to handle the event.
	 */
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
		net2_workq_deactivate(&q->consume);
		goto out;
	}

	/* Acquire an element from the queue. */
	elem = NULL;
	QUEUE_LOCK(q);
	elem = TAILQ_FIRST(&q->elems);
	assert(elem == NULL || elem->item != NULL);
	if (elem != NULL) {
		/* Remove from queue, update length. */
		TAILQ_REMOVE(&q->elems, elem, q);

		if (q->len-- == q->maxlen)
			net2_workq_activate(&q->produce, 0);
		if (q->len == 0 &&
		    (atomic_fetch_or(&q->flags, DPQ_EMPTY) &
		    DPQ_HAS_IN) == 0)
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
	ev_wq = ev_out->wq;
	if (ev_wq != NULL) {
		net2_workq_ref(ev_wq);
		want = net2_workq_want(ev_wq, 0);
		assert(want == 0 || want == EDEADLK);
	}

	assert(ev_out->dp == &q->out);
	assert(ev_out->consumer.fn != NULL);
	ev_out->consumer.fn(item, ev_out->consumer.arg);

	if (!dead) {
		/* Clear running state. */
		state = NET2_DPEV_RUNNING;
		atomic_compare_exchange_strong(&ev_out->state, &state,
		    NET2_DPEV_ACTIVE);
		/* Move the event to the rear. */
		TAILQ_REMOVE(&q->out.events, ev_out, q);
		TAILQ_INSERT_HEAD(&q->out.events, ev_out, q);
	}

	/* Release event workq. */
	if (ev_wq != NULL) {
		if (want == 0)
			net2_workq_unwant(ev_wq);
		net2_workq_release(ev_wq);
	}

out:
	queue_release(q, 0);
	return;
}
