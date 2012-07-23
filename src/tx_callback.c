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
#include <ilias/net2/tx_callback.h>
#include <ilias/net2/config.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/mutex.h>
#include <assert.h>
#include <errno.h>

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <ilias/net2/bsd_compat/queue.h>
#endif


/* Entry in tx callback. */
struct net2_txcb_entry {
	TAILQ_ENTRY(net2_txcb_entry)
				 q_entry,
				 eq_entry;

	struct net2_workq_job	 callback;

	struct net2_mutex	*change_mtx;
	struct net2_mutex	*refcnt_mtx;
	size_t			 refcnt;

	struct net2_tx_callback	*q;
	struct net2_txcb_entryq	*eq;

	int			 active; /* Active queue. */
#define Q_TIMEOUT		 0
#define Q_ACK			 1
#define Q_NACK			 2
#define Q_DESTROY		 3
#define Q__SIZE			 4
	net2_tx_callback_fn	 fn[Q__SIZE];
	void			*arg0;
};

#define TXCB_JOB_OFFSET							\
	((size_t)(&((struct net2_txcb_entry*)0)->callback))
#define JOB_2_TXCB(_j)							\
	((struct net2_txcb_entry*)((char*)(_j) - TXCB_JOB_OFFSET))

/* Validate assumption: 1 << Q_* yields the NET2_TXCB_EQ_*. */
#if ((1 << Q_TIMEOUT) != NET2_TXCB_EQ_TIMEOUT ||			\
     (1 << Q_ACK) != NET2_TXCB_EQ_ACK ||				\
     (1 << Q_NACK) != NET2_TXCB_EQ_NACK ||				\
     (1 << Q_DESTROY) != NET2_TXCB_EQ_DESTROY)
#error "Q_* macros and NET2_TXCB_EQ_* macros don't line up."
#endif


static void txcb_wqdestroy(struct net2_workq_job*);
static void txcb_entry_fn(void*, void*);

static const struct net2_workq_job_cb txcb_jcb = {
	NULL,
	NULL,
	NULL,
	&txcb_wqdestroy
};


/* Acquire a reference on an entry. */
static __inline void
entry_acquire(struct net2_txcb_entry *e)
{
	net2_mutex_lock(e->refcnt_mtx);
	e->refcnt++;
	assert(e->refcnt != 0);	/* Overflow. */
	net2_mutex_unlock(e->refcnt_mtx);
}
/* Release a reference on an entry. */
static void
entry_release(struct net2_txcb_entry *e)
{
	int			 do_free;

	net2_mutex_lock(e->refcnt_mtx);
	assert(e->refcnt > 0);
	e->refcnt--;
	do_free = (e->refcnt == 0 && e->q == NULL && e->eq == NULL);
	net2_mutex_unlock(e->refcnt_mtx);

	if (do_free) {
		assert(e->active == Q_TIMEOUT);
		net2_workq_deinit_work(&e->callback);
		net2_free(e);
	}
}
/* Retrieve the head of the entry queue. */
static __inline struct net2_txcb_entry*
entryq_first(struct net2_txcb_entryq *q)
{
	struct net2_txcb_entry	*e;

	net2_mutex_lock(q->mtx);
	if ((e = TAILQ_FIRST(&q->entries)) != NULL)
		entry_acquire(e);
	net2_mutex_unlock(q->mtx);
	return e;
}
/* Retrieve the head of the entry queue. */
static __inline struct net2_txcb_entry*
txcb_first(struct net2_tx_callback *q)
{
	struct net2_txcb_entry	*e;

	net2_mutex_lock(q->mtx);
	if ((e = TAILQ_FIRST(&q->entries)) != NULL)
		entry_acquire(e);
	net2_mutex_unlock(q->mtx);
	return e;
}
/* Cancel an entry. */
static void
entry_cancel(struct net2_txcb_entry *e)
{
	struct net2_txcb_entryq	*eq;
	struct net2_tx_callback	*q;

	net2_mutex_lock(e->change_mtx);
	q = e->q;
	eq = e->eq;

	if (q != NULL) {
		net2_mutex_lock(q->mtx);
		TAILQ_REMOVE(&q->entries, e, q_entry);
		e->q = NULL;
		net2_mutex_lock(q->mtx);
	}

	if (eq != NULL) {
		net2_mutex_lock(eq->mtx);
		TAILQ_REMOVE(&eq->entries, e, eq_entry);
		e->eq = NULL;
		net2_mutex_unlock(eq->mtx);
	}

	net2_mutex_unlock(e->change_mtx);

	/* Deactivate callback and prevent callback from releasing this. */
	net2_workq_deactivate(&e->callback);
	if (e->active != Q_TIMEOUT) {
		e->active = Q_TIMEOUT;
		entry_release(e);
	}
}
/* Cancel an entry queue. */
static void
entryq_cancel(struct net2_txcb_entryq *eq)
{
	struct net2_txcb_entry	*e;

	while ((e = entryq_first(eq)) != NULL) {
		entry_cancel(e);
		entry_release(e);
	}
}
/* Fire all timeout events. */
static void
txcb_fire(struct net2_tx_callback *q, int which)
{
	struct net2_txcb_entry	*e;
	struct net2_workq	*wq;
	int			 rv;
	struct net2_tx_callback	*cb;

	assert(which >= 0 && which < Q__SIZE);

	/* Timeouts fire, but don't release the queue elements. */
	if (which == Q_TIMEOUT) {
		net2_mutex_lock(q->mtx);
		TAILQ_FOREACH(e, &q->entries, q_entry) {
			assert(e->active == Q_TIMEOUT);
			if (e->fn[Q_TIMEOUT] != NULL)
				net2_workq_activate(&e->callback, 0);
		}
		net2_mutex_unlock(q->mtx);
		return;
	}

	/* All other callbacks fire once, then die. */
	while ((e = txcb_first(q)) != NULL) {
		net2_mutex_lock(e->change_mtx);
		wq = net2_workq_get(&e->callback);

		/* Detach from this txcb. */
		net2_mutex_lock(q->mtx);
		TAILQ_REMOVE(&e->q->entries, e, q_entry);
		cb = e->q;
		e->q = NULL;
		net2_mutex_unlock(q->mtx);

		/*
		 * Check that we can actually run, if we can't, simply
		 * don't run, but release this entry immediately.
		 */
		if (wq != NULL && cb != NULL && e->active == Q_TIMEOUT &&
		    e->fn[which] != NULL) {
			assert(cb == q);

			/*
			 * Only fire if the entry wasn't removed already.
			 *
			 * We try to lock the workq, so the callback doesn't
			 * get delayed.  If that fails, we resort to
			 * deactivating the callback, to conquer the
			 * missed wakeup problem.
			 */
			rv = net2_workq_want(wq, 1);
			if (rv != 0 && rv != EDEADLK)
				net2_workq_deactivate(&e->callback);
			e->active = which;
			net2_workq_activate(&e->callback, 0);
			if (rv == 0)
				net2_workq_unwant(wq);

			/*
			 * Changes applied.  Note that we don't release e,
			 * since we marked it as active.
			 */
			net2_mutex_unlock(e->change_mtx);
		} else {
			net2_mutex_unlock(e->change_mtx);
			entry_release(e);
		}

		net2_workq_release(wq);
	}
}
/* Create a new entry in txcb. */
static int
new_entry(struct net2_tx_callback *q, struct net2_txcb_entryq *eq,
    struct net2_workq *wq,
    net2_tx_callback_fn timeout, net2_tx_callback_fn ack,
    net2_tx_callback_fn nack, net2_tx_callback_fn destroy,
    void *arg0, void *arg1)
{
	struct net2_txcb_entry	*e;
	int			 error;

	assert(q != NULL);
	/* Nothing to do? */
	if (timeout == NULL && ack == NULL && nack == NULL && destroy == NULL)
		return 0;

	if ((e = net2_malloc(sizeof(*e))) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	if ((e->refcnt_mtx = net2_mutex_alloc()) == NULL) {
		error = ENOMEM;
		goto fail_1;
	}
	if ((e->change_mtx = net2_mutex_alloc()) == NULL) {
		error = ENOMEM;
		goto fail_2;
	}
	if ((error = net2_workq_init_work(&e->callback, wq,
	    &txcb_entry_fn, e, arg1, 0)) != 0)
		goto fail_3;

	e->q = q;
	e->eq = eq;
	e->refcnt = 0;
	e->active = Q_TIMEOUT;
	e->fn[Q_TIMEOUT] = timeout;
	e->fn[Q_ACK] = ack;
	e->fn[Q_NACK] = nack;
	e->fn[Q_DESTROY] = destroy;
	e->arg0 = arg0;
	net2_workq_set_callbacks(&e->callback, &txcb_jcb);

	/*
	 * No failures permitted past this point.
	 */
	net2_mutex_lock(q->mtx);
	TAILQ_INSERT_TAIL(&q->entries, e, q_entry);
	net2_mutex_unlock(q->mtx);
	net2_mutex_lock(eq->mtx);
	TAILQ_INSERT_TAIL(&eq->entries, e, eq_entry);
	net2_mutex_unlock(eq->mtx);

	/* Done. */
	return 0;


fail_4:
	net2_workq_deinit_work(&e->callback);
fail_3:
	net2_mutex_free(e->change_mtx);
fail_2:
	net2_mutex_free(e->refcnt_mtx);
fail_1:
	net2_free(e);
fail_0:
	assert(error != 0);
	return error;
}

/* React to workq destruction. */
static void
txcb_wqdestroy(struct net2_workq_job *j)
{
	struct net2_txcb_entry	*e = JOB_2_TXCB(j);

	/*
	 * No lock required to read e->active: workq will be locked
	 * when it is called.
	 */
	if (!e->active)
		entry_acquire(e);
	entry_cancel(e);
	entry_release(e);
}
/* Invocation method. */
static void
txcb_entry_fn(void *e_ptr, void *arg1)
{
	struct net2_txcb_entry	*e = e_ptr;
	void			*arg0;
	net2_tx_callback_fn	 fn;
	int			 active;

	assert(e != NULL);
	assert(e->active > 0 && e->active < Q__SIZE);

	net2_mutex_lock(e->change_mtx);
	active = e->active;
	e->active = 0;	/* Prevent double release if workq is destroyed. */
	arg0 = e->arg0;
	fn = e->fn[active];
	net2_mutex_unlock(e->change_mtx);

	/*
	 * Prevent destruction during execution of fn.
	 * Note: if active != 0, txcb_fire() will have already incremented
	 * the reference counter so won't have to.
	 */
	if (active == 0)
		entry_acquire(e);

	if (fn != NULL)
		(*fn)(arg0, arg1);

	entry_release(e);
}

/* Merge two tx_callbacks together. */
static void
merge_q(struct net2_tx_callback *dst, struct net2_tx_callback *src)
{
	struct net2_mutex	*lock_order[2];
	struct net2_txcb_entry	*e;

	/* Merge with self, trivial. */
	if (dst == src)
		return;

	/*
	 * Establish lock ordering.
	 * Prevents dead lock when both need to be locked.
	 */
	if (dst < src) {
		lock_order[0] = dst->mtx;
		lock_order[1] = src->mtx;
	} else {
		lock_order[0] = src->mtx;
		lock_order[1] = dst->mtx;
	}

	/* Acquire both queues. */
	net2_mutex_lock(lock_order[0]);
	net2_mutex_lock(lock_order[1]);

	while ((e = TAILQ_FIRST(&src->entries)) != NULL) {
		/*
		 * While we hold the queue lock, the entry cannot
		 * become completely unreferenced.
		 *
		 * In other words, we're guaranteed its existence as
		 * long as we hold src->lock and dst->lock.
		 * Try locking the change_mtx using trylock, because it
		 * is an ordering violation.
		 */
		if (net2_mutex_trylock(e->change_mtx)) {
			TAILQ_REMOVE(&src->entries, e, q_entry);
			TAILQ_INSERT_TAIL(&dst->entries, e, q_entry);
			e->q = dst;
			net2_mutex_unlock(e->change_mtx);
		} else {
			/*
			 * Long path to move this entry: we ensure the entry
			 * remains reachable, then unlock everything and
			 * reacquire the locks.
			 */
			entry_acquire(e);
			net2_mutex_unlock(src->mtx);
			net2_mutex_unlock(dst->mtx);

			/*
			 * Acquire all locks in the correct order:
			 * change_mtx before queues, queues in lock_order.
			 */
			net2_mutex_lock(e->change_mtx);
			net2_mutex_lock(lock_order[0]);
			net2_mutex_lock(lock_order[1]);

			/*
			 * Queue might have changed.
			 * Skip if that happened.
			 */
			if (e->q == src) {
				TAILQ_REMOVE(&src->entries, e, q_entry);
				TAILQ_INSERT_TAIL(&dst->entries, e, q_entry);
				e->q = dst;
			}

			/*
			 * Change complete.
			 * Release change mutex and entry.
			 *
			 * Note: we don't release the src/dst mutexes:
			 * they'll do just fine during the next iteration.
			 */
			net2_mutex_unlock(e->change_mtx);
			entry_release(e);
		}
	}

	/* Release both queues. */
	net2_mutex_unlock(src->mtx);
	net2_mutex_unlock(dst->mtx);
}


/* Test if the txcbq is empty. */
ILIAS_NET2_EXPORT int
net2_txcb_empty(struct net2_tx_callback *tx)
{
	int			 result;

	net2_mutex_lock(tx->mtx);
	result = TAILQ_EMPTY(&tx->entries);
	net2_mutex_unlock(tx->mtx);
	return result;
}

/* Initialize new tx_callback. */
ILIAS_NET2_EXPORT int
net2_txcb_init(struct net2_tx_callback *cb)
{
	if ((cb->mtx = net2_mutex_alloc()) == NULL)
		return ENOMEM;
	TAILQ_INIT(&cb->entries);
	return 0;
}

/*
 * Release resources held by tx_callback.
 *
 * Any remaining callbacks are cancelled, using their destroy callback.
 */
ILIAS_NET2_EXPORT void
net2_txcb_deinit(struct net2_tx_callback *cb)
{
	txcb_fire(cb, Q_DESTROY);
	net2_mutex_free(cb->mtx);
}

/* TX callback ACK completion. */
ILIAS_NET2_EXPORT void
net2_txcb_ack(struct net2_tx_callback *cb)
{
	txcb_fire(cb, Q_ACK);
}

/* TX callback NACK completion. */
ILIAS_NET2_EXPORT void
net2_txcb_nack(struct net2_tx_callback *cb)
{
	txcb_fire(cb, Q_NACK);
}

/* TX callback timeout invocation. */
ILIAS_NET2_EXPORT void
net2_txcb_timeout(struct net2_tx_callback *cb)
{
	txcb_fire(cb, Q_TIMEOUT);
}

/* Move all event from src to dst. */
ILIAS_NET2_EXPORT void
net2_txcb_merge(struct net2_tx_callback *dst, struct net2_tx_callback *src)
{
	merge_q(dst, src);
}

/* Add callback to tx callback. */
ILIAS_NET2_EXPORT int
net2_txcb_add(struct net2_tx_callback *cb, struct net2_workq *workq,
    struct net2_txcb_entryq *txcbq,
    net2_tx_callback_fn timeout, net2_tx_callback_fn ack,
    net2_tx_callback_fn nack, net2_tx_callback_fn destroy,
    void *arg0, void *arg1)
{
	return new_entry(cb, txcbq, workq, timeout, ack, nack, destroy,
	    arg0, arg1);
}


/* Initialize txcb entry set. */
ILIAS_NET2_EXPORT int
net2_txcb_entryq_init(struct net2_txcb_entryq *eq)
{
	if ((eq->mtx = net2_mutex_alloc()) == NULL)
		return ENOMEM;
	TAILQ_INIT(&eq->entries);
	return 0;
}
/* Deinitialize txcb entry set.  Cancels each callback. */
ILIAS_NET2_EXPORT void
net2_txcb_entryq_deinit(struct net2_txcb_entryq *eq)
{
	entryq_cancel(eq);
	net2_mutex_free(eq->mtx);
}
/* Test if txcb entry set is empty. */
ILIAS_NET2_EXPORT int
net2_txcb_entryq_empty(struct net2_txcb_entryq *eq, int which)
{
	struct net2_txcb_entry	*e;
	int			 i;
	int			 empty, referenced;

	/* Empty set is empty. */
	if (which == 0)
		return 1;

	empty = 1;
	net2_mutex_lock(eq->mtx);
restart:
	TAILQ_FOREACH(e, &eq->entries, eq_entry) {
		/* Acquire change mutex on e; try without sleeping. */
		referenced = 0;
		if (!net2_mutex_trylock(e->change_mtx)) {
			entry_acquire(e);
			referenced = 1;
			net2_mutex_unlock(eq->mtx);
			net2_mutex_lock(e->change_mtx);
			net2_mutex_lock(eq->mtx);

			/* No longer in this set. */
			if (e->eq != eq) {
				net2_mutex_unlock(e->change_mtx);
				entry_release(e);
				goto restart;
			}
		}

		/* Test each of the given masks is set/active. */
		for (i = 0; i < Q__SIZE; i++) {
			if (!(which & (1 << i)))
				continue;
			/* Unreachable timeouts will be skipped. */
			if (e->active != Q_TIMEOUT && i != e->active)
				continue;

			if (e->fn[i] != NULL) {
				empty = 0;
				break;	/* optimization */
			}
		}

		/* Unlock entry. */
		net2_mutex_unlock(e->change_mtx);
		if (referenced)
			entry_release(e);

		if (!empty)
			break;		/* GUARD */
	}
	net2_mutex_unlock(eq->mtx);

	return empty;
}
/* Clear some or all of the given events. */
ILIAS_NET2_EXPORT void
net2_txcb_entryq_clear(struct net2_txcb_entryq *eq, int which)
{
	struct net2_txcb_entry	*e;
	int			 i;
	int			 cancel, referenced, active_cancel, do_restart;

	assert((which & NET2_TXCB_EQ_ALL) == which);

	net2_mutex_lock(eq->mtx);
restart:
	TAILQ_FOREACH(e, &eq->entries, eq_entry) {
		referenced = 0;
		do_restart = 0;

		/* Try to acquire the change mutex on e. */
		if (!net2_mutex_trylock(e->change_mtx)) {
			referenced = 1;
			entry_acquire(e);
			net2_mutex_unlock(eq->mtx);
			net2_mutex_lock(e->change_mtx);
			net2_mutex_lock(eq->mtx);

			if (e->eq != eq) {
				net2_mutex_unlock(e->change_mtx);
				entry_release(e);
				goto restart;
			}
		}

		/*
		 * Clear the requested callbacks.
		 * If the callback has no callbacks that it'll reach anymore,
		 * mark it as to-be-canceled.
		 *
		 * Also track if the active callback got canceled (only if
		 * it wasn't a timeout).
		 */
		cancel = 1;
		active_cancel = 0;
		for (i = 0; i < Q__SIZE; i++) {
			if (which & (1 << i)) {
				if (e->active == i && e->fn[i] != NULL)
					active_cancel = 1;
				e->fn[i] = NULL;
			} else if (e->fn[i] != NULL &&
			    (e->active == Q_TIMEOUT || e->active == i)) {
				/*
				 * This call can still reach a timeout:
				 * - e->fn[e->active] != NULL or
				 * - e->active == Q_TIMEOUT and
				 *   at least one function is not null.
				 */
				cancel = 0;
			}
		}

		if (active_cancel) {
			/* Release change lock, ensure we keep entry alive. */
			net2_mutex_unlock(e->change_mtx);
			if (!referenced) {
				referenced = 1;
				entry_acquire(e);
			}
			/*
			 * Release eq, in case the callback is running and
			 * needs access.
			 */
			net2_mutex_unlock(eq->mtx);

			/* Deactivate callback. */
			net2_workq_deactivate(&e->callback);

			/* Reacquire eq, change mtx. */
			net2_mutex_lock(e->change_mtx);
			net2_mutex_lock(eq->mtx);

			/*
			 * Release reference, since callback was unable to
			 * do so.
			 */
			if (e->active != Q_TIMEOUT) {
				e->active = Q_TIMEOUT;
				entry_release(e);
			}

			/*
			 * We slept with eq unlocked.  If this item is no
			 * longer in eq, we'll need to restart the call.
			 */
			if (e->eq != eq)
				do_restart = 1;
		}

		/* Remove entry from this eq queue. */
		if (cancel && !referenced) {
			referenced = 1;
			entry_acquire(e);
		}

		/*
		 * Detach from this queue.
		 * By detaching, we avoid deadlocking during cancelation and
		 * can keep the eq lock, meaning we don't have to restart.
		 */
		if (cancel && e->eq == eq) {
			TAILQ_REMOVE(&eq->entries, e, eq_entry);
			e->eq = NULL;
		}
		/* Release change mutex. */
		net2_mutex_unlock(e->change_mtx);

		/* Cancel entry if further progression is impossible. */
		if (cancel)
			entry_cancel(e);
		/* Release entry if we referenced it. */
		if (referenced)
			entry_release(e);

		/* If we need to restart the call, do so now. */
		if (do_restart)
			goto restart;
	}
	net2_mutex_unlock(eq->mtx);
}

/* Merge two entry sets. */
ILIAS_NET2_EXPORT void
net2_txcb_entryq_merge(struct net2_txcb_entryq *dst,
    struct net2_txcb_entryq *src)
{
	struct net2_mutex	*lock_order[2];
	struct net2_txcb_entry	*e;

	if (src == dst)
		return;	/* Nothing to do. */

	/* Establish lock order. */
	if (src < dst) {
		lock_order[0] = src->mtx;
		lock_order[1] = dst->mtx;
	} else {
		lock_order[0] = dst->mtx;
		lock_order[1] = src->mtx;
	}

	/* Lock both queues. */
	net2_mutex_lock(lock_order[0]);
	net2_mutex_lock(lock_order[1]);

	while ((e = TAILQ_FIRST(&src->entries)) != NULL) {
		if (net2_mutex_trylock(e->change_mtx)) {
			/*
			 * Use the fact that e cannot become unreachable with
			 * its queue locked.
			 */
			TAILQ_REMOVE(&src->entries, e, eq_entry);
			TAILQ_INSERT_TAIL(&dst->entries, e, eq_entry);
			e->eq = dst;
			net2_mutex_unlock(e->change_mtx);
		} else {
			/* Release locks, ensuring entry will stay alive. */
			entry_acquire(e);
			net2_mutex_unlock(dst->mtx);
			net2_mutex_unlock(src->mtx);

			/* Acquire locks in the correct order. */
			net2_mutex_lock(e->change_mtx);
			net2_mutex_lock(lock_order[0]);
			net2_mutex_lock(lock_order[1]);

			/*
			 * Now that the locks are acquired properly,
			 * we can move entry over.
			 * Unless it disappeared from its queue.
			 */
			if (e->eq == src) {
				TAILQ_REMOVE(&src->entries, e, eq_entry);
				TAILQ_INSERT_TAIL(&dst->entries, e, eq_entry);
				e->eq = dst;
			}

			/* Release change mtx and entry. */
			net2_mutex_unlock(e->change_mtx);
			entry_release(e);
		}
	}

	net2_mutex_unlock(src->mtx);
	net2_mutex_unlock(dst->mtx);
}
