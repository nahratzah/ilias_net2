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
#include <ilias/net2/workq.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/mutex.h>
#include <ilias/net2/thread.h>
#include <ilias/net2/semaphore.h>
#include <ilias/net2/spinlock.h>
#include <ilias/net2/bsd_compat/error.h>
#include <ev.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>

#ifdef HAS_NANOSLEEP
#include <time.h>
#endif

#ifdef EV_C
#include EV_C
#endif

/*
 * net2_workq, net2_workq_evbase, net2_workq_job implementation.
 *
 * net2_workq_evbase exists while it has a reference.  References are either
 * external (due to user code holding a reference) or internal (due to a workq
 * pointing at this evbase).  Consequently, a workq can always safely
 * dereference its workq_evbase pointer.
 *
 *
 * A net2_workq_job is not guaranteed to have a workq.  Dereferencing
 * the workq is safe while it is in the running state and has the HAS_OWNER
 * flag set.  It cannot enter the running state while it does not have the
 * HAS_OWNER flag set.  If a workq is dying, it will clear the HAS_OWNER bit
 * from each of the workq_jobs.
 *
 * The workq_job entering the running state must mark the workq as RUNNING.
 * Failure to switch the workq to RUNNING state is a failure to start the job.
 *
 *
 * When the workq is destroyed, it can be either destroyed from within
 * its current worker thread or from another thread.  In the former case,
 * it must currently be RUNNING.  And the latter case, it may be RUNNING,
 * or may not be.
 * If the workq is destroyed from an external thread, the destructor may
 * not return while the workq is in the RUNNING state.  Once it is no longer
 * in the running state, the destruction may complete.
 * If the workq is destroyed from within the thread that is currently
 * running it, it must not wait until it is done running (doing so would
 * cause a deadlock).
 *
 * When the workq is being destroyed, it must mark itself as dying.  Because
 * the workq job can re-expose the workq, the workq must then proceed to
 * test the reference counter, if it is non-zero, it must abort the release
 * operation.
 * Next, the workq must wait until it exits the RUNNING state, unless it
 * is running in the current thread.
 */


#if defined(__GNUC__) || defined(__clang__)
#define predict_true(_x)	__builtin_expect(((_x) != 0), 1)
#define predict_false(_x)	__builtin_expect(((_x) != 0), 0)
#else
#define predict_true(_x)	((_x) != 0)
#define predict_false(_x)	((_x) != 0)
#define __attribute__(_x)	/* No attributes. */
#endif

#if defined(__GNUC__) && !defined(__clang__)
#define __hot__			__attribute__((hot))
#define __cold__		__attribute__((cold))
#else
#define	__hot__			/* Nothing. */
#define __cold__		/* Nothing. */
#endif

#ifdef _WIN32
static void
thryield()
{
	if (!SwitchToThread())
		Sleep(1);	/* Sleep one millisecond. */
}
#elif defined(HAS_NANOSLEEP)
static void
thryield()
{
	const struct timespec	yield = { 0, 1000 };

	nanosleep(&yield, NULL);
}
#else
static __inline void
thryield()
{
	pthread_yield();
}
#endif


/* Flags that can be used at job initialization time. */
#define NET2_WORKQ_VALID_USERFLAGS	(NET2_WORKQ_PERSIST)


/*
 * Dying state of the workq.
 *
 * A dying workq can either be getting killed by another thread,
 * or having to be killed by the thread running it.
 */
enum workq_dying_state {
	wq_none,
	wq_dying,
	wq_killme
};
/*
 * Want acquisition result of the workq.
 *
 * A want acquisition may fail due to being called from inside the workq or
 * memory shortage.
 * If the try flag was given and the workq was already want-locked or running,
 * the operation will fail with tryfail.
 */
enum workq_want_state {
	wq_want_succes,
	wq_want_running,
	wq_want_tryfail,
	wq_want_memfail
};
/*
 * Job_run_set return values.
 *
 * The job may only be set running if:
 * - the job is not currently running (job_run_twice),
 * - the job is active (job_run_inactive),
 * - the job has a workq (job_run_nowq),
 * - the job workq is not currently running or wantlocked (job_run_wqbusy).
 * - no threads are waiting for the job to cease the running state
 *   (job_run_wait).
 */
enum job_run_state {
	job_run_succes,
	job_run_twice,
	job_run_inactive,
	job_run_wait,
	job_run_nowq,
	job_run_wqbusy
};


/* Internal state flags for workq job. */
#define JOB_RUNNING	0x00010000		/* Job is executing. */
#define JOB_ACTIVE	0x00020000		/* Job is to run. */
#define JOB_DEREFING	0x00040000		/* Dereferencing wq. */
#define JOB_ONQUEUE	0x00080000		/* Job is on workq runq. */


/* Workq data. */
struct net2_workq {
	atomic_uint	 flags;			/* State bits. */
#define WQ_RUNNING	0x00000001		/* Running. */
#define WQ_ONQUEUE	0x00000002		/* Waiting to run. */
#define WQ_KILLME	0x00000004		/* Kill workq after run. */
#define WQ_DYING	0x00000008		/* Workq is dying. */
#define WQ_WANTLOCK	0x00000010		/* Workq is wanted. */
#define WQ_THRLOCK	0x00000020		/* Thread modify/eval lock. */
	struct net2_workq_evbase
			*wqev;

	TAILQ_ENTRY(net2_workq)
			 wqev_runq;		/* WQ evbase runqueue. */
	TAILQ_HEAD(, net2_workq_job)
			 runqueue;		/* All active jobs. */

	atomic_uint	 refcnt;		/* Reference counter. */
	atomic_uintptr_t thread;		/* Execing thread
						 * (pointer to net2_thread). */
	atomic_uint	 want_refcnt;		/* Want refcnt. */
	atomic_uint	 want_queued;		/* # queued wants. */
	struct net2_mutex
			*want_mtx;		/* For want sleep sync. */

	net2_spinlock	 spl;			/* Protect runq. */
	TAILQ_HEAD(, net2_workq_job)
			 members;		/* All jobs on wq. */
};

/* Event base and thread pool. */
struct net2_workq_evbase {
	net2_spinlock	 spl;			/* Protect runq. */
	TAILQ_HEAD(, net2_workq)
			 runq;			/* All workq that need run. */

	atomic_uintptr_t evloop;		/* Event loop. */
	ev_async	 ev_wakeup;		/* Wakeup for evloop. */
	ev_async	 ev_newevent;		/* Wakeup: events are added. */

	int		 jobthreads;		/* # threads running jobs. */
	int		 maxthreads;		/* # threads total. */
	struct net2_semaphore
			 thr_active,		/* Limit # running
						 * worker threads. */
			 thr_idle,		/* # worker thread idling. */
			 thr_die,		/* # worker threads
						 * that need to die. */
			 thr_death;		/* # dead worker threads. */

	char		*wq_worker_name;	/* Thread name of workers. */
	atomic_uint	 refcnt;		/* Reference counter. */

	struct net2_mutex
			*workers_mtx;		/* Locked when changing
						 * thread counts. */
	net2_spinlock	 spl_workers;		/* Protect workers tailq. */
	TAILQ_HEAD(, net2_workq_evbase_worker)
			 workers,		/* All active worker
						 * threads. */
			 dead_workers;		/* All dead worker
						 * threads. */
};

/*
 * A worker thread.
 */
struct net2_workq_evbase_worker {
	TAILQ_ENTRY(net2_workq_evbase_worker)
			 tq;			/* Link into threads. */
	struct net2_thread
			*worker;		/* Worker thread. */
	struct net2_workq_evbase
			*evbase;		/* Owner. */
	net2_spinlock	 spl;			/* Protect owner pointer. */
};


static void	evloop_wakeup(struct ev_loop*, ev_async*, int);
static void	evloop_new_event(struct ev_loop*, ev_async*, int);


/* Only called with non-zero reference count. */
static __inline void
workq_ref(struct net2_workq *wq)
{
	atomic_fetch_add_explicit(&wq->refcnt, 1, memory_order_acquire);
}
/*
 * Release reference to a workq.
 *
 * Returns true if the last reference went away.
 */
static __inline int
workq_release(struct net2_workq *wq)
{
	return (atomic_fetch_sub_explicit(&wq->refcnt, 1,
	    memory_order_release) == 1);
}
/*
 * Put the workq on the runq.
 * If clear_run is set, the run bit will be cleared.
 *
 * Returns the updated flags of the workq.
 */
static __inline unsigned int
workq_onqueue(struct net2_workq *wq, int clear_run)
{
	struct net2_workq_evbase
			*wqev;
	unsigned int	 fl;

	wqev = wq->wqev;
	net2_spinlock_lock(&wqev->spl);
	fl = atomic_fetch_or_explicit(&wq->flags, WQ_ONQUEUE,
	    memory_order_consume);
	if (!(fl & WQ_ONQUEUE))
		TAILQ_INSERT_TAIL(&wqev->runq, wq, wqev_runq);

	if (clear_run) {
		fl = atomic_fetch_and_explicit(&wq->flags, ~WQ_RUNNING,
		    memory_order_release);
		assert(fl & WQ_RUNNING);
		fl &= ~WQ_RUNNING;
	}

	/* Activate worker. */
	if (net2_semaphore_trydown(&wqev->thr_idle))
		net2_semaphore_up(&wqev->thr_active, 1);

	net2_spinlock_unlock(&wqev->spl);
	return fl;
}
/*
 * Remove the workq from the runq.
 *
 * Returns true if the workq was moved from WQ_ONQUEUE to !WQ_ONQUEUE.
 */
static __inline int
workq_offqueue(struct net2_workq *wq)
{
	struct net2_workq_evbase
			*wqev;
	int		 rv;

	wqev = wq->wqev;
	rv = 0;
	if (!(atomic_load_explicit(&wq->flags, memory_order_consume) &
	    WQ_ONQUEUE))
		return 0;

	net2_spinlock_lock(&wqev->spl);
	if (atomic_fetch_or_explicit(&wq->flags, WQ_ONQUEUE,
	    memory_order_consume) & WQ_ONQUEUE) {
		TAILQ_REMOVE(&wqev->runq, wq, wqev_runq);
		rv = 1;
	}
	net2_spinlock_unlock(&wqev->spl);
	return rv;
}
/*
 * Returns true if the workq is executing on the current thread.
 */
static __inline int
workq_self(struct net2_workq *wq)
{
	int			 selflocked;
	struct net2_thread	*thr;

	while (atomic_fetch_or_explicit(&wq->flags, WQ_THRLOCK,
	    memory_order_acquire) & WQ_THRLOCK)
		SPINWAIT();
	thr = (struct net2_thread*)(atomic_load_explicit(&wq->thread,
	    memory_order_relaxed));
	selflocked = (thr != NULL && net2_thread_is_self(thr));
	atomic_fetch_and_explicit(&wq->flags, ~WQ_THRLOCK,
	    memory_order_release);
	return selflocked;
}
/* Clear the current thread ID. */
static __inline struct net2_thread*
workq_self_clear(struct net2_workq *wq)
{
	struct net2_thread	*thr;

	while (atomic_fetch_or_explicit(&wq->flags, WQ_THRLOCK,
	    memory_order_acquire) & WQ_THRLOCK)
		SPINWAIT();
	thr = (struct net2_thread*)(atomic_load_explicit(&wq->thread,
	    memory_order_relaxed));
	atomic_store_explicit(&wq->thread, 0, memory_order_release);
	atomic_fetch_and_explicit(&wq->flags, ~WQ_THRLOCK,
	    memory_order_release);

	return thr;
}
/*
 * Set the current thread ID.
 * Returns true if the assignment succeeded (i.e. wq->thread was clear).
 */
static __inline int
workq_self_set(struct net2_workq *wq, struct net2_thread *curthread)
{
	uintptr_t	 t;
	int		 succes;

	assert(curthread != NULL && net2_thread_is_self(curthread));
	t = 0;
	/*
	 * Don't acquire THRLOCK during upgrade:
	 * it's only used for testing if the thread is self, so we don't
	 * care if another thread reads 0 or curthread, since both indicate
	 * to that thread it isn't its thread executing on the workq.
	 */
	succes = atomic_compare_exchange_strong_explicit(&wq->thread, &t,
	    (uintptr_t)curthread, memory_order_acquire, memory_order_relaxed);
	return succes;
}
/*
 * Lock workq dereference and return the workq of a job.
 * The lock is only acquired if a non-null value is returned.
 *
 * Returns NULL if the workq is unavailable.
 */
static __inline struct net2_workq*
job_deref_lock(struct net2_workq_job *j)
{
	struct net2_workq	*wq;

	/* Spin acquire lock. */
	while (atomic_fetch_or_explicit(&j->flags, JOB_DEREFING,
	    memory_order_acquire) & JOB_DEREFING)
		SPINWAIT();

	wq = j->wq;
	if (wq != NULL && atomic_load_explicit(&wq->refcnt,
	    memory_order_acquire) == 0)
		wq = NULL;
	if (wq == NULL) {
		atomic_fetch_and_explicit(&j->flags, ~JOB_DEREFING,
		    memory_order_release);
	}
	return wq;
}
/*
 * Unlock the job deref state.
 * Returns the state of the flags as a hint.
 */
static __inline unsigned int
job_deref_unlock(struct net2_workq_job *j)
{
	unsigned int	 f;

	f = atomic_fetch_and_explicit(&j->flags, ~JOB_DEREFING,
	    memory_order_release);
	assert(f & JOB_DEREFING);
	return (f & ~JOB_DEREFING);
}
/*
 * Put the job on the workq runqueue.
 *
 * Workq must exist and be reachable.
 */
static __inline void
job_onqueue(struct net2_workq_job *j)
{
	struct net2_workq	*wq;
	unsigned int		 jf;
	int			 activate_wq;

	activate_wq = 0;
	wq = j->wq;
	assert(wq != NULL);
	jf = atomic_load_explicit(&j->flags, memory_order_relaxed);
	assert((jf & JOB_DEREFING) ||
	    (atomic_load_explicit(&wq->refcnt, memory_order_relaxed) != 0));
	if (jf & JOB_ONQUEUE)
		return;

	net2_spinlock_lock(&wq->spl);
	if (!(atomic_fetch_or_explicit(&j->flags, JOB_ONQUEUE,
	    memory_order_acquire) & JOB_ONQUEUE)) {
		activate_wq = TAILQ_EMPTY(&wq->runqueue);
		TAILQ_INSERT_TAIL(&wq->runqueue, j, runqueue);
	}
	net2_spinlock_unlock(&wq->spl);

	if (activate_wq)
		workq_onqueue(wq, 0);
}
/*
 * Remove the job from its workq runqueue.
 */
static __inline unsigned int
job_offqueue(struct net2_workq_job *j)
{
	struct net2_workq	*wq;
	unsigned int		 jf;

	wq = j->wq;
	assert(wq != NULL);
	jf = atomic_load_explicit(&j->flags, memory_order_relaxed);
	assert((jf & JOB_DEREFING) ||
	    (atomic_load_explicit(&wq->refcnt, memory_order_relaxed) != 0));
	if (!(jf & JOB_ONQUEUE))
		return jf;

	net2_spinlock_lock(&wq->spl);
	jf = atomic_fetch_and_explicit(&j->flags, ~JOB_ONQUEUE,
	    memory_order_acquire);
	if (jf & JOB_ONQUEUE)
		TAILQ_REMOVE(&wq->runqueue, j, runqueue);
	net2_spinlock_unlock(&wq->spl);

	return jf & ~JOB_ONQUEUE;
}
/*
 * Attempt to acquire a workq from within a job.
 *
 * Upon succesful acquire, the reference counter to the workq is updated.
 */
static __inline struct net2_workq*
workq_job_wq(struct net2_workq_job *j)
{
	struct net2_workq
			*wq;

	/* Spin acquire lock. */
	if ((wq = job_deref_lock(j)) == NULL)
		return NULL;

	atomic_fetch_add_explicit(&wq->refcnt, 1, memory_order_acquire);

	/* Release lock. */
	job_deref_unlock(j);

	return wq;
}
/*
 * Detach a job from its workq.
 *
 * Returns true if this call detached the wq.
 */
static __inline int
workq_job_wq_clear(struct net2_workq_job *j)
{
	struct net2_workq
			*wq;
	unsigned int	 jf;

	/* Spin acquire derefence lock. */
	if ((wq = job_deref_lock(j)) == NULL)
		return 0;

	/* Remove job from workq queues. */
	jf = job_offqueue(j);
	/* Clear workq on job. */
	j->wq = NULL;

	/* Remove job from memberq. */
	net2_spinlock_lock(&wq->spl);
	TAILQ_REMOVE(&wq->members, j, members);
	net2_spinlock_unlock(&wq->spl);

	/*
	 * If the job is running, wait until it stops unless this
	 * would result in deadlock.
	 *
	 * Note that we have to refetch the flags, since the code above may
	 * have slept (by spinning).
	 */
	if (!(jf & JOB_RUNNING))
		goto out;

	/* Check if we are the ones holding the lock. */
	if (workq_self(wq)) {
		assert(j->death != NULL);
		*j->death = 1;
		goto out;
	}

	/* Spinwait for the job to exit the running state. */
	while (atomic_load_explicit(&j->flags, memory_order_consume) &
	    JOB_RUNNING)
		thryield();

out:
	/*
	 * Spinwait to give all other threads waiting to notice that
	 * the job is no longer runing a chance to find this out
	 * prior to job destruction.
	 */
	while (atomic_load_explicit(&j->runwait, memory_order_acquire) != 0)
		thryield();

	job_deref_unlock(j);
	return 1;
}
/*
 * Put a workq on the runq.
 * Will fail if the workq is already on the runqueue.
 */
static __inline void
workq_activate(struct net2_workq *wq)
{
	workq_onqueue(wq, 0);
}
/*
 * Remove workq from the runq.
 * Will fail if the workq is not on the runqueue.
 *
 * Returns true if the operation succeeded.
 */
static __inline int
workq_deactivate(struct net2_workq *wq)
{
	return workq_offqueue(wq);
}
/*
 * Change workq to running state.
 *
 * Returns true if the operation succeeded.
 */
static __inline int
__hot__
workq_run_set(struct net2_workq *wq, struct net2_thread *curthread)
{
	unsigned int	 f;

	assert(curthread != NULL);

	/* Set running flag. */
	f = atomic_fetch_or_explicit(&wq->flags, WQ_RUNNING,
	    memory_order_acquire);

	/* Already running?  Fail. */
	if (f & WQ_RUNNING)
		return 0;
	/* Dying or wanted? Clear running state and fail. */
	if (f & (WQ_DYING | WQ_WANTLOCK))
		goto fail;
	if (predict_false(atomic_load_explicit(&wq->want_queued,
	    memory_order_relaxed) != 0))
		goto fail;

	/* Store current thread. */
	if (!workq_self_set(wq, curthread))
		goto fail;

	return 1;

fail:
	atomic_fetch_and_explicit(&wq->flags, ~WQ_RUNNING,
	    memory_order_release);
	return 0;
}
/*
 * Clear the run state on the workq.
 * If activate is set, the workq will be placed on the wqev runq.
 *
 * Returns the dying state of the workq.
 */
static __inline enum workq_dying_state
__hot__
workq_run_clear(struct net2_workq *wq, int activate)
{
	unsigned int	 f;

	/* Assert that the current thread holds the running state. */
	assert(workq_self(wq));

	workq_self_clear(wq);

	/* Activate workq and clear running bit. */
	if (activate)
		f = workq_onqueue(wq, 1);
	else {
		f = atomic_fetch_and_explicit(&wq->flags, ~WQ_RUNNING,
		    memory_order_release);
		assert(f & WQ_RUNNING);
	}

	if (f & WQ_KILLME)
		return wq_killme;
	else if (f & WQ_DYING)
		return wq_dying;
	return wq_none;
}
/*
 * Mark the workq as wanted.
 *
 * Acquires the mutex.
 * Note that the workq must be referenced for this function to be possible.
 */
static __inline enum workq_want_state
workq_want_set(struct net2_workq *wq, int try)
{
	unsigned int	 f;
	struct net2_thread
			*thr;

	/*
	 * First check if we are already owner of the wq.
	 */
	f = atomic_load_explicit(&wq->flags, memory_order_acquire);
	if (f & (WQ_RUNNING | WQ_WANTLOCK)) {
		/*
		 * Check if we are the thread
		 * currently holding the want/run lock.
		 */
		if (workq_self(wq)) {
			if (f & WQ_RUNNING)
				return wq_want_running;
			atomic_fetch_add_explicit(&wq->want_refcnt, 1,
			    memory_order_acquire);
			return wq_want_succes;
		}
		if (try)
			return wq_want_tryfail;
	}

	/*
	 * We are not the lock owner, so we'll have to acquire it.
	 * For that, we need a thread.
	 *
	 * We allocate the thread prior to modifying the workq, so
	 * memfail error recovery can be atomic.
	 */
	if (predict_false((thr = net2_thread_self()) == NULL))
		return wq_want_memfail;

	/*
	 * Increment waiter count and block on the want_mtx.
	 *
	 * The want_mtx is mainly intended for the wakeup
	 * call (wish there was a condition variable to
	 * wakeup without locking anything).
	 *
	 * The try counterpart of the function is on purpose written in
	 * such a way that it won't modify the workq state until it is
	 * commited.
	 */
	if (try) {
		if (!net2_mutex_trylock(wq->want_mtx))
			goto tryfail_0;

		f = atomic_load_explicit(&wq->flags, memory_order_consume);
		for (;;) {
			if (f & (WQ_WANTLOCK | WQ_RUNNING))
				goto tryfail_1;
			if (atomic_compare_exchange_weak_explicit(&wq->flags,
			    &f, f | WQ_WANTLOCK,
			    memory_order_acquire, memory_order_consume))
				break;	/* GUARD */
			SPINWAIT();
		}

		atomic_fetch_add_explicit(&wq->want_queued, 1,
		    memory_order_acquire);
	} else {
		atomic_fetch_add_explicit(&wq->want_queued, 1,
		    memory_order_acquire);
		net2_mutex_lock(wq->want_mtx);

		/* Mark ourselves as the owner. */
		for (;;) {
			f = atomic_fetch_or_explicit(&wq->flags, WQ_WANTLOCK,
			    memory_order_acquire);
			if (!(f & WQ_WANTLOCK))
				break;	/* GUARD */
			SPINWAIT();
		}

		/* Wait until RUNNING state is released. */
		while (f & WQ_RUNNING) {
			thryield();
			f = atomic_load_explicit(&wq->flags,
			    memory_order_acquire);
		}
	}

	/* Increment the reference count. */
	atomic_fetch_add_explicit(&wq->want_refcnt, 1, memory_order_acquire);

	/* We now hold the wantlock exclusively. */
	while (predict_false(!workq_self_set(wq, thr)))
		SPINWAIT();

	return wq_want_succes;


tryfail_1:
	net2_mutex_unlock(wq->want_mtx);
tryfail_0:
	net2_thread_free(thr);
	return wq_want_tryfail;
}
/*
 * Release a want from the wq.
 * Releases the mutex if the last reference goes away.
 *
 * Note that the workq must be referenced for this function to be possible.
 *
 * Returns true if the workq requires activation.
 */
static __inline int
workq_want_clear(struct net2_workq *wq)
{
	int		 do_activate = 0;
	struct net2_thread
			*thr;

	assert(workq_self(wq));
	if (atomic_fetch_sub_explicit(&wq->want_refcnt, 1,
	    memory_order_release) == 1) {
		/*
		 * Last reference went away.
		 * Clear parameters.
		 */
		thr = workq_self_clear(wq);

		net2_mutex_unlock(wq->want_mtx);
		atomic_fetch_and_explicit(&wq->flags, ~WQ_WANTLOCK,
		    memory_order_release);
		if (atomic_fetch_sub_explicit(&wq->want_queued, 1,
		    memory_order_release) == 1) {
			/*
			 * No other thread wants this workq,
			 * check if it needs to be activated.
			 */
			do_activate = 1;
			if (net2_spinlock_trylock(&wq->spl)) {
				/* Empty workq is never active. */
				if (TAILQ_EMPTY(&wq->runqueue))
					do_activate = 0;
				net2_spinlock_unlock(&wq->spl);
			}
		}

		net2_thread_free(thr);
	}

	return do_activate;
}
/*
 * Change a job to the running state.
 *
 * If update_wq is set, the workq will also be marked running.
 * If update_wq is clear, it is assumed the caller will verify if the workq is
 * reachable and prevent it from running in parallel.
 * If the job is not active, the operation will fail.
 *
 * Return:
 * - job_run_succes: the job is succesfully marked running.
 * - job_run_twice: the job is already running.
 * - job_run_inactive: the job is not active.
 * - job_run_wait: at least one thread is waiting for this job to cease running
 *   and runwait was not set.
 * - job_run_nowq: job has lost its workq (only if updatewq was specified).
 * - job_run_wqbusy: workq is currently running or wanted (only if updatewq was
 *   specified).
 *
 * If job_run_succes is returned, the job will be deactivated
 * unless it is marked persistent.
 *
 * If allow_inactive is set, the job does not need to be active to run.
 */
static __inline enum job_run_state
__hot__
job_run_set(struct net2_workq_job *j, int update_wq,
    struct net2_thread *curthread, int runwait, int allow_inactive)
{
	unsigned int	 jf, wqf;
	struct net2_workq
			*wq;

	assert(!update_wq || curthread != NULL);

	/*
	 * Some threads may be processing the end of the previous time this
	 * job ran.  Wait until they notice it isn't running.
	 *
	 * While those threads are waiting, we cannot modify the flag bits.
	 */
	while (atomic_load_explicit(&j->runwait, memory_order_release) != 0) {
		jf = atomic_load_explicit(&j->flags, memory_order_consume);
		if (!(jf & JOB_ACTIVE) && !allow_inactive)
			return job_run_inactive;
		if (jf & JOB_RUNNING)
			return job_run_twice;
		if (!runwait)
			return job_run_wait;
		thryield();
	}

	/* Attempt to mark job as running. */
	jf = atomic_fetch_or_explicit(&j->flags, JOB_RUNNING,
	    memory_order_acquire);
	if (jf & JOB_RUNNING)
		return job_run_twice;
	if (!(jf & JOB_ACTIVE) && !allow_inactive) {
		atomic_fetch_and_explicit(&j->flags, ~JOB_RUNNING,
		    memory_order_release);
		return job_run_inactive;
	}

	if (update_wq) {
		/* Spin acquire workq. */
		if ((wq = job_deref_lock(j)) == NULL) {
			/* Undo job flag change. */
			atomic_fetch_and_explicit(&j->flags, ~JOB_RUNNING,
			    memory_order_release);
			return job_run_nowq;
		}

		/*
		 * Mark workq as running.
		 *
		 * Note that this cannot be done in a loop,
		 * since the wq flags also maintains onqueue state etc.
		 */
		wqf = atomic_load_explicit(&wq->flags, memory_order_consume);
		for (;;) {
			if (wqf & (WQ_RUNNING | WQ_WANTLOCK |
			    WQ_DYING | WQ_KILLME)) {
				job_deref_unlock(j);
				/* Undo job flag change. */
				atomic_fetch_and_explicit(&j->flags,
				    ~JOB_RUNNING, memory_order_release);
				return ((wqf & (WQ_RUNNING | WQ_WANTLOCK)) ?
				    job_run_wqbusy : job_run_nowq);
			}
			if (atomic_compare_exchange_weak_explicit(&wq->flags,
			    &wqf, wqf | WQ_RUNNING,
			    memory_order_acquire, memory_order_consume))
				break;	/* GUARD */
			SPINWAIT();
		}

		/*
		 * Check that the queue is actually available.
		 * If not, undo all operations and return.
		 *
		 * Note that this only happens in the small window where
		 * the refcnt reaches zero until the WQ_DYING flag (tested
		 * above) is set.
		 *
		 * Despite the earlier test for this in job_deref_lock, the
		 * state can change between then and now.
		 */
		if (predict_false(atomic_load_explicit(&wq->refcnt,
		    memory_order_consume) == 0)) {
			/* Undo update to running flag. */
			atomic_fetch_and_explicit(&wq->flags, ~WQ_RUNNING,
			    memory_order_release);
			/* Undo job flag change. */
			job_deref_unlock(j);
			atomic_fetch_and_explicit(&j->flags, ~JOB_RUNNING,
			    memory_order_release);
			return job_run_nowq;
		}
		if (predict_false(atomic_load_explicit(&wq->want_refcnt,
		    memory_order_consume) != 0)) {
			/* Undo update to running flag. */
			atomic_fetch_and_explicit(&wq->flags, ~WQ_RUNNING,
			    memory_order_release);
			/* Undo job flag change. */
			job_deref_unlock(j);
			atomic_fetch_and_explicit(&j->flags, ~JOB_RUNNING,
			    memory_order_release);
			return job_run_wqbusy;
		}

		/* Release lock on workq. */
		job_deref_unlock(j);

		/* We acquired the workq running state,
		 * fill in the thread pointer. */
		workq_self_set(wq, curthread);
	}

	/* If this job is not persistent, clear the active bit. */
	if (!(jf & NET2_WORKQ_PERSIST)) {
		atomic_fetch_and_explicit(&j->flags, ~JOB_ACTIVE,
		    memory_order_consume);
	}

	/*
	 * job is now marked running.
	 * If update_wq was set, workq is also marked running.
	 */
	return job_run_succes;
}
/*
 * Clear running flag from job.
 *
 * Returns true if the job is active.
 */
static __inline int
__hot__
job_run_clear(struct net2_workq_job *j)
{
	int		 active;
	struct net2_workq
			*wq;
	unsigned int	 jfl;

	/*
	 * Mark as not running.
	 * If the job is active but not onqueue, update the workq.
	 */
	jfl = atomic_fetch_and_explicit(&j->flags, ~JOB_RUNNING,
	    memory_order_release);
	active = (jfl & JOB_ACTIVE);
	if (!active || (jfl & JOB_ONQUEUE))
		return active;

	/* Acquire the workq. */
	if ((wq = job_deref_lock(j)) == NULL)
		return active;

	/* Put the job on its workq runq. */
	job_onqueue(j);

	job_deref_unlock(j);
	return active;
}
/*
 * Kill the workq.
 *
 * Workq must have a refcnt of zero.
 * If wait is set, the operation will not complete until the workq
 * has ceased to be running.
 * The operation may complete with running jobs, if the current thread
 * is executing this job.
 *
 * If killme is set, the operation is invoked due to the killme flag being set.
 * In this case, the DYING flag must already be present,
 * so the duplicate assignment is ignored.
 *
 * Returns true if the workq was killed immediately.
 */
static int
__cold__
kill_wq(struct net2_workq *wq, int wait, int killme)
{
	unsigned int	 wqf;
	unsigned int	 jf;
	struct net2_workq_job
			*j;
	int		 spin;

	assert(atomic_load_explicit(&wq->refcnt, memory_order_relaxed) == 0);

	/* Mark workq as dying. */
	wqf = atomic_fetch_or_explicit(&wq->flags, WQ_DYING,
	    memory_order_acquire);
	assert(killme || !(wqf & WQ_DYING));
	wqf |= WQ_DYING;

	/* If this workq is on the runqueue, remove it now. */
	if (wqf & WQ_ONQUEUE)
		workq_offqueue(wq);

	if (wqf & WQ_RUNNING) {
		/*
		 * Figure out which thread is running this workq.
		 *
		 * If the current thread is running this workq, it cannot wait
		 * and final destruction must be forwarded to the running
		 * thread.
		 *
		 * Note that if thr is null, it cannot be the current thread,
		 * since no thread will call this function between modifying
		 * the running state and modifying the thread.
		 */
		if (workq_self(wq)) {
			atomic_fetch_or_explicit(&wq->flags, WQ_KILLME,
			    memory_order_acq_rel);
			return 0;
		}

		/*
		 * If wait is set, wait for the running job to complete.
		 * Otherwise, put the requirement to clean up
		 * on the running thread.
		 */
		if (wait) {
			while (atomic_load_explicit(&wq->flags,
			    memory_order_consume) & WQ_RUNNING);
				thryield();
		} else {
			if (atomic_fetch_or_explicit(&wq->flags, WQ_KILLME,
			    memory_order_acq_rel) & WQ_RUNNING)
				return 0;
			/* Running state was disengaged. */
			wqf = atomic_fetch_and_explicit(&wq->flags, ~WQ_KILLME,
			    memory_order_relaxed);
			assert(wqf & WQ_KILLME);
			wqf &= ~WQ_KILLME;
		}
	}

	/*
	 * Workq is not running and can be released.
	 */
	net2_spinlock_lock(&wq->spl);
	while ((j = TAILQ_FIRST(&wq->members)) != NULL) {
#define SPIN 128
		/* Acquire the dereference lock.
		 * If the lock is held, there's a chance wq_clear is running,
		 * which means it will deadlock on our spl.
		 *
		 * Release the spl, yield, then continue.
		 * This also means we cannot touch the job.
		 *
		 * Because the deref lock is also used for very short failing
		 * attempts at referencing the workq, allow a short duration
		 * spin.
		 */
		spin = SPIN;
		for (spin = SPIN; spin > 0; spin--) {
			jf = atomic_fetch_or_explicit(&j->flags, JOB_DEREFING,
			    memory_order_acquire);
			if (!(jf & JOB_DEREFING))
				break;	/* GUARD */
			SPINWAIT();
		}
		if (jf & JOB_DEREFING) {
			/*
			 * Since we hold the spinlock, we may as well move the
			 * job to the back of the members queue, to enable us
			 * to progress with less chance of entering the wait
			 * again.
			 */
			TAILQ_REMOVE(&wq->members, j, members);
			TAILQ_INSERT_TAIL(&wq->members, j, members);

			net2_spinlock_unlock(&wq->spl);
			thryield();
			net2_spinlock_lock(&wq->spl);
			continue;
		}

		/*
		 * We hold the lock and the job is on the queue,
		 * workq pointer must be valid.
		 */
		assert(j->wq == wq);
		j->wq = NULL;
		/* Don't care about active. */
		TAILQ_REMOVE(&wq->members, j, members);

		/* Release dereference lock. */
		atomic_fetch_and_explicit(&j->flags, ~JOB_DEREFING,
		    memory_order_release);

		/*
		 * If the job had a callback set, invoke it now.
		 *
		 * XXX job_internal should be squashed so the callbacks
		 * are dereferenced easier.
		 */
		if (j->callbacks != NULL &&
		    j->callbacks->on_wqdestroy != NULL) {
			net2_spinlock_unlock(&wq->spl);
			j->callbacks->on_wqdestroy(j);
			net2_spinlock_lock(&wq->spl);
		}
#undef SPIN
	}
	net2_spinlock_unlock(&wq->spl);

	/*
	 * No jobs point at this workq, it has no references,
	 * nor is it running.
	 * It can now safely be destroyed.
	 */
	net2_workq_evbase_release(wq->wqev);
	net2_mutex_free(wq->want_mtx);
	net2_spinlock_deinit(&wq->spl);
	net2_free(wq);

	/* Since the workq is now fully dead, return succes. */
	return 1;
}
/*
 * Mark job as active.
 *
 * Returns true if the job transitioned from inactive to active.
 */
static __inline int
job_active_set(struct net2_workq_job *j)
{
	/* Mark the job as active. */
	if (atomic_fetch_or_explicit(&j->flags, JOB_ACTIVE,
	    memory_order_acq_rel) & JOB_ACTIVE)
		return 0;	/* Already active. */

	/* Acquire workq. */
	if (job_deref_lock(j) == NULL) {
		/*
		 * Undo activation and fail.
		 *
		 * Since a job without a workq can never regain another workq,
		 * we maintain the ACTIVE flag so future invocations will
		 * complete faster (by erronously detecting double activation).
		 */
		return 0;
	}

	/* Put the job on its workq runq. */
	job_onqueue(j);

	/* Release our hold on the job. */
	job_deref_unlock(j);
	return 1;
}
/*
 * Mark job as inactive.
 *
 * Note that a deactivated job is not removed from the workq.
 * The workq will encounter the job and noticing it cannot run,
 * remove it from the queue.
 */
static __inline void
job_active_clear(struct net2_workq_job *j, int wait)
{
	unsigned int	 jf;
	struct net2_workq
			*wq;

	jf = atomic_fetch_and_explicit(&j->flags, ~JOB_ACTIVE,
	    memory_order_acq_rel);
	if (!wait || !(jf & JOB_RUNNING))
		return;

	/*
	 * Acquire workq.
	 *
	 * Note that we do not test if the workq is live:
	 * a workq can cease to be live while still completing its last
	 * job.  Since we hold the DEREF lock, the workq cannot go away
	 * without us allowing it.
	 */
	for (;;) {
		jf = atomic_fetch_or_explicit(&j->flags, JOB_DEREFING,
		    memory_order_acq_rel);
		if (!(jf & JOB_DEREFING))
			break;	/* GUARD */
		SPINWAIT();
	}
	if (predict_false(!(jf & JOB_RUNNING))) {
		/* Shortcut: while we waited, the job ceased to be running. */
		goto out;
	}

	/* Test that the workq is alive. */
	wq = j->wq;
	if (predict_false(wq == NULL)) {
		/*
		 * Job cannot be running if workq is nonexistant.
		 * Predicted false since a running workq is usually live.
		 */
		goto out;
	}

	/*
	 * Check if we are running the thread.
	 * Waiting for ourselves would be silly.
	 */
	if (workq_self(wq))
		goto out;

	/* Release the workq but wait for the job to cease running. */
	atomic_fetch_add_explicit(&j->runwait, 1, memory_order_acquire);
	jf = atomic_fetch_and_explicit(&j->flags, ~JOB_DEREFING,
	    memory_order_release);
	while (jf & JOB_RUNNING) {
		thryield();
		jf = atomic_load_explicit(&j->flags, memory_order_consume);
	}
	atomic_fetch_sub_explicit(&j->runwait, 1, memory_order_release);
	return;

out:
	atomic_fetch_and_explicit(&j->flags, ~JOB_DEREFING,
	    memory_order_release);
	return;
}

/* Create a new evbase. */
ILIAS_NET2_EXPORT struct net2_workq_evbase*
__cold__
net2_workq_evbase_new(const char *name, int jobthreads, int maxthreads)
{
	struct net2_workq_evbase
			*wqev;

	if (maxthreads < jobthreads)
		return NULL;

	if ((wqev = net2_malloc(sizeof(*wqev))) == NULL)
		goto fail_0;
	if (net2_spinlock_init(&wqev->spl))
		goto fail_1;
	TAILQ_INIT(&wqev->runq);
	atomic_init(&wqev->evloop, 0);	/* Lazily allocated. */
	ev_async_init(&wqev->ev_wakeup, &evloop_wakeup);
	ev_async_init(&wqev->ev_newevent, &evloop_new_event);

	wqev->jobthreads = 0;
	wqev->maxthreads = 0;
	if (net2_semaphore_init(&wqev->thr_active))
		goto fail_2;
	if (net2_semaphore_init(&wqev->thr_idle))
		goto fail_3;
	if (net2_semaphore_init(&wqev->thr_die))
		goto fail_4;
	if (net2_semaphore_init(&wqev->thr_death))
		goto fail_5;
	if (name == NULL)
		wqev->wq_worker_name = NULL;
	else if ((wqev->wq_worker_name = net2_strdup(name)) == NULL)
		goto fail_6;
	atomic_init(&wqev->refcnt, 1);

	if ((wqev->workers_mtx = net2_mutex_alloc()) == NULL)
		goto fail_7;
	if (net2_spinlock_init(&wqev->spl_workers))
		goto fail_8;
	TAILQ_INIT(&wqev->workers);
	TAILQ_INIT(&wqev->dead_workers);

	if (net2_workq_set_thread_count(wqev, jobthreads, maxthreads)) {
		net2_workq_set_thread_count(wqev, 0, 0);
		goto fail_9;
	}

	return wqev;


fail_10:
	net2_workq_set_thread_count(wqev, 0, 0);
fail_9:
	net2_spinlock_deinit(&wqev->spl_workers);
fail_8:
	net2_mutex_free(wqev->workers_mtx);
fail_7:
	if (wqev->wq_worker_name != NULL)
		net2_free(wqev->wq_worker_name);
fail_6:
	net2_semaphore_deinit(&wqev->thr_death);
fail_5:
	net2_semaphore_deinit(&wqev->thr_die);
fail_4:
	net2_semaphore_deinit(&wqev->thr_idle);
fail_3:
	net2_semaphore_deinit(&wqev->thr_active);
fail_2:
	net2_spinlock_deinit(&wqev->spl);
fail_1:
	net2_free(wqev);
fail_0:
	return NULL;
}
/* Acquire an additional reference to the wwqev. */
ILIAS_NET2_EXPORT void
__cold__
net2_workq_evbase_ref(struct net2_workq_evbase *wqev)
{
	atomic_fetch_add_explicit(&wqev->refcnt, 1, memory_order_acquire);
}
/*
 * Release reference to wqev.
 *
 * Destroys the wqev if the last reference went away.
 */
ILIAS_NET2_EXPORT void
__cold__
net2_workq_evbase_release(struct net2_workq_evbase *wqev)
{
	struct ev_loop	*evl;

	if (predict_false(wqev == NULL))
		return;
	if (predict_true(atomic_fetch_sub_explicit(&wqev->refcnt, 1,
	    memory_order_release) != 1))
		return;

	/* Kill all worker threads. */
	net2_workq_set_thread_count(wqev, 0, 0);

	evl = (struct ev_loop*)(atomic_load_explicit(&wqev->evloop,
	    memory_order_relaxed));
	if (evl != NULL)
		ev_loop_destroy(evl);

	if (wqev->wq_worker_name != NULL)
		net2_free(wqev->wq_worker_name);
	net2_spinlock_deinit(&wqev->spl);
	net2_semaphore_deinit(&wqev->thr_active);
	net2_semaphore_deinit(&wqev->thr_idle);
	net2_semaphore_deinit(&wqev->thr_die);
	net2_semaphore_deinit(&wqev->thr_death);
	net2_mutex_free(wqev->workers_mtx);
	net2_spinlock_deinit(&wqev->spl_workers);
	net2_free(wqev);
}
/* Inform the workq that the set of events changed. */
ILIAS_NET2_LOCAL void
net2_workq_evbase_evloop_changed(struct net2_workq_evbase *wqev)
{
	struct ev_loop	*evl;

	evl = (struct ev_loop*)(atomic_load_explicit(&wqev->evloop,
	    memory_order_relaxed));
	if (evl != NULL)
		ev_async_send(evl, &wqev->ev_wakeup);
}

/* Create a new workq. */
ILIAS_NET2_EXPORT struct net2_workq*
net2_workq_new(struct net2_workq_evbase *wqev)
{
	struct net2_workq	*wq;

	if (wqev == NULL)
		return NULL;

	if ((wq = net2_malloc(sizeof(*wq))) == NULL)
		goto fail_0;

	atomic_init(&wq->flags, 0);
	wq->wqev = wqev;
	TAILQ_INIT(&wq->runqueue);

	atomic_init(&wq->refcnt, 1);
	atomic_init(&wq->thread, 0);

	atomic_init(&wq->want_refcnt, 0);
	atomic_init(&wq->want_queued, 0);

	if ((wq->want_mtx = net2_mutex_alloc()) == NULL)
		goto fail_1;

	if (net2_spinlock_init(&wq->spl))
		goto fail_2;

	TAILQ_INIT(&wq->members);

	net2_workq_evbase_ref(wqev);
	return wq;


fail_3:
	net2_spinlock_deinit(&wq->spl);
fail_2:
	net2_mutex_free(wq->want_mtx);
fail_1:
	net2_free(wq);
fail_0:
	return NULL;
}
/* Acquire a reference to a workq. */
ILIAS_NET2_EXPORT void
net2_workq_ref(struct net2_workq *wq)
{
	workq_ref(wq);
}
/* Release reference to a workq. */
ILIAS_NET2_EXPORT void
net2_workq_release(struct net2_workq *wq)
{
	if (predict_false(wq == NULL))
		return;
	if (predict_false(workq_release(wq)))
		kill_wq(wq, 0, 0);
}
/*
 * Return the workq_evbase that this workq runs on.
 * The returned wqev is not referenced.
 */
ILIAS_NET2_EXPORT struct net2_workq_evbase*
net2_workq_evbase(struct net2_workq *wq)
{
	return wq->wqev;
}

/* Initialize a job. */
ILIAS_NET2_EXPORT int
__hot__
net2_workq_init_work(struct net2_workq_job *j, struct net2_workq *wq,
    net2_workq_cb fn, void *arg0, void *arg1, int flags)
{
	if (fn == NULL || wq == NULL || j == NULL)
		return EINVAL;
	if (flags & ~NET2_WORKQ_VALID_USERFLAGS)
		return EINVAL;

	j->fn = fn;
	j->cb_arg[0] = arg0;
	j->cb_arg[1] = arg1;
	atomic_init(&j->flags, flags);
	j->wq = wq;
	atomic_init(&j->runwait, 0);
	j->callbacks = NULL;
	j->death = NULL;

	/* Add new job to workq member set. */
	net2_spinlock_lock(&wq->spl);
	TAILQ_INSERT_TAIL(&wq->members, j, members);
	net2_spinlock_unlock(&wq->spl);

	workq_ref(wq);
	return 0;
}
/* Deinit a job. */
ILIAS_NET2_EXPORT void
__hot__
net2_workq_deinit_work(struct net2_workq_job *j)
{
	if (j->fn == NULL)
		return;

	if (predict_true(workq_job_wq_clear(j))) {
		if (j->callbacks && j->callbacks->on_destroy)
			j->callbacks->on_destroy(j);
	}
	j->fn = NULL;
}
/* Activate a job. */
ILIAS_NET2_EXPORT void
__hot__
net2_workq_activate(struct net2_workq_job *j, int flags)
{
	struct net2_thread
			*thr;
	int		 death;

	if (predict_false(j->fn == NULL))
		return;

	if (flags & NET2_WQ_ACT_IMMED) {
		thr = net2_thread_self();
		if (thr != NULL &&
		    job_run_set(j, 1, thr, 0, 1) == job_run_succes) {
			/* Mark the job as active if it is a persistent job. */
			if (atomic_load_explicit(&j->flags,
			    memory_order_consume) & NET2_WORKQ_PERSIST) {
				atomic_fetch_or_explicit(&j->flags, JOB_ACTIVE,
				    memory_order_seq_cst);
			}

			/* Invoke the job. */
			death = 0;
			j->death = &death;
			j->fn(j->cb_arg[0], j->cb_arg[1]);

			/* Release job and thread. */
			if (!death) {
				j->death = NULL;
				job_run_clear(j);
			}
			net2_thread_free(thr);
			return;
		}
	}

	job_active_set(j);
}
/* Deactivate a job. */
ILIAS_NET2_EXPORT void
__hot__
net2_workq_deactivate(struct net2_workq_job *j)
{
	if (j->fn == NULL)
		return;

	job_active_clear(j, 1);
}

/*
 * Returns the workq that runs the specified job.
 * Returns NULL if the workq no longer exists.
 *
 * The returned workq is referenced.
 */
ILIAS_NET2_EXPORT struct net2_workq*
net2_workq_get(struct net2_workq_job *j)
{
	if (j->fn == NULL)
		return NULL;
	return workq_job_wq(j);
}

/*
 * Wait until the workq becomes available.
 *
 * Returns:
 * 0:		succes
 * EDEADLK:	called from within the workq
 * ETIMEDOUT:	failed to acquire lock
 * ENOMEM:	insufficient memory to start operation
 *
 * Workq want state acquisition is reentrant: for each succesful
 * net2_workq_want() invocation, a matching net2_workq_unwant()
 * invocation must occur in the same thread.
 */
ILIAS_NET2_EXPORT int
net2_workq_want(struct net2_workq *wq, int try)
{
	switch (workq_want_set(wq, try)) {
	case wq_want_succes:
		return 0;
	case wq_want_running:
		return EDEADLK;
	case wq_want_tryfail:
		return ETIMEDOUT;
	case wq_want_memfail:
		return ENOMEM;
	default:
		abort();
	}
}
/* Release workq want state. */
ILIAS_NET2_EXPORT void
net2_workq_unwant(struct net2_workq *wq)
{
	if (workq_want_clear(wq))
		workq_activate(wq);
}

/*
 * Return the event loop.
 *
 * The ev_loop is created on demand (calling this function being the demand).
 */
ILIAS_NET2_LOCAL struct ev_loop*
net2_workq_get_evloop(struct net2_workq *wq)
{
	uintptr_t	 evl;
	struct ev_loop	*new;
	struct net2_workq_evbase
			*wqev;

	wqev = wq->wqev;

	/* Load existing evloop. */
	evl = atomic_load_explicit(&wqev->evloop, memory_order_relaxed);
	if (predict_true(evl != 0))
		return (struct ev_loop*)evl;

	/* No existing evloop, create a new evloop. */
	new = ev_loop_new(EVFLAG_AUTO);
	if (new == NULL)
		return NULL;

	/* Assign wqev as the user data for the event loop. */
	ev_set_userdata(new, wqev);

	/*
	 * Assign the new evloop.
	 * Failure indicates another thread assigned an ev_loop
	 * while we were creating one.
	 */
	if (atomic_compare_exchange_strong_explicit(&wqev->evloop, &evl,
	    (uintptr_t)new, memory_order_seq_cst, memory_order_relaxed)) {
		ev_async_start(new, &wqev->ev_wakeup);
		ev_async_start(new, &wqev->ev_newevent);
		return new;
	}

	/*
	 * Failure to assign.
	 * Free the new ev_loop and return the updated evl.
	 */
	ev_loop_destroy(new);
	return (struct ev_loop*)evl;
}

/* Interrupt the evloop (async wakeup callback). */
static void
evloop_wakeup(struct ev_loop *loop, ev_async *ev ILIAS_NET2__unused,
    int events ILIAS_NET2__unused)
{
	ev_break(loop, EVBREAK_ALL);
}

/* Interrupt the evloop so that it will re-evaluate its list of events. */
static void
evloop_new_event(struct ev_loop *loop ILIAS_NET2__unused,
    ev_async *ev ILIAS_NET2__unused,
    int events ILIAS_NET2__unused)
{
	/*
	 * Do nothing: desired behaviour is a side effect from invoking this
	 * function.
	 */
}

/* Acquire a queued workq from the wqev. */
static __inline struct net2_workq*
__hot__
wqev_run_pop(struct net2_workq_evbase *wqev, struct net2_thread *curthread)
{
	struct net2_workq	*wq;

	/* Acquire a workq and mark it running. */
	TAILQ_FOREACH(wq, &wqev->runq, wqev_runq) {
		if (workq_run_set(wq, curthread)) {
			assert(atomic_load_explicit(&wq->flags,
			    memory_order_relaxed) & WQ_ONQUEUE);
			atomic_fetch_and_explicit(&wq->flags, ~WQ_ONQUEUE,
			    memory_order_seq_cst);
			TAILQ_REMOVE(&wqev->runq, wq, wqev_runq);
			return wq;
		}
	}
	return NULL;
}

/*
 * Release a workq previously acquired using wqev_run_pop.
 *
 * If did_something is set, the workq had some workq queued and
 * is immediately activated.
 */
static __inline void
__hot__
wqev_run_push(struct net2_workq *wq, int did_something)
{
	if (workq_run_clear(wq, did_something) == wq_killme)
		kill_wq(wq, 1, 1);
}

/* Acquire a job from the workq. */
static __inline struct net2_workq_job*
__hot__
wq_run_pop(struct net2_workq *wq, int *did_something)
{
	struct net2_workq_job	*j, *j_next, *first, *last;

	net2_spinlock_lock(&wq->spl);
	first = TAILQ_FIRST(&wq->runqueue);
	last = NULL;
	for (j = first; j != last; j = j_next) {
		j_next = TAILQ_NEXT(j, runqueue);

		switch (job_run_set(j, 0, NULL, 0, 0)) {
		case job_run_succes:
			*did_something = 1;
			TAILQ_REMOVE(&wq->runqueue, j, runqueue);
			TAILQ_INSERT_TAIL(&wq->runqueue, j, runqueue);
			goto out;	/* Loop break. */
		case job_run_inactive:
			atomic_fetch_and_explicit(&j->flags, ~JOB_ONQUEUE,
			    memory_order_seq_cst);
			TAILQ_REMOVE(&wq->runqueue, j, runqueue);
			break;
		case job_run_wait:
			*did_something = 1;
			/* FALLTHROUGH */
		case job_run_twice:
			TAILQ_REMOVE(&wq->runqueue, j, runqueue);
			TAILQ_INSERT_TAIL(&wq->runqueue, j, runqueue);
			if (last == NULL)
				last = j;
			break;
		case job_run_nowq:
		case job_run_wqbusy:
			/*
			 * Shouldn't happen:
			 * the workq must be in the running state.
			 */
			abort();
			break;
		}
	}
out:
	net2_spinlock_unlock(&wq->spl);
	return j;
}

/* Release a job previously acquire using wq_run_pop. */
static __inline void
__hot__
wq_run_push(struct net2_workq_job *j)
{
	job_run_clear(j);
}

/*
 * Worker thread implementation.
 */
static void*
__hot__
wqev_worker(void *wthr_ptr)
{
	struct net2_workq_evbase_worker
				*wthr;
	struct net2_thread	*curthread;
	struct net2_workq_evbase*wqev;
	struct net2_workq	*wq;
	struct net2_workq_job	*j;
	int			 did_something;
	int			 count;
	const int		 COUNT = 8;
	int			 death;

	/* XXX put wthr into ThreadLocalStorage. */
	wthr = wthr_ptr;
	net2_spinlock_lock(&wthr->spl);
	wqev = wthr->evbase;
	curthread = wthr->worker;
	net2_spinlock_unlock(&wthr->spl);

	/*
	 * A worker always transitions from active to idle.
	 *
	 * To run, it decrements thr_active.
	 * When it ceases to run, it increments thr_idle.
	 * The workq_onqueue function always attempts to transfer one
	 * semaphore level from idle to active.
	 *
	 * thr_active is also incremented when threads need to die.
	 * In this case, the trydown on thr_die will enable the thread to
	 * die immediately.
	 */
	for (;;) {
		did_something = 0;
		net2_semaphore_down(&wqev->thr_active);
		if (net2_semaphore_trydown(&wqev->thr_die))
			break;	/* GUARD */

		/* Lock runq. */
		net2_spinlock_lock(&wqev->spl);
		while ((wq = wqev_run_pop(wqev, curthread)) != NULL) {
			net2_spinlock_unlock(&wqev->spl);

			/* Execute up to count jobs from this workq. */
			count = COUNT;
			while (count-- > 0 &&
			    (j = wq_run_pop(wq, &did_something)) != NULL) {
				death = 0;
				j->death = &death;
				j->fn(j->cb_arg[0], j->cb_arg[1]);
				if (!death) {
					j->death = NULL;
					wq_run_push(j);
				}
			}

			/* Release the workq exec state. */
			wqev_run_push(wq, did_something);

			/* Check in every so often to see if we need to die. */
			if (net2_semaphore_trydown(&wqev->thr_die))
				goto die;	/* double GUARD */

			/* Reacquire the wqev runq. */
			net2_spinlock_lock(&wqev->spl);
		}

		/* Go to sleep. */
		net2_semaphore_up(&wqev->thr_idle, 1);	/* Must be done while
							 * holding the
							 * spinlock! */
		net2_spinlock_unlock(&wqev->spl);
	}

die:
	/* Mark this wthr as dead. */
	net2_spinlock_lock(&wqev->spl_workers);
	TAILQ_REMOVE(&wqev->workers, wthr, tq);
	TAILQ_INSERT_TAIL(&wqev->dead_workers, wthr, tq);
	net2_spinlock_unlock(&wqev->spl_workers);
	/* Signal for cleanup. */
	net2_semaphore_up(&wqev->thr_death, 1);
	return NULL;
}

/* Create a worker thread for this wqev. */
static int
__cold__
create_thread(struct net2_workq_evbase *wqev)
{
	struct net2_workq_evbase_worker
				*wthr;
	const char		*wname;

	wname = (wqev->wq_worker_name == NULL ?
	    "workq worker" :
	    wqev->wq_worker_name);

	if ((wthr = net2_malloc(sizeof(*wthr))) == NULL)
		return ENOMEM;
	wthr->evbase = wqev;
	net2_spinlock_init(&wthr->spl);
	net2_spinlock_lock(&wthr->spl);
	wthr->worker = net2_thread_new(&wqev_worker, wthr, wname);
	net2_spinlock_unlock(&wthr->spl);
	if (wthr->worker == NULL) {
		net2_spinlock_unlock(&wqev->spl_workers);
		net2_free(wthr);
		return ENOMEM;
	}

	net2_spinlock_lock(&wqev->spl_workers);
	TAILQ_INSERT_TAIL(&wqev->workers, wthr, tq);
	net2_spinlock_unlock(&wqev->spl_workers);
	return 0;
}
static void
__cold__
destroy_thread(struct net2_workq_evbase *wqev, int count)
{
	struct net2_workq_evbase_worker
				*wthr;
	int			 i;

	if (count <= 0)
		return;

	/* Mark count threads as having to die. */
	net2_semaphore_up(&wqev->thr_die, count);
	/* Make the same number of threads active. */
	net2_semaphore_up(&wqev->thr_active, count);

	/* Wait for all dying threads to finish. */
	for (i = 0; i < count; i++)
		net2_semaphore_down(&wqev->thr_death);

	/* Collect all dead threads. */
	while ((wthr = TAILQ_FIRST(&wqev->dead_workers)) != NULL) {
		TAILQ_REMOVE(&wqev->dead_workers, wthr, tq);
		net2_thread_join(wthr->worker, NULL);
		net2_thread_free(wthr->worker);
		net2_spinlock_deinit(&wthr->spl);
		net2_free(wthr);
	}
}

/* Modify the thread counts. */
ILIAS_NET2_EXPORT int
__cold__
net2_workq_set_thread_count(struct net2_workq_evbase *wqev,
    int jobthreads, int maxthreads)
{
	int	 kill;
	int	 error;

	/* Lock out other threads from modifying the counts. */
	net2_mutex_lock(wqev->workers_mtx);

	/* Increase number of worker threads. */
	while (wqev->maxthreads < maxthreads) {
		if ((error = create_thread(wqev)) != 0)
			goto out;
		wqev->maxthreads++;
	}
	/* Decrease number of worker threads. */
	if (wqev->maxthreads > maxthreads) {
		kill = wqev->maxthreads - maxthreads;
		destroy_thread(wqev, kill);
		wqev->maxthreads -= kill;
	}

	/* Change the number of job threads. */
	if (jobthreads > wqev->jobthreads) {
		/* Increment activity. */
		net2_semaphore_up(&wqev->thr_active,
		    jobthreads - wqev->jobthreads);
		wqev->jobthreads = jobthreads;
	} else {
		/* Descrement activity. */
		while (jobthreads < wqev->jobthreads) {
			if (net2_semaphore_trydown(&wqev->thr_active))
				wqev->jobthreads--;
			else
				break;
		}
		/* Decrement idle threads. */
		while (jobthreads < wqev->jobthreads) {
			net2_semaphore_down(&wqev->thr_idle);
			wqev->jobthreads--;
		}
	}

	error = 0;

out:
	/* Unlock thread count modification. */
	net2_mutex_unlock(wqev->workers_mtx);

	return error;
}

/*
 * Help out a specific workq.
 *
 * Runs up to count jobs from the specified workq.
 * The workq reference must stay valid during execution.
 * If the workq has less runnable jobs than requested, the function
 * will return before running those jobs.
 *
 * Returns:
 * - 0: at least one job was run
 * - ENOMEM: insufficient memory to run workq
 * - EAGAIN: workq had no runnable jobs
 * - EBUSY: the workq is running or want-locked
 */
ILIAS_NET2_EXPORT int
net2_workq_aid(struct net2_workq *wq, int count)
{
	struct net2_workq_evbase_worker
				 wthr;
	struct net2_workq_job	*j;
	int			 error;
	int			 did_something = 0;
	int			 wqev_locked = 0;
	int			 death;

	/* No point in running negative # of jobs. */
	if (count <= 0)
		return EINVAL;

	/* Create fake worker structure. */
	if ((error = net2_spinlock_init(&wthr.spl)) != 0)
		goto out_0;
	if ((wthr.worker = net2_thread_self()) == NULL) {
		error = ENOMEM;
		goto out_1;
	}
	wthr.evbase = wq->wqev;
	net2_workq_evbase_ref(wthr.evbase);

	/* Lock runq. */
	net2_spinlock_lock(&wthr.evbase->spl);
	wqev_locked = 1;

	/* Attempt to run the wq. */
	if (!workq_run_set(wq, wthr.worker)) {
		error = EBUSY;
		goto out_3;
	}

	/* Take job from the runqueue. */
	if (atomic_fetch_and_explicit(&wq->flags, ~WQ_ONQUEUE,
	    memory_order_seq_cst) & WQ_ONQUEUE)
		TAILQ_REMOVE(&wthr.evbase->runq, wq, wqev_runq);
	/* Unlock wqev. */
	net2_spinlock_unlock(&wthr.evbase->spl);
	wqev_locked = 0;

	/* Run up to COUNT jobs from this wq. */
	while (count-- > 0 && (j = wq_run_pop(wq, &did_something)) != NULL) {
		death = 0;
		j->death = &death;
		j->fn(j->cb_arg[0], j->cb_arg[1]);
		if (!death) {
			j->death = NULL;
			wq_run_push(j);
		}
	}

	/* Succesful completion. */
	if (!did_something)
		error = EAGAIN;
	else
		error = 0;

out_4:
	/* Put job back on the runqueue. */
	assert(!wqev_locked);
	wqev_run_push(wq, did_something);
out_3:
	/* Unlock wqev. */
	if (wqev_locked)
		net2_spinlock_unlock(&wthr.evbase->spl);
out_2:
	net2_workq_evbase_release(wthr.evbase);
	net2_thread_free(wthr.worker);
out_1:
	net2_spinlock_deinit(&wthr.spl);
out_0:
	return error;
}
