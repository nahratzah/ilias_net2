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
#include <ilias/net2/ll.h>
#include <ilias/net2/config.h>
#include <ilias/net2/bsd_compat/error.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <ilias/net2/bsd_compat/queue.h>
#endif

#ifndef WIN32
#include <pthread.h>
#ifdef __linux__
#include <sched.h>
#define pthread_yield()		sched_yield()
#endif
#endif

#ifdef HAS_NANOSLEEP
#include <time.h>
#endif

#ifndef WIN32	/* Only use libev on non-windows. */
#include <ev.h>
#ifdef EV_C
#include EV_C
#endif
#endif

#ifdef WIN32
/* For timer management interaction. */
#include <ilias/net2/workq_timer.h>
#include <ilias/net2/workq_io.h>
#endif

/*
 * net2_workq, net2_workq_evbase, net2_workq_job implementation.
 *
 * === evbase ===
 * The event base maintains the worker threads and directs IO.
 * The event base is referenced by each workq, in addition to the external
 * references from code using the workq, controlled via
 * net2_workq_evbase_ref() and net2_workq_evbase_release().
 *
 * == evbase IO ==
 * The IO part of net2_workq_evbase coordinates timers and IO.
 * On windows, the system is split in two parts: the timer logic
 * and the IO logic, where the latter is implemented in terms of IOCP.
 * On all other platforms, we use libev to coordinate IO and timers.
 *
 * == worker threads ==
 * An evbase may have 0 or more worker threads.  These worker threads
 * will run jobs, sleeping for new jobs to become runnable in between.
 *
 * === workq ===
 * The workq is the heart of the code.  They abstract many (userspace)
 * threads.  Each workq is like an event loop, where it executes any
 * activated job.
 *
 * Workq activity can be suspended using a call to net2_workq_want().
 * Care should be taken using this call: there is a possibility for deadlock
 * when workq A wants B and workq B wants A, since A and B are the currently
 * running workqs in this example.
 *
 * A workq exists while it has at least one associated job or at least
 * one reference from userspace.
 *
 * === workq job ===
 * The workq jobs represent instances of workq that is to be done using
 * the workq.  Jobs may be marked persistent, which means they will be
 * invoked until they are deactivated.  Non-persistent jobs are activated
 * when they start running.
 *
 * Null jobs are a special kind of job, on which every operation is a
 * noop.  Transitioning from a null job to a real job and vice versa is
 * atomic.  It is recommended that each job that is not explicitly
 * initialized at construction, is initialized as a null job.
 * Deinitializing a job changes it into a null job.  Null jobs do not
 * require deinitialization.
 *
 * Job deactivation marks the job as not-to-be-run.  The
 * net2_workq_deactivate() function deactivates a job.  By default the
 * function will wait with returning until the job ceases to be running
 * (regardless of another thread activating the job while waiting).
 * The wait can be avoided by supplying the NOWAIT flag to
 * net2_workq_deactivate().  Job deinitialization will always wait
 * until the job ends the running state.
 *
 * When destroying an object, it is recommended to first deinitialize
 * all jobs it holds.  Alternatively, if the object has a designated
 * workq, the workq can be prevented from running with net2_workq_want(),
 * by surfing into the workq or by running the destructor from within
 * a workq job (the latter does not prevent PARALLEL jobs from running).
 *
 * === running ===
 * When a worker thread or user thread starts a job, the job and its
 * associated workq will be marked as running.  Thread-local-storage
 * is used to expose which workqs and jobs are owned by the currently
 * running thread.
 *
 * Jobs with the marker PARALLEL do not mark their associated workq
 * as running.  Since a workq can only be marked running in one thread,
 * this allows one or more PARALLEL jobs to run alongside non-PARALLEL
 * jobs.  PARALLEL jobs are still blocked by the workq being wanted.
 *
 * === workq surfing ===
 * A workq can be marked running on the fly, by calling the
 * net2_workq_mark_run() function.  This will mark the currently running
 * workq (if any) as not-running and the new workq (if not null) as running.
 * If the new workq is running or wanted, the implementation will sleep
 * until those conditions clear.
 *
 * The previous workq will be able to start new jobs.  To prevent the
 * previous workq from running any new jobs, net2_workq_want() can be
 * invoked prior to the switch, to prevent the old workq from becoming
 * runable (but note that this may create deadlock).
 *
 * If a job is activated using the IMMED flag, the underlying implementation
 * will behave as if workq surfing is being performed, pushing the current
 * workq on the stack, to be popped back after the IMMED activation completes.
 *
 * Only one workq can be the active workq.
 */


/*
 * Macros to optimize code generation in critical paths in this code.
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


/* __thread keyword for windows. */
#if defined(WIN32) && !defined(HAS_TLS)
#define __thread	__declspec(thread)
#define HAS_TLS
#endif

/* Thread specific state for workq functions. */
struct wq_tls_state_t {
#ifndef HAS_TLS
	TAILQ_ENTRY(wq_tls_state_t) q;
#endif

	struct wq_act {
		struct net2_workq *wq;
		int		 parallel;
	}			 active_wq;
	struct net2_workq_job_int
				*active_job;
	struct net2_workq_evbase_worker
				*wthr;
	struct wthrq		*wq_stack;
};

#ifndef HAS_TLS
/* pthreads implementation. */
static pthread_key_t wq_tls_slot;

#define wq_tls_state		(*get_wq_tls_state())

static struct wq_tls_state_t	*get_wq_tls_state() __attribute__((pure));
static void			 release_wq_tls_state(void*);
#else
static __thread struct wq_tls_state_t wq_tls_state;
#endif


/* Flags that can be used at job initialization time. */
#define NET2_WORKQ_VALID_USERFLAGS					\
	(NET2_WORKQ_PERSIST | NET2_WORKQ_PARALLEL)


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


/* Internal state flags for workq job. */
#define JOB_RUNNING	0x00000001		/* Job is executing. */
#define JOB_ACTIVE	0x00000002		/* Job is to run. */
#define JOB_DEINIT	0x00000010		/* Job is being destroyed. */
#define JOB_QMANIP	0x00001000		/* Job is being put on q. */


/* List definitions. */
LL_HEAD(net2_workq_job_runq, net2_workq_job_int);
LL_HEAD(net2_workq_job_prunq, net2_workq_job_int);
LL_HEAD(net2_workq_runq, net2_workq);

/*
 * Internals of workq job.
 */
struct net2_workq_job_int {
	LL_ENTRY(net2_workq_job_int)
				 runq,		/* Link into workq runq. */
				 prunq;		/* Link into parallel runq. */

	net2_workq_cb		 fn;
	void			*cb_arg[2];

	struct net2_workq	*wq;
	struct wq_tls_state_t	*self;		/* Thread running this job. */

	atomic_size_t		 refcnt;	/* # references to job. */
	atomic_int		 flags;
	atomic_uint		 run_gen;	/* Run generation counter. */
};

/* Workq data. */
struct net2_workq {
	LL_ENTRY(net2_workq)
			 wqev_runq;		/* WQ evbase runqueue. */
	struct net2_workq_job_runq
			 runqueue;		/* All active jobs. */
	struct net2_workq_job_prunq
			 prunqueue;		/* All parallelizeable jobs. */

	struct net2_workq_evbase
			*wqev;

	struct wq_tls_state_t
			*want_owner;		/* Owner of want lock. */
	struct net2_mutex
			*want_mtx;		/* For want sleep sync. */

	atomic_int	 flags;			/* State bits. */
#define WQ_RUNNING	0x00000001		/* Running. */
#define WQ_WANTLOCK	0x00000010		/* Workq is wanted. */
#define WQ_QMANIP	0x00000100		/* Queue manipulation active. */
#define WQ_DEINIT	0x00000200		/* Workq deinit active. */
	atomic_uint	 prun;			/* # parallel jobs on this wq
						 * currently running. */

	atomic_uint	 int_refcnt;		/* Internal references. */
	atomic_uint	 refcnt;		/* Reference counter. */
	atomic_uint	 want_refcnt;		/* Want refcnt. */
	atomic_uint	 want_queued;		/* # queued wants. */
};

/* Event base and thread pool. */
struct net2_workq_evbase {
	struct net2_workq_runq
			 runq;			/* All workq that need run. */

#ifndef WIN32
	struct ev_loop	*evloop;		/* Event loop. */
	ev_async	 ev_wakeup;		/* Wakeup for evloop. */
	ev_async	 ev_newevent;		/* Wakeup: events are added. */
	atomic_int	 evl_running;		/* True if a thread is running
						 * evloop. */
#define EVL_NOWAIT	1			/* Running in no-wait mode. */
#define EVL_WAIT	2			/* Running in wait more. */
	atomic_uint	 ev_idle;		/* Evloop is consuming an idle. */
#endif /* !WIN32 */

	struct net2_semaphore
			 thr_active,		/* Limit # running
						 * worker threads. */
			 thr_death;		/* # dead worker threads. */
	int		 jobthreads;		/* # threads running jobs. */
	int		 maxthreads;		/* # threads total. */
	atomic_uint	 thr_idle,		/* # worker thread idling. */
			 thr_die;		/* # worker threads
						 * that need to die. */

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

#ifdef WIN32
	net2_spinlock	 spl_io;		/* Protect io structures. */
	net2_spinlock	 spl_timer;		/* Protect timer structures. */
	struct net2_workq_io_container
			*io;			/* Windows IOCP wrapper. */
	struct net2_workq_timer_container
			*timer;			/* Windows timer, to handle
						 * timeouts. */
#else
	net2_spinlock	 spl_evloop;		/* Protect evloop
						 * construction. */
#endif
};

/* Worker thread differentiation. */
enum wthr_kind {
	WQEVW_NIL,			/* Uninitialized. */
	WQEVW_THREAD,			/* A workq thread. */
	WQEVW_AID			/* An aid invocation. */
};
/* A worker thread. */
struct net2_workq_evbase_worker {
	TAILQ_ENTRY(net2_workq_evbase_worker)
			 tq;			/* Link into threads. */
	net2_spinlock	 spl;			/* Protect owner pointer. */
	struct net2_thread
			*worker;		/* Worker thread. */
	struct net2_workq_evbase
			*evbase;		/* Owner. */

	struct net2_workq
			*wq_wthr;		/* Execing this workq. */

	enum wthr_kind	 kind;

	struct wthrq	*stack_spare;		/* Spare element. */
};

/* List of threads (via wq_tls_state) operating on a workq. */
struct wthrq {
	struct net2_workq	*wq;
	struct wthrq		*next;
};


/* List implementations. */
LL_GENERATE(net2_workq_job_runq, net2_workq_job_int, runq);
LL_GENERATE(net2_workq_job_prunq, net2_workq_job_int, prunq);
LL_GENERATE(net2_workq_runq, net2_workq, wqev_runq);


static void	activate_worker(struct net2_workq_evbase*);
static void	workq_clear_run(struct net2_workq*);
static void	job_clear_run(struct net2_workq_job_int*);
static void	kill_wq(struct net2_workq*);

#ifndef WIN32
static void	evloop_wakeup(struct ev_loop*, ev_async*, int);
static void	evloop_new_event(struct ev_loop*, ev_async*, int);

#define RUNEVL_NOWAIT		0x00000001
#define RUNEVL_RELEASE_SPL	0x00000002
#define RUNEVL_THRIDLE		0x00000004
static void	run_evl(struct net2_workq_evbase*, int);


/* Interupt the event loop, allowing re-evaluation of thr_active semaphore. */
static __inline void
evl_wakeup(struct net2_workq_evbase *wqev)
{
	assert(wqev->evloop != NULL);
	ev_async_send(wqev->evloop, &wqev->ev_wakeup);
}
#endif /* !WIN32 */


/* Allocate a wthr entry. */
static __inline struct wthrq*
__hot__
wthrq_alloc()
{
	struct wthrq	*result = NULL;
	struct net2_workq_evbase_worker
			*wthr = wq_tls_state.wthr;

	if (predict_true(wthr != NULL)) {
		result = wthr->stack_spare;
		wthr->stack_spare = NULL;
	}
	if (result == NULL)
		result = net2_malloc(sizeof(*result));
	if (result != NULL) {
		result->wq = NULL;
		result->next = NULL;
	}
	return result;
}
/* Free a wthr entry. */
static void
__hot__
wthrq_free(struct wthrq *q)
{
	struct net2_workq_evbase_worker
			*wthr = wq_tls_state.wthr;

	if (predict_true(wthr != NULL && wthr->stack_spare == NULL))
		wthr->stack_spare = q;
	else
		net2_free(q);
}
/* Put workq on activity stack. */
static __inline void
wthrq_assign(struct wthrq *q, struct net2_workq *wq)
{
	assert(q != NULL);
	assert(wq != NULL);
	assert(q->wq == NULL);

	q->wq = wq;
	q->next = wq_tls_state.wq_stack;
	wq_tls_state.wq_stack = q;
}
/* Remove wq from the activity stack. */
static void
__hot__
wthrq_unassign(struct net2_workq *wq)
{
	struct wthrq	*q, **q_ptr;

	/* Find q where q->wq == wq. */
	q_ptr = &wq_tls_state.wq_stack;
	for (;;) {
		q = *q_ptr;
		/*
		 * wq must be on the list, therefor we will never reach
		 * the end.
		 */
		assert(q != NULL);

		if (q->wq == wq)
			break;
	}

	/* Remove q from list. */
	*q_ptr = q->next;
	wthrq_free(q);
}
/* Check if the given workq is present on the activity stack. */
static int
wthrq_present(struct net2_workq *wq)
{
	struct wthrq	*q;

	for (q = wq_tls_state.wq_stack; q != NULL; q = q->next) {
		if (q->wq == wq)
			return 1;
	}
	return 0;
}


/*
 * Decrement atomic_uint, unless it is 0.
 * Returns 1 on succes, 0 on failure.
 */
static __inline int
decrement_idle(atomic_uint *i)
{
	unsigned int	 idle;

	/* Attempt to convert an idle thread to an active thread. */
	idle = atomic_load_explicit(i, memory_order_relaxed);
	while (idle > 0) {
		if (atomic_compare_exchange_weak_explicit(i, &idle, idle - 1,
		    memory_order_relaxed, memory_order_relaxed))
			return 1;
	}
	return 0;
}
/* Activate a worker thread. */
static void
__hot__
activate_worker(struct net2_workq_evbase *wqev)
{
	if (decrement_idle(&wqev->thr_idle))
		net2_semaphore_up(&wqev->thr_active, 1);

#ifndef WIN32
	/*
	 * Try to switch an idle evloop into active mode.
	 * We first read the flag, since that will be cheaper than
	 * decrementing the semaphore.
	 */
	if (atomic_load_explicit(&wqev->evl_running, memory_order_relaxed) ==
	    EVL_WAIT &&
	    decrement_idle(&wqev->ev_idle)) {
		net2_semaphore_up(&wqev->thr_active, 1);
		evl_wakeup(wqev);
		return;
	}
#endif /* !WIN32 */
}


/*
 * Workq onqueue management functions.
 */


/*
 * Take the workq off the runqueue.
 *
 * Returns 1 on succes, 0 on failure.
 */
static int
wq_offqueue(struct net2_workq *wq)
{
	struct net2_workq_evbase*wqev = wq->wqev;
	int			 rv;
	unsigned int		 int_refcnt;

	/* Refer to the runq. */
	LL_REF(net2_workq_runq, &wqev->runq, wq);
	rv = (LL_UNLINK(net2_workq_runq, &wqev->runq, wq) != NULL);
	if (rv) {
		int_refcnt = atomic_fetch_sub_explicit(&wq->int_refcnt, 1,
		    memory_order_relaxed);
		assert(int_refcnt > 1);
	} else
		LL_RELEASE(net2_workq_runq, &wqev->runq, wq);
	return rv;
}
/* Take a workq from the runq and acquire an internal reference. */
static struct net2_workq*
__hot__
wq_pop(struct net2_workq_evbase *wqev)
{
	struct net2_workq	*wq;
	unsigned int		 int_refcnt;
	int			 wqfl;

	while ((wq = LL_POP_FRONT_NOWAIT(net2_workq_runq, &wqev->runq)) !=
	    NULL) {
		if (atomic_load_explicit(&wq->flags, memory_order_relaxed) &
		    WQ_DEINIT) {
			LL_UNLINK_WAIT(net2_workq_runq, &wqev->runq, wq);
			int_refcnt = atomic_fetch_sub_explicit(&wq->int_refcnt,
			    1, memory_order_relaxed);
			assert(int_refcnt > 0);
		} else
			break;
	}
	if (wq == NULL)
		return NULL;

	if (LL_EMPTY(net2_workq_job_runq, &wq->runqueue)) {
wait_only:
		LL_UNLINK_WAIT(net2_workq_runq, &wqev->runq, wq);
	} else {
		wqfl = atomic_fetch_or_explicit(&wq->flags, WQ_QMANIP,
		    memory_order_acquire);
		if (wqfl & WQ_QMANIP)
			goto wait_only;
		if (wqfl & WQ_DEINIT) {
			atomic_fetch_and_explicit(&wq->flags, ~WQ_QMANIP,
			    memory_order_release);
			goto wait_only;
		}

		atomic_fetch_add_explicit(&wq->int_refcnt, 1,
		    memory_order_relaxed);
		LL_UNLINK_WAIT_INSERT_TAIL(net2_workq_runq,
		    &wqev->runq, wq);

		wqfl = atomic_fetch_and_explicit(&wq->flags, ~WQ_QMANIP,
		    memory_order_release);
		assert(wqfl & WQ_QMANIP);

		/*
		 * Release wq, since UNLINK_WAIT_INSERT_TAIL does not release
		 * the last reference.
		 */
		LL_RELEASE(net2_workq_runq,
		    &wqev->runq, wq);

		/* Activate an additional worker to pick up this workq. */
		activate_worker(wqev);
	}
	return wq;
}
/* Put workq on the runqueue at the tail position. */
static void
__hot__
wq_onqueue_tail(struct net2_workq *wq)
{
	struct net2_workq_evbase*wqev = wq->wqev;
	int			 wqfl, pb_succes = 0;
	unsigned int		 int_refcnt;

	/*
	 * Increment internal reference counter, to signify the workq
	 * is referenced by the runq.
	 */
	int_refcnt = atomic_fetch_add_explicit(&wq->int_refcnt, 1,
	    memory_order_relaxed);
	assert(int_refcnt > 0);

	/* Lock workq queue reference. */
	LL_REF(net2_workq_runq, &wqev->runq, wq);

	/* Mark queue as undergoing queue manipulation. */
	wqfl = atomic_fetch_or_explicit(&wq->flags, WQ_QMANIP,
	    memory_order_acquire);
	if (predict_true((wqfl & (WQ_QMANIP | WQ_DEINIT)) == 0))
		pb_succes = LL_PUSH_BACK(net2_workq_runq, &wqev->runq, wq);
	if (predict_true((wqfl & WQ_QMANIP) == 0)) {
		wqfl = atomic_fetch_and_explicit(&wq->flags, ~WQ_QMANIP,
		    memory_order_release);
		assert(wqfl & WQ_QMANIP);
	}

	/*
	 * Undo internal reference counter incrementation
	 * if we didn't insert the workq.
	 */
	if (!pb_succes) {
		int_refcnt = atomic_fetch_sub_explicit(&wq->int_refcnt, 1,
		    memory_order_relaxed);
		assert(int_refcnt > 1);
	}

	/* Unlock workq queue reference. */
	LL_RELEASE(net2_workq_runq, &wqev->runq, wq);

	/* If succesful, activate a worker to pick up the workq. */
	if (predict_true(pb_succes))
		activate_worker(wqev);
}
/*
 * Put workq on the runqueue at the head position.
 *
 * Called by code that may trigger a workq removal
 * without actually causing it to be run.
 */
static void
wq_onqueue_head(struct net2_workq *wq)
{
	struct net2_workq_evbase*wqev = wq->wqev;
	int			 wqfl, pb_succes = 0;
	unsigned int		 int_refcnt;

	/*
	 * Increment internal reference counter, to signify the workq
	 * is referenced by the runq.
	 */
	int_refcnt = atomic_fetch_add_explicit(&wq->int_refcnt, 1,
	    memory_order_relaxed);
	assert(int_refcnt > 0);

	/* Lock workq queue reference. */
	LL_REF(net2_workq_runq, &wqev->runq, wq);

	/* Mark queue as undergoing queue manipulation. */
	wqfl = atomic_fetch_or_explicit(&wq->flags, WQ_QMANIP,
	    memory_order_acquire);
	if (predict_true((wqfl & (WQ_QMANIP | WQ_DEINIT)) == 0))
		pb_succes = LL_PUSH_FRONT(net2_workq_runq, &wqev->runq, wq);
	if (predict_true((wqfl & WQ_QMANIP) == 0)) {
		wqfl = atomic_fetch_and_explicit(&wq->flags, ~WQ_QMANIP,
		    memory_order_release);
		assert(wqfl & WQ_QMANIP);
	}

	/*
	 * Undo internal reference counter incrementation
	 * if we didn't insert the workq.
	 */
	if (!pb_succes) {
		int_refcnt = atomic_fetch_sub_explicit(&wq->int_refcnt, 1,
		    memory_order_relaxed);
		assert(int_refcnt > 1);
	}

	/* Unlock workq queue reference. */
	LL_RELEASE(net2_workq_runq, &wqev->runq, wq);

	/* If succesful, activate a worker to pick up the workq. */
	if (predict_true(pb_succes))
		activate_worker(wqev);
}


/* Take the job off its runqueues. */
static int
job_offqueue(struct net2_workq_job_int *job)
{
	struct net2_workq	*wq = job->wq;
	int			 parallel, rv, rv_p;
	unsigned int		 refcnt;

	parallel = (atomic_load_explicit(&job->flags, memory_order_relaxed) &
	    NET2_WORKQ_PARALLEL);

	/* Refer to the job. */
	LL_REF(net2_workq_job_runq, &wq->runqueue, job);
	rv = (LL_UNLINK(net2_workq_job_runq, &wq->runqueue, job) != NULL);
	if (rv) {
		refcnt = atomic_fetch_sub_explicit(&job->refcnt, 1,
		    memory_order_relaxed);
		assert(refcnt > 1);
	} else
		LL_RELEASE(net2_workq_job_runq, &wq->runqueue, job);

	if (!parallel)
		return rv;

	LL_REF(net2_workq_job_prunq, &wq->prunqueue, job);
	rv_p = (LL_UNLINK(net2_workq_job_prunq, &wq->prunqueue, job) != NULL);
	if (rv_p) {
		refcnt = atomic_fetch_sub_explicit(&job->refcnt, 1,
		    memory_order_relaxed);
		assert(refcnt > 1);
	} else
		LL_RELEASE(net2_workq_job_prunq, &wq->prunqueue, job);

	return rv;
}
/* Take a job from the runq and acquire an internal reference. */
struct net2_workq_job_int*
__hot__
job_pop(struct net2_workq *wq)
{
	struct net2_workq_job_int *job;
	unsigned int		 refcnt;

	while ((job = LL_POP_FRONT(net2_workq_job_runq, &wq->runqueue)) !=
	    NULL) {
		if (atomic_load_explicit(&job->flags, memory_order_relaxed) &
		    JOB_DEINIT) {
			refcnt = atomic_fetch_sub_explicit(
			    &job->refcnt, 1, memory_order_relaxed);
			assert(refcnt > 0);
		} else
			break;
	}

	if (job != NULL && (atomic_load_explicit(&job->flags,
	    memory_order_relaxed) & NET2_WORKQ_PARALLEL)) {
		LL_REF(net2_workq_job_prunq, &wq->prunqueue, job);
		if (LL_UNLINK(net2_workq_job_prunq, &wq->prunqueue, job) !=
		    NULL) {
			refcnt = atomic_fetch_sub_explicit(
			    &job->refcnt, 1, memory_order_relaxed);
			assert(refcnt > 0);
		} else
			LL_RELEASE(net2_workq_job_prunq, &wq->prunqueue, job);
	}

	return job;
}
/* Take a job from the parallel runq and acquire an internal reference. */
struct net2_workq_job_int*
__hot__
job_parallel_pop(struct net2_workq *wq)
{
	struct net2_workq_job_int *job;
	unsigned int		 refcnt;

	while ((job = LL_POP_FRONT(net2_workq_job_prunq, &wq->prunqueue)) !=
	    NULL) {
		if (atomic_load_explicit(&job->flags, memory_order_relaxed) &
		    JOB_DEINIT) {
			refcnt = atomic_fetch_sub_explicit(
			    &job->refcnt, 1, memory_order_relaxed);
			assert(refcnt > 0);
		} else
			break;
	}

	if (job != NULL) {
		LL_REF(net2_workq_job_runq, &wq->runqueue, job);
		if (LL_UNLINK(net2_workq_job_runq, &wq->runqueue, job) !=
		    NULL) {
			refcnt = atomic_fetch_sub_explicit(
			    &job->refcnt, 1, memory_order_relaxed);
			assert(refcnt > 0);
		} else
			LL_RELEASE(net2_workq_job_runq, &wq->runqueue, job);
	}

	return job;
}
/* Put a job on its runqueue.  Also enables the workq. */
static void
__hot__
job_onqueue(struct net2_workq_job_int *job)
{
	unsigned int		 refcnt;
	struct net2_workq	*wq = job->wq;
	int			 parallel;
	int			 activate = 0;
	int			 fl;

	LL_REF(net2_workq_job_runq, &wq->runqueue, job);
	fl = atomic_fetch_or_explicit(&job->flags, JOB_QMANIP,
	    memory_order_acquire);
	if (fl & JOB_QMANIP)
		goto out_no_manip;
	if (fl & JOB_DEINIT)
		goto out;

	parallel = (fl & NET2_WORKQ_PARALLEL);
	refcnt = atomic_fetch_add_explicit(&job->refcnt,
	    (parallel ? 2 : 1), memory_order_relaxed);
	assert(refcnt > 0);

	if (!LL_PUSH_BACK(net2_workq_job_runq, &wq->runqueue, job)) {
		refcnt = atomic_fetch_sub_explicit(&job->refcnt, 1,
		    memory_order_relaxed);
		assert(refcnt > 1);
	} else
		activate = 1;

	if (parallel &&
	    !LL_PUSH_BACK(net2_workq_job_prunq, &wq->prunqueue, job)) {
		refcnt = atomic_fetch_sub_explicit(&job->refcnt, 1,
		    memory_order_relaxed);
		assert(refcnt > 1);
	} else if (parallel)
		activate = 1;

out:
	fl = atomic_fetch_and_explicit(&job->flags, ~JOB_QMANIP,
	    memory_order_release);
	assert(fl & JOB_QMANIP);
out_no_manip:
	LL_RELEASE(net2_workq_job_runq, &wq->runqueue, job);
	if (activate)
		wq_onqueue_tail(wq);
}


/* Test if the workq is active in the current thread. */
static __inline int
workq_self(struct net2_workq *wq)
{
	if (wq == NULL)
		return 0;
	return (wq == wq_tls_state.active_wq.wq);
}
/* Test if the job is active in the current thread. */
static __inline int
jobint_self(struct net2_workq_job_int *job)
{
	if (job == NULL)
		return 0;
	return (job == wq_tls_state.active_job);
}
/* Test if the job (external view) is active in the current thread. */
static __inline int
job_self(struct net2_workq_job *job)
{
	struct net2_workq_job_int *jobint;
	int	 is_self = 0;

	if (atomic_load_explicit(&job->internal, memory_order_relaxed) == NULL)
		return 0;

	atomic_fetch_add_explicit(&job->refcnt, 1, memory_order_relaxed);
	jobint = atomic_load_explicit(&job->internal, memory_order_relaxed);
	if (jobint != NULL)
		is_self = jobint_self(jobint);
	atomic_fetch_sub_explicit(&job->refcnt, 1, memory_order_relaxed);
	return is_self;
}

/*
 * Acquire reference counter on workq.
 *
 * Only succeeds with non-zero reference count.
 */
static __inline void
workq_ref(struct net2_workq *wq)
{
	unsigned int refcnt;

	refcnt = atomic_fetch_add_explicit(&wq->int_refcnt, 1,
	    memory_order_relaxed);
	assert(refcnt > 0);
}
/*
 * Release reference to a workq.
 *
 * Returns true if the last reference went away.
 */
static __inline void
workq_release(struct net2_workq *wq, int fall_to_zero)
{
	unsigned int refcnt;

	assert(wq != NULL);

	/* Normal code path: workq internal reference will not fall to zero. */
	if (predict_true(!fall_to_zero ||
	    !(atomic_load_explicit(&wq->flags, memory_order_relaxed) &
	      WQ_DEINIT)) ||
	    workq_self(wq)) {
		refcnt = atomic_fetch_sub_explicit(&wq->int_refcnt, 1,
		    memory_order_relaxed);
		assert(refcnt > 1);
		return;
	}

	/* Check workq state. */
	assert(atomic_load_explicit(&wq->flags, memory_order_relaxed) &
	    WQ_DEINIT);
	assert(atomic_load_explicit(&wq->refcnt, memory_order_relaxed) == 0);
	assert(wq_tls_state.active_wq.wq != wq);

	/*
	 * Take workq off the runqueue.
	 * Before removing the workq, wait until the most recent insert
	 * stabilizes (WQ_QMANIP is cleared).
	 */
	while (atomic_load_explicit(&wq->flags, memory_order_acquire) &
	    WQ_QMANIP)
		SPINWAIT();
	wq_offqueue(wq);

	/*
	 * Wait until the reference count drops to 1 (i.e. we hold the last
	 * reference).
	 */
	refcnt = 1;
	while (!atomic_compare_exchange_weak_explicit(&wq->int_refcnt,
	    &refcnt, 0, memory_order_relaxed, memory_order_relaxed)) {
		refcnt = 1;
		SPINWAIT();
	}
	/*
	 * After releasing the last reference, kill the workq.
	 */
	kill_wq(wq);
}
/* Only called with non-zero reference count. */
static __inline void
job_ref(struct net2_workq_job_int *job)
{
	size_t refcnt;

	refcnt = atomic_fetch_add_explicit(&job->refcnt, 1,
	    memory_order_acquire);
	assert(refcnt != 0);
}
/*
 * Release reference to a job.
 *
 * Returns true if the last reference went away.
 */
static __inline void
job_release(struct net2_workq_job_int *job)
{
	size_t			 refcnt;
	struct net2_workq	*wq;

	refcnt = atomic_fetch_sub_explicit(&job->refcnt, 1,
	    memory_order_release);
	assert(refcnt >= 1);
	if (predict_false(refcnt == 1)) {
		assert(atomic_load_explicit(&job->flags,
		    memory_order_relaxed) & JOB_DEINIT);

		wq = job->wq;
		net2_free(job);
		net2_workq_release(wq);
	}
}

/*
 * Change the active workq.
 * Returns the previous active workq.
 *
 * Note that the reference to wq is used to activate the workq
 * (i.e. the reference to wq is stolen).
 * The returned workq is referenced (since its reference from wq_tls_state
 * is stolen for the return value).
 * q is freed in the process.
 */
static __inline void
wq_surf(struct net2_workq *wq, int parallel, struct wq_act *orig,
    struct wthrq *q)
{
	struct wq_act	 wq_prev;
	unsigned int prun;

	/* Argument validation. */
	assert(wq == NULL || parallel ||
	    (atomic_load_explicit(&wq->flags, memory_order_relaxed) &
	     WQ_RUNNING));
	assert(wq == NULL || !parallel ||
	    (atomic_load_explicit(&wq->prun, memory_order_relaxed) > 0));
	assert(wq == NULL || wq != wq_tls_state.active_wq.wq);
	assert(wq == NULL ||
	    atomic_load_explicit(&wq->refcnt, memory_order_relaxed) > 0);
	assert(wq == NULL ||
	    atomic_load_explicit(&wq->int_refcnt, memory_order_relaxed) > 1);
	/* wq and q must either both be set or both be clear. */
	assert((wq == NULL && q == NULL) || (wq != NULL && q != NULL));

	/* Store previous state. */
	wq_prev = wq_tls_state.active_wq;

	/* Previous workq validation. */
	assert(wq_prev.wq == NULL || wq_prev.parallel ||
	    (atomic_load_explicit(&wq_prev.wq->flags,
	     memory_order_relaxed) & WQ_RUNNING));
	assert(wq_prev.wq == NULL || !wq_prev.parallel ||
	    (atomic_load_explicit(&wq_prev.wq->prun,
	     memory_order_relaxed) > 0));
	assert(wq_prev.wq == NULL ||
	    (atomic_load_explicit(&wq_prev.wq->int_refcnt,
	     memory_order_relaxed) > 0));
	assert(wq_prev.wq == NULL ||
	    wthrq_present(wq_prev.wq));

	if (orig != NULL)
		*orig = wq_prev;
	else if (wq_prev.wq != NULL) {
		if (!wq_prev.parallel)
			workq_clear_run(wq_prev.wq);
		else {
			prun = atomic_fetch_sub_explicit(&wq_prev.wq->prun, 1,
			    memory_order_release);
			assert(prun > 0);
		}
		workq_release(wq_prev.wq, 1);

		/* Remove old workq from activity stack. */
		wthrq_unassign(wq_prev.wq);
	}

	/*
	 * Store new state.
	 * This is done after releasing the previous state,
	 * so workq_release can test workq_self.
	 */
	wq_tls_state.active_wq.wq = wq;
	wq_tls_state.active_wq.parallel = parallel;

	/* Assign workq to activity stack. */
	if (wq != NULL)
		wthrq_assign(q, wq);
}
/*
 * Restore the active workq.
 * orig must be previously initialized by wq_surf.
 */
static __inline void
wq_surf_pop(struct wq_act *orig)
{
	struct wq_act	wq_prev;
	unsigned int	prun;

	assert(orig != NULL);
	assert(orig->wq == NULL || wthrq_present(orig->wq));

	/* Load old state. */
	wq_prev = wq_tls_state.active_wq;
	assert(wq_prev.wq == NULL || wthrq_present(wq_prev.wq));
	if (wq_prev.wq != NULL) {
		/* Clear running state. */
		if (!wq_prev.parallel)
			workq_clear_run(wq_prev.wq);
		else {
			prun = atomic_fetch_sub_explicit(&wq_prev.wq->prun, 1,
			    memory_order_release);
			assert(prun > 0);
		}
		/* Release workq. */
		workq_release(wq_prev.wq, 1);
		wthrq_unassign(wq_prev.wq);
	}

	/* Assign popped state. */
	wq_tls_state.active_wq = *orig;
}
/*
 * Change the active job.
 * Returns the previous active job.
 *
 * Note that the reference to job is used to activate the job
 * (i.e. the reference to job is stolen).
 * The returned job is referenced (since its reference from wq_tls_state
 * is stolen for the return value).
 *
 * Job must be marked runnable (since any job on wq_tls_state must be running).
 */
static __inline void
job_surf(struct net2_workq_job_int *job, struct net2_workq_job_int **orig)
{
	struct net2_workq_job_int *job_prev;

	assert(job == NULL ||
	    (atomic_load_explicit(&job->flags, memory_order_relaxed) &
	    JOB_RUNNING));
	assert(job == NULL || job != wq_tls_state.active_job);
	assert(job == NULL ||
	    atomic_load_explicit(&job->refcnt, memory_order_relaxed) > 0);

	job_prev = wq_tls_state.active_job;
	wq_tls_state.active_job = job;

	assert(job_prev == NULL ||
	    (atomic_load_explicit(&job_prev->flags, memory_order_relaxed) &
	    JOB_RUNNING));
	assert(job_prev == NULL ||
	    atomic_load_explicit(&job_prev->refcnt, memory_order_relaxed) > 0);

	if (orig != NULL)
		*orig = job_prev;
	else if (job_prev != NULL) {
		job_clear_run(job_prev);
		job_release(job_prev);
	}
}

/*
 * Job runq invariants:
 * - LL_UNLINK(net2_workq_runq,..., job)  =>  (job->flags & ONQUEUE)
 * - LL_UNLINK(net2_workq_prunq,..., job)  =>  (job->flags & ONPQUEUE)
 * - (job->flags & ONPQUEUE)  =>  (job->flags & PARALLEL)
 * - LL_UNLINK(net2_workq_runq,..., job)  =>  !(job_flags & RUNNING)
 */

/* Pop a job from the normal runq. */
static struct net2_workq_job_int*
__hot__
wqev_run_pop_job(struct net2_workq *wq)
{
	struct net2_workq_job_int	*job;
	int				 fl;

restart:
	assert(atomic_load_explicit(&wq->flags, memory_order_relaxed) &
	    WQ_RUNNING);

	if ((job = job_pop(wq)) == NULL)
		return NULL;

	/* Mark job as running,
	 * to prevent it from reappearing on the runqueues. */
	fl = atomic_fetch_or_explicit(&job->flags, JOB_RUNNING,
	    memory_order_acquire);
	/*
	 * Did we win the race?
	 */
	if (fl & JOB_RUNNING) {
		job_release(job);
		goto restart;
	}

	/*
	 * If the job is being deinitialized, we may not run it.
	 * Cancel running the job and restart this call.
	 */
	if (fl & JOB_DEINIT) {
		atomic_fetch_and_explicit(&job->flags, ~JOB_RUNNING,
		    memory_order_release);
		job_release(job);
		goto restart;
	}
	assert(!(fl & (JOB_RUNNING | JOB_DEINIT)));

	/*
	 * If the job isn't active, clear the run bit and drop the job.
	 * This is a cas operation, since we want to prevent another thread
	 * from marking the job as active, but failing to update the runqs
	 * due to our RUNNING bit.
	 *
	 * Note that in the initial step of the loop, the JOB_ACTIVE bit
	 * will be set if it was set earlier in this function, in which
	 * case we simply run the job, pretending the deactivation happened
	 * after the invocation started.  If the job becomes active while
	 * we're still trying to clear the RUNNING bit, we change to running
	 * the job after all.
	 */
	while (!(fl & JOB_ACTIVE)) {
		if (atomic_compare_exchange_weak_explicit(&job->flags,
		    &fl, fl & ~JOB_RUNNING,
		    memory_order_release, memory_order_relaxed)) {
			job_release(job);
			goto restart;
		}
		SPINWAIT();
	}

	/*
	 * If the job is not persistent, clear the active bit.
	 */
	if (!(fl & NET2_WORKQ_PERSIST)) {
		fl = atomic_fetch_and_explicit(&job->flags, ~JOB_ACTIVE,
		    memory_order_relaxed);
	}

	/*
	 * job:
	 * - not NULL
	 * - JOB_RUNNING is set
	 * - not on RUNQ
	 * - if on PQUEUE, another thread will detect the running state
	 *   and remove it
	 * - may be a parallel job
	 */
	return job;
}
/* Pop a job from the parallel runq. */
static struct net2_workq_job_int*
__hot__
wqev_prun_pop_job(struct net2_workq *wq)
{
	struct net2_workq_job_int	*job;
	int				 fl;

restart:
	if ((job = job_parallel_pop(wq)) == NULL)
		return NULL;
	fl = atomic_load_explicit(&job->flags, memory_order_relaxed);

	/* Mark job as running,
	 * to prevent it from reappearing on the runqueues. */
	fl = atomic_fetch_or_explicit(&job->flags, JOB_RUNNING,
	    memory_order_acquire);
	/*
	 * Did we win the race?
	 */
	if (fl & JOB_RUNNING) {
		job_release(job);
		goto restart;
	}

	/*
	 * If the job is being deinitialized, we may not run it.
	 * Cancel running the job and restart this call.
	 */
	if (fl & JOB_DEINIT) {
		atomic_fetch_and_explicit(&job->flags, ~JOB_RUNNING,
		    memory_order_release);
		job_release(job);
		goto restart;
	}

	/*
	 * If the job isn't active, clear the run bit and drop the job.
	 * This is a cas operation, since we want to prevent another thread
	 * from marking the job as active, but failing to update the runqs
	 * due to our RUNNING bit.
	 *
	 * Note that in the initial step of the loop, the JOB_ACTIVE bit
	 * will be set if it was set earlier in this function, in which
	 * case we simply run the job, pretending the deactivation happened
	 * after the invocation started.  If the job becomes active while
	 * we're still trying to clear the RUNNING bit, we change to running
	 * the job after all.
	 */
	while (!(fl & JOB_ACTIVE)) {
		if (atomic_compare_exchange_weak_explicit(&job->flags,
		    &fl, fl & ~JOB_RUNNING,
		    memory_order_relaxed, memory_order_relaxed)) {
			job_release(job);
			goto restart;
		}
		SPINWAIT();
	}

	/*
	 * If the job is not persistent, clear the active bit.
	 */
	if (!(fl & NET2_WORKQ_PERSIST)) {
		fl = atomic_fetch_and_explicit(&job->flags, ~JOB_ACTIVE,
		    memory_order_relaxed);
	}

	/*
	 * job:
	 * - not NULL
	 * - JOB_RUNNING is set
	 * - not on RUNQ
	 * - not on PQUEUE
	 * - is parallel job
	 */
	return job;
}

/*
 * Acquire a job from the given workq.
 * The workq will be pushed onto the wqev runq on succes.
 *
 * Attempts to mark the workq runnable.
 *
 * Returns EAGAIN if no runnable job is found.
 */
static int
__hot__
wqev_run_pop_wq(struct net2_workq_evbase *wqev,
    struct net2_workq *wq, struct net2_workq_job_int **job_out)
{
	struct net2_workq_job_int	*job;
	int				 fl;

	assert(job_out != NULL);
	assert(wqev == wq->wqev);

	/* Set running bit. */
	fl = atomic_fetch_or_explicit(&wq->flags, WQ_RUNNING,
	    memory_order_acquire);

	/* If the workq is wanted, cancel the run_pop operation. */
	if (predict_false((fl & WQ_WANTLOCK) ||
	    atomic_load_explicit(&wq->want_queued, memory_order_relaxed)))
		goto fail_eagain;

	/* Select a job, dependant on the state of the WQ_RUNNING bit. */
	if (fl & WQ_RUNNING) {
		/*
		 * Workq is already running normal jobs.
		 * Try one of the parallel jobs.
		 *
		 * We have to increment prun, but make sure we don't
		 * start a job while WANTLOCK is engaged; hence the
		 * optimistic increment, test and conditional decrement.
		 */
		atomic_fetch_add_explicit(&wq->prun, 1, memory_order_acquire);
		if (atomic_load_explicit(&wq->flags, memory_order_relaxed) &
		    WQ_WANTLOCK)
			job = NULL;
		else
			job = wqev_prun_pop_job(wq);
		if (job == NULL) {
			atomic_fetch_sub_explicit(&wq->prun, 1,
			    memory_order_release);
		} else {
			/* Sanity check. */
			assert(atomic_load_explicit(&job->flags,
			    memory_order_relaxed) & NET2_WORKQ_PARALLEL);
		}
	} else {
		/* We hold the main run marker.
		 * Fetch any job. */
		job = wqev_run_pop_job(wq);
		/* If we fetched a parallel job, clear the RUNNING bit
		 * on the workq. */
		if (job != NULL && (atomic_load_explicit(&job->flags,
		    memory_order_relaxed) & NET2_WORKQ_PARALLEL)) {
			atomic_fetch_add_explicit(&wq->prun, 1, memory_order_acquire);
			atomic_fetch_and_explicit(&wq->flags, ~WQ_RUNNING,
			    memory_order_release);
		}
	}

	/*
	 * Push workq back on its queue.
	 * We only push it back on the runq, if we found a runnable job.
	 * If we found no runnable job, the workq is no longer runnable.
	 */
	if (predict_false(job == NULL))
		goto fail_eagain;
	else
		wq_onqueue_tail(wq);

	*job_out = job;
	return 0;

fail_eagain:
	if (!(fl & WQ_RUNNING)) {
		atomic_fetch_and_explicit(&wq->flags, ~WQ_RUNNING,
		    memory_order_release);
	}
	*job_out = NULL;
	return EAGAIN;
}
/*
 * Acquire a wq from the wqev->runq.
 * If the workq has something that is runnable, the workq will be left on
 * the queue, otherwise it will be dequeued.
 *
 * Returns EAGAIN if no runnable job is found.
 */
static int
__hot__
wqev_run_pop(struct net2_workq_evbase *wqev,
    struct net2_workq **wq_out, struct net2_workq_job_int **job_out)
{
	struct net2_workq	*wq;
	struct net2_workq_job_int *job;
	int			 error;

restart:
	if ((wq = wq_pop(wqev)) == NULL)
		return EAGAIN;

	/* Try to load a job from this workq. */
	if ((error = wqev_run_pop_wq(wqev, wq, &job)) != 0) {
		if (error == EAGAIN) {
			workq_release(wq, 0);
			goto restart;
		}
		wq_onqueue_tail(wq);
		return error;
	}

	/*
	 * We now have a workq and a job, where the job is marked RUNNING
	 * and, if the job is not parallel, the workq is also marked
	 * RUNNING.
	 *
	 * Both have a reference count upgrade of 1.
	 */
	assert(wq != NULL && job != NULL);
	*wq_out = wq;
	*job_out = job;
	return 0;
}
/*
 * Run the given job.
 *
 * Pushes the active_job, active_wq onto the tls of workq, popping
 * the original values afterwards.  Consumes the reference on workq
 * and job.
 *
 * The job has its RUNNING bit cleared after the run completes.
 */
static void
__hot__
run_job(struct net2_workq *wq, struct net2_workq_job_int *job,
    struct wthrq *q)
{
	struct wq_act			 prev_wq;
	struct net2_workq_job_int	*prev_job;
	int				 parallel;

	assert(wq != NULL && job != NULL);
	assert(job->wq == wq);
	assert(job->fn != NULL);
	assert(q != NULL && q->wq == NULL);

	parallel = (atomic_load_explicit(&job->flags, memory_order_relaxed) &
	    NET2_WORKQ_PARALLEL);

	assert(atomic_load_explicit(&job->flags, memory_order_relaxed) &
	    JOB_RUNNING);
	assert(parallel ||
	    (atomic_load_explicit(&wq->flags, memory_order_relaxed) &
	    WQ_RUNNING));
	assert(!parallel ||
	    atomic_load_explicit(&wq->prun, memory_order_relaxed) > 0);

	/* Update tls wthr. */
	wq_surf(wq, parallel, &prev_wq, q);
	job_surf(job, &prev_job);

	/* Mark this thread as running the job. */
	assert(job->self == NULL);
	job->self = &wq_tls_state;

	/* Invoke actual function. */
	job->fn(job->cb_arg[0], job->cb_arg[1]);

	/* Clear the marker for the self thread. */
	assert(job->self == &wq_tls_state);
	job->self = NULL;

	/* Pop old values of active {wq,job}. */
	job_surf(prev_job, NULL);
	wq_surf_pop(&prev_wq);
}
/*
 * Run a job on wqev.
 *
 * Returns EAGAIN if it was unable to run a job.
 */
static int
__hot__
wqev_run1(struct net2_workq_evbase *wqev, struct wthrq *q)
{
	struct net2_workq	*wq;
	struct net2_workq_job_int *job;
	int			 error;

	assert(q != NULL && q->wq == NULL);

	wq = NULL;
	job = NULL;

	if ((error = wqev_run_pop(wqev, &wq, &job)) != 0)
		return error;
	run_job(wq, job, q);
	return 0;
}
/*
 * Clear the run bit on a job.
 */
static void
__hot__
job_clear_run(struct net2_workq_job_int *job)
{
	int			 fl;

	/* Clear running bit, increment run generation counter. */
	fl = atomic_fetch_and_explicit(&job->flags, ~JOB_RUNNING,
	    memory_order_release);
	assert(fl & JOB_RUNNING);
	atomic_fetch_add_explicit(&job->run_gen, 1, memory_order_release);
	if (predict_false(fl & JOB_DEINIT))
		return;

	/* Add the job to the queues. */
	if (fl & JOB_ACTIVE)
		job_onqueue(job);
}
/*
 * Clear the run bit on a workq.
 *
 * If the workq has runnable jobs, the workq is placed on the runqueue.
 * Note that this function may place the workq on the runqueue if it is
 * empty though (it's not illegal, it's simply more efficient not to).
 */
static void
__hot__
workq_clear_run(struct net2_workq *wq)
{
	int			 fl;

	/* Clear running bit. */
	fl = atomic_fetch_and_explicit(&wq->flags, ~WQ_RUNNING,
	    memory_order_release);
	assert(fl & WQ_RUNNING);

	/* If the workq has jobs, place it on the wqev runq. */
	if (!LL_EMPTY(net2_workq_job_runq, &wq->runqueue))
		wq_onqueue_tail(wq);
}
/*
 * Wait until job is no longer running.
 *
 * Internals:
 * the running state only changes when the job transitions
 * from RUNNING to not-RUNNING.  By loading the generation counter
 * and monitoring it, the end of the current run-cycle can be detected.
 * Testing the RUNNING flag after acquiring the generation counter prevents
 * waiting on a non-running job.
 */
static void
job_wait_run(struct net2_workq_job_int *job)
{
	unsigned int	gen;

	/* Load generation counter. */
	gen = atomic_load_explicit(&job->run_gen, memory_order_relaxed);

	/* Test if the job is currently running. */
	if (!(atomic_load_explicit(&job->flags, memory_order_relaxed) &
	    JOB_RUNNING))
		return;

	/* Job is being destroyed from within.  Don't wait up. */
	if (job->self == &wq_tls_state)
		return;

	/* Wait until the generation counter changes. */
	while (atomic_load_explicit(&job->run_gen, memory_order_consume) ==
	    gen)
		SPINWAIT();
}

/*
 * Mark worker thread as idle.
 * Immediately activates a worker if the runq is not empty.
 */
static __inline void
wqev_thridle(struct net2_workq_evbase *wqev)
{
	atomic_fetch_add_explicit(&wqev->thr_idle, 1, memory_order_relaxed);

	/* Handle missed wakeups between wqev_run1 and sem-up. */
	if (!LL_EMPTY(net2_workq_runq, &wqev->runq))
		activate_worker(wqev);
}
/* Worker thread function. */
static void*
__hot__
wqev_worker(void *wthr_ptr)
{
	struct net2_workq_evbase_worker *wthr = wthr_ptr;
	struct net2_workq_evbase *wqev;
	int			 count;
	static const int	 COUNT = 8;
	struct wthrq		*q;

	wq_tls_state.wthr = wthr;
	wqev = wthr->evbase;

	for (;;) {
		net2_semaphore_down(&wqev->thr_active);
		if (predict_false(decrement_idle(&wqev->thr_die)))
			goto thrdie;		/* GUARD */

		q = wthrq_alloc();
		assert(q != NULL);

		count = COUNT;
		while (wqev_run1(wqev, q) == 0) {
			if (predict_false(decrement_idle(&wqev->thr_die)))
				goto thrdie;	/* GUARD */
			if (--count == 0) {
#ifndef WIN32
				run_evl(wqev, RUNEVL_NOWAIT);
#endif
				count = COUNT;
			}

			q = wthrq_alloc();
			assert(q != NULL);
		}
		/* Release q when not consumed by wqev_run1. */
		wthrq_free(q);

#ifdef WIN32
		wqev_thridle(wqev);
#else
		run_evl(wqev, RUNEVL_THRIDLE);
#endif
	}

thrdie:
	net2_spinlock_lock(&wqev->spl_workers);
	wq_tls_state.wthr = NULL;
	TAILQ_REMOVE(&wqev->workers, wthr, tq);
	TAILQ_INSERT_TAIL(&wqev->dead_workers, wthr, tq);
	net2_semaphore_up(&wqev->thr_death, 1);
	net2_spinlock_unlock(&wqev->spl_workers);
	return wthr;
}

#ifndef WIN32
/*
 * Run event loop for libev based implementation.
 */
static void
run_evl(struct net2_workq_evbase *wqev, int flags)
{
	int		 evloop_flags, evl_running, zero;

	assert(!(flags & RUNEVL_NOWAIT) || !(flags & RUNEVL_THRIDLE));

	if (flags & RUNEVL_NOWAIT) {
		evloop_flags = EVRUN_NOWAIT;
		evl_running = EVL_NOWAIT;
	} else {
		evloop_flags = 0;
		evl_running = EVL_WAIT;
	}

	/* No need to run evloop if no evloop exists. */
	if (wqev->evloop == NULL) {
no_run:
		if (flags & RUNEVL_THRIDLE)
			wqev_thridle(wqev);
		return;
	}

	/* Mark as running evloop. */
	zero = 0;
	if (!atomic_compare_exchange_strong_explicit(&wqev->evl_running,
	    &zero, evl_running,
	    memory_order_acquire, memory_order_relaxed))
		goto no_run;

	/* Update idle counter. */
	if (flags & RUNEVL_THRIDLE) {
		atomic_fetch_add_explicit(&wqev->ev_idle, 1,
		    memory_order_relaxed);
	}

	/* Run event loop. */
	ev_run(wqev->evloop, evloop_flags);

	/* Release idle count, unless worker activation did so already. */
	if ((flags & RUNEVL_THRIDLE) && decrement_idle(&wqev->ev_idle))
		wqev_thridle(wqev);

	/* Release running-evloop flag. */
	atomic_store_explicit(&wqev->evl_running, 0, memory_order_release);
	return;
}
#endif /* WIN32 */

/* Put job on runq. */
static __inline void
job_activate(struct net2_workq_job_int *job)
{
	/* Set active bit. */
	atomic_fetch_or_explicit(&job->flags, JOB_ACTIVE,
	    memory_order_relaxed);

	/* Push on runqueue, parallel runqueue. */
	job_onqueue(job);
}
/* Deactivate job. */
static __inline void
job_deactivate(struct net2_workq_job_int *job, int wait_run)
{
	int			 fl;

	fl = atomic_fetch_and_explicit(&job->flags, ~JOB_ACTIVE,
	    memory_order_relaxed);
	if (wait_run && (fl & JOB_RUNNING))
		job_wait_run(job);
}

/* Acquire the workq want lock. */
static enum workq_want_state
workq_want_acquire(struct net2_workq *wq, int flags)
{
	int		 fl, queued_delta = 0;
	unsigned int	 refcnt;

	/* Argument check. */
	assert((flags & (NET2_WQ_WANT_TRY | NET2_WQ_WANT_RECURSE)) == flags);

	/* Test if locking would recurse the running bit. */
	if (workq_self(wq) && !(flags & NET2_WQ_WANT_RECURSE))
		return wq_want_running;

	/* If we already own the wq want-lock, recurse. */
	if (wq->want_owner == &wq_tls_state) {
		atomic_fetch_add_explicit(&wq->want_refcnt, 1, memory_order_relaxed);
		return wq_want_succes;
	}

	/* Lock, only modifying the want_queued counter
	 * if we are allowed to sleep. */
	if (flags & NET2_WQ_WANT_TRY) {
		if (!net2_mutex_trylock(wq->want_mtx))
			return wq_want_tryfail;
	} else {
		atomic_fetch_add_explicit(&wq->want_queued, 1,
		    memory_order_relaxed);
		net2_mutex_lock(wq->want_mtx);
		queued_delta = 1;
	}
	fl = atomic_fetch_or_explicit(&wq->flags, WQ_WANTLOCK,
	    memory_order_acquire);
	if (queued_delta != 0) {
		atomic_fetch_sub_explicit(&wq->want_queued, queued_delta,
		    memory_order_relaxed);
	}

	/*
	 * WQ_WANTLOCK is set,
	 * want_mtx is locked by us.
	 */

	/* If the workq is running, fail if try-flag is set. */
	if ((flags & NET2_WQ_WANT_TRY) &&
	    ((fl & WQ_RUNNING) ||
	     atomic_load_explicit(&wq->prun, memory_order_relaxed) > 0)) {
		atomic_fetch_and_explicit(&wq->flags, ~WQ_WANTLOCK,
		    memory_order_release);
		if (!LL_EMPTY(net2_workq_job_runq, &wq->runqueue))
			wq_onqueue_head(wq);
		net2_mutex_unlock(wq->want_mtx);
		return wq_want_tryfail;
	}
	/* Wait until the workq is not longer running. */
	while ((fl & WQ_RUNNING) ||
	    atomic_load_explicit(&wq->prun, memory_order_acquire) > 0) {
		SPINWAIT();
		fl = atomic_load_explicit(&wq->flags, memory_order_acquire);
	}

	/* Assign first reference. */
	refcnt = atomic_exchange_explicit(&wq->want_refcnt, 1,
	    memory_order_acquire);
	assert(refcnt == 0);

	/* Assign this as owner. */
	wq->want_owner = &wq_tls_state;

	/* Synchronize state between previous owners and current owner. */
	atomic_thread_fence(memory_order_seq_cst);

	return wq_want_succes;
}
/* Release want lock. */
static void
workq_want_release(struct net2_workq *wq)
{
	assert(wq->want_owner == &wq_tls_state);
	assert(atomic_load_explicit(&wq->want_refcnt,
	    memory_order_relaxed) > 0);

	if (atomic_fetch_sub_explicit(&wq->want_refcnt, 1,
	    memory_order_release) == 1) {
		wq->want_owner = NULL;
		atomic_fetch_and_explicit(&wq->flags, ~WQ_WANTLOCK,
		    memory_order_release);
		net2_mutex_unlock(wq->want_mtx);

		if (!LL_EMPTY(net2_workq_job_runq, &wq->runqueue))
			wq_onqueue_head(wq);
	}
}

/*
 * Kill the workq.
 *
 * Workq must have a reference count of zero.
 */
static void
__cold__
kill_wq(struct net2_workq *wq)
{
	struct net2_workq_evbase*wqev;

	/* Assert workq state. */
	assert(atomic_load_explicit(&wq->refcnt, memory_order_relaxed) == 0);
	assert(atomic_load_explicit(&wq->int_refcnt, memory_order_relaxed) == 0);
	assert(LL_EMPTY(net2_workq_job_runq, &wq->runqueue));
	assert(LL_EMPTY(net2_workq_job_prunq, &wq->prunqueue));
	assert(!(atomic_load_explicit(&wq->flags, memory_order_relaxed) &
	    (WQ_RUNNING | WQ_WANTLOCK)));
	assert(atomic_load_explicit(&wq->prun, memory_order_relaxed) == 0);
	assert(atomic_load_explicit(&wq->want_refcnt,
	    memory_order_relaxed) == 0);
	assert(atomic_load_explicit(&wq->flags, memory_order_relaxed) &
	    WQ_DEINIT);

	/* Remove workq from its runq. */
	wq_offqueue(wq);

	/* Wait for other threads to release reference to wq. */
	while (atomic_load_explicit(&wq->int_refcnt, memory_order_relaxed) > 1)
		SPINWAIT();

	/*
	 * wq is now only referenced by us.
	 * It is not on the runq.
	 * It has no associated jobs.
	 * It is not running.
	 */
	wqev = wq->wqev;
	net2_mutex_free(wq->want_mtx);
	net2_free(wq);

	net2_workq_evbase_release(wqev);
}

ILIAS_NET2_EXPORT struct net2_workq_evbase*
__cold__
net2_workq_evbase_new(const char *name, int jobthreads, int maxthreads)
{
	struct net2_workq_evbase*wqev;

	if (maxthreads < jobthreads)
		goto fail_0;

	if ((wqev = net2_malloc(sizeof(*wqev))) == NULL)
		goto fail_0;

	/*
	 * OS dependant initialization.
	 */
#ifdef WIN32
	if (net2_spinlock_init(&wqev->spl_io) != 0)
		goto fail_1;
	if (net2_spinlock_init(&wqev->spl_timer) != 0)
		goto fail_2;
	wqev->io = NULL;
	wqev->timer = NULL;
#else
	if (net2_spinlock_init(&wqev->spl_evloop) != 0)
		goto fail_3;
	atomic_init(&wqev->evl_running, 0);
	wqev->evloop = NULL;
	ev_async_init(&wqev->ev_wakeup, &evloop_wakeup);
	ev_async_init(&wqev->ev_newevent, &evloop_new_event);
#endif

	wqev->jobthreads = 0;
	wqev->maxthreads = 0;
	if (net2_semaphore_init(&wqev->thr_active) != 0)
		goto fail_4;
	if (net2_semaphore_init(&wqev->thr_death) != 0)
		goto fail_5;
	atomic_init(&wqev->thr_idle, 0);
	atomic_init(&wqev->thr_die, 0);
	LL_INIT(&wqev->runq);
	atomic_init(&wqev->refcnt, 1);

	if (name == NULL)
		wqev->wq_worker_name = NULL;
	else if ((wqev->wq_worker_name = net2_strdup(name)) == NULL)
		goto fail_6;

	if ((wqev->workers_mtx = net2_mutex_alloc()) == NULL)
		goto fail_7;
	if (net2_spinlock_init(&wqev->spl_workers) != 0)
		goto fail_8;
	TAILQ_INIT(&wqev->workers);
	TAILQ_INIT(&wqev->dead_workers);

	if (net2_workq_set_thread_count(wqev, jobthreads, maxthreads) != 0) {
		net2_workq_set_thread_count(wqev, 0, 0);
		goto fail_9;
	}

	return wqev;


fail_9:
	net2_spinlock_deinit(&wqev->spl_workers);
fail_8:
	net2_mutex_free(wqev->workers_mtx);
fail_7:
	if (wqev->wq_worker_name)
		net2_free(wqev->wq_worker_name);
fail_6:
	net2_semaphore_deinit(&wqev->thr_death);
fail_5:
	net2_semaphore_deinit(&wqev->thr_active);
fail_4:
#ifndef WIN32
	net2_spinlock_deinit(&wqev->spl_evloop);
#endif
fail_3:
#ifdef WIN32
	net2_spinlock_deinit(&wqev->spl_timer);
#endif
fail_2:
#ifdef WIN32
	net2_spinlock_deinit(&wqev->spl_io);
#endif
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
	if (predict_false(wqev == NULL))
		return;
	if (predict_true(atomic_fetch_sub_explicit(&wqev->refcnt, 1,
	    memory_order_release) != 1))
		return;

	/* Kill all worker threads. */
	net2_workq_set_thread_count(wqev, 0, 0);

	/* Kill event loop/iocp/timer. */
#ifdef WIN32
	if (wqev->timer != NULL)
		net2_workq_timer_container_destroy(wqev->timer);
	if (wqev->io != NULL)
		net2_workq_io_container_destroy(wqev->io);
#else
	if (wqev->evloop != NULL)
		ev_loop_destroy(wqev->evloop);
#endif


	net2_spinlock_deinit(&wqev->spl_workers);
	net2_mutex_free(wqev->workers_mtx);
	if (wqev->wq_worker_name)
		net2_free(wqev->wq_worker_name);
	net2_semaphore_deinit(&wqev->thr_death);
	net2_semaphore_deinit(&wqev->thr_active);
#ifndef WIN32
	net2_spinlock_deinit(&wqev->spl_evloop);
#else
	net2_spinlock_deinit(&wqev->spl_timer);
	net2_spinlock_deinit(&wqev->spl_io);
#endif
	net2_free(wqev);
}

#ifndef WIN32
/* Inform the workq that the set of events changed. */
ILIAS_NET2_LOCAL void
net2_workq_evbase_evloop_changed(struct net2_workq_evbase *wqev)
{
	assert(wqev->evloop != NULL);
	ev_async_send(wqev->evloop, &wqev->ev_newevent);
}
#endif /* !WIN32 */

/* Create a new workq. */
ILIAS_NET2_EXPORT struct net2_workq*
net2_workq_new(struct net2_workq_evbase *wqev)
{
	struct net2_workq	*wq;

	assert(wqev != NULL);

	if ((wq = net2_malloc(sizeof(*wq))) == NULL)
		goto fail_0;

	atomic_init(&wq->flags, 0);
	atomic_init(&wq->prun, 0);
	wq->wqev = wqev;
	LL_INIT(&wq->runqueue);
	LL_INIT(&wq->prunqueue);
	LL_INIT_ENTRY(&wq->wqev_runq);

	atomic_init(&wq->refcnt, 1);
	atomic_init(&wq->int_refcnt, 1);
	atomic_init(&wq->want_refcnt, 0);
	atomic_init(&wq->want_queued, 0);
	wq->want_owner = NULL;

	if ((wq->want_mtx = net2_mutex_alloc()) == NULL)
		goto fail_1;

	net2_workq_evbase_ref(wqev);
	return wq;


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
	unsigned int refcnt;

	refcnt = atomic_fetch_add_explicit(&wq->refcnt, 1,
	    memory_order_relaxed);
	assert(refcnt > 0);
}
/* Release reference to a workq. */
ILIAS_NET2_EXPORT void
net2_workq_release(struct net2_workq *wq)
{
	unsigned int	 refcnt;
	int		 fl;

	if (predict_false(wq == NULL))
		return;
	refcnt = atomic_fetch_sub_explicit(&wq->refcnt, 1,
	    memory_order_relaxed);
	assert(refcnt > 0);
	if (predict_false(refcnt == 1)) {
		fl = atomic_fetch_or_explicit(&wq->flags, WQ_DEINIT,
		    memory_order_acquire);
		assert(!(fl & WQ_DEINIT));
		workq_release(wq, 1);
	}
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
	struct net2_workq_job_int	*job;

	if (fn == NULL || wq == NULL || j == NULL)
		return EINVAL;
	if (flags & ~NET2_WORKQ_VALID_USERFLAGS)
		return EINVAL;

	if ((job = net2_malloc(sizeof(*job))) == NULL)
		return ENOMEM;

	job->fn = fn;
	job->cb_arg[0] = arg0;
	job->cb_arg[1] = arg1;
	job->wq = wq;
	atomic_init(&job->refcnt, 1);
	job->self = NULL;
	atomic_init(&job->flags, flags);
	atomic_init(&job->run_gen, 0);

	net2_workq_ref(wq);
	LL_INIT_ENTRY(&job->runq);
	LL_INIT_ENTRY(&job->prunq);

	/*
	 * Synchronize this job to all threads.
	 *
	 * Note that the job is in essence immutable, apart from the
	 * atomic state variables.
	 * Thus after construction and prior to destruction are the
	 * only moments we need to actively fence.
	 */
	atomic_thread_fence(memory_order_seq_cst);

	/* Publish result. */
	atomic_store_explicit(&j->refcnt, 0, memory_order_release);
	atomic_store_explicit(&j->internal, job, memory_order_release);

	return 0;
}
/* Deinit a job. */
ILIAS_NET2_EXPORT void
__hot__
net2_workq_deinit_work(struct net2_workq_job *j)
{
	struct net2_workq_job_int	*job;
	int				 fl;

	/*
	 * Take ownership of job from j.
	 */
	job = atomic_exchange_explicit(&j->internal, NULL,
	    memory_order_acquire);
	if (job == NULL)
		return;
	/* Wait for other threads that require job to stay valid. */
	while (atomic_load_explicit(&j->refcnt, memory_order_acquire) > 0)
		SPINWAIT();

	/*
	 * Mark job as deinitialized, take it from the queues and wait
	 * until it stops running.
	 */
	fl = atomic_fetch_or_explicit(&job->flags, JOB_DEINIT,
	    memory_order_acquire);
	assert(!(fl & JOB_DEINIT));
	while (fl & JOB_QMANIP) {
		SPINWAIT();
		fl = atomic_load_explicit(&job->flags, memory_order_acquire);
	}
	job_offqueue(job);

	/*
	 * Wait until the job stops running,
	 * note that the job cannot start running after it stops,
	 * because JOB_DEINIT it set.
	 */
	job_wait_run(job);

	/* Release job if it is being run by us. */
	if (job->self == &wq_tls_state) {
		job_release(job);
		return;
	}
	assert(!(atomic_load_explicit(&job->flags, memory_order_relaxed) &
	    JOB_RUNNING));

	/* Wait for our reference to be the last reference held. */
	while (atomic_load_explicit(&job->refcnt, memory_order_relaxed) > 1)
		SPINWAIT();

	job_release(job);
}

/*
 * Returns the workq that runs the specified job.
 * Returns NULL if the job is deinitialized or a null-job.
 *
 * The returned workq is referenced.
 */
ILIAS_NET2_EXPORT struct net2_workq*
net2_workq_get(struct net2_workq_job *j)
{
	struct net2_workq_job_int	*job;
	struct net2_workq		*wq = NULL;

	job = atomic_load_explicit(&j->internal, memory_order_acquire);
	if (predict_false(job == NULL))
		return NULL;
	atomic_fetch_add_explicit(&j->refcnt, 1, memory_order_acquire);
	job = atomic_load_explicit(&j->internal, memory_order_consume);
	if (predict_false(job != NULL)) {
		wq = job->wq;
		if (atomic_load_explicit(&wq->refcnt,
		    memory_order_relaxed) == 0)
			wq = NULL;
	}
	if (wq != NULL)
		net2_workq_ref(wq);
	atomic_fetch_sub_explicit(&j->refcnt, 1, memory_order_release);

	return wq;
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
 *
 * Flags:
 * NET2_WQ_WANT_TRY: fail instead of sleeping if the workq is busy.
 * NET2_WQ_WANT_RECURS: don't fail if the want lock is recursing the workq.
 */
ILIAS_NET2_EXPORT int
net2_workq_want(struct net2_workq *wq, int flags)
{
	assert(wq != NULL);

	switch (workq_want_acquire(wq, flags)) {
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
	assert(wq != NULL);

	workq_want_release(wq);
}
/* Check if the workq is running on this thread. */
ILIAS_NET2_EXPORT int
net2_workq_is_self(struct net2_workq *wq)
{
	return workq_self(wq);
}

/*
 * Switch wq as the active workq.
 * If parallel is true, the workq will be activated in parallel mode.
 * If orig is not null, it will be filled with the previous workq,
 * which must be reactivated afterwards using
 * net2_workq_surf(orig->wq, orig->parallel, NULL);
 *
 * Returns ENOMEM if the surf fails.
 *
 * Synchronizes with invocations of net2_workq_want().
 */
ILIAS_NET2_EXPORT int
net2_workq_surf(struct net2_workq *wq, int parallel)
{
	struct wthrq	*q = NULL;

	if (wq != NULL) {
		if ((q = wthrq_alloc()) == NULL)
			return ENOMEM;
		workq_ref(wq);
	}

	/* Deactivate old workq. */
	wq_surf(NULL, 0, NULL, NULL);
	if (wq == NULL)
		return 0;

	/*
	 * Lock out other want acquire.
	 *
	 * Once other net2_workq_want() cannot acquire this wq,
	 * set the right flags on the workq.
	 */
	net2_mutex_lock(wq->want_mtx);
	if (parallel)
		/* Parallel jobs can always run. */
		atomic_fetch_add_explicit(&wq->prun, 1, memory_order_acquire);
	else {
		/* Non-parallel surf needs to wait
		 * until the workq becomes not-running. */
		while (atomic_fetch_or_explicit(&wq->flags, WQ_RUNNING,
		    memory_order_acquire) & WQ_RUNNING)
			SPINWAIT();
	}
	net2_mutex_unlock(wq->want_mtx);

	wq_surf(wq, parallel, NULL, q);
	return 0;
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
		goto fail_0;
	if ((wthr->stack_spare = net2_malloc(sizeof(*wthr->stack_spare))) ==
	    NULL)
		goto fail_1;
	wthr->kind = WQEVW_THREAD;
	wthr->evbase = wqev;
	if (net2_spinlock_init(&wthr->spl) != 0)
		goto fail_2;
	net2_spinlock_lock(&wthr->spl);
	wthr->worker = net2_thread_new(&wqev_worker, wthr, wname);
	net2_spinlock_unlock(&wthr->spl);
	if (wthr->worker == NULL)
		goto fail_3;

	/* No failure past this point. */

	net2_spinlock_lock(&wqev->spl_workers);
	TAILQ_INSERT_TAIL(&wqev->workers, wthr, tq);
	net2_spinlock_unlock(&wqev->spl_workers);
	return 0;


fail_3:
	net2_spinlock_deinit(&wthr->spl);
fail_2:
	net2_free(wthr->stack_spare);
fail_1:
	net2_free(wthr);
fail_0:
	return ENOMEM;
}
static void
__cold__
destroy_thread(struct net2_workq_evbase *wqev, int count)
{
	struct net2_workq_evbase_worker
				*wthr;
	int			 i;

	assert(count > 0 && count <= wqev->maxthreads);

	/* Mark count threads as having to die. */
	atomic_fetch_add_explicit(&wqev->thr_die, count, memory_order_relaxed);
	/* Make the same number of threads active. */
	net2_semaphore_up(&wqev->thr_active, count);

#ifndef WIN32
	if (wqev->maxthreads == count && wqev->evloop != NULL)
		evl_wakeup(wqev);
#endif /* !WIN32 */

	/* Wait for all dying threads to finish. */
	for (i = 0; i < count; i++)
		net2_semaphore_down(&wqev->thr_death);

	/* Collect all dead threads. */
	while ((wthr = TAILQ_FIRST(&wqev->dead_workers)) != NULL) {
		assert(wthr->kind == WQEVW_THREAD);
		TAILQ_REMOVE(&wqev->dead_workers, wthr, tq);
		net2_thread_join(wthr->worker, NULL);
		net2_thread_free(wthr->worker);
		net2_spinlock_deinit(&wthr->spl);
		net2_free(wthr->stack_spare);
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
			unsigned int idle, back;

			/* Steal all idle threads. */
			idle = atomic_exchange_explicit(&wqev->thr_idle, 0,
			    memory_order_relaxed);
			while (idle == 0) {
				net2_thread_yield();
				idle = atomic_exchange_explicit(
				    &wqev->thr_idle, 0, memory_order_relaxed);
			}

			/*
			 * Calculate the number of stolen threads exceeding
			 * our target.
			 *
			 * This process involves reducing idle by the amount
			 * we want to steal, while activating the remainder.
			 */
			if (wqev->jobthreads - idle < (unsigned)jobthreads) {
				back = jobthreads + idle - wqev->jobthreads;
				net2_semaphore_up(&wqev->thr_active, back);
				idle -= back;
			}

			wqev->jobthreads -= idle;
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
	struct net2_workq_job_int *job;
	int			 error, runcount;
	struct wthrq		*q;


	/* No point in running negative # of jobs. */
	if (count <= 0)
		return EINVAL;

#ifndef WIN32
	/* Run event loop once. */
	run_evl(wq->wqev, RUNEVL_NOWAIT);
#endif

	assert(atomic_load_explicit(&wq->refcnt,
	    memory_order_relaxed) > 0);
	assert(atomic_load_explicit(&wq->int_refcnt,
	    memory_order_relaxed) > 0);

	for (runcount = 0; runcount < count; runcount++) {
		if ((q = wthrq_alloc()) == NULL)
			return (runcount == 0 ? ENOMEM : 0);

		/* Find a runnable job. */
		error = wqev_run_pop_wq(wq->wqev, wq, &job);

		/* Detect if this is an EBUSY scenario. */
		if (error == EAGAIN && (atomic_load_explicit(&wq->flags,
		    memory_order_relaxed) & WQ_WANTLOCK))
			error = EBUSY;
		/* Return error if it occured. */
		if (error != 0) {
			wthrq_free(q);
			return (runcount == 0 ? error : 0);
		}

		/*
		 * Reference wq prior to run_job(), since the latter
		 * will consume the reference counter.
		 * Note that the job refcounter is already incremented
		 * by the wqev_run_pop_wq() function.
		 */
		workq_ref(wq);
		run_job(wq, job, q);
	}
	return 0;
}

/*
 * Helper function for net2_workq_activate.
 *
 * Marks the given job and its workq such that they can run.
 * Used for NET2_WQ_ACT_IMMED option on net2_workq_activate.
 */
static int
mark_job_running(struct net2_workq_job_int *job)
{
	int			 jfl, wfl;
	unsigned int		 prun;
	struct net2_workq	*wq = NULL;

	jfl = atomic_load_explicit(&job->flags, memory_order_relaxed);
	if (jfl & JOB_RUNNING)
		return 0;

	/* If the job is not parallel, first attempt to mark the workq as running. */
	if (!(jfl & NET2_WORKQ_PARALLEL)) {
		wq = job->wq;

		/* Mark as running. */
		wfl = atomic_fetch_or_explicit(&wq->flags, WQ_RUNNING,
		    memory_order_acquire);
		/* Check flags again: they may have changed in the meantime. */
		if (wfl & WQ_RUNNING)
			return 0;
		if (predict_false((wfl & WQ_WANTLOCK) ||
		    atomic_load_explicit(&wq->want_queued,
		    memory_order_relaxed) > 0)) {
			wfl = atomic_fetch_and_explicit(&wq->flags, ~WQ_RUNNING,
			    memory_order_release);
			assert(wfl & WQ_RUNNING);
			return 0;
		}
	} else
		atomic_fetch_add_explicit(&wq->prun, 1, memory_order_acquire);

	/* Mark job as running. */
	jfl = atomic_fetch_or_explicit(&job->flags, JOB_RUNNING, memory_order_acquire);
	if (jfl & JOB_RUNNING) {
		if (!(jfl & NET2_WORKQ_PARALLEL)) {
			/* Undo modification to workq. */
			wfl = atomic_fetch_and_explicit(&wq->flags, ~WQ_RUNNING,
			    memory_order_release);
			assert(wfl & WQ_RUNNING);
		} else {
			prun = atomic_fetch_sub_explicit(&wq->prun, 1,
			    memory_order_release);
			assert(prun > 0);
		}
		return 0;
	}

	/* If the job is persistent, add the ACTIVE bit. */
	if (jfl & NET2_WORKQ_PERSIST) {
		atomic_fetch_or_explicit(&job->flags, JOB_ACTIVE,
		    memory_order_relaxed);
	}

	return 1;
}

/* Activate a job. */
ILIAS_NET2_EXPORT void
__hot__
net2_workq_activate(struct net2_workq_job *j, int flags)
{
	struct net2_workq_job_int	*job;
	struct net2_workq		*wq;
	int				 immed;
	struct wthrq			*q = NULL;

	/* Load job and keep it referenced via j->refcnt. */
	job = atomic_load_explicit(&j->internal, memory_order_acquire);
	if (predict_false(job == NULL))
		return;
	atomic_fetch_add_explicit(&j->refcnt, 1, memory_order_acquire);
	job = atomic_load_explicit(&j->internal, memory_order_consume);
	if (predict_false(job == NULL))
		goto unlock_return;

	/* Determine if we will run the job immediately. */
	if (predict_true(!(flags & NET2_WQ_ACT_IMMED) ||
	    (!(flags & NET2_WQ_ACT_RECURS) && workq_self(job->wq))))
		immed = 0;
	else if (predict_true((q = wthrq_alloc()) != NULL))
		immed = mark_job_running(job);
	else
		immed = 0;

	/* Activate and return for non-immediate case. */
	if (predict_true(!immed)) {
		job_activate(job);
unlock_return:
		atomic_fetch_sub_explicit(&j->refcnt, 1, memory_order_release);
		if (predict_false(q != NULL))
			wthrq_free(q);
		return;
	}

	/*
	 * Immediate invocation.
	 * Job is already marked as running.
	 */

	/* Reference job, release j->refcnt. */
	job_ref(job);
	atomic_fetch_sub_explicit(&j->refcnt, 1, memory_order_relaxed);

	/* Reference workq. */
	wq = job->wq;
	workq_ref(wq);

	/* Run job, consuming reference on both job and workq. */
	run_job(wq, job, q);
}
/* Deactivate a job. */
ILIAS_NET2_EXPORT void
__hot__
net2_workq_deactivate(struct net2_workq_job *j)
{
	struct net2_workq_job_int	*job;

	/* Load job and keep it referenced via j->refcnt. */
	job = atomic_load_explicit(&j->internal, memory_order_acquire);
	if (predict_false(job == NULL))
		return;
	atomic_fetch_add_explicit(&j->refcnt, 1, memory_order_acquire);
	job = atomic_load_explicit(&j->internal, memory_order_consume);
	if (job != NULL)
		job_deactivate(job, 1);
	atomic_fetch_sub_explicit(&j->refcnt, 1, memory_order_release);
}

#ifndef WIN32
/*
 * Return the event loop.
 *
 * The ev_loop is created on demand (calling this function being the demand).
 */
ILIAS_NET2_LOCAL struct ev_loop*
net2_workq_get_evloop(struct net2_workq_evbase *wqev)
{
	struct ev_loop	*new;

	if (wqev->evloop != NULL)
		return wqev->evloop;

	net2_spinlock_lock(&wqev->spl_evloop);
	if (wqev->evloop != NULL)
		goto out;

	/* No existing evloop, create a new evloop. */
	new = ev_loop_new(EVFLAG_AUTO);
	if (new == NULL) {
		net2_spinlock_unlock(&wqev->spl_evloop);
		return NULL;
	}

	/* Assign wqev as the user data for the event loop. */
	ev_set_userdata(new, wqev);

	/*
	 * Assign the new evloop events.
	 * Failure indicates another thread assigned an ev_loop
	 * while we were creating one.
	 */
	ev_async_start(new, &wqev->ev_wakeup);
	ev_async_start(new, &wqev->ev_newevent);

	/*
	 * Ensure all initialization before has been completed
	 * prior to initialing wqev->evloop.
	 */
	atomic_thread_fence(memory_order_seq_cst);

	/* Publish evloop. */
	wqev->evloop = new;

out:
	net2_spinlock_unlock(&wqev->spl_evloop);

	return wqev->evloop;
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

#else

/* Get a timer manager. */
ILIAS_NET2_LOCAL struct net2_workq_timer_container*
net2_workq_get_timer(struct net2_workq *wq)
{
	struct net2_workq_evbase*wqev = wq->wqev;

	if (wqev->timer == NULL) {
		net2_spinlock_lock(&wqev->spl_timer);
		if (wqev->timer == NULL)
			wqev->timer = net2_workq_timer_container_new();
		net2_spinlock_unlock(&wqev->spl_timer);
	}
	return wqev->timer;
}

/* Get an io manager. */
ILIAS_NET2_LOCAL struct net2_workq_io_container*
net2_workq_get_io(struct net2_workq *wq)
{
	struct net2_workq_evbase*wqev = wq->wqev;

	if (wqev->io == NULL) {
		net2_spinlock_lock(&wqev->spl_io);
		if (wqev->io == NULL) {
			wqev->io = net2_workq_io_container_new(&wqev->thr_idle,
			    &wqev->thr_active);
		}
		net2_spinlock_unlock(&wqev->spl_io);
	}
	return wqev->io;
}
#endif


#ifndef HAS_TLS
static net2_spinlock			tls_lock;
static TAILQ_HEAD(, wq_tls_state_t)	tls_states;

/*
 * Retrieve tls state for non-__thread archs.
 *
 * Note that this function is declared pure, since it will always
 * return the same value (unless it fails, in which case it'll abort
 * the program).
 */
static struct wq_tls_state_t*
get_wq_tls_state()
{
	struct wq_tls_state_t	*state;

	if ((state = pthread_getspecific(wq_tls_slot)) == NULL) {
		if ((state = net2_calloc(1, sizeof(*state))) == NULL)
			abort();
		if (pthread_setspecific(wq_tls_slot, state) != 0)
			abort();

		net2_spinlock_lock(&tls_lock);
		TAILQ_INSERT_HEAD(&tls_states, state, q);
		net2_spinlock_unlock(&tls_lock);
	}

	return state;
}
/*
 * Destroy tls state at thread exit.
 */
static void
release_wq_tls_state(void *state_ptr)
{
	struct wq_tls_state_t	*state = state_ptr;

	net2_spinlock_lock(&tls_lock);
	TAILQ_REMOVE(&tls_states, state, q);
	net2_spinlock_unlock(&tls_lock);
	net2_free(state);
}

/* Initialize workq subsystem. */
ILIAS_NET2_LOCAL int
net2_workq_init()
{
	int		 error = 0;

	if ((error = pthread_key_create(&wq_tls_slot,
	    &release_wq_tls_state)) != 0)
		return error;
	TAILQ_INIT(&tls_states);
	if ((error = net2_spinlock_init(&tls_lock)) != 0) {
		pthread_key_delete(wq_tls_slot);
		return error;
	}
	return 0;
}
/* Finalize workq subsystem. */
ILIAS_NET2_LOCAL void
net2_workq_fini()
{
	struct wq_tls_state_t	*state;

	/* First destroy the key, so no more destructors will be called. */
	pthread_key_delete(wq_tls_slot);

	/* Clean up any remaining tls states. */
	net2_spinlock_lock(&tls_lock);
	while ((state = TAILQ_FIRST(&tls_states)) != NULL) {
		TAILQ_REMOVE(&tls_states, state, q);
		net2_free(state);
	}
	net2_spinlock_unlock(&tls_lock);

	/* Destroy the lock on the states. */
	net2_spinlock_deinit(&tls_lock);
	return;
}
#endif	/* !HAS_TLS */

/*
 * Reference and return the current workq.
 * If the workq is not actively referenced, NULL is returned.
 */
ILIAS_NET2_EXPORT struct net2_workq*
net2_workq_current()
{
	struct net2_workq	*wq;

	wq = wq_tls_state.active_wq.wq;
	assert(wq == NULL ||
	    atomic_load_explicit(&wq->int_refcnt, memory_order_relaxed) > 0);
	if (wq != NULL &&
	    atomic_load_explicit(&wq->refcnt, memory_order_relaxed) == 0)
		wq = NULL;
	if (wq != NULL)
		net2_workq_ref(wq);
	return wq;
}
