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
#include <ilias/net2/bsd_compat/error.h>
#include <ev.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>

/* Internal flags for workq jobs. */
#define NET2_WORKQ_ONQUEUE	0x00010000	/* Job is on ready queue. */
#define NET2_WORKQ_RUNNING	0x00020000	/* Job is running. */
#define NET2_WORKQ_ACTIVE	0x00040000	/* Job is (re)queued. */
#define NET2_WORKQ_WANT_EXE	0x00080000	/* Signal at job completion. */
/* Flags that can be used at job initialization time. */
#define NET2_WORKQ_VALID_USERFLAGS	(NET2_WORKQ_PERSIST)

/* Internal data for workq job. */
struct net2_workq_job_internal {
	struct net2_mutex
			*mtx;			/* Protect workq pointer. */
	struct net2_condition
			*wq_death;		/* Workq death event. */
	struct net2_workq
			*workq;			/* Owner workq. */
	int		 flags;			/* Flags/options. */

	net2_workq_cb	 fn;			/* Callback. */
	void		*cb_arg[2];		/* Callback arguments. */

	TAILQ_ENTRY(net2_workq_job_internal)
			 readyq,		/* Link into ready queue. */
			 memberq;		/* Link into workq. */

	int		*died;			/* Set only if running. */
	struct net2_workq_job
			*backptr;		/* Point back to job. */

	struct net2_condition
			*exe_complete;		/* Execution finished with
						 * WANT_EXE set. */
};

/* Workq data. */
struct net2_workq {
	struct net2_mutex
			*mtx;			/* Mutex. */
	struct net2_workq_evbase
			*evbase;		/* Event base for IO/timers. */

	TAILQ_HEAD(, net2_workq_job_internal)
			 runqueue,		/* Jobs that are to run now. */
			 members;		/* Jobs on this workq. */
	TAILQ_ENTRY(net2_workq)
			 wqe_member;		/* Membership of evbase. */
	TAILQ_ENTRY(net2_workq)
			 wqe_runq;		/* Runqueue of evbase. */
	size_t		 refcnt;		/* Reference counter. */

	/*
	 * Below is locked using evbase->mtx.
	 */
	struct net2_condition
			*dying;			/* After running, fire. */
	struct net2_thread
			*execing;		/* Executing in this thread. */
	int		 flags;			/* Workq flags. */
#define NET2_WQ_F_RUNNING	0x00000001	/* Workq is executing. */
#define NET2_WQ_F_ONQUEUE	0x00000002	/* Workq is on runqueue. */
#define NET2_WQ_F_DYING		0x00000004	/* Workq is dying. */
	int		*died;			/* Pointer to boolean, only
						 * set if thread is in the
						 * running state. */

	size_t		 wanted;		/* Want to suspend workq. */
	struct net2_condition
			*wanted_cond;		/* Ready for suspension. */
};

/*
 * Event base and thread pool.
 */
struct net2_workq_evbase {
	struct net2_mutex
			*mtx;			/* Mutex. */
	struct net2_condition
			*wakeup;		/* Element added to runq. */

	TAILQ_HEAD(, net2_workq)
			 workq;			/* All workq on this evbase. */
	TAILQ_HEAD(, net2_workq)
			 runq;			/* All workq that need run. */

	struct ev_loop	*evloop;		/* Event loop. */
	ev_async	 ev_wakeup;		/* Wakeup for evloop. */
	ev_async	 ev_newevent;		/* Wakeup: events are added. */

	size_t		 thread_active;		/* # threads active. */
	size_t		 thread_target;		/* # threads active. */
	size_t		 thread_waiting;	/* # threads that waiting. */
	int		 evbase_wait;		/* Set if worker in evbase. */
	struct net2_condition
			*thread_death;		/* Condition on thread stop. */
	TAILQ_HEAD(, net2_workq_evbase_worker)
			 dead_threads;		/* Dead threads. */

	char		*wq_worker_name;	/* Thread name of workers. */
	int		 wakeup_sent;		/* Cleared once awoken thread
						 * starts execution. */
	int		 modify_thread_count;	/* Set while thread count is
						 * modified. */
	size_t		 refcnt;		/* Reference counter. */
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
};


static void	 net2_workq_wakeup(struct net2_workq_evbase*);
static void	*net2_workq_worker(void *);
static void	 wqev_unlock(struct ev_loop*);
static void	 wqev_lock(struct ev_loop*);
static void	 evloop_wakeup(struct ev_loop*, ev_async*, int);
static void	 evloop_new_event(struct ev_loop*, ev_async*, int);
static int	 wqev_mtx_unlock(struct net2_workq_evbase*, int);
static void	 net2_workq_deactivate_internal(
		    struct net2_workq_job_internal*, int);
static int	 run_wq(struct net2_workq_evbase*, struct net2_workq*);
static void	 run_job(struct net2_workq*, struct net2_workq_job_internal*);


/*
 * Wake up a workq worker.
 * Must be called with wqev->mtx locked.
 */
static void
net2_workq_wakeup(struct net2_workq_evbase *wqev)
{
	/*
	 * Only 1 thread is woken up at a time.
	 * This thread will wake up more threads, if it sees reason
	 * to do so.  These reasons are:
	 * - the runq is not empty,
	 * - the thread is asked to die.
	 *
	 * Required to get threads not to miss their wakeup (this may happen
	 * because waking up the event queue is special and cond_signal does
	 * not report succes or failure).
	 *
	 * As a side effect, this prevents thundering herd on the mutex,
	 * which may improve performance slightly.
	 */
	if (wqev->wakeup_sent)
		return;

	if (wqev->thread_waiting == 0)
		ev_async_send(wqev->evloop, &wqev->ev_wakeup);
	else
		net2_cond_signal(wqev->wakeup);
	wqev->wakeup_sent = 1; /* Cleared once worker acquires the lock. */
}

/* Workq worker thread. */
static void*
net2_workq_worker(void *w_ptr)
{
	struct net2_workq_evbase_worker	*w = w_ptr;
	struct net2_workq_evbase	*wqev = w->evbase;
	struct net2_workq		*run;
	struct net2_workq_job_internal	*job;
	int				 died;
	int				 jobdied;

	net2_mutex_lock(wqev->mtx);			/* LOCK: wqev */
	while (wqev->thread_active <= wqev->thread_target) {
		run = TAILQ_FIRST(&wqev->runq);

		/* Unblock future wakeups. */
		wqev->wakeup_sent = 0;

		if (!wqev->evbase_wait) {
			/*
			 * No thread is currently running the event loop.
			 *
			 * We'll check it now.
			 * If we have a job, we run the non-blocking version,
			 * otherwise we'll block.
			 */
			wqev->evbase_wait = 1;
			ev_run(wqev->evloop, (run == NULL ? 0 : EVRUN_NOWAIT));
			wqev->evbase_wait = 0;
		} else if (run == NULL) {
			/*
			 * We have no workq to run.
			 * Wait until we are woken up.
			 */
			wqev->thread_waiting++;
			net2_cond_wait(wqev->wakeup, wqev->mtx);
			wqev->thread_waiting--;
		}

		/* If we have nothing to do, simply restart the loop. */
		if (run == NULL) {
			/*
			 * Below, the code will attempt to immediately dive
			 * into a workq, skipping another (pointless) run
			 * of the event loop.
			 * Ofcourse, if the thread was woken up because it
			 * needs to die, it should not do this, but return
			 * immediately.
			 */
			if (wqev->thread_active > wqev->thread_target)
				break;	/* GUARD */

			/*
			 * The above code will have waited for work.
			 * Try to pick up work immediately.
			 */
			if ((run = TAILQ_FIRST(&wqev->runq)) == NULL)
				continue;

			/*
			 * We slept, then we acquired a job.
			 * Unblock wakeup events, since we picked up on it.
			 */
			wqev->wakeup_sent = 0;
		}

		/*
		 * We have something to run.
		 * Check if there are more workqs waiting to run.
		 * If so, wake them up.
		 */
		if (TAILQ_NEXT(run, wqe_runq) != NULL)
			net2_workq_wakeup(wqev);

		if (run_wq(wqev, run)) {
			/*
			 * Workq died while running it.
			 *
			 * Test if this was the last workq to go down.
			 * If so, destroy the wqev from within.
			 */
			if (wqev_mtx_unlock(wqev, 1))
				goto wqev_destroy_from_within;
		}
	}

	/*
	 * Dying code.
	 * Add the thread to the list of dead threads, to allow wqev
	 * to collect it.
	 */
	TAILQ_INSERT_TAIL(&wqev->dead_threads, w, tq);
	net2_cond_signal(wqev->thread_death);
	assert(wqev->thread_active > 0);
	wqev->thread_active--;
	/*
	 * Wake up more threads.
	 * Obviously, if more threads are to die, they must be woken up.
	 * But if the runq is not empty, there's a chance that our thread
	 * death consumed a wakeup for the runqueue.  In this case, we simply
	 * signal for the runq (awoken thread can deal with it).
	 *
	 * Ofcourse, to force the wakeup to succeed, we need to actually clear
	 * the block flag.
	 */
	wqev->wakeup_sent = 0;
	if (!TAILQ_EMPTY(&wqev->runq) ||
	    wqev->thread_active > wqev->thread_target)
		net2_workq_wakeup(wqev);
	net2_mutex_unlock(wqev->mtx);			/* UNLOCK: wqev */
	return NULL;


wqev_destroy_from_within:
	/*
	 * Special case dying code: this worker will execute the death.
	 *
	 * In this case, the thread cannot be collected and thus, it must free
	 * its own data structures internally.
	 */
	net2_cond_signal(wqev->thread_death);
	assert(wqev->thread_active > 0);
	wqev->thread_active--;
	net2_mutex_unlock(wqev->mtx);			/* UNLOCK: wqev */

	/* Free data structure. */
	net2_thread_free(w->worker);
	net2_free(w);

	/* Deamonize the thread, so it won't become a zombie thread. */
	net2_thread_detach_self();
	return NULL;
}

/* Change the number of worker threads. */
ILIAS_NET2_EXPORT int
net2_workq_set_thread_count(struct net2_workq_evbase *wqev, size_t target)
{
	struct net2_workq_evbase_worker	*w;
	size_t				 i;
	int				 error = 0;

	net2_mutex_lock(wqev->mtx);			/* LOCK: wqev */

	/* Prevent multiple set_thread_count calls from interfering. */
	while (wqev->modify_thread_count)
		net2_cond_wait(wqev->thread_death, wqev->mtx);
	wqev->modify_thread_count = 1;

	wqev->thread_target = target;

	/*
	 * Reduce number of active threads to target.
	 */
	if (wqev->thread_active > wqev->thread_target) {
		/*
		 * Wake up a thread to die.
		 * Thread will ensure other threads get woken up
		 * if necessary.
		 */
		net2_workq_wakeup(wqev);

		/* Wait for these threads to die. */
		while (wqev->thread_active > wqev->thread_target)
			net2_cond_wait(wqev->thread_death, wqev->mtx);
	}

	/*
	 * Add threads to reach active target.
	 */
	while (wqev->thread_active < wqev->thread_target) {
		/* Allocate a new worker. */
		if ((w = net2_malloc(sizeof(*w))) == NULL) {
			error = ENOMEM;
			break;
		}

		/* Start the new worker. */
		if ((w->worker = net2_thread_new(&net2_workq_worker, w,
		    wqev->wq_worker_name)) == NULL) {
			error = ENOMEM;
			net2_free(w);
			break;
		}

		/* Increment worker counter. */
		wqev->thread_active++;
	}

	/* Collect all dead threads. */
	while ((w = TAILQ_FIRST(&wqev->dead_threads)) != NULL) {
		TAILQ_REMOVE(&wqev->dead_threads, w, tq);
		net2_thread_join(w->worker, NULL);
		net2_thread_free(w->worker);
		net2_free(w);
	}

	/* Allow any blocked set_thread_count calls from continueing. */
	wqev->modify_thread_count = 0;
	net2_cond_signal(wqev->thread_death);

	net2_mutex_unlock(wqev->mtx);			/* UNLOCK: wqev */

	return error;
}

/* Ev loop callback: release wqev lock. */
static void
wqev_unlock(struct ev_loop *loop)
{
	struct net2_workq_evbase	*wqev;

	wqev = ev_userdata(loop);
	assert(wqev != NULL);
	net2_mutex_unlock(wqev->mtx);
}

/* Ev loop callback: acquire wqev lock. */
static void
wqev_lock(struct ev_loop *loop)
{
	struct net2_workq_evbase	*wqev;

	wqev = ev_userdata(loop);
	assert(wqev != NULL);
	net2_mutex_lock(wqev->mtx);
}

/* Stop the event loop (async wakeup callback). */
static void
evloop_wakeup(struct ev_loop *loop, ev_async * ILIAS_NET2__unused w,
    int ILIAS_NET2__unused events)
{
	ev_break(loop, EVBREAK_ALL);
}

/* Inform the evloop that new events have been added. */
static void
evloop_new_event(struct ev_loop * ILIAS_NET2__unused loop,
    ev_async * ILIAS_NET2__unused w,
    int ILIAS_NET2__unused events)
{
	/* Do nothing: desired behaviour is a side effect from invocation. */
}

/* Create a new workq evbase. */
ILIAS_NET2_EXPORT struct net2_workq_evbase*
net2_workq_evbase_new(const char *name)
{
	struct net2_workq_evbase	*wqev;
	size_t				 nlen;
	char				*buf;

	if ((wqev = net2_malloc(sizeof(*wqev))) == NULL)
		goto fail_0;
	if ((wqev->mtx = net2_mutex_alloc()) == NULL)
		goto fail_1;
	if ((wqev->wakeup = net2_cond_alloc()) == NULL)
		goto fail_2;

	TAILQ_INIT(&wqev->workq);
	TAILQ_INIT(&wqev->runq);

	if ((wqev->evloop = ev_loop_new(EVFLAG_AUTO)) == NULL)
		goto fail_3;
	/* Assign wqev as the user data for the event loop. */
	ev_set_userdata(wqev->evloop, wqev);
	/* Unlock wqev during runs of evloop. */
	ev_set_loop_release_cb(wqev->evloop, &wqev_unlock, &wqev_lock);
	/* Set up the wakeup callback for the event loop. */
	ev_async_init(&wqev->ev_wakeup, &evloop_wakeup);
	ev_async_start(wqev->evloop, &wqev->ev_wakeup);
	/* Set up the wakeup callback to inform evloop of new events. */
	ev_async_init(&wqev->ev_newevent, &evloop_new_event);
	ev_async_start(wqev->evloop, &wqev->ev_newevent);

	if ((wqev->thread_death = net2_cond_alloc()) == NULL)
		goto fail_4;

	TAILQ_INIT(&wqev->dead_threads);

	/* Store name for workers. */
	if (name == NULL || name[0] == '\0') {
		if ((wqev->wq_worker_name = net2_strdup("wq-worker")) == NULL)
			goto fail_5;
	} else {
		/* Detect name len. */
		nlen = snprintf(NULL, 0, "wq-%s-worker", name) + 1;
		/* Allocate name. */
		if ((buf = net2_malloc(nlen)) == NULL)
			goto fail_5;
		/* Write worker name. */
		snprintf(buf, nlen, "wq-%s-worker", name);
		wqev->wq_worker_name = buf;
	}

	/* Create with single reference. */
	wqev->refcnt = 1;

	/* Clear busy flags. */
	wqev->wakeup_sent = 0;
	wqev->modify_thread_count = 0;
	/* No threads are active/waiting, since none exist (yet). */
	wqev->thread_target = wqev->thread_active = wqev->thread_waiting = 0;

	/* Start a single thread. */
	if (net2_workq_set_thread_count(wqev, 1) != 0)
		goto fail_6;

	return wqev;

fail_6:
	net2_free(wqev->wq_worker_name);
fail_5:
	net2_cond_free(wqev->thread_death);
fail_4:
	ev_loop_destroy(wqev->evloop);
fail_3:
	net2_cond_free(wqev->wakeup);
fail_2:
	net2_mutex_free(wqev->mtx);
fail_1:
	net2_free(wqev);
fail_0:
	return NULL;
}

/*
 * Unlock the workq eventbase.
 * Destroys the wqev if it has no references left.
 *
 * If keep_lock is set, the lock will be maintained unless
 * the wqev dies.  Keep_lock may only be set by a worker thread.
 * Returns nonzero if the wqev was destroyed.
 */
static int
wqev_mtx_unlock(struct net2_workq_evbase *wqev, int keep_lock)
{
	int			 error;

	/*
	 * Another thread or external function is already destroying
	 * this.
	 */
	if (keep_lock && wqev->thread_target == 0)
		return 0;

	/* Test if destruction is required prior to unlocking. */
	if (wqev->refcnt == 0 && TAILQ_EMPTY(&wqev->workq)) {
		if (!keep_lock)
			net2_mutex_unlock(wqev->mtx);	/* UNLOCK: wqev */
		return 0; /* Still in use. */
	}
	net2_mutex_unlock(wqev->mtx);			/* UNLOCK: wqev */

	/*
	 * Destroy all threads.
	 */
	error = net2_workq_set_thread_count(wqev, 0);
	if (error != 0) {
		errno = error;
		warn("net2_workq_evbase: failed to kill all threads in workq eventbase");
		/*
		 * Continuing here would cause a segfault once the thread
		 * tries to access wqev.  If this wouldn't deadlock first
		 * because the eventloop might have f.i. a file descriptor
		 * in use while it is being closed.
		 *
		 * We'll leak instead (fucked either way...).
		 */
		return 1;
	}

	/* Destroy all resources used by wqev. */
	net2_free(wqev->wq_worker_name);
	net2_cond_free(wqev->thread_death);
	ev_loop_destroy(wqev->evloop);
	net2_cond_free(wqev->wakeup);
	net2_mutex_free(wqev->mtx);
	net2_free(wqev);
	return 1;
}

/* Add reference to the workq eventbase. */
ILIAS_NET2_EXPORT void
net2_workq_evbase_ref(struct net2_workq_evbase *wqev)
{
	net2_mutex_lock(wqev->mtx);
	wqev->refcnt++;
	assert(wqev->refcnt > 0);
	net2_mutex_unlock(wqev->mtx);
}

/* Remove reference to the workq eventbase. */
ILIAS_NET2_EXPORT void
net2_workq_evbase_release(struct net2_workq_evbase *wqev)
{
	net2_mutex_lock(wqev->mtx);
	assert(wqev->refcnt > 0);
	wqev->refcnt--;
	wqev_mtx_unlock(wqev, 0);
}

ILIAS_NET2_EXPORT void
net2_workq_evbase_evloop_changed(struct net2_workq_evbase *wqev)
{
	ev_async_send(wqev->evloop, &wqev->ev_wakeup);
}


/* Initialize new workq. */
ILIAS_NET2_EXPORT struct net2_workq*
net2_workq_new(struct net2_workq_evbase *wqev)
{
	struct net2_workq		*wq;

	if (wqev == NULL)
		return NULL;

	if ((wq = net2_malloc(sizeof(*wq))) == NULL)
		goto fail_0;
	if ((wq->mtx = net2_mutex_alloc()) == NULL)
		goto fail_1;
	if ((wq->dying = net2_cond_alloc()) == NULL)
		goto fail_2;
	TAILQ_INIT(&wq->runqueue);
	wq->flags = 0;
	wq->refcnt = 1;
	wq->wanted = 0;
	if ((wq->wanted_cond = net2_cond_alloc()) == NULL)
		goto fail_3;

	net2_mutex_lock(wqev->mtx);			/* LOCK: wqev */
	TAILQ_INSERT_TAIL(&wqev->workq, wq, wqe_member);
	wq->evbase = wqev;
	net2_mutex_unlock(wqev->mtx);			/* UNLOCK: wqev */
	return wq;


fail_4:
	net2_cond_free(wq->wanted_cond);
fail_3:
	net2_cond_free(wq->dying);
fail_2:
	net2_mutex_free(wq->mtx);
fail_1:
	net2_free(wq);
fail_0:
	return NULL;
}

/* Increment reference count to wq. */
ILIAS_NET2_EXPORT void
net2_workq_ref(struct net2_workq *wq)
{
	net2_mutex_lock(wq->mtx);			/* LOCK: wq */
	wq->refcnt++;
	assert(wq->refcnt > 0);
	net2_mutex_unlock(wq->mtx);			/* LOCK: wq */
}

/* Destroy workq. */
ILIAS_NET2_EXPORT void
net2_workq_release(struct net2_workq *wq)
{
	struct net2_workq_evbase	*wqev;
	struct net2_workq_job_internal	*job;
	int				 do_free;

	if (wq == NULL)
		return;

	/*
	 * Decrement reference counter.
	 */
	net2_mutex_lock(wq->mtx);			/* LOCK: wq */
	wqev = wq->evbase;
	assert(wqev != NULL);
	assert(wq->refcnt > 0);
	wq->refcnt--;
	do_free = (wq->refcnt == 0);
	if (do_free) {
		net2_mutex_lock(wqev->mtx);
		/*
		 * Mark as dying, so that jobs will no longer modify
		 * the runqueue.
		 */
		wq->flags |= NET2_WQ_F_DYING;
	}
	net2_mutex_unlock(wq->mtx);			/* LOCK: wq */
	if (!do_free)
		return; /* Still in use. */

	/* Remove us from the runq. */
	if (wq->flags & NET2_WQ_F_ONQUEUE)
		TAILQ_REMOVE(&wqev->runq, wq, wqe_runq);

	/* Ensure the workq isn't running. */
	if (wq->flags & NET2_WQ_F_RUNNING) {
		/* Kill in this thread. */
		if (net2_thread_is_self(wq->execing))
			*wq->died = 1;
		else {
			/* Wait until execing thread is done. */
			while (wq->flags & NET2_WQ_F_RUNNING)
				net2_cond_wait(wq->dying, wqev->mtx);
		}
	}
	TAILQ_REMOVE(&wqev->workq, wq, wqe_member);

	/*
	 * Unlock wqev.
	 * Note that we don't use wqev_mtx_unlock, since the worker has
	 * to clean up the thread.  The worker has to detect the wqev
	 * destruction case by itself.
	 */
	net2_mutex_unlock(wqev->mtx);

	/*
	 * Remove all jobs.
	 * Note that until this has completed, jobs may still access
	 * the workq.
	 */
	while ((job = TAILQ_FIRST(&wq->members)) != NULL) {
		net2_mutex_lock(job->mtx);
		job->flags &= ~NET2_WORKQ_ONQUEUE;
		TAILQ_REMOVE(&wq->members, job, memberq);
		job->workq = NULL;
		net2_cond_broadcast(job->wq_death);
		net2_mutex_unlock(job->mtx);

		/* Inform job of workq destruction. */
		if (job->backptr->callbacks != NULL &&
		    job->backptr->callbacks->on_wqdestroy != NULL)
			(*job->backptr->callbacks->on_wqdestroy)(job->backptr);
	}

	/* Free resources. */
	net2_mutex_free(wq->mtx);
	net2_cond_free(wq->dying);
	net2_cond_free(wq->wanted_cond);
	wq->evbase = NULL;
}

/*
 * Returns the workq_evbase that manages this workq.
 * Returned evbase is not referenced.
 */
ILIAS_NET2_EXPORT struct net2_workq_evbase*
net2_workq_evbase(struct net2_workq *wq)
{
	return wq->evbase;	/* No lock required: is only set once. */
}

/* Add a job to the workq. */
ILIAS_NET2_EXPORT int
net2_workq_init_work(struct net2_workq_job *jj, struct net2_workq *wq,
    net2_workq_cb fn, void *arg0, void *arg1, int flags)
{
	struct net2_workq_job_internal	*j;
	int				 error;

	jj->internal = NULL;
	jj->callbacks = NULL;

	if ((flags & NET2_WORKQ_VALID_USERFLAGS) != flags)
		return EINVAL;
	/* fn == NULL is allowed: it won't ever activate however. */

	if ((j = net2_malloc(sizeof(*j))) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	j->backptr = jj;

	if ((j->mtx = net2_mutex_alloc()) == NULL) {
		error = ENOMEM;
		goto fail_1;
	}
	if ((j->wq_death = net2_cond_alloc()) == NULL) {
		error = ENOMEM;
		goto fail_2;
	}
	if ((j->exe_complete = net2_cond_alloc()) == NULL) {
		error = ENOMEM;
		goto fail_3;
	}

	j->workq = wq;
	j->flags = flags;
	j->fn = fn;
	j->cb_arg[0] = arg0;
	j->cb_arg[1] = arg1;

	jj->internal = j;
	return 0;


fail_4:
	net2_cond_free(j->exe_complete);
fail_3:
	net2_cond_free(j->wq_death);
fail_2:
	net2_mutex_free(j->mtx);
fail_1:
	net2_free(j);
fail_0:
	assert(error != 0);
	return error;
}

/* Destroy workq job. */
ILIAS_NET2_EXPORT void
net2_workq_deinit_work(struct net2_workq_job *jj)
{
	struct net2_workq		*wq;
	struct net2_workq_job_internal	*j;

	j = jj->internal;
	jj->internal = NULL;

	/* Detach from the workq in a permanent fashion. */
	if (j != NULL) {
		net2_workq_deactivate_internal(j, 1);

		net2_cond_free(j->wq_death);
		net2_mutex_free(j->mtx);
	}

	if (jj->callbacks != NULL && jj->callbacks->on_destroy != NULL)
		(*jj->callbacks->on_destroy)(jj);
	jj->callbacks = NULL;

	net2_free(j);
}

/*
 * Mark a job as active.
 * An active job will have its callback run.
 */
ILIAS_NET2_EXPORT void
net2_workq_activate(struct net2_workq_job *jj)
{
	struct net2_workq		*wq;
	struct net2_workq_evbase	*wqev;
	struct net2_workq_job_internal	*j = jj->internal;
	int				 add_me;
	int				 j_added = 0;

	if (j == NULL)
		return;

	net2_mutex_lock(j->mtx);
	if (j->fn == NULL)
		goto out; /* Noop. */
	wq = j->workq;
	if (wq == NULL)
		goto out; /* Queue died. */

	/* Add job to workq. */
	net2_mutex_lock(wq->mtx);			/* LOCK: wq */
	if (wq->flags & NET2_WQ_F_DYING) {
		/* Queue is dying, we cannot activate. */
		net2_mutex_unlock(wq->mtx);
		goto out;
	}

	wqev = wq->evbase;
	j->flags |= NET2_WORKQ_ACTIVE;
	if (!(j->flags & NET2_WORKQ_ONQUEUE)) {
		add_me = TAILQ_EMPTY(&wq->runqueue);
		TAILQ_INSERT_TAIL(&wq->runqueue, j, readyq);
		j->flags |= NET2_WORKQ_ONQUEUE;

		/* Keep the workq alive until after the callback. */
		wq->refcnt++;
		j_added = 1;
	} else
		add_me = 0;
	net2_mutex_unlock(wq->mtx);			/* UNLOCK: wq */

	/*
	 * Workq already had jobs, so it must already be active.
	 * No scheduling required.
	 */
	if (!add_me)
		goto out;

	/* Notify the workq evbase. */
	net2_mutex_lock(wqev->mtx);			/* LOCK: wqev */
	if (!(wq->flags & (NET2_WQ_F_RUNNING | NET2_WQ_F_ONQUEUE)) &&
	    wq->wanted == 0) {
		TAILQ_INSERT_TAIL(&wqev->runq, wq, wqe_runq);
		wq->flags |= NET2_WQ_F_ONQUEUE;
		net2_workq_wakeup(wqev);
	}
	net2_mutex_unlock(wqev->mtx);			/* UNLOCK: wqev */

out:
	net2_mutex_unlock(j->mtx);

	if (j_added) {
		if (jj->callbacks != NULL &&
		    jj->callbacks->on_activate != NULL)
			(*jj->callbacks->on_activate)(jj);
		/* Undo refcount increment. */
		net2_workq_release(wq);
	}
}

/* Mark job as inactive. */
static void
net2_workq_deactivate_internal(struct net2_workq_job_internal *j, int die)
{
	struct net2_workq		*wq;
	int				 deleted = 0;

	/* Lock job and acquire workq. */
	net2_mutex_lock(j->mtx);
	wq = j->workq;
	if (wq == NULL) {
		if (j->flags & NET2_WORKQ_ACTIVE) {
			j->flags &= ~NET2_WORKQ_ACTIVE;
			goto out;
		}
		net2_mutex_unlock(j->mtx);
		return;
	}

	net2_mutex_lock(wq->mtx);
	if (wq->flags & NET2_WQ_F_DYING) {
		net2_mutex_unlock(wq->mtx);
		if (!die)
			goto out; /* Not dying, just deactivating. */

		/* Workq is marking all jobs, wait until that has completed. */
		while (j->workq != NULL)
			net2_cond_wait(j->wq_death, j->mtx);
		goto out;
	}

	/* Deactivate job. */
	j->flags &= ~NET2_WORKQ_ACTIVE;
	if (j->flags & NET2_WORKQ_ONQUEUE) {
		TAILQ_REMOVE(&wq->runqueue, j, readyq);
		j->flags &= ~NET2_WORKQ_ONQUEUE;
		deleted = 1;
	}

	/*
	 * If the job dies, it may no longer be a member of the workq.
	 * The workq must also be informed if the job disappears from under it.
	 */
	if (die) {
		TAILQ_REMOVE(&wq->members, j, memberq);
		if (j->flags & NET2_WORKQ_RUNNING)
			*j->died = 1;
		j->workq = NULL;	/* No longer owned by workq. */
	}

	/*
	 * Wait until the job completes before erasing it.
	 * Avoid deadlock if this thread is running the job.
	 */
	if ((j->flags & NET2_WORKQ_RUNNING) && !net2_thread_is_self(wq->execing)) {
		j->flags |= NET2_WORKQ_WANT_EXE;
		while (j->flags & NET2_WORKQ_RUNNING)
			net2_cond_wait(j->exe_complete, wq->mtx);
		j->flags &= ~NET2_WORKQ_WANT_EXE;
	}

	net2_mutex_unlock(wq->mtx);
out:
	net2_mutex_unlock(j->mtx);

	if (deleted && j->backptr->callbacks != NULL &&
	    j->backptr->callbacks->on_deactivate != NULL)
		(*j->backptr->callbacks->on_deactivate)(j->backptr);
}

/* Mark job as inactive. */
ILIAS_NET2_EXPORT void
net2_workq_deactivate(struct net2_workq_job *j)
{
	if (j->internal == NULL)
		return;
	net2_workq_deactivate_internal(j->internal, 0);
}

/* Returns the event loop used for the workq. */
ILIAS_NET2_LOCAL struct ev_loop*
net2_workq_get_evloop(struct net2_workq *wq)
{
	return wq->evbase->evloop;
}

/*
 * Returns the workq on which this job is running.
 * Returns NULL if the workq has been destroyed.
 *
 * The returned workq has its refcount incremented.
 * Call net2_workq_release to release the workq again.
 */
ILIAS_NET2_EXPORT struct net2_workq*
net2_workq_get(struct net2_workq_job *jj)
{
	struct net2_workq_job_internal	*j = jj->internal;
	struct net2_workq		*wq;
	int				 wq_is_dead = 0;

	if (j == NULL)
		return NULL;

	/* Read the workq from j. */
	net2_mutex_lock(j->mtx);
	wq = j->workq;
	/* Check if the workq is still alive. */
	if (wq != NULL) {
		net2_mutex_lock(wq->mtx);
		wq_is_dead = (wq->flags & NET2_WQ_F_DYING);
		/* Keep the workq alive for the return value. */
		if (!wq_is_dead)
			wq->refcnt++;
		net2_mutex_unlock(wq->mtx);
	}

out:
	net2_mutex_unlock(j->mtx);
	return (wq_is_dead ? NULL : wq);
}


/*
 * Run a wq from the wqev.
 *
 * If wq is NULL, a workq will be selected.
 *
 * Called with wqev locked, returns with wqev locked.
 *
 * If wq dies, returns 1, otherwise 0.
 */
static int
run_wq(struct net2_workq_evbase *wqev, struct net2_workq *wq)
{
	int			 died;
	struct net2_thread	*th_self;

	/* If no workq was selected, select one manually. */
	if (wq == NULL) {
		if ((wq = TAILQ_FIRST(&wqev->runq)) == NULL)
			return 0;
	}
	/* Acquire this thread. */
	if ((th_self = net2_thread_self()) == NULL)
		return 0;

	TAILQ_REMOVE(&wqev->runq, wq, wqe_runq);
	wq->flags &= ~NET2_WQ_F_ONQUEUE;
	wq->flags |= NET2_WQ_F_RUNNING;

	assert(wq->died == NULL);
	died = 0;
	wq->died = &died;
	wq->execing = th_self;
	net2_mutex_unlock(wqev->mtx);

	net2_mutex_lock(wq->mtx);
	run_job(wq, NULL);

	net2_mutex_lock(wqev->mtx);
	if (died)
		goto out;

	wq->died = NULL;
	wq->execing = NULL;

	assert(!(wq->flags & NET2_WQ_F_ONQUEUE));
	wq->flags &= ~NET2_WQ_F_RUNNING;
	if (wq->flags & NET2_WQ_F_DYING)
		net2_cond_broadcast(wq->dying);
	else if (wq->wanted > 0)
		net2_cond_signal(wq->wanted_cond);
	else if (!TAILQ_EMPTY(&wq->runqueue)) {
		wq->flags |= NET2_WQ_F_ONQUEUE;
		TAILQ_INSERT_TAIL(&wqev->runq, wq, wqe_runq);
	}

	net2_mutex_unlock(wq->mtx);

out:
	net2_thread_free(th_self);
	return died;
}

/*
 * Run a job on the workq.
 *
 * If j is NULL, the first job from the workq will be selected.
 *
 * Called with wq locked, exits with wq locked unless wq died.
 */
static void
run_job(struct net2_workq *wq, struct net2_workq_job_internal *j)
{
	int			*wq_died;
	int			 died;

	assert(wq->flags & NET2_WQ_F_RUNNING);
	wq_died = wq->died;

	assert(wq->execing != NULL && net2_thread_is_self(wq->execing));
	if (j == NULL) {
		/* Find the first job that is not blocking on exec. */
		if ((j = TAILQ_FIRST(&wq->runqueue)) == NULL)
			return;
	}
	assert(j->flags & NET2_WORKQ_ACTIVE);
	TAILQ_REMOVE(&wq->runqueue, j, readyq);

	assert(j->died == NULL);
	died = 0;
	j->died = &died;
	j->flags |= NET2_WORKQ_RUNNING;
	/*
	 * Deactivate job now, unless it is persistent.
	 */
	if (!(j->flags & NET2_WORKQ_PERSIST))
		j->flags &= ~NET2_WORKQ_ACTIVE;
	net2_mutex_unlock(wq->mtx);

	/* Run the callback. */
	(*j->fn)(j->cb_arg[0], j->cb_arg[1]);

	if (!*wq_died)
		net2_mutex_lock(wq->mtx);
	if (!died) {
		/* Clear modifications. */
		j->died = NULL;
		j->flags &= ~NET2_WORKQ_RUNNING;
	}
	if (died || *wq_died) {
		/*
		 * If either the job or its workq ceased to exist,
		 * we did all we can do.
		 *
		 * Note that unless wq_died, we exit with the workq lock
		 * held.
		 */
		return;
	}

	/* If the active bit survived all that the job did, requeue it now. */
	if ((j->flags & (NET2_WORKQ_ACTIVE | NET2_WORKQ_ONQUEUE)) ==
	    NET2_WORKQ_ACTIVE) {
		TAILQ_INSERT_TAIL(&wq->runqueue, j, readyq);
		j->flags |= NET2_WORKQ_ONQUEUE;
	}
	/* Signal that the job has completed. */
	if (j->flags & NET2_WORKQ_WANT_EXE)
		net2_cond_broadcast(j->exe_complete);
}

/*
 * Wait for a specific workq to become available.
 *
 * Returns:
 * 0:		succes
 * EDEADLK:	called from within workq
 * ETIMEDOUT:	lock failed
 * ENOMEM:	insufficient memory to acquire lock
 */
ILIAS_NET2_EXPORT int
net2_workq_want(struct net2_workq *wq, int try)
{
	struct net2_workq_evbase*wqev;
	int			 error;

	net2_mutex_lock(wq->mtx);
	wqev = wq->evbase;

	/*
	 * Test if this thread is already on the workq it attempts to join.
	 */
	net2_mutex_lock(wqev->mtx);
	if ((wq->flags & NET2_WQ_F_RUNNING)) {
		if (net2_thread_is_self(wq->execing))
			error = EDEADLK;
		else if (try)
			error = EINTR;
		else
			error = 0;
		if (error != 0) {
			net2_mutex_unlock(wqev->mtx);
			net2_mutex_unlock(wq->mtx);
			return error;
		}
	}
	net2_mutex_unlock(wqev->mtx);

	/*
	 * If other wanted threads are queued, they'll have done
	 * the necessary work.  Simply skip forward to join the wait
	 * queue.
	 */
	if (wq->wanted > 0)
		goto wait;

	/* Retry until we acquire the workq. */
	for (;;) {
		net2_mutex_lock(wqev->mtx);
		if (!(wq->flags & NET2_WQ_F_RUNNING)) {
			error = 0;
			wq->flags |= NET2_WQ_F_RUNNING;
			if ((wq->execing = net2_thread_self()) == NULL)
				error = ENOMEM;
			net2_mutex_unlock(wqev->mtx);
			net2_mutex_unlock(wq->mtx);
			return error;
		}

		/*
		 * WQ is running, wait until it becomes available.
		 * We must unlock the wqev, since we are going to block
		 * on a variable controlled by wq.
		 *
		 * Before we unlock the workq, we must remove it from the
		 * runqueue, so it won't be picked up by another worker.
		 */
		if (wq->flags & NET2_WQ_F_ONQUEUE) {
			wq->flags &= ~NET2_WQ_F_ONQUEUE;
			TAILQ_REMOVE(&wqev->runq, wq, wqe_runq);
		}
		net2_mutex_unlock(wqev->mtx);

wait:
		wq->wanted++;
		net2_cond_wait(wq->wanted_cond, wq->mtx);
		wq->wanted--;
	}
}

/*
 * Release the want-lock on the workq.
 */
ILIAS_NET2_EXPORT void
net2_workq_unwant(struct net2_workq *wq)
{
	struct net2_workq_evbase*wqev;

	wqev = wq->evbase;
	net2_mutex_lock(wq->mtx);

	/* Clear running flag. */
	net2_mutex_lock(wqev->mtx);
	assert(wq->flags & NET2_WQ_F_RUNNING);
	wq->flags &= ~NET2_WQ_F_RUNNING;

	/* Signal next blocking thread. */
	if (wq->wanted > 0) {
		net2_mutex_unlock(wqev->mtx);
		net2_cond_signal(wq->wanted_cond);
		net2_mutex_unlock(wq->mtx);
		return;
	}

	/* Lock on wq no longer required. */
	net2_mutex_unlock(wq->mtx);

	/* Enqueue wq if it has running tasks. */
	if (wq->flags & NET2_WQ_F_DYING)
		net2_cond_broadcast(wq->dying);
	else if (!TAILQ_EMPTY(&wq->runqueue)) {
		wq->flags |= NET2_WQ_F_ONQUEUE;
		TAILQ_INSERT_TAIL(&wqev->runq, wq, wqe_runq);
		/*
		 * Since this is not a worker thread that can pick up
		 * the workq immediately, wake up a workq.
		 */
		net2_workq_wakeup(wqev);
	}

	/* Release wqev. */
	net2_mutex_unlock(wqev->mtx);
}
