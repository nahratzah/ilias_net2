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
/* Flags that can be used at job initialization time. */
#define NET2_WORKQ_VALID_USERFLAGS	(NET2_WORKQ_PERSIST)

/* Workq data. */
struct net2_workq {
	struct net2_mutex
			*mtx;			/* Mutex. */
	struct net2_workq_evbase
			*evbase;		/* Event base for IO/timers. */

	TAILQ_HEAD(, net2_workq_job)
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
static void	 net2_workq_deactivate_internal(struct net2_workq_job*, int);


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
	struct net2_workq_job		*job;
	int				 died;
	int				 jobdied;

	net2_mutex_lock(wqev->mtx);			/* LOCK: wqev */
	while (wqev->thread_active <= wqev->thread_target) {
		run = TAILQ_FIRST(&wqev->runq);
		if (run == NULL) {
			if (wqev->wakeup_sent) {
				/*
				 * There's no reason to be awake:
				 * - the runq is empty
				 * - the thread count is at/below the target
				 * (both tested during the same lock, so no
				 * race).
				 *
				 * Clear the flag to ensure the next wakeup
				 * will actually be fire off properly.
				 */
				wqev->wakeup_sent = 0;
			}

			if (!wqev->evbase_wait) {
				/*
				 * Run event loop.
				 * Event loop needs explicit unlock of the
				 * mutex, since cond_wait is not called to
				 * do that for us.
				 *
				 * Note that the evloop has callbacks installed
				 * that unlock wqev during its select/poll/etc.
				 * magic.
				 */
				wqev->evbase_wait = 1;
				ev_run(wqev->evloop, 0);
				wqev->evbase_wait = 0;
			} else {
				wqev->thread_waiting++;
				net2_cond_wait(wqev->wakeup, wqev->mtx);
				wqev->thread_waiting--;
			}
			/* Clear wakeup bit. */
			wqev->wakeup_sent = 0;
			continue;
		}

		/* run != NULL */
		TAILQ_REMOVE(&wqev->runq, run, wqe_runq);
		/* If there is more to be run, wakeup another thread. */
		if (!TAILQ_EMPTY(&wqev->runq))
			net2_workq_wakeup(wqev);
		run->flags &= ~NET2_WQ_F_ONQUEUE;
		run->flags |= NET2_WQ_F_RUNNING;

		died = 0;
		run->died = &died;
		run->execing = w->worker;
		net2_mutex_unlock(wqev->mtx);		/* UNLOCK: wqev */

		net2_mutex_lock(run->mtx);		/* LOCK: run */

		job = TAILQ_FIRST(&run->runqueue);
		if (job != NULL) {
			/* Take job off the runqueue. */
			TAILQ_REMOVE(&run->runqueue, job, readyq);

			/*
			 * Unlock workq, so that the job can alter it while
			 * running.
			 */
			job->died = &jobdied;
			job->flags |= NET2_WORKQ_RUNNING;
			net2_mutex_unlock(run->mtx);	/* UNLOCK: run */

			/* Run callback. */
			(*job->fn)(job->cb_arg[0], job->cb_arg[1]);
			if (died) {
				net2_mutex_lock(wqev->mtx);
				/* Test if the wqev became unreferenced. */
				if (wqev_mtx_unlock(wqev, 1))
					goto wqev_destroy_from_within;
				continue;
			}

			/* Relock. */
			net2_mutex_lock(run->mtx);	/* LOCK: run */
			if (!jobdied) {
				job->died = NULL;
				job->flags &= ~NET2_WORKQ_RUNNING;

				/*
				 * Put job back, if it is persistent and not
				 * already added by another thread or the
				 * callback itself.
				 */
				if ((job->flags & (NET2_WORKQ_PERSIST |
				    NET2_WORKQ_ONQUEUE)) ==
				    NET2_WORKQ_PERSIST) {
					if (job->ev != NULL) {
						assert(0); /* TODO */
					} else {
						TAILQ_INSERT_TAIL(
						    &run->runqueue, job,
						    readyq);
						job->flags |=
						    NET2_WORKQ_ONQUEUE;
					}
				}
			}
		}

		net2_mutex_lock(wqev->mtx);		/* LOCK: wqev */
		run->died = NULL;
		run->execing = NULL;

		/*
		 * Put run back on the queue, if it has more jobs to run.
		 * No wakeup: this thread will pick it up if no other
		 * thread will.
		 *
		 * If run is dying, signal its completion.
		 */
		run->flags &= ~NET2_WQ_F_RUNNING;
		if (run->flags & NET2_WQ_F_DYING)
			net2_cond_broadcast(run->dying);
		else if (!TAILQ_EMPTY(&run->runqueue)) {
			run->flags |= NET2_WQ_F_ONQUEUE;
			TAILQ_INSERT_TAIL(&wqev->runq, run, wqe_runq);
		}
		net2_mutex_unlock(run->mtx);		/* UNLOCK: run */
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
	 */
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
evloop_wakeup(struct ev_loop *loop, ev_async *w, int events)
{
	ev_break(loop, EVBREAK_ALL);
}

/* Inform the evloop that new events have been added. */
static void
evloop_new_event(struct ev_loop *loop, ev_async *w, int events)
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

	net2_mutex_lock(wqev->mtx);			/* LOCK: wqev */
	TAILQ_INSERT_TAIL(&wqev->workq, wq, wqe_member);
	wq->evbase = wqev;
	net2_mutex_unlock(wqev->mtx);			/* UNLOCK: wqev */
	return wq;


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
	struct net2_workq_job		*job;
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
	}

	/* Free resources. */
	net2_mutex_free(wq->mtx);
	net2_cond_free(wq->dying);
	wq->evbase = NULL;
}

/* Add a job to the workq. */
ILIAS_NET2_EXPORT int
net2_workq_init_work(struct net2_workq_job *j, struct net2_workq *wq,
    net2_workq_cb fn, void *arg0, void *arg1, int flags)
{
	if ((flags & NET2_WORKQ_VALID_USERFLAGS) != flags)
		return EINVAL;
	if (fn == NULL)
		return EINVAL;

	if ((j->mtx = net2_mutex_alloc()) == NULL)
		return ENOMEM;
	if ((j->wq_death = net2_cond_alloc()) == NULL) {
		net2_mutex_free(j->mtx);
		return ENOMEM;
	}

	j->workq = wq;
	j->flags = flags;
	j->fn = fn;
	j->cb_arg[0] = arg0;
	j->cb_arg[1] = arg1;
	j->ev = NULL;
	j->callbacks = NULL;
	return 0;
}

/* Destroy workq job. */
ILIAS_NET2_EXPORT void
net2_workq_deinit_work(struct net2_workq_job *j)
{
	struct net2_workq *wq;

	/* Detach from the workq in a permanent fashion. */
	net2_workq_deactivate_internal(j, 1);

	if (j->ev != NULL) {
		assert(j->ev == NULL); /* TODO: implement. */
	}

	net2_cond_free(j->wq_death);
	net2_mutex_free(j->mtx);

	if (j->callbacks != NULL && j->callbacks->on_destroy != NULL)
		(*j->callbacks->on_destroy)(j);
}

/*
 * Mark a job as active.
 * An active job will have its callback run.
 */
ILIAS_NET2_EXPORT void
net2_workq_activate(struct net2_workq_job *j)
{
	struct net2_workq		*wq;
	struct net2_workq_evbase	*wqev;
	int				 add_me;
	int				 j_added = 0;

	net2_mutex_lock(j->mtx);
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
	if (!(wq->flags & (NET2_WQ_F_RUNNING | NET2_WQ_F_ONQUEUE))) {
		TAILQ_INSERT_TAIL(&wqev->runq, wq, wqe_runq);
		wq->flags |= NET2_WQ_F_ONQUEUE;
		net2_workq_wakeup(wqev);
	}
	net2_mutex_unlock(wqev->mtx);			/* UNLOCK: wqev */

out:
	net2_mutex_unlock(j->mtx);

	if (j_added) {
		if (j->callbacks != NULL &&
		    j->callbacks->on_activate != NULL)
			(*j->callbacks->on_activate)(j);
		/* Undo refcount increment. */
		net2_workq_release(wq);
	}
}

/* Mark job as inactive. */
static void
net2_workq_deactivate_internal(struct net2_workq_job *j, int die)
{
	struct net2_workq		*wq;
	int				 deleted = 0;

	net2_mutex_lock(j->mtx);
	wq = j->workq;
	if (wq == NULL)
		goto out;

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

	if (j->flags & NET2_WORKQ_ONQUEUE) {
		TAILQ_REMOVE(&wq->runqueue, j, readyq);
		j->flags &= ~(NET2_WORKQ_ONQUEUE | NET2_WORKQ_PERSIST);
		deleted = 1;
	}

	if (j->flags & NET2_WORKQ_RUNNING)
		*j->died = 1;

	/* If the job dies, it may no longer be a member of the workq. */
	if (die)
		TAILQ_REMOVE(&wq->members, j, memberq);
	net2_mutex_unlock(wq->mtx);

out:
	if (die)
		j->workq = NULL;
	net2_mutex_unlock(j->mtx);

	if (deleted && j->callbacks != NULL &&
	    j->callbacks->on_deactivate != NULL)
		(*j->callbacks->on_deactivate)(j);
}

/* Mark job as inactive. */
ILIAS_NET2_EXPORT void
net2_workq_deactivate(struct net2_workq_job *j)
{
	net2_workq_deactivate_internal(j, 0);
}

/* Returns the event loop used for the workq. */
ILIAS_NET2_EXPORT void*
net2_workq_get_evloop(struct net2_workq *wq)
{
	wq->evbase->evloop;
}

/*
 * Returns the workq on which this job is running.
 * Returns NULL if the workq has been destroyed.
 *
 * The returned workq has its refcount incremented.
 * Call net2_workq_release to release the workq again.
 */
ILIAS_NET2_EXPORT struct net2_workq*
net2_workq_get(struct net2_workq_job *j)
{
	struct net2_workq		*wq;
	int				 wq_is_dead = 0;

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
