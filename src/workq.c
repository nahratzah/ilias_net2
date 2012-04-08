#include <ilias/net2/workq.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/mutex.h>
#include <ilias/net2/thread.h>
#include <ilias/net2/bsd_compat/error.h>
#include <ev.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>

#define NET2_WORKQ_ONQUEUE	0x00010000

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

	const char	*wq_worker_name;	/* Thread name of workers. */
	int		 wakeup_sent;		/* Cleared once awoken thread
						 * starts execution. */
	int		 modify_thread_count;	/* Set while thread count is
						 * modified. */
	size_t		 refcnt;		/* Reference counter. */
};

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
static void	 wqev_mtx_unlock(struct net2_workq_evbase*);


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
		net2_mutex_unlock(wqev->mtx);		/* UNLOCK: wqev */

		net2_mutex_lock(run->mtx);		/* LOCK: run */
		run->flags &= ~NET2_WQ_F_ONQUEUE;
		run->flags |= NET2_WQ_F_RUNNING;

		job = TAILQ_FIRST(&run->runqueue);
		if (job != NULL) {
			/* Take job off the runqueue. */
			TAILQ_REMOVE(&run->runqueue, job, readyq);

			/*
			 * Unlock workq, so that the job can alter it while
			 * running.
			 */
			net2_mutex_unlock(run->mtx);	/* UNLOCK: run */

			/* Run callback. */
			(*job->fn)(job->cb_arg[0], job->cb_arg[1]);

			/* Relock. */
			net2_mutex_lock(run->mtx);	/* LOCK: run */

			/*
			 * Put job back, if it is persistent and not already
			 * added by another thread or the callback itself.
			 */
			if ((job->flags &
			    (NET2_WORKQ_PERSIST | NET2_WORKQ_ONQUEUE)) ==
			    NET2_WORKQ_PERSIST) {
				if (job->ev != NULL) {
					assert(0); /* TODO: event_add. */
				} else {
					TAILQ_INSERT_TAIL(&run->runqueue, job,
					    readyq);
					job->flags |= NET2_WORKQ_ONQUEUE;
				}
			}
		}

		/*
		 * Put run back on the queue, if it has more jobs to run.
		 * No wakeup: this thread will pick it up if no other
		 * thread will.
		 */
		if (!TAILQ_EMPTY(&run->runqueue)) {
			run->flags |= NET2_WQ_F_ONQUEUE;
			TAILQ_INSERT_TAIL(&wqev->runq, run, wqe_runq);
		}
		run->flags &= ~NET2_WQ_F_RUNNING;
		net2_mutex_unlock(run->mtx);		/* UNLOCK: run */

		net2_mutex_lock(wqev->mtx);		/* LOCK: wqev */
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

/*
 * Inform the evloop that new events have been added.
 */
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
	wqev_mtx_unlock(wqev);
}

/*
 * Unlock the workq eventbase.
 * Destroys the wqev if it has no references left.
 */
static void
wqev_mtx_unlock(struct net2_workq_evbase *wqev)
{
	int			 do_destroy;
	int			 error;

	/* Test if destruction is required prior to unlocking. */
	do_destroy = (wqev->refcnt == 0 && TAILQ_EMPTY(&wqev->workq));
	net2_mutex_unlock(wqev->mtx);		/* UNLOCK: wqev */
	if (!do_destroy)
		return; /* Still in use. */

	/* Destroy all threads. */
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
		return;
	}

	/* Destroy all resources used by wqev. */
	net2_free(wqev->wq_worker_name);
	net2_cond_free(wqev->thread_death);
	ev_loop_destroy(wqev->evloop);
	net2_cond_free(wqev->wakeup);
	net2_mutex_free(wqev->mtx);
	net2_free(wqev);
}
