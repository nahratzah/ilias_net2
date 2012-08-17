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
#include <ilias/net2/workq_timer.h>
#include <ilias/net2/workq.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/mutex.h>
#include <ilias/net2/bsd_compat/clock.h>

#ifndef WIN32
#include <ev.h>
#ifdef EV_C
#include EV_C
#endif
#endif


#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <process.h>
#include <ilias/net2/spinlock.h>
#include <ilias/net2/thread.h>
#include <ilias/net2/bsd_compat/error.h>
#include <ilias/net2/bsd_compat/sysexits.h>
#include <ilias/net2/bsd_compat/clock.h>
#include <errno.h>
#include <stdlib.h>

struct net2_workq_timer_container {
	net2_spinlock		 spl;		/* Protect container. */
	HANDLE			 timer;		/* Timer object. */
	LARGE_INTEGER		 expires;	/* Next expiry. */

	size_t			 nwqt_arrsz;	/* Array size of wq_timers. */
	size_t			 nwq_timers;	/* Number of workq timers. */
	struct net2_workq_timer	**wq_timers;	/* Array of workq timers. */
	int			 need_sort;	/* Set if the array lost
						 * ordering. */

	HANDLE			 shutdown;	/* Thread shutdown object. */
	HANDLE			 thread;	/* Worker thread that waits
						 * for timer expiry. */
};
#endif

struct net2_workq_timer {
	struct net2_workq_job	 job;		/* Base job implementation. */

#ifdef WIN32
	LARGE_INTEGER		 timeo_at;	/* Expiry moment. */
	volatile int		 active;	/* Set if active. */
#else
	struct ev_timer		 watcher;	/* Timer watcher. */
	ev_tstamp		 timeo_at;	/* When timeout must fire. */

	struct ev_loop		*loop;		/* Event loop. */
	struct net2_mutex	*loopmtx;	/* Protect loop pointer. */
#endif
};

#define TIMER_EV_OFFSET							\
	((size_t)(&((struct net2_workq_timer*)0)->watcher))
#define EV_2_TIMER(_ev)							\
	((struct net2_workq_timer*)((char*)(_ev) - TIMER_EV_OFFSET))
#define TIMER_WQJ_OFFSET						\
	((size_t)(&((struct net2_workq_timer*)0)->job))
#define WQJ_2_TIMER(_ev)						\
	((struct net2_workq_timer*)((char*)(_ev) - TIMER_WQJ_OFFSET))

/*
 * Deactivate timer and prevent future activations.
 * Also: prevent free from using an invalid loop pointer.
 */
static void
wqtimer_on_wqdestroy(struct net2_workq_job *j)
{
	struct net2_workq_timer	*ev = WQJ_2_TIMER(j);

	net2_mutex_lock(ev->loopmtx);
	if (ev_loop != NULL) {
		ev_timer_stop(ev->loop, &ev->watcher);
		ev->loop = NULL;
	}
	net2_mutex_unlock(ev->loopmtx);
}

static const struct net2_workq_job_cb timer_wqcb = {
	NULL,
	wqtimer_on_wqdestroy
};


/* Timer callback. */
static void
timer_evcb(struct ev_loop *loop, ev_timer *t,
    int ILIAS_NET2__unused revents)
{
	struct net2_workq_timer	*ev;
	ev_tstamp		 delay;

	/* Translate t to ev. */
	ev = EV_2_TIMER(t);
	delay = ev->timeo_at - ev_now(loop);
	if (delay < 0.)
		net2_workq_activate(&ev->job, 0);
	else {
		ev_timer_set(t, delay, 0.);
		ev_timer_start(loop, t);
	}
}

/* Make the timer expire after the given delay. */
ILIAS_NET2_EXPORT void
net2_workq_timer_set(struct net2_workq_timer *ev,
    const struct timeval *delay_tv)
{
	ev_tstamp		 timeo_at;
	ev_tstamp		 delay;
	struct ev_loop		*loop;
	struct net2_workq	*wq;

	if ((wq = net2_workq_get(&ev->job)) == NULL) {
		/* Workq no longer exists.  Timer cannot fire. */
		return;
	}
	loop = net2_workq_get_evloop(wq);

	/* Calculate delay period and expected timeout moment. */
	delay = (delay_tv->tv_sec + delay_tv->tv_usec / 1000000.);
	timeo_at = ev_now(loop) + delay;

	/*
	 * Reset timer if:
	 * - it's not running (reset will cause it to start)
	 * - the new delay is shorter than the original delay and it would
	 *   time out after the current delay.
	 *
	 * In these cases, the timer needs re-activation to ensure the evcb
	 * will fire before or at the timeout.
	 */
	if (!ev_is_active(&ev->watcher) ||
	    (timercmp(delay_tv, &ev->delay, <) && ev->timeo_at > timeo_at)) {
		ev_timer_stop(loop, &ev->watcher);
		ev_timer_set(&ev->watcher, delay, 0.);
		ev_timer_start(loop, &ev->watcher);
		net2_workq_evbase_evloop_changed(net2_workq_evbase(wq));
	}

	/* Prevent job from running. */
	net2_workq_deactivate(&ev->job);

	/* Mark planned timeout. */
	ev->timeo_at = timeo_at;

	/* Release workq. */
	net2_workq_release(wq);
}

/* Stop the timer. Cancels pending callbacks. */
ILIAS_NET2_EXPORT void
net2_workq_timer_stop(struct net2_workq_timer *ev)
{
	struct net2_workq	*wq;

	wq = net2_workq_get(&ev->job);
	net2_workq_deactivate(&ev->job);
	ev_timer_stop(net2_workq_get_evloop(wq), &ev->watcher);
	net2_workq_evbase_evloop_changed(net2_workq_evbase(wq));
	net2_workq_release(wq);
}

/* Create a new timer. */
ILIAS_NET2_EXPORT struct net2_workq_timer*
net2_workq_timer_new(struct net2_workq *wq, net2_workq_cb cb,
    void *arg0, void *arg1)
{
	struct net2_workq_timer	*ev;

	/* Validate arguments. */
	if (wq == NULL || cb == NULL)
		return NULL;

	/* Allocate timer. */
	if ((ev = net2_malloc(sizeof(*ev))) == NULL)
		return NULL;

	if (net2_workq_init_work(&ev->job, wq, cb, arg0, arg1, 0) != 0)
		goto fail_0;
	ev_init(&ev->watcher, &timer_evcb);
	if ((ev->loopmtx = net2_mutex_alloc()) == NULL)
		goto fail_2;

	ev->delay.tv_sec = 0;
	ev->delay.tv_usec = 0;
	ev->loop = net2_workq_get_evloop(wq);
	ev->timeo_at = ev_now(ev->loop);

	net2_workq_set_callbacks(&ev->job, &timer_wqcb);

	return ev;

fail_3:
	net2_mutex_free(ev->loopmtx);
fail_2:
	/* No deinitialization counterpart for ev_init. */
fail_1:
	net2_workq_deinit_work(&ev->job);
fail_0:
	return NULL;
}

/* Destroys a timer. */
ILIAS_NET2_EXPORT void
net2_workq_timer_free(struct net2_workq_timer *ev)
{
	if (ev == NULL)
		return;

	net2_mutex_lock(ev->loopmtx);
	if (ev->loop != NULL)
		ev_timer_stop(ev->loop, &ev->watcher);
	net2_mutex_unlock(ev->loopmtx);

	net2_workq_deinit_work(&ev->job);
	net2_mutex_free(ev->loopmtx);
	net2_free(ev);
}

#ifdef WIN32
/*
 * Sort timers in descending order (i.e. the one that is first to expire
 * will be at the end of the array.
 */
static int __cdecl
timeo_at_cmp(const void *x_ptr, const void *y_ptr)
{
	struct net2_workq_timer *x, *y;

	x = *(struct net2_workq_timer**)x_ptr;
	y = *(struct net2_workq_timer**)y_ptr;
	return (x->timeo_at.QuadPart > y->timeo_at.QuadPart ? -1 :
	    x->timeo_at.QuadPart < y->timeo_at.QuadPart);
}

static __inline void
ft2tv(struct timeval *tv, FILETIME *ft)
{
	LARGE_INTEGER fti;

	fti.HighPart = ft->dwHighDateTime;
	fti.LowPart = ft->dwLowDateTime;

	/* Round down to micro second resolution. */
	fti.QuadPart /= 10;
	tv->tv_sec = fti.QuadPart / 1000000;
	tv->tv_usec = fti.QuadPart % 1000000;
}
static __inline void
tv2li(LARGE_INTEGER *i, struct timeval *tv)
{
	FILETIME	now;
	LARGE_INTEGER	fti, ftnow;

	GetSystemTimeAsFileTime(&now);
	ftnow.HighPart = now.dwHighDateTime;
	ftnow.LowPart = now.dwLowDateTime;

	fti.QuadPart = tv->tv_sec;
	fti.QuadPart *= 1000000;
	fti.QuadPart += tv->tv_usec;
	fti.QuadPart *= 10;

	i->QuadPart = ftnow.QuadPart + fti.QuadPart;
}

/* Sort timers. */
static __inline void
timer_sort(struct net2_workq_timer_container *c)
{
	qsort(c->wq_timers, c->nwq_timers,
	    sizeof(*c->wq_timers), &timeo_at_cmp);
	c->need_sort = 0;
}

static unsigned int __stdcall
worker(void *c_ptr)
{
	struct net2_workq_timer_container
			*c;
	struct net2_workq_timer *t;
	/*
	 * 2 important handles:
	 * - [0] the shutdown event, set when the timer thread is to stop.
	 * - [1] the timer event, which expires every once in a while and
	 *       for which we'll enqueue jobs.
	 * Since the shutdown event is more important than the timer event,
	 * the shutdown event must be the first event in the list.
	 */
	HANDLE		 handles[2];
	DWORD		 wait;
	FILETIME	 now_ft;
	LARGE_INTEGER	 now;

	handles[0] = c->shutdown;
	handles[1] = c->timer = CreateWaitableTimer(NULL, TRUE, NULL);

	for (;;) {
		wait = WaitForMultipleObjects(2, handles, FALSE, 5000);

		switch (wait) {
		case WAIT_OBJECT_0 + 0:
			/* Shutdown event, handled in loop guard. */
			_endthreadex(0);
			break;
		case WAIT_OBJECT_0 + 1:
		case WAIT_TIMEOUT:
			/* Timer expired. */
			net2_spinlock_lock(&c->spl);

			/*
			 * Sort timeouts, placing the ones that are first
			 * to expire at the end of the array.
			 */
			if (c->need_sort)
				timer_sort(c);

			/*
			 * Update now.
			 */
			GetSystemTimeAsFileTime(&now_ft);
			now.HighPart = now_ft.dwHighDateTime;
			now.LowPart = now_ft.dwLowDateTime;

			/* Activate all timed-out jobs. */
			while (c->nwq_timers > 0) {
				t = c->wq_timers[c->nwq_timers - 1];

				/* Skip deactivated timers. */
				if (t->timeo_at.QuadPart == 0) {
					t->active = 0;
					c->nwq_timers--;
					continue;
				}

				if (t->timeo_at.QuadPart <= now.QuadPart) {
					/* Activate timed out job. */
					t->active = 0;
					c->nwq_timers--;
					net2_workq_activate(&t->job, 0);
				} else {
					/* Update expiry. */
					c->expires = t->timeo_at;
					SetWaitableTimer(c->timer, &c->expires,
					    60000 /* msec */, NULL, NULL,
					    FALSE);
					break;
				}
			}
			/* If we have no timers enqueued, cancel the timer. */
			if (c->nwq_timers == 0)
				CancelWaitableTimer(c->timer);

			net2_spinlock_unlock(&c->spl);
			break;
		case WAIT_FAILED:
			errx(EX_OSERR, "net2_workq_timer wait failed, "
			    "GetLastError() = %ul", GetLastError());
			break;
		case WAIT_ABANDONED_0 + 0:
		case WAIT_ABANDONED_0 + 1:
		default:
			/* Error. */
			errx(EX_OSERR, "net2_workq_timer fail");
			break;
		}
	}
}

/* Thread name exception (MSVC debugger listens to this). */
static const DWORD MS_VC_EXCEPTION=0x406D1388;

#pragma pack(push,8)
typedef struct tagTHREADNAME_INFO
{
	DWORD dwType; // Must be 0x1000.
	LPCSTR szName; // Pointer to name (in user addr space).
	DWORD dwThreadID; // Thread ID (-1=caller thread).
	DWORD dwFlags; // Reserved for future use, must be zero.
} THREADNAME_INFO;
#pragma pack(pop)

static void
SetThreadName(DWORD dwThreadID, char *threadName)
{
	THREADNAME_INFO info;
	info.dwType = 0x1000;
	info.szName = threadName;
	info.dwThreadID = dwThreadID;
	info.dwFlags = 0;

	__try
	{
		RaiseException(MS_VC_EXCEPTION, 0,
		    sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
}

ILIAS_NET2_LOCAL struct net2_workq_timer_container*
net2_workq_timer_container_new()
{
	struct net2_workq_timer_container
				*c;
	unsigned int		 tid;

	if ((c = net2_malloc(sizeof(*c))) == NULL)
		goto fail_0;
	if (net2_spinlock_init(&c->spl))
		goto fail_1;
	if ((c->shutdown = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL)
		goto fail_2;

	c->timer = INVALID_HANDLE_VALUE;
	c->nwqt_arrsz = 0;
	c->wq_timers = NULL;
	c->nwq_timers = 0;
	c->need_sort = 0;

	/*
	 * Start worker thread.  The worker thread will initialize the
	 * timer object.
	 */
	if ((c->thread = (HANDLE)_beginthreadex(NULL, 0, &worker, c,
	    0, &tid)) == (HANDLE)-1)
		goto fail_3;
	SetThreadName(tid, "timer worker thread");
	while ((volatile HANDLE)c->timer == INVALID_HANDLE_VALUE)
		SwitchToThread();
	if (c->timer == NULL)
		goto fail_4;

	return c;


fail_4:
	SetEvent(c->shutdown);
	if (WaitForSingleObject(c->thread, INFINITE) != WAIT_OBJECT_0) {
		warnx("WaitForSingleObject thread failed to be collectable");
	}
fail_3:
	CloseHandle(c->shutdown);
fail_2:
	net2_spinlock_deinit(&c->spl);
fail_1:
	net2_free(c);
fail_0:
	return NULL;
}
/* Destroy workq timer container. */
ILIAS_NET2_LOCAL void
net2_workq_timer_container_destroy(struct net2_workq_timer_container *c)
{
	/* XXX remove timers? */

	assert(c->nwq_timers == 0);
	net2_spinlock_deinit(&c->spl);
	net2_free(c->wq_timers);
	CloseHandle(c->timer);
	net2_free(c);
}
/* Add a timer to the container. */
static int
net2_workq_timer_container_add(struct net2_workq_timer_container *c,
    struct net2_workq_timer *t, struct timeval *tv)
{
	struct net2_workq_timer	**ct;
	int			 error;

	net2_spinlock_lock(&c->spl);

	/* Assign timeout. */
	tv2li(&t->timeo_at, tv);
	assert(t->timeo_at.QuadPart > 0);

	/* If already on the queue, simply update the timeout. */
	if (t->active) {
		c->need_sort = 1;
		goto test_expire;
	}

	/* Grow the array that holds the timers. */
	if (c->nwqt_arrsz == c->nwq_timers) {
		if ((ct = net2_recalloc(c->wq_timers, 2 * c->nwqt_arrsz,
		    sizeof(*c->wq_timers))) == NULL) {
			error = ENOMEM;
			goto out;
		}
		c->wq_timers = ct;
		c->nwqt_arrsz *= 2;
	}

	/*
	 * If the insert will unsort the heap,
	 * mark the set as requiring sorting.
	 * We want the smallest element at the end of the array.
	 */
	if (c->nwq_timers > 0 &&
	    c->wq_timers[c->nwq_timers - 1]->timeo_at.QuadPart <
	    t->timeo_at.QuadPart)
		c->need_sort = 1;
	c->wq_timers[c->nwq_timers++] = t;

test_expire:
	/* Update timeout if the new timeout expires before any other. */
	if (c->expires.QuadPart > t->timeo_at.QuadPart) {
		c->expires = t->timeo_at;
		SetWaitableTimer(c->timer, &c->expires, 60000,
		    NULL, NULL, FALSE);
	}

out:
	net2_spinlock_unlock(&c->spl);
}
/*
 * Remove timer from container.
 *
 * This operation should only be run prior to a delete operation,
 * since it's hideously expensive (requiring a qsort).
 * To deactivate a timer, simply set its timeout to 0.
 */
static void
net2_workq_timer_container_del(struct net2_workq_timer_container *c,
    struct net2_workq_timer *t)
{
	if (!t->active)
		return;

	net2_spinlock_lock(&c->spl);
	if (c->nwq_timers == 0) {
		assert(!t->active);
		goto out;
	}

	/*
	 * Find ourselved using a timeo_at of 0 (nothing will be that low
	 * unless expired).
	 * The beauty is that it will still be sorted after removal.
	 */
	t->timeo_at.QuadPart = 0;	/* Just before newyear 1601. */
	timer_sort(c);
	while (c->nwq_timers > 0 &&
	    c->wq_timers[c->nwq_timers - 1]->timeo_at.QuadPart == 0) {
		c->wq_timers[c->nwq_timers - 1]->active = 0;
		c->nwq_timers--;
	}

out:
	net2_spinlock_unlock(&c->spl);
}
/* Deactivate a timer, preventing it from firing. */
static void
net2_workq_timer_container_deactivate(struct net2_workq_timer_container *c,
    struct net2_workq_timer *t)
{
	if (!t->active)
		return;

	net2_spinlock_lock(&c->spl);
	t->timeo_at.QuadPart = 0;
	net2_spinlock_unlock(&c->spl);
}
#endif /* WIN32 */
