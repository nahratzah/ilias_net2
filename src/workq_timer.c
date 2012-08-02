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
#include <ev.h>

#ifdef EV_C
#include EV_C
#endif


struct net2_workq_timer {
	struct net2_workq_job	 job;		/* Base job implementation. */
	struct ev_timer		 watcher;	/* Timer watcher. */

	ev_tstamp		 timeo_at;	/* When timeout must fire. */
	struct timeval		 delay;		/* Last set delay. */

	struct ev_loop		*loop;		/* Event loop. */
	struct net2_mutex	*loopmtx;	/* Protect loop pointer. */
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
