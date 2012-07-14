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
#include <ilias/net2/event.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/bsd_compat/error.h>
#include <ilias/net2/bsd_compat/sysexits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>


/*
 * Event type.
 *
 * Changing and blocking on event requires mtx.
 * Active can be read without locking, since the only case in which it will
 * be non-zero, will be during or after it is transition to the signalled
 * state.
 */
struct net2_event {
	pthread_mutex_t		mtx;	/* Write access and wait. */
	pthread_cond_t		cnd;	/* Signal condition. */
	int			active;	/* State. */
};

/* Create new event. */
ILIAS_NET2_LOCAL struct net2_event*
net2_event_alloc()
{
	struct net2_event	*ev;

	if ((ev = net2_malloc(sizeof(*ev))) == NULL)
		goto fail_0;
	if (pthread_mutex_init(&ev->mtx, NULL))
		goto fail_1;
	if (pthread_cond_init(&ev->cnd, NULL))
		goto fail_2;
	ev->active = 0;
	return ev;

fail_3:
	pthread_cond_destroy(&ev->cnd);
fail_2:
	pthread_mutex_destroy(&ev->mtx);
fail_1:
	net2_free(ev);
fail_0:
	return NULL;
}

/* Free event. */
ILIAS_NET2_LOCAL void
net2_event_free(struct net2_event *ev)
{
	pthread_cond_destroy(&ev->cnd);
	pthread_mutex_destroy(&ev->mtx);
	net2_free(ev);
}

/* Wait for event to become active. */
ILIAS_NET2_LOCAL void
net2_event_wait(struct net2_event *ev)
{
	int rv;

	/* Short cut. */
	if (ev->active)
		return;

	/* Acquire mutex. */
	while ((rv = pthread_mutex_lock(&ev->mtx)) != 0) {
		switch (rv) {
		case EINTR:
		case ETIMEDOUT:
			break;
		case EDEADLK:
			warnx("%s: %s", "pthread_mutex_lock", strerror(rv));
			abort();
		default:
			errx(EX_OSERR, "%s: %s", "pthread_mutex_lock",
			    strerror(rv));
		}
	}

	/* Wait until active state is reached. */
	while (!ev->active)
		pthread_cond_wait(&ev->cnd, &ev->mtx);

	/* Release lock. */
	pthread_mutex_unlock(&ev->mtx);
	return;
}

/* Change the event to active state. */
ILIAS_NET2_LOCAL void
net2_event_signal(struct net2_event *ev)
{
	int rv;

	/* Short cut. */
	if (ev->active)
		return;

	/* Acquire mutex. */
	while ((rv = pthread_mutex_lock(&ev->mtx)) != 0) {
		switch (rv) {
		case EINTR:
		case ETIMEDOUT:
			break;
		case EDEADLK:
			warnx("%s: %s", "pthread_mutex_lock", strerror(rv));
			abort();
		default:
			errx(EX_OSERR, "%s: %s", "pthread_mutex_lock",
			    strerror(rv));
		}
	}

	/* Activate event. */
	ev->active = 1;
	pthread_cond_broadcast(&ev->cnd);

	/* Unlock. */
	pthread_mutex_unlock(&ev->mtx);
}

/* Test if the event is active. */
ILIAS_NET2_LOCAL int
net2_event_test(struct net2_event *ev)
{
	return ev->active;
}
