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
#include <ilias/net2/mutex.h>
#include <ilias/net2/memory.h>
#include <bsd_compat/sysexits.h>
#include <bsd_compat/error.h>
#include <windows.h>
#include <assert.h>

#ifndef HAVE_SYS_QUEUE_H
#include <bsd_compat/queue.h>
#else
#include <sys/queue.h>
#endif

#ifndef HAVE_SYSEXITS_H
#include <bsd_compat/sysexits.h>
#else
#include <sys/sysexits.h>
#endif

struct net2_mutex {
	CRITICAL_SECTION	s;
	volatile int		locks;
};


/*
 * Allocate a new mutex.
 */
ILIAS_NET2_LOCAL struct net2_mutex*
net2_mutex_alloc()
{
	struct net2_mutex	*m;

	if ((m = net2_malloc(sizeof(*m))) == NULL)
		return NULL;
	InitializeCriticalSection(&m->s);
	m->locks = 0;
	return m;
}

/*
 * Free a mutex.
 */
ILIAS_NET2_LOCAL void
net2_mutex_free(struct net2_mutex *m)
{
	if (m) {
		DeleteCriticalSection(&m->s);
		net2_free(m);
	}
}

/*
 * Lock a mutex.
 */
ILIAS_NET2_LOCAL void
net2_mutex_lock(struct net2_mutex *m)
{
	EnterCriticalSection(&m->s);
	assert(m->locks == 0);	/* ilias_net2 does not do recursive locking. */
	m->locks++;
}

/*
 * Unlock a previously locked mutex.
 */
ILIAS_NET2_LOCAL void
net2_mutex_unlock(struct net2_mutex *m)
{
	assert(m->locks > 0);
	LeaveCriticalSection(&m->s);
}


struct net2_condition {
	CRITICAL_SECTION	s;
	TAILQ_HEAD(, waiter)	wq;
};

struct waiter {
	TAILQ_ENTRY(waiter)	entry;
	HANDLE			event;
};

/* Thread wakeup. */
static __inline void
wakeup(struct waiter *w)
{
	if (SetEvent(w->event) == 0) {
		/* SetEvent failure. */
		warnx("Unable to wake condition: error %u",
		    (unsigned int)GetLastError());
	}
}

static __inline void
wait(struct waiter *w)
{
	DWORD	result;

restart:
	result = WaitForSingleObject(w->event, INFINITE);
	switch (result) {
	case WAIT_OBJECT_0:
		/* We got signalled. */
		break;
	case WAIT_TIMEOUT:	/* Infinite timed out..? */
		errx(EX_SOFTWARE, "condition infinite timeout expired");
		break;
	case WAIT_FAILED:
		warnx("condition wait failure: error %u", (unsigned int)GetLastError());
		goto restart;
	case WAIT_ABANDONED:
		errx(EX_SOFTWARE, "condition wait abandoned, but event is not a mutex");
		break;
	}
}

/* Create wait object. */
static __inline void
init_waiter(struct waiter *w)
{
	/* An event that requires manual reset and is currently inactive. */
	w->event = CreateEvent(NULL, TRUE, FALSE, NULL);

	if (w->event == NULL) {
		/* Failed to create event. */
		errx(EX_UNAVAILABLE, "Unable to create condition wait-event: "
		    "error %u.", (unsigned int)GetLastError());
	}
}

/* Destroy wait object. */
static __inline void
destroy_waiter(struct waiter *w)
{
	CloseHandle(w->event);
}

/* Create a new condition variable. */
ILIAS_NET2_LOCAL struct net2_condition*
net2_cond_alloc()
{
	struct net2_condition	*c;

	if ((c = net2_malloc(sizeof(*c))) == NULL)
		return NULL;

	InitializeCriticalSection(&c->s);
	TAILQ_INIT(&c->wq);
	return c;
}

/* Free a condition variable. */
ILIAS_NET2_LOCAL void
net2_cond_free(struct net2_condition *c)
{
	EnterCriticalSection(&c->s);
	assert(TAILQ_EMPTY(&c->wq));
	LeaveCriticalSection(&c->s);

	DeleteCriticalSection(&c->s);
}

/* Wait for a condition variable to signal. */
ILIAS_NET2_LOCAL void
net2_cond_wait(struct net2_condition *c, struct net2_mutex *m)
{
	struct waiter		self;
	int			locks, i;

	assert(m->locks > 0);

	init_waiter(&self);
	EnterCriticalSection(&c->s);

	/* Unlock m. */
	locks = m->locks;
	for (i = 0; i < locks; i++)
		LeaveCriticalSection(&m->s);
	m->locks = 0;

	TAILQ_INSERT_TAIL(&c->wq, &self, entry);
	LeaveCriticalSection(&c->s);
	wait(&self);

	/* Relock m. */
	for (i = 0; i < locks; i++)
		EnterCriticalSection(&m->s);
	m->locks = locks;

	destroy_waiter(&self);
}

/* Signal a single thread blocked on this condition variable. */
ILIAS_NET2_LOCAL void
net2_cond_signal(struct net2_condition *c)
{
	struct waiter		*qhead;

	EnterCriticalSection(&c->s);
	if ((qhead = TAILQ_FIRST(&c->wq)) == NULL)
		goto out;
	TAILQ_REMOVE(&c->wq, qhead, entry);

	/* Wakeup qhead. */
	wakeup(qhead);

out:
	LeaveCriticalSection(&c->s);
}

/* Signal all threads blocked on this condition variable. */
ILIAS_NET2_LOCAL void
net2_cond_broadcast(struct net2_condition *c)
{
	struct waiter		*qhead;

	EnterCriticalSection(&c->s);

	while ((qhead = TAILQ_FIRST(&c->wq)) != NULL) {
		TAILQ_REMOVE(&c->wq, qhead, entry);

		/* Wakeup qhead. */
		wakeup(qhead);
	}

	LeaveCriticalSection(&c->s);
}
