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
#include <ilias/net2/config.h>
#include <ilias/net2/bsd_compat/sysexits.h>
#include <ilias/net2/bsd_compat/error.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <assert.h>

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <ilias/net2/bsd_compat/queue.h>
#endif

#ifdef HAVE_SYSEXITS_H
#include <sys/sysexits.h>
#else
#include <ilias/net2/bsd_compat/sysexits.h>
#endif

struct net2_mutex {
#ifndef NDEBUG
	volatile unsigned int	n2m_magic;
#define M_MAGIC	0x7fb838a8
#endif
	CRITICAL_SECTION	s;
	volatile int		locks;
};

struct net2_condition {
#ifndef NDEBUG
	volatile unsigned int	n2c_magic;
#define C_MAGIC	0xb9d9d9fb
#endif
	CRITICAL_SECTION	s;
	TAILQ_HEAD(, waiter)	wq;
};

#ifndef NDEBUG
#define ASSERT_M_MAGIC(_m)	assert((_m) != NULL && (_m)->n2m_magic == M_MAGIC)
#define ASSERT_C_MAGIC(_c)	assert((_c) != NULL && (_c)->n2c_magic == C_MAGIC)
#else
#define ASSERT_M_MAGIC(_m)	do {} while (0)
#define ASSERT_C_MAGIC(_c)	do {} while (0)
#endif


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
	m->n2c_magic = MAGIC;
	return m;
}

/*
 * Free a mutex.
 */
ILIAS_NET2_LOCAL void
net2_mutex_free(struct net2_mutex *m)
{
	if (m) {
		ASSERT_M_MAGIC(m);
		DeleteCriticalSection(&m->s);
		m->n2c_magic = 0;
		net2_free(m);
	}
}

/*
 * Lock a mutex.
 */
ILIAS_NET2_LOCAL void
net2_mutex_lock(struct net2_mutex *m)
{
	ASSERT_M_MAGIC(m);
	EnterCriticalSection(&m->s);
	assert(m->locks == 0);	/* ilias_net2 does not do recursive locking. */
	m->locks++;
}

/*
 * Try lock.  Won't block but may fail to acquire lock.
 *
 * Returns false on error, true on succes.
 */
ILIAS_NET2_LOCAL int
net2_mutex_trylock(struct net2_mutex *m)
{
	ASSERT_M_MAGIC(m);
	if (!TryEnterCriticalSection(&m->s))
		return 0;
	assert(m->locks == 0);	/* ilias_net2 does not do recursive locking. */
	m->locks++;
	return 1;
}

/*
 * Unlock a previously locked mutex.
 */
ILIAS_NET2_LOCAL void
net2_mutex_unlock(struct net2_mutex *m)
{
	ASSERT_M_MAGIC(m);
	assert(m->locks > 0);
	m->locks--;
	LeaveCriticalSection(&m->s);
}


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
	c->n2c_magic = C_MAGIC;
	return c;
}

/* Free a condition variable. */
ILIAS_NET2_LOCAL void
net2_cond_free(struct net2_condition *c)
{
	if (!c)
		return;
	ASSERT_C_MAGIC(c);
	EnterCriticalSection(&c->s);
	assert(TAILQ_EMPTY(&c->wq));
	LeaveCriticalSection(&c->s);

	DeleteCriticalSection(&c->s);
	c->n2c_magic = 0;
	net2_free(c);
}

/* Wait for a condition variable to signal. */
ILIAS_NET2_LOCAL void
net2_cond_wait(struct net2_condition *c, struct net2_mutex *m)
{
	struct waiter		self;
	int			locks, i;

	ASSERT_C_MAGIC(c);
	ASSERT_M_MAGIC(m);
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
	assert(m->locks == 0);
	m->locks = locks;

	destroy_waiter(&self);
}

/* Signal a single thread blocked on this condition variable. */
ILIAS_NET2_LOCAL void
net2_cond_signal(struct net2_condition *c)
{
	struct waiter		*qhead;

	ASSERT_C_MAGIC(c);
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

	ASSERT_C_MAGIC(c);
	EnterCriticalSection(&c->s);

	while ((qhead = TAILQ_FIRST(&c->wq)) != NULL) {
		TAILQ_REMOVE(&c->wq, qhead, entry);

		/* Wakeup qhead. */
		wakeup(qhead);
	}

	LeaveCriticalSection(&c->s);
}
