#include <ilias/net2/mutex.h>
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
};


/*
 * Allocate a new mutex.
 */
ILIAS_NET2_LOCAL struct net2_mutex*
net2_mutex_alloc()
{
	struct net2_mutex	*m;

	if ((m = malloc(sizeof(*m))) == NULL)
		return NULL;
	InitializeCriticalSection(&m->s);
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
		free(m);
	}
}

/*
 * Lock a mutex.
 */
ILIAS_NET2_LOCAL void
net2_mutex_lock(struct net2_mutex *m)
{
	EnterCriticalSection(&m->s);
}

/*
 * Unlock a previously locked mutex.
 */
ILIAS_NET2_LOCAL void
net2_mutex_unlock(struct net2_mutex *m)
{
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

	if ((c = malloc(sizeof(*c))) == NULL)
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

	init_waiter(&self);
	EnterCriticalSection(&c->s);
	LeaveCriticalSection(&m->s);	/* unlock m */
	TAILQ_INSERT_TAIL(&c->wq, &self, entry);
	LeaveCriticalSection(&c->s);
	wait(&self);
	EnterCriticalSection(&m->s);	/* lock m */
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