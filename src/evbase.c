#include <ilias/net2/evbase.h>
#include <ilias/net2/mutex.h>
#include <ilias/net2/thread.h>
#include <bsd_compat/error.h>
#include <event2/event.h>
#include <stdlib.h>
#include <assert.h>

static void
threadping(int fd, short what, void *arg)
{
	return; /* No work, apart from keeping the event loop alive. */
}

/* Create a new shared event base. */
ILIAS_NET2_EXPORT struct net2_evbase*
net2_evbase_new()
{
	struct net2_evbase *b;

	b = malloc(sizeof(*b));
	b->refcnt = 1;
	b->thread = NULL;

	b->mtx = net2_mutex_alloc();
	if (b->mtx == NULL) {
		free(b);
		return NULL;
	}

	b->evbase = event_base_new();
	if (b->evbase == NULL) {
		net2_mutex_free(b->mtx);
		free(b);
		return NULL;
	}

	b->threadlive = event_new(b->evbase, -1, EV_PERSIST, &threadping, b);
	if (b->threadlive == NULL) {
		event_base_free(b->evbase);
		net2_mutex_free(b->mtx);
		free(b);
		return NULL;
	}

	return b;
}

/*
 * Release a shared event base.
 *
 * If the last reference to the event base is released, the event base will
 * be freed.
 */
ILIAS_NET2_EXPORT void
net2_evbase_release(struct net2_evbase *b)
{
	if (b == NULL)
		return;

	net2_mutex_lock(b->mtx);
	assert(b->refcnt > 0);
	if (--b->refcnt == 0) {
		net2_mutex_unlock(b->mtx);
		if (b->thread)
			net2_thread_free(b->thread);
		net2_mutex_free(b->mtx);
		event_free(b->threadlive);
		event_base_free(b->evbase);
		free(b);
	} else
		net2_mutex_unlock(b->mtx);
}

/*
 * Add a reference to an event base.
 */
ILIAS_NET2_EXPORT void
net2_evbase_ref(struct net2_evbase *b)
{
	if (b == NULL)
		return;
	net2_mutex_lock(b->mtx);
	b->refcnt++;
	assert(b->refcnt != 0);
	net2_mutex_unlock(b->mtx);
}

/*
 * Thread worker.
 * Runs the event loop in its own thread.
 */
static void*
net2_evbase_worker(void *bptr)
{
	struct net2_evbase	*b = bptr;
	int			 rv;

	/* Wait until net2_evbase_threadstart is ready. */
	net2_mutex_lock(b->mtx);
	net2_mutex_unlock(b->mtx);

	if ((rv = event_base_loop(b->evbase, 0)) != 0)
		warnx("libevent loop exited with %d", rv);

	net2_evbase_release(b);
	return NULL;
}

/* Start a thread to manage this event base. */
ILIAS_NET2_EXPORT int
net2_evbase_threadstart(struct net2_evbase *b)
{
	/* wakeup: wake up every so often to check if something important
	 * (like net2_evbase_threadstop) happened. */
	const struct timeval
			wakeup = { 1, 0 };
	int		rv = -1;

	net2_mutex_lock(b->mtx);
	if (b->thread != NULL)
		goto fail;
	if (event_add(b->threadlive, &wakeup))
		goto fail;
	if ((b->thread = net2_thread_new(&net2_evbase_worker, b)) == NULL)
		goto fail;
	b->refcnt++;

	rv = 0;
fail:
	net2_mutex_unlock(b->mtx);
	return rv;
}

/* Stop the event base. */
ILIAS_NET2_EXPORT int
net2_evbase_threadstop(struct net2_evbase *b, int flags)
{
	net2_mutex_lock(b->mtx);
	if (b->thread == NULL) {
		net2_mutex_unlock(b->mtx);
		return 0;
	}
	/* Don't stop the thread-live if WAITONLY was specified. */
	if (!(flags & NET2_EVBASE_WAITONLY) && event_del(b->threadlive)) {
		warnx("failed to remove thread live event");
		net2_mutex_unlock(b->mtx);
		return -1;
	}
	if (event_base_loopbreak(b->evbase)) {
		warnx("failed to loopbreak evbase");
		net2_mutex_unlock(b->mtx);
		return -1;
	}

	net2_mutex_unlock(b->mtx);
	if (net2_thread_join(b->thread, NULL)) {
		warnx("failed to join evbase thread");
		return -1;
	}
	net2_mutex_lock(b->mtx);

	net2_thread_free(b->thread);
	b->thread = NULL;
	net2_mutex_unlock(b->mtx);
	return 0;
}
