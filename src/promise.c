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
#include <ilias/net2/promise.h>
#include <ilias/net2/mutex.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <event2/event.h>

struct net2_promise {
	size_t			 refcnt;	/* Reference counter. */
	struct net2_mutex	*mtx;		/* Promise guard. */
	struct net2_condition	*cnd;		/* Promise cond. var. */

	int			 flags;		/* State flags. */
#define NET2_PROM_F_RUNNING		0x00000010	/* Is running. */
#define NET2_PROM_F_CANCEL_REQ		0x00000020	/* Cancel requested. */
#define NET2_PROM_F_FINISHED		0x0000000f	/* Finish mask. */
#define NET2_PROM_F_FINISH_FIRED	0x00010000	/* Finish has fired. */
#define NET2_PROM_F_RUN_FIRED		0x00020000	/* Start has fired. */

	uint32_t		 error;		/* Promise error. */
	void			*result;	/* Promise result. */

	struct {
		void		(*fn)(void *result, void *arg);
		void		*arg;
	}			 free;		/* Result release function. */

	struct event		*event[NET2_PROM__NUM_EVENTS];
						/* Events. */
};


/*
 * Allocate a new promise.
 */
ILIAS_NET2_EXPORT struct net2_promise*
net2_promise_new()
{
	struct net2_promise		*p;
	int				 i;

	if ((p = malloc(sizeof(*p))) == NULL)
		goto fail_0;

	p->refcnt = 1;
	if ((p->mtx = net2_mutex_alloc()) == NULL)
		goto fail_1;
	if ((p->cnd = net2_cond_alloc()) == NULL)
		goto fail_2;
	p->flags = 0;
	p->error = 0;
	p->result = NULL;
	p->free.fn = NULL;
	p->free.arg = NULL;

	for (i = 0; i < NET2_PROM__NUM_EVENTS; i++)
		p->event[i] = NULL;

	return p;

fail_2:
	net2_mutex_free(p->mtx);
fail_1:
	free(p);
fail_0:
	return NULL;
}

/*
 * Unlock a promise.
 *
 * Promise will be destroyed if it has become unreferenced.
 */
static void
net2_promise_unlock(struct net2_promise *p)
{
	int				 do_free;

	do_free = (p->refcnt == 0);
	net2_mutex_unlock(p->mtx);

	if (do_free) {
		net2_mutex_free(p->mtx);
		net2_cond_free(p->cnd);

		/* Release result. */
		if (p->result != NULL && p->free.fn != NULL)
			(*p->free.fn)(p->result, p->free.arg);

		free(p);
	}
}

/* Read flags on promise. */
static int
net2_promise_flags(struct net2_promise *p)
{
	int				 flags;

	net2_mutex_lock(p->mtx);
	flags = p->flags;
	net2_mutex_unlock(p->mtx);
	return flags;
}

/* Fire the on-finish event. */
static void
prom_on_finish(struct net2_promise *p)
{
	/* No locking: this is always called with p locked. */

	/* Fire only once. */
	if (p->flags & NET2_PROM_F_FINISH_FIRED)
		return;

	if (p->event[NET2_PROM_ON_FINISH]) {
		event_active(p->event[NET2_PROM_ON_FINISH], 0, 0);
		p->flags |= NET2_PROM_F_FINISH_FIRED;
	}
}

/*
 * Fire the on-run event.
 *
 * This event only fires if:
 * at least one thread asked for the result of the promise and
 * the promise does not have the running state.
 *
 * Does not fire if the promise already holds a result.
 */
static void
prom_on_run(struct net2_promise *p)
{
	/* No locking: this is always called with p locked. */

	/* Fire only once. */
	if (p->flags & (NET2_PROM_F_RUN_FIRED | NET2_PROM_F_RUNNING |
	    NET2_PROM_F_FINISHED))
		return;

	if (p->event[NET2_PROM_ON_RUN]) {
		event_active(p->event[NET2_PROM_ON_RUN], 0, 0);
		p->flags |= (NET2_PROM_F_RUN_FIRED | NET2_PROM_F_RUNNING);
	}
}

/* Release reference to promise. */
ILIAS_NET2_EXPORT void
net2_promise_release(struct net2_promise *p)
{
	net2_mutex_lock(p->mtx);
	assert(p->refcnt > 0);
	p->refcnt--;
	net2_promise_unlock(p);
}

/* Add a reference to promise. */
ILIAS_NET2_EXPORT void
net2_promise_ref(struct net2_promise *p)
{
	net2_mutex_lock(p->mtx);
	p->refcnt++;
	assert(p->refcnt > 0);		/* Wrap around triggers this. */
	net2_mutex_unlock(p->mtx);
}

/* Set the promise to the error state. */
ILIAS_NET2_EXPORT int
net2_promise_set_error(struct net2_promise *p, uint32_t errcode, int flags)
{
	int				 error;

	net2_mutex_lock(p->mtx);

	/* Detect and fail duplicate finish messages. */
	if (p->flags & NET2_PROM_F_FINISHED) {
		error = EINVAL;
		goto out;
	}

	error = 0;	/* No failures permitted past this point. */

	/*
	 * Change state:
	 * - promise is no longer running
	 * - promise finished with error
	 * - store error code
	 */
	p->flags &= ~NET2_PROM_F_RUNNING;
	p->flags |= NET2_PROM_FIN_ERROR;	/* Finished with error. */
	p->error = errcode;

	/* Fire on-finish event. */
	prom_on_finish(p);
	/* Broadcast finish state. */
	net2_cond_broadcast(p->cnd);

	/* Decrement refcount if release was specified. */
	if (flags & NET2_PROMFLAG_RELEASE)
		p->refcnt--;

out:
	net2_promise_unlock(p);
	return error;
}

/* Return true iff the promise has a cancel request pending. */
ILIAS_NET2_EXPORT int
net2_promise_is_cancelreq(struct net2_promise *p)
{
	return net2_promise_flags(p) & NET2_PROM_F_CANCEL_REQ;
}

/* Mark promise as cancelled. */
ILIAS_NET2_EXPORT int
net2_promise_set_cancel(struct net2_promise *p, int flags)
{
	int				 error;

	net2_mutex_lock(p->mtx);

	/* Detect and fail duplicate finish messages. */
	if (p->flags & NET2_PROM_F_FINISHED) {
		error = EINVAL;
		goto out;
	}

	error = 0;	/* No failures permitted past this point. */

	/*
	 * Change state:
	 * - promise is no longer running
	 * - promise finished with error
	 * - store error code
	 */
	p->flags &= ~NET2_PROM_F_RUNNING;
	p->flags |= NET2_PROM_FIN_CANCEL;	/* Finished with cancel. */

	/* Fire on-finish event. */
	prom_on_finish(p);
	/* Broadcast finish state. */
	net2_cond_broadcast(p->cnd);

	/* Decrement refcount if release was specified. */
	if (flags & NET2_PROMFLAG_RELEASE)
		p->refcnt--;

out:
	net2_promise_unlock(p);
	return error;
}

/* Mark promise for succesful completion. */
ILIAS_NET2_EXPORT int
net2_promise_set_finok(struct net2_promise *p, void *result,
    void (*free_fn)(void*, void*), void *free_arg, int flags)
{
	int				 error;

	net2_mutex_lock(p->mtx);

	/* Detect and fail duplicate finish messages. */
	if (p->flags & NET2_PROM_F_FINISHED) {
		error = EINVAL;
		goto out;
	}

	error = 0;	/* No failures permitted past this point. */

	/*
	 * Change state:
	 * - promise is no longer running
	 * - promise finished with error
	 * - store error code
	 */
	p->flags &= ~NET2_PROM_F_RUNNING;
	p->flags |= NET2_PROM_FIN_OK;		/* Finished with succes. */
	p->result = result;
	p->free.fn = free_fn;
	p->free.arg = free_arg;

	/* Fire on-finish event. */
	prom_on_finish(p);
	/* Broadcast finish state. */
	net2_cond_broadcast(p->cnd);

	/* Decrement refcount if release was specified. */
	if (flags & NET2_PROMFLAG_RELEASE)
		p->refcnt--;

out:
	net2_promise_unlock(p);
	return error;
}

/*
 * Block promise from freeing its result.
 *
 * Requires promise to have completed.
 */
ILIAS_NET2_EXPORT int
net2_promise_dontfree(struct net2_promise *p)
{
	int				 error;

	net2_mutex_lock(p->mtx);

	if (!(p->flags & NET2_PROM_F_FINISHED)) {
		error = EINVAL;
		goto out;
	}

	p->free.fn = NULL;
	error = 0;

out:
	net2_mutex_unlock(p->mtx);

	return error;
}

/* Return true iff the promise is in the running state. */
ILIAS_NET2_EXPORT int
net2_promise_is_running(struct net2_promise *p)
{
	return net2_promise_flags(p) & NET2_PROM_F_RUNNING;
}

/*
 * Mark the promise as running.
 *
 * Returns EDEADLK if the promise was already running or has finished.
 *
 * This function is intended for promises that have their logic not started
 * using an event.
 */
ILIAS_NET2_EXPORT int
net2_promise_set_running(struct net2_promise *p)
{
	int				 error;

	net2_mutex_lock(p->mtx);

	if (p->flags & (NET2_PROM_F_RUNNING | NET2_PROM_F_FINISHED))
		error = EDEADLK;
	else {
		p->flags |= NET2_PROM_F_RUNNING;
		error = 0;
	}

	net2_mutex_unlock(p->mtx);
	return error;
}

/* Return the finish state of the promise. */
ILIAS_NET2_EXPORT int
net2_promise_is_finished(struct net2_promise *p)
{
	return net2_promise_flags(p) & NET2_PROM_F_FINISHED;
}

/* Return event pointer. */
ILIAS_NET2_EXPORT struct event*
net2_promise_get_event(struct net2_promise *p, int evno)
{
	struct event			*ev;

	if (evno < 0 || evno >= NET2_PROM__NUM_EVENTS)
		return NULL;

	net2_mutex_lock(p->mtx);
	ev = p->event[evno];
	net2_mutex_unlock(p->mtx);
	return ev;
}

/* Set event pointer. */
ILIAS_NET2_EXPORT int
net2_promise_set_event(struct net2_promise *p, int evno,
    struct event *new_ev, struct event **old_ev)
{
	if (evno < 0 || evno >= NET2_PROM__NUM_EVENTS)
		return EINVAL;

	net2_mutex_lock(p->mtx);
	if (old_ev)
		*old_ev = p->event[evno];
	p->event[evno] = new_ev;

	if (p->flags & NET2_PROM_F_FINISHED)
		prom_on_finish(p);

	net2_mutex_unlock(p->mtx);
	return 0;
}

/*
 * Read the result from the promise.
 *
 * Returns the finish state.
 * *result_ptr will contain the result, if FIN_OK.
 * *err_ptr will contain the error, if FIN_ERROR.
 */
ILIAS_NET2_EXPORT int
net2_promise_get_result(struct net2_promise *p, void **result_ptr, uint32_t *err_ptr)
{
	int				 rv;

	net2_mutex_lock(p->mtx);

	/* Read result state. */
	rv = (p->flags & NET2_PROM_F_FINISHED);

	/* Assign result pointer. */
	if (result_ptr != NULL) {
		if (rv == NET2_PROM_FIN_OK)
			*result_ptr = p->result;
		else
			*result_ptr = NULL;
	}

	/* Assign error code. */
	if (err_ptr != NULL) {
		if (rv == NET2_PROM_FIN_ERROR)
			*err_ptr = p->error;
		else
			*err_ptr = 0;
	}

	net2_mutex_unlock(p->mtx);

	return rv;
}

/*
 * Wait until the promise finishes.
 *
 * Returns:
 * 0:		event has finished
 * EDEADLK:	event is not running
 */
ILIAS_NET2_EXPORT int
net2_promise_wait(struct net2_promise *p)
{
	int				 error;

	net2_mutex_lock(p->mtx);

	/* Try to start the request now, unless it already is running or
	 * completed. */
	prom_on_run(p);

	while (!(p->flags & NET2_PROM_F_FINISHED)) {
		if (!(p->flags & NET2_PROM_F_RUNNING)) {
			error = EDEADLK;
			goto out;
		}

		net2_cond_wait(p->cnd, p->mtx);
	}

	error = 0;

out:
	net2_mutex_unlock(p->mtx);
	return error;
}
