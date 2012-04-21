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
#include <ilias/net2/memory.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <event2/event.h>

/* Pointer magic. */
#define PROMCB_JOB_OFFSET						\
	((size_t)(&((struct net2_promise_event*)0)->job))
#define JOB_2_PROMCB(_ev)						\
	((struct net2_promise_event*)((char*)(_ev) - PROMCB_JOB_OFFSET))

struct net2_promise {
	size_t			 refcnt;	/* Reference counter. */
	size_t			 combi_refcnt;	/* # combi referencing this. */
	struct net2_mutex	*mtx;		/* Promise guard. */
	struct net2_condition	*cnd;		/* Promise cond. var. */

	int			 flags;		/* State flags. */
#define NET2_PROM_F_RUNNING		0x00000010	/* Is running. */
#define NET2_PROM_F_CANCEL_REQ		0x00000020	/* Cancel requested. */
#define NET2_PROM_F_FINISHED		0x0000000f	/* Finish mask. */
#define NET2_PROM_F_FINISH_FIRED	0x00010000	/* Finish has fired. */
#define NET2_PROM_F_RUN_FIRED		0x00020000	/* Start has fired. */
#define NET2_PROM_F_NEED_RUN		0x00040000	/* Need to run. */
#define NET2_PROM_F_COMBI		0x10000000	/* Is combi prom. */

	uint32_t		 error;		/* Promise error. */
	void			*result;	/* Promise result. */

	struct {
		void		(*fn)(void *result, void *arg);
		void		*arg;
	}			 free;		/* Result release function. */

	TAILQ_HEAD(, net2_promise_event)
				 event[NET2_PROM__NUM_EVENTS];
						/* Events. */

	/* On destruction, run this callback. */
	struct {
		void		(*fn)(void*, void*);
		void		*arg0;
		void		*arg1;
	}			 on_destroy;
};

/* Combined promise. */
struct net2_promise_combi {
	struct net2_promise	 base;

	/* List of all referenced promises. */
	struct net2_promise	**prom;
	/* List of all events on those promises. */
	struct net2_promise_event
				*events;
	/* Number of promises. */
	size_t			 nprom;
	/* Number of unfinished promises. */
	size_t			 need_fin;

	net2_promise_ccb	 fn;
	struct net2_promise_event
				 work;
};


static int	net2_promise_init(struct net2_promise*);
static void	net2_promise_unlock(struct net2_promise*);
static int	net2_promise_flags(struct net2_promise*);
static void	prom_on_run(struct net2_promise*);
static void	prom_on_finish(struct net2_promise*);
static void	promise_wqcb(void *pcb_ptr,void*);
static void	pcb_destroy(struct net2_workq_job*);


/* Initialize promise. */
static int
net2_promise_init(struct net2_promise *p)
{
	int				 i;

	p->refcnt = 1;
	p->combi_refcnt = 0;
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
		TAILQ_INIT(&p->event[i]);

	p->on_destroy.fn = NULL;
	p->on_destroy.arg0 = p->on_destroy.arg1 = NULL;

	return 0;

fail_2:
	net2_mutex_free(p->mtx);
fail_1:
	net2_free(p);
fail_0:
	return ENOMEM;
}

/*
 * Allocate a new promise.
 */
ILIAS_NET2_EXPORT struct net2_promise*
net2_promise_new()
{
	struct net2_promise		*p;

	if ((p = net2_malloc(sizeof(*p))) == NULL)
		return NULL;
	if (net2_promise_init(p)) {
		net2_free(p);
		return NULL;
	}
	return p;
}

/*
 * Unlock a promise.
 *
 * Promise will be destroyed if it has become unreferenced.
 *
 * A promise can only stay alive if:
 * - refcnt > 0
 * - combi_refcnt > 0 && [has on-run event]
 *
 * A promise that has run events, but cannot stay alive, must end
 * with FIN_UNREF, unless another finish is already in progress.
 *
 * If the promise is still referenced by a combi promise, don't free
 * it, only run the FIN_UNREF callback.
 */
static void
net2_promise_unlock(struct net2_promise *p)
{
	int				 do_free;
	struct net2_promise_combi	*combi;
	size_t				 i;

	/* Set combi, if this is a combi event. */
	if (p->flags & NET2_PROM_F_COMBI) {
		combi = (struct net2_promise_combi*)p;
		assert(&combi->base == p);
	} else
		combi = NULL;

	/* Check if we can stay alive. */
	if (p->refcnt > 0 ||
	    (p->combi_refcnt > 0 && !TAILQ_EMPTY(&p->event[NET2_PROM_ON_RUN])))
		do_free = 0;
	else
		do_free = 1;

	/* Check if we need to finish with FIN_UNREF. */
	if (do_free && !TAILQ_EMPTY(&p->event[NET2_PROM_ON_FINISH])) {
		if (!(p->flags & NET2_PROM_F_FINISHED)) {
			p->flags |= NET2_PROM_FIN_UNREF;
			prom_on_finish(p);
		}
		do_free = 0; /* Events will need this promise. */
	}

	/* If we have combi promise refcount, don't free after all. */
	if (p->combi_refcnt > 0)
		do_free = 0;

	net2_mutex_unlock(p->mtx);

	if (!do_free)
		return;

	/*
	 * Free path.
	 */

	net2_mutex_free(p->mtx);
	net2_cond_free(p->cnd);

	/* Release result. */
	if (p->result != NULL && p->free.fn != NULL)
		(*p->free.fn)(p->result, p->free.arg);

	/* Break the combi chain. */
	if (combi != NULL) {
		for (i = 0; i < combi->nprom; i++)
			net2_promise_event_deinit(&combi->events[i]);

		for (i = 0; i < combi->nprom; i++) {
			net2_mutex_lock(combi->prom[i]->mtx);
			combi->prom[i]->combi_refcnt--;
			net2_promise_unlock(combi->prom[i]);
		}

		net2_free(combi->events);
		net2_free(combi->prom);
		net2_promise_event_deinit(&combi->work);
	}

	/* Invoke on_destroy callback. */
	if (p->on_destroy.fn != NULL)
		(*p->on_destroy.fn)(p->on_destroy.arg0, p->on_destroy.arg1);

	net2_free(p);
}

/* Set the on-destroy callback. */
ILIAS_NET2_EXPORT void
net2_promise_destroy_cb(struct net2_promise *p, void (*fn)(void*, void*),
    void *arg0, void *arg1)
{
	net2_mutex_lock(p->mtx);
	p->on_destroy.fn = fn;
	p->on_destroy.arg0 = fn;
	p->on_destroy.arg1 = fn;
	net2_mutex_unlock(p->mtx);
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
	struct net2_promise_event	*pcb;

	/* No locking: this is always called with p locked. */

	/* Fire only once. */
	if (p->flags & NET2_PROM_F_FINISH_FIRED)
		return;

	TAILQ_FOREACH(pcb, &p->event[NET2_PROM_ON_FINISH], promq)
		net2_workq_activate(net2_promise_event_wqjob(pcb));
	p->flags |= NET2_PROM_F_FINISH_FIRED;
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
	struct net2_promise_event	*pcb;
	struct net2_promise_combi	*c;
	struct net2_promise		**pp;
	int				 do_recurse;

	/* No locking: this is always called with p locked. */

	/* Fire only once. */
	if (p->flags & (NET2_PROM_F_RUN_FIRED | NET2_PROM_F_RUNNING |
	    NET2_PROM_F_FINISHED))
		return;

	/* Mark promise as needing to run. */
	do_recurse = !(p->flags & NET2_PROM_F_NEED_RUN);
	p->flags |= NET2_PROM_F_NEED_RUN;

	/* Combi event needs to wait until all dependant events completed. */
	if (p->flags & NET2_PROM_F_COMBI) {
		c = (struct net2_promise_combi*)p;
		assert(&c->base == p);

		if (c->need_fin > 0)
			return;
	}

	if ((pcb = TAILQ_FIRST(&p->event[NET2_PROM_ON_RUN])) != NULL) {
		assert(TAILQ_NEXT(pcb, promq) == NULL);
		net2_workq_activate(net2_promise_event_wqjob(pcb));
		p->flags |= (NET2_PROM_F_RUN_FIRED | NET2_PROM_F_RUNNING);
	}

	/*
	 * Recurse into referenced promises of combi promise.
	 */
	if (do_recurse && (p->flags & NET2_PROM_F_COMBI)) {
		c = (struct net2_promise_combi*)p;
		assert(&c->base == p);

		for (pp = c->prom; pp < c->prom + c->nprom; pp++) {
			net2_mutex_lock((*pp)->mtx);
			prom_on_run(*pp);
			net2_mutex_unlock((*pp)->mtx);
		}
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

/* Request cancellation of this request. */
ILIAS_NET2_EXPORT void
net2_promise_cancel(struct net2_promise *p)
{
	net2_mutex_lock(p->mtx);
	p->flags |= NET2_PROM_F_CANCEL_REQ;
	net2_promise_unlock(p);
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
	struct net2_promise_event	*cb;

	net2_mutex_lock(p->mtx);

	if (p->flags & (NET2_PROM_F_RUNNING | NET2_PROM_F_FINISHED))
		error = EDEADLK;
	else {
		p->flags |= NET2_PROM_F_RUNNING;
		error = 0;

		/* Remove any pending events. */
		while ((cb = TAILQ_FIRST(&p->event[NET2_PROM_ON_RUN])) !=
		    NULL) {
			cb->owner = NULL;
			TAILQ_REMOVE(&p->event[NET2_PROM_ON_RUN], cb, promq);
		}
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

/*
 * Start the promise.
 * Fires the on-run event if present.
 *
 * If an on-run event is set after this call, the on-run event will fire
 * immediately.
 */
ILIAS_NET2_EXPORT void
net2_promise_start(struct net2_promise *p)
{
	net2_mutex_lock(p->mtx);
	prom_on_run(p);
	net2_mutex_unlock(p->mtx);
}


/* Event callback, releases promise after completion. */
static void
promise_wqcb(void *pcb_ptr, void *arg1)
{
	struct net2_promise_event	*pcb;
	struct net2_promise		*p;

	pcb = pcb_ptr;

	/* Only fire once. */
	if (p == NULL)
		return;
	pcb->owner = NULL;

	p = pcb->owner;

	/* Remove from event list, but keep refcnt to promise. */
	net2_mutex_lock(p->mtx);
	TAILQ_REMOVE(&p->event[pcb->evno], pcb, promq);
	p->refcnt++;
	net2_mutex_unlock(p->mtx);

	/* Invoke callback. */
	assert(pcb->fn != NULL);
	(*pcb->fn)(pcb->arg0, arg1);

	/* Release. */
	net2_promise_release(p);
}

/* Handle event queue destruction. */
static void
pcb_destroy(struct net2_workq_job *j)
{
	struct net2_promise_event	*pcb;
	struct net2_promise		*p;

	pcb = JOB_2_PROMCB(j);
	p = pcb->owner;

	if (p != NULL) {
		pcb->owner = NULL;
		net2_mutex_lock(p->mtx);
		TAILQ_REMOVE(&p->event[pcb->evno], pcb, promq);
		net2_promise_unlock(p);
	}
}

static const struct net2_workq_job_cb promcb_cb = {
	NULL,
	NULL,
	&pcb_destroy,
	&pcb_destroy
};

static int
net2_promise_event_initf(struct net2_promise_event *cb, struct net2_promise *p,
    int evno, struct net2_workq *wq, net2_workq_cb fn, void *arg0, void *arg1,
    int fire)
{
	int				error = 0;

	if (evno < 0 || evno >= NET2_PROM__NUM_EVENTS) {
		error = EINVAL;
		goto fail_0;
	}

	if ((cb = net2_malloc(sizeof(*cb))) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}

	net2_mutex_lock(p->mtx);
	/*
	 * Can only have 1 on-run event, which can only be set
	 * when the promise is not running.
	 */
	if (evno == NET2_PROM_ON_RUN) {
		/* We have an event. */
		if (!TAILQ_EMPTY(&p->event[NET2_PROM_ON_RUN])) {
			error = EBUSY;
			goto fail_1;
		}
		/* We are running or have run. */
		if (p->flags & (NET2_PROM_F_RUNNING | NET2_PROM_F_FINISHED)) {
			error = EBUSY;
			goto fail_1;
		}
		/* May not be set on combi events. */
		if (p->flags & NET2_PROM_F_COMBI) {
			error = EBUSY;
			goto fail_1;
		}
	}

	/* Add event to promise. */
	TAILQ_INSERT_TAIL(&p->event[evno], cb, promq);
	/* Setup. */
	cb->fn = fn;
	cb->evno = evno;
	cb->owner = p;
	cb->arg0 = arg0;

	/* Create event callback. */
	if ((error = net2_workq_init_work(&cb->job, wq, &promise_wqcb, cb, arg1,
	    0)) != 0)
		goto fail_1;
	cb->job.callbacks = &promcb_cb;

	/*
	 * Handle state.
	 */
	switch (evno) {
	case NET2_PROM_ON_RUN:
		/* If we have a waiter or on-finish event, fire immediately. */
		if (p->flags & NET2_PROM_F_NEED_RUN)
			prom_on_run(p);
		break;
	case NET2_PROM_ON_FINISH:
		/* If the promise is finished, fire immediately. */
		if (p->flags & NET2_PROM_F_FINISH_FIRED)
			net2_workq_activate(&cb->job);
		/* On-finish event: we need to run. */
		if (fire)
			prom_on_run(p);
		break;
	}

	net2_mutex_unlock(p->mtx);

	return 0;


fail_1:
	net2_mutex_unlock(p->mtx);
	net2_free(cb);
fail_0:
	return error;
}

/* Add event to promise. */
ILIAS_NET2_EXPORT int
net2_promise_event_init(struct net2_promise_event *cb, struct net2_promise *p,
    int evno, struct net2_workq *wq, net2_workq_cb fn, void *arg0, void *arg1)
{
	return net2_promise_event_initf(cb, p, evno, wq, fn, arg0, arg1, 1);
}


/*
 * Promise callback, marks specific promise as done in the given combi.
 */
static void
combi_cb(void *c_ptr, void *ev_ptr)
{
	struct net2_promise_combi	*c = c_ptr;
	struct net2_promise_event	*ev = ev_ptr;
	struct net2_promise		*pp;
	size_t				 idx;

	idx = (size_t)(ev - c->events);
	assert(idx < c->nprom);
	pp = c->prom[idx];

	net2_mutex_lock(c->base.mtx);
	assert(c->need_fin > 0);
	c->need_fin--;

	/*
	 * Be selective with firing the on-run event.
	 * We cannot run until all events have completed.
	 *
	 * By only firing at that moment, we can release our old promises
	 * soon (thereby claiming less memory).  By not firing on any other
	 * occasion, we don't cause unstarted promises to run after all,
	 * thus we save CPU cycles.
	 */
	if (c->need_fin == 0)
		prom_on_run(&c->base);

	net2_promise_unlock(&c->base);
}

static void
combi_cb_invoke(void *c_ptr, void *arg)
{
	struct net2_promise_combi	*c = c_ptr;
	struct net2_promise_event	*events;
	struct net2_promise		**prom;
	size_t				 nprom, i;

	assert(c->need_fin == 0);
	assert(c->fn != NULL);
	assert(c->base.flags & NET2_PROM_F_RUNNING);

	/* Invoke combiner function. */
	(*c->fn)(&c->base, c->prom, c->nprom, arg);

	net2_mutex_lock(c->base.mtx);

	/* Detach all promises, in order to release them now. */
	events = c->events;
	c->events = NULL;
	prom = c->prom;
	c->prom = NULL;
	nprom = c->nprom;
	c->nprom = 0;

	net2_promise_unlock(&c->base);

	/* Release all promises and events. */
	for (i = 0; i < nprom; i++) {
		net2_promise_event_deinit(&events[i]);
		net2_mutex_lock(prom[i]->mtx);
		assert(prom[i]->combi_refcnt > 0);
		prom[i]->combi_refcnt--;
		net2_promise_unlock(prom[i]);
	}
}

/*
 * Create a promise that combines multiple promises.
 */
ILIAS_NET2_EXPORT struct net2_promise*
net2_promise_combine(struct net2_workq *wq, net2_promise_ccb fn,
    void *arg, struct net2_promise **pp, size_t np)
{
	struct net2_promise_combi	*c;
	struct net2_promise		*p;
	size_t				 i;
	size_t				 pdone;

	if (pp == NULL || np == 0)
		return NULL;
	/* Require a function pointer to handle the combined result. */
	if (fn == NULL || wq == NULL)
		return NULL;

	if ((c = net2_malloc(sizeof(*c))) == NULL)
		goto fail_0;
	p = &c->base;
	if (net2_promise_init(p))
		goto fail_1;

	/* Fill in depend chain, but don't reference the promises yet. */
	c->prom = net2_calloc(np, sizeof(*c->prom));
	c->events = net2_calloc(np, sizeof(*c->events));
	if (c->prom == NULL || c->events == NULL)
		goto fail_2;
	for (i = 0; i < np; i++) {
		if ((c->prom[i] = pp[i]) == NULL)
			goto fail_2;
	}

	/* Set up the combine function. */
	c->fn = fn;
	if (net2_promise_event_initf(&c->work, p, NET2_PROM_ON_RUN, wq,
	    &combi_cb_invoke, c, arg, 0))
		goto fail_2;

	/*
	 * Lock mutex, to prevent callbacks from modifying state
	 * prematurely.
	 */
	net2_mutex_lock(p->mtx);

	/* Reference all promises. */
	for (pdone = 0; pdone < np; pdone++) {
		if (net2_promise_event_initf(&c->events[pdone],
		    c->prom[pdone], NET2_PROM_ON_FINISH, wq, &combi_cb,
		    c, &c->events[pdone], 0))
			goto fail_4;

		/* Combi now has a reference to this mutex. */
		net2_mutex_lock(c->prom[pdone]->mtx);
		c->prom[pdone]->combi_refcnt++;
		net2_mutex_unlock(c->prom[pdone]->mtx);
	}

	/*
	 * From this point on, no failures are permitted.
	 */
	c->need_fin = c->nprom = pdone;

	/* Set flag to indicate this is a combined promise. */
	p->flags |= NET2_PROM_F_COMBI;

	net2_mutex_unlock(p->mtx);

	return p;


fail_4:
	while (pdone-- > 0) {
		/* Decrease reference count. */
		net2_mutex_lock(c->prom[pdone]->mtx);
		assert(c->prom[pdone]->combi_refcnt > 0);
		c->prom[pdone]->combi_refcnt--;
		/* mutex_unlock: promise is referenced by caller. */
		net2_mutex_unlock(c->prom[pdone]->mtx);

		net2_promise_event_deinit(&c->events[pdone]);
	}
fail_3:
	net2_promise_event_deinit(&c->work);
fail_2:
	if (c->prom != NULL)
		net2_free(c->prom);
	if (c->events != NULL)
		net2_free(c->events);
	net2_promise_release(p);
	c = NULL;
fail_1:
	if (c != NULL)
		net2_free(c);
fail_0:
	return NULL;
}
