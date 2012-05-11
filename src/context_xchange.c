#include <ilias/net2/context_xchange.h>
#include <ilias/net2/promise.h>
#include <ilias/net2/mutex.h>
#include <ilias/net2/thread.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/xchange.h>
#include <ilias/net2/context.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/config.h>
#include <ilias/net2/bsd_compat/clock.h>
#include <assert.h>
#include <errno.h>

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <ilias/net2/bsd_compat/queue.h>
#endif
#ifdef HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include <ilias/net2/bsd_compat/tree.h>
#endif


/* Job queue. */
struct job {
	int		 xchange;	/* Xchange algorithm ID. */
	size_t		 keysize;	/* Key size. */

	struct net2_promise
			*promise;	/* Output promise. */

	RB_ENTRY(job)	 set;
	TAILQ_ENTRY(job) queue;
};

/* Key set. */
struct key {
	struct net2_buffer
			*initbuf;	/* Initial buffer. */
	struct net2_xchange_ctx
			*xchange;	/* Xchange implementation. */

	int		 xchange_alg;	/* Xchange algorithm ID. */
	size_t		 keysize;	/* Key size. */

	struct timeval	 creat;		/* Creation timestamp. */

	RB_ENTRY(key)	 set;
};

/* Scope of the cache. */
struct scope {
	RB_HEAD(ctx_key, key)
			 keys;		/* All generated keys. */
	RB_HEAD(ctx_job, job)
			 jobs;		/* All requested keys. */

	TAILQ_HEAD(, job)
			 jobq;		/* FIFO with requests. */

	struct net2_mutex
			*mtx;		/* Guard. */
	struct net2_condition
			*wait;		/* Wakeup condition. */
	volatile int	 stop;		/* Stop signal. */
	struct net2_thread
			*worker;	/* Worker thread. */
};


/* Keys expire every TIMEOUT interval. */
static const struct timeval TIMEOUT = {
	30 * 60,	/* 30 minutes */
	0
};


/* Comparator for jobs. */
static __inline int
job_cmp(struct job *j1, struct job *j2)
{
	int		 cmp = 0;

	/* First order: xchange comparison. */
	if (cmp == 0) {
		cmp = (j1->xchange < j2->xchange ? -1 :
		    j1->xchange > j2->xchange);
	}
	/* Second order: keysize comparison. */
	if (cmp == 0) {
		cmp = (j1->keysize < j2->keysize ? -1 :
		    j1->keysize > j2->keysize);
	}
	/* Last: promise identity comparison (guaranteed to be unique). */
	if (cmp == 0) {
		cmp = (j1->promise < j2->promise ? -1 :
		    j1->promise > j2->promise);
	}

	return cmp;
}

/* Comparator for keys. */
static __inline int
key_cmp(struct key *k1, struct key *k2)
{
	int		 cmp = 0;

	/* First order: xchange comparison. */
	if (cmp == 0) {
		cmp = (k1->xchange_alg < k2->xchange_alg ? -1 :
		    k1->xchange_alg > k2->xchange_alg);
	}
	/* Second order: keysize comparison. */
	if (cmp == 0) {
		cmp = (k1->keysize < k2->keysize ? -1 :
		    k1->keysize > k2->keysize);
	}

	return cmp;
}


RB_PROTOTYPE_STATIC(ctx_key, key, set, key_cmp);
RB_PROTOTYPE_STATIC(ctx_job, job, set, job_cmp);


/* Find key xchange, given algorithm and keysize. */
static struct key*
find_key(struct scope *s, int alg, size_t keysize)
{
	struct key	 search;

	search.xchange_alg = alg;
	search.keysize = keysize;
	return RB_FIND(ctx_key, &s->keys, &search);
}

/* Find key xchange, but fail for expired keys. */
static struct key*
find_key_unexpired(struct scope *s, int alg, size_t keysize)
{
	struct key	*key;
	struct timeval	 now, expire;

	/* Find the key. If the key is expired, pretend not to find it. */
	key = find_key(s, alg, keysize);
	if (key != NULL) {
		/*
		 * If the clock fails, assume the worst and treat the key as
		 * expired.
		 */
		if (tv_clock_gettime(CLOCK_MONOTONIC, &now))
			return NULL;

		/*
		 * Test if the key has expired.
		 */
		timeradd(&key->creat, &TIMEOUT, &expire);
		if (timercmp(&expire, &now, <=))
			return NULL;
	}

	return key;
}

/* Set result of job. Promise will be released. */
static void
apply_result_to_promise(struct net2_promise *p,
    struct net2_xchange_ctx *xchange, struct net2_buffer *buf)
{
	struct net2_ctx_xchange_factory_result
			*result;
	int		 error;

	/* Create and assign result. */
	result = net2_ctx_xchange_factory_result_new(xchange, buf);
	if (result != NULL) {
		error = net2_promise_set_finok(p, result,
		    &net2_ctx_xchange_factory_result_free, NULL,
		    NET2_PROMFLAG_RELEASE);
		if (error != 0)
			net2_ctx_xchange_factory_result_free(result, NULL);
	} else
		error = ENOMEM;

	/* If the operation fails, assign the error code. */
	if (error != 0) {
		error = net2_promise_set_error(p, error,
		    NET2_PROMFLAG_RELEASE);
		/*
		 * If even assigning the error code fails, just release the
		 * promise and hope everything works out.
		 * TODO: maybe this is a fatal error?
		 */
		if (error != 0)
			net2_promise_release(p);
	}
}

/*
 * Inform all jobs of a newly generated xchange and cache the result.
 */
static void
apply_result(struct scope *s, int alg, size_t keysize,
    struct net2_xchange_ctx *xchange, struct net2_buffer *buf)
{
	struct job	*j, *j_next, search;
	struct net2_ctx_xchange_factory_result
			*result;
	struct key	*key;

	/*
	 * First: inform all jobs that were waiting for this key of the
	 * completion.
	 */
	search.xchange = alg;
	search.keysize = keysize;
	search.promise = NULL;

	for (j = RB_NFIND(ctx_job, &s->jobs, &search);
	    j != NULL && j->xchange == alg && j->keysize == keysize;
	    j = j_next) {
		j_next = RB_NEXT(ctx_job, &s->jobs, j);

		/* Set result on job promise. */
		apply_result_to_promise(j->promise, xchange, buf);

		/* Job has completed, destroy it. */
		RB_REMOVE(ctx_job, &s->jobs, j);
		TAILQ_REMOVE(&s->jobq, j, queue);
		net2_free(j);
	}

	/*
	 * Second: create a cache entry for the new key.
	 * Note that if this fails, the worst that can happen is that we
	 * spend a few extra CPU cycles redoing the calculation (i.e. nothing
	 * that cannot be gracefully recovered from).
	 */
	key = find_key(s, alg, keysize);

	if (key == NULL) {
		if ((key = net2_malloc(sizeof(*key))) == NULL)
			return;
		key->xchange_alg = alg;
		key->keysize = keysize;

		key->initbuf = net2_buffer_copy(buf);
		key->xchange = net2_xchangectx_clone(xchange);
		if (key->initbuf == NULL || key->xchange == NULL)
			goto key_fail;

		if (RB_INSERT(ctx_key, &s->keys, key) != NULL)
			goto key_fail;
	} else {
		net2_buffer_free(key->initbuf);
		net2_xchangectx_free(key->xchange);

		key->initbuf = net2_buffer_copy(buf);
		key->xchange = net2_xchangectx_clone(xchange);
		if (key->initbuf == NULL || key->xchange == NULL)
			goto key_fail_remove;
	}

	/* Record the creation timestamp. */
	if (tv_clock_gettime(CLOCK_MONOTONIC, &key->creat))
		goto key_fail_remove;

key_fail_remove:
	RB_REMOVE(ctx_key, &s->keys, key);
key_fail:
	if (key->initbuf != NULL)
		net2_buffer_free(key->initbuf);
	if (key->xchange != NULL)
		net2_xchangectx_free(key->xchange);
	net2_free(key);
	return;
}

/* Create a new xchange promise. */
static struct net2_promise*
new_promise(struct scope *s, int alg, size_t keysize)
{
	struct net2_promise	*p;
	struct job		*j, *collide;
	struct key		*key;

	/* Check arguments. */
	if (s == NULL)
		return NULL;

	/* Allocate promise. */
	if ((p = net2_promise_new()) == NULL)
		return NULL;

	net2_mutex_lock(s->mtx);		/* LOCK */
	/* If no running worker, return immediately. */
	if (s->worker == NULL) {
		net2_mutex_unlock(s->mtx);
		net2_promise_release(p);
		return NULL;
	}

	/*
	 * If a key exists, simply assign it and immediately return.
	 */
	if ((key = find_key_unexpired(s, alg, keysize)) != NULL) {
		apply_result_to_promise(p, key->xchange, key->initbuf);
		net2_mutex_unlock(s->mtx);	/* UNLOCK */
		return p;
	}

	/*
	 * Key didn't exist, create a job to calculate it.
	 */
	j = net2_malloc(sizeof(*j));
	j->xchange = alg;
	j->keysize = keysize;
	j->promise = p;
	net2_promise_ref(p);

	/* Insert job into set and queue, wakeup the worker thread. */
	collide = RB_INSERT(ctx_job, &s->jobs, j);
	assert(collide == NULL);
	TAILQ_INSERT_TAIL(&s->jobq, j, queue);
	net2_cond_signal(s->wait);

	net2_mutex_unlock(s->mtx);		/* UNLOCK */
	return p;
}

/* Worker queue. */
static void*
worker(void *s_ptr)
{
	struct scope		*s;
	struct job		*j;
	struct net2_buffer	*initbuf;
	struct net2_xchange_ctx	*alice;
	int			 error;

	s = (struct scope*)s_ptr;

	net2_mutex_lock(s->mtx);
	for (;;) {
		while (!s->stop && (j = TAILQ_FIRST(&s->jobq)) == NULL)
			net2_cond_wait(s->wait, s->mtx);
		if (s->stop)
			break;

		RB_REMOVE(ctx_job, &s->jobs, j);
		TAILQ_REMOVE(&s->jobq, j, queue);

		net2_mutex_unlock(s->mtx);		/* UNLOCK */

		/* Set the promise as running. */
		if (net2_promise_set_running(j->promise)) {
			/* Already running? */
			net2_promise_release(j->promise);
			goto fail_no_error;
		}

		/* If the request is running or cancelled, skip it. */
		if (net2_promise_is_cancelreq(j->promise)) {
			net2_promise_set_cancel(j->promise,
			    NET2_PROMFLAG_RELEASE);
			goto fail_no_error;
		}

		/*
		 * Acquire xchange context and initial buffer.
		 */
		if ((initbuf = net2_buffer_new()) == NULL) {
			error = ENOMEM;
			goto fail;
		}
		if ((alice = net2_xchangectx_prepare(j->xchange, j->keysize,
		    NET2_XCHANGE_F_INITIATOR, initbuf)) == NULL) {
			net2_buffer_free(initbuf);
			error = ENOMEM;
			goto fail;
		}

		/* Apply to this job. */
		apply_result_to_promise(j->promise, alice, initbuf);

		/* Apply result to other waiting jobs. */
		net2_mutex_lock(s->mtx);		/* LOCK */
		apply_result(s, j->xchange, j->keysize, alice, initbuf);

		/*
		 * No longer need alice's initbuf or her
		 * (we cloned her though).
		 */
		net2_buffer_free(initbuf);
		net2_xchangectx_free(alice);

		net2_free(j);
		continue;


fail:
		/* Only reached for error case, while UNLOCKED. */
		assert(error != 0);
		error = net2_promise_set_error(j->promise, error,
		    NET2_PROMFLAG_RELEASE);
		/* Desperate: promise is not receptive to our error. */
		if (error)
			net2_promise_release(j->promise);

fail_no_error:
		net2_free(j);

		net2_mutex_lock(s->mtx);		/* LOCK */
	}

	/* Error each remaining promise with EINTR. */
	while ((j = TAILQ_FIRST(&s->jobq)) != NULL) {
		RB_REMOVE(ctx_job, &s->jobs, j);
		TAILQ_REMOVE(&s->jobq, j, queue);

		/* Set the promise as running. */
		if (net2_promise_set_running(j->promise)) {
			/* Already running? */
			net2_promise_release(j->promise);
			goto cancel_no_error;
		}

		/* If the request is running or cancelled, skip it. */
		if (net2_promise_is_cancelreq(j->promise)) {
			net2_promise_set_cancel(j->promise,
			    NET2_PROMFLAG_RELEASE);
			goto cancel_no_error;
		}

		error = net2_promise_set_error(j->promise, EINTR,
		    NET2_PROMFLAG_RELEASE);
		/* Desperate: promise is not receptive to our error. */
		if (error)
			net2_promise_release(j->promise);

cancel_no_error:
		net2_free(j);
	}

	net2_mutex_unlock(s->mtx);

	return NULL;
}

/* Stop the worker thread. */
static void
stop_worker(struct scope *s)
{
	struct net2_thread	*worker;

	net2_mutex_lock(s->mtx);
	if (s->worker == NULL) {
		net2_mutex_unlock(s->mtx);
		return;
	}

	s->stop = 1;
	net2_cond_signal(s->wait);
	worker = s->worker;
	s->worker = NULL;
	net2_mutex_unlock(s->mtx);

	net2_thread_join(worker, NULL);
	net2_thread_free(worker);
}

/* Create a new scope. */
static struct scope*
new_scope()
{
	struct scope		*s;

	if ((s = net2_malloc(sizeof(*s))) == NULL)
		goto fail_0;
	RB_INIT(&s->keys);
	RB_INIT(&s->jobs);
	TAILQ_INIT(&s->jobq);
	s->stop = 0;

	if ((s->mtx = net2_mutex_alloc()) == NULL)
		goto fail_1;
	if ((s->wait = net2_cond_alloc()) == NULL)
		goto fail_2;
	if ((s->worker = net2_thread_new(&worker, s,
	    "ctx_xchange_factory")) == NULL)
		goto fail_3;

	return s;


fail_3:
	net2_cond_free(s->wait);
fail_2:
	net2_mutex_free(s->mtx);
fail_1:
	net2_free(s);
fail_0:
	return NULL;
}

/* Destroy scope. */
static void
destroy_scope(struct scope *s)
{
	struct key		*key;

	if (s == NULL)
		return;

	stop_worker(s);
	net2_mutex_lock(s->mtx);

	/* Remove all cached keys. */
	while ((key = RB_ROOT(&s->keys)) != NULL) {
		RB_REMOVE(ctx_key, &s->keys, key);

		if (key->initbuf != NULL)
			net2_buffer_free(key->initbuf);
		if (key->xchange != NULL)
			net2_xchangectx_free(key->xchange);
		net2_free(key);
	}

	/* Job set has been freeed by the stop_worker() call. */
	assert(TAILQ_EMPTY(&s->jobq));
	assert(RB_EMPTY(&s->jobs));

	net2_mutex_unlock(s->mtx);

	net2_cond_free(s->wait);
	net2_mutex_free(s->mtx);
	net2_free(s);
}


/* Generate tree implementation. */
RB_GENERATE_STATIC(ctx_key, key, set, key_cmp);
RB_GENERATE_STATIC(ctx_job, job, set, job_cmp);


/*
 * External access points.
 */

/* Background allocation function. */
ILIAS_NET2_EXPORT struct net2_promise*
net2_ctx_xchange_factory_bg(int xchange, size_t keysize, void *ctx)
{
	return new_promise((struct scope*)ctx, xchange, keysize);
}

/* Create the background context. */
ILIAS_NET2_EXPORT void*
net2_ctx_xchange_factory_bg_new()
{
	return new_scope();
}

/* Destroy the background context. */
ILIAS_NET2_EXPORT void
net2_ctx_xchange_factory_bg_destroy(void *s)
{
	destroy_scope((struct scope*)s);
}
