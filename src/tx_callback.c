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
#include <ilias/net2/tx_callback.h>
#include <ilias/net2/config.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/mutex.h>
#include <assert.h>
#include <errno.h>

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <ilias/net2/bsd_compat/queue.h>
#endif


/* List of callbacks. */
struct net2_txcbq {
	struct net2_mutex	*mtx;
	int			 ref;		/* In use by net2_txcbq. */
	TAILQ_HEAD(, txcb)	 txcb;		/* Actual events. */
};

/* A single callback. */
struct txcb {
	struct net2_workq_job	 job;
	net2_workq_cb		 fn;
	void			*arg0;
	TAILQ_ENTRY(txcb)	 q;
	struct net2_txcbq	*owner;
};

static void	 txcbq_unlock(struct net2_txcbq**);
static void	 txcb_destroy_unlocked(struct txcb*);
static void	 txcb_destroy(struct txcb*);
static void	 txcb_wqdestroy(struct net2_workq_job*);
static void	 txcbq_activate(struct net2_tx_callback*, int);
static struct net2_txcbq
		*new_q();
static void	 merge_q(struct net2_txcbq**, struct net2_txcbq**);
static struct txcb
		*txcb_new(net2_tx_callback_fn, void*, void*,
		    struct net2_workq*);

#define Q_TIMEOUT	0
#define Q_ACK		1
#define Q_NACK		2
#define Q_DESTROY	3

static const struct net2_workq_job_cb txcb_jcb = {
	NULL,
	NULL,
	NULL,
	&txcb_wqdestroy
};

static void
txcb_execute(void *txcb_ptr, void *arg1)
{
	struct txcb		*t;
	net2_workq_cb		 fn;
	void			*arg0;

	/* Save function and arguments. */
	t = txcb_ptr;
	fn = t->fn;
	arg0 = t->arg0;
	/* Destroy txcb. */
	txcb_destroy(t);

	/* Invoke function. */
	(*fn)(arg0, arg1);
}
static void
txcbq_unlock(struct net2_txcbq **q_ptr)
{
	struct net2_txcbq	*q = *q_ptr;
	int			 do_free;

	if (q == NULL)
		return;

	do_free = (!q->ref && TAILQ_EMPTY(&q->txcb));
	if (do_free)
		*q_ptr = NULL;
	net2_mutex_unlock(q->mtx);

	if (do_free) {
		net2_mutex_free(q->mtx);
		net2_free(q);
	}
}
static __inline void
txcb_destroy_unlocked(struct txcb *t)
{
	struct net2_txcbq	*q;

	if ((q = t->owner) != NULL)
		TAILQ_REMOVE(&q->txcb, t, q);
	net2_workq_deinit_work(&t->job);
	net2_free(t);
}
static __inline void
txcb_destroy(struct txcb *t)
{
	struct net2_txcbq	*q;

	q = t->owner;
	if (q != NULL)
		net2_mutex_lock(q->mtx);
	txcb_destroy_unlocked(t);
	if (q != NULL)
		txcbq_unlock(&q);
}
static void
txcb_wqdestroy(struct net2_workq_job *j)
{
	struct txcb		*t = (struct txcb*)j;

	assert(&t->job == j);
	txcb_destroy(t);
}
/*
 * Activate the specified queue.
 * Handles deactivation and destruction of all queues, as appropriate
 * for the activated queue.
 */
static void
txcbq_activate(struct net2_tx_callback *tx, int which)
{
	struct txcb		*t;
	size_t			 i;

	assert(which > 0 &&
	    (size_t)which < sizeof(tx->queue) / sizeof(tx->queue[0]));

	/*
	 * Destroy all queues that cannot fire after this operation.
	 * Note: Q_TIMEOUT will always allow the other queues to fire.
	 */
	if (which != Q_TIMEOUT) {
		for (i = 0; i < sizeof(tx->queue) / sizeof(tx->queue[0]);
		    i++) {
			if (i == (size_t)which)
				continue;
			if (tx->queue[i] == NULL)
				continue;

			net2_mutex_lock(tx->queue[i]->mtx);
			while ((t = TAILQ_FIRST(&tx->queue[i]->txcb)) != NULL)
				txcb_destroy_unlocked(t);
			tx->queue[i]->ref = 0;
			txcbq_unlock(&tx->queue[Q_TIMEOUT]);
		}
	}

	/*
	 * Fire the selected queue.
	 */
	if (tx->queue[which] != NULL) {
		net2_mutex_lock(tx->queue[which]->mtx);
		TAILQ_FOREACH(t, &tx->queue[i]->txcb, q)
			net2_workq_activate(&t->job);
		/* Keep Q_TIMEOUT, but throw away any others once they fire. */
		if (which != Q_TIMEOUT)
			tx->queue[which]->ref = 0;
		txcbq_unlock(&tx->queue[which]);
	}
}

/* Create a new queue. */
static struct net2_txcbq*
new_q()
{
	struct net2_txcbq	*q;

	if ((q = net2_malloc(sizeof(*q))) == NULL)
		return NULL;
	if ((q->mtx = net2_mutex_alloc()) == NULL) {
		net2_free(q);
		return NULL;
	}
	q->ref = 1;
	TAILQ_INIT(&q->txcb);
	return q;
}

/*
 * Merge two queues.
 * Note that the queue may not have fired.
 */
static void
merge_q(struct net2_txcbq **dst, struct net2_txcbq **src)
{
	struct net2_txcbq	*q;
	struct txcb		*t;

	assert(dst != NULL && src != NULL);

	/* Trivial case: src did not exist. */
	if (*src == NULL)
		return;
	/* Trivial case: dst did not exist. */
	if (*dst == NULL) {
		*dst = *src;
		*src = NULL;
		return;
	}
	/* Self copy breaks, avoid it. */
	if (*dst == *src)
		return;

	/* Both exist. */
	q = *src;
	*src = NULL;
	net2_mutex_lock((*dst)->mtx);
	net2_mutex_lock(q->mtx);

	/* Move them all over. */
	while ((t = TAILQ_FIRST(&q->txcb)) != NULL) {
		TAILQ_REMOVE(&q->txcb, t, q);
		TAILQ_INSERT_TAIL(&(*dst)->txcb, t, q);
	}

	/*
	 * Release src: it is not referenced by the previous owner,
	 * nor by dst.
	 */
	q->ref = 0;
	net2_mutex_unlock((*dst)->mtx);
	txcbq_unlock(&q);
	assert(q == NULL);
}

/* Create a new txcb. */
static struct txcb*
txcb_new(net2_tx_callback_fn fn, void *arg0, void *arg1,
    struct net2_workq *workq)
{
	struct txcb		*t;

	assert(fn != NULL);

	if ((t = net2_malloc(sizeof(*t))) == NULL)
		goto fail_0;
	t->owner = NULL;
	t->fn = fn;
	t->arg0 = arg0;
	if (net2_workq_init_work(&t->job, workq, &txcb_execute, t, arg1, 0))
		goto fail_1;
	net2_workq_set_callbacks(&t->job, &txcb_jcb);
	return t;


fail_2:
	net2_workq_deinit_work(&t->job);
fail_1:
	net2_free(t);
fail_0:
	return NULL;
}

/* Test if the txcbq is empty. */
ILIAS_NET2_EXPORT int
net2_txcbq_empty(struct net2_tx_callback *tx)
{
	int			 result;
	size_t			 i;

	for (i = 0, result = 1;
	    result && i < sizeof(tx->queue) / sizeof(tx->queue[0]); i++) {
		if (tx->queue[i] == NULL)
			continue;

		net2_mutex_lock(tx->queue[i]->mtx);
		if (TAILQ_EMPTY(&tx->queue[i]->txcb))
			tx->queue[i]->ref = 0;
		else
			result = 0;
		txcbq_unlock(&tx->queue[i]);
	}
	return result;
}


/* Initialize new tx_callback. */
ILIAS_NET2_EXPORT int
net2_txcb_init(struct net2_tx_callback *cb)
{
	size_t			 i;

	for (i = 0; i < sizeof(cb->queue) / sizeof(cb->queue[0]); i++)
		cb->queue[i] = NULL;
	return 0;
}

/*
 * Release resources held by tx_callback.
 *
 * Any remaining callbacks are cancelled, using their destroy callback.
 */
ILIAS_NET2_EXPORT void
net2_txcb_deinit(struct net2_tx_callback *cb)
{
	txcbq_activate(cb, Q_DESTROY);
}

/* TX callback ACK completion. */
ILIAS_NET2_EXPORT void
net2_txcb_ack(struct net2_tx_callback *cb)
{
	txcbq_activate(cb, Q_ACK);
}

/* TX callback NACK completion. */
ILIAS_NET2_EXPORT void
net2_txcb_nack(struct net2_tx_callback *cb)
{
	txcbq_activate(cb, Q_NACK);
}

/* TX callback timeout invocation. */
ILIAS_NET2_EXPORT void
net2_txcb_timeout(struct net2_tx_callback *cb)
{
	txcbq_activate(cb, Q_TIMEOUT);
}

/* Move all event from src to dst. */
ILIAS_NET2_EXPORT void
net2_txcb_merge(struct net2_tx_callback *dst, struct net2_tx_callback *src)
{
	size_t			 i;

	assert(dst != NULL && src != NULL);
	for (i = 0; i < sizeof(dst->queue) / sizeof(dst->queue[0]); i++)
		merge_q(&dst->queue[i], &src->queue[i]);
}

/* Add callback to tx callback. */
ILIAS_NET2_EXPORT int
net2_txcb_add(struct net2_tx_callback *cb, struct net2_workq *workq,
    net2_tx_callback_fn timeout, net2_tx_callback_fn ack,
    net2_tx_callback_fn nack, net2_tx_callback_fn destroy,
    void *arg0, void *arg1)
{
	struct txcb		*t[4];
	size_t			 i;

	t[0] = t[1] = t[2] = t[3] = NULL;

	/* Create events. */
	if (timeout != NULL) {
		if ((t[Q_TIMEOUT] = txcb_new(timeout, arg0, arg1, workq)) ==
		    NULL)
			goto fail;
	}
	if (ack != NULL) {
		if ((t[Q_ACK] = txcb_new(ack, arg0, arg1, workq)) ==
		    NULL)
			goto fail;
	}
	if (nack != NULL) {
		if ((t[Q_NACK] = txcb_new(nack, arg0, arg1, workq)) ==
		    NULL)
			goto fail;
	}
	if (destroy != NULL) {
		if ((t[Q_DESTROY] = txcb_new(destroy, arg0, arg1, workq)) ==
		    NULL)
			goto fail;
	}

	/* Create missing queues that we require. */
	for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
		if (t[i] == NULL)
			continue;

		if (cb->queue[i] == NULL) {
			if ((cb->queue[i] = new_q()) == NULL)
				goto fail;
		}
	}

	/* Add events to queues. */
	for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
		if (t[i] == NULL)
			continue;

		net2_mutex_lock(cb->queue[i]->mtx);
		TAILQ_INSERT_TAIL(&cb->queue[i]->txcb, t[i], q);
		net2_mutex_unlock(cb->queue[i]->mtx);
	}

	return 0;


fail:
	/* Release events. */
	for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
		if (t[i] != NULL)
			txcb_destroy_unlocked(t[i]);
	}
	return ENOMEM;
}
