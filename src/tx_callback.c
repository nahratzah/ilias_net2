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
#include <ilias/net2/evbase.h>
#include <ilias/net2/memory.h>
#include <event2/event.h>
#include <assert.h>
#include <errno.h>


struct net2_tx_callback_cb {
	net2_tx_callback_fn	 txcb_ack,	/* ACK callback. */
				 txcb_nack,	/* NACK callback. */
				 txcb_timeout,	/* Timeout callback. */
				 txcb_destroy;	/* Destroy callback. */

	void			*txcb_arg0;	/* CB FN first arg. */
	void			*txcb_arg1;	/* CB FN second arg. */

	int			 txcb_state;	/* Callback state. */
#define NET2_TXCB_NONE		0 /* State: nothing to do. */
#define NET2_TXCB_ACK		1 /* State: ack received. */
#define NET2_TXCB_NACK		2 /* State: ack received. */
#define NET2_TXCB_DESTROY	3 /* State: destroyed. */

	struct event		*txcb_ev;	/* Conclusion event. */
	struct event		*txcb_ev_timeout; /* Timeout event. */

	TAILQ_ENTRY(net2_tx_callback_cb)
				 txcb_entry;	/* Link into list. */
};


static void	 txcb_timeout(evutil_socket_t, short, void*);
static void	 txcb_conclude(evutil_socket_t, short, void*);
static struct net2_tx_callback_cb*
		 tx_callback_cb_new(net2_tx_callback_fn, net2_tx_callback_fn,
		    net2_tx_callback_fn, net2_tx_callback_fn,
		    void*, void*, struct net2_evbase*);
static void	 tx_callback_cb_destroy(struct net2_tx_callback_cb*);
static void	 tx_callback_timeout(struct net2_tx_callback*);
static void	 tx_callback_completion(struct net2_tx_callback*, int);


/* Execute timeout. */
static void
txcb_timeout(evutil_socket_t sock, short what, void *txcb_ptr)
{
	struct net2_tx_callback_cb
				*txcb;

	txcb = txcb_ptr;

	assert(txcb->txcb_state == NET2_TXCB_NONE);
	if (txcb->txcb_timeout != NULL)
		(*txcb->txcb_timeout)(txcb->txcb_arg0, txcb->txcb_arg1);
}

/* Execute conclusion. */
static void
txcb_conclude(evutil_socket_t sock, short what, void *txcb_ptr)
{
	struct net2_tx_callback_cb
				*txcb;
	net2_tx_callback_fn	 fn;

	txcb = txcb_ptr;

	assert(txcb->txcb_state != NET2_TXCB_NONE);
	switch (txcb->txcb_state) {
	default:
		fn = NULL;
		break;
	case NET2_TXCB_ACK:
		fn = txcb->txcb_ack;
		break;
	case NET2_TXCB_NACK:
		fn = txcb->txcb_nack;
		break;
	case NET2_TXCB_DESTROY:
		fn = txcb->txcb_destroy;
		break;
	}

	if (fn != NULL)
		(*fn)(txcb->txcb_arg0, txcb->txcb_arg1);
	tx_callback_cb_destroy(txcb);
}


/* Create a new txcb. */
static struct net2_tx_callback_cb*
tx_callback_cb_new(net2_tx_callback_fn ack, net2_tx_callback_fn nack,
    net2_tx_callback_fn timeout, net2_tx_callback_fn destroy,
    void *arg0, void *arg1, struct net2_evbase *evbase)
{
	struct net2_tx_callback_cb
				*txcb;

	if ((txcb = net2_malloc(sizeof(*txcb))) == NULL)
		goto fail_0;

	txcb->txcb_ack = ack;
	txcb->txcb_nack = nack;
	txcb->txcb_timeout = timeout;
	txcb->txcb_destroy = destroy;
	txcb->txcb_arg0 = arg0;
	txcb->txcb_arg1 = arg1;
	txcb->txcb_state = 0;

	if (timeout != NULL) {
		if ((txcb->txcb_ev_timeout = event_new(evbase->evbase, -1, 0,
		    txcb_timeout, txcb)) == NULL)
			goto fail_1;
	}
	if ((txcb->txcb_ev = event_new(evbase->evbase, -1, 0,
	    txcb_conclude, txcb)) == NULL)
		goto fail_2;

	return txcb;


fail_3:
	event_free(txcb->txcb_ev);
fail_2:
	if (txcb->txcb_ev_timeout != NULL)
		event_free(txcb->txcb_ev_timeout);
fail_1:
	net2_free(txcb);
fail_0:
	return NULL;
}

/* Destroy txcb. */
static void
tx_callback_cb_destroy(struct net2_tx_callback_cb *txcb)
{
	event_free(txcb->txcb_ev);
	if (txcb->txcb_ev_timeout != NULL)
		event_free(txcb->txcb_ev_timeout);
	net2_free(txcb);
}


/* Fire timeout event. */
static void
tx_callback_timeout(struct net2_tx_callback *cb)
{
	struct net2_tx_callback_cb
				*txcb;

	TAILQ_FOREACH(txcb, cb, txcb_entry) {
		if (txcb->txcb_ev_timeout != NULL)
			event_active(txcb->txcb_ev_timeout, 0, 1);
	}
}

/* Fire completion event. */
static void
tx_callback_completion(struct net2_tx_callback *cb, int txcb_state)
{
	struct net2_tx_callback_cb
				*txcb;
	assert(txcb_state == NET2_TXCB_ACK ||
	    txcb_state == NET2_TXCB_NACK ||
	    txcb_state == NET2_TXCB_DESTROY);

	while ((txcb = TAILQ_FIRST(cb)) != NULL) {
		/* Cancel any pending timout events. */
		if (txcb->txcb_ev_timeout != NULL)
			event_del(txcb->txcb_ev_timeout);

		assert(txcb->txcb_state == NET2_TXCB_NONE);
		txcb->txcb_state = txcb_state;
		event_active(txcb->txcb_ev, 0, 1);

		TAILQ_REMOVE(cb, txcb, txcb_entry);
	}
}


/* Initialize new tx_callback. */
ILIAS_NET2_EXPORT int
net2_txcb_init(struct net2_tx_callback *cb)
{
	TAILQ_INIT(cb);
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
	tx_callback_completion(cb, NET2_TXCB_DESTROY);
}

/* TX callback ACK completion. */
ILIAS_NET2_EXPORT void
net2_txcb_ack(struct net2_tx_callback *cb)
{
	tx_callback_completion(cb, NET2_TXCB_ACK);
}

/* TX callback NACK completion. */
ILIAS_NET2_EXPORT void
net2_txcb_nack(struct net2_tx_callback *cb)
{
	tx_callback_completion(cb, NET2_TXCB_NACK);
}

/* TX callback timeout invocation. */
ILIAS_NET2_EXPORT void
net2_txcb_timeout(struct net2_tx_callback *cb)
{
	tx_callback_timeout(cb);
}

/* Move all event from src to dst. */
ILIAS_NET2_EXPORT void
net2_txcb_merge(struct net2_tx_callback *dst, struct net2_tx_callback *src)
{
	struct net2_tx_callback_cb
				*txcb;

	while ((txcb = TAILQ_FIRST(src)) != NULL) {
		TAILQ_REMOVE(src, txcb, txcb_entry);
		TAILQ_INSERT_TAIL(dst, txcb, txcb_entry);
	}
}

/* Add callback to tx callback. */
ILIAS_NET2_EXPORT int
net2_txcb_add(struct net2_tx_callback *cb, struct net2_evbase *evbase,
    net2_tx_callback_fn ack, net2_tx_callback_fn nack,
    net2_tx_callback_fn timeout, net2_tx_callback_fn destroy,
    void *arg0, void *arg1)
{
	struct net2_tx_callback_cb
				*txcb;

	if ((txcb = tx_callback_cb_new(ack, nack, timeout, destroy, arg0, arg1,
	    evbase)) == NULL)
		return ENOMEM;

	TAILQ_INSERT_TAIL(cb, txcb, txcb_entry);
	return 0;
}
