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
#include <ilias/net2/conn_keys.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/connection.h>
#include <ilias/net2/connwindow.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/promise.h>
#include <ilias/net2/workq_timer.h>
#include <ilias/net2/cneg_key_xchange.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include "packet.h"


static const struct timeval tv_rekey = { NET2_REKEY_INTERVAL_SEC, 0 };
static const struct timeval tv_expire = { NET2_REKEY_DAMOCLES_SEC, 0 };


static void	do_killme(void*, void*);
static void	do_rx_alt_cutoff(void*, void*);
static void	do_tx_alt_cutoff(void*, void*);
static int	update_rx_alt_cutoff(struct net2_conn_keys*, struct net2_connwindow*, uint32_t);
static int	update_tx_alt_cutoff(struct net2_conn_keys*, struct net2_connwindow*, uint32_t);
static void	ck_assign_kx(void*, void*);
static void	do_rx_rekey_assign(void*, void*);
static void	do_tx_rekey_assign(void*, void*);
static void	do_rx_rekey(void*, void*);


/* Test if the key set has keys. */
static __inline int
has_keys(const net2_ck_keys *k)
{
	size_t				 i;

	for (i = 0; i < sizeof(*k) / sizeof((*k)[0]); i++) {
		if ((*k)[i].key != NULL)
			return 1;
	}
	return 0;
}
/* Free keys. */
static __inline void
free_keys(net2_ck_keys *k)
{
	size_t				 i;

	for (i = 0; i < sizeof(*k) / sizeof((*k)[0]); i++)
		net2_buffer_free((*k)[i].key);
}
/* Forget keys (without releasing them). */
static __inline void
zero_keys(net2_ck_keys *k)
{
	size_t				 i;

	for (i = 0; i < sizeof(*k) / sizeof((*k)[0]); i++) {
		(*k)[i].alg = 0;
		(*k)[i].key = NULL;
	}
}

/*
 * Retrieve specific keys.
 * Returns NULL if the keys are not present.
 */
static __inline net2_ck_keys*
net2_ck_key(struct net2_conn_keys *ck, int which)
{
	assert(which >= 0 &&
	    which < (int)(sizeof(ck->keys) / sizeof(ck->keys[0])));
	return (has_keys(&ck->keys[which]) ? &ck->keys[which] : NULL);
}

/* Workq callback: kill connection. */
static void
do_killme(void * ILIAS_NET2__unused unused, void *conn)
{
	net2_connection_destroy(conn);
}

/*
 * Upgrade RX alt key to active key.
 */
static void
do_rx_alt_cutoff(void *ck_ptr, void* ILIAS_NET2__unused unused)
{
	struct net2_conn_keys		*ck = ck_ptr;
	net2_ck_keys			*active, *alt;

	/* Check state. */
	active = &ck->keys[NET2_CK_RX_ACTIVE];
	alt = net2_ck_key(ck, NET2_CK_RX_ALT);
	assert(alt != NULL);

	/* Switch alt over to active. */
	free_keys(active);
	memcpy(active, alt, sizeof(*active));	/* struct copy */
	zero_keys(alt);

	/* Forget local key exchange. */
	net2_cneg_key_xchange_forget_local(ck->kx);

	/* Destroy event that ran this function. */
	net2_promise_event_deinit(&ck->rx_alt_cutoff_expire);
}

/*
 * Upgrade TX alt key to active key.
 */
static void
do_tx_alt_cutoff(void *ck_ptr, void* ILIAS_NET2__unused unused)
{
	struct net2_conn_keys		*ck = ck_ptr;
	net2_ck_keys			*active, *alt;
	struct net2_promise		*kx_remote;

	/* Check state. */
	active = &ck->keys[NET2_CK_TX_ACTIVE];
	alt = net2_ck_key(ck, NET2_CK_TX_ALT);
	assert(alt != NULL);

	/* Switch alt over to active. */
	free_keys(active);
	memcpy(active, alt, sizeof(*active));	/* struct copy */
	zero_keys(alt);

	/* Forget remote key exchange. */
	net2_cneg_key_xchange_forget_remote(ck->kx);

	/* Destroy event that ran this function. */
	net2_promise_event_deinit(&ck->tx_alt_cutoff_expire);

	/* Recreate remote key exchange, so new keys can be received. */
	net2_cneg_key_xchange_forget_remote(ck->kx);
	if ((kx_remote = net2_cneg_key_xchange_recreate_remote(ck->kx)) ==
	    NULL)
		return;	/* Key will expire and fail soon. */

	assert(net2_promise_event_is_null(&ck->rx_rekey_ready));
	net2_promise_event_init(&ck->rx_rekey_ready, kx_remote,
	    NET2_PROM_ON_FINISH, ck->wq,
	    &do_tx_rekey_assign, ck, ck->kx);

	net2_promise_release(kx_remote);	/* Referenced by event. */
}

/*
 * Update the rx cutoff point.
 *
 * The update consists of lowering the cutoff (relative to the rx window)
 * and (re)scheduling the upgrade from alt to active.
 */
static int
update_rx_alt_cutoff(struct net2_conn_keys *ck,
    struct net2_connwindow *w, uint32_t seq)
{
	struct net2_promise		*p;
	int				 error;

	/* Acquire a new rx expiry value. */
	if ((p = net2_connwindow_rx_expiry(w, seq)) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}

	/* Update event to switch over. */
	net2_promise_event_deinit(&ck->rx_alt_cutoff_expire);
	if ((error = net2_promise_event_init(&ck->rx_alt_cutoff_expire, p,
	    NET2_PROM_ON_FINISH, ck->wq, &do_rx_alt_cutoff, ck, NULL)) != 0)
		goto fail_1;

	/*
	 * No errors past this point.
	 */

	/* Restart expiry timer. */
	if (ck->flags & NET2_CK_F_NO_RX_CUTOFF)
		net2_workq_timer_set(ck->rx_rekey, &tv_rekey);

	/* Update cutoff value. */
	ck->rx_alt_cutoff = seq;
	ck->rx_rekey_off = seq + NET2_REKEY_INTERVAL_WIN;
	ck->flags &= ~NET2_CK_F_NO_RX_CUTOFF;

	/* Release promise: event will hang on to it in the proper fashion. */
	net2_promise_release(p);

	return 0;


fail_2:
	net2_promise_event_deinit(&ck->rx_alt_cutoff_expire);
fail_1:
	net2_promise_release(p);
fail_0:
	assert(error != 0);
	return error;
}

/*
 * Update the tx cutoff point.
 *
 * The update consists of setting the cutoff point and
 * set up an event to expire the old active key.
 */
static int
update_tx_alt_cutoff(struct net2_conn_keys *ck,
    struct net2_connwindow *w, uint32_t seq)
{
	struct net2_promise		*p;
	int				 error;

	/* Acquire a new tx expiry promise. */
	if ((p = net2_connwindow_tx_expiry(w, seq)) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}

	/* Update event to switch over. */
	assert(net2_promise_event_is_null(&ck->tx_alt_cutoff_expire));
	if ((error = net2_promise_event_init(&ck->tx_alt_cutoff_expire, p,
	    NET2_PROM_ON_FINISH, ck->wq, &do_tx_alt_cutoff, ck, NULL)) != 0)
		goto fail_1;

	/*
	 * No errors past this point.
	 */

	/* Update cutoff value. */
	ck->tx_alt_cutoff = seq;
	ck->tx_expirekey_off = seq + NET2_REKEY_DAMOCLES_WIN;
	ck->flags &= ~NET2_CK_F_NO_TX_CUTOFF;

	/* Release promise: event will hang on to it in the proper fashion. */
	net2_promise_release(p);

	/* Reschedule rekey timer and expiry. */
	net2_workq_timer_set(ck->tx_rekey_expire, &tv_expire);

	return 0;


fail_2:
	net2_promise_event_deinit(&ck->tx_alt_cutoff_expire);
fail_1:
	net2_promise_release(p);
fail_0:
	assert(error != 0);
	return error;
}

/*
 * key xchange first time completion event.
 *
 * Assigns keys with connection.
 */
static void
ck_assign_kx(void *ck_ptr, void *kx_ptr)
{
	struct net2_conn_keys	*ck = ck_ptr;
	struct net2_cneg_key_xchange
				*kx = kx_ptr;
	struct net2_promise	*kx_ready,
				*kx_remote,
				*kx_local;
	int			 fin_local, fin_remote;
	net2_ck_keys		*keys_local, *keys_remote;

	kx_ready = net2_cneg_key_xchange_ready(kx, 1);
	assert(kx_ready != NULL);
	assert(ck->kx == NULL);

	kx_remote = net2_cneg_key_xchange_promise_remote(kx);
	kx_local = net2_cneg_key_xchange_promise_local(kx);

	/* Test that the key exchange went succesful. */
	if (net2_promise_is_finished(kx_ready) != NET2_PROM_FIN_OK) {
fail:
		if (kx_remote != NULL)
			net2_promise_release(kx_remote);
		if (kx_local != NULL)
			net2_promise_release(kx_local);
		net2_connection_destroy(ck->conn);
		return;
	}

	/* Lookup local and remote keys. */
	fin_remote = net2_promise_get_result(kx_remote,
	    (void**)&keys_remote, NULL);
	fin_local = net2_promise_get_result(kx_local,
	    (void**)&keys_local, NULL);
	assert(fin_remote == NET2_PROM_FIN_OK &&
	    fin_local == NET2_PROM_FIN_OK);

	/*
	 * No keys should be present yet.
	 */
	assert(net2_ck_key(ck, NET2_CK_TX_ACTIVE) == NULL);
	assert(net2_ck_key(ck, NET2_CK_TX_ALT) == NULL);
	assert(net2_ck_key(ck, NET2_CK_RX_ACTIVE) == NULL);
	assert(net2_ck_key(ck, NET2_CK_RX_ALT) == NULL);

	/*
	 * Inject keys.
	 *
	 * Remote initialized keys are used for transmit,
	 * local initialized keys are used for receive.
	 */
	if (net2_ck_tx_key_inject(ck, keys_remote) != 0)
		goto fail;
	if (net2_ck_rx_key_inject(ck, keys_local) != 0)
		goto fail;

	/* Store kx, so that future rekey attempts may succeed. */
	ck->kx = kx;

	net2_promise_release(kx_remote);
	net2_promise_release(kx_local);
}

/*
 * Assign keys from local promise as RX alt keys.
 */
static void
do_rx_rekey_assign(void *ck_ptr, void *kx_local_ptr)
{
	struct net2_conn_keys	*ck = ck_ptr;
	struct net2_promise	*kx_local = kx_local_ptr;
	net2_ck_keys		*keys;
	int			 fin;

	/* Cancel this event. */
	net2_promise_event_deinit(&ck->rx_rekey_ready);

	/* Acquire result. */
	fin = net2_promise_get_result(kx_local, (void**)&keys, NULL);
	if (fin != NET2_PROM_FIN_OK)
		return;	/* Failure. */

	/* Inject new keys as alt keys. */
	if (net2_ck_rx_key_inject(ck, keys) != 0)
		return;	/* Failure. */
}

/*
 * Assign keys from remote promise as TX alt keys.
 */
static void
do_tx_rekey_assign(void *ck_ptr, void *kx_remote_ptr)
{
	struct net2_conn_keys	*ck = ck_ptr;
	struct net2_promise	*kx_remote = kx_remote_ptr;
	net2_ck_keys		*keys;
	int			 fin;

	/* Cancel this event. */
	net2_promise_event_deinit(&ck->rx_rekey_ready);

	/* Acquire result. */
	fin = net2_promise_get_result(kx_remote, (void**)&keys, NULL);
	if (fin != NET2_PROM_FIN_OK)
		return;	/* Failure. */

	/* Inject new keys as alt keys. */
	if (net2_ck_tx_key_inject(ck, keys) != 0)
		return;	/* Failure. */
}

/*
 * Start local key xchange update.
 */
static void
do_rx_rekey(void *ck_ptr, void *kx_ptr)
{
	struct net2_conn_keys	*ck = ck_ptr;
	struct net2_cneg_key_xchange
				*kx = kx_ptr;
	struct net2_promise	*kx_local;

	assert(ck->kx == kx);	/* Sanity. */

	/*
	 * Alternative key should have been promoted to active
	 * a while ago.
	 */
	assert(net2_ck_key(ck, NET2_CK_TX_ALT) == NULL);

	/* Recreate locally initialized key negotiation. */
	if ((kx_local = net2_cneg_key_xchange_recreate_local(kx)) == NULL) {
		/*
		 * Unable to recreate local key renegotiation;
		 * allow connection to die via timeout.
		 * XXX handle this better
		 */
		return;
	}

	/* Stop timeout that would fire this event. */
	net2_workq_timer_stop(ck->rx_rekey);

	/*
	 * Attach event to inject new key.
	 */
	assert(net2_promise_event_is_null(&ck->rx_rekey_ready));
	if (net2_promise_event_init(&ck->rx_rekey_ready, kx_local,
	    NET2_PROM_ON_FINISH, ck->wq,
	    &do_rx_rekey_assign, ck, kx_local) != 0)
		goto out;


out:
	/* Release promise (event still holds on to it). */
	net2_promise_release(kx_local);
	return;
}

/*
 * Get rx key.
 *
 * Note that this function may not alter the net2_conn_keys,
 * unless the hash and decryption succeed.
 */
ILIAS_NET2_LOCAL void
net2_ck_rx_key(net2_ck_keys **out, struct net2_conn_keys *ck,
    struct net2_connwindow *w, const struct packet_header *ph)
{
	net2_ck_keys		*k;

	/*
	 * If no altkey is present, the active key must be the right
	 * key.
	 */
	if ((k = net2_ck_key(ck, NET2_CK_RX_ALT)) == NULL)
		goto active;

	/*
	 * Return alternative key if either the flag is set,
	 * or the packet is past the cutoff point.
	 */
	if ((ph->flags & PH_ALTKEY) ||
	    (!(ck->flags & NET2_CK_F_NO_RX_CUTOFF) &&
	    ph->seq - w->cw_rx_start >=
	    ck->rx_alt_cutoff - w->cw_rx_start)) {
		*out = k;
		return;
	}

active:
	/*
	 * Packet is prior to cutoff point, return old key.
	 */
	*out = net2_ck_key(ck, NET2_CK_RX_ACTIVE);
	return;
}

/*
 * Handle commitment of received packet.
 */
ILIAS_NET2_LOCAL int
net2_ck_rx_key_commit(struct net2_conn_keys *ck,
    struct net2_connwindow *w, const struct packet_header *ph)
{
	/* Nothing to do if we don't have an altkey. */
	if (net2_ck_key(ck, NET2_CK_RX_ALT) == NULL) {
		/*
		 * Test if the rx packet exceeds the rekey point.
		 */
		if (net2_promise_event_is_null(&ck->rx_rekey_ready) &&
		    ph->seq - w->cw_rx_start >=
		    ck->rx_rekey_off - w->cw_rx_start)
			do_rx_rekey(ck, ck->kx);

		return 0;
	}

	/*
	 * If this packet moves the cutoff point backward,
	 * update the cutoff point.
	 */
	if ((ph->flags & PH_ALTKEY) && ((ck->flags & NET2_CK_F_NO_RX_CUTOFF) ||
	    ph->seq - w->cw_rx_start <
	    ck->rx_alt_cutoff - w->cw_rx_start))
		return update_rx_alt_cutoff(ck, w, ph->seq);

	return 0;
}

/*
 * Update the key set with a new alternative RX key.
 */
ILIAS_NET2_LOCAL int
net2_ck_rx_key_inject(struct net2_conn_keys *ck,
    const net2_ck_keys *key)
{
	size_t				 i;

	if (net2_ck_key(ck, NET2_CK_RX_ALT) != NULL)
		return EINVAL;
	if (key == NULL || !has_keys(key))
		return EINVAL;

	/* Assign alternate key. */
	for (i = 0; i < NET2_CNEG_S2_MAX; i++) {
		ck->keys[NET2_CK_RX_ALT][i].alg = (*key)[i].alg;
		if ((ck->keys[NET2_CK_RX_ALT][i].key =
		    net2_buffer_copy((*key)[i].key)) == NULL) {
			free_keys(&ck->keys[NET2_CK_RX_ALT]);
			return ENOMEM;
		}
	}
	/* Mark our cutoff point as invalid. */
	ck->flags |= NET2_CK_F_NO_RX_CUTOFF;

	return 0;
}

/*
 * Return the key that is to be used for transmission.
 * May modify packet header flags to indicate the use of an alternative key.
 */
ILIAS_NET2_LOCAL int
net2_ck_tx_key(net2_ck_keys **out, struct net2_conn_keys *ck,
    struct net2_connwindow *w, struct packet_header *ph)
{
	net2_ck_keys			*k;

	/* No alt key, return active key. */
	if ((k = net2_ck_key(ck, NET2_CK_TX_ALT)) == NULL) {
		if (ck->tx_expirekey_off == ph->seq)
			return ERANGE;
		*out = net2_ck_key(ck, NET2_CK_TX_ACTIVE);
		return 0;
	}

	/* We need a cutoff point for the TX key. */
	if (ck->flags & NET2_CK_F_NO_TX_CUTOFF) {
		/*
		 * If we cannot create the tx cutoff point,
		 * return the active key instead.  This is safe because
		 * the altkey has not been used yet.  Maybe the sent
		 * buffer will free up some memory, so next invocation
		 * we can use the altkey instead.
		 */
		if (update_tx_alt_cutoff(ck, w, ph->seq) != 0) {
			*out = net2_ck_key(ck, NET2_CK_TX_ACTIVE);
			return 0;
		}
	}

	/* Mark packet as containing alternative key. */
	ph->flags |= PH_ALTKEY;
	*out = k;
	return 0;
}

/*
 * Update the key set with a new alternative TX key.
 */
ILIAS_NET2_LOCAL int
net2_ck_tx_key_inject(struct net2_conn_keys *ck,
    const net2_ck_keys *key)
{
	size_t				 i;

	if (net2_ck_key(ck, NET2_CK_TX_ALT) != NULL)
		return EINVAL;
	if (key == NULL || !has_keys(key))
		return EINVAL;

	/* Assign alternate key. */
	for (i = 0; i < NET2_CNEG_S2_MAX; i++) {
		ck->keys[NET2_CK_TX_ALT][i].alg = (*key)[i].alg;
		if ((ck->keys[NET2_CK_TX_ALT][i].key =
		    net2_buffer_copy((*key)[i].key)) == NULL) {
			free_keys(&ck->keys[NET2_CK_TX_ALT]);
			return ENOMEM;
		}
	}
	/* Mark our cutoff point as invalid. */
	ck->flags |= NET2_CK_F_NO_TX_CUTOFF;

	return 0;
}

/*
 * Initialize connection keys.
 */
ILIAS_NET2_LOCAL int
net2_ck_init(struct net2_conn_keys *ck, struct net2_workq *wq,
    struct net2_cneg_key_xchange *kx, struct net2_connection *conn)
{
	size_t			 i;
	int			 error;

	ck->wq = wq;
	ck->kx = NULL;
	ck->conn = conn;
	for (i = 0; i < sizeof(ck->keys) / sizeof(ck->keys[0]); i++)
		zero_keys(&ck->keys[i]);

	/* Set up timer for rekeying. */
	if ((ck->tx_rekey_expire = net2_workq_timer_new(wq,
	    &do_killme, ck, conn)) == NULL)
		goto fail_0;
	/* Set up expiry for remotely created keys. */
	if ((ck->rx_rekey = net2_workq_timer_new(wq,
	    &do_rx_rekey, ck, kx)) == NULL)
		goto fail_1;

	ck->rx_alt_cutoff = ck->tx_alt_cutoff = 0;
	ck->flags = 0;
	net2_promise_event_init_null(&ck->rx_alt_cutoff_expire);
	net2_promise_event_init_null(&ck->tx_alt_cutoff_expire);
	net2_promise_event_init_null(&ck->rx_rekey_ready);
	net2_promise_event_init_null(&ck->tx_rekey_ready);

	if ((error = net2_promise_event_init(&ck->kx_complete,
	    net2_cneg_key_xchange_ready(kx, 1),
	    NET2_PROM_ON_FINISH, wq, &ck_assign_kx, ck, kx)) != 0)
		goto fail_2;

	return 0;

fail_3:
	net2_promise_event_deinit(&ck->kx_complete);
fail_2:
	net2_workq_timer_free(ck->rx_rekey);
fail_1:
	net2_workq_timer_free(ck->tx_rekey_expire);
fail_0:
	return error;
}

/*
 * Deinitialize connection keys.
 */
ILIAS_NET2_LOCAL void
net2_ck_deinit(struct net2_conn_keys *ck)
{
	size_t			 i;

	net2_workq_timer_free(ck->tx_rekey_expire);
	net2_workq_timer_free(ck->rx_rekey);

	net2_promise_event_deinit(&ck->rx_alt_cutoff_expire);
	net2_promise_event_deinit(&ck->tx_alt_cutoff_expire);
	net2_promise_event_deinit(&ck->rx_rekey_ready);
	net2_promise_event_deinit(&ck->tx_rekey_ready);
	net2_promise_event_deinit(&ck->kx_complete);

	for (i = 0; i < sizeof(ck->keys) / sizeof(ck->keys[0]); i++)
		free_keys(&ck->keys[i]);
}


/* Duplicate a key. */
ILIAS_NET2_LOCAL struct net2_ck_key_single*
net2_ck_ks_dup(const struct net2_ck_key_single *k)
{
	struct net2_ck_key_single	*clone;

	if ((clone = net2_malloc(sizeof(*clone))) == NULL)
		goto fail_0;
	if (net2_ck_ks_copy(clone, k) != 0)
		goto fail_1;
	return clone;


fail_1:
	net2_free(clone);
fail_0:
	return NULL;
}
/* Copy a key. */
ILIAS_NET2_LOCAL int
net2_ck_ks_copy(struct net2_ck_key_single *dst,
    const struct net2_ck_key_single *src)
{
	return net2_ck_ks_init(dst, src->alg, src->key);
}
/* Create a new key (allocated). */
ILIAS_NET2_LOCAL struct net2_ck_key_single*
net2_ck_ks_new(int alg, const struct net2_buffer *buf)
{
	struct net2_ck_key_single	*clone;

	if ((clone = net2_malloc(sizeof(*clone))) == NULL)
		goto fail_0;
	if (net2_ck_ks_init(clone, alg, buf) != 0)
		goto fail_1;
	return clone;


fail_1:
	net2_free(clone);
fail_0:
	return NULL;
}
/* Initialize a key. */
ILIAS_NET2_LOCAL int
net2_ck_ks_init(struct net2_ck_key_single *k,
    int alg, const struct net2_buffer *buf)
{
	k->alg = alg;
	if (buf == NULL)
		k->key = NULL;
	else if ((k->key = net2_buffer_copy(buf)) == NULL)
		return ENOMEM;
	return 0;
}
/* Destroy a key (freeing it). */
ILIAS_NET2_LOCAL void
net2_ck_ks_destroy(struct net2_ck_key_single *k)
{
	net2_ck_ks_deinit(k);
	net2_free(k);
}
/* Deinitialize a key. */
ILIAS_NET2_LOCAL void
net2_ck_ks_deinit(struct net2_ck_key_single *k)
{
	if (k != NULL && k->key != NULL)
		net2_buffer_free(k->key);
}


/* Initialize connection keys to empty. */
ILIAS_NET2_LOCAL void
net2_ck_keys_init(net2_ck_keys *k)
{
	size_t			 i;

	for (i = 0; i < NET2_CNEG_S2_MAX; i++)
		net2_ck_ks_init(&(*k)[i], 0, NULL);
}
ILIAS_NET2_LOCAL void
net2_ck_keys_deinit(net2_ck_keys *k)
{
	size_t			 i;

	for (i = 0; i < NET2_CNEG_S2_MAX; i++)
		net2_ck_ks_deinit(&(*k)[i]);
}
