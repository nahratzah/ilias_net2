#include <ilias/net2/conn_keys.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/connwindow.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/promise.h>
#include <assert.h>
#include <errno.h>

#include "packet.h"


/* Test if the key set has keys. */
static __inline int
has_keys(const struct net2_ck_keys *k)
{
	size_t				 i;

	for (i = 0; i < sizeof(k->key) / sizeof(k->key[0]); i++) {
		if (k->key[i] != NULL)
			return 1;
	}
	return 0;
}
/* Free keys. */
static __inline void
free_keys(struct net2_ck_keys *k)
{
	size_t				 i;

	for (i = 0; i < sizeof(k->key) / sizeof(k->key[0]); i++)
		net2_buffer_free(k->key[i]);
}
/* Forget keys (without releasing them). */
static __inline void
zero_keys(struct net2_ck_keys *k)
{
	size_t				 i;

	for (i = 0; i < sizeof(k->key) / sizeof(k->key[0]); i++)
		k->key[i] = NULL;
}

/*
 * Retrieve specific keys.
 * Returns NULL if the keys are not present.
 */
static __inline struct net2_ck_keys*
net2_ck_key(struct net2_conn_keys *ck, int which)
{
	assert(which >= 0 && which < sizeof(ck->keys) / sizeof(ck->keys[0]));
	return (has_keys(&ck->keys[which]) ? &ck->keys[which] : NULL);
}

/*
 * Upgrade RX alt key to active key.
 */
static void
do_rx_alt_cutoff(void *ck_ptr, void* ILIAS_NET2__unused unused)
{
	struct net2_conn_keys		*ck = ck_ptr;
	struct net2_ck_keys		*active, *alt;

	/* Check state. */
	active = &ck->keys[NET2_CK_RX_ACTIVE];
	alt = net2_ck_key(ck, NET2_CK_RX_ALT);
	assert(alt != NULL);

	/* Switch alt over to active. */
	free_keys(active);
	*active = *alt;	/* struct copy */
	zero_keys(alt);

	/* Destroy event that ran this function. */
	net2_promise_event_deinit(ck->rx_alt_cutoff_expire);
	ck->rx_alt_cutoff_expire = NULL;
}

/*
 * Upgrade TX alt key to active key.
 */
static void
do_tx_alt_cutoff(void *ck_ptr, void* ILIAS_NET2__unused unused)
{
	struct net2_conn_keys		*ck = ck_ptr;
	struct net2_ck_keys		*active, *alt;

	/* Check state. */
	active = &ck->keys[NET2_CK_TX_ACTIVE];
	alt = net2_ck_key(ck, NET2_CK_TX_ALT);
	assert(alt != NULL);

	/* Switch alt over to active. */
	free_keys(active);
	*active = *alt;	/* struct copy */
	zero_keys(alt);

	/* Destroy event that ran this function. */
	net2_promise_event_deinit(ck->tx_alt_cutoff_expire);
	ck->tx_alt_cutoff_expire = NULL;
}

/*
 * Update the rx cutoff point.
 *
 * The update consists of lowering the cutoff (relative to the rx window)
 * and (re)scheduling the upgrade from alt to active.
 */
static int
update_rx_alt_cutoff(struct net2_conn_keys *ck, struct net2_workq *wq,
    struct net2_connwindow *w, uint32_t seq)
{
	struct net2_promise		*p;
	struct net2_promise_event	*event;
	int				 error;

	/* Acquire a new rx expiry value. */
	if ((p = net2_connwindow_rx_expiry(w, seq)) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	/* Set up event to hold new cutoff. */
	if ((event = net2_malloc(sizeof(*event))) == NULL) {
		error = ENOMEM;
		goto fail_1;
	}
	if ((error = net2_promise_event_init(event, p, NET2_PROM_ON_FINISH, wq,
	    &do_rx_alt_cutoff, ck, NULL)) != 0)
		goto fail_2;

	/*
	 * No errors past this point.
	 */

	/* Update cutoff value. */
	ck->rx_alt_cutoff = seq;
	ck->flags &= ~NET2_CK_F_NO_RX_CUTOFF;

	/* Update event to switch over. */
	if (ck->rx_alt_cutoff_expire != NULL) {
		net2_promise_event_deinit(ck->rx_alt_cutoff_expire);
		ck->rx_alt_cutoff_expire = NULL;
	}
	ck->rx_alt_cutoff_expire = event;

	/* Release promise: event will hang on to it in the proper fashion. */
	net2_promise_release(p);

	return 0;


fail_3:
	net2_promise_event_deinit(event);
fail_2:
	net2_free(event);
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
update_tx_alt_cutoff(struct net2_conn_keys *ck, struct net2_workq *wq,
    struct net2_connwindow *w, uint32_t seq)
{
	struct net2_promise		*p;
	struct net2_promise_event	*event;
	int				 error;

	/* Acquire a new tx expiry promise. */
	if ((p = net2_connwindow_tx_expiry(w, seq)) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	/* Set up event to hold new cutoff. */
	if ((event = net2_malloc(sizeof(*event))) == NULL) {
		error = ENOMEM;
		goto fail_1;
	}
	if ((error = net2_promise_event_init(event, p, NET2_PROM_ON_FINISH, wq,
	    &do_tx_alt_cutoff, ck, NULL)) != 0)
		goto fail_2;

	/*
	 * No errors past this point.
	 */

	/* Update cutoff value. */
	ck->rx_alt_cutoff = seq;
	ck->flags &= ~NET2_CK_F_NO_TX_CUTOFF;

	/* Update event to switch over. */
	assert(ck->tx_alt_cutoff_expire == NULL); /* Only assigned once. */
	ck->tx_alt_cutoff_expire = event;

	/* Release promise: event will hang on to it in the proper fashion. */
	net2_promise_release(p);

	return 0;


fail_3:
	net2_promise_event_deinit(event);
fail_2:
	net2_free(event);
fail_1:
	net2_promise_release(p);
fail_0:
	assert(error != 0);
	return error;
}

/*
 * Get rx key.
 *
 * Note that this function may not alter the net2_conn_keys,
 * unless the hash and decryption succeed.
 */
ILIAS_NET2_LOCAL struct net2_ck_keys*
net2_ck_rx_key(struct net2_conn_keys *ck,
    struct net2_connwindow *w, const struct packet_header *ph)
{
	struct net2_ck_keys	*k;

	/*
	 * If no altkey is present, the active key must be the right
	 * key.
	 */
	if ((k = net2_ck_key(ck, NET2_CK_RX_ALT)) == NULL)
		return net2_ck_key(ck, NET2_CK_RX_ACTIVE);

	/*
	 * Return alternative key if either the flag is set,
	 * or the packet is past the cutoff point.
	 */
	if ((ph->flags & PH_ALTKEY) ||
	    (!(ck->flags & NET2_CK_F_NO_RX_CUTOFF) &&
	    ph->seq - w->cw_rx_start >=
	    ck->rx_alt_cutoff - w->cw_rx_start))
		return k;

	/*
	 * Packet is prior to cutoff point, return old key.
	 */
	return net2_ck_key(ck, NET2_CK_RX_ACTIVE);
}

/*
 * Handle commitment of received packet.
 */
ILIAS_NET2_LOCAL int
net2_ck_rx_key_commit(struct net2_conn_keys *ck, struct net2_workq *wq,
    struct net2_connwindow *w, const struct packet_header *ph)
{
	/* Nothing to do if we don't have an altkey. */
	if (net2_ck_key(ck, NET2_CK_RX_ALT) == NULL)
		return 0;

	/*
	 * If this packet moves the cutoff point backward,
	 * update the cutoff point.
	 */
	if ((ph->flags & PH_ALTKEY) && ((ck->flags & NET2_CK_F_NO_RX_CUTOFF) ||
	    ph->seq - w->cw_rx_start <
	    ck->rx_alt_cutoff - w->cw_rx_start))
		return update_rx_alt_cutoff(ck, wq, w, ph->seq);

	return 0;
}

/*
 * Update the key set with a new alternative RX key.
 */
ILIAS_NET2_LOCAL int
net2_ck_rx_key_inject(struct net2_conn_keys *ck,
    const struct net2_ck_keys *key)
{
	size_t				 i;

	if (net2_ck_key(ck, NET2_CK_RX_ALT) != NULL)
		return EINVAL;
	if (key == NULL || !has_keys(key))
		return EINVAL;

	/* Assign alternate key. */
	for (i = 0; i < NET2_CNEG_S2_MAX; i++) {
		ck->keys[NET2_CK_RX_ALT].alg[i] = key->alg[i];
		if ((ck->keys[NET2_CK_RX_ALT].key[i] =
		    net2_buffer_copy(key->key[i])) == NULL) {
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
ILIAS_NET2_LOCAL struct net2_ck_keys*
net2_ck_tx_key(struct net2_conn_keys *ck, struct net2_workq *wq,
    struct net2_connwindow *w, struct packet_header *ph)
{
	struct net2_ck_keys		*k;

	/* No alt key, return active key. */
	if ((k = net2_ck_key(ck, NET2_CK_TX_ALT)) == NULL)
		return net2_ck_key(ck, NET2_CK_TX_ACTIVE);

	/* We need a cutoff point for the TX key. */
	if (ck->flags & NET2_CK_F_NO_TX_CUTOFF) {
		/*
		 * If we cannot create the tx cutoff point,
		 * return the active key instead.  This is safe because
		 * the altkey has not been used yet.  Maybe the sent
		 * buffer will free up some memory, so next invocation
		 * we can use the altkey instead.
		 */
		if (update_tx_alt_cutoff(ck, wq, w, ph->seq) != 0)
			return net2_ck_key(ck, NET2_CK_TX_ACTIVE);
	}

	/* Mark packet as containing alternative key. */
	ph->flags |= PH_ALTKEY;
	return k;
}

/*
 * Update the key set with a new alternative TX key.
 */
ILIAS_NET2_LOCAL int
net2_ck_tx_key_inject(struct net2_conn_keys *ck,
    const struct net2_ck_keys *key)
{
	size_t				 i;

	if (net2_ck_key(ck, NET2_CK_TX_ALT) != NULL)
		return EINVAL;
	if (key == NULL || !has_keys(key))
		return EINVAL;

	/* Assign alternate key. */
	for (i = 0; i < NET2_CNEG_S2_MAX; i++) {
		ck->keys[NET2_CK_TX_ALT].alg[i] = key->alg[i];
		if ((ck->keys[NET2_CK_TX_ALT].key[i] =
		    net2_buffer_copy(key->key[i])) == NULL) {
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
net2_ck_init(struct net2_conn_keys *ck)
{
	size_t			 i;

	for (i = 0; i < sizeof(ck->keys) / sizeof(ck->keys[0]); i++)
		free_keys(&ck->keys[i]);

	ck->rx_alt_cutoff = ck->tx_alt_cutoff = 0;
	ck->flags = 0;
	ck->rx_alt_cutoff_expire = ck->tx_alt_cutoff_expire = NULL;
	return 0;
}

/*
 * Deinitialize connection keys.
 */
ILIAS_NET2_LOCAL void
net2_ck_deinit(struct net2_conn_keys *ck)
{
	size_t			 i;

	if (ck->rx_alt_cutoff_expire != NULL)
		net2_promise_event_deinit(ck->rx_alt_cutoff_expire);
	if (ck->tx_alt_cutoff_expire != NULL)
		net2_promise_event_deinit(ck->tx_alt_cutoff_expire);

	for (i = 0; i < sizeof(ck->keys) / sizeof(ck->keys[0]); i++)
		free_keys(&ck->keys[i]);
}
