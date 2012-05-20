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
#include <ilias/net2/conn_negotiator.h>
#include <ilias/net2/connection.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/bitset.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/cp.h>
#include <ilias/net2/packet.h>
#include <ilias/net2/promise.h>
#include <ilias/net2/workq.h>
#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/context.h>
#include <ilias/net2/carver.h>
#include <ilias/net2/tx_callback.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ilias/net2/bsd_compat/minmax.h>
#include <ilias/net2/config.h>
#include <event2/event.h>

#include <ilias/net2/enc.h>
#include <ilias/net2/hash.h>
#include <ilias/net2/xchange.h>

#include <ilias/net2/cneg_stage1.h>
#include <ilias/net2/cneg_key_xchange.h>

#include "handshake.h"
#include "exchange.h"

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <ilias/net2/bsd_compat/queue.h>
#endif

#define REQUIRE								\
	(NET2_CNEG_REQUIRE_ENCRYPTION | NET2_CNEG_REQUIRE_SIGNING)
#define UNKNOWN_SIZE		((size_t)-1)

#define CNEG_OFFSET							\
		(size_t)(&((struct net2_connection*)0)->n2c_negotiator)
#define CNEG_CONN(_cn)							\
		((struct net2_connection*)((char*)(_cn) - CNEG_OFFSET))


/* Notify connection that we want to send data. */
static void
cneg_ready_to_send(struct net2_conn_negotiator *cn)
{
	net2_acceptor_socket_ready_to_send(&CNEG_CONN(cn)->n2c_socket);
}


/*
 * True iff the connection is ready and sufficiently secure
 * to allow payload to cross.
 */
ILIAS_NET2_LOCAL int
net2_cneg_allow_payload(struct net2_conn_negotiator *cn,
    uint32_t ILIAS_NET2__unused seq)
{
	int	require = (cn->flags & REQUIRE);

	/* XXX for now, allow progress anyway */
	return 1;

	/* Check that all required options are enabled. */
	if ((cn->flags_have & require) != require)
		return 0;

	return 1;
}

/* Initialize connection negotiator. */
ILIAS_NET2_LOCAL int
net2_cneg_init(struct net2_conn_negotiator *cn, struct net2_ctx *context)
{
	int			 error;
	struct net2_connection	*s = CNEG_CONN(cn);
	struct encoded_header	*h;
	size_t			 i;
	struct net2_workq	*wq;

	assert(s != NULL);
	wq = net2_acceptor_socket_workq(&s->n2c_socket);

	cn->flags = cn->flags_have = 0;
	if (!(s->n2c_socket.fn->flags & NET2_SOCKET_SECURE)) {
		cn->flags |= NET2_CNEG_REQUIRE_ENCRYPTION |
		    NET2_CNEG_REQUIRE_SIGNING;
	}
	cn->stage = NET2_CNEG_STAGE_PRISTINE;
	cn->context = context;
	cn->recv_no_send = 0;
	if ((cn->stage1 = cneg_stage1_new()) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	cn->keyx = NULL;

	cn->hash.supported = NULL;
	cn->hash.num_supported = 0;
	cn->enc.supported = NULL;
	cn->enc.num_supported = 0;
	cn->xchange.supported = NULL;
	cn->xchange.num_supported = 0;
	cn->sign.supported = NULL;
	cn->sign.num_supported = 0;

	return 0;


fail_1:
	cneg_stage1_free(cn->stage1);
fail_0:
	return error;
}

/* Destroy connection negotiator. */
ILIAS_NET2_LOCAL void
net2_cneg_deinit(struct net2_conn_negotiator *cn)
{
	struct encoded_header	*h;
	size_t			 i;
	struct event		*ev;

	/* Release stage2 data. */
	if (cn->keyx != NULL)
		net2_cneg_key_xchange_free(cn->keyx);
	/* Release stage1 data. */
	if (cn->stage1 != NULL)
		cneg_stage1_free(cn->stage1);

	net2_free(cn->hash.supported);
	net2_free(cn->enc.supported);
	net2_free(cn->xchange.supported);
	net2_free(cn->sign.supported);

	return;
}

/* Get connection negotiator transmission. */
ILIAS_NET2_LOCAL int
net2_cneg_get_transmit(struct net2_conn_negotiator *cn,
    struct packet_header* ph,
    struct net2_buffer **bufptr, struct net2_tx_callback *tx, size_t maxlen,
    int stealth, int want_payload)
{
	int			 error;
	struct net2_buffer	*buf;
	struct net2_encdec_ctx	 ectx;

	if ((buf = net2_buffer_new()) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}

	switch (cn->stage) {
	default:
		error = 0;
		break;

	case NET2_CNEG_STAGE_PRISTINE:
		/* Fill stage 1 transmission data. */
#if 0
		error = cneg_stage1_get_transmit(cn, ph, bufptr, tx, maxlen,
		    stealth, want_payload);
#endif
		break;

	case NET2_CNEG_STAGE_KEY_EXCHANGE:
		if (cn->keyx == NULL)
			break;

		/* Fill stage 2 transmission data. */
		if ((error = net2_encdec_ctx_newaccsocket(&ectx,
		    &CNEG_CONN(cn)->n2c_socket)) != 0)
			goto fail_1;
		error = net2_cneg_key_xchange_get_transmit(cn->keyx, &ectx,
		    net2_acceptor_socket_workq(&CNEG_CONN(cn)->n2c_socket),
		    buf, tx, maxlen, !stealth, want_payload);
		net2_encdec_ctx_deinit(&ectx);
		if (error != 0)
			goto fail_1;

		/* Append stage2 payload and set indicator flag. */
		if (!net2_buffer_empty(buf)) {
			*bufptr = buf;
			buf = NULL;
			ph->flags |= PH_HANDSHAKE_S2;
		}

		break;
	}

	if (error == 0 && *bufptr != NULL)
		cn->recv_no_send = 0;

fail_1:
	if (buf != NULL)
		net2_buffer_free(buf);
fail_0:
	return error;
}

/*
 * Accept packets.
 */
ILIAS_NET2_LOCAL int
net2_cneg_accept(struct net2_conn_negotiator *cn, struct packet_header *ph,
    struct net2_buffer *buf)
{
	struct net2_encdec_ctx	 ectx;
	int			 error;

	/* Handle stage 1 decoding. */
	if (ph->flags & PH_HANDSHAKE) {
		if (cn->stage1 == NULL)
			error = EINVAL;
		else
			error = cneg_stage1_accept(cn->stage1, ph, buf);
		if (error != 0)
			goto fail;
	}

	/* Handle stage 2 decoding. */
	if (ph->flags & PH_HANDSHAKE_S2) {
		if (cn->keyx == NULL)
			error = EINVAL;
		else {
			if ((error = net2_encdec_ctx_newaccsocket(&ectx,
			    &CNEG_CONN(cn)->n2c_socket)) != 0)
				goto fail;
			error = net2_cneg_key_xchange_accept(cn->keyx,
			    &ectx, buf);
			net2_encdec_ctx_deinit(&ectx);
		}
	}

	cn->recv_no_send = 1;
	return 0;

fail:
	return error;
}

ILIAS_NET2_LOCAL int
net2_cneg_pvlist(struct net2_conn_negotiator *cn, struct net2_pvlist *pv)
{
#if 0 /* XXX todo */
	return net2_pvlist_merge(pv, &cn->negotiated.proto);
#endif
	return cn == NULL && pv == NULL; /* 0 */
}

#if 0
/*
 * Retrieve decoding keys.
 *
 * Note that this function is called prior to the validation of the message.
 * Therefore it is imperative that this code does not take decisions, but
 * operates without modifying ph, cn or cn->keys.
 */
ILIAS_NET2_LOCAL int
net2_cneg_rxkeys(struct net2_cneg_keys *k, struct net2_conn_negotiator *cn,
    struct packet_header *ph)
{
	int			 alt_mask;
	struct net2_cneg_key_state
				*keys = cn->keys;

	/* These flags can never be present together. */
	if (ph->flags & (PH_ALTKEY | PH_ALTKEY_DROP))
		return EINVAL;

	/* Default: receive only unencrypted data. */
	k->hash.algorithm = 0;
	k->hash.key = NULL;
	k->hash.keylen = 0;
	k->hash.allow_insecure = 1;
	k->enc.algorithm = 0;
	k->enc.key = NULL;
	k->enc.keylen = 0;
	k->enc.allow_insecure = 1;

	/* Cannot do alternate keys until we have keys to alternate between. */
	if (keys == NULL && (ph->flags & (PH_ALTKEY | PH_ALTKEY_DROP)))
		return EINVAL;

	/* Override no-key result if keys are present. */
	if (keys != NULL) {
		if (keys->flags & KEYSTATE_F_SECURE_INBOUND)
			k->hash.allow_insecure = k->enc.allow_insecure = 0;

		/* Default: main key is valid and to be used. */
		alt_mask = KEYCHAIN_MAIN;

		/*
		 * If the packet sequence is consistent with the old key,
		 * use the old key.
		 *
		 * The logic is thus:
		 * - the old key was valid up until winstart_in
		 * - the new key is valid starting at winstart_in
		 * - if alt is not old, then default to the main key
		 *   (but see override based on ph->flags below).
		 */
		if (keys->flags & KEYSTATE_F_RX_ALT_IS_OLD) {
			/* Check sequence index of new key. */
			if (keys->flags & KEYSTATE_F_RX_ALT_USED) {
				if (ph->seq - keys->winstart_in_alt <
				    keys->winstart_in - keys->winstart_in_alt)
					alt_mask = KEYCHAIN_ALT;
				else
					alt_mask = KEYCHAIN_MAIN;
			} else
				alt_mask = KEYCHAIN_ALT;
		}

		/*
		 * Override based on ph->flags.
		 */
		if (ph->flags & PH_ALTKEY) {
			if ((keys->flags & KEYSTATE_F_RX_ALT_PRESENT))
				alt_mask = KEYCHAIN_ALT;
			/* Otherwise: logic above (usually main key). */
		} else if ((ph->flags & PH_ALTKEY_DROP) &&
		    (keys->flags & KEYSTATE_F_RX_ALT_PRESENT)) {
			/* Drop hasn't happened yet. */
			alt_mask = KEYCHAIN_ALT;
		}

		/* Check if we are to hard abort the connection. */
		if (ph->seq - (alt_mask == KEYCHAIN_MAIN ? keys->winstart_in :
		    keys->winstart_in_alt) > CNEG_KEYSTATE_EXP_HARD)
			return EINVAL;

		/* Apply what we learned above. */
		k->enc.key =
		    keys->chain[KEYCHAIN_IN|KEYCHAIN_ENC|alt_mask].key;
		k->enc.keylen =
		    keys->chain[KEYCHAIN_IN|KEYCHAIN_ENC|alt_mask].keylen;
		k->enc.algorithm =
		    keys->chain[KEYCHAIN_IN|KEYCHAIN_ENC|alt_mask].algorithm;

		k->hash.key =
		    keys->chain[KEYCHAIN_IN|KEYCHAIN_HASH|alt_mask].key;
		k->hash.keylen =
		    keys->chain[KEYCHAIN_IN|KEYCHAIN_HASH|alt_mask].keylen;
		k->hash.algorithm =
		    keys->chain[KEYCHAIN_IN|KEYCHAIN_HASH|alt_mask].algorithm;
	}

	return 0;
}

/* Retrieve encoding keys. */
ILIAS_NET2_LOCAL int
net2_cneg_txkeys(struct net2_cneg_keys *k, struct net2_conn_negotiator *cn,
    struct packet_header *ph, uint32_t tx_winstart, struct net2_tx_callback *tx)
{
	int			 alt_mask;
	struct net2_cneg_key_state
				*keys = cn->keys;

	/* Default: send unencrypted data. */
	k->hash.algorithm = 0;
	k->hash.key = NULL;
	k->hash.keylen = 0;
	k->hash.allow_insecure = 1;
	k->enc.algorithm = 0;
	k->enc.key = NULL;
	k->enc.keylen = 0;
	k->enc.allow_insecure = 1;

	/* TODO: implement */
	if (keys != NULL) {
		if (keys->flags & KEYSTATE_F_SECURE_OUTBOUND)
			k->hash.allow_insecure = k->enc.allow_insecure = 0;

		/* Default. */
		alt_mask = KEYCHAIN_MAIN;

		/* Handle alternative keying. */
		if (keys->flags & KEYSTATE_F_TX_ALT_PRESENT) {
			if (keys->winstart_out == tx_winstart) {
				keys->flags |= KEYSTATE_F_TX_ALT_EXPIRING;
				keys->flags &= ~KEYSTATE_F_TX_ALT_PRESENT;

				/* Secure release of keys. */
				net2_secure_zero(keys->chain[KEYCHAIN_OUT|
				    KEYCHAIN_MAIN|KEYCHAIN_HASH].key,
				    keys->chain[KEYCHAIN_OUT|KEYCHAIN_MAIN|
				    KEYCHAIN_HASH].keylen);
				net2_free(keys->chain[KEYCHAIN_OUT|
				    KEYCHAIN_MAIN|KEYCHAIN_HASH].key);

				net2_secure_zero(keys->chain[KEYCHAIN_OUT|
				    KEYCHAIN_MAIN|KEYCHAIN_ENC].key,
				    keys->chain[KEYCHAIN_OUT|KEYCHAIN_MAIN|
				    KEYCHAIN_ENC].keylen);
				net2_free(keys->chain[KEYCHAIN_OUT|
				    KEYCHAIN_MAIN|KEYCHAIN_HASH].key);

				/* Change alt key to main key,
				 * using struct copy. */
				keys->chain[KEYCHAIN_OUT|KEYCHAIN_MAIN|
				    KEYCHAIN_HASH] =
				    keys->chain[KEYCHAIN_OUT|KEYCHAIN_ALT|
				    KEYCHAIN_HASH];
				keys->chain[KEYCHAIN_OUT|KEYCHAIN_MAIN|
				    KEYCHAIN_ENC] =
				    keys->chain[KEYCHAIN_OUT|KEYCHAIN_ALT|
				    KEYCHAIN_ENC];
				/* Unset alt keys. */
				keys->chain[KEYCHAIN_OUT|KEYCHAIN_ALT|
				    KEYCHAIN_HASH].key =
				    keys->chain[KEYCHAIN_OUT|KEYCHAIN_ALT|
				    KEYCHAIN_ENC].key = NULL;
			} else
				alt_mask = KEYCHAIN_ALT;
		}

		/* Apply key bits to packet header. */
		if (alt_mask == KEYCHAIN_ALT)
			ph->flags |= PH_ALTKEY;
		if (keys->flags & KEYSTATE_F_TX_ALT_EXPIRING) {
			assert(!(ph->flags & PH_ALTKEY));
			assert(alt_mask == KEYCHAIN_MAIN);
			ph->flags |= PH_ALTKEY_DROP;

			/* TODO: connect callback to tx, on ack,
			 * clear KEYSTATE_F_ALT_EXPIRING. */
		}

		/* Activate re-keying. */
		if (alt_mask == KEYCHAIN_MAIN && keys->expire_ev != NULL &&
		    ph->seq - keys->winstart_out >= CNEG_KEYSTATE_EXP_WIN)
			event_active(keys->expire_ev, 0, 1);

		/* Apply active key chain to result. */
		k->hash.algorithm =
		    keys->chain[KEYCHAIN_OUT|KEYCHAIN_HASH|alt_mask].algorithm;
		k->hash.key =
		    keys->chain[KEYCHAIN_OUT|KEYCHAIN_HASH|alt_mask].key;
		k->hash.keylen =
		    keys->chain[KEYCHAIN_OUT|KEYCHAIN_HASH|alt_mask].keylen;

		k->enc.algorithm =
		    keys->chain[KEYCHAIN_OUT|KEYCHAIN_ENC|alt_mask].algorithm;
		k->enc.key =
		    keys->chain[KEYCHAIN_OUT|KEYCHAIN_ENC|alt_mask].key;
		k->enc.keylen =
		    keys->chain[KEYCHAIN_OUT|KEYCHAIN_ENC|alt_mask].keylen;
	}

	return 0;
}
#endif
