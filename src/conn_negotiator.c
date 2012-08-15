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
#include <ilias/net2/conn_keys.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/bitset.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/cp.h>
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

#include <ilias/net2/enc.h>
#include <ilias/net2/hash.h>
#include <ilias/net2/sign.h>
#include <ilias/net2/xchange.h>

#include <ilias/net2/cneg_stage1.h>
#include <ilias/net2/cneg_key_xchange.h>

#include "handshake.h"
#include "exchange.h"
#include "packet.h"

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

static void	 free2(void*, void*);
static void	 kx_free2(void*, void*);
static int	 select_hash(int*, size_t);
static int	 select_enc(int*, size_t);
static int	 select_xchange(int*, size_t);
static int	 select_sighash(int*, size_t);
static void	 choose_alg(struct net2_promise*, struct net2_promise**,
		    size_t, void*);

static struct net2_promise*
		 create_key_xchange_prom(struct net2_workq*,
		    struct net2_cneg_stage1*,
		    struct net2_promise*, struct net2_promise*,
		    struct net2_promise*, struct net2_promise*);
static void	 create_key_xchange(struct net2_promise*,
		    struct net2_promise**, size_t, void*);
static void	 key_xchange_assign(void*, void*);


static void
free2(void *p, void *unused ILIAS_NET2__unused)
{
	net2_free(p);
}
static void
kx_free2(void *kx, void *unused ILIAS_NET2__unused)
{
	net2_cneg_key_xchange_free(kx);
}

/* Notify connection that we want to send data. */
static void
cneg_ready_to_send(struct net2_conn_negotiator *cn)
{
	net2_acceptor_socket_ready_to_send(&CNEG_CONN(cn)->n2c_socket);
}
/* Ready-to-send with 2 arguments. */
static void
cneg_ready_to_send_arg(void *cn_ptr, void *unused ILIAS_NET2__unused)
{
	cneg_ready_to_send(cn_ptr);
}

/*
 * Select best keyed hash algorithm.
 * Returns -1 if none are sufficient.
 */
static int
select_hash(int *algs, size_t n)
{
	int	selected, key, hash, i_key, i_hash, i_alg;
	size_t	i;
	const int min_keylen = 128 / 8;
	const int min_hashlen = 32 / 8;

	selected = -1;
	key = -1;
	hash = -1;
	for (i = 0; i < n; i++) {
		i_alg = algs[i];
		i_key = net2_hash_getkeylen(i_alg);
		i_hash = net2_hash_gethashlen(i_alg);
		if (i_key >= min_keylen && i_hash >= min_hashlen &&
		    (i_key > key || (i_key == key && i_hash > hash))) {
			selected = i_alg;
			key = i_key;
			hash = i_hash;
		}
	}

	return selected;
}
/*
 * Select best keyed enc algorithm.
 * Returns -1 if none are sufficient.
 */
static int
select_enc(int *algs, size_t n)
{
	int	selected, key, iv, i_key, i_iv, i_alg;
	size_t	i;
	const int min_keylen = 128 / 8;
	const int min_ivlen = 32 / 8;

	selected = -1;
	key = -1;
	iv = -1;
	for (i = 0; i < n; i++) {
		i_alg = algs[i];
		i_key = net2_enc_getkeylen(i_alg);
		i_iv = net2_enc_getivlen(i_alg);
		if (i_key >= min_keylen && i_iv >= min_ivlen &&
		    (i_key > key || (i_key == key && i_iv > iv))) {
			selected = i_alg;
			key = i_key;
			iv = i_iv;
		}
	}

	return selected;
}
/*
 * Select best xchange algorithm.
 * Returns -1 if none are sufficient.
 */
static int
select_xchange(int *algs, size_t n)
{
	int	selected;
	size_t	i;

	/*
	 * Assume that algorithms are better
	 * if they have a higher algorithm number.
	 */
	selected = -1;
	for (i = 0; i < n; i++) {
		if (algs[i] > 0 && algs[i] > selected)
			selected = algs[i];
	}
	return selected;
}
/*
 * Select best unkeyed hash algorithm.
 * Returns -1 if none are sufficient.
 */
static int
select_sighash(int *algs, size_t n)
{
	int	selected, hash, i_hash, i_alg;
	size_t	i;
	const int min_hashlen = 32 / 8;

	selected = -1;
	hash = -1;
	for (i = 0; i < n; i++) {
		i_alg = algs[i];
		if (net2_hash_getkeylen(i_alg) != 0)
			continue;	/* Skip keyed hashes. */
		i_hash = net2_hash_gethashlen(i_alg);
		if (i_hash >= min_hashlen && i_hash > hash) {
			selected = i_alg;
			hash = i_hash;
		}
	}

	return selected;
}

/* Choose the hash algorithm we want to use for packet hashes. */
static void
choose_alg(struct net2_promise *out, struct net2_promise **in,
    size_t insz, void *select_fn)
{
	struct net2_cneg_stage1_algorithms
				*algs;
	uint32_t		 err;
	int			 fin;
	int			*outval;
	int			(*select)(int*, size_t) = select_fn;
	int			 selected;

	/* Skip assignment if cancelation was requested. */
	if (net2_promise_is_cancelreq(out)) {
		net2_promise_set_cancel(out, 0);
		return;
	}

	/* Only 1 input promise. */
	if (insz != 1) {
		err = EINVAL;
		goto fail;
	}

	/* Check result of input. */
	fin = net2_promise_get_result(in[0], (void**)&algs, &err);
	assert(fin != NET2_PROM_FIN_UNFINISHED);
	switch (fin) {
	case NET2_PROM_FIN_OK:
		break;
	case NET2_PROM_FIN_ERROR:
		goto fail;
	default:
		err = EIO;
		goto fail;
	}

	/*
	 * Check the hash with the highest key size, highest hash size.
	 * Simple linear search for max.
	 */
	selected = (*select)(algs->algs, algs->sz);
	if (selected == -1) {
		/* Nothing suitable was presented. */
		err = ESRCH;
		goto fail;
	}

	/* Assign selected algorithm. */
	if ((outval = net2_malloc(sizeof(*outval))) == NULL) {
		err = ENOMEM;
		goto fail;
	}
	*outval = selected;
	if ((err = net2_promise_set_finok(out, outval, &free2, NULL,
	    0)) != 0) {
		net2_free(outval);
		goto fail;
	}
	return;

fail:
	net2_promise_set_error(out, err, 0);
}


/*
 * True iff the connection is ready and sufficiently secure
 * to allow payload to cross.
 */
ILIAS_NET2_LOCAL int
net2_cneg_allow_payload(struct net2_conn_negotiator *cn,
    uint32_t seq ILIAS_NET2__unused)
{
	int	require = (cn->flags & REQUIRE);

	/* XXX for now, allow progress anyway */
	return 1;

	/* Check that all required options are enabled. */
	if ((cn->flags_have & require) != require)
		return 0;

	return 1;
}

/* Create the key xchange factory. */
static struct net2_promise*
create_key_xchange_prom(struct net2_workq *wq, struct net2_cneg_stage1 *s1,
    struct net2_promise *hash, struct net2_promise *enc,
    struct net2_promise *xchange, struct net2_promise *sighash)
{
	struct net2_promise	*proms[7];
	struct net2_promise	*result;

	proms[0] = cneg_stage1_get_pver(s1);
	proms[1] = hash;
	proms[2] = enc;
	proms[3] = xchange;
	proms[4] = sighash;
	proms[5] = cneg_stage1_get_accepted_signatures(s1);
	proms[6] = cneg_stage1_get_transmit_signatures(s1);

	result = net2_promise_combine(wq, &create_key_xchange, NULL,
	    proms, sizeof(proms) / sizeof(proms[0]));

	net2_promise_release(proms[0]);
	net2_promise_release(proms[5]);
	net2_promise_release(proms[6]);

	return result;
}
/* Convert stage1 information into a key exchange handler. */
static void
create_key_xchange(struct net2_promise *out, struct net2_promise **in,
    size_t insz, void *cn_ptr)
{
	struct net2_cneg_stage1_pver	*pver;
	int				*hash, *crypt, *xchange, *sighash;
	uint32_t			 error;
	struct net2_encdec_ctx		 ectx;
	struct net2_pvlist		 pvlist;
	struct net2_cneg_key_xchange	*kx;
	struct net2_conn_negotiator	*cn = cn_ptr;
	struct net2_connection		*s = CNEG_CONN(cn);
	struct net2_workq		*wq;
	struct net2_cneg_stage1_req_signs
					*in_signs, *out_signs;

	/* If cancelation was requested, skip operation. */
	if (net2_promise_is_cancelreq(out)) {
		net2_promise_set_cancel(out, 0);
		return;
	}

	/* Check that there are exactly 7 promises. */
	if (insz != 7) {
		error = EINVAL;
		goto fail_0;
	}

	/*
	 * Gather results and check that each promise completed succesfully.
	 */
	if (net2_promise_get_result(in[0], (void**)&pver, NULL) !=
	    NET2_PROM_FIN_OK ||
	    net2_promise_get_result(in[1], (void**)&hash, NULL) !=
	    NET2_PROM_FIN_OK ||
	    net2_promise_get_result(in[2], (void**)&crypt, NULL) !=
	    NET2_PROM_FIN_OK ||
	    net2_promise_get_result(in[3], (void**)&xchange, NULL) !=
	    NET2_PROM_FIN_OK ||
	    net2_promise_get_result(in[4], (void**)&sighash, NULL) !=
	    NET2_PROM_FIN_OK ||
	    net2_promise_get_result(in[5], (void**)&in_signs, NULL) !=
	    NET2_PROM_FIN_OK ||
	    net2_promise_get_result(in[6], (void**)&out_signs, NULL) !=
	    NET2_PROM_FIN_OK) {
		error = EIO;
		goto fail_0;
	}

	/* Acquire workq. */
	if ((wq = net2_acceptor_socket_workq(&s->n2c_socket)) == NULL) {
		error = EIO;
		goto fail_0;
	}

	/* Create encdec ctx. */
	if ((error = net2_pvlist_init(&pvlist)) != 0)
		goto fail_0;
	error = net2_pvlist_add(&pvlist, &net2_proto, pver->proto0);
	if (error == 0)
		error = net2_encdec_ctx_init(&ectx, &pvlist, NULL);
	net2_pvlist_deinit(&pvlist);
	if (error != 0)
		goto fail_1;

	/* Create key exchange. */
	kx = net2_cneg_key_xchange_new(wq, &ectx, cn->context,
	    *hash, *crypt, *xchange, *sighash,
	    &cneg_ready_to_send_arg, cn, NULL,
	    out_signs->sz, out_signs->sctx,
	    in_signs->sz, in_signs->sctx);
	if (kx == NULL) {
		error = ENOMEM;
		goto fail_1;
	}

	/* Assign output. */
	if ((error = net2_promise_set_finok(out, kx, &kx_free2, NULL, 0)) != 0)
		goto fail_2;
	return;

fail_2:
	net2_cneg_key_xchange_free(kx);
fail_1:
	net2_encdec_ctx_deinit(&ectx);
fail_0:
	assert(error != 0);
	net2_promise_set_error(out, error, 0);
}
/* Assign key exchange to conn negotiator. */
static void
key_xchange_assign(void *kx_promise, void *cn_ptr)
{
	struct net2_cneg_key_xchange	*kx;
	struct net2_conn_negotiator	*cn = cn_ptr;
	int				 fin;
	uint32_t			 err;

	fin = net2_promise_get_result(kx_promise, (void**)&kx, &err);
	assert(fin != NET2_PROM_FIN_UNFINISHED);
	switch (fin) {
	case NET2_PROM_FIN_OK:
		assert(kx != NULL);
		cn->keyx = kx;
		if (net2_ck_init_key_xchange(&CNEG_CONN(cn)->n2c_keys, kx) != 0)
			goto fail;	/* Handle failure. */
		net2_promise_dontfree(kx_promise);
		break;
	default:
		err = EIO;
		/* FALLTHROUGH */
	case NET2_PROM_FIN_ERROR:
fail:
		net2_connection_close(CNEG_CONN(cn)); /* Handle failure. */
		break;
	}
}
/* Assign protocol version to conn negotiator. */
static void
pver_assign(void *pver_promise, void *cn_ptr)
{
	struct net2_cneg_stage1_pver	*pver;
	struct net2_conn_negotiator	*cn = cn_ptr;
	int				 fin;
	uint32_t			 err;

	fin = net2_promise_get_result(pver_promise, (void**)&pver, &err);
	assert(fin != NET2_PROM_FIN_UNFINISHED);
	switch (fin) {
	case NET2_PROM_FIN_OK:
		cn->flags_have = pver->flags;
		err = net2_pvlist_add(&cn->proto, &net2_proto, pver->proto0);
		if (err != 0)
			goto pass_error;
		break;
	default:
		err = EIO;
		/* FALLTHROUGH */
	case NET2_PROM_FIN_ERROR:
pass_error:
		net2_connection_close(CNEG_CONN(cn));
		break;
	}
}

/* Initialize connection negotiator. */
ILIAS_NET2_LOCAL int
net2_cneg_init(struct net2_conn_negotiator *cn, struct net2_ctx *context)
{
	int			 error;
	struct net2_connection	*s = CNEG_CONN(cn);
	struct net2_workq	*wq;
	struct net2_promise	*p_hash, *p_enc, *p_xchange, *p_kx,
				*p_pver, *p_sighash;

	assert(s != NULL);
	p_hash = p_enc = p_xchange = p_sighash = NULL;
	wq = net2_acceptor_socket_workq(&s->n2c_socket);

	if ((error = net2_pvlist_init(&cn->proto)) != 0)
		goto fail_0;

	cn->flags = cn->flags_have = 0;
	if (!(s->n2c_socket.fn->flags & NET2_SOCKET_SECURE)) {
		cn->flags |= NET2_CNEG_REQUIRE_ENCRYPTION |
		    NET2_CNEG_REQUIRE_SIGNING;
	}
	cn->stage = NET2_CNEG_STAGE_PRISTINE;
	cn->context = context;
	cn->recv_no_send = 0;
	if ((cn->stage1 = cneg_stage1_new(cn->flags, context, wq)) == NULL) {
		error = ENOMEM;
		goto fail_1;
	}
	cn->keyx = NULL;

	/*
	 * Extract support sets from stage1.
	 * Promises are delivered with reference from stage1.
	 */
	cn->hash = cneg_stage1_get_hash(cn->stage1);
	cn->enc = cneg_stage1_get_crypt(cn->stage1);
	cn->sign = cneg_stage1_get_sign(cn->stage1);
	cn->xchange = cneg_stage1_get_xchange(cn->stage1);
	if (cn->hash == NULL || cn->enc == NULL || cn->sign == NULL ||
	    cn->xchange == NULL) {
		error = ENOMEM;
		goto fail_2;
	}

	/* Hash selector promise setup. */
	p_hash = net2_promise_combine(wq, &choose_alg,
	    &select_hash, &cn->hash, 1);
	/* Enc selector promise setup. */
	p_enc = net2_promise_combine(wq, &choose_alg,
	    &select_enc, &cn->enc, 1);
	/* Xchange selector promise setup. */
	p_xchange = net2_promise_combine(wq, &choose_alg,
	    &select_xchange, &cn->xchange, 1);
	/* Signature hash selector promise setup. */
	p_sighash = net2_promise_combine(wq, &choose_alg,
	    &select_sighash, &cn->hash, 1);
	/* Check that promises above got created properly. */
	if (p_hash == NULL || p_enc == NULL ||
	    p_xchange == NULL || p_sighash == NULL) {
		error = ENOMEM;
		goto fail_2;
	}

	/* Create key xchange factory. */
	if ((p_kx = create_key_xchange_prom(wq, cn->stage1,
	    p_hash, p_enc, p_xchange, p_sighash)) == NULL) {
		error = ENOMEM;
		goto fail_2;
	}
	if ((error = net2_promise_event_init(&cn->kx_event, p_kx,
	    NET2_PROM_ON_FINISH, wq, &key_xchange_assign, p_kx, cn)) != 0)
		goto fail_3;
	/* p_kx will now be kept alive via its on-completion event. */
	net2_promise_release(p_kx);
	p_kx = NULL;

	/* Done.  Release temporary promises (they're chained). */
	net2_promise_release(p_hash);
	net2_promise_release(p_enc);
	net2_promise_release(p_xchange);
	net2_promise_release(p_sighash);
	p_hash = p_enc = p_xchange = p_sighash = NULL;

	/* Pver event: assign protocol version for net2_proto. */
	if ((p_pver = cneg_stage1_get_pver(cn->stage1)) == NULL)
		goto fail_4;
	error = net2_promise_event_init(&cn->pver_event, p_pver,
	    NET2_PROM_ON_FINISH, wq, &pver_assign, p_pver, cn);
	net2_promise_release(p_pver);
	if (error != 0)
		goto fail_4;

	return 0;


fail_5:
	net2_promise_event_deinit(&cn->pver_event);
fail_4:
	net2_promise_event_deinit(&cn->kx_event);
fail_3:
	if (p_kx != NULL) {
		net2_promise_cancel(p_kx);
		net2_promise_release(p_kx);
	}
fail_2:
	if (cn->hash != NULL)
		net2_promise_release(cn->hash);
	if (cn->enc != NULL)
		net2_promise_release(cn->enc);
	if (cn->sign != NULL)
		net2_promise_release(cn->sign);
	if (cn->xchange != NULL)
		net2_promise_release(cn->xchange);
	cneg_stage1_free(cn->stage1);
fail_1:
	net2_pvlist_deinit(&cn->proto);
fail_0:
	if (p_hash != NULL) {
		net2_promise_cancel(p_hash);
		net2_promise_release(p_hash);
	}
	if (p_enc != NULL) {
		net2_promise_cancel(p_enc);
		net2_promise_release(p_enc);
	}
	if (p_xchange != NULL) {
		net2_promise_cancel(p_xchange);
		net2_promise_release(p_xchange);
	}
	if (p_sighash != NULL) {
		net2_promise_cancel(p_sighash);
		net2_promise_release(p_sighash);
	}
	assert(error != 0);
	return error;
}

/* Destroy connection negotiator. */
ILIAS_NET2_LOCAL void
net2_cneg_deinit(struct net2_conn_negotiator *cn)
{
	/* Cancel events. */
	net2_promise_event_deinit(&cn->pver_event);
	net2_promise_event_deinit(&cn->kx_event);
	/* Release stage2 data. */
	if (cn->keyx != NULL)
		net2_cneg_key_xchange_free(cn->keyx);
	/* Release stage1 data. */
	if (cn->stage1 != NULL)
		cneg_stage1_free(cn->stage1);

	/* Release exposed promises. */
	net2_promise_release(cn->hash);
	net2_promise_release(cn->enc);
	net2_promise_release(cn->xchange);
	net2_promise_release(cn->sign);

	/* Release protocol information. */
	net2_pvlist_deinit(&cn->proto);

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
		error = cneg_stage1_get_transmit(cn->stage1,
		    net2_acceptor_socket_workq(&CNEG_CONN(cn)->n2c_socket),
		    buf, tx, maxlen, !stealth, want_payload);

		/* Append stage1 payload and set indicator flag. */
		if (!net2_buffer_empty(buf)) {
			*bufptr = buf;
			buf = NULL;
			ph->flags |= PH_HANDSHAKE;
		}

		break;

	case NET2_CNEG_STAGE_KEY_EXCHANGE:
		if (cn->keyx == NULL) {
			error = 0;
			break;
		}

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
	return net2_pvlist_merge(pv, &cn->proto);
}
