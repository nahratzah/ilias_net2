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
#include <ilias/net2/cneg_key_xchange.h>

#include <ilias/net2/buffer.h>
#include <ilias/net2/context.h>
#include <ilias/net2/cp.h>
#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/promise.h>
#include <ilias/net2/signed_carver.h>
#include <ilias/net2/tx_callback.h>

#include <ilias/net2/sign.h>
#include <ilias/net2/xchange.h>

#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>

#include "exchange.h"


/* Release key. */
ILIAS_NET2_EXPORT void
net2_cneg_key_result_deinit(struct net2_cneg_key_result *k)
{
	if (k->key) {
		net2_secure_zero((void*)k->key, k->keylen);
		net2_free((void*)k->key);
	}
}
/* Create key result from memory. */
ILIAS_NET2_EXPORT int
net2_cneg_key_result_init(struct net2_cneg_key_result *k,
    const void *data, size_t len)
{
	if (len == 0) {
		k->key = NULL;
		k->keylen = 0;
		return 0;
	}

	if (data == NULL)
		return EINVAL;
	k->keylen = len;
	if ((k->key = net2_malloc(len)) == NULL)
		return ENOMEM;
	memcpy((void*)k->key, data, len);
	return 0;
}
/* Create key result from buffer. */
ILIAS_NET2_EXPORT int
net2_cneg_key_result_initbuf(struct net2_cneg_key_result *k,
    struct net2_buffer *buf)
{
	if (buf == NULL)
		return EINVAL;
	k->keylen = net2_buffer_length(buf);
	if (k->keylen == 0) {
		k->key = NULL;
		return 0;
	}

	if ((k->key = net2_malloc(k->keylen)) == NULL)
		return ENOMEM;
	if (net2_buffer_copyout(buf, (void*)k->key, k->keylen) != k->keylen)
		return EIO;
	return 0;
}
/* Release function for key result (supplied to promise). */
static void
cneg_key_result_deinit2(void *k_ptr, void * ILIAS_NET2__unused unused)
{
	net2_cneg_key_result_deinit(k_ptr);
}


/* Additional information required to set up carver. */
struct xchange_carver_setup_data {
	struct net2_encdec_ctx	 ectx;
	struct net2_workq	*wq;
	struct net2_sign_ctx	**sigs;
	uint32_t		 num_sigs;
};

/*
 * State shared between xchange_local, xchange_remote.
 *
 * xchange: promise yielding net2_ctx_xchange_factory_result.
 * key_promise: promise yielding net2_cneg_key_result.
 */
struct xchange_shared {
	struct net2_promise	*xchange;	/* Xchange context. */
	struct net2_promise	*key_promise;	/* Key ready promise. */
	struct net2_promise	*complete;	/* Completion promise. */

	int			 alg;		/* Algorithm ID. */
	int			 xchange_alg;	/* Xchange method. */
	int			 sighash_alg;	/* Signature hash algorithm. */
	uint32_t		 keysize;	/* Negotiated key size. */

	uint16_t		 dstslot;	/* Destination slot. */
	uint16_t		 rcvslot;	/* Receive slot. */

	struct xchange_carver_setup_data
				*out_xcsd;
};

/* Locally initialized key negotiation. */
struct xchange_local {
	struct xchange_shared	 shared;	/* Shared state. */

	struct net2_signed_carver
				*init;		/* Initialization buffer. */
	struct net2_signed_carver
				*export;	/* Export buffer. */
	struct net2_signed_combiner
				*import;	/* Import buffer. */

	struct net2_promise_event
				 setup_carvers;	/* Event setting up carvers. */
	struct net2_promise_event
				 key_promise_complete;	/* key_complete ->
							 * complete */
	struct net2_promise_event
				 carver_complete;	/* carver_complete ->
							 * complete */
};
/* Remotely initialized key negotiation. */
struct xchange_remote {
	struct xchange_shared	 shared;	/* Shared state. */

	struct net2_signed_combiner
				*init;		/* Initialization buffer. */
	struct net2_signed_carver
				*export;	/* Export buffer. */
	struct net2_signed_combiner
				*import;	/* Import buffer. */

	struct net2_promise_event
				 setup_carvers;	/* Event setting up carvers. */
	struct net2_promise_event
				 key_promise_complete;	/* key_complete ->
							 * complete */
	struct net2_promise_event
				 carver_complete;	/* carver_complete ->
							 * complete */
};

/* Key negotiation handler. */
struct net2_cneg_key_xchange {
#define NET2_CNEG_S2_HASH	0	/* Hash key negotiation. */
#define NET2_CNEG_S2_ENC	1	/* Exchange key negotiation. */
#define NET2_CNEG_S2_MAX	2	/* # exchanges. */

	struct xchange_local	 local[NET2_CNEG_S2_MAX];
	struct xchange_remote	 remote[NET2_CNEG_S2_MAX];
	struct net2_promise	*complete;	/* Completion promise. */
};

/* Direct initialization (i.e. without factory) of xchange promise. */
struct pdirect_data {
	int			 xchange_alg;
	size_t			 keysize;

	struct net2_promise_event
				 ev;
};


static int	 xchange_shared_init(struct xchange_shared*, int, uint32_t,
		    int, int, uint16_t, uint16_t);
static void	 xchange_shared_deinit(struct xchange_shared*);

static void	 xchange_promise_pdd_job(void*, void*);
static void	 xchange_promise_pdd_release(void*, void*);
static struct net2_promise
		*xchange_promise_direct_new(struct net2_workq*, int, size_t);

static void	 xchange_carver_setup_data_free(
		    struct xchange_carver_setup_data*);
static struct xchange_carver_setup_data*
		 xchange_carver_setup_data(struct net2_workq*,
		    struct net2_encdec_ctx*, uint32_t, struct net2_sign_ctx**);

static void	 xchange_local_on_xchange(void*, void*);
static void	 xchange_remote_on_xchange(void*, void*);
static void	 prom_buffer_free(void*, void*);
static void	 xchange_import_combine(struct net2_promise*,
		    struct net2_promise**, size_t, void*);
static void	 key_verified_combine(struct net2_promise*,
		    struct net2_promise**, size_t, void*);
static void	 xchange_local_complete(void*, void*);
static void	 xchange_remote_complete(void*, void*);


/* Initialize shared portion of xchange_{local,remote}. */
static int
xchange_shared_init(struct xchange_shared *xs, int alg, uint32_t keysize,
    int xchange_alg, int sighash_alg, uint16_t dstslot, uint16_t rcvslot)
{
	xs->xchange = NULL;
	xs->key_promise = NULL;
	xs->complete = net2_promise_new();
	xs->alg = alg;
	xs->xchange_alg = xchange_alg;
	xs->sighash_alg = sighash_alg;
	xs->keysize = keysize;
	xs->dstslot = dstslot;
	xs->rcvslot = rcvslot;
	xs->out_xcsd = NULL;
	return 0;
}
/* Release shared portion of xchange_{local,remote}. */
static void
xchange_shared_deinit(struct xchange_shared *xs)
{
	if (xs->xchange != NULL)
		net2_promise_release(xs->xchange);
	if (xs->key_promise != NULL)
		net2_promise_release(xs->key_promise);
	if (xs->complete != NULL)
		net2_promise_release(xs->complete);
	if (xs->out_xcsd != NULL)
		xchange_carver_setup_data_free(xs->out_xcsd);
}


/* Run event for direct xchange promise. */
static void
xchange_promise_pdd_job(void *prom_ptr, void *pdd_ptr)
{
	struct net2_promise	*prom = prom_ptr;
	struct pdirect_data	*pdd = pdd_ptr;
	struct net2_ctx_xchange_factory_result
				*result;
	uint32_t		 error;

	assert(prom != NULL && pdd != NULL);

	/* Don't do any work if the promise was canceled. */
	if (net2_promise_is_cancelreq(prom)) {
		net2_promise_set_cancel(prom, 0);
		return;
	}

	if ((result = net2_malloc(sizeof(*result))) == NULL) {
		error = ENOMEM;
		goto fail;
	}
	result->initbuf = NULL;
	result->ctx = NULL;

	if ((result->initbuf = net2_buffer_new()) == NULL) {
		error = ENOMEM;
		goto fail;
	}
	if ((result->ctx = net2_xchangectx_prepare(pdd->xchange_alg,
	    pdd->keysize, NET2_XCHANGE_F_INITIATOR,
	    result->initbuf)) == NULL) {
		error = ENOMEM;
		goto fail;
	}

	if ((error = net2_promise_set_finok(prom, result,
	    &net2_ctx_xchange_factory_result_free, NULL, 0)) != 0)
		goto fail;
	return;


fail:
	net2_ctx_xchange_factory_result_free(result, NULL);
	net2_promise_set_error(prom, error, 0);
}
/* Free direct xchange promise argument. */
static void
xchange_promise_pdd_release(void *pdd_ptr, void * ILIAS_NET2__unused unused)
{
	struct pdirect_data	*pdd = pdd_ptr;

	net2_promise_event_deinit(&pdd->ev);
	net2_free(pdd);
}
/* Create new direct xchange promise. */
static struct net2_promise*
xchange_promise_direct_new(struct net2_workq *wq, int xchange_alg, size_t keysize)
{
	struct pdirect_data	*pdd;
	struct net2_promise	*prom;

	if ((pdd = net2_malloc(sizeof(*pdd))) == NULL)
		goto fail_0;
	pdd->xchange_alg = xchange_alg;
	pdd->keysize = keysize;

	if ((prom = net2_promise_new()) == NULL)
		goto fail_1;
	if (net2_promise_event_init(&pdd->ev, prom, NET2_PROM_ON_RUN, wq,
	    &xchange_promise_pdd_job, prom, pdd) != 0)
		goto fail_2;

	net2_promise_destroy_cb(prom, xchange_promise_pdd_release, pdd, NULL);
	pdd = NULL;	/* Now owned by prom. */

	return prom;


fail_3:
	if (pdd != NULL)
		net2_promise_event_deinit(&pdd->ev);
fail_2:
	net2_promise_cancel(prom);
	net2_promise_release(prom);
fail_1:
	if (pdd != NULL)
		net2_free(pdd);
fail_0:
	return NULL;
}


/* Release xchange_carver_setup_data. */
static void
xchange_carver_setup_data_free(struct xchange_carver_setup_data *xcsd)
{
	size_t			 i;

	xcsd->wq = NULL;	/* Borrowed only. */
	for (i = 0; i < xcsd->num_sigs; i++)
		net2_signctx_free(xcsd->sigs[i]);
	net2_free(xcsd->sigs);
	net2_encdec_ctx_deinit(&xcsd->ectx);
	net2_free(xcsd);
}
/* Create xchange_carver_setup_data. */
static struct xchange_carver_setup_data*
xchange_carver_setup_data(struct net2_workq *wq, struct net2_encdec_ctx *ectx,
    uint32_t num_sigs, struct net2_sign_ctx **sigs)
{
	struct xchange_carver_setup_data
				*xcsd;

	if ((xcsd = net2_malloc(sizeof(*xcsd))) == NULL)
		goto fail_0;
	xcsd->wq = wq;
	if ((xcsd->sigs = net2_calloc(num_sigs, sizeof(*xcsd->sigs))) == NULL)
		goto fail_1;

	/* Clone each signature. */
	for (xcsd->num_sigs = 0; xcsd->num_sigs < num_sigs; xcsd->num_sigs++) {
		if ((sigs[xcsd->num_sigs] =
		    net2_signctx_clone(sigs[xcsd->num_sigs])) == NULL)
			goto fail_3;
	}

	if (net2_encdec_ctx_init(&xcsd->ectx, &ectx->ed_proto, NULL) != 0)
		goto fail_3;

	return xcsd;


fail_4:
	net2_encdec_ctx_deinit(&xcsd->ectx);
fail_3:
	while (xcsd->num_sigs-- > 0)
		net2_signctx_free(xcsd->sigs[xcsd->num_sigs]);
fail_2:
	net2_free(xcsd->sigs);
fail_1:
	net2_free(xcsd);
fail_0:
	return NULL;
}

/*
 * xchange_local event callback.
 *
 * Event: xchange promise completion.
 * Initializes initbuf carver for sending data.
 */
static void
xchange_local_on_xchange(void *xl_ptr, void * ILIAS_NET2__unused unused)
{
	struct xchange_local	*xl = xl_ptr;
	struct xchange_carver_setup_data
				*xcsd;
	struct net2_ctx_xchange_factory_result
				*result;
	uint32_t		 xch_err;
	int			 fin;
	struct net2_buffer	*exportbuf;

	/* Claim ownership of out_xcsd. */
	xcsd = xl->shared.out_xcsd;
	xl->shared.out_xcsd = NULL;

	fin = net2_promise_get_result(xl->shared.xchange,
	    (void**)&result, &xch_err);
	assert(fin != NET2_PROM_FIN_UNFINISHED);

	/* Test if the promise finished succesfully. */
	if (fin != NET2_PROM_FIN_OK)
		goto fail_0;

	assert(result->ctx != NULL && result->initbuf != NULL);
	assert(xl->init == NULL && xl->export == NULL);

	/* Setup init signed_carver. */
	xl->init = net2_signed_carver_new(xcsd->wq, &xcsd->ectx,
	    result->initbuf,
	    xl->shared.sighash_alg, xcsd->num_sigs, xcsd->sigs);

	/* Setup export signed_carver. */
	if ((exportbuf = net2_xchangectx_export(result->ctx)) == NULL)
		goto fail_0;
	xl->export = net2_signed_carver_new(xcsd->wq, &xcsd->ectx, exportbuf,
	    xl->shared.sighash_alg, xcsd->num_sigs, xcsd->sigs);
	net2_buffer_free(exportbuf);
	exportbuf = NULL;

	/* Handle signed_carver initialization failure. */
	if (xl->init == NULL || xl->export == NULL)
		goto fail_1;

	/* Add completion callback to new carver. */
	if (net2_promise_event_init(&xl->carver_complete,
	    net2_signed_carver_complete(xl->export), NET2_PROM_ON_FINISH,
	    xcsd->wq, &xchange_local_complete, xl, NULL) != 0)
		goto fail_1;

	/* Free no longer needed xcsd. */
	xchange_carver_setup_data_free(xcsd);

	return;


fail_1:
	if (xl->init != NULL) {
		net2_signed_carver_destroy(xl->init);
		xl->init = NULL;	/* Prevent double free. */
	}
	if (xl->export != NULL) {
		net2_signed_carver_destroy(xl->export);
		xl->export = NULL;	/* Prevent double free. */
	}
fail_0:
	/* Set error value. */
	if (fin != NET2_PROM_FIN_OK &&
	    (fin != NET2_PROM_FIN_ERROR || xch_err != ENOMEM))
		net2_promise_set_error(xl->shared.key_promise, EIO, 0);
	else
		net2_promise_set_error(xl->shared.key_promise, ENOMEM, 0);

	xchange_carver_setup_data_free(xcsd);
}
/*
 * xchange_local event callback.
 *
 * Event: xchange promise completion.
 * Initializes initbuf carver for sending data.
 */
static void
xchange_remote_on_xchange(void *xr_ptr, void * ILIAS_NET2__unused unused)
{
	struct xchange_local	*xr = xr_ptr;
	struct xchange_carver_setup_data
				*xcsd;
	struct net2_ctx_xchange_factory_result
				*result;
	uint32_t		 xch_err;
	int			 fin;
	struct net2_buffer	*exportbuf;

	/* Claim ownership of out_xcsd. */
	xcsd = xr->shared.out_xcsd;
	xr->shared.out_xcsd = NULL;

	fin = net2_promise_get_result(xr->shared.xchange,
	    (void**)&result, &xch_err);
	assert(fin != NET2_PROM_FIN_UNFINISHED);

	/* Test if the promise finished succesfully. */
	if (fin != NET2_PROM_FIN_OK)
		goto fail_0;

	assert(result->ctx != NULL && result->initbuf != NULL);
	assert(xr->export == NULL);

	/* Setup export signed_carver. */
	if ((exportbuf = net2_xchangectx_export(result->ctx)) == NULL)
		goto fail_0;
	xr->export = net2_signed_carver_new(xcsd->wq, &xcsd->ectx, exportbuf,
	    xr->shared.sighash_alg, xcsd->num_sigs, xcsd->sigs);
	net2_buffer_free(exportbuf);
	exportbuf = NULL;

	/* Handle signed_carver initialization failure. */
	if (xr->export == NULL)
		goto fail_1;

	/* Add completion callback to new carver. */
	if (net2_promise_event_init(&xr->carver_complete,
	    net2_signed_carver_complete(xr->export), NET2_PROM_ON_FINISH,
	    xcsd->wq, &xchange_remote_complete, xr, NULL) != 0)
		goto fail_1;

	/* Free no longer needed xcsd. */
	xchange_carver_setup_data_free(xcsd);

	return;


fail_1:
	if (xr->export != NULL) {
		net2_signed_carver_destroy(xr->export);
		xr->export = NULL;	/* Prevent double free. */
	}
fail_0:
	/* Set error value. */
	if (fin != NET2_PROM_FIN_OK &&
	    (fin != NET2_PROM_FIN_ERROR || xch_err != ENOMEM))
		net2_promise_set_error(xr->shared.key_promise, EIO, 0);
	else
		net2_promise_set_error(xr->shared.key_promise, ENOMEM, 0);

	xchange_carver_setup_data_free(xcsd);
}

static void
prom_buffer_free(void *buf, void * ILIAS_NET2__unused unused)
{
	net2_buffer_free(buf);
}
/* Combine import buffer and xchange. */
static void
xchange_import_combine(struct net2_promise *out, struct net2_promise **in,
    size_t insz, void * ILIAS_NET2__unused unused)
{
	struct net2_ctx_xchange_factory_result
				*xch;
	struct net2_buffer	*import, *key;
	uint32_t		 xch_err, import_err;
	int			 xch_fin, import_fin;
	int			 error;

	assert(insz == 2);

	/* Handle out cancellation. */
	if (net2_promise_is_cancelreq(out)) {
		net2_promise_set_cancel(out, 0);
		return;
	}

	/* Read result. */
	xch_fin = net2_promise_get_result(in[0], (void**)&xch, &xch_err);
	import_fin = net2_promise_get_result(in[1], (void**)&import, &import_err);

	/* Cascade ENOMEM. */
	if ((xch_fin == NET2_PROM_FIN_ERROR && xch_err == ENOMEM) ||
	    (import_fin == NET2_PROM_FIN_ERROR && import_err == ENOMEM)) {
		net2_promise_set_error(out, ENOMEM, 0);
		return;
	}

	/* Any other end -> EIO failure. */
	if (xch_fin != NET2_PROM_FIN_OK || import_fin != NET2_PROM_FIN_OK) {
		net2_promise_set_error(out, EIO, 0);
		return;
	}

	/* Input succeeded. */
	assert(xch != NULL && xch->ctx != NULL && import != NULL);
	if ((error = net2_xchangectx_import(xch->ctx, import)) != 0) {
		net2_promise_set_error(out, error, 0);
		return;
	}

	/* Retrieve final key. */
	key = net2_xchangectx_final(xch->ctx);
	error = net2_promise_set_finok(out, key, &prom_buffer_free, NULL, 0);
	if (error != 0) {
		/* Assignment failure. */
		net2_buffer_free(key);
		net2_promise_set_error(out, error, 0);
	}
}
/* Combine verified import buffer with negotiated key. */
static void
key_verified_combine(struct net2_promise *out, struct net2_promise **in,
    size_t insz, void * ILIAS_NET2__unused unused)
{
	struct net2_buffer	*key;
	uint32_t		 key_err, verify_err;
	int			 error;
	size_t			 i;

	assert(insz >= 1);

	/* Handle out cancellation. */
	if (net2_promise_is_cancelreq(out)) {
		net2_promise_set_cancel(out, 0);
		return;
	}

	/* Check if all signatures were ok. */
	for (i = 1; i < insz; i++) {
		switch (net2_promise_get_result(in[i], NULL, &verify_err)) {
		case NET2_PROM_FIN_OK:
			break;
		case NET2_PROM_FIN_ERROR:
			net2_promise_set_error(out, verify_err, 0);
			return;
		default:
			net2_promise_set_error(out, EIO, 0);
			return;
		}
	}

	/* Check if key was generated succesfully. */
	switch (net2_promise_get_result(in[0], (void**)&key, &key_err)) {
	case NET2_PROM_FIN_OK:
		break;
	case NET2_PROM_FIN_ERROR:
		net2_promise_set_error(out, key_err, 0);
		return;
	default:
		net2_promise_set_error(out, EIO, 0);
		return;
	}

	/* Key was succesfully generated and all signatures matched. */
	if ((key = net2_buffer_copy(key)) == NULL) {
		net2_promise_set_error(out, ENOMEM, 0);
		return;
	}
	if ((error = net2_promise_set_finok(out, key, &prom_buffer_free, NULL,
	    0)) != 0) {
		net2_buffer_free(key);
		net2_promise_set_error(out, error, 0);
	}
}
/* xchange_local completion test. */
static void
xchange_local_complete(void *xl_ptr, void * ILIAS_NET2__unused unused)
{
	struct xchange_local	*xl = xl_ptr;
	struct net2_promise	*p_export, *p_key;
	int			 fin_export, fin_key;
	struct net2_buffer	*key;

	/* Don't attempt to assign to a finished promise. */
	if (net2_promise_is_finished(xl->shared.complete))
		return;
	/* If the promise is canceled, stop it now. */
	if (net2_promise_is_cancelreq(xl->shared.complete)) {
		net2_promise_set_cancel(xl->shared.complete, 0);
		return;
	}

	/* Test if export is complete. */
	if (xl->export == NULL)
		return;
	p_export = net2_signed_carver_complete(xl->export);
	fin_export = net2_promise_is_finished(p_export);
	if (fin_export == NET2_PROM_FIN_UNFINISHED)
		return;
	else if (fin_export != NET2_PROM_FIN_OK)
		goto fail;

	/* Test if key promise is complete. */
	p_key = xl->shared.key_promise;
	fin_key = net2_promise_get_result(p_key, (void**)&key, NULL);
	if (fin_key == NET2_PROM_FIN_UNFINISHED)
		return;
	else if (fin_key != NET2_PROM_FIN_OK)
		goto fail;

	/* All promises are complete. */
	assert(key != NULL);
	if ((key = net2_buffer_copy(key)) == NULL)
		goto fail;

	/* Assign key result. */
	if (net2_promise_set_finok(xl->shared.complete, key,
	    &prom_buffer_free, NULL, 0) != 0) {
		net2_buffer_free(key);
		goto fail;
	}

	return;

fail:
	net2_promise_set_error(xl->shared.complete, EIO, 0);
}
/* xchange_local completion test. */
static void
xchange_remote_complete(void *xr_ptr, void * ILIAS_NET2__unused unused)
{
	struct xchange_local	*xr = xr_ptr;
	struct net2_promise	*p_export, *p_key;
	int			 fin_export, fin_key;
	struct net2_buffer	*key;

	/* Don't attempt to assign to a finished promise. */
	if (net2_promise_is_finished(xr->shared.complete))
		return;
	/* If the promise is canceled, stop it now. */
	if (net2_promise_is_cancelreq(xr->shared.complete)) {
		net2_promise_set_cancel(xr->shared.complete, 0);
		return;
	}

	/* Test if export is complete. */
	if (xr->export == NULL)
		return;
	p_export = net2_signed_carver_complete(xr->export);
	fin_export = net2_promise_is_finished(p_export);
	if (fin_export == NET2_PROM_FIN_UNFINISHED)
		return;
	else if (fin_export != NET2_PROM_FIN_OK)
		goto fail;

	/* Test if key promise is complete. */
	p_key = xr->shared.key_promise;
	fin_key = net2_promise_get_result(p_key, (void**)&key, NULL);
	if (fin_key == NET2_PROM_FIN_UNFINISHED)
		return;
	else if (fin_key != NET2_PROM_FIN_OK)
		goto fail;

	/* All promises are complete. */
	assert(key != NULL);
	if ((key = net2_buffer_copy(key)) == NULL)
		goto fail;

	/* Assign key result. */
	if (net2_promise_set_finok(xr->shared.complete, key,
	    &prom_buffer_free, NULL, 0) != 0) {
		net2_buffer_free(key);
		goto fail;
	}

	return;

fail:
	net2_promise_set_error(xr->shared.complete, EIO, 0);
}

/* Create an xchange from a signed_combiner init buffer. */
static void
initbuf_import(struct net2_promise *out, struct net2_promise **in,
    size_t insz, void *xr_ptr)
{
	struct net2_buffer	*buf;
	struct xchange_remote	*xr = xr_ptr;
	struct net2_xchange_ctx	*ctx;
	struct net2_ctx_xchange_factory_result
				*result = NULL;
	uint32_t		 err;
	int			 fin;

	assert(insz == 1);

	/* Test if out was cancelled. */
	if (net2_promise_is_cancelreq(out)) {
		net2_promise_set_cancel(out, 0);
		return;
	}

	/* Get in[0] result. */
	fin = net2_promise_get_result(in[0], (void**)&buf, &err);
	assert(fin != NET2_PROM_FIN_UNFINISHED);

	/* Handle failure. */
	if (fin == NET2_PROM_FIN_ERROR && err == ENOMEM) {
		net2_promise_set_error(out, ENOMEM, 0);
		return;
	}
	if (fin != NET2_PROM_FIN_OK) {
		net2_promise_set_error(out, EIO, 0);
		return;
	}

	/* Calculate xchange result. */
	if ((result = net2_malloc(sizeof(*result))) == NULL) {
		net2_promise_set_error(out, ENOMEM, 0);
		return;
	}

	/* Create xchange ctx. */
	result->ctx = net2_xchangectx_prepare(xr->shared.xchange_alg,
	    xr->shared.keysize, 0, buf);
	result->initbuf = net2_buffer_copy(buf);
	if (result->initbuf == NULL || result->ctx == NULL)
		goto fail;

	/* Assign result. */
	if ((net2_promise_set_finok(out, result,
	    &net2_ctx_xchange_factory_result_free, NULL, 0)) != 0)
		goto fail;
	return;

fail:
	if (result != NULL)
		net2_ctx_xchange_factory_result_free(result, NULL);
	net2_promise_set_error(out, EIO, 0);
}

/*
 * Initialize local xchange.
 *
 * nctx: allowed to be null
 */
static int
xchange_local_init(
    struct xchange_local *xl,
    struct net2_workq *wq, struct net2_encdec_ctx *ectx,
    struct net2_ctx *nctx,
    int alg, uint32_t keysize, int xchange_alg, int sighash_alg,
    uint16_t dstslot, uint16_t rcvslot,
    uint32_t num_outsigs, struct net2_sign_ctx **outsigs,
    uint32_t num_insigs, struct net2_sign_ctx **insigs)
{
	struct net2_promise	*key_unverified;
	struct net2_promise	*prom2[2]; /* tmp references. */
	int			 error;

	if ((error = xchange_shared_init(&xl->shared, alg, keysize,
	    xchange_alg, sighash_alg, dstslot, rcvslot)) != 0)
		goto fail_0;

	/* Setup carver setup data. */
	if ((xl->shared.out_xcsd = xchange_carver_setup_data(wq, ectx,
	    num_outsigs, outsigs)) == NULL) {
		error = ENOMEM;
		goto fail_1;
	}

	/*
	 * Set up xchange promise.
	 * If nctx is NULL or fails to create a promise,
	 * create an in-thread promise instead.
	 */
	if (xl->shared.xchange == NULL && nctx != NULL) {
		/* Try to use net2_ctx. */
		xl->shared.xchange = net2_ctx_get_xchange(nctx,
		    xchange_alg, keysize);
	}
	if (xl->shared.xchange == NULL) {
		/* Create direct promise. */
		xl->shared.xchange = xchange_promise_direct_new(wq,
		    xchange_alg, keysize);
	}
	if (xl->shared.xchange == NULL) {
		error = ENOMEM;
		goto fail_1;
	}

	/* Set up import combiner. */
	if ((xl->import = net2_signed_combiner_new(wq, ectx,
	    num_insigs, insigs)) == NULL) {
		error = ENOMEM;
		goto fail_1;
	}
	/* Set up xchange+import promise. */
	prom2[0] = xl->shared.xchange;
	prom2[1] = net2_signed_combiner_payload(xl->import);
	if ((key_unverified = net2_promise_combine(wq, &xchange_import_combine,
	    NULL, prom2, 2)) == NULL) {
		error = ENOMEM;
		goto fail_2;
	}
	/* Set up verified key promise. */
	prom2[0] = key_unverified;
	prom2[1] = net2_signed_combiner_complete(xl->import);
	if ((xl->shared.key_promise = net2_promise_combine(wq,
	    &key_verified_combine, NULL, prom2, 2)) == NULL) {
		error = ENOMEM;
		goto fail_3;
	}
	net2_promise_release(key_unverified);
	key_unverified = NULL;	/* Free floating promise. */


	/* Event: create carvers from xchange. */
	if ((error = net2_promise_event_init(&xl->setup_carvers,
	    xl->shared.xchange, NET2_PROM_ON_RUN, wq,
	    &xchange_local_on_xchange, xl, NULL)) != 0)
		goto event_0;

	/* Assign event to completion routine. */
	if ((error = net2_promise_event_init(&xl->key_promise_complete,
	    xl->shared.key_promise, NET2_PROM_ON_FINISH, wq,
	    &xchange_local_complete, xl, NULL)) != 0)
		goto event_1;
	if ((error = net2_promise_set_running(xl->shared.complete)) != 0)
		goto event_1;

	return 0;


event_2:
	net2_promise_event_deinit(&xl->key_promise_complete);
event_1:
	net2_promise_event_deinit(&xl->setup_carvers);
event_0:


fail_3:
	if (key_unverified != NULL)
		net2_promise_release(key_unverified);
fail_2:
	net2_signed_combiner_destroy(xl->import);
fail_1:
	xchange_shared_deinit(&xl->shared);
fail_0:
	return error;
}
/* Release all resources held by local xchange. */
static void
xchange_local_deinit(struct xchange_local *xl)
{
	/* First, destroy events (to ensure they won't run). */
	net2_promise_event_deinit(&xl->setup_carvers);
	net2_promise_event_deinit(&xl->key_promise_complete);
	if (xl->export != NULL)
		net2_promise_event_deinit(&xl->carver_complete);

	/* Release carvers/combiners. */
	if (xl->init)
		net2_signed_carver_destroy(xl->init);
	if (xl->import)
		net2_signed_combiner_destroy(xl->import);
	if (xl->export)
		net2_signed_carver_destroy(xl->export);

	xchange_shared_deinit(&xl->shared);
}

/*
 * Initialize remote xchange.
 *
 * nctx: allowed to be null
 */
static int
xchange_remote_init(
    struct xchange_remote *xr,
    struct net2_workq *wq, struct net2_encdec_ctx *ectx,
    struct net2_ctx * ILIAS_NET2__unused nctx,
    int alg, uint32_t keysize, int xchange_alg, int sighash_alg,
    uint16_t dstslot, uint16_t rcvslot,
    uint32_t num_outsigs, struct net2_sign_ctx **outsigs,
    uint32_t num_insigs, struct net2_sign_ctx **insigs)
{
	struct net2_promise	*key_unverified;
	struct net2_promise	*prom2[3]; /* tmp references. */
	int			 error;

	if ((error = xchange_shared_init(&xr->shared, alg, keysize,
	    xchange_alg, sighash_alg, dstslot, rcvslot)) != 0)
		goto fail_0;

	/* Set up init combiner. */
	if ((xr->init = net2_signed_combiner_new(wq, ectx,
	    num_outsigs, outsigs)) == NULL) {
		error = ENOMEM;
		goto fail_1;
	}

	/* Setup carver setup data. */
	if ((xr->shared.out_xcsd = xchange_carver_setup_data(wq, ectx,
	    num_outsigs, outsigs)) == NULL) {
		error = ENOMEM;
		goto fail_2;
	}

	/* Set up xchange promise. */
	prom2[0] = net2_signed_combiner_payload(xr->import);
	if ((xr->shared.xchange = net2_promise_combine(wq, initbuf_import,
	    xr, prom2, 1)) == NULL) {
		error = ENOMEM;
		goto fail_2;
	}

	/* Set up import combiner. */
	if ((xr->import = net2_signed_combiner_new(wq, ectx,
	    num_insigs, insigs)) == NULL)
		goto fail_2;
	/* Set up xchange+import promise. */
	prom2[0] = xr->shared.xchange;
	prom2[1] = net2_signed_combiner_payload(xr->import);
	if ((key_unverified = net2_promise_combine(wq, &xchange_import_combine,
	    NULL, prom2, 2)) == NULL)
		goto fail_3;
	/* Set up verified key promise. */
	prom2[0] = key_unverified;
	prom2[1] = net2_signed_combiner_complete(xr->import);
	prom2[2] = net2_signed_combiner_complete(xr->init);
	if ((xr->shared.key_promise = net2_promise_combine(wq,
	    &key_verified_combine, NULL, prom2, 2)) == NULL)
		goto fail_4;
	net2_promise_release(key_unverified);
	key_unverified = NULL;	/* Free floating promise. */


	/* Event: create carvers from xchange. */
	if ((error = net2_promise_event_init(&xr->setup_carvers,
	    xr->shared.xchange, NET2_PROM_ON_RUN, wq,
	    &xchange_remote_on_xchange, xr, NULL)) != 0)
		goto event_0;

	/* Assign event to completion routine. */
	if ((error = net2_promise_event_init(&xr->key_promise_complete,
	    xr->shared.key_promise, NET2_PROM_ON_FINISH, wq,
	    &xchange_remote_complete, xr, NULL)) != 0)
		goto event_1;
	if ((error = net2_promise_set_running(xr->shared.complete)) != 0)
		goto event_1;

	return 0;


event_2:
	net2_promise_event_deinit(&xr->key_promise_complete);
event_1:
	net2_promise_event_deinit(&xr->setup_carvers);
event_0:


fail_4:
	if (key_unverified != NULL)
		net2_promise_release(key_unverified);
fail_3:
	net2_signed_combiner_destroy(xr->import);
fail_2:
	net2_signed_combiner_destroy(xr->init);
fail_1:
	xchange_shared_deinit(&xr->shared);
fail_0:
	return error;
}
/* Release all resources held by local xchange. */
static void
xchange_remote_deinit(struct xchange_remote *xr)
{
	/* First, destroy events (to ensure they won't run). */
	net2_promise_event_deinit(&xr->setup_carvers);
	net2_promise_event_deinit(&xr->key_promise_complete);
	if (xr->export != NULL)
		net2_promise_event_deinit(&xr->carver_complete);

	/* Release carvers/combiners. */
	if (xr->init)
		net2_signed_combiner_destroy(xr->init);
	if (xr->import)
		net2_signed_combiner_destroy(xr->import);
	if (xr->export)
		net2_signed_carver_destroy(xr->export);

	xchange_shared_deinit(&xr->shared);
}
