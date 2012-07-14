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
#include <ilias/net2/ctypes.h>
#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/promise.h>
#include <ilias/net2/bsd_compat/secure_random.h>
#include <ilias/net2/signed_carver.h>
#include <ilias/net2/tx_callback.h>

#include <ilias/net2/hash.h>
#include <ilias/net2/enc.h>
#include <ilias/net2/sign.h>
#include <ilias/net2/xchange.h>
#include <ilias/net2/poetry.h>

#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>


/* Free a key set. */
ILIAS_NET2_LOCAL void
net2_cneg_keyset_free(struct net2_cneg_keyset *ks)
{
	size_t			 i;

	for (i = 0; i < NET2_CNEG_S2_MAX; i++) {
		if (ks->tx[i] != NULL)
			net2_buffer_free(ks->tx[i]);
		if (ks->rx[i] != NULL)
			net2_buffer_free(ks->rx[i]);
	}
	net2_free(ks);
}
/* Duplicate a keyset. */
ILIAS_NET2_LOCAL struct net2_cneg_keyset*
net2_cneg_keyset_dup(struct net2_cneg_keyset *ks)
{
	struct net2_cneg_keyset	*copy;
	size_t			 i;

	/* Initialize empty keyset. */
	if ((copy = net2_malloc(sizeof(*copy))) == NULL)
		return NULL;
	for (i = 0; i < NET2_CNEG_S2_MAX; i++)
		copy->tx[i] = copy->rx[i] = NULL;

	/* Copy all tx keys. */
	for (i = 0; i < NET2_CNEG_S2_MAX; i++) {
		if (ks->tx[i] == NULL)
			continue;
		if ((copy->tx[i] = net2_buffer_copy(ks->tx[i])) == NULL)
			goto fail;
	}
	/* Copy all rx keys. */
	for (i = 0; i < NET2_CNEG_S2_MAX; i++) {
		if (ks->rx[i] == NULL)
			continue;
		if ((copy->rx[i] = net2_buffer_copy(ks->rx[i])) == NULL)
			goto fail;
	}

	return copy;

fail:
	net2_cneg_keyset_free(copy);
	return NULL;
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

	struct xchange_carver_setup_data
				*out_xcsd;

	struct {
		void		(*fn)(void*, void*);
		void		*arg0, *arg1;
	}			 rts;		/* Ready-to-send event. */
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

#define NET2_CNEG_LOCAL		0x0000	/* Local inited exchange. */
#define NET2_CNEG_REMOTE	0x8000	/* Remote inited exchange. */

#define NET2_CNEG__LRMASK	0x8000	/* Mask local/remote bit. */
#define NET2_CNEG__MASK		(~NET2_CNEG__LRMASK) /* Slot index mask. */

	struct xchange_local	 local[NET2_CNEG_S2_MAX];
	struct xchange_remote	 remote[NET2_CNEG_S2_MAX];
	struct net2_promise	*keys;	/* Unverified keys are ready. */
	struct net2_promise	*complete; /* Completion promise. */
};

/* Direct initialization (i.e. without factory) of xchange promise. */
struct pdirect_data {
	int			 xchange_alg;
	size_t			 keysize;

	struct net2_promise_event
				 ev;
};


static int	 xchange_shared_init(struct xchange_shared*, int, uint32_t,
		    int, int,
		    void (*)(void*, void*), void*, void*);
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


static void	 half_keyset_free(void*, void*);
static void	 key_xchange_combine(struct net2_promise*,
		    struct net2_promise**, size_t, void*);
static void	 key_xchange_combine_final(struct net2_promise*,
		    struct net2_promise**, size_t, void*);
static void	 key_xchange_checked(struct net2_promise*,
		    struct net2_promise**, size_t, void*);


/* Initialize shared portion of xchange_{local,remote}. */
static int
xchange_shared_init(struct xchange_shared *xs, int alg, uint32_t keysize,
    int xchange_alg, int sighash_alg,
    void (*rts_fn)(void*, void*), void *rts_arg0, void *rts_arg1)
{
	xs->xchange = NULL;
	xs->key_promise = NULL;
	xs->complete = net2_promise_new();
	xs->alg = alg;
	xs->xchange_alg = xchange_alg;
	xs->sighash_alg = sighash_alg;
	xs->keysize = keysize;
	xs->out_xcsd = NULL;
	xs->rts.fn = rts_fn;
	xs->rts.arg0 = rts_arg0;
	xs->rts.arg1 = rts_arg1;
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
xchange_promise_pdd_release(void *pdd_ptr, void *unused ILIAS_NET2__unused)
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
xchange_local_on_xchange(void *xl_ptr, void *unused ILIAS_NET2__unused)
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

	/* Set ready-to-send callback. */
	net2_signed_carver_set_rts(xl->init, xl->shared.rts.fn,
	    xl->shared.rts.arg0, xl->shared.rts.arg1);
	net2_signed_carver_set_rts(xl->export, xl->shared.rts.fn,
	    xl->shared.rts.arg0, xl->shared.rts.arg1);

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
xchange_remote_on_xchange(void *xr_ptr, void *unused ILIAS_NET2__unused)
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

	/* Assign ready-to-send callback. */
	net2_signed_carver_set_rts(xr->export, xr->shared.rts.fn,
	    xr->shared.rts.arg0, xr->shared.rts.arg1);

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
prom_buffer_free(void *buf, void *unused ILIAS_NET2__unused)
{
	net2_buffer_free(buf);
}
/* Combine import buffer and xchange. */
static void
xchange_import_combine(struct net2_promise *out, struct net2_promise **in,
    size_t insz, void *unused ILIAS_NET2__unused)
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
    size_t insz, void *unused ILIAS_NET2__unused)
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
xchange_local_complete(void *xl_ptr, void *unused ILIAS_NET2__unused)
{
	struct xchange_local	*xl = xl_ptr;
	struct net2_promise	*p_export, *p_init, *p_key;
	int			 fin_export, fin_init, fin_key;
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
		fin_export = NET2_PROM_FIN_UNFINISHED;
	else {
		p_export = net2_signed_carver_complete(xl->export);
		fin_export = net2_promise_is_finished(p_export);
		if (fin_export != NET2_PROM_FIN_OK &&
		    fin_export != NET2_PROM_FIN_UNFINISHED)
			goto fail;
	}

	/* Test if init is complete. */
	if (xl->init == NULL)
		fin_init = NET2_PROM_FIN_UNFINISHED;
	else {
		p_init = net2_signed_carver_complete(xl->init);
		fin_init = net2_promise_is_finished(p_init);
		if (fin_init != NET2_PROM_FIN_OK &&
		    fin_init != NET2_PROM_FIN_UNFINISHED)
			goto fail;
	}

	/* Test if key promise is complete. */
	p_key = xl->shared.key_promise;
	fin_key = net2_promise_get_result(p_key, (void**)&key, NULL);
	if (fin_key != NET2_PROM_FIN_OK &&
	    fin_key != NET2_PROM_FIN_UNFINISHED)
		goto fail;

	/*
	 * No failures so far.
	 * If any dependancy is unfinished, stop now and recheck on next
	 * invocation.
	 */
	if (fin_key == NET2_PROM_FIN_UNFINISHED ||
	    fin_init == NET2_PROM_FIN_UNFINISHED ||
	    fin_export == NET2_PROM_FIN_UNFINISHED)
		return;

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
xchange_remote_complete(void *xr_ptr, void *unused ILIAS_NET2__unused)
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
		fin_export = NET2_PROM_FIN_UNFINISHED;
	else {
		p_export = net2_signed_carver_complete(xr->export);
		fin_export = net2_promise_is_finished(p_export);
		if (fin_export != NET2_PROM_FIN_OK ||
		    fin_export != NET2_PROM_FIN_UNFINISHED)
			goto fail;
	}

	/* Test if key promise is complete. */
	p_key = xr->shared.key_promise;
	fin_key = net2_promise_get_result(p_key, (void**)&key, NULL);
	if (fin_key != NET2_PROM_FIN_OK &&
	    fin_key != NET2_PROM_FIN_UNFINISHED)
		goto fail;

	/*
	 * No errors so far.
	 * If any promise still needs to complete, return now and recheck
	 * on next invocation.
	 */
	if (fin_key == NET2_PROM_FIN_UNFINISHED ||
	    fin_export == NET2_PROM_FIN_UNFINISHED)
		return;

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
    void (*rts_fn)(void*, void*), void *rts_arg0, void *rts_arg1,
    uint32_t num_outsigs, struct net2_sign_ctx **outsigs,
    uint32_t num_insigs, struct net2_sign_ctx **insigs)
{
	struct net2_promise	*key_unverified;
	struct net2_promise	*prom2[2]; /* tmp references. */
	int			 error;

	if ((error = xchange_shared_init(&xl->shared, alg, keysize,
	    xchange_alg, sighash_alg,
	    rts_fn, rts_arg0, rts_arg1)) != 0)
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
    struct net2_ctx *nctx ILIAS_NET2__unused,
    int alg, uint32_t keysize, int xchange_alg, int sighash_alg,
    void (*rts_fn)(void*, void*), void *rts_arg0, void *rts_arg1,
    uint32_t num_outsigs, struct net2_sign_ctx **outsigs,
    uint32_t num_insigs, struct net2_sign_ctx **insigs)
{
	struct net2_promise	*key_unverified;
	struct net2_promise	*prom2[3]; /* tmp references. */
	int			 error;

	if ((error = xchange_shared_init(&xr->shared, alg, keysize,
	    xchange_alg, sighash_alg,
	    rts_fn, rts_arg0, rts_arg1)) != 0)
		goto fail_0;

	/* Set up init combiner. */
	if ((xr->init = net2_signed_combiner_new(wq, ectx,
	    num_insigs, insigs)) == NULL) {
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


/*
 * For data originating from a local exchange, these two bits
 * determine what data is present.
 */
#define XL_INIT		0x01	/* Init buffer was sent. */
#define XL_EXPORT	0x02	/* Export buffer was sent. */

/* Get transmission for xchange_remote. */
static __inline int
xchange_remote_get_transmit(struct xchange_remote *xr,
    struct net2_encdec_ctx *ectx, struct net2_workq *wq,
    struct net2_buffer *buf, struct net2_tx_callback *txcb, size_t maxsz)
{
	/* Only 1 carver is present. */
	if (xr->export == NULL)
		return 0;
	return net2_signed_carver_get_transmit(xr->export, ectx, wq, buf,
	    txcb, maxsz);
}

/* Get transmission for xchange_local. */
static int
xchange_local_get_transmit(struct xchange_local *xl,
    struct net2_encdec_ctx *ectx, struct net2_workq *wq,
    struct net2_buffer *buf, struct net2_tx_callback *txcb, size_t maxsz)
{
	struct net2_tx_callback	 tmp_txcb;
	struct net2_buffer	*tmp_buf;
	int			 error;
	size_t			 len = 0;
	uint8_t			 status = (XL_INIT | XL_EXPORT);

	assert(net2_buffer_empty(buf));

	if ((error = net2_txcb_init(&tmp_txcb)) != 0)
		goto fail_0;
	if ((tmp_buf = net2_buffer_new()) == NULL) {
		error = ENOMEM;
		goto fail_1;
	}

	/* Send init. */
	error = net2_signed_carver_get_transmit(xl->init, ectx, wq, tmp_buf,
	    &tmp_txcb, maxsz - len);
	if (error != 0)
		goto fail_2;

	if (net2_buffer_empty(tmp_buf)) {
		status &= ~XL_INIT;
	} else {
		/* Append to output buf. */
		len = net2_buffer_length(tmp_buf);
		assert(net2_buffer_length(buf) + len <= maxsz);
		net2_buffer_remove_buffer(tmp_buf, buf, len);
	}

	/* Send export. */
	error = net2_signed_carver_get_transmit(xl->export, ectx, wq, tmp_buf,
	    &tmp_txcb, maxsz - len);
	if (error != 0)
		goto fail_2;

	if (net2_buffer_empty(tmp_buf)) {
		status &= ~XL_EXPORT;
	} else {
		/* Append to output buf. */
		len = net2_buffer_length(tmp_buf);
		assert(net2_buffer_length(buf) + len <= maxsz);
		net2_buffer_remove_buffer(tmp_buf, buf, len);
	}

	/* Write status byte. */
	if (status) {
		if ((error = net2_cp_encode(ectx, &cp_uint8, tmp_buf, &status,
		    NULL)) != 0)
			goto fail_2;
		net2_buffer_prepend(buf, tmp_buf);
	}

	net2_txcb_merge(txcb, &tmp_txcb);
	error = 0;	/* Use failure path for cleanup. */

fail_2:
	net2_buffer_free(tmp_buf);
fail_1:
	net2_txcb_nack(&tmp_txcb);
	net2_txcb_deinit(&tmp_txcb);
fail_0:
	if (error != 0)
		net2_buffer_truncate(buf, 0);
	return error;
}

/* Accept data sent to xchange_remote. */
static int
xchange_remote_accept(struct xchange_remote *xl,
    struct net2_encdec_ctx *ectx, struct net2_buffer *buf)
{
	uint8_t			 status;
	int			 error;

	assert(xl->init != NULL && xl->import != NULL);
	if ((error = net2_cp_decode(ectx, &cp_uint8, &status, buf, NULL)) != 0)
		goto fail;

	if (status & XL_INIT) {
		if ((error = net2_signed_combiner_accept(xl->init, ectx, buf)) != 0)
			goto fail;
	}
	if (status & XL_EXPORT) {
		if ((error = net2_signed_combiner_accept(xl->import, ectx, buf)) != 0)
			goto fail;
	}

fail:
	return error;
}

/* Accept data sent to xchange_local. */
static __inline int
xchange_local_accept(struct xchange_local *xl,
    struct net2_encdec_ctx *ectx, struct net2_buffer *buf)
{
	assert(xl->import != NULL);
	return net2_signed_combiner_accept(xl->import, ectx, buf);
}


/* Flip a slot from local to remote. */
static __inline uint16_t
flip_slot(uint16_t slot)
{
	return slot ^ NET2_CNEG__LRMASK;
}

/* Initialize key exchange. */
ILIAS_NET2_LOCAL struct net2_cneg_key_xchange*
net2_cneg_key_xchange_new(struct net2_workq *wq, struct net2_encdec_ctx *ectx,
    struct net2_ctx *nctx,
    int hash_alg, int enc_alg,
    int xchange_alg, int sighash_alg,
    void (*rts_fn)(void*, void*), void *rts_arg0, void *rts_arg1,	/* XXX Hide these. */
    uint32_t num_outsigs, struct net2_sign_ctx **outsigs,
    uint32_t num_insigs, struct net2_sign_ctx **insigs)
{
	struct net2_cneg_key_xchange	*ke;
	struct net2_promise		*proms[2 * NET2_CNEG_S2_MAX + 1];
	struct net2_promise		*local_keys, *remote_keys;
	size_t				 i;
	size_t				 hash_keysize, enc_keysize;

	hash_keysize = net2_hash_getkeylen(hash_alg);
	enc_keysize = net2_enc_getkeylen(enc_alg);

	if ((ke = net2_malloc(sizeof(*ke))) == NULL)
		goto fail_0;

	if (xchange_local_init(&ke->local[NET2_CNEG_S2_HASH],
	    wq, ectx, nctx, hash_alg, hash_keysize, xchange_alg, sighash_alg,
	    rts_fn, rts_arg0, rts_arg1,
	    num_outsigs, outsigs, num_insigs, insigs))
		goto fail_1;
	if (xchange_local_init(&ke->local[NET2_CNEG_S2_ENC],
	    wq, ectx, nctx, enc_alg, enc_keysize, xchange_alg, sighash_alg,
	    rts_fn, rts_arg0, rts_arg1,
	    num_outsigs, outsigs, num_insigs, insigs))
		goto fail_2;
	if (xchange_remote_init(&ke->remote[NET2_CNEG_S2_HASH],
	    wq, ectx, nctx, hash_alg, hash_keysize, xchange_alg, sighash_alg,
	    rts_fn, rts_arg0, rts_arg1,
	    num_outsigs, outsigs, num_insigs, insigs))
		goto fail_3;
	if (xchange_remote_init(&ke->remote[NET2_CNEG_S2_ENC],
	    wq, ectx, nctx, enc_alg, enc_keysize, xchange_alg, sighash_alg,
	    rts_fn, rts_arg0, rts_arg1,
	    num_outsigs, outsigs, num_insigs, insigs))
		goto fail_4;

	/* Set up promise for local keys. */
	for (i = 0; i < NET2_CNEG_S2_MAX; i++)
		proms[i] = ke->local[i].shared.key_promise;
	if ((local_keys = net2_promise_combine(wq, &key_xchange_combine,
	    NULL, proms, NET2_CNEG_S2_MAX)) == NULL)
		goto fail_5;

	/* Set up promise for remote keys. */
	for (i = 0; i < NET2_CNEG_S2_MAX; i++)
		proms[i] = ke->remote[i].shared.key_promise;
	if ((remote_keys = net2_promise_combine(wq, &key_xchange_combine,
	    NULL, proms, NET2_CNEG_S2_MAX)) == NULL)
		goto fail_6;

	/* Set up combined promise for keys. */
	proms[0] = local_keys;
	proms[1] = remote_keys;
	if ((ke->keys = net2_promise_combine(wq, &key_xchange_combine_final,
	    NULL, proms, 2)) == NULL)
		goto fail_7;

	/*
	 * Now that ke->keys is set up, release {local,remote}_keys.
	 * These promises will be free-floating.
	 */
	net2_promise_release(local_keys);
	local_keys = NULL;
	net2_promise_release(remote_keys);
	remote_keys = NULL;

	/* Set up combined promise for completion. */
	proms[0] = ke->keys;
	for (i = 0; i < NET2_CNEG_S2_MAX; i++) {
		proms[2 * i + 1] = ke->local[i].shared.complete;
		proms[2 * i + 2] = ke->remote[i].shared.complete;
	}
	if ((ke->complete = net2_promise_combine(wq, &key_xchange_checked,
	    NULL, proms, 2 * NET2_CNEG_S2_MAX + 1)) == NULL)
		goto fail_8;

	return ke;


fail_9:
	net2_promise_cancel(ke->complete);
	net2_promise_release(ke->complete);
fail_8:
	net2_promise_cancel(ke->keys);
	net2_promise_release(ke->keys);
fail_7:
	if (remote_keys != NULL) {
		net2_promise_cancel(remote_keys);
		net2_promise_release(remote_keys);
	}
fail_6:
	if (local_keys != NULL) {
		net2_promise_cancel(local_keys);
		net2_promise_release(local_keys);
	}
fail_5:
	xchange_remote_deinit(&ke->remote[NET2_CNEG_S2_ENC]);
fail_4:
	xchange_remote_deinit(&ke->remote[NET2_CNEG_S2_HASH]);
fail_3:
	xchange_local_deinit(&ke->local[NET2_CNEG_S2_ENC]);
fail_2:
	xchange_local_deinit(&ke->local[NET2_CNEG_S2_HASH]);
fail_1:
	net2_free(ke);
fail_0:
	return NULL;
}
/* Destroy key_xchange. */
ILIAS_NET2_LOCAL void
net2_cneg_key_xchange_free(struct net2_cneg_key_xchange *ke)
{
	size_t			 i;

	net2_promise_cancel(ke->complete);
	net2_promise_cancel(ke->keys);
	net2_promise_release(ke->complete);
	net2_promise_release(ke->keys);

	for (i = 0; i < NET2_CNEG_S2_MAX; i++)
		xchange_remote_deinit(&ke->remote[i]);
	for (i = 0; i < NET2_CNEG_S2_MAX; i++)
		xchange_local_deinit(&ke->local[i]);
	net2_free(ke);
}


/* Intermediate type to contain keys. */
typedef struct net2_buffer *half_keyset[NET2_CNEG_S2_MAX];

/* Free half keyset. */
static void
half_keyset_free(void *hks, void *unused ILIAS_NET2__unused)
{
	half_keyset		*result = hks;
	size_t			 i;

	for (i = 0; i < NET2_CNEG_S2_MAX; i++) {
		if ((*result)[i] != NULL)
			net2_buffer_free((*result)[i]);
	}
	net2_free(result);
}

/*
 * Combine key xchange keys.
 * Only combines a single side of the keys (either remote, or local).
 */
static void
key_xchange_combine(struct net2_promise *out, struct net2_promise **in,
    size_t insz, void *unused ILIAS_NET2__unused)
{
	int			 fin;
	uint32_t		 err;
	half_keyset		*result;
	struct net2_buffer	*buf[NET2_CNEG_S2_MAX];
	size_t			 i;

	assert(insz == NET2_CNEG_S2_MAX);

	/* If the promise was canceled, don't bother expending more effort. */
	if (net2_promise_is_cancelreq(out)) {
		net2_promise_set_cancel(out, 0);
		return;
	}

	/* Collect results. */
	for (i = 0; i < NET2_CNEG_S2_MAX; i++) {
		fin = net2_promise_get_result(in[i], (void**)&buf[i], &err);
		assert(fin != NET2_PROM_FIN_UNFINISHED);

		/* Fail on error. */
		if (fin == NET2_PROM_FIN_ERROR && err == ENOMEM) {
			net2_promise_set_error(out, ENOMEM, 0);
			return;
		}
		if (fin != NET2_PROM_FIN_OK) {
			net2_promise_set_error(out, EIO, 0);
			return;
		}
		assert(buf[i] != NULL);
	}

	/* All buffers have been filled in, there were no errors. */
	if ((result = net2_malloc(sizeof(*result))) == NULL)
		goto fail_0;
	for (i = 0; i < NET2_CNEG_S2_MAX; i++)
		(*result)[i] = NULL;
	for (i = 0; i < NET2_CNEG_S2_MAX; i++) {
		if (((*result)[i] = net2_buffer_copy(buf[i])) == NULL)
			goto fail_1;
	}

	/* Assign result. */
	if (net2_promise_set_finok(out, result, &half_keyset_free, NULL,
	    0) != 0) {
		net2_promise_set_error(out, EIO, 0);
		half_keyset_free(result, NULL);
	}
	return;


fail_1:
	half_keyset_free(result, NULL);
fail_0:
	net2_promise_set_error(out, ENOMEM, 0);
}

/* Simple wrapper around keyset free, for promise. */
static void
net2_cneg_keyset_promfree(void *ks, void *unused ILIAS_NET2__unused)
{
	net2_cneg_keyset_free(ks);
}

/*
 * Combine tx and rx keys together into final promise.
 */
static void
key_xchange_combine_final(struct net2_promise *out, struct net2_promise **in,
    size_t insz, void *unused ILIAS_NET2__unused)
{
	half_keyset		*r[2];
	int			 fin;
	uint32_t		 err;
	size_t			 i;
	struct net2_cneg_keyset	*keys;

	assert(insz == 2);

	/* Handle cancel request on out. */
	if (net2_promise_is_cancelreq(out)) {
		net2_promise_set_cancel(out, 0);
		return;
	}

	/* Check that all in promises completed succesfully. */
	for (i = 0; i < 2; i++) {
		fin = net2_promise_get_result(in[i], (void**)&r[i], &err);
		if (fin == NET2_PROM_FIN_ERROR) {
			net2_promise_set_error(out, err, 0);
			return;
		}
		if (fin != NET2_PROM_FIN_OK) {
			net2_promise_set_error(out, EIO, 0);
			return;
		}
	}

	if ((keys = net2_malloc(sizeof(*keys))) == NULL) {
		net2_promise_set_error(out, ENOMEM, 0);
		return;
	}
	/*
	 * Simply claim all keys for ourselves (in promises are only
	 * refered by us, so it's safe.
	 */
	for (i = 0; i < NET2_CNEG_S2_MAX; i++) {
		keys->tx[i] = (*r[0])[i];
		keys->rx[i] = (*r[1])[i];
		(*r[0])[i] = (*r[1])[i] = NULL;
	}

	/* Assign keys to out promise. */
	if (net2_promise_set_finok(out, keys, &net2_cneg_keyset_promfree,
	    NULL, 0) != 0) {
		net2_cneg_keyset_free(keys);
		net2_promise_set_error(out, EIO, 0);
	}
}

/* Assign keyset from in[0] to out, unless any of in failed. */
static void
key_xchange_checked(struct net2_promise *out, struct net2_promise **in,
    size_t insz, void *unused ILIAS_NET2__unused)
{
	size_t			 i;
	int			 fin;
	uint32_t		 err;
	struct net2_cneg_keyset	*keys;

	assert(insz >= 1);

	/* Handle cancel request on out. */
	if (net2_promise_is_cancelreq(out)) {
		net2_promise_set_cancel(out, 0);
		return;
	}

	/* Test if the additional promises all succeeded. */
	for (i = 1; i < insz; i++) {
		if (net2_promise_is_finished(in[i]) != NET2_PROM_FIN_OK) {
			net2_promise_set_error(out, EIO, 0);
			return;
		}
	}

	/* Read result, cascade errors. */
	fin = net2_promise_get_result(in[0], (void**)&keys, &err);
	if (fin == NET2_PROM_FIN_ERROR) {
		net2_promise_set_error(out, err, 0);
		return;
	} else if (fin != NET2_PROM_FIN_OK) {
		net2_promise_set_error(out, EIO, 0);
		return;
	}

	/* Duplicate result keyset. */
	if ((keys = net2_cneg_keyset_dup(keys)) == NULL) {
		net2_promise_set_error(out, ENOMEM, 0);
		return;
	}

	/* Assign keyset. */
	if (net2_promise_set_finok(out, keys, &net2_cneg_keyset_promfree,
	    NULL, 0) != 0) {
		net2_cneg_keyset_free(keys);
		net2_promise_set_error(out, EIO, 0);
	}
}


#define SLOT_FIN	0xffff
#define SLOT_POETRY	0x7fff
#define CP_POETRY	cp_paddedstring
#define SLOT_LEN	2	/* 2 bytes to encode slot identifier. */

static struct net2_buffer*
mk_poetry(struct net2_encdec_ctx *ectx)
{
	static const uint16_t	 slot = SLOT_POETRY;

	int			 idx;
	struct net2_buffer	*out;

	if ((out = net2_buffer_new()) == NULL)
		return NULL;

	idx = secure_random_uniform(poetry_sz);

	if (net2_cp_encode(ectx, &cp_uint16, out, &slot, NULL) != 0)
		goto fail_1;
	if (net2_cp_encode(ectx, &CP_POETRY, out, &poetry_txts[idx],
	    NULL) != 0)
		goto fail_1;

	return out;


fail_1:
	net2_buffer_free(out);
fail_0:
	return NULL;
}

/*
 * Merge generated buffers into result.
 * If poetry is set, attempts to add poetry as well (and resets it on succes).
 *
 * Sets do_break on recoverable failure.
 */
static int
add_buffer(struct net2_buffer *out, struct net2_tx_callback *txcb,
    struct net2_encdec_ctx *ectx,
    struct net2_buffer *tmp_buf, struct net2_tx_callback *tmp_txcb,
    uint16_t slot, struct net2_buffer **poetry, int *do_break, size_t maxsz)
{
	int			 error;
	size_t			 outlen, inlen;

	assert((slot & NET2_CNEG__MASK) < NET2_CNEG_S2_MAX);

	*do_break = 0;
	outlen = net2_buffer_length(out);
	inlen = net2_buffer_length(tmp_buf);

	/* Nothing to append. */
	if (net2_buffer_empty(tmp_buf)) {
		error = 0;
		goto out;
	}

	/* Encode destination slot number. */
	error = net2_cp_encode(ectx, &cp_uint16, out, &slot, NULL);
	if (error != 0)
		goto out;

	/* Append data. */
	if (net2_buffer_remove_buffer(tmp_buf, out, (size_t)-1) == 0) {
		error = ENOMEM;
		goto out;
	}

	/* Merge tx callbacks. */
	net2_txcb_merge(txcb, tmp_txcb);
	error = 0;	/* No failures permitted past this point. */

	/* Try to add poetry.  Failure is silently ignored. */
	if (*poetry != NULL &&
	    outlen + inlen + SLOT_LEN + net2_buffer_length(*poetry) <= maxsz) {
		if (net2_buffer_remove_buffer(out, *poetry, (size_t)-1) != 0) {
			net2_buffer_free(*poetry);
			*poetry = NULL;
		}
	}


out:
	net2_txcb_nack(tmp_txcb);
	if (error != 0)
		net2_buffer_truncate(out, outlen);

	/* Check code above is correct. */
	assert(error != 0 || net2_buffer_empty(tmp_buf));

	/* Error is recoverable: let next transmission attempt again. */
	if (error == ENOMEM && outlen > 0) {
		*do_break = 1;
		error = 0;
	}

	return error;
}

/* Generate outgoing transmission. */
ILIAS_NET2_LOCAL int
net2_cneg_key_xchange_get_transmit(struct net2_cneg_key_xchange *ke,
    struct net2_encdec_ctx *ectx, struct net2_workq *wq,
    struct net2_buffer *out, struct net2_tx_callback *txcb, size_t maxsz,
    int add_poetry, int empty_poetry)
{
	struct net2_tx_callback	 tmp_txcb;
	struct net2_buffer	*tmp_buf, *poetry;
	size_t			 lmax;
	size_t			 i, lr;
	int			 do_break;
	int			 error;
	uint16_t		 dstslot;

	assert(net2_buffer_empty(out));

	/* Initialize temporaries. */
	if ((error = net2_txcb_init(&tmp_txcb)) != 0)
		goto fail_0;
	if ((tmp_buf = net2_buffer_new()) == NULL) {
		error = ENOMEM;
		goto fail_1;
	}
	poetry = NULL;

	/* Create poetry buffer. */
	if (add_poetry) {
		if ((poetry = mk_poetry(ectx)) == NULL)
			goto fail_2;
	} else
		poetry = NULL;

	do_break = 0;
	for (i = 0; !do_break && i < NET2_CNEG_S2_MAX; i++) {
		for (lr = 0; !do_break && lr < 2; lr++) {
			lmax = maxsz - net2_buffer_length(out);
			if (lmax <= SLOT_LEN)
				break;
			lmax -= 2 * SLOT_LEN;	/* This slot + final slot. */

			/*
			 * Add local transmission.
			 */
			switch (lr) {
			case 0: /* Local. */
				error = xchange_local_get_transmit(
				    &ke->local[i], ectx, wq,
				    tmp_buf, &tmp_txcb, lmax);
				dstslot = flip_slot(i | NET2_CNEG_LOCAL);
				break;
			case 1: /* Remote. */
				error = xchange_remote_get_transmit(
				    &ke->remote[i], ectx, wq,
				    tmp_buf, &tmp_txcb, lmax);
				dstslot = flip_slot(i | NET2_CNEG_REMOTE);
				break;
			default:
				assert(0);
				error = 0; /* Buffer should be empty. */
				break;
			}

			/*
			 * Can we recover from this error?
			 * If so, send what we have so far.
			 */
			if (error == ENOMEM && !net2_buffer_empty(out))
				break;
			if (error != 0)
				goto fail_3;

			/* Empty buffer? Nothing to do. */
			if (net2_buffer_empty(tmp_buf))
				continue;

			/* Append buffer. */
			error = add_buffer(out, txcb, ectx,
			    tmp_buf, &tmp_txcb, dstslot,
			    &poetry, &do_break, maxsz - SLOT_LEN);
			if (error != 0)
				goto fail_3;

			/* Clear. */
			net2_buffer_truncate(tmp_buf, 0);
			net2_txcb_nack(&tmp_txcb);
		}
	}

	if (poetry != NULL && empty_poetry &&
	    net2_buffer_length(out) + net2_buffer_length(poetry) + SLOT_LEN <=
	    maxsz)
		net2_buffer_append(out, poetry); /* Failure is fine. */

	/* Encode fin token. */
	if (!net2_buffer_empty(out)) {
		dstslot = SLOT_FIN;
		error = net2_cp_encode(ectx, &cp_uint16, out, &dstslot, NULL);
	} else
		error = 0;


fail_3:
	if (poetry != NULL)
		net2_buffer_free(poetry);
fail_2:
	net2_buffer_free(tmp_buf);
fail_1:
	net2_txcb_deinit(&tmp_txcb);
fail_0:
	if (error != 0)
		net2_buffer_truncate(out, 0);
	return error;
}

/* Handle received transmission. */
ILIAS_NET2_LOCAL int
net2_cneg_key_xchange_accept(struct net2_cneg_key_xchange *ke,
    struct net2_encdec_ctx *ectx, struct net2_buffer *in)
{
	int			 error;
	uint16_t		 slot;
	char			*poetry;

	for (;;) {
		/* Decode slot identifier. */
		if ((error = net2_cp_decode(ectx, &cp_uint16, &slot, in,
		    NULL)) != 0)
			goto fail;
		if (slot == SLOT_FIN)
			break;	/* GUARD */

		/* Decode poetry payload. */
		if (slot == SLOT_POETRY) {
			if ((error = net2_cp_init(ectx, &CP_POETRY,
			    &poetry, NULL)) != 0)
				goto fail;
			if ((error = net2_cp_decode(ectx, &CP_POETRY,
			    &poetry, in, NULL)) != 0) {
				net2_cp_destroy(ectx, &CP_POETRY, &poetry, NULL);
				goto fail;
			}
			if ((error = net2_cp_destroy(ectx, &CP_POETRY,
			    &poetry, NULL)) != 0)
				goto fail;
			continue;
		}

		/* Test slot validity. */
		if ((slot & NET2_CNEG__MASK) >= NET2_CNEG_S2_MAX) {
			error = EINVAL;
			goto fail;
		}

		/* Decode data. */
		switch (slot & NET2_CNEG__LRMASK) {
		case NET2_CNEG_LOCAL:
			error = xchange_local_accept(
			    &ke->local[slot & NET2_CNEG__MASK], ectx, in);
			break;
		case NET2_CNEG_REMOTE:
			error = xchange_remote_accept(
			    &ke->remote[slot & NET2_CNEG__MASK], ectx, in);
			break;
		default:
			error = EINVAL;
			break;
		}
		if (error != 0)
			goto fail;
	}

fail:
	return error;
}

ILIAS_NET2_LOCAL struct net2_promise*
net2_cneg_key_xchange_keys(struct net2_cneg_key_xchange *ke, int verified)
{
	return (verified ? ke->complete : ke->keys);
}
