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

#include <ilias/net2/carver.h>
#include <ilias/net2/cp.h>
#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/promise.h>
#include <ilias/net2/sign.h>

#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>

#include "signature.h"


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


/* Signed transmission handler. */
struct signed_carver {
	struct net2_carver	 payload;	/* TX data. */
	struct net2_carver	*signatures;	/* Signatures on data. */
	struct net2_promise	*complete;	/* TX complete. */
	size_t			 num_signatures; /* # signatures. */
};
/* Signed receive handler. */
struct signed_combiner {
	struct net2_combiner	 payload;	/* RX data. */
	struct net2_combiner	*signatures;	/* Signatures on data. */
	struct net2_promise	*complete;	/* RX complete. */
	size_t			 num_signatures; /* # signatures. */
};

/* Additional data for signctx validation function. */
struct signctx_validate_arg {
	struct net2_sign_ctx	*sctx;		/* Signature validator. */
	struct net2_encdec_ctx	 ectx;		/* Encoder/decoder context. */
};

/* State shared between xchange_local, xchange_remote. */
struct xchange_shared {
	struct net2_xchange_ctx	*xchange;	/* Xchange context. */
	struct net2_promise	*key_promise;	/* Completion promise. */

	int			 alg;		/* Algorithm ID. */
	int			 xchange_alg;	/* Xchange method. */
	int			 hash_alg;	/* Signature hash algorithm. */
	uint32_t		 keysize;	/* Negotiated key size. */
};

/* Locally initialized key negotiation. */
struct xchange_local {
	struct xchange_shared	 shared;	/* Shared state. */

	struct signed_carver	 init;		/* Initialization buffer. */
	struct signed_carver	 export;	/* Export buffer. */
	struct signed_combiner	 import;	/* Import buffer. */
};
/* Remotely initialized key negotiation. */
struct xchange_remote {
	struct xchange_shared	 shared;	/* Shared state. */

	struct signed_combiner	 init;		/* Initialization buffer. */
	struct signed_carver	 export;	/* Export buffer. */
	struct signed_combiner	 import;	/* Import buffer. */
	int			 export_inited;	/* Set: export is inited. */
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


static void	 signed_carver_completion(struct net2_promise*,
		    struct net2_promise**, size_t, void*);
static struct signed_carver
		*signed_carver_new(struct net2_workq*, struct net2_encdec_ctx*,
		    struct net2_buffer*, int, size_t, struct net2_sign_ctx**);
static void	 signed_carver_destroy(struct signed_carver*);

static void	 signed_combiner_completion(struct net2_promise*,
		    struct net2_promise**, size_t, void*);
static void	 combiner_buffer_release(void*, void*);
static void	 signctx_promdestroy(void *sctx_ptr, void *);
static void	 signctx_validate(struct net2_promise*, struct net2_promise**,
		    size_t, void*);
static struct net2_promise
		*signed_combiner_check(struct net2_workq*,
		    struct net2_encdec_ctx*,
		    struct net2_promise*, struct net2_promise*,
		    struct net2_sign_ctx*);
static struct signed_combiner
		*signed_combiner_init(struct net2_workq*,
		    struct net2_encdec_ctx*, size_t, struct net2_sign_ctx**);
static void	 signed_combiner_deinit(struct signed_combiner*);


/*
 * Signed carver completion combiner.
 *
 * Tests if all carvers completed succesfully and if so, sets the no-error
 * condition on its output promise.
 */
static void
signed_carver_completion(struct net2_promise *out,
    struct net2_promise **in, size_t insz, void * ILIAS_NET2__unused unused)
{
	void			*in_data;
	size_t			 i;
	int			 fin, unfinished = 0;
	uint32_t		 in_error;

	/* Ensure result is possible. */
	assert(insz >= 1);

	/* If this promise was canceled, handle cancellation. */
	if (net2_promise_is_cancelreq(out)) {
		net2_promise_set_cancel(out, 0);
		return;
	}

	/* Check if all in promises succeeded. */
	for (i = 0; i < insz; i++) {
		fin = net2_promise_get_result(in[i], &in_data, &in_error);

		switch (fin) {
		case NET2_PROM_FIN_OK:
			break;
		case NET2_PROM_FIN_UNFINISHED:
			/*
			 * Allow loop to complete, maybe it will find a real
			 * cause.
			 */
			unfinished = 1;
			break;
		case NET2_PROM_FIN_ERROR:
			assert(in_error != 0);
			net2_promise_set_error(out, in_error, 0);
			return;
		case NET2_PROM_FIN_CANCEL:
		case NET2_PROM_FIN_UNREF:
			net2_promise_set_cancel(out, 0);
			return;
		case NET2_PROM_FIN_FAIL:
		default:
			net2_promise_set_error(out, EIO, 0);
			return;
		}
	}

	/* Unfinished promises? */
	if (unfinished) {
		net2_promise_set_error(out, EIO, 0);
		return;
	}

	/* No failures -> assign ok status. */
	net2_promise_set_finok(out, NULL, NULL, NULL, 0);
	return;
}

/*
 * Signed combiner completion combiner.
 *
 * Tests if all promises completed succesfully and if so, sets the no-error
 * condition on its output promise.
 * Assigns the buffer from in[0] as the result to out.
 */
static void
signed_combiner_completion(struct net2_promise *out,
    struct net2_promise **in, size_t insz, void * ILIAS_NET2__unused unused)
{
	void			*in_data;
	struct net2_buffer	*pl;
	size_t			 i;
	int			 fin, unfinished = 0;
	uint32_t		 in_error;

	/* Ensure result is possible. */
	assert(insz >= 1);

	/* If this promise was canceled, handle cancellation. */
	if (net2_promise_is_cancelreq(out)) {
		net2_promise_set_cancel(out, 0);
		return;
	}

	/* Check if all in promises succeeded. */
	for (i = 0; i < insz; i++) {
		fin = net2_promise_get_result(in[i], &in_data, &in_error);
		/* Save in[0] result for assignment later. */
		if (i == 0)
			pl = in_data;

		switch (fin) {
		case NET2_PROM_FIN_OK:
			break;
		case NET2_PROM_FIN_UNFINISHED:
			/*
			 * Allow loop to complete, maybe it will find a real
			 * cause.
			 */
			unfinished = 1;
			break;
		case NET2_PROM_FIN_ERROR:
			assert(in_error != 0);
			net2_promise_set_error(out, in_error, 0);
			return;
		case NET2_PROM_FIN_CANCEL:
		case NET2_PROM_FIN_UNREF:
			net2_promise_set_cancel(out, 0);
			return;
		case NET2_PROM_FIN_FAIL:
		default:
			net2_promise_set_error(out, EIO, 0);
			return;
		}
	}

	/* Unfinished promises? */
	if (unfinished) {
		net2_promise_set_error(out, EIO, 0);
		return;
	}

	/* pl must be set, create a clone. */
	assert(pl != NULL);
	if ((pl = net2_buffer_copy(pl)) == NULL) {
		net2_promise_set_error(out, EIO, 0);
		return;
	}

	/* No failures -> assign ok status. */
	if (net2_promise_set_finok(out, pl, &combiner_buffer_release, NULL,
	    0)) {
		net2_buffer_free(pl);	/* Failed to assign, release now. */

		/*
		 * set_finok only fails if the promise already has an
		 * assigned value.  This function should only be called once,
		 * so it should not happen.
		 */
		assert(0);
	}
	return;
}


/*
 * Function to free buffer on completion event.
 */
static void
combiner_buffer_release(void *bufptr, void * ILIAS_NET2__unused unused)
{
	struct net2_buffer	*buf;

	buf = bufptr;
	if (buf)
		net2_buffer_free(buf);
}

/*
 * Function to free sign context associated with promise.
 */
static void
signctx_promdestroy(void *svarg_ptr, void * ILIAS_NET2__unused unused)
{
	struct signctx_validate_arg	*svarg;

	svarg = svarg_ptr;
	if (svarg->sctx)
		net2_signctx_free(svarg->sctx);
	net2_encdec_ctx_deinit(&svarg->ectx);
	net2_free(svarg);
}

/*
 * Validate signature of payload, using the given signcontext.
 *
 * Out will be set to finok (with no value) if the signature is valid.
 * Out will error with EINVAL if the signature is invalid or the inputs
 * failed to yield a result.
 */
static void
signctx_validate(struct net2_promise *out, struct net2_promise **in,
    size_t insz, void *svarg_ptr)
{
	struct signctx_validate_arg
				*svarg;
	struct net2_buffer	*pl;
	struct net2_buffer	*sig;
	uint32_t		 pl_err, sig_err;
	int			 pl_fin, sig_fin;
	struct net2_signature	 sent;
	int			 sigvalid;

	assert(insz == 2);
	svarg = svarg_ptr;
	assert(svarg != NULL && svarg->sctx != NULL);

	/* Don't do anything if out was canceled. */
	if (net2_promise_is_cancelreq(out))
		goto fail;

	/* Read results. */
	pl_fin = net2_promise_get_result(in[0], (void**)&pl, &pl_err);
	sig_fin = net2_promise_get_result(in[1], (void**)&sig, &sig_err);
	assert(pl_fin != NET2_PROM_FIN_UNFINISHED &&
	    sig_fin != NET2_PROM_FIN_UNFINISHED);

	/* Check if payload and signature completed ok. */
	if (pl_fin != NET2_PROM_FIN_OK || sig_fin != NET2_PROM_FIN_OK)
		goto fail;

	/* Both must have buffer result. */
	assert(pl != NULL && sig != NULL);

	/*
	 * Both completed succesful (NET2_PROM_FIN_OK).
	 *
	 * Time to test if the signature is actually correct.
	 */

	/* Decode signature. */
	if (net2_cp_init(&svarg->ectx, &cp_net2_signature, &sent, NULL) != 0)
		goto fail;
	if (net2_cp_decode(&svarg->ectx, &cp_net2_signature, &sent, sig,
	    NULL) != 0)
		goto fail_decode;
	if (net2_signature_validate(&sent, pl, svarg->sctx, &sigvalid) != 0)
		goto fail_decode;
	net2_cp_destroy(&svarg->ectx, &cp_net2_signature, &sent, NULL);

	/* sigvalid now describes if the signature is valid. */
	if (sigvalid)
		net2_promise_set_finok(out, NULL, NULL, NULL, 0);
	else
		net2_promise_set_error(out, EINVAL, 0);

out:
	/*
	 * Promise has been assigned, release the signature context now.
	 */
	net2_signctx_free(svarg->sctx);
	svarg->sctx = NULL;
	return;


	/*
	 * Error handling.
	 */
fail_decode:
	net2_cp_destroy(&svarg->ectx, &cp_net2_signature, &sent, NULL);
fail:
	net2_promise_set_error(out, EIO, 0);
	goto out;
}

/*
 * Generates a promise that tests if the received signature is a match for
 * the given payload.
 */
static struct net2_promise*
signed_combiner_check(struct net2_workq *wq, struct net2_encdec_ctx *c,
    struct net2_promise *pl, struct net2_promise *sig,
    struct net2_sign_ctx *sctx)
{
	struct net2_promise	*out;
	struct net2_promise	*in[2] = { pl, sig };
	struct net2_sign_ctx	*sctx_clone;
	struct signctx_validate_arg
				*svarg;

	if ((svarg = net2_malloc(sizeof(*svarg))) == NULL)
		goto fail_0;
	if ((svarg->sctx = net2_signctx_clone(sctx)) == NULL)
		goto fail_1;
	if (net2_encdec_ctx_init(&svarg->ectx, &c->ed_proto, NULL) != 0)
		goto fail_2;
	if ((out = net2_promise_combine(wq, &signctx_validate, svarg,
	    in, 2)) == NULL)
		goto fail_3;
	/* Ensure sctx_clone will be released when promise is destroyed. */
	net2_promise_destroy_cb(out, &signctx_promdestroy, svarg, NULL);
	svarg = NULL; /* Now owned by out. */

	return out;


fail_3:
	if (svarg != NULL)
		net2_encdec_ctx_deinit(&svarg->ectx);
fail_2:
	if (svarg != NULL)
		net2_signctx_free(svarg->sctx);
fail_1:
	if (svarg != NULL)
		net2_free(svarg);
fail_0:
	return NULL;
}


/* Construct a new signed carver. */
static struct signed_carver*
signed_carver_new(struct net2_workq *wq, struct net2_encdec_ctx *c,
    struct net2_buffer *payload, int hash_alg, size_t num_signatures,
    struct net2_sign_ctx **signatures)
{
	struct signed_carver	*sc;
	struct net2_signature	 sigdata;
	struct net2_buffer	*tmp;
	struct net2_promise	**in;
	size_t			 i;

	if (num_signatures + 1 == 0)
		goto fail_0;	/* Overflow. */

	if ((sc = net2_malloc(sizeof(*sc))) == NULL)
		goto fail_0;
	if (net2_carver_init(&sc->payload, NET2_CARVER_16BIT, payload) != 0)
		goto fail_1;

	if ((sc->signatures = net2_calloc(sc->num_signatures,
	    sizeof(*sc->signatures))) == NULL)
		goto fail_2;
	for (sc->num_signatures = 0; sc->num_signatures < num_signatures;
	    sc->num_signatures++) {
		if (net2_signature_create(&sigdata, payload, hash_alg,
		    signatures[sc->num_signatures]) != 0)
			goto fail_3;

		if ((tmp = net2_buffer_new()) == NULL)
			goto loop_fail_0;
		if (net2_cp_encode(c, &cp_net2_signature, tmp, &sigdata,
		    NULL) != 0)
			goto loop_fail_1;
		if (net2_carver_init(&sc->signatures[sc->num_signatures],
		    NET2_CARVER_16BIT, tmp) != 0)
			goto loop_fail_1;

		net2_buffer_free(tmp);
		net2_signature_deinit(&sigdata);

		continue;

loop_fail_1:
		net2_buffer_free(tmp);
loop_fail_0:
		net2_signature_deinit(&sigdata);
		goto fail_3;
	}

	/* Collect all promises required for completion promise. */
	in = net2_calloc(num_signatures + 1, sizeof(*in));
	in[0] = net2_carver_prom_ready(&sc->payload);
	for (i = 0; i < num_signatures; i++)
		in[i + 1] = net2_carver_prom_ready(&sc->signatures[i]);
	/* Initialize completion promise. */
	sc->complete = net2_promise_combine(wq, &signed_carver_completion,
	    NULL, in, num_signatures + 1);
	/*
	 * Release all promises again (note that we didn't reference them,
	 * hence do not release either.
	 */
	net2_free(in);
	/* Test if completion promise creation was actually succesful. */
	if (sc->complete == NULL)
		goto fail_3;

	return sc;

fail_4:
	net2_promise_cancel(sc->complete);
	net2_promise_release(sc->complete);
fail_3:
	while (sc->num_signatures > 0)
		net2_carver_deinit(&sc->signatures[--sc->num_signatures]);
	net2_free(sc->signatures);
fail_2:
	net2_carver_deinit(&sc->payload);
fail_1:
	net2_free(sc);
fail_0:
	return NULL;
}

/* Destroy a signed carver. */
static void
signed_carver_destroy(struct signed_carver *sc)
{
	/* Release completion promise. */
	net2_promise_cancel(sc->complete);
	net2_promise_release(sc->complete);

	/* Release payload. */
	net2_carver_deinit(&sc->payload);

	/* Release all signatures. */
	while (sc->signatures-- > 0)
		net2_carver_deinit(&sc->signatures[sc->num_signatures]);
	net2_free(sc->signatures);

	net2_free(sc);
}

/* Construct a new signed combiner. */
static struct signed_combiner*
signed_combiner_init(struct net2_workq *wq, struct net2_encdec_ctx *c,
    size_t num_signatures, struct net2_sign_ctx **signatures)
{
	struct signed_combiner		*sc;
	struct net2_promise		**in;
	size_t				 insz;

	in = NULL;
	if (num_signatures + 1 == 0)
		goto fail_0;	/* Overflow. */

	if ((in = net2_calloc(num_signatures + 1, sizeof(*in))) == NULL)
		goto fail_0;
	if ((sc = net2_malloc(sizeof(*sc))) == NULL)
		goto fail_0;
	if (net2_combiner_init(&sc->payload, NET2_CARVER_16BIT) != 0)
		goto fail_1;

	if ((sc->signatures = net2_calloc(num_signatures,
	    sizeof(*sc->signatures))) == NULL)
		goto fail_2;
	for (sc->num_signatures = 0; sc->num_signatures < num_signatures;
	    sc->num_signatures++) {
		if (net2_combiner_init(&sc->signatures[sc->num_signatures],
		    NET2_CARVER_16BIT) != 0)
			goto fail_3;
	}

	/*
	 * Create completion promise.
	 * in[0] is the payload promise, which is not referenced
	 *     (borrowed from combiner).
	 * in[1..n] are validation promises, which are referenced
	 *     (created by signed_combiner_check).
	 *
	 * in[1..n] thus must be released prior to freeing in.
	 */
	in[0] = net2_combiner_prom_ready(&sc->payload);
	for (insz = 0; insz < num_signatures; insz++) {
		if ((in[insz + 1] = signed_combiner_check(wq, c, in[0],
		    net2_combiner_prom_ready(&sc->signatures[insz]),
		    signatures[insz])) == NULL)
			goto fail_4;
	}
	sc->complete = net2_promise_combine(wq, &signed_combiner_completion,
	    NULL, in, num_signatures + 1);
	if (sc->complete == NULL)
		goto fail_4;

	/* Release temporary list of promises. */
	while (insz-- > 1)
		net2_promise_release(in[insz]);
	net2_free(in);
	in = NULL;

	return sc;


fail_5:
	net2_promise_release(sc->complete);
fail_4:
	while (in != NULL && insz-- > 1) {
		net2_promise_cancel(in[insz]);
		net2_promise_release(in[insz]);
	}
fail_3:
	while (sc->num_signatures > 0)
		net2_combiner_deinit(&sc->signatures[--sc->num_signatures]);
	net2_free(sc->signatures);
fail_2:
	net2_combiner_deinit(&sc->payload);
fail_1:
	net2_free(sc);
fail_0:
	if (in != NULL)
		net2_free(in);
	return NULL;
}

/* Destroy a signed combiner. */
static void
signed_combiner_deinit(struct signed_combiner *sc)
{
	/* Release completion promise. */
	net2_promise_cancel(sc->complete);
	net2_promise_release(sc->complete);

	/* Release payload. */
	net2_combiner_deinit(&sc->payload);

	/* Release all signatures. */
	while (sc->num_signatures-- > 0)
		net2_combiner_deinit(&sc->signatures[sc->num_signatures]);
	net2_free(sc->signatures);

	net2_free(sc);
}
