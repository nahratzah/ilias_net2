#include <ilias/net2/signed_carver.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/cp.h>
#include <ilias/net2/carver.h>
#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/promise.h>
#include <ilias/net2/sign.h>
#include <ilias/net2/tx_callback.h>

#include <ilias/net2/sign.h>
#include <ilias/net2/xchange.h>

#include <assert.h>
#include <errno.h>

#include "signature.h"
#include "signed_carver_header.h"


/* Signed transmission handler. */
struct net2_signed_carver {
	struct net2_carver	 payload;	/* TX data. */
	struct net2_carver	*signatures;	/* Signatures on data. */
	struct net2_promise	*complete;	/* TX complete. */
	uint32_t		 num_signatures; /* # signatures. */
};
/* Signed receive handler. */
struct net2_signed_combiner {
	struct net2_combiner	 payload;	/* RX data. */
	struct net2_combiner	*signatures;	/* Signatures on data. */
	struct net2_promise	*complete;	/* RX complete. */
	uint32_t		 num_signatures; /* # signatures. */
};

/* Additional data for signctx validation function. */
struct signctx_validate_arg {
	struct net2_sign_ctx	*sctx;		/* Signature validator. */
	struct net2_encdec_ctx	 ectx;		/* Encoder/decoder context. */
};


static void	 signed_carver_completion(struct net2_promise*,
		    struct net2_promise**, size_t, void*);

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

static struct net2_buffer
		*signed_carver_get_transmit_sig_header(struct net2_encdec_ctx*,
		    signed_carver_sigidx);


/*
 * Signed carver completion combiner.
 *
 * Tests if all carvers completed succesfully and if so, sets the no-error
 * condition on its output promise.
 */
static void
signed_carver_completion(struct net2_promise *out,
    struct net2_promise **in, size_t insz, void *unused ILIAS_NET2__unused)
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
    struct net2_promise **in, size_t insz, void *unused ILIAS_NET2__unused)
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
combiner_buffer_release(void *bufptr, void *unused ILIAS_NET2__unused)
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
signctx_promdestroy(void *svarg_ptr, void *unused ILIAS_NET2__unused)
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
ILIAS_NET2_EXPORT struct net2_signed_carver*
net2_signed_carver_new(struct net2_workq *wq, struct net2_encdec_ctx *c,
    struct net2_buffer *payload, int hash_alg, uint32_t num_signatures,
    struct net2_sign_ctx **signatures)
{
	struct net2_signed_carver *sc;
	struct net2_signature	 sigdata;
	struct net2_buffer	*tmp;
	struct net2_promise	**in;
	size_t			 i;

	if ((size_t)num_signatures + 1 == 0)
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
	in = net2_calloc((size_t)num_signatures + 1, sizeof(*in));
	in[0] = net2_carver_prom_ready(&sc->payload);
	for (i = 0; i < num_signatures; i++)
		in[i + 1] = net2_carver_prom_ready(&sc->signatures[i]);
	/* Initialize completion promise. */
	sc->complete = net2_promise_combine(wq, &signed_carver_completion,
	    NULL, in, (size_t)num_signatures + 1);
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
ILIAS_NET2_EXPORT void
net2_signed_carver_destroy(struct net2_signed_carver *sc)
{
	/* Release completion promise. */
	net2_promise_cancel(sc->complete);
	net2_promise_release(sc->complete);

	/* Release payload. */
	net2_carver_deinit(&sc->payload);

	/* Release all signatures. */
	while (sc->num_signatures-- > 0)
		net2_carver_deinit(&sc->signatures[sc->num_signatures]);
	net2_free(sc->signatures);

	net2_free(sc);
}


/* Construct a new signed combiner. */
ILIAS_NET2_EXPORT struct net2_signed_combiner*
net2_signed_combiner_new(struct net2_workq *wq, struct net2_encdec_ctx *c,
    uint32_t num_signatures, struct net2_sign_ctx **signatures)
{
	struct net2_signed_combiner	*sc;
	struct net2_promise		**in;
	size_t				 insz;

	in = NULL;
	if ((size_t)num_signatures + 1 == 0)
		goto fail_0;	/* Overflow. */

	if ((in = net2_calloc((size_t)num_signatures + 1,
	    sizeof(*in))) == NULL)
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
	    NULL, in, (size_t)num_signatures + 1);
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
ILIAS_NET2_EXPORT void
net2_signed_combiner_destroy(struct net2_signed_combiner *sc)
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


/* Retrieve payload transmission. */
static __inline int
signed_carver_get_transmit_pl(struct net2_signed_carver *sc,
    struct net2_encdec_ctx *c, struct net2_workq *wq,
    struct net2_buffer *out, struct net2_tx_callback *txcb,
    size_t maxsz)
{
	return net2_carver_get_transmit(&sc->payload, c, wq, out, txcb, maxsz);
}

/* Retrieve signature transmission. */
static __inline int
signed_carver_get_transmit_sig(struct net2_signed_carver *sc, uint32_t sigidx,
    struct net2_encdec_ctx *c, struct net2_workq *wq,
    struct net2_buffer *out, struct net2_tx_callback *txcb,
    size_t maxsz)
{
	if (sigidx >= sc->num_signatures)
		return EINVAL;
	return net2_carver_get_transmit(&sc->signatures[sigidx], c, wq,
	    out, txcb, maxsz);
}

/* Get combiner to accept payload data. */
static __inline int
signed_combiner_accept_pl(struct net2_signed_combiner *sc,
    struct net2_encdec_ctx *c, struct net2_buffer *buf)
{
	return net2_combiner_accept(&sc->payload, c, buf);
}

/* Get combiner to accept signature data. */
static __inline int
signed_combiner_accept_sig(struct net2_signed_combiner *sc, uint32_t sigidx,
    struct net2_encdec_ctx *c, struct net2_buffer *buf)
{
	if (sigidx >= sc->num_signatures)
		return EINVAL;
	return net2_combiner_accept(&sc->signatures[sigidx], c, buf);
}

/* Returns the number of signatures on carver. */
static __inline size_t
signed_carver_num_sigs(struct net2_signed_carver *sc)
{
	return sc->num_signatures;
}

/* Returns the number of signatures on combiner. */
static __inline size_t
signed_combiner_num_sigs(struct net2_signed_combiner *sc)
{
	return sc->num_signatures;
}


/* Generate signature header for signed carver. */
static struct net2_buffer*
signed_carver_get_transmit_sig_header(struct net2_encdec_ctx *c,
    signed_carver_sigidx sigidx)
{
	struct net2_buffer	*out;

	if ((out = net2_buffer_new()) == NULL)
		goto fail_0;
	if (net2_cp_encode(c, &cp_signed_carver_sigidx, out, &sigidx,
	    NULL) != 0)
		goto fail_1;

	return out;


fail_1:
	net2_buffer_free(out);
fail_0:
	return NULL;
}
/* Decode signature header. */
static __inline int
signed_combiner_sig_header(signed_carver_sigidx *sigidx,
    struct net2_encdec_ctx *c, struct net2_buffer *in)
{
	return net2_cp_decode(c, &cp_signed_carver_sigidx, sigidx, in, NULL);
}


/*
 * Get transmission data for signed carver.
 *
 * The out buffer will be filled up with as many messages this signed carver
 * has available.  Headers will be generated for each of the messages, using
 * the supplied dstslot and xmsg_type as appropriate.
 */
ILIAS_NET2_EXPORT int
net2_signed_carver_get_transmit(struct net2_signed_carver *sc,
    struct net2_encdec_ctx *c, struct net2_workq *wq, struct net2_buffer *out,
    struct net2_tx_callback *txcb_out, size_t maxsz)
{
	struct net2_buffer	*header = NULL, *carver = NULL;
	size_t			 out_header_len;	/* |out| + |header| */
	int			 do_break;
	struct net2_tx_callback	 tmp_txcb, txcb;
	uint32_t		 sigidx;
	int			 error;
	struct signed_carver_header
				 sch;

	assert(net2_buffer_empty(out));

	sch.pl_segs = sch.sig_segs = 0;
	if (maxsz <= SIGNED_CARVER_HEADERSZ)
		return 0;
	maxsz -= SIGNED_CARVER_HEADERSZ;

	/*
	 * Temporary txcb.
	 */
	if ((error = net2_txcb_init(&tmp_txcb)) != 0)
		goto fail_0;
	if ((error = net2_txcb_init(&txcb)) != 0) {
		net2_txcb_deinit(&tmp_txcb);
		goto fail_0;
	}

	/*
	 * Try and load payload data into out.
	 */
	do_break = 0;
	while (!do_break && sch.pl_segs < SIGNED_CARVER_MAXSEGS &&
	    (out_header_len = net2_buffer_length(out)) < maxsz) {
		if ((carver = net2_buffer_new()) == NULL) {
			error = ENOMEM;
			goto fail_1;
		}
		if ((error = signed_carver_get_transmit_pl(sc, c, wq, carver,
		    &tmp_txcb, maxsz - out_header_len)) != 0)
			goto fail_1;

		if (!net2_buffer_empty(carver)) {
			if (net2_buffer_append(out, carver)) {
				error = ENOMEM;
				net2_txcb_nack(&tmp_txcb);
				if (sch.pl_segs == 0)
					goto fail_1;
				else
					do_break = 1;
			} else
				sch.pl_segs++;
		} else
			do_break = 1;

		net2_txcb_merge(&txcb, &tmp_txcb);
		net2_buffer_free(carver);
		carver = NULL;
	}

	/*
	 * Generate transmission for each signature.
	 */
	for (sigidx = 0; sigidx < signed_carver_num_sigs(sc); sigidx++) {
		if ((header = signed_carver_get_transmit_sig_header(c,
		    sigidx)) == NULL) {
			error = ENOMEM;
			if (sch.pl_segs == 0 && sch.sig_segs == 0)
				goto fail_1;
			else
				do_break = 1;
		}

		do_break = 0;
		while (!do_break && sch.sig_segs < SIGNED_CARVER_MAXSEGS &&
		    (out_header_len = net2_buffer_length(out) +
		    net2_buffer_length(header)) < maxsz) {
			if ((carver = net2_buffer_new()) == NULL) {
				error = ENOMEM;
				goto fail_1;
			}
			if ((error = signed_carver_get_transmit_sig(sc, sigidx,
			    c, wq, carver, &tmp_txcb,
			    maxsz - out_header_len)) != 0)
				goto fail_1;

			if (!net2_buffer_empty(carver)) {
				if (net2_buffer_append(out, header) ||
				    net2_buffer_append(out, carver)) {
					error = ENOMEM;
					/*
					 * Reduce out length back to
					 * the size prior to failure.
					 */
					net2_buffer_truncate(out,
					    out_header_len);
					net2_txcb_nack(&tmp_txcb);
					if (sch.pl_segs == 0 &&
					    sch.sig_segs == 0)
						goto fail_1;
					else
						do_break = 1;
				} else
					sch.sig_segs++;
			} else
				do_break = 1;

			net2_txcb_merge(&txcb, &tmp_txcb);
			net2_buffer_free(carver);
			carver = NULL;
		}
		/* Release header. */
		net2_buffer_free(header);
		header = NULL;
	}

	/* Encode sch header. */
	if (sch.pl_segs == 0 && sch.sig_segs == 0)
		assert(net2_buffer_empty(out));
	else {
		header = net2_buffer_new();
		if ((error = net2_cp_encode(c, &cp_signed_carver_header,
		    header, &sch, NULL)) != 0)
			goto fail_1;
		if (net2_buffer_prepend(out, header) != 0) {
			error = ENOMEM;
			goto fail_1;
		}
		net2_buffer_free(header);
		header = NULL;

		net2_txcb_merge(txcb_out, &txcb);
	}

	/* All messages have been stored in out. */
	error = 0;

	/* FALLTHROUGH: allow failure code to perform cleanup. */


fail_1:
	if (error != 0) {
		net2_txcb_nack(&txcb);
		net2_buffer_truncate(out, 0);	/* Reset. */
	}

	net2_txcb_deinit(&tmp_txcb);
	net2_txcb_deinit(&txcb);
fail_0:
	if (carver != NULL)
		net2_buffer_free(carver);
	if (header != NULL)
		net2_buffer_free(header);

	return error;
}

/*
 * Accept message for combiner.
 *
 * Supplied header has been decoded by caller.
 */
ILIAS_NET2_EXPORT int
net2_signed_combiner_accept(struct net2_signed_combiner *sc,
    struct net2_encdec_ctx *c, struct net2_buffer *buf)
{
	struct signed_carver_header
				 sch;
	uint32_t		 sig_idx;
	size_t			 i;
	int			 error;

	/* Decode and validate header. */
	if ((error = net2_cp_decode(c, &cp_signed_carver_header, &sch, buf,
	    NULL)) != 0)
		return error;
	if (sch.pl_segs == 0 && sch.sig_segs == 0)
		return EINVAL;

	/* Decode all payloads. */
	for (i = 0; i < sch.pl_segs; i++) {
		if ((error = signed_combiner_accept_pl(sc, c, buf)) != 0)
			return error;
	}

	/* Decode all signatures. */
	for (i = 0; i < sch.sig_segs; i++) {
		if ((error = signed_combiner_sig_header(&sig_idx,
		    c, buf)) != 0)
			return error;
		if ((error = signed_combiner_accept_sig(sc, sig_idx,
		    c, buf)) != 0)
			return error;
	}

	return 0;
}


/*
 * Returns pointer to completion promise.
 * Promise reference counter is not modified.
 */
ILIAS_NET2_EXPORT struct net2_promise*
net2_signed_carver_complete(struct net2_signed_carver *sc)
{
	return sc->complete;
}
/*
 * Returns pointer to payload sent promise.
 * Promise reference counter is not modified.
 */
ILIAS_NET2_EXPORT struct net2_promise*
net2_signed_carver_payload(struct net2_signed_carver *sc)
{
	return sc->payload.ready;
}

/*
 * Returns pointer to completion promise.
 * Promise reference counter is not modified.
 */
ILIAS_NET2_EXPORT struct net2_promise*
net2_signed_combiner_complete(struct net2_signed_combiner *sc)
{
	return sc->complete;
}
/*
 * Returns pointer to payload sent promise.
 * Promise reference counter is not modified.
 */
ILIAS_NET2_EXPORT struct net2_promise*
net2_signed_combiner_payload(struct net2_signed_combiner *sc)
{
	return sc->payload.ready;
}


/* Assign ready-to-send callback. */
ILIAS_NET2_EXPORT void
net2_signed_carver_set_rts(struct net2_signed_carver *sc,
    struct net2_workq *wq, void (*fn)(void*, void*), void *arg0, void *arg1)
{
	size_t			 i;

	net2_carver_set_rts(&sc->payload, wq, fn, arg0, arg1);
	for (i = 0; i < signed_carver_num_sigs(sc); i++)
		net2_carver_set_rts(&sc->signatures[i], wq, fn, arg0, arg1);
}
