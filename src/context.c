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
#include <ilias/net2/context.h>
#include <ilias/net2/sign.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/xchange.h>
#include <ilias/net2/memory.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <ilias/net2/bsd_compat/error.h>


/*
 * Initialize network context.
 *
 * Set maximum supported protocol version.
 */
ILIAS_NET2_EXPORT int
net2_ctx_init(struct net2_ctx *ctx)
{
	net2_signset_init(&ctx->local_signs);
	net2_signset_init(&ctx->remote_signs);
	ctx->remote_min = 0;
	ctx->xchange_factory = NULL;
	ctx->xchange_factory_arg = NULL;
	return 0;
}

/*
 * Destroy network context.
 */
ILIAS_NET2_EXPORT void
net2_ctx_destroy(struct net2_ctx *ctx)
{
	net2_signset_deinit(&ctx->local_signs);
	net2_signset_deinit(&ctx->remote_signs);
	return;
}

/* Add a localhost signature. */
ILIAS_NET2_EXPORT int
net2_ctx_add_local_signature(struct net2_ctx *ctx, int alg,
    const void *key, size_t keylen)
{
	struct net2_sign_ctx	*sign;
	int			 error;

	if ((sign = net2_signctx_privnew(alg, key, keylen)) == NULL)
		return EINVAL;
	if ((error = net2_signset_insert(&ctx->local_signs, sign)) != 0) {
		net2_signctx_free(sign);
		return error;
	}
	return 0;
}

/* Add a remote host signature. */
ILIAS_NET2_EXPORT int
net2_ctx_add_remote_signature(struct net2_ctx *ctx, int alg,
    const void *key, size_t keylen)
{
	struct net2_sign_ctx	*sign;
	int			 error;

	if ((sign = net2_signctx_pubnew(alg, key, keylen)) == NULL)
		return EINVAL;
	if ((error = net2_signset_insert(&ctx->remote_signs, sign)) != 0) {
		net2_signctx_free(sign);
		return error;
	}

	if (ctx->remote_min == 0)
		ctx->remote_min = 1;
	return 0;
}

/* Retrieve a promise of a new exchange context with the given algorithm. */
ILIAS_NET2_EXPORT struct net2_promise*
net2_ctx_get_xchange(struct net2_ctx *ctx, int alg, size_t keylen)
{
	if (ctx->xchange_factory != NULL) {
		return (*ctx->xchange_factory)(alg, keylen,
		    ctx->xchange_factory_arg);
	}
	return NULL;
}

/* Create a new xchange factory result. */
ILIAS_NET2_EXPORT struct net2_ctx_xchange_factory_result*
net2_ctx_xchange_factory_result_new(const struct net2_xchange_ctx *xchange,
    const struct net2_buffer *initbuf)
{
	struct net2_ctx_xchange_factory_result
				*r;

	if (xchange == NULL || initbuf == NULL)
		return NULL;

	if ((r = net2_malloc(sizeof(*r))) == NULL)
		return NULL;

	r->ctx = net2_xchangectx_clone(xchange);
	r->initbuf = net2_buffer_copy(initbuf);
	if (r->ctx == NULL || r->initbuf == NULL) {
		net2_ctx_xchange_factory_result_free(r, NULL);
		return NULL;
	}
	return r;
}

/* Free xchange factory result. */
ILIAS_NET2_EXPORT void
net2_ctx_xchange_factory_result_free(void *r_ptr, void *ignored)
{
	struct net2_ctx_xchange_factory_result	*r;

	r = (struct net2_ctx_xchange_factory_result*)r_ptr;

	if (r != NULL) {
		if (r->ctx != NULL)
			net2_xchangectx_free(r->ctx);
		if (r->initbuf != NULL)
			net2_buffer_free(r->initbuf);
		net2_free(r);
	}
}
