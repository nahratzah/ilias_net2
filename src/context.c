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
#include <ilias/net2/protocol.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <bsd_compat/error.h>


/* Initialize signature collection. */
static void
signatures_init(struct net2_ctx_signatures *s)
{
	s->signatures = NULL;
	s->count = 0;
}

/* Destroy signature collection. */
static void
signatures_deinit(struct net2_ctx_signatures *s)
{
	while (s->count > 0)
		net2_signctx_free(s->signatures[--s->count]);
	free(s->signatures);
}

/* Append signature to collection. */
static int
signatures_append(struct net2_ctx_signatures *s, struct net2_sign_ctx *sign)
{
	struct net2_sign_ctx	**list;

	/* Protect against overflow. */
	if ((s->count + 1) > SIZE_MAX / sizeof(*list))
		return ENOMEM;

	/* Prepare storage space. */
	list = s->signatures;
	if ((list = realloc(list, sizeof(*list) * (s->count + 1))) == NULL)
		return ENOMEM;
	s->signatures = list;

	s->signatures[s->count] = sign;
	s->count++;
	return 0;
}


/*
 * Initialize network context.
 *
 * Set maximum supported protocol version.
 */
ILIAS_NET2_EXPORT int
net2_ctx_init(struct net2_ctx *ctx)
{
	signatures_init(&ctx->local_signs);
	signatures_init(&ctx->remote_signs);
	return 0;
}

/*
 * Destroy network context.
 */
ILIAS_NET2_EXPORT void
net2_ctx_destroy(struct net2_ctx *ctx)
{
	signatures_deinit(&ctx->local_signs);
	signatures_deinit(&ctx->remote_signs);
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
	if ((error = signatures_append(&ctx->local_signs, sign)) != 0) {
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
	if ((error = signatures_append(&ctx->remote_signs, sign)) != 0) {
		net2_signctx_free(sign);
		return error;
	}
	return 0;
}
