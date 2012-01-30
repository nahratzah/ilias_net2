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

/*
 * Initialize network context.
 *
 * Set maximum supported protocol version.
 */
ILIAS_NET2_EXPORT void
net2_ctx_init(struct net2_ctx *ctx, const struct net2_protocol *protocol)
{
	ctx->version = NET2_CTX_NEGOTIATE;
	ctx->protocol = protocol;
	TAILQ_INIT(&ctx->conn);
}

/*
 * Destroy network context.
 */
ILIAS_NET2_EXPORT void
net2_ctx_destroy(struct net2_ctx *ctx)
{
	assert(TAILQ_EMPTY(&ctx->conn));
	return;
}
