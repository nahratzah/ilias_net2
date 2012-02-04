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
#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/connection.h>
#include <ilias/net2/obj_manager.h>
#include <ilias/net2/context.h>
#include <ilias/net2/protocol.h>
#include <assert.h>

/*
 * Allocate a new encoding/decoding context.
 */
ILIAS_NET2_LOCAL int
net2_encdec_ctx_init(struct net2_encdec_ctx *ctx, struct net2_pvlist *pv,
    struct net2_objmanager *m)
{
	int			 rv;

	if ((rv = net2_pvlist_init(&ctx->ed_proto)) != 0)
		goto fail_0;
	if (pv != NULL && (rv = net2_pvlist_merge(&ctx->ed_proto, pv)) != 0)
		goto fail_1;

	ctx->ed_objman = m;
	return 0;

fail_1:
	net2_pvlist_deinit(&ctx->ed_proto);
fail_0:
	return rv;
}

/*
 * Perform a rollback on the encoding/decoding context.
 */
ILIAS_NET2_LOCAL void
net2_encdec_ctx_rollback(struct net2_encdec_ctx *ctx)
{
	return;
}

/*
 * Release an encoding/decoding context.
 *
 * This operation commits the context.
 */
ILIAS_NET2_LOCAL void
net2_encdec_ctx_deinit(struct net2_encdec_ctx *ctx)
{
	net2_pvlist_deinit(&ctx->ed_proto);
}

/*
 * Create a new encdec_ctx from a connection.
 */
ILIAS_NET2_LOCAL int
net2_encdec_ctx_newaccsocket(struct net2_encdec_ctx *ctx,
    struct net2_acceptor_socket *s)
{
	struct net2_pvlist		 pv;
	int				 rv;

	if (s == NULL) {
		rv = EINVAL;
		goto out_0;
	}

	if ((rv = net2_pvlist_init(&pv)) != 0)
		goto out_0;
	if ((rv = net2_acceptor_socket_pvlist(s, &pv)) != 0)
		goto out_1;
	if ((rv = net2_encdec_ctx_init(ctx, &pv, NULL)) != 0)
		goto out_1;
	rv = 0;

out_1:
	net2_pvlist_deinit(&pv);
out_0:
	return rv;
}

/*
 * Create a new encdec_ctx from an objmanager.
 */
ILIAS_NET2_LOCAL int
net2_encdec_ctx_newobjman(struct net2_encdec_ctx *ctx,
    struct net2_objmanager *m)
{
	return net2_encdec_ctx_init(ctx, &m->pvlist, m);
}
