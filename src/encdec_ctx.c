#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/connection.h>
#include <ilias/net2/context.h>
#include <ilias/net2/protocol.h>
#include <stdlib.h>
#include <assert.h>

/*
 * Allocate a new encoding/decoding context.
 */
ILIAS_NET2_LOCAL struct net2_encdec_ctx*
net2_encdec_ctx_new(struct net2_pvlist *pv, struct net2_objmanager *m)
{
	struct net2_encdec_ctx	*ctx;

	if ((ctx = malloc(sizeof(*ctx))) == NULL)
		goto fail_0;
	if (net2_pvlist_init(&ctx->ed_proto))
		goto fail_1;
	if (net2_pvlist_merge(&ctx->ed_proto, pv))
		goto fail_2;

	ctx->ed_objman = m;
	return ctx;

fail_2:
	net2_pvlist_deinit(&ctx->ed_proto);
fail_1:
	free(ctx);
fail_0:
	return NULL;
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
net2_encdec_ctx_release(struct net2_encdec_ctx *ctx)
{
	net2_pvlist_deinit(&ctx->ed_proto);
	free(ctx);
}
