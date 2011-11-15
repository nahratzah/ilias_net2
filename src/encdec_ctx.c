#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/connection.h>
#include <ilias/net2/context.h>
#include <stdlib.h>
#include <assert.h>

/*
 * Allocate a new encoding/decoding context.
 */
ILIAS_NET2_LOCAL struct net2_encdec_ctx*
net2_encdec_ctx_new(struct net2_objmanager *m)
{
	struct net2_encdec_ctx	*ctx;

	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL)
		return NULL;

	ctx->ed_objman = m;
	return ctx;
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
	free(ctx);
}
