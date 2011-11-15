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
