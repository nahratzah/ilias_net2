#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/connection.h>
#include <ilias/net2/obj_manager.h>
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
	if (pv != NULL && net2_pvlist_merge(&ctx->ed_proto, pv))
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

/*
 * Create a new encdec_ctx from a connection.
 */
ILIAS_NET2_LOCAL struct net2_encdec_ctx*
net2_encdec_ctx_newconn(struct net2_connection *c)
{
	struct net2_encdec_ctx		*ctx;

	if (c == NULL)
		return NULL;

	if ((ctx = net2_encdec_ctx_new(NULL, NULL)) == NULL)
		return NULL;
	if (net2_pvlist_add(&ctx->ed_proto, &net2_proto, c->n2c_version)) {
		net2_encdec_ctx_release(ctx);
		return NULL;
	}
	return ctx;
}

/*
 * Create a new encdec_ctx from an objmanager.
 */
ILIAS_NET2_LOCAL struct net2_encdec_ctx*
net2_encdec_ctx_newobjman(struct net2_objmanager *m)
{
	return net2_encdec_ctx_new(&m->pvlist, m);
}
