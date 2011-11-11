#include <ilias/net2/context.h>
#include <ilias/net2/remote.h>
#include <ilias/net2/protocol.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <bsd_compat/error.h>

/* Type ID comparator. */
static int
net2_objtype_idcmp(const void *lptr, const void *rptr)
{
	const struct net2_objtype	*l, *r;

	l = *(const struct net2_objtype*const*)lptr;
	r = *(const struct net2_objtype*const*)rptr;
	return (l->n2ot_id < r->n2ot_id ? -1 : l->n2ot_id > r->n2ot_id);
}

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

/*
 * Locate the type corresponding to a type ID.
 *
 * Returns NULL on failure.
 */
ILIAS_NET2_LOCAL const struct net2_objtype*
net2_ctx_objtype_find(struct net2_ctx *ctx, uint32_t id)
{
	const struct net2_objtype	*found;

	found = net2_protocol_type(ctx->protocol, id);
	if (found == NULL) {
		warnx("protocol %s: request for unregistered type %u",
		    ctx->protocol->name, id);
	} else {
		debug("protocol %s: matched type ID %u to type %s",
		    ctx->protocol->name, id, found->n2ot_name);
	}
	return found;
}
