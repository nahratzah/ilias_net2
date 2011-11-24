#include "testprotocol.h"
#include <ilias/net2/context.h>
#include <stdlib.h>

static const struct command_param *test_cps[] = {
	NULL
};
static const struct net2_objtype *test_proto_types[] = {
	NULL
};

const struct net2_protocol test_protocol = {
	"test protocol",
	0,
	test_cps,
	sizeof(test_cps) / sizeof(test_cps[0]),
	test_proto_types,
	sizeof(test_proto_types) / sizeof(test_proto_types[0]),
	NET2_CTX_HAS_CLIENT
};

/* Allocate and initialize a new net2_ctx object. */
struct net2_ctx*
test_ctx()
{
	struct net2_ctx	*ctx;

	if ((ctx = malloc(sizeof(*ctx))) == NULL)
		return NULL;
	net2_ctx_init(ctx, &test_protocol);
	return ctx;
}

/* Free a net2_ctx object. */
void
test_ctx_free(struct net2_ctx *ctx)
{
	net2_ctx_destroy(ctx);
	free(ctx);
}
