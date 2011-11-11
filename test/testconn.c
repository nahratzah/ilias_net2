#include "testconn.h"
#include "testprotocol.h"
#include <ilias/net2/buffer.h>
#include <stdlib.h>


struct net2_evbase	*global_evbase = NULL;

void	testconn_free(struct net2_connection*);
void	testconn_ready_to_send(struct net2_connection*);

static const struct net2_conn_functions testconn_fn = {
	0,
	testconn_free,
	testconn_ready_to_send
};

struct testconn*
testconn_1()
{
	struct testconn		*tc;
	struct net2_ctx		*ctx;

	if (global_evbase == NULL) {
		if ((global_evbase = net2_evbase_new()) == NULL)
			return NULL;
	}

	if ((ctx = test_ctx()) == NULL)
		return NULL;
	tc = malloc(sizeof(*tc));
	if (net2_connection_init(&tc->base_conn, ctx, global_evbase,
	    &testconn_fn)) {
		free(tc);
		test_ctx_free(ctx);
		return NULL;
	}
	tc->other = NULL;
	tc->in = NULL;
	tc->inlen = 0;
	return tc;
}

int
testconn(struct net2_connection **c1, struct net2_connection **c2)
{
	struct testconn		*c1_tc, *c2_tc;

	c1_tc = testconn_1();
	c2_tc = testconn_1();
	if (c1_tc == NULL || c2_tc == NULL) {
		if (c1_tc)
			testconn_free(&c1_tc->base_conn);
		if (c2_tc)
			testconn_free(&c2_tc->base_conn);
		return -1;
	}

	c1_tc->other = c2_tc;
	c2_tc->other = c1_tc;
	*c1 = &c1_tc->base_conn;
	*c2 = &c2_tc->base_conn;
	return 0;
}

void
testconn_free(struct net2_connection *cptr)
{
	struct testconn		*c = (struct testconn*)cptr;

	net2_connection_deinit(cptr);
	if (c->in)
		free(c->in);
	free(c);
}

void
testconn_ready_to_send(struct net2_connection *cptr)
{
	struct testconn		*c = (struct testconn*)cptr;

	c->wantsend = 1;
}
