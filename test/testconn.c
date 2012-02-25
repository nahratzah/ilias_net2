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
#include "testconn.h"
#include "testprotocol.h"
#include <ilias/net2/buffer.h>
#include <stdlib.h>


struct net2_evbase	*global_evbase = NULL;
struct net2_ctx		*ctx = NULL;

void	testconn_free(struct net2_acceptor_socket*);
void	testconn_ready_to_send(struct net2_acceptor_socket*);

static const struct net2_acceptor_socket_fn testconn_fn = {
	0,
	testconn_free,
	testconn_ready_to_send,
	NULL,
	NULL,
	NULL,
};

struct testconn*
testconn_1()
{
	struct testconn		*tc;

	if (global_evbase == NULL) {
		if ((global_evbase = net2_evbase_new()) == NULL)
			return NULL;
	}

	if (ctx == NULL) {
		if ((ctx = test_ctx()) == NULL)
			return NULL;
	}

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
			testconn_free(&c1_tc->base_conn.n2c_socket);
		if (c2_tc)
			testconn_free(&c2_tc->base_conn.n2c_socket);
		return -1;
	}

	c1_tc->other = c2_tc;
	c2_tc->other = c1_tc;
	*c1 = &c1_tc->base_conn;
	*c2 = &c2_tc->base_conn;
	return 0;
}

void
testconn_free(struct net2_acceptor_socket *cptr)
{
	struct testconn		*c = (struct testconn*)cptr;

	net2_connection_deinit(&c->base_conn);
	if (c->in)
		free(c->in);
	free(c);
}

void
testconn_ready_to_send(struct net2_acceptor_socket *cptr)
{
	struct testconn		*c = (struct testconn*)cptr;

	c->wantsend = 1;
}

void
testconn_cleanup()
{
	if (global_evbase != NULL)
		net2_evbase_release(global_evbase);
	global_evbase = NULL;

	if (ctx != NULL)
		test_ctx_free(ctx);
	ctx = NULL;
}
