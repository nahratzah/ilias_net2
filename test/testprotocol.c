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
#include "testprotocol.h"
#include <ilias/net2/context.h>
#include <stdlib.h>

static const struct command_param *test_cps[] = {
	NULL
};
static const struct command_method *test_methods[] = {
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
	test_methods,
	sizeof(test_methods) / sizeof(test_methods[0]),
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
	if (net2_ctx_init(ctx) != 0) {
		free(ctx);
		return NULL;
	}
	return ctx;
}

/* Free a net2_ctx object. */
void
test_ctx_free(struct net2_ctx *ctx)
{
	net2_ctx_destroy(ctx);
	free(ctx);
}
