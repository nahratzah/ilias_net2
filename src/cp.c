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
#include <ilias/net2/cp.h>
#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/obj_manager.h>
#include <ilias/net2/mutex.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/promise.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

/* Enable for printing of encoding/decoding errors. */
#define DEBUG_ENCODING

#ifdef DEBUG_ENCODING
#include <stdio.h>
#include <string.h>
#endif

ILIAS_NET2_EXPORT int
net2_cp_encode(struct net2_encdec_ctx *c, const struct command_param *cp,
    struct net2_buffer *out, const void *val, const void *arg)
{
	int			 error;

	assert(cp->cp_encode != NULL);
	error = (*cp->cp_encode)(c, out, val, arg);
#ifdef DEBUG_ENCODING
	if (error != 0) {
		char	errbuf[1024];

		strerror_r(error, errbuf, sizeof(errbuf));
		fprintf(stderr, "%s: error for type %s, value at %p: %d %s\n",
		    __FUNCTION__, cp->cp_name, val, error, errbuf);
	}
#endif
	return error;
}

ILIAS_NET2_EXPORT int
net2_cp_decode(struct net2_encdec_ctx *c, const struct command_param *cp,
    void *val, struct net2_buffer *in, const void *arg)
{
	int			 error;

	assert(cp->cp_decode != NULL);
	error = (*cp->cp_decode)(c, val, in, arg);
#ifdef DEBUG_ENCODING
	if (error != 0) {
		char	errbuf[1024];

		strerror_r(error, errbuf, sizeof(errbuf));
		fprintf(stderr, "%s: error for type %s, value at %p: %d %s\n",
		    __FUNCTION__, cp->cp_name, val, error, errbuf);
	}
#endif
	return error;
}

ILIAS_NET2_EXPORT int
net2_cp_init(struct net2_encdec_ctx *c, const struct command_param *cp,
    void *val, const void *arg)
{
	if (!cp->cp_init)
		return 0;
	return (*cp->cp_init)(c, val, arg);
}

ILIAS_NET2_EXPORT int
net2_cp_destroy(struct net2_encdec_ctx *c, const struct command_param *cp,
    void *val, const void *arg)
{
	if (!cp->cp_delete)
		return 0;
	return (*cp->cp_delete)(c, val, arg);
}

/*
 * Allocate and initialize a command_param.
 */
ILIAS_NET2_EXPORT int
net2_cp_init_alloc(struct net2_encdec_ctx *ctx, const struct command_param *cp,
    void **ptr, const void *arg)
{
	/* Allocate parameter space. */
	if ((*ptr = net2_malloc(cp->cp_size)) == NULL)
		goto fail_0;
	/* Initialize allocated space. */
	if (net2_cp_init(ctx, cp, *ptr, arg))
		goto fail_1;

	return 0;

fail_1:
	net2_free(*ptr);
	*ptr = NULL;
fail_0:
	return -1;
}

/*
 * Destroy and release a command param.
 */
ILIAS_NET2_EXPORT int
net2_cp_destroy_alloc(struct net2_encdec_ctx *ctx,
    const struct command_param *cp, void **ptr, const void *arg)
{
	int				 err;

	/* Cannot release what doesn't exist. */
	if (*ptr == NULL)
		return 0;

	/* Destroy allocated space. */
	if ((err = net2_cp_destroy(ctx, cp, *ptr, arg)) == 0) {
		/* Release parameter space. */
		net2_free(*ptr);
		*ptr = NULL;	/* For safety. */
	}

	return err;
}


/*
 * Invocation context.
 *
 * Describes invocation method, input and output parameters.
 */
struct net2_invocation_ctx {
	struct net2_objmanager		*man;		/* Context. */
	const struct command_method	*invocation;	/* Method decl. */
	void				*in_params;	/* Input. */
};

/*
 * Create invocation context.
 *
 * in_arg will be owned by the resulting promise.
 */
ILIAS_NET2_EXPORT struct net2_promise*
net2_invoke(struct net2_objmanager *man, const struct command_param *cp,
    void *in_arg)
{
	assert(0); /* XXX implement. */
	return NULL;
}
