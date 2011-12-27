#include <ilias/net2/cp.h>
#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/obj_manager.h>
#include <stdlib.h>
#include <assert.h>

ILIAS_NET2_EXPORT int
net2_cp_encode(struct net2_encdec_ctx *c, const struct command_param *cp,
    struct net2_buffer *out, const void *val, const void *arg)
{
	assert(cp->cp_encode != NULL);
	return (*cp->cp_encode)(c, out, val, arg);
}

ILIAS_NET2_EXPORT int
net2_cp_decode(struct net2_encdec_ctx *c, const struct command_param *cp,
    void *val, struct net2_buffer *in, const void *arg)
{
	assert(cp->cp_decode != NULL);
	return (*cp->cp_decode)(c, val, in, arg);
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


struct net2_invocation_ctx {
	struct net2_objmanager		*man;
	const struct command_method	*invocation;
	void				*in_params;
	void				*out_params;
	uint32_t			 error;
};

/*
 * Allocate and initialize a command_param.
 */
static int
init_cp_pointer(struct net2_objmanager *man, const struct command_param *cp,
    void **ptr, const void *arg)
{
	struct net2_encdec_ctx		*ctx;

	/* Creating nothing is easy. */
	if (cp == NULL) {
		*ptr = NULL;
		return 0;
	}

	/* Prepare encoding context. */
	if ((ctx = net2_encdec_ctx_newobjman(man)) == NULL)
		goto fail_0;
	/* Allocate parameter space. */
	if ((*ptr = malloc(cp->cp_size)) == NULL)
		goto fail_1;
	/* Initialize allocated space. */
	if (net2_cp_init(ctx, cp, *ptr, arg))
		goto fail_2;

	/* Release encoding context. */
	net2_encdec_ctx_release(ctx);
	return 0;

fail_2:
	free(*ptr);
	*ptr = NULL;
fail_1:
	net2_encdec_ctx_rollback(ctx);
	net2_encdec_ctx_release(ctx);
fail_0:
	return -1;
}

/*
 * Destroy and release a command param.
 */
static int
destroy_cp_pointer(struct net2_objmanager *man, const struct command_param *cp,
    void **ptr, const void *arg)
{
	struct net2_encdec_ctx		*ctx;

	/* Cannot release what doesn't exist. */
	if (cp == NULL)
		return 0;
	if (*ptr == NULL)
		return 0;

	/* Prepare encoding context. */
	if ((ctx = net2_encdec_ctx_newobjman(man)) == NULL)
		goto fail_0;
	/* Destroy allocated space. */
	if (net2_cp_destroy(ctx, cp, *ptr, arg))
		goto fail_1;
	/* Release parameter space. */
	free(*ptr);
	*ptr = NULL;	/* For safety. */

	/* Release encoding context. */
	net2_encdec_ctx_release(ctx);
	return 0;

fail_1:
	net2_encdec_ctx_rollback(ctx);
	net2_encdec_ctx_release(ctx);
fail_0:
	return -1;
}

/*
 * Acquire an invocation context.
 */
ILIAS_NET2_EXPORT struct net2_invocation_ctx*
net2_invocation_ctx_new(struct net2_objmanager *man,
    const struct command_method *cm, void *in_params)
{
	struct net2_invocation_ctx	*ctx;

	if (man == NULL || cm == NULL || cm->cm_method == NULL)
		return NULL;
	if ((cm->cm_in == NULL) != (in_params == NULL))
		return NULL;

	if ((ctx = malloc(sizeof(*ctx))) == NULL)
		goto fail_0;
	ctx->man = man;
	net2_objmanager_ref(man);
	ctx->invocation = cm;
	ctx->in_params = in_params;
	ctx->error = 0;

	/* Prepare output space. */
	if (init_cp_pointer(man, cm->cm_out, &ctx->out_params, NULL))
		goto fail_1;

	return ctx;

fail_1:
	net2_objmanager_release(man);
	free(ctx);
fail_0:
	return NULL;
}

/*
 * Free an invocation context.
 */
ILIAS_NET2_EXPORT void
net2_invocation_ctx_free(struct net2_invocation_ctx *ctx)
{
	if (ctx == NULL)
		return;

	/* No ability to handle errors in this path... */
	destroy_cp_pointer(ctx->man, ctx->invocation->cm_in, ctx->in_params,
	    NULL);
	destroy_cp_pointer(ctx->man, ctx->invocation->cm_out, ctx->out_params,
	    NULL);

	if (ctx->man)
		net2_objmanager_release(ctx->man);

	free(ctx);
}
