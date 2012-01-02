#include <ilias/net2/cp.h>
#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/obj_manager.h>
#include <ilias/net2/mutex.h>
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

/*
 * Allocate and initialize a command_param.
 */
ILIAS_NET2_EXPORT int
net2_cp_init_alloc(struct net2_encdec_ctx *ctx, const struct command_param *cp,
    void **ptr, const void *arg)
{
	/* Allocate parameter space. */
	if ((*ptr = malloc(cp->cp_size)) == NULL)
		goto fail_0;
	/* Initialize allocated space. */
	if (net2_cp_init(ctx, cp, *ptr, arg))
		goto fail_1;

	return 0;

fail_1:
	free(*ptr);
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
		free(*ptr);
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
	void				*out_params;	/* Output. */
	uint32_t			 error;		/* Error code. */

	struct net2_mutex		*mtx;		/* Protect flags. */
	int				 flags;		/* State flags. */
#define N2IVCTX_RUNNING			0x00000001	/* Is running. */
#define N2IVCTX_CANCEL_REQ		0x00000002	/* Cancel requested. */
};

static int
init(struct net2_objmanager *man, const struct command_param *cp,
    void **ptr, const void *arg)
{
	struct net2_encdec_ctx		*ctx;
	int				 err;

	if (cp == NULL) {
		*ptr = NULL;
		return 0;
	}

	if ((ctx = net2_encdec_ctx_newobjman(man)) == NULL)
		return -1;
	if ((err = net2_cp_init_alloc(ctx, cp, ptr, arg)) != 0)
		net2_encdec_ctx_rollback(ctx);
	net2_encdec_ctx_release(ctx);
	return err;
}

static int
destroy(struct net2_objmanager *man, const struct command_param *cp,
    void **ptr, const void *arg)
{
	struct net2_encdec_ctx		*ctx;
	int				 err;

	if (cp == NULL || *ptr == NULL)
		return 0;

	if ((ctx = net2_encdec_ctx_newobjman(man)) == NULL)
		return -1;
	if ((err = net2_cp_destroy_alloc(ctx, cp, ptr, arg)) != 0)
		net2_encdec_ctx_rollback(ctx);
	net2_encdec_ctx_release(ctx);
	return err;
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
	if ((ctx->mtx = net2_mutex_alloc()) == NULL)
		goto fail_1;
	ctx->flags = 0;

	/* Prepare output space. */
	if (init(man, cm->cm_out, &ctx->out_params, NULL))
		goto fail_2;

	return ctx;

fail_2:
	net2_mutex_free(ctx->mtx);
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
	destroy(ctx->man, ctx->invocation->cm_in,
	    ctx->in_params, NULL);
	destroy(ctx->man, ctx->invocation->cm_out,
	    ctx->out_params, NULL);

	if (ctx->man)
		net2_objmanager_release(ctx->man);
	net2_mutex_free(ctx->mtx);

	free(ctx);
}

/*
 * Mark invocation context as cancelled.
 */
ILIAS_NET2_EXPORT void
net2_invocation_ctx_cancel(struct net2_invocation_ctx *ctx)
{
	net2_mutex_lock(ctx->mtx);
	ctx->flags |= N2IVCTX_CANCEL_REQ;
	net2_mutex_unlock(ctx->mtx);
}

/*
 * True iff cancel was requesed.
 */
ILIAS_NET2_EXPORT int
net2_invocation_ctx_is_cancelled(struct net2_invocation_ctx *ctx)
{
	int		 cancelled;

	net2_mutex_lock(ctx->mtx);
	cancelled = (ctx->flags & N2IVCTX_CANCEL_REQ);
	net2_mutex_unlock(ctx->mtx);
	return cancelled;
}
