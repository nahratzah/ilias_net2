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
#include <event2/event.h>
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
	void				*out_params;	/* Output. */
	uint32_t			 error;		/* Error code. */

	struct net2_mutex		*mtx;		/* Protect flags. */
	int				 flags;		/* State flags. */
#define N2IVCTX_RUNNING			0x00000010	/* Is running. */
#define N2IVCTX_CANCEL_REQ		0x00000020	/* Cancel requested. */
#define N2IVCTX_FINISHED		0x0000000f	/* Finish mask. */
#define N2IVCTX_FINISH_FIRED		0x00010000	/* Finish has fired. */

	struct event			*event[NET2_IVCTX__NUM_EVENTS];
							/* Events. */
};

static int
init(struct net2_objmanager *man, const struct command_param *cp,
    void **ptr, const void *arg)
{
	struct net2_encdec_ctx		 ctx;
	int				 err;

	if (cp == NULL) {
		*ptr = NULL;
		return 0;
	}

	if ((err = net2_encdec_ctx_newobjman(&ctx, man)) != 0)
		return err;
	if ((err = net2_cp_init_alloc(&ctx, cp, ptr, arg)) != 0)
		net2_encdec_ctx_rollback(&ctx);
	net2_encdec_ctx_deinit(&ctx);
	return err;
}

static int
destroy(struct net2_objmanager *man, const struct command_param *cp,
    void **ptr, const void *arg)
{
	struct net2_encdec_ctx		 ctx;
	int				 err;

	if (cp == NULL || *ptr == NULL)
		return 0;

	if ((err = net2_encdec_ctx_newobjman(&ctx, man)) != 0)
		return err;
	if ((err = net2_cp_destroy_alloc(&ctx, cp, ptr, arg)) != 0)
		net2_encdec_ctx_rollback(&ctx);
	net2_encdec_ctx_deinit(&ctx);
	return err;
}

/* Finish event, fired with cp locked. */
static void
ivctx_on_finish(struct net2_invocation_ctx *ctx)
{
	/* No locking: this is always called with ctx locked. */

	/* Fire only once. */
	if (ctx->flags & N2IVCTX_FINISH_FIRED)
		return;

	if (ctx->event[NET2_IVCTX_ON_FINISH]) {
		event_active(ctx->event[NET2_IVCTX_ON_FINISH], 0, 0);
		ctx->flags |= N2IVCTX_FINISH_FIRED;
	}
}

/* Retrieve flags in atomic fashion. */
static int
net2_invocation_ctx_flags(struct net2_invocation_ctx *ctx)
{
	int				 flags;

	net2_mutex_lock(ctx->mtx);
	flags = ctx->flags;
	net2_mutex_unlock(ctx->mtx);
	return flags;
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

	if ((ctx = net2_malloc(sizeof(*ctx))) == NULL)
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
	net2_free(ctx);
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

	net2_free(ctx);
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
	return (net2_invocation_ctx_flags(ctx) & N2IVCTX_CANCEL_REQ);
}

/*
 * Mark invocation as finished, due to cancelled request.
 */
ILIAS_NET2_EXPORT int
net2_invocation_ctx_fin(struct net2_invocation_ctx *ctx, int how)
{
	int			error = 0;

	/* Check that how is an allowed parameter. */
	switch (how) {
	case NET2_IVCTX_FIN_OK:
	case NET2_IVCTX_FIN_CANCEL:
	case NET2_IVCTX_FIN_ERROR:
		break;
	default:
		return EINVAL;
	}

	/* May only be invoked by asynchronous methods. */
	if (!(ctx->invocation->cm_flags & CM_ASYNC))
		return EINVAL;

	net2_mutex_lock(ctx->mtx);

	/* Cannot finish invocation that isn't running. */
	if (!(ctx->flags & N2IVCTX_RUNNING)) {
		error = EINVAL;
		goto out;
	}

	ctx->flags &= ~N2IVCTX_RUNNING;
	ctx->flags |= how;
	ivctx_on_finish(ctx); /* Fire event. */

out:
	net2_mutex_unlock(ctx->mtx);
	return error;
}

/*
 * Start running an invocation.
 */
ILIAS_NET2_EXPORT int
net2_invocation_ctx_run(struct net2_invocation_ctx *ctx)
{
	int			error = 0;
	int			invoke_error;

	net2_mutex_lock(ctx->mtx);

	/* Prevent double invocation. */
	if (ctx->flags & (N2IVCTX_RUNNING | N2IVCTX_FINISHED)) {
		error = EBUSY;
		goto out;
	}
	/* If cancelled, handle that immediately. */
	if (ctx->flags & N2IVCTX_CANCEL_REQ) {
		ctx->flags |= NET2_IVCTX_FIN_CANCEL;
		goto out;
	}

	/* Set to running state. */
	ctx->flags |= N2IVCTX_RUNNING;
	net2_mutex_unlock(ctx->mtx);

	/* Invoke method and store invocation error. */
	invoke_error = (*ctx->invocation->cm_method)(ctx, ctx->in_params,
	    ctx->out_params);
	/* If the method is async, return immediately. */
	if (ctx->invocation->cm_flags & CM_ASYNC) {
		if (invoke_error != 0) {
			/*
			 * Invocation failed to start.
			 */
			net2_mutex_lock(ctx->mtx);
			ctx->flags &= ~N2IVCTX_RUNNING;
			ctx->flags |= NET2_IVCTX_FIN_FAIL;
			/* No fin event: invocation failure != finish. */
			net2_mutex_unlock(ctx->mtx);
		}

		/* Return invocation error result. */
		return invoke_error;
	}

	/*
	 * Method is not async, thus it completed.
	 * Mark it as completed.
	 */
	net2_mutex_lock(ctx->mtx);
	ctx->flags &= ~N2IVCTX_RUNNING;
	if (invoke_error) {
		ctx->flags |= NET2_IVCTX_FIN_ERROR;
		ctx->error = invoke_error;
	} else
		ctx->flags |= NET2_IVCTX_FIN_OK;

	assert(ctx->flags & N2IVCTX_FINISHED);
	assert(!(ctx->flags & N2IVCTX_RUNNING));
	ivctx_on_finish(ctx); /* We just declared fin. */

out:
	net2_mutex_unlock(ctx->mtx);
	return error;
}

/* Return true iff the invocation is in the running state. */
ILIAS_NET2_EXPORT int
net2_invocation_ctx_is_running(struct net2_invocation_ctx *ctx)
{
	return net2_invocation_ctx_flags(ctx) & N2IVCTX_RUNNING;
}

/* Return the finish state of the invocation. */
ILIAS_NET2_EXPORT int
net2_invocation_ctx_finished(struct net2_invocation_ctx *ctx)
{
	return net2_invocation_ctx_flags(ctx) & N2IVCTX_FINISHED;
}

/* Return event pointer. */
ILIAS_NET2_EXPORT struct event*
net2_invocation_ctx_get_event(struct net2_invocation_ctx *ctx, int evno)
{
	struct event			*ev;

	if (evno < 0 || evno >= NET2_IVCTX__NUM_EVENTS)
		return NULL;

	net2_mutex_lock(ctx->mtx);
	ev = ctx->event[evno];
	net2_mutex_unlock(ctx->mtx);
	return ev;
}

/* Set event pointer. */
ILIAS_NET2_EXPORT int
net2_invocation_ctx_set_event(struct net2_invocation_ctx *ctx, int evno,
    struct event *new_ev, struct event **old_ev)
{
	if (evno < 0 || evno >= NET2_IVCTX__NUM_EVENTS)
		return -1;

	net2_mutex_lock(ctx->mtx);
	if (old_ev)
		*old_ev = ctx->event[evno];
	ctx->event[evno] = new_ev;

	if (ctx->flags & N2IVCTX_FINISHED)
		ivctx_on_finish(ctx);
	net2_mutex_unlock(ctx->mtx);
	return 0;
}
