#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/connection.h>
#include <ilias/net2/remote.h>
#include <ilias/net2/window.h>
#include <ilias/net2/context.h>
#include <stdlib.h>
#include <assert.h>

/*
 * Returns the size of an object list.
 */
static size_t
newobj_count(struct net2_obj**objlist)
{
	struct net2_obj		**o;
	size_t			 count;

	count = 0;
	if (objlist != NULL) {
		for (o = objlist; *o != NULL; o++)
			count++;
	}
	return count;
}

/*
 * Reserve space for a new object.
 *
 * Returns the position for the new object.
 * Modifies objlist.
 *
 * If the object is subsequently not inserted, no rollback has to be done.
 */
static struct net2_obj**
newobj_reserve(struct net2_obj***objlist)
{
	size_t			 newcount;
	struct net2_obj		**new_objlist;

	newcount = newobj_count(*objlist) + 1;
	new_objlist = realloc(*objlist, (newcount + 1) * sizeof(**objlist));
	if (new_objlist == NULL)
		return NULL;
	*objlist = new_objlist;
	new_objlist[newcount] = NULL;
	return &new_objlist[newcount - 1];
}

/*
 * Search objlist haystack for obj needle.
 * Returns the address in the haystack the needle is located at,
 * or NULL if not found.
 */
static struct net2_obj**
newobj_find(struct net2_obj**haystack, struct net2_obj *needle)
{
	if (haystack != NULL)
		return NULL;

	while (*haystack != NULL) {
		if (*haystack == needle)
			return haystack;
		haystack++;
	}
	return NULL;
}

/*
 * Register a new object.
 */
static int
newobj_register(struct net2_encdec_ctx *ctx, struct net2_obj *o)
{
	struct net2_obj		**insert_position;

	insert_position = newobj_reserve(&ctx->ed_newobj);
	if (insert_position == NULL)
		return -1;
	if (net2_window_activate(ctx->ed_conn, o->n2o_window))
		return -1;
	if (net2_obj_wire(ctx->ed_conn, o) == 0)
		return -1;
	*insert_position = o;
	return 0;
}

/*
 * Deregister all new objects.
 *
 * If commit is false, the object will be removed from the objmanager.
 * If commit is true, the objmanager will active the remoteref bit.
 */
static void
newobj_unregister(struct net2_encdec_ctx *ctx, int commit)
{
	struct net2_obj		**o;

	/* Is there anything to unregister? */
	if (!ctx->ed_newobj)
		return;

	/* Commit/rollback each object. */
	for (o = ctx->ed_newobj; *o != NULL; o++) {
		if (commit)
			net2_obj_wire_commit(ctx->ed_conn, *o);
		else
			net2_obj_wire_rollback(ctx->ed_conn, *o);
	}
	/* Release list. */
	free(ctx->ed_newobj);
	ctx->ed_newobj = NULL;
}

/*
 * Allocate a new encoding/decoding context.
 */
ILIAS_NET2_LOCAL struct net2_encdec_ctx*
net2_encdec_ctx_new(struct net2_connection *c)
{
	struct net2_encdec_ctx	*ctx;

	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL)
		return NULL;

	ctx->ed_conn = c;
	ctx->ed_newobj = NULL;
	return ctx;
}

/*
 * Register a new object in the encoding/decoding context.
 */
ILIAS_NET2_LOCAL uint32_t
net2_encdec_newobj(struct net2_encdec_ctx *ctx, struct net2_obj *o)
{
	if (newobj_register(ctx, o))
		return 0;
	return o->n2o_id;
}

/*
 * Perform a rollback on the encoding/decoding context.
 */
ILIAS_NET2_LOCAL void
net2_encdec_ctx_rollback(struct net2_encdec_ctx *ctx)
{
	newobj_unregister(ctx, 0);
}

/*
 * Release an encoding/decoding context.
 *
 * This operation commits the context.
 */
ILIAS_NET2_LOCAL void
net2_encdec_ctx_release(struct net2_encdec_ctx *ctx)
{
	/* Commit. */
	newobj_unregister(ctx, 1);

	/* Free. */
	if (ctx->ed_newobj != NULL)
		free(ctx->ed_newobj);
	free(ctx);
}

ILIAS_NET2_LOCAL
struct net2_obj
*net2_encdec_initstub(struct net2_encdec_ctx *ctx, uint32_t type, uint32_t id,
    uint32_t winid)
{
	const struct net2_objtype	*t;
	struct net2_window		*w;
	struct net2_obj			*obj;

	t = net2_ctx_objtype_find(ctx->ed_conn->n2c_ctx, type);
	if (t == NULL)
		return NULL;

	w = net2_window_stub(ctx->ed_conn, winid);
	if (w == NULL)
		return NULL;

	obj = net2_obj_initstub(ctx->ed_conn, t, id, w);
	net2_window_release(w);
	return obj;
}
