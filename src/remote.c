#include <ilias/net2/remote.h>
#include <ilias/net2/connection.h>
#include <ilias/net2/mutex.h>
#include <ilias/net2/window.h>
#include <bsd_compat/error.h>
#include <stdlib.h>
#include <assert.h>

/* ID comparator. */
static __inline int
n2o_idcmp(struct net2_obj *l, struct net2_obj *r)
{
	return (l->n2o_id < r->n2o_id ? -1 : l->n2o_id > r->n2o_id);
}

/* Implementation comparator. */
static int
n2o_implcmp(struct net2_obj *l, struct net2_obj *r)
{
	int cmp;

	if (l->n2o_type == r->n2o_type)
		cmp = 0;
	else
		cmp = (l->n2o_type->n2ot_id < r->n2o_type->n2ot_id ? -1 :
		    l->n2o_type->n2ot_id > r->n2o_type->n2ot_id);

	if (cmp == 0)
		cmp = (l->n2o_impl < r->n2o_impl ? -1 :
		    l->n2o_impl > r->n2o_impl);
	return cmp;
}

RB_PROTOTYPE_STATIC(net2_obj_set, net2_obj, n2o_idtree, n2o_idcmp);

/* Initialize object manager. */
ILIAS_NET2_LOCAL int
net2_objmanager_init(struct net2_connection *c)
{
	struct net2_objmanager	*m = &c->n2c_objmanager;

	RB_INIT(&m->om_idset);
	if ((m->mtx = net2_mutex_alloc()) == NULL)
		return -1;
	return 0;
}

/* Destroy object manager. */
ILIAS_NET2_LOCAL void
net2_objmanager_destroy(struct net2_connection *c)
{
	struct net2_objmanager	*m = &c->n2c_objmanager;
	struct net2_obj		*obj;

	while ((obj = RB_ROOT(&m->om_idset)) != NULL) {
		RB_REMOVE(net2_obj_set, &m->om_idset, obj);
		net2_obj_release(obj);
	}
	net2_mutex_free(m->mtx);
}

/* Release reference to object. */
ILIAS_NET2_EXPORT void
net2_obj_release(struct net2_obj *o)
{
	if (o == NULL)
		return;

	net2_mutex_lock(o->n2o_mtx);
	assert(o->n2o_refcnt > 0);
	--o->n2o_refcnt;

	if (o->n2o_refcnt == 0 && o->n2o_remoteref == 0 &&
	    o->n2o_wirecnt == 0) {
		net2_mutex_unlock(o->n2o_mtx);
		if (o->n2o_release)
			(*o->n2o_release)(o->n2o_window->n2w_conn, o->n2o_impl);
		net2_window_unlink(o);
		free(o);
	} else
		net2_mutex_unlock(o->n2o_mtx);
}

/* Add reference to object. */
ILIAS_NET2_EXPORT void
net2_obj_reference(struct net2_obj *o)
{
	if (o != NULL) {
		net2_mutex_lock(o->n2o_mtx);
		o->n2o_refcnt++;
		assert(o->n2o_refcnt != 0);
		net2_mutex_unlock(o->n2o_mtx);
	}
}

/*
 * Allocate a new object.
 *
 * The newly allocated object is not associated with a connection.
 */
ILIAS_NET2_EXPORT struct net2_obj*
net2_obj_new(struct net2_connection *conn, const struct net2_objtype *t,
    void *impl, net2_objrelease_fun rel, struct net2_window *window)
{
	struct net2_obj		*o;

	if (window != NULL && window->n2w_conn != conn) {
		warnx("new object %p: connection %p and window connection %p "
		    "do not match", impl, conn, window->n2w_conn);
		return NULL;
	}

	if ((o = malloc(sizeof(*o))) == NULL)
		return NULL;
	if ((o->n2o_mtx = net2_mutex_alloc()) == NULL) {
		free(o);
		return NULL;
	}

	/* Connect window to object. */
	if (window)
		net2_window_reference(window);
	else if ((window = net2_window_new(conn)) == NULL) {
		net2_mutex_free(o->n2o_mtx);
		free(o);
		return NULL;
	}
	net2_window_link(window, o);
	net2_window_release(window);

	/* Setup variables. */
	o->n2o_id = 0;
	o->n2o_refcnt = 1;
	o->n2o_remoteref = 0;
	o->n2o_wirecnt = 0;
	o->n2o_impl = impl;
	o->n2o_release = rel;
	o->n2o_type = t;
	return o;
}

/* Locate object via ID. */
ILIAS_NET2_EXPORT struct net2_obj*
net2_obj_by_id(struct net2_connection *c, uint32_t id)
{
	struct net2_objmanager	*m = &c->n2c_objmanager;
	struct net2_obj		 search, *found;

	search.n2o_id = id;

	net2_mutex_lock(m->mtx);
	found = RB_FIND(net2_obj_set, &m->om_idset, &search);
	net2_obj_reference(found);
	net2_mutex_unlock(m->mtx);
	return found;
}

/*
 * Find an unused ID within the object manager.
 */
static uint32_t
objman_id(struct net2_objmanager *m)
{
	struct net2_obj	*o;
	uint32_t	 id;

	id = 1;
	assert(!(id & NET2_OBJ_IDREMOTE));
	RB_FOREACH(o, net2_obj_set, &m->om_idset) {
		if (id != o->n2o_id)
			return id;
		if (++id & NET2_OBJ_IDREMOTE)
			break;
	}
	return 0;
}

/*
 * Place object on the wire.
 *
 * The object will be kept alive and subsequent efforts to put the object on
 * the wire are assured of the same ID.
 * The object can later be committed or rolled back.
 */
ILIAS_NET2_LOCAL uint32_t
net2_obj_wire(struct net2_connection *c, struct net2_obj *o)
{
	struct net2_objmanager	*m = &c->n2c_objmanager;
	struct net2_obj		*collide;

	/* Lock the object manager. */
	net2_mutex_lock(m->mtx);
	/* Lock the object. */
	net2_mutex_lock(o->n2o_mtx);

	/* Handle duplicate registration. */
	if (o->n2o_id != 0) {
		if (o->n2o_window->n2w_conn != c) {
			warnx("%s: attempt to register object "
			    "that is registered on a different connection",
			    __FUNCTION__);
			goto fail;
		}
	} else {
		/* Object cannot be on the wire without being registered. */
		assert(o->n2o_wirecnt == 0);

		/* Assign ID and connection to object. */
		if ((o->n2o_id = objman_id(m)) == 0)
			goto fail;

		/*
		 * Insert object into set.
		 * Collision here means programmer error finding a unique ID.
		 */
		collide = RB_INSERT(net2_obj_set, &m->om_idset, o);
		assert(collide == NULL);
	}

	/* Increment wire reference counter. */
	o->n2o_wirecnt++;
	/* Unlock object manager and return ID. */
	net2_mutex_unlock(o->n2o_mtx);
	net2_mutex_unlock(m->mtx);
	return o->n2o_id;

fail:
	net2_mutex_unlock(o->n2o_mtx);
	net2_mutex_unlock(m->mtx);
	return 0;
}

/*
 * Commit the object to the object maanger.
 * Called when remote end has acknowledged the object will be processed.
 */
ILIAS_NET2_LOCAL void
net2_obj_wire_commit(struct net2_connection *c, struct net2_obj *o)
{
	net2_mutex_lock(o->n2o_mtx);
	assert(o->n2o_window->n2w_conn == c);	/* Programmer error. */
	assert(o->n2o_wirecnt > 0);	/* Programmer error. */
	o->n2o_wirecnt--;
	o->n2o_remoteref = 1;
	net2_mutex_unlock(o->n2o_mtx);
}

/*
 * Perform rollback for an object added to the object manager.
 * Called when remote end confirms not having processed the object.
 */
ILIAS_NET2_LOCAL void
net2_obj_wire_rollback(struct net2_connection *c, struct net2_obj *o)
{
	struct net2_objmanager	*m = &c->n2c_objmanager;
	struct net2_obj		*rm;

	/* Lock object manager and object. */
	net2_mutex_lock(m->mtx);
	net2_mutex_lock(o->n2o_mtx);

	assert(o->n2o_window->n2w_conn == c);	/* Programmer error. */
	assert(o->n2o_wirecnt > 0);	/* Programmer error. */
	o->n2o_wirecnt--;
	o->n2o_refcnt++;		/* Keep alive while here. */

	/* Remove object from manager if it is not in use. */
	if (o->n2o_remoteref == 0 && o->n2o_wirecnt == 0) {
		rm = RB_REMOVE(net2_obj_set, &m->om_idset, o);
		assert(rm == o);
	}

	/* Unlock. */
	net2_mutex_unlock(o->n2o_mtx);
	net2_mutex_unlock(m->mtx);

	net2_obj_release(o);		/* Counter previous refcnt++. */
}

/*
 * Deregister an object.
 *
 * Used internally during insert rollback and when client releases an object.
 */
ILIAS_NET2_LOCAL void
net2_obj_deregister(struct net2_connection *c, struct net2_obj *o)
{
	struct net2_objmanager	*m = &c->n2c_objmanager;
	struct net2_obj		*rm;

	/* Check if the object is not registered. */
	if (o->n2o_wirecnt != 0 || o->n2o_remoteref != 0)
		return;
	assert(o->n2o_window->n2w_conn == c);

	/* Lock the object manager. */
	net2_mutex_lock(m->mtx);

	/* Remove object from set. */
	rm = RB_REMOVE(net2_obj_set, &m->om_idset, o);
	assert(rm == o);

	/* Decrement reference counter. */
	net2_obj_release(o);

	/* Unlock object manager and return ID. */
	net2_mutex_unlock(m->mtx);
}

/*
 * Invoke stub creation.
 */
struct net2_obj*
net2_obj_initstub(struct net2_connection *c,
    const struct net2_objtype *t, uint32_t id, struct net2_window *win)
{
	struct net2_objmanager	*m = &c->n2c_objmanager;
	struct net2_obj		*o, search, *collide;

	/* Lock object manager. */
	net2_mutex_lock(m->mtx);

	/* Check if the object already exists. */
	search.n2o_id = id;
	o = RB_FIND(net2_obj_set, &m->om_idset, &search);
	if (o != NULL) {
		if (o->n2o_type->n2ot_id != t->n2ot_id) {
			warnx("%s: attempt to register stub id %u "
			    "which exists with a different type",
			    "net2_obj_initstub");
			net2_mutex_unlock(m->mtx);
			return NULL;
		}
		net2_obj_reference(o);
		net2_mutex_unlock(m->mtx);
		return o;
	}

	/* Allocate new object. */
	o = malloc(sizeof(*o));
	if (o == NULL) {
		net2_mutex_unlock(m->mtx);
		return NULL;
	}
	o->n2o_mtx = net2_mutex_alloc();
	if (o->n2o_mtx == NULL) {
		free(o);
		net2_mutex_unlock(m->mtx);
		return NULL;
	}

	/* Initialize values. */
	o->n2o_id = id;
	o->n2o_type = t;
	o->n2o_impl = NULL;
	o->n2o_release = NULL;
	o->n2o_refcnt = 2;	/* Ref in objmanager and return value. */

	/* Initialize stub. */
	if (t->n2ot_stubinit) {
		if ((*t->n2ot_stubinit)(c, &o->n2o_impl, &o->n2o_release)) {
			net2_mutex_unlock(m->mtx);
			net2_mutex_free(o->n2o_mtx);
			free(o);
			return NULL;
		}
	}

	/*
	 * Collision here can only happen if object duplicate ID wasn't
	 * detected above.
	 */
	collide = RB_INSERT(net2_obj_set, &m->om_idset, o);
	assert(collide == NULL);
	net2_window_link(win, o);

	net2_mutex_unlock(m->mtx);
	return o;
}

RB_GENERATE_STATIC(net2_obj_set, net2_obj, n2o_idtree, n2o_idcmp);
