#ifndef ILIAS_NET2_REMOTE_H
#define ILIAS_NET2_REMOTE_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/types.h>
#include <bsd_compat.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include <bsd_compat/tree.h>
#endif

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <bsd_compat/queue.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif


/* Callback, invoked when an object is released. */
typedef void (*net2_objrelease_fun)(struct net2_connection*, void*);
typedef int  (*net2_stubinit_fun)(struct net2_connection*,
    void**, net2_objrelease_fun*);

/*
 * Object types are stored globally.
 *
 * Each object type has a unique ID which may not collide.
 */
struct net2_objtype {
	uint32_t	 n2ot_id;	/* Object type ID. */
	const char	*n2ot_name;	/* Name of this type. */

	net2_stubinit_fun
			 n2ot_stubinit;	/* Initialize remote object stub. */
};

/*
 * Objects are local to a particular connection.
 *
 * Each object has a pointer to its implementation.
 * Multiple connection level objects are allowed to share a single
 * implementation.
 *
 * The high bit of the ID is 1 if the object ID was allocated on the
 * remote end of the connection, while the ID is 0 if the object ID was
 * allocated locally.
 * Therefor, the full implementation of the object will always have the high
 * bit set to 0, while a stub will always have the high bit set to 1.
 *
 * Curries: the object may be curry for one or more objects.
 * Each request to the object will need to correct window IDs for these objects
 * in addition to its own ID.
 */
struct net2_obj {
	uint32_t	 n2o_id;	/* Connection scoped ID. */
#define NET2_OBJ_IDREMOTE	0x80000000

	const struct net2_objtype
			*n2o_type;	/* Object type. */

	void		*n2o_impl;	/* Implementation pointer. */

	struct net2_mutex
			*n2o_mtx;	/* Protect reference counters. */
	size_t		 n2o_refcnt;	/* Reference counter. */
	size_t		 n2o_remoteref : 1;
					/* Local object is referenced by
					 * remote object. */
	size_t		 n2o_wirecnt : 31;
					/* Local or remote object is referenced
					 * by transmission data on the wire. */

	RB_ENTRY(net2_obj)
			 n2o_idtree;	/* Index based on ID. */

	struct net2_window
			*n2o_window;	/* Object window. */

	net2_objrelease_fun
			 n2o_release;	/* Object release callback. */
};

/*
 * Object manager.
 */
struct net2_objmanager {
	struct net2_mutex
			*mtx;

	/* Tree maintaining all objects based on the ID. */
	RB_HEAD(net2_obj_set, net2_obj)
			 om_idset;
};

ILIAS_NET2_EXPORT
void		 net2_obj_release(struct net2_obj*);
ILIAS_NET2_EXPORT
void		 net2_obj_reference(struct net2_obj*);
ILIAS_NET2_EXPORT
struct net2_obj	*net2_obj_by_id(struct net2_connection*, uint32_t);
ILIAS_NET2_EXPORT
struct net2_obj	*net2_obj_new(struct net2_connection *conn,
		    const struct net2_objtype*,
		    void*, net2_objrelease_fun, struct net2_window*);

#ifdef ilias_net2_EXPORTS
ILIAS_NET2_LOCAL
int		 net2_objmanager_init(struct net2_connection*);
ILIAS_NET2_LOCAL
void		 net2_objmanager_destroy(struct net2_connection*);
ILIAS_NET2_LOCAL
uint32_t	 net2_obj_wire(struct net2_connection*,
		    struct net2_obj*);
ILIAS_NET2_LOCAL
void		 net2_obj_wire_commit(struct net2_connection*,
		    struct net2_obj*);
ILIAS_NET2_LOCAL
void		 net2_obj_wire_rollback(struct net2_connection*,
		    struct net2_obj*);
ILIAS_NET2_LOCAL
void		 net2_obj_deregister(struct net2_connection*,
		    struct net2_obj*);
ILIAS_NET2_LOCAL
struct net2_obj	*net2_obj_initstub(struct net2_connection*,
		    const struct net2_objtype*, uint32_t,
		    struct net2_window*);
#endif /* ilias_net2_EXPORTS */


#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_REMOTE_H */
