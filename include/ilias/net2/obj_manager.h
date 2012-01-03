#ifndef ILIAS_NET2_OBJ_MANAGER_H
#define ILIAS_NET2_OBJ_MANAGER_H

#include <ilias/net2/ilias_net2_export.h>

#ifdef ilias_net2_EXPORTS

#include <ilias/net2/connection.h>
#include <ilias/net2/protocol.h>
#include <bsd_compat.h>

#ifdef HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include <bsd_compat/tree.h>
#endif

#endif /* ilias_net2_EXPORTS */

#ifdef __cplusplus
extern "C" {
#endif

struct net2_objmanager;

/* Callback argument return. */
typedef void (*net2_objman_return_cb)(int conn_error, int cb_error,
    void *cbarg, void *out_params);


#ifdef ilias_net2_EXPORTS
struct net2_objman_group;
struct net2_objman_tx_ticket;
struct net2_objman_rx_ticket;

RB_HEAD(net2_objman_groups, net2_objman_group);
RB_HEAD(net2_objman_ttx, net2_objman_tx_ticket);

/*
 * Object manager.
 *
 * Manages groups (which are 0 or more objects sharing a single window).
 * Manages requests (which are remote method invocations).
 */
struct net2_objmanager {
	struct net2_conn_acceptor
				 base;
	struct net2_evbase	*evbase;

	int			 flags;		/* State flags. */
	struct net2_pvlist	 pvlist;	/* Negotiated protocols. */

	struct net2_objman_groups
				 groups;	/* Local groups. */
	struct net2_objman_ttx	 tx_tickets;	/* Outstanding invocations. */

	struct net2_mutex	*mtx;		/* Guard. */
	size_t			 refcnt;	/* Reference counter. */
};
#endif /* ilias_net2_EXPORTS */


/* Cast objmanager to conn acceptor. */
static __inline struct net2_conn_acceptor*
net2_objmanager_reduce(struct net2_objmanager *m)
{
	return (struct net2_conn_acceptor*)m;
}


/* Create a new obj manager. */
ILIAS_NET2_EXPORT
struct net2_objmanager	*net2_objmanager_new();

/* Reference an objmanager. */
ILIAS_NET2_EXPORT
void			 net2_objmanager_ref(struct net2_objmanager*);
/* Release an objmanager. */
ILIAS_NET2_EXPORT
void			 net2_objmanager_release(struct net2_objmanager*);

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_OBJ_MANAGER_H */
