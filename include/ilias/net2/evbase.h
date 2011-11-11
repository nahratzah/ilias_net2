#ifndef ILIAS_NET2_EVBASE_H
#define ILIAS_NET2_EVBASE_H

#include <ilias/net2/types.h>
#include <ilias/net2/ilias_net2_export.h>
#include <sys/types.h>

/*
 * A shared event base.
 *
 * The event base is reference counted and can be shared across network code.
 */
struct net2_evbase {
	struct net2_mutex	*mtx;		/* Protect the refcnt. */
	struct event_base	*evbase;	/* Libevent base. */
	size_t			 refcnt;	/* Reference counter. */

	struct net2_thread	*thread;	/* Active thread. */
	struct event		*threadlive;	/* Keep thread alive. */
};

ILIAS_NET2_EXPORT
struct net2_evbase		*net2_evbase_new();
ILIAS_NET2_EXPORT
void				 net2_evbase_release(struct net2_evbase*);
ILIAS_NET2_EXPORT
void				 net2_evbase_ref(struct net2_evbase*);
ILIAS_NET2_EXPORT
int				 net2_evbase_threadstart(struct net2_evbase*);
ILIAS_NET2_EXPORT
int				 net2_evbase_threadstop(struct net2_evbase*);

#endif /* ILIAS_NET2_EVBASE_H */
