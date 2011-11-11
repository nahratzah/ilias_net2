#ifndef ILIAS_NET2_MUTEX_H
#define ILIAS_NET2_MUTEX_H

#include <ilias/net2/ilias_net2_export.h>

struct net2_mutex;

#ifdef ilias_net2_EXPORTS
ILIAS_NET2_LOCAL
struct net2_mutex	*net2_mutex_alloc();
ILIAS_NET2_LOCAL
void			 net2_mutex_free(struct net2_mutex*);
ILIAS_NET2_LOCAL
void			 net2_mutex_lock(struct net2_mutex*);
ILIAS_NET2_LOCAL
void			 net2_mutex_unlock(struct net2_mutex*);
#endif /* ilias_net2_EXPORTS */

#endif /* ILIAS_NET2_MUTEX_H */
