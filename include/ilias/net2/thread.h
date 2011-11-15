#ifndef ILIAS_NET2_THREAD_H
#define ILIAS_NET2_THREAD_H

#include <ilias/net2/ilias_net2_export.h>

#ifdef __cplusplus
extern "C" {
#endif

struct net2_thread;

#ifdef ilias_net2_EXPORTS
ILIAS_NET2_LOCAL
struct net2_thread	*net2_thread_new(void *(*)(void*), void*, const char*);
ILIAS_NET2_LOCAL
int			 net2_thread_join(struct net2_thread*, void**);
ILIAS_NET2_LOCAL
void			 net2_thread_free(struct net2_thread*);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_THREAD_H */
