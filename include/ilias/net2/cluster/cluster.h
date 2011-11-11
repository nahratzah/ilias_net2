#ifndef ILIAS_NET2_CLUSTER_CLUSTER_H
#define ILIAS_NET2_CLUSTER_CLUSTER_H

#include <ilias/net2/ilias_net2_export.h>

#ifdef __cplusplus
extern "C" {
#endif

struct net2_cluster_cfg;
struct net2_cluster;
struct net2_cluster_site;
struct net2_cluster_node;

ILIAS_NET2_EXPORT
struct net2_cluster	*net2_cluster_create(struct net2_cluster_cfg*);
ILIAS_NET2_EXPORT
void			 net2_cluster_destroy(struct net2_cluster*);

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_CLUSTER_CLUSTER_H */
