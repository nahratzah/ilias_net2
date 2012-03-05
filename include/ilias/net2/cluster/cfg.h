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
#ifndef ILIAS_NET2_CLUSTER_CFG_H
#define ILIAS_NET2_CLUSTER_CFG_H

#include <ilias/net2/ilias_net2_export.h>
#include <stdint.h>
#include <ilias/net2/config.h>
#ifdef WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <ilias/net2/bsd_compat/queue.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * An address in the cluster.
 */
struct net2_cluster_addr {
	struct sockaddr_storage
			 addr;
	socklen_t	 addrlen;
};

/*
 * An network specification.
 */
struct net2_cluster_network {
	struct net2_cluster_addr
			 base;
	struct net2_cluster_addr
			 mask;
	uint16_t	 port;		/* Network port (0 for any). */
};

/*
 * Configuration of the cluster.
 */
struct net2_cluster_cfg {
	char		*name;		/* Cluster name. */
	char		*secret;	/* Cluster shared secret. */

	TAILQ_HEAD(, net2_site_cfg)
			 sites;		/* Site configuration. */
};

/*
 * Configuration of a site.
 */
struct net2_site_cfg {
	char		*name;		/* Site name. */
	char		*secret;	/* Site shared secret. */

	struct net2_cluster_cfg
			*parent;	/* Pointer back to cluster. */
	TAILQ_HEAD(, net2_node_cfg)
			 nodes;		/* Node configuration. */
	TAILQ_ENTRY(net2_site_cfg)
			 siteq;		/* Link into cluster cfg. */

	struct net2_cluster_addr
			*site_mcast;	/* Site multicast address. */

	/* Automatic site configuration logic. */
	struct net2_site_auto_cfg {
		struct net2_cluster_network
			 site_addr;	/* Automatic site-local node. */
		struct net2_cluster_network
			 clust_addr;	/* Automatic cluster-local node. */
		struct net2_cluster_network
			**client_addr;	/* Automatic client side address. */
	}		*auto_node;
};

/*
 * Configuration of a node.
 */
struct net2_node_cfg {
	char		*hostname;	/* Node hostname. */

	struct net2_site_cfg
			*parent;	/* Pointer back to site. */
	TAILQ_ENTRY(net2_node_cfg)
			 nodeq;		/* Link into site cfg. */

	struct net2_cluster_addr
			*site_addr;	/* Site-local network address. */
	struct net2_cluster_addr
			*clust_addr;	/* Cluster-local network address. */
	struct net2_cluster_addr
			**client_addr;	/* Client side network addresses. */
};


ILIAS_NET2_EXPORT
void			 net2_clustercfg_destroy(struct net2_cluster_cfg*);
ILIAS_NET2_EXPORT
struct net2_site_cfg	*net2_clustercfg_addsite(struct net2_cluster_cfg*,
			    const char*, const char*);
ILIAS_NET2_EXPORT
struct net2_node_cfg	*net2_clustercfg_addnode(struct net2_site_cfg*,
			    const char*);
ILIAS_NET2_EXPORT
struct net2_site_cfg	*net2_clustercfg_findsite(struct net2_cluster_cfg*,
			    const char*);
ILIAS_NET2_EXPORT
struct net2_node_cfg	*net2_clustercfg_findnode(struct net2_cluster_cfg*,
			    const char*);

#ifdef BUILDING_ILIAS_NET2
ILIAS_NET2_LOCAL
int			 net2_clustercfg_thisnode(struct net2_cluster_cfg*,
			    struct net2_node_cfg**,
			    struct net2_site_cfg**);
#endif /* BUILDING_ILIAS_NET2 */

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_CLUSTER_CFG_H */
