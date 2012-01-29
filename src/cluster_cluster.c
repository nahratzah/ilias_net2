#include <ilias/net2/cluster/cluster.h>
#include <ilias/net2/cluster/cfg.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <bsd_compat/bsd_compat.h>
#ifdef WIN32
#include <io.h>
#else
#include <sys/param.h>
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include <bsd_compat/tree.h>
#endif

/* Tree head for cluster sites. */
RB_HEAD(cluster_sites_name, net2_cluster_site);
RB_HEAD(cluster_sites_id,   net2_cluster_site);
/* Tree head for cluster nodes. */
RB_HEAD(cluster_nodes_name, net2_cluster_node);
RB_HEAD(cluster_nodes_id,   net2_cluster_node);

/*
 * A cluster definition.
 */
struct net2_cluster {
	struct cluster_sites_name
				 site_names;	/* Sites by name. */
	struct cluster_sites_id	 site_ids;	/* Sites by ID. */

	struct net2_cluster_cfg	*cfg;		/* Cluster configuration. */
};

/*
 * A site definition.
 */
struct net2_cluster_site {
	struct cluster_nodes_name
				 node_names;	/* Nodes by name. */
	struct cluster_nodes_id	 node_ids;	/* Nodes by ID. */

	RB_ENTRY(net2_cluster_site)
				 cname_tree;	/* Link by name into cluster. */
	RB_ENTRY(net2_cluster_site)
				 cid_tree;	/* Link by ID into cluster. */

	char			*name;		/* Site name. */
	uint32_t		 id;		/* Site ID. */
};

/*
 * A node definition.
 */
struct net2_cluster_node {
	struct net2_cluster_site*parent;	/* Site. */

	RB_ENTRY(net2_cluster_node)
				 sname_tree;	/* Link by name into site. */
	RB_ENTRY(net2_cluster_node)
				 sid_tree;	/* Link by ID into site. */

	char			*name;		/* Node hostname. */
	uint32_t		 id;		/* Node ID. */
};

/* Name comparator for site. */
static __inline int
cname_cmp(struct net2_cluster_site *l, struct net2_cluster_site *r)
{
	return strcmp(l->name, r->name);
}
/* ID comparator for site. */
static __inline int
cid_cmp(struct net2_cluster_site *l, struct net2_cluster_site *r)
{
	return (l->id < r->id ? -1 : l->id > r->id);
}
/* Name comparator for node. */
static __inline int
sname_cmp(struct net2_cluster_node *l, struct net2_cluster_node *r)
{
	return strcmp(l->name, r->name);
}
/* ID comparator for node. */
static __inline int
sid_cmp(struct net2_cluster_node *l, struct net2_cluster_node *r)
{
	return (l->id < r->id ? -1 : l->id > r->id);
}

/* Tree declarations. */
RB_PROTOTYPE_STATIC(cluster_sites_name, net2_cluster_site,
    cname_tree, cname_cmp);
RB_PROTOTYPE_STATIC(cluster_sites_id,   net2_cluster_site,
    cid_tree,   cid_cmp  );
RB_PROTOTYPE_STATIC(cluster_nodes_name, net2_cluster_node,
    sname_tree, sname_cmp);
RB_PROTOTYPE_STATIC(cluster_nodes_id,   net2_cluster_node,
    sid_tree,   sid_cmp  );


/* Create a basic cluster node. */
static struct net2_cluster_node*
net2_cluster_create_node(struct net2_node_cfg *cfg)
{
	struct net2_cluster_node*node;

	if ((node = malloc(sizeof(*node))) == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	if ((node->name = strdup(cfg->hostname)) == NULL) {
		free(node);
		errno = ENOMEM;
		return NULL;
	}
	node->id = -1;		/* Unassigned ID. */

	return node;
}

/* Create a basic cluster site. */
static struct net2_cluster_site*
net2_cluster_create_site(struct net2_site_cfg *cfg)
{
	struct net2_cluster_site*site;

	if ((site = malloc(sizeof(*site))) == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	RB_INIT(&site->node_names);
	RB_INIT(&site->node_ids);
	if ((site->name = strdup(cfg->name)) == NULL) {
		free(site);
		errno = ENOMEM;
		return NULL;
	}
	site->id = -1;		/* Unassigned ID. */

	return site;
}

/* Create a cluster from a cluster config. */
ILIAS_NET2_EXPORT struct net2_cluster*
net2_cluster_create(struct net2_cluster_cfg *cfg)
{
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif
	struct net2_cluster	*c;
	struct net2_node_cfg	*self;
	struct net2_cluster_site*site;
	struct net2_cluster_node*node;
	char			 hostname[MAXHOSTNAMELEN + 1];

	/* Create cluster. */
	if ((c = malloc(sizeof(*c))) == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	RB_INIT(&c->site_names);
	RB_INIT(&c->site_ids);
	c->cfg = cfg;
	gethostname(hostname, sizeof(hostname));

	/* Find this node in the cluster config. */
	self = net2_clustercfg_findnode(cfg, hostname);
	if (self == NULL) {
		free(c);
		errno = ESRCH;
		return NULL;
	}

	/* Create the site that we are to be part of. */
	site = net2_cluster_create_site(self->parent);
	if (site == NULL) {
		/* Propagate errno set by net2_cluster_create_site. */
		goto fail;
	}
	RB_INSERT(cluster_sites_name, &c->site_names, site);

	/* Create the node that we are to be part of. */
	node = net2_cluster_create_node(self);
	if (node == NULL) {
		/* Propagate errno set by net2_cluster_create_node. */
		goto fail;
	}
	RB_INSERT(cluster_nodes_name, &site->node_names, node);

	return c;

fail:
	net2_cluster_destroy(c);
	return NULL;
}


/* Free cluster node. */
static void
net2_cluster_destroy_node(struct net2_cluster_node *node)
{
	free(node->name);
	free(node);
}

/* Free cluster site. */
static void
net2_cluster_destroy_site(struct net2_cluster_site *site)
{
	struct net2_cluster_node*node;

	while ((node = RB_ROOT(&site->node_names)) == NULL) {
		RB_REMOVE(cluster_nodes_name, &site->node_names, node);
		net2_cluster_destroy_node(node);
	}
	free(site->name);
	free(site);
}

/* Free cluster. */
ILIAS_NET2_EXPORT void
net2_cluster_destroy(struct net2_cluster *c)
{
	struct net2_cluster_site*site;

	while ((site = RB_ROOT(&c->site_names)) == NULL) {
		RB_REMOVE(cluster_sites_name, &c->site_names, site);
		net2_cluster_destroy_site(site);
	}
	free(c);
}


/* Tree implementations. */
RB_GENERATE_STATIC(cluster_sites_name, net2_cluster_site,
    cname_tree, cname_cmp);
RB_GENERATE_STATIC(cluster_sites_id,   net2_cluster_site,
    cid_tree,   cid_cmp  );
RB_GENERATE_STATIC(cluster_nodes_name, net2_cluster_node,
    sname_tree, sname_cmp);
RB_GENERATE_STATIC(cluster_nodes_id,   net2_cluster_node,
    sid_tree,   sid_cmp  );
