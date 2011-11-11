#include <ilias/net2/cluster/cfg.h>
#include <bsd_compat/error.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#ifdef WIN32
#include <WinSock2.h>
#include <Iphlpapi.h>
#else
#include <unistd.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#endif
#include <assert.h>


/* Release resources associated with the node config. */
static void
net2_nodecfg_destroy(struct net2_node_cfg *cfg)
{
	struct net2_cluster_addr**addr;

	if (cfg->site_addr)
		free(cfg->site_addr);
	if (cfg->clust_addr)
		free(cfg->clust_addr);
	if (cfg->client_addr) {
		for (addr = cfg->client_addr; *addr != NULL; addr++)
			free(*addr);
		free(cfg->client_addr);
	}
	free(cfg->hostname);
}

/* Release resources associated with the site config. */
static void
net2_sitecfg_destroy(struct net2_site_cfg *cfg)
{
	struct net2_cluster_network
				**addr;
	struct net2_node_cfg	*node;

	while ((node = TAILQ_FIRST(&cfg->nodes)) != NULL) {
		TAILQ_REMOVE(&cfg->nodes, node, nodeq);
		net2_nodecfg_destroy(node);
		free(node);
	}
	if (cfg->site_mcast)
		free(cfg->site_mcast);
	if (cfg->auto_node) {
		if (cfg->auto_node->client_addr) {
			for (addr = cfg->auto_node->client_addr;
			    *addr != NULL; addr++)
				free(*addr);
			free(cfg->auto_node->client_addr);
		}
		free(cfg->auto_node);
	}
	free(cfg->name);
	free(cfg->secret);
}

/*
 * Free all resources used to maintain the cluster configuration.
 * Does not free cfg.
 */
ILIAS_NET2_EXPORT
void
net2_clustercfg_destroy(struct net2_cluster_cfg *cfg)
{
	struct net2_site_cfg	*site;

	while ((site = TAILQ_FIRST(&cfg->sites)) != NULL) {
		TAILQ_REMOVE(&cfg->sites, site, siteq);
		net2_sitecfg_destroy(site);
		free(site);
	}
	free(cfg->name);
	free(cfg->secret);
}

/*
 * Add a site to the cluster.
 *
 * Name and secret are copied.
 * Returns NULL and sets errno on failure.
 *
 * errno ENOMEM: insufficient memory to complete operation
 * errno EINVAL: invalid argument supplied (name or secret were NULL or empty)
 * errno EEXIST: site with this name already exists
 */
ILIAS_NET2_EXPORT struct net2_site_cfg*
net2_clustercfg_addsite(struct net2_cluster_cfg *cfg,
    const char *name, const char *secret)
{
	struct net2_site_cfg	*site;

	/* Check arguments. */
	if (name   == NULL || name[0]   == '\0' ||
	    secret == NULL || secret[0] == '\0') {
		errno = EINVAL;
		return NULL;
	}

	/* Check if the named site already exists. */
	TAILQ_FOREACH(site, &cfg->sites, siteq) {
		if (strcmp(site->name, name) == 0) {
			errno = EEXIST;
			return NULL;
		}
	}

	/* Create site structure. */
	if ((site = malloc(sizeof(*site))) == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	TAILQ_INIT(&site->nodes);
	site->parent = cfg;
	site->name = strdup(name);
	site->secret = strdup(secret);
	site->site_mcast = NULL;
	site->auto_node = NULL;

	/* Check if name and secret copy succeeded. */
	if (site->name == NULL || site->secret == NULL) {
		if (site->name)
			free(site->name);
		if (site->secret)
			free(site->secret);
		free(site);
		errno = ENOMEM;
		return NULL;
	}

	/* Link site into cluster. */
	TAILQ_INSERT_TAIL(&cfg->sites, site, siteq);

	return site;
}

/*
 * Add a node to the site.
 *
 * Name and secret are copied.
 * Returns NULL and sets errno on failure.
 *
 * errno ENOMEM: insufficient memory to complete operation
 * errno EINVAL: invalid argument supplied (name was NULL or empty)
 * errno EINVAL: cfg is not a valid config
 * errno EEXIST: node with this name already exists
 */
ILIAS_NET2_EXPORT struct net2_node_cfg*
net2_clustercfg_addnode(struct net2_site_cfg *cfg, const char *hostname)
{
	struct net2_node_cfg	*node;
	struct net2_site_cfg	*site;

	/* Check arguments. */
	if (hostname == NULL || hostname[0] == '\0' || cfg->parent == NULL) {
		errno = EINVAL;
		return NULL;
	}

	/* Check if the named node already exists. */
	TAILQ_FOREACH(site, &cfg->parent->sites, siteq) {
		TAILQ_FOREACH(node, &site->nodes, nodeq) {
			if (strcmp(node->hostname, hostname) == 0) {
				errno = EEXIST;
				return NULL;
			}
		}
	}

	/* Create node structure. */
	if ((node = malloc(sizeof(*node))) == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	node->parent = cfg;
	node->hostname = strdup(hostname);
	node->site_addr = NULL;
	node->clust_addr = NULL;
	node->client_addr = NULL;

	/* Check if name copy succeeded. */
	if (node->hostname == NULL) {
		errno = ENOMEM;
		free(node);
		return NULL;
	}

	/* Link node into cluster. */
	TAILQ_INSERT_TAIL(&cfg->nodes, node, nodeq);

	return node;
}

/*
 * Find the site with the given name.
 */
ILIAS_NET2_EXPORT struct net2_site_cfg*
net2_clustercfg_findsite(struct net2_cluster_cfg *cfg, const char *name)
{
	struct net2_site_cfg	*site;

	TAILQ_FOREACH(site, &cfg->sites, siteq) {
		if (strcmp(site->name, name) == 0)
			goto out;
	}
out:
	return site;
}

/*
 * Find the site with the given name.
 */
ILIAS_NET2_EXPORT struct net2_node_cfg*
net2_clustercfg_findnode(struct net2_cluster_cfg *cfg, const char *hostname)
{
	struct net2_site_cfg	*site;
	struct net2_node_cfg	*node;

	node = NULL;
	TAILQ_FOREACH(site, &cfg->sites, siteq) {
		TAILQ_FOREACH(node, &site->nodes, nodeq) {
			if (strcmp(node->hostname, hostname) == 0)
				goto out;
		}
	}
out:
	return node;
}

/* Check if two sockaddr addresses are equal. */
static int
sockaddr_eq(struct net2_cluster_addr *ca, struct sockaddr *sa)
{
	struct sockaddr_in	*sa_in, *ca_in;
	struct sockaddr_in6	*sa_in6, *ca_in6;

	if (ca == NULL)
		return 0;

	/* Ensure address families match. */
	if (ca->addr.ss_family != sa->sa_family)
		return 0;

	/* Compare address, based on address family. */
	switch (ca->addr.ss_family) {
	case AF_INET:
		sa_in = (struct sockaddr_in*)sa;
		ca_in = (struct sockaddr_in*)&ca->addr;
		if (ca_in->sin_addr.s_addr != sa_in->sin_addr.s_addr)
			return 0;
		break;
	case AF_INET6:
		sa_in6 = (struct sockaddr_in6*)sa;
		ca_in6 = (struct sockaddr_in6*)&ca->addr;
		if (memcmp(&ca_in6->sin6_addr, &sa_in6->sin6_addr,
		    sizeof(ca_in6->sin6_addr)))
			return 0;
		/* TODO: Should we compare interface address too? */
		break;
	default:
		return 0;
	}

	return 1;	/* All comparisons succeeded. */
}

/* Mask an IPv6 address. */
static __inline void
in6_apply_mask(struct in6_addr *addr, struct in6_addr *mask)
{
	int	i_max = sizeof(addr->s6_addr) / sizeof(addr->s6_addr[0]);
	int	i;

	for (i = 0; i < i_max; i++)
		addr->s6_addr[i] &= mask->s6_addr[i];
}

/* Check if the address is in the specified network. */
static int
in_cluster_network(struct net2_cluster_network *n, struct sockaddr *sa)
{
	struct in_addr		 addr4, *mask4, *base4;
	struct in6_addr		 addr6, *mask6, *base6;

	assert(n->base.addr.ss_family == n->mask.addr.ss_family);
	if (n->base.addr.ss_family != sa->sa_family)
		return 0;

	switch (n->base.addr.ss_family) {
	case AF_INET:
		addr4 = ((struct sockaddr_in*)sa)->sin_addr;
		mask4 = &((struct sockaddr_in*)&n->mask.addr)->sin_addr;
		base4 = &((struct sockaddr_in*)&n->base.addr)->sin_addr;
		addr4.s_addr &= mask4->s_addr;
		if (addr4.s_addr == base4->s_addr)
			return 1;
		break;
	case AF_INET6:
		addr6 = ((struct sockaddr_in6*)sa)->sin6_addr;
		mask6 = &((struct sockaddr_in6*)&n->mask.addr)->sin6_addr;
		base6 = &((struct sockaddr_in6*)&n->base.addr)->sin6_addr;
		in6_apply_mask(&addr6, mask6);
		if (memcmp(&addr6.s6_addr, base6->s6_addr,
		    sizeof(addr6.s6_addr)) == 0)
			return 0;
		break;
	default:
		warnx("unrecognized address family %u",
		    (unsigned int)n->base.addr.ss_family);
		return 0;
	}

	return 0;
}

/*
 * True iff the sockaddr is in the site autoconfig range.
 */
static int
in_autonode(struct net2_site_auto_cfg *cfg, struct sockaddr *sa)
{
	struct net2_cluster_network
				**n;

	if (cfg == NULL)
		return 0;

	if (in_cluster_network(&cfg->clust_addr, sa))
		return 1;
	for (n = cfg->client_addr; n != NULL && *n != NULL; n++) {
		if (in_cluster_network(*n, sa))
			return 1;
	}
	return 0;
}

/*
 * True iff the sockaddr is in the list of addresses of the node config.
 */
static int
in_node_addr(struct net2_node_cfg *cfg, struct sockaddr *sa)
{
	struct net2_cluster_addr**n;

	if (cfg == NULL)
		return 0;

	if (sockaddr_eq(cfg->site_addr, sa))
		return 1;
	if (sockaddr_eq(cfg->clust_addr, sa))
		return 1;
	for (n = cfg->client_addr; n != NULL && *n != NULL; n++) {
		if (sockaddr_eq(*n, sa))
			return 1;
	}
	return 0;
}


#ifdef WIN32
#define struct_ifaddrs	IP_ADAPTER_ADDRESSES
#define ifa_next	Next

/*
 * Implement a getifaddrs for windows OS, using the GetAdapterAddresses
 * function.
 *
 * See also: http://msdn.microsoft.com/en-us/library/aa365915.aspx
 */
ILIAS_NET2_LOCAL int
getifaddrs(struct_ifaddrs **ifa)
{
	ULONG	ifalen = 1024;			/* initial ifalen. */
	ULONG	rv = ERROR_BUFFER_OVERFLOW;	/* not ERROR_SUCCESS */
	int	tries = 0;

	/*
	 * Read adapter addresses from OS.
	 */
	while (rv != ERROR_SUCCESS) {
		if ((*ifa = malloc(ifalen)) == NULL)
			return -1;
		rv = GetAdaptersAddresses(AF_UNSPEC,
		    GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST |
		    GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER |
		    GAA_FLAG_SKIP_FRIENDLY_NAME,
		    NULL, *ifa, &ifalen);
		if (rv != ERROR_SUCCESS) {
			free(*ifa);
			if (rv != ERROR_BUFFER_OVERFLOW || tries > 3) {
				errno = EINVAL;	/* TODO: real errno */
				return -1;
			}

			/* ifalen now holds better length */
		}

		tries++;	/* Ensure we will terminate at some point... */
	}

	return 0;
}

struct ifaddrs_iter {
	IP_ADAPTER_ADDRESSES	*adapter;
	IP_ADAPTER_UNICAST_ADDRESS
				*addr;
};

static __inline void
first(struct ifaddrs_iter *i, IP_ADAPTER_ADDRESSES *list)
{
	i->adapter = list;
	if (list == NULL)
		i->addr = NULL;
	else
		i->addr = list->FirstUnicastAddress;
}

static __inline void
next(struct ifaddrs_iter *i)
{
	i->addr = i->addr->Next;
	if (i->addr != NULL)
		return;

	i->adapter = i->adapter->Next;
	if (i->adapter == NULL)
		return;
	i->addr = i->adapter->FirstUnicastAddress;
	return;
}

#define freeifaddrs(ifaddrs)	free((ifaddrs))
#define ifaddrs_iter		struct ifaddrs_iter
#define ifaddrs_sockaddr(_ifaiter)					\
				((_ifaiter).addr ?			\
				((_ifaiter).addr->Address.lpSockaddr) :	\
				NULL)

#define IFADDRS_FOREACH(_i, _list)					\
	for (first(&_i, _list); _i.adapter != NULL; next(&_i))

#else	/* WIN32 */

#define struct_ifaddrs		struct ifaddrs
#define ifaddrs_iter		struct ifaddrs *
#define ifaddrs_sockaddr(_ifaiter)				\
				((_ifaiter)->ifa_addr)

#define IFADDRS_FOREACH(_i, _list)				\
	for ((_i) = (_list); (_i) != NULL; (_i) = (_i)->ifa_next)

#endif	/* WIN32 */


/*
 * Attempt to find the nodecfg for this node.
 *
 * Returns NULL if the search fails.
 */
ILIAS_NET2_LOCAL int
net2_clustercfg_thisnode(struct net2_cluster_cfg *cfg,
    struct net2_node_cfg **node, struct net2_site_cfg **site)
{
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN	512
#endif
	struct net2_node_cfg	*self, *node_i;
	struct net2_site_cfg	*auto_site, *site_i;
	char			 myname[MAXHOSTNAMELEN];
	char			*dot;
	struct_ifaddrs		*ifap;
	ifaddrs_iter		 ifa;
	int			 dup_autosite, dup_selfnode, err;
	struct sockaddr		*sa;

	if (gethostname(myname, sizeof(myname))) {
		warn("failed to retrieve hostname");
		self = NULL;
		goto skip_hostname;
	}
	dot = strchr(myname, '.');

	/*
	 * Attempt to find hostname in clustercfg.
	 * If the full hostname fails to yield a result, try again with
	 * only the host-portion of the name.
	 */
	for (;;) {
		info("attempting to find hostname %s in clustercfg", myname);
		self = net2_clustercfg_findnode(cfg, myname);

		/* GUARD */
		if (self != NULL || dot == NULL || *dot == '\0')
			break;

		*dot = '\0';
	}

	/* Fill in site and node. */
	if (self != NULL) {
		*node = self;
		*site = self->parent;
		return 0;
	}

skip_hostname:
	if (getifaddrs(&ifap) == -1) {
		warn("getifaddrs failed");
		return -1;
	}

	auto_site = NULL;
	self = NULL;
	IFADDRS_FOREACH(ifa, ifap) {
		sa = ifaddrs_sockaddr(ifa);
		/* We're only interested in IP and IPv6 addresses. */
		if (sa == NULL)
			continue;
		if (sa->sa_family != AF_INET &&
		    sa->sa_family != AF_INET6)
			continue;

		/* Check if the address falls within a site. */
		TAILQ_FOREACH(site_i, &cfg->sites, siteq) {
			/*
			 * Check if the node is an automatically configured
			 * node within site_i.
			 */
			if (auto_site != site_i &&
			    site_i->auto_node != NULL &&
			    in_autonode(site_i->auto_node, sa)) {
				info("thisnode in auto site %s", site_i->name);
				if (auto_site == NULL)
					auto_site = site_i;
				else
					dup_autosite = 1;
			}

			/*
			 * Check if the node is a specially configured
			 * node within site_i.
			 */
			TAILQ_FOREACH(node_i, &site_i->nodes, nodeq) {
				/* Skip if already found. */
				if (self == node_i)
					continue;

				/* Test if node_i describes this address. */
				if (in_node_addr(node_i, sa)) {
					if (self == NULL)
						self = node_i;
					else
						dup_selfnode = 1;
				}
			}
		}
	}

	/*
	 * Conclusion.
	 *
	 * Fill in *site and *node.
	 * Complain if the selection returned an ambiguous result.
	 */
	err = -1;	/* Default to failure. */
	if (self != NULL) {
		if (dup_selfnode) {
			warnx("node selection ambiguity");
			goto out;
		}

		info("thisnode is host %s in site %s",
		    self->hostname, self->parent->name);
		*node = self;
		*site = self->parent;
	} else if (auto_site != NULL) {
		if (dup_autosite) {
			warnx("site selection ambiguity");
			goto out;
		}

		info("thisnode is autoconfigured host in site %s",
		    auto_site->name);
		*node = NULL;
		*site = auto_site;
	} else {
		warn("failure to find thisnode in site configuration");
		goto out;
	}

	err = 0;

out:
	if (ifap)
		freeifaddrs(ifap);

	return err;
}
