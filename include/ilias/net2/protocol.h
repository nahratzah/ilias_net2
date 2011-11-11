#ifndef ILIAS_NET2_PROTOCOL_H
#define ILIAS_NET2_PROTOCOL_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/types.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Protocol specification.
 *
 * This is a static datastructure that is initialized by the software using
 * the net2 library.
 */
struct net2_protocol {
	/* Name of the protocol. */
	const char			*name;
	/* Implementation version of the protocol. */
	net2_protocol_t			 version;
	/* List of types in this context. */
	const struct net2_objtype	**types;
	/* Number of types in this context. */
	size_t				 numtypes;

	/* Protocol flags. */
	int				 flags;
#define NET2_CTX_CLUST_SRVR	 0x80000000	/* Server is a cluster. */
#define NET2_CTX_CLUST_CLNT	 0x40000000	/* Client is a cluster. */
#define NET2_CTX_HAS_CLIENT	 0x10000000	/* Client/server cluster. */
#define NET2_CTX_OBJMOVE	 0x00800000	/* Objects may hop nodes. */
};

ILIAS_NET2_EXPORT
const struct net2_objtype	*net2_protocol_type(
				    const struct net2_protocol*, uint32_t);
#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_PROTOCOL_H */
