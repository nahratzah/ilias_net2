#ifndef ILIAS_NET2_CONTEXT_H
#define ILIAS_NET2_CONTEXT_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/types.h>
#include <sys/types.h>

#include <bsd_compat/bsd_compat.h>
#ifdef HAS_QUEUE
#include <sys/queue.h>
#else
#include <bsd_compat/queue.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Network context.
 *
 * Network context setup happens before connections are built.
 * The network context module is not thread-safe.
 *
 * For each protocol, exactly one instance of net2_ctx is required.
 */
struct net2_ctx {
	/** Protocol in use. */
	const struct net2_protocol	*protocol;
	/* Protocol implementation version. */
	net2_protocol_t			 version;
#define NET2_CTX_NEGOTIATE		 0xffffffff
	/* All connections in the same cluster. */
	TAILQ_HEAD(, net2_connection)	 conn;
};

ILIAS_NET2_EXPORT
void			 net2_ctx_init(struct net2_ctx*,
			    const struct net2_protocol*);
ILIAS_NET2_EXPORT
void			 net2_ctx_destroy(struct net2_ctx*);

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_CONTEXT_H */
