#ifndef ILIAS_NET2_CONN_NEGOTIATOR_H
#define ILIAS_NET2_CONN_NEGOTIATOR_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/types.h>
#include <ilias/net2/protocol.h>
#include <ilias/net2/bitset.h>
#include <sys/types.h>
#include <stdint.h>

#include <bsd_compat/bsd_compat.h>
#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <bsd_compat/queue.h>
#endif

struct net2_connection;			/* From ilias/net2/connection.h */
struct net2_buffer;			/* From ilias/net2/buffer.h */
struct encoded_header;			/* Internal. */
struct net2_conn_negotiator_set;	/* Internal. */
struct net2_cw_tx;			/* From ilias/net2/connwindow.h */

/*
 * Connection negotiator module.
 *
 * Performs negotiation of protocols, security properties.
 */
struct net2_conn_negotiator {
	int			 flags;		/* Want options. */
	int			 flags_have;	/* Have options. */
#define REQUIRE_ENCRYPTION	0x00000001
#define REQUIRE_SIGNING		0x00000002

	int			 stage;		/* DFA stage. */
#define STAGE_PRISTINE		0x00000000	/* No work done. */
#define STAGE_PROTO_FIXATED	0x00000001	/* Nothing to do. */

	TAILQ_HEAD(, encoded_header)
				 sendq, waitq;

	struct {
		struct net2_pvlist
				 proto;

		size_t		 sets_expected;	/* Expected sets_count. */
		size_t		 sets_count;	/* Number of collections. */
		struct net2_conn_negotiator_set
				*sets;		/* Collections. */

		struct net2_bitset
				 received;	/* Received commands. */
		size_t		 rcv_expected;	/* Expected received size. */
		int		 flags;		/* Negotiated flags. */
	}			 negotiated;	/* Negotiated settings. */
};


ILIAS_NET2_LOCAL
int	net2_cneg_allow_payload(struct net2_conn_negotiator*, uint32_t);
ILIAS_NET2_LOCAL
int	net2_cneg_init(struct net2_conn_negotiator*);
ILIAS_NET2_LOCAL
void	net2_cneg_deinit(struct net2_conn_negotiator*);
ILIAS_NET2_LOCAL
int	net2_cneg_get_transmit(struct net2_conn_negotiator*, struct net2_buffer**,
	    struct net2_cw_tx*, size_t);
ILIAS_NET2_LOCAL
int	net2_cneg_accept(struct net2_conn_negotiator*, struct net2_buffer*);

#endif /* ILIAS_NET2_CONN_NEGOTIATOR_H */
