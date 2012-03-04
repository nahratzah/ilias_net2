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
#ifndef ILIAS_NET2_CONN_NEGOTIATOR_H
#define ILIAS_NET2_CONN_NEGOTIATOR_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/types.h>
#include <ilias/net2/protocol.h>
#include <ilias/net2/bitset.h>
#include <ilias/net2/signset.h>
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
struct net2_tx_callback;		/* From ilias/net2/tx_callback.h */
struct net2_promise;			/* From ilias/net2/promise.h */
struct packet_header;			/* From ilias/net2/packet.h */

/*
 * Connection negotiator module.
 *
 * Performs negotiation of protocols, security properties.
 */
struct net2_conn_negotiator {
	int			 flags;		/* Want options. */
	int			 flags_have;	/* Have options. */
#define NET2_CNEG_REQUIRE_ENCRYPTION	0x00000001
#define NET2_CNEG_REQUIRE_SIGNING	0x00000002

	int			 stage;		/* DFA stage. */
#define NET2_CNEG_STAGE_PRISTINE	0x00000000	/* No work done. */
#define NET2_CNEG_STAGE_KEY_EXCHANGE	0x00000001	/* Exchanging keys. */
#define NET2_CNEG_STAGE_PROTO_IDLE	0xffffffff	/* Nothing to do. */

	int			 pver_acknowledged;
						/* True iff pver was received
						 * by remote endpoint. */
	struct net2_ctx		*context;	/* Network metadata. */

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

	struct {
		int		*supported;	/* Algorithm set. */
		size_t		 num_supported;	/* # supported. */
	}			 hash,		/* Supported hashes. */
				 enc,		/* Supported encoders. */
				 xchange,	/* Supported xchange. */
				 sign;		/* Supported sign. */
	struct net2_signset	 remote_signs;	/* Known remote signatures. */

	struct {
		struct net2_sign_ctx
				**signatures;	/* Signatures. */
		size_t		 size;		/* Signature count. */
	}			 signature_list; /* Signatures that must be
						  * used to sign messages.
						  * Order is significant and
						  * decided by remote host. */

	struct {
/* Stage 2 exchange codes. */
#define NET2_CNEG_S2_HASH	0	/* Hash key negotiation. */
#define NET2_CNEG_S2_ENC	2	/* Enc key negotiation. */
#define NET2_CNEG_S2_REMOTE	1	/* Or-ed with above for remote
					 * counterpart. */
#define NET2_CNEG_S2_LOCAL	0	/* Or-ed with above for local
					 * counterpart. */
#define NET2_CNEG_S2_MAX	4	/* Number of stage 2 exchanges. */
		struct net2_cneg_exchange
				*xchanges; /* Contexts. */
	}			 stage2;
};

/*
 * Connection negotiator is responsible for negotiating the security keys.
 *
 * Two security keys are defined: message hash and message encryption.
 * Each sending side has its own keys.
 */
struct net2_cneg_keys {
	struct {
		int		 algorithm;	/* Hash/enc algorithm. */
		const void	*key;		/* Key. */
		size_t		 keylen;	/* Length of key. */
		int		 allow_insecure; /* Iff set, received data
						  * does not need enc/hash. */
	}			 hash,		/* Message hash key. */
				 enc;		/* Message enc key. */
};


ILIAS_NET2_LOCAL
int	 net2_cneg_rxkeys(struct net2_cneg_keys*, struct net2_conn_negotiator*,
	    struct packet_header*);
ILIAS_NET2_LOCAL
int	 net2_cneg_txkeys(struct net2_cneg_keys*, struct net2_conn_negotiator*,
	    struct packet_header*);

ILIAS_NET2_LOCAL
int	net2_cneg_allow_payload(struct net2_conn_negotiator*, uint32_t);
ILIAS_NET2_LOCAL
int	net2_cneg_init(struct net2_conn_negotiator*, struct net2_ctx*);
ILIAS_NET2_LOCAL
void	net2_cneg_deinit(struct net2_conn_negotiator*);
ILIAS_NET2_LOCAL
int	net2_cneg_get_transmit(struct net2_conn_negotiator*,
	    struct packet_header*, struct net2_buffer**,
	    struct net2_tx_callback*, size_t, int, int);
ILIAS_NET2_LOCAL
int	net2_cneg_accept(struct net2_conn_negotiator*, struct packet_header*,
	    struct net2_buffer*);
ILIAS_NET2_LOCAL
int	net2_cneg_pvlist(struct net2_conn_negotiator*, struct net2_pvlist*);

#endif /* ILIAS_NET2_CONN_NEGOTIATOR_H */
