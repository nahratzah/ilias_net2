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
#include <ilias/net2/promise.h>
#include <sys/types.h>
#include <stdint.h>

#include <ilias/net2/config.h>
#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <ilias/net2/bsd_compat/queue.h>
#endif

ILIAS_NET2__begin_cdecl


struct net2_connection;			/* From ilias/net2/connection.h */
struct net2_buffer;			/* From ilias/net2/buffer.h */
struct encoded_header;			/* Internal. */
struct net2_conn_negotiator_set;	/* Internal. */
struct net2_tx_callback;		/* From ilias/net2/tx_callback.h */
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

	struct net2_pvlist	 proto;		/* Protocol versions. */

	struct net2_ctx		*context;	/* Network metadata. */

	int			 recv_no_send;	/* Set each time a packet is
						 * received, cleared each time
						 * a packet is sent. */

	struct net2_cneg_stage1	*stage1;	/* First stage negotiation. */
	struct net2_cneg_key_xchange
				*keyx;		/* Key xchange stage. */

	struct net2_promise	*hash,		/* Supported hashes. */
				*enc,		/* Supported encoders. */
				*xchange,	/* Supported xchange. */
				*sign;		/* Supported sign. */
	struct net2_promise_event kx_event;	/* Handle key xchange. */
	struct net2_promise_event pver_event;	/* Handle pver information. */
};

#ifdef BUILDING_ILIAS_NET2

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

#endif /* BUILDING_ILIAS_NET2 */


ILIAS_NET2__end_cdecl
#endif /* ILIAS_NET2_CONN_NEGOTIATOR_H */
