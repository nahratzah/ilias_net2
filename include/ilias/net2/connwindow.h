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
#ifndef ILIAS_NET2_CONNWINDOW_H
#define ILIAS_NET2_CONNWINDOW_H

#include <ilias/net2/ilias_net2_export.h>
#include <sys/types.h>
#include <stdint.h>

#include <bsd_compat/bsd_compat.h>
#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <bsd_compat/queue.h>
#endif
#ifdef HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include <bsd_compat/tree.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Recommended minimum space for connwindow data. */
extern ILIAS_NET2_LOCAL const size_t net2_connwindow_overhead;
/* Minimum window size that is able to make progress. */
extern ILIAS_NET2_LOCAL const size_t net2_connwindow_min_overhead;

/*
 * Connection window delivery callback.
 */
typedef void (*net2_connwindow_cb)(void*, void*);

/*
 * Actual connection window.
 *
 * Each transmitted packet will be decorated using a transmission ID.
 * If the window runs out of space, it will generate short, empty packets,
 * containing only window updates and a request for confirmation.
 * When this happens, the transmission is considered stalled.
 *
 * When a transmission becomes stalled, it will start to time out,
 * damocles will kill it if it the remote host does not advance the
 * window state.
 */
struct net2_connwindow {
	struct net2_connection
			*cw_conn;		/* Connection. */

	uint32_t	 cw_tx_start;		/* Start of tx window. */
	uint32_t	 cw_tx_nextseq;		/* Next sequence ID. */
	uint32_t	 cw_tx_windowsz;	/* Size of the tx window. */
	uint32_t	 cw_tx_ssthresh;	/* ssthresh in tcp. */
	uint32_t	 cw_rx_start;		/* Start of rx window. */
	uint32_t	 cw_rx_windowsz;	/* Size of the rx window. */
	uint32_t	 cw_rx_nextrecv;	/* First seq not in cw_tx_id. */

	size_t		 cw_tx_count;		/* Number of entries on tx. */
	TAILQ_HEAD(, net2_cw_tx)
			 cw_tx_bad;		/* Bad transmit queue. */
	RB_HEAD(net2_cw_transmits, net2_cw_tx)
			 cw_tx_id;		/* Transmit ID list. */

	TAILQ_HEAD(, net2_cw_rx)
			 cw_rx_wantack;		/* Receive queue, want ack. */
	RB_HEAD(net2_cw_recvs, net2_cw_rx)
			 cw_rx_id;		/* Receives per ID. */

	struct event	*cw_stallbackoff;	/* Stall backoff event. */
	struct event	*cw_keepalive;		/* Keepalive timer. */
	int		 cw_flags;		/* Connection window state. */
#define NET2_CW_F_WANTRECV	0x00000001	/* Need to recv 1st packet. */
#define NET2_CW_F_STALLED	0x00000002	/* Damocles pending. */
#define NET2_CW_F_STALLBACKOFF	0x00000004	/* Don't send stalled. */
#define NET2_CW_F_KEEPALIVE	0x00000008	/* Keepalive timer ticking. */
};


#ifdef BUILDING_ILIAS_NET2
struct packet_header;
struct net2_buffer;

ILIAS_NET2_LOCAL
int			 net2_connwindow_init(struct net2_connwindow*,
			    struct net2_connection*);
ILIAS_NET2_LOCAL
void			 net2_connwindow_deinit(struct net2_connwindow*);
ILIAS_NET2_LOCAL
int			 net2_connwindow_accept(const struct net2_connwindow*,
			    struct packet_header*);
ILIAS_NET2_LOCAL
int			 net2_connwindow_update(struct net2_connwindow*,
			    struct packet_header*, struct net2_buffer*,
			    size_t);
ILIAS_NET2_LOCAL
struct net2_buffer	*net2_connwindow_writebuf(struct net2_connwindow*,
			    struct packet_header*, size_t);

ILIAS_NET2_LOCAL
struct net2_cw_tx	*net2_connwindow_tx_prepare(struct net2_connwindow*,
			    struct packet_header*, int*);
ILIAS_NET2_LOCAL
void			 net2_connwindow_tx_commit(struct net2_cw_tx*,
			    struct packet_header*, size_t);
ILIAS_NET2_LOCAL
void			 net2_connwindow_tx_rollback(struct net2_cw_tx*);
#endif /* BUILDING_ILIAS_NET2 */


struct net2_evbase;

ILIAS_NET2_EXPORT
int			 net2_connwindow_txcb_register(struct net2_cw_tx*,
			    struct net2_evbase*,
			    net2_connwindow_cb, net2_connwindow_cb,
			    net2_connwindow_cb, net2_connwindow_cb,
			    void*, void*);

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_CONNWINDOW_H */
