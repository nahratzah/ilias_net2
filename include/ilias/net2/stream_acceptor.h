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
#ifndef ILIAS_NET2_STREAM_ACCEPTOR_H
#define ILIAS_NET2_STREAM_ACCEPTOR_H


#include <ilias/net2/ilias_net2_export.h>
#include <sys/types.h>
#include <stdint.h>

/*
 * The stream acceptor.
 *
 * Converts the underlying connection into a stream.
 * This is a conn_acceptor.
 */
struct net2_stream_acceptor;

/*
 * Stream transmission side.
 */
struct net2_sa_tx;

/*
 * net2_sa_tx events.
 *
 * ON_FINISH will be called when
 * all data and the close event have been acknowledged.
 *
 * ON_DETACH will be called when the net2_sa_tx is detached
 * from the connection.
 *
 * LOWBUFFER will be called each time the transmit buffer drops
 * below the low water mark since the last write.
 */
#define NET2_SATX_ON_FINISH	0	/* Transmission complete. */
#define NET2_SATX_ON_DETACH	1	/* Connection detached. */
#define NET2_SATX_ON_LOWBUFFER	2	/* Buffer crossed low-water mark. */
#define NET2_SATX__NUM_EVENTS	3	/* Number of events. */

/*
 * Stream receive side.
 */
struct net2_sa_rx;

/*
 * net2_sa_rx events.
 *
 * ON_RECV will be called when data has been received since the last read.
 *
 * ON_FINISH will be called once all data has been received and the remote
 * end closed the stream.
 */
#define NET2_SARX_ON_FINISH	0	/* Transmission complete. */
#define NET2_SARX_ON_DETACH	1	/* Connection detached. */
#define NET2_SARX_ON_RECV	2	/* New data received. */
#define NET2_SARX__NUM_EVENTS	3	/* Number of events. */


/* Cast stream acceptor to conn acceptor. */
static __inline struct net2_conn_acceptor*
net2_stream_acceptor_reduce(struct net2_stream_acceptor *nsa)
{
	return (struct net2_conn_acceptor*)nsa;
}


struct net2_buffer;	/* from ilias/net2/buffer.h */
struct event;		/* from event2/event.h */

ILIAS_NET2_EXPORT
struct net2_stream_acceptor
			*net2_stream_acceptor_new();
ILIAS_NET2_EXPORT
void			 net2_stream_acceptor_destroy(
			    struct net2_stream_acceptor*);

ILIAS_NET2_EXPORT
struct net2_sa_tx	*net2_stream_acceptor_tx(struct net2_stream_acceptor*);
ILIAS_NET2_EXPORT
struct net2_sa_rx	*net2_stream_acceptor_rx(struct net2_stream_acceptor*);

ILIAS_NET2_EXPORT
int			 net2_sa_tx_write(struct net2_sa_tx*,
			    const struct net2_buffer*);
ILIAS_NET2_EXPORT
void			 net2_sa_tx_close(struct net2_sa_tx*);
ILIAS_NET2_EXPORT
int			 net2_sa_tx_isclosed(struct net2_sa_tx*);
ILIAS_NET2_EXPORT
int			 net2_sa_tx_uptodate(struct net2_sa_tx*);

ILIAS_NET2_EXPORT
size_t			 net2_sa_tx_get_lowwatermark(struct net2_sa_tx*);
ILIAS_NET2_EXPORT
size_t			 net2_sa_tx_set_lowwatermark(struct net2_sa_tx*,
			    size_t);

ILIAS_NET2_EXPORT
struct net2_buffer	*net2_sa_rx_read(struct net2_sa_rx*, size_t, int);
#define NET2_SARX_READ_ALL	0x00000001	/* Read all data. */
#define NET2_SARX_PEEK		0x00000002	/* Peek at data. */
ILIAS_NET2_EXPORT
size_t			 net2_sa_rx_avail(struct net2_sa_rx*);
ILIAS_NET2_EXPORT
int			 net2_sa_rx_eof(struct net2_sa_rx*);
ILIAS_NET2_EXPORT
int			 net2_sa_rx_eof_pending(struct net2_sa_rx*);


ILIAS_NET2_EXPORT
int			 net2_sa_tx_set_event(struct net2_sa_tx*, int,
			    struct event*, struct event**);
ILIAS_NET2_EXPORT
struct event		*net2_sa_tx_get_event(struct net2_sa_tx*, int);

ILIAS_NET2_EXPORT
int			 net2_sa_rx_set_event(struct net2_sa_rx*, int,
			    struct event*, struct event**);
ILIAS_NET2_EXPORT
struct event		*net2_sa_rx_get_event(struct net2_sa_rx*, int);

#endif /* ILIAS_NET2_STREAM_ACCEPTOR_H */
