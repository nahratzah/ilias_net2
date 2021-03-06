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
#ifndef ILIAS_NET2_WORKQ_IO_H
#define ILIAS_NET2_WORKQ_IO_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/config.h>
#include <ilias/net2/workq.h>
#include <ilias/net2/types.h>
#include <sys/types.h>
#include <stdint.h>

#ifdef WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#endif

ILIAS_NET2__begin_cdecl


#define NET2_WORKQ_IO_MAXLEN	((size_t)64 * 1024)

/* Received data. */
struct net2_dgram_rx {
	struct sockaddr_storage	 addr;		/* Origin address. */
	socklen_t		 addrlen;

	int			 error;		/* Received error. */
	struct net2_buffer	*data;		/* Received data. */
};

/*
 * Transmit data promise.
 *
 * tx_promise: will be filled in with net2_dgram_tx_promdata.
 * - if the promise completes with FIN_OK, it will contain the data
 *   that is to be transmitted.
 * - if the promise fails or is canceled, no data will be transmitted.
 * - when the sender is destroyed, the outstanding promises will have
 *   cancel_req set.
 */
struct net2_dgram_tx_promdata {
	struct sockaddr_storage	 addr;		/* Destination address. */
	socklen_t		 addrlen;

	struct net2_buffer	*data;		/* Data to transmit. */
	struct net2_promise	*tx_done;	/* Optional: tx done event. */
};

/* Invoked for a received packet. */
typedef void (*net2_workq_io_recv)(void*, struct net2_dgram_rx*);

/* Datagram event. */
struct net2_workq_io;

ILIAS_NET2_EXPORT
struct net2_workq_io
	*net2_workq_io_new(struct net2_workq*, net2_socket_t);
ILIAS_NET2_EXPORT
void	 net2_workq_io_destroy(struct net2_workq_io*);
ILIAS_NET2_EXPORT
void	 net2_workq_io_activate_rx(struct net2_workq_io*);
ILIAS_NET2_EXPORT
void	 net2_workq_io_deactivate_rx(struct net2_workq_io*);
ILIAS_NET2_EXPORT
int	 net2_workq_io_tx(struct net2_workq_io*, struct net2_promise*);

ILIAS_NET2_EXPORT
void	 net2_workq_io_tx_pdata_free(void*, void*);

ILIAS_NET2_EXPORT
struct net2_datapipe_in*
	 net2_workq_io_txpipe(struct net2_workq_io *io);
ILIAS_NET2_EXPORT
struct net2_datapipe_out*
	 net2_workq_io_rxpipe(struct net2_workq_io *io);

/* Max number of unprocessed input buffers. */
#define MAX_RX		128
/* Max number of outstanding tx promises. */
#define MAX_TX		128

#ifdef WIN32
struct net2_workq_io_container;

ILIAS_NET2_LOCAL
struct net2_workq_io_container
	 *net2_workq_io_container_new();
ILIAS_NET2_LOCAL
void	 net2_workq_io_container_destroy(struct net2_workq_io_container*);
#endif /* WIN32 */


ILIAS_NET2__end_cdecl
#endif /* ILIAS_NET2_WORKQ_IO_H */
