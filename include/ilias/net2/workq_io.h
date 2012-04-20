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
#include <ev.h>

#ifdef WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <ilias/net2/bsd_compat/queue.h>
#endif

/* Received data. */
struct net2_dgram {
	struct sockaddr_storage
			 addr;
	socklen_t	 addrlen;
	int		 error;
	struct net2_buffer
			*data;

	TAILQ_ENTRY(net2_dgram)
			 bufq;
};

typedef void (*net2_workq_io_recv)(void*, struct net2_dgram*);
typedef void (*net2_workq_io_send)(void*, void*);

/* Datagram event. */
struct net2_workq_dgram {
	struct net2_workq_job
			 job;		/* Base job implementation. */
	ev_io		 watcher;	/* Watcher implementation. */
	net2_workq_io_recv
			 recv;		/* External callback. */
	net2_workq_io_send
			 send;		/* External callback. */

	struct net2_mutex
			*bufmtx;	/* Protect buffers. */
	TAILQ_HEAD(, net2_dgram)
			 buffers;
	size_t		 buflen;	/* # buffers. */

	struct ev_loop	*loop;
};

ILIAS_NET2_EXPORT
int	net2_workq_dgram_init(struct net2_workq_dgram*, int,
	    struct net2_workq*, net2_workq_io_recv, net2_workq_io_send,
	    void*);
ILIAS_NET2_EXPORT
void	net2_workq_dgram_deinit(struct net2_workq_dgram*);

#endif /* ILIAS_NET2_WORKQ_IO_H */
