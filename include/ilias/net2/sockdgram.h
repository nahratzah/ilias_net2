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
#ifndef ILIAS_NET2_SOCKDGRAM_H
#define ILIAS_NET2_SOCKDGRAM_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/types.h>

#ifdef WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#endif


#ifdef BUILDING_ILIAS_NET2
struct net2_connection;
struct net2_conn_receive;
struct net2_buffer;

ILIAS_NET2_LOCAL
int	net2_sockdgram_recv(net2_socket_t, int*, struct net2_buffer**,
	    struct sockaddr*, socklen_t*);
ILIAS_NET2_LOCAL
int	net2_sockdgram_send(net2_socket_t,
	    struct net2_buffer*, struct sockaddr*, socklen_t);
ILIAS_NET2_LOCAL
int	net2_sockdgram_nonblock(net2_socket_t);
ILIAS_NET2_LOCAL
int	net2_sockdgram_dnf(net2_socket_t);
#endif /* BUILDING_ILIAS_NET2 */


/* Error codes for net2_sockdgram_send. */
#define NET2_CONNFAIL_OK	0	/* No error. */
#define NET2_CONNFAIL_CLOSE	1	/* Connection destroyed. */
#define NET2_CONNFAIL_TOOBIG	2	/* Datagram was too big. */
#define NET2_CONNFAIL_BAD	3	/* Connection failure. */
#define NET2_CONNFAIL_OS	4	/* OS had insufficient resources. */
#define NET2_CONNFAIL_IO	5	/* IO error occured. */
#define NET2_CONNFAIL_RESOURCE	6	/* Out of memory. */


#endif /* ILIAS_NET2_SOCKDGRAM_H */
