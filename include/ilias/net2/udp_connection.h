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
#ifndef ILIAS_NET2_UDP_CONNECTION_H
#define ILIAS_NET2_UDP_CONNECTION_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/connection.h>
#include <sys/types.h>
#ifdef WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <sys/socket.h>
#endif
#include <event2/util.h>

struct net2_udpsocket;

ILIAS_NET2_EXPORT
struct net2_connection	*net2_conn_p2p_create_fd(struct net2_ctx*,
			    struct net2_evbase*, evutil_socket_t,
			    struct sockaddr*, socklen_t);
ILIAS_NET2_EXPORT
struct net2_connection	*net2_conn_p2p_create(struct net2_ctx*,
			    struct net2_evbase*, struct net2_udpsocket*,
			    struct sockaddr*, socklen_t);
ILIAS_NET2_EXPORT
struct net2_udpsocket	*net2_conn_p2p_socket(struct net2_evbase *ev,
			    struct sockaddr*, socklen_t);
ILIAS_NET2_EXPORT
void			 net2_conn_p2p_socket_ref(struct net2_udpsocket*);
ILIAS_NET2_EXPORT
void			 net2_conn_p2p_socket_release(struct net2_udpsocket*);

#endif /* ILIAS_NET2_UDP_CONNECTION_H */
