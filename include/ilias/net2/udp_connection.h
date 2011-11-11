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

struct net2_udpsocket;

ILIAS_NET2_EXPORT
struct net2_connection	*net2_conn_p2p_create_fd(struct net2_ctx*,
			    struct net2_evbase*, int,
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
