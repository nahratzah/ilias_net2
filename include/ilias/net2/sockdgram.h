#ifndef ILIAS_NET2_SOCKDGRAM_H
#define ILIAS_NET2_SOCKDGRAM_H

#include <ilias/net2/ilias_net2_export.h>

#ifdef WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#endif


#ifdef ilias_net2_EXPORTS
struct net2_connection;
struct net2_conn_receive;
struct net2_buffer;

ILIAS_NET2_LOCAL
int	net2_sockdgram_recv(int, struct net2_conn_receive**,
	    struct sockaddr*, socklen_t*);
ILIAS_NET2_LOCAL
int	net2_sockdgram_send(int, struct net2_connection*,
	    struct net2_buffer*, struct sockaddr*, socklen_t);
ILIAS_NET2_LOCAL
int	net2_sockdgram_nonblock(int);
#endif /* ilias_net2_EXPORTS */


/* Error codes for net2_sockdgram_send. */
#define NET2_CONNFAIL_OK	0	/* No error. */
#define NET2_CONNFAIL_CLOSE	1	/* Connection destroyed. */
#define NET2_CONNFAIL_TOOBIG	2	/* Datagram was too big. */
#define NET2_CONNFAIL_BAD	3	/* Connection failure. */
#define NET2_CONNFAIL_OS	4	/* OS had insufficient resources. */
#define NET2_CONNFAIL_IO	5	/* IO error occured. */
#define NET2_CONNFAIL_RESOURCE	6	/* Out of memory. */


#endif /* ILIAS_NET2_SOCKDGRAM_H */
