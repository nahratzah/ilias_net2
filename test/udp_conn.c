#include "testprotocol.h"
#include <ilias/net2/init.h>
#include <ilias/net2/udp_connection.h>
#include <ilias/net2/stream_acceptor.h>
#include <ilias/net2/evbase.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/packet.h>
#include <event2/event.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#ifdef WIN32
#include <WinSock2.h>
#include <io.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#endif

#define DOODLE	"Yankee Doodle sing a song\ndoodaa, doodaa"

static struct net2_buffer*
doodle_buf()
{
	struct net2_buffer	*buf;

	if ((buf = net2_buffer_new()) == NULL)
		return NULL;
	if (net2_buffer_add(buf, DOODLE, strlen(DOODLE)) == -1) {
		net2_buffer_free(buf);
		return NULL;
	}
	return buf;
}

int fail = 0;

int
udp_socketpair(int *fd1, int *fd2, int do_connect)
{
	struct sockaddr_in	sa1, sa2;
	socklen_t		sa1len, sa2len;

	memset(&sa1, 0, sizeof(sa1));
	memset(&sa2, 0, sizeof(sa2));
	sa1.sin_family =      sa2.sin_family =      AF_INET;
	sa1.sin_addr.s_addr = sa2.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa1.sin_port =        sa2.sin_port =        htons(0);

	*fd1 = socket(AF_INET, SOCK_DGRAM, 0);
	*fd2 = socket(AF_INET, SOCK_DGRAM, 0);
	if (*fd1 == -1 || *fd2 == -1) {
		perror("socket");
		goto fail;
	}

	if (bind(*fd1, (struct sockaddr*)&sa1, sizeof(sa1)) ||
	    bind(*fd2, (struct sockaddr*)&sa2, sizeof(sa2))) {
		perror("bind");
		goto fail;
	}

	sa1len = sa2len = sizeof(sa1);
	if (getsockname(*fd1, (struct sockaddr*)&sa1, &sa1len) ||
	    getsockname(*fd2, (struct sockaddr*)&sa2, &sa2len)) {
		perror("getsockname");
		goto fail;
	}

	if (do_connect) {
		if (connect(*fd1, (struct sockaddr*)&sa2, sa2len) ||
		    connect(*fd2, (struct sockaddr*)&sa1, sa1len)) {
			perror("connect");
			goto fail;
		}
	}

	return 0;

fail:
	if (*fd1 != -1)
#ifdef WIN32
		closesocket(*fd1);
#else
		close(*fd1);
#endif
	if (*fd2 != -1)
#ifdef WIN32
		closesocket(*fd2);
#else
		close(*fd2);
#endif
	*fd1 = *fd2 = -1;
	return -1;
}

void
mirror_recv_event(int fd, short what, void *nsa_ptr)
{
	struct net2_stream_acceptor	*nsa = nsa_ptr;
	struct net2_sa_rx		*rx = net2_stream_acceptor_rx(nsa);
	struct net2_sa_tx		*tx = net2_stream_acceptor_tx(nsa);
	struct net2_buffer		*buf;

	/* Bounce input back. */
	if ((buf = net2_sa_rx_read(rx, -1, 0)) == NULL) {
		printf("net2_sa_rx_read(rx, -1, 0) fail");
		exit(-1);
	}
	if (net2_sa_tx_write(tx, buf)) {
		printf("net2_sa_tx_write() fail");
		exit(-1);
	}
	net2_buffer_free(buf);

	/* Close return stream on finishing input stream. */
	if (net2_sa_rx_eof(rx))
		net2_sa_tx_close(tx);
}

int
main()
{
	int			 fd[2];
	struct net2_ctx		*protocol_ctx;
	struct net2_evbase	*evbase;
	struct net2_connection	*c1, *c2;
	struct net2_stream_acceptor
				*sa1, *sa2;
	struct net2_buffer	*sent, *received;

	net2_init();

	if (udp_socketpair(&fd[0], &fd[1], 1)) {
		printf("socketpair fail: %d %s\n", errno, strerror(errno));
		return -1;
	}

	if ((protocol_ctx = test_ctx()) == NULL) {
		printf("test_ctx() fail");
		return -1;
	}
	if ((evbase = net2_evbase_new()) == NULL) {
		printf("net2_evbase_new() fail");
		return -1;
	}

	/* Create connection. */
	c1 = net2_conn_p2p_create_fd(protocol_ctx, evbase, fd[0], NULL, 0);
	c2 = net2_conn_p2p_create_fd(protocol_ctx, evbase, fd[1], NULL, 0);
	if (c1 == NULL || c2 == NULL) {
		printf("net2_conn_p2p_create_fd() fail");
		return -1;
	}

	/* Create stream. */
	sa1 = net2_stream_acceptor_new();
	sa2 = net2_stream_acceptor_new();
	if (sa1 == NULL || sa2 == NULL) {
		printf("net2_stream_acceptor_new() fail");
		return -1;
	}

	/* Turn sa2 into an echo service. */
	{
		struct event		*mirror_ev;
		struct net2_sa_rx	*rx = net2_stream_acceptor_rx(sa2);

		mirror_ev = event_new(evbase->evbase, -1, 0,
		    mirror_recv_event, sa2);
		if (mirror_ev == NULL) {
			printf("event_new fail");
			return -1;
		}

		if (net2_sa_rx_set_event(rx, NET2_SARX_ON_RECV,
		    mirror_ev, NULL) ||
		    net2_sa_rx_set_event(rx, NET2_SARX_ON_FINISH,
		    mirror_ev, NULL)) {
			printf("net2_sa_rx_set_event fail");
			return -1;
		}
	}

	/* Attach stream to connection. */
	if (net2_conn_acceptor_attach(c1, net2_stream_acceptor_reduce(sa1)) ||
	    net2_conn_acceptor_attach(c2, net2_stream_acceptor_reduce(sa2))) {
		printf("net2_conn_acceptor_attach() fail");
		return -1;
	}

	/* Send data into sa1. */
	if ((sent = doodle_buf()) == NULL) {
		printf("doodle_buf() fail");
		return -1;
	}
	net2_sa_tx_write(net2_stream_acceptor_tx(sa1), sent);
	net2_sa_tx_close(net2_stream_acceptor_tx(sa1));

	/* TODO: send data into sa1, read it back, compare. */

	net2_connection_destroy(c1);
	net2_connection_destroy(c2);
	net2_stream_acceptor_destroy(sa1);
	net2_stream_acceptor_destroy(sa2);
	test_ctx_free(protocol_ctx);
	net2_cleanup();

	return fail;
}
