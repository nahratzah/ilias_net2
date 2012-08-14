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
#include "test.h"
#include "testprotocol.h"
#include <ilias/net2/init.h>
#include <ilias/net2/udp_connection.h>
#include <ilias/net2/workq.h>
#include <ilias/net2/stream_acceptor.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/bsd_compat/secure_random.h>
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

#define DOODLE	"Yankee Doodle sing a song\ndoodaa, doodaa\n"

static struct net2_buffer*
doodle_buf()
{
	struct net2_buffer	*buf, *tmp;

	tmp = NULL;
	if ((buf = net2_buffer_new()) == NULL)
		goto fail;

	/* Doodle buf. */
	do {
		if (net2_buffer_add(buf, DOODLE, strlen(DOODLE) + 1) == -1)
			goto fail;
	} while (net2_buffer_length(buf) < 64 * 1024);

	/* Result: repeat doodle until we reach 100 MB. */
	while (net2_buffer_length(buf) < 100 * 1024 * 1024) {
		printf("doodle: %lu bytes\n",
		    (unsigned long)net2_buffer_length(buf));

		if ((tmp = net2_buffer_copy(buf)) == NULL ||
		    net2_buffer_append(buf, tmp))
			goto fail;
		net2_buffer_free(tmp);
		tmp = NULL;
	}

	printf("doodle complete: %lu bytes\n",
	    (unsigned long)net2_buffer_length(buf));
	return buf;

fail:
	net2_buffer_free(buf);
	net2_buffer_free(tmp);
	return NULL;
}

int fail = 0;
volatile int detached = 0;
volatile int finished = 0;
volatile int recv_finished = 0;
volatile int sa1_recv_finished = 0;

void
detach_flag(void *unused0, void *unused1)
{
	printf("event: detached\n");
	detached = 1;
}
void
finish_flag(void *unused0, void *unused1)
{
	printf("event: finished\n");
	finished = 1;
}
void
recv_finish_flag(void *unused0, void *unused1)
{
	printf("event: finish_flag\n");
	recv_finished = 1;
}
void
sa1_recv_finish_flag(void *unused0, void *unused1)
{
	printf("event: sa1_recv_finish_flag\n");
	sa1_recv_finished = 1;
}

void
mirror_recv_event(void *nsa_ptr, void *unused)
{
	struct net2_stream_acceptor	*nsa = nsa_ptr;
	struct net2_sa_rx		*rx = net2_stream_acceptor_rx(nsa);
	struct net2_sa_tx		*tx = net2_stream_acceptor_tx(nsa);
	struct net2_buffer		*buf;

	/* Bounce input back. */
	if ((buf = net2_sa_rx_read(rx, -1, 0)) == NULL) {
		printf("net2_sa_rx_read(rx, -1, 0) fail\n");
		exit(-1);
	}
#if 0
	printf("received %lu bytes\n", (unsigned long)net2_buffer_length(buf));
#endif
	if (net2_sa_tx_write(tx, buf)) {
		printf("net2_sa_tx_write() fail\n");
		exit(-1);
	}
	net2_buffer_free(buf);

	/* Close return stream on finishing input stream. */
	if (net2_sa_rx_eof(rx))
		net2_sa_tx_close(tx);
}

int
udp_socketpair(net2_socket_t *fd1, net2_socket_t *fd2, int do_connect)
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
#ifdef WIN32
		fprintf(stderr, "socket wsa error %d\n", WSAGetLastError());
#else
		perror("socket");
#endif
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

int
main()
{
	net2_socket_t		 fd[2];
	struct net2_ctx		*protocol_ctx;
	struct net2_workq_evbase*evbase;
	struct net2_connection	*c1, *c2;
	struct net2_stream_acceptor
				*sa1, *sa2;
	struct net2_buffer	*sent, *received;
	struct net2_promise_event
				 sa1_rx_fin, sa1_tx_fin,
				 sa2_rx_fin, sa2_tx_fin;

	test_start();

	/* Initialize network. */
	net2_init();

	if (udp_socketpair(&fd[0], &fd[1], 1)) {
		printf("socketpair fail: %d %s\n", errno, strerror(errno));
		return -1;
	} else {
#ifdef WIN32
		printf("socketpair (udp loopback) { %p, %p }\n",
		    (void*)fd[0], (void*)fd[1]);
#else
		printf("socketpair (udp loopback) { %d, %d }\n",
		    fd[0], fd[1]);
#endif
	}

	if ((protocol_ctx = test_ctx()) == NULL) {
		printf("test_ctx() fail\n");
		return -1;
	}
	if ((evbase = net2_workq_evbase_new("udp evbase", 2, 2)) == NULL) {
		printf("net2_evbase_new() fail\n");
		return -1;
	}

	/* Create connection. */
	c1 = net2_conn_p2p_create_fd(protocol_ctx, evbase, fd[0], NULL, 0);
	c2 = net2_conn_p2p_create_fd(protocol_ctx, evbase, fd[1], NULL, 0);
	if (c1 == NULL || c2 == NULL) {
		printf("net2_conn_p2p_create_fd() fail\n");
		return -1;
	}
	net2_workq_evbase_release(evbase);
	evbase = NULL;

	/* Create stream. */
	sa1 = net2_stream_acceptor_new();
	sa2 = net2_stream_acceptor_new();
	if (sa1 == NULL || sa2 == NULL) {
		printf("net2_stream_acceptor_new() fail\n");
		return -1;
	}

	/* Turn sa2 into an echo service. */
	{
		struct net2_workq	*wq = net2_acceptor_socket_workq(
					    &c2->n2c_socket);
		struct net2_sa_rx	*rx = net2_stream_acceptor_rx(sa2);
		struct net2_sa_tx	*tx = net2_stream_acceptor_tx(sa2);
		struct net2_promise	*rx_fin = net2_sa_rx_get_fin(rx);
		struct net2_promise	*tx_fin = net2_sa_tx_get_fin(tx);

		if (net2_sa_rx_set_event(rx, NET2_SARX_ON_RECV, wq,
		    &mirror_recv_event, sa2, NULL)) {
			printf("net2_sa_rx_set_event fail\n");
			return -1;
		}
		if (net2_promise_event_init(&sa2_rx_fin, rx_fin,
		    NET2_PROM_ON_FINISH, wq,
		    &mirror_recv_event, sa2, NULL)) {
			printf("net2_sa_rx_fin promise event fail\n");
			return -1;
		}
		if (net2_promise_event_init(&sa2_rx_fin, tx_fin,
		    NET2_PROM_ON_FINISH, wq,
		    &recv_finish_flag, NULL, NULL)) {
			printf("net2_sa_tx_fin promise event fail\n");
			return -1;
		}
		net2_promise_release(rx_fin);
		net2_promise_release(tx_fin);
	}

	/* Set up the finish and detach events for sa1. */
	{
		struct net2_workq	*wq = net2_acceptor_socket_workq(
					    &c1->n2c_socket);
		struct net2_sa_tx	*tx = net2_stream_acceptor_tx(sa1);
		struct net2_sa_rx	*rx = net2_stream_acceptor_rx(sa1);
		struct net2_promise	*rx_fin = net2_sa_rx_get_fin(rx);
		struct net2_promise	*tx_fin = net2_sa_tx_get_fin(tx);

		if (net2_promise_event_init(&sa1_tx_fin, tx_fin,
		    NET2_PROM_ON_FINISH, wq,
		    &finish_flag, NULL, NULL)) {
			printf("net2_sa_tx_fin promise event fail\n");
			return -1;
		}
		if (net2_promise_event_init(&sa1_rx_fin, rx_fin,
		    NET2_PROM_ON_FINISH, wq,
		    &sa1_recv_finish_flag, NULL, NULL)) {
			printf("net2_sa_rx_fin promise event fail\n");
			return -1;
		}
		net2_promise_release(rx_fin);
		net2_promise_release(tx_fin);
	}

	/* Attach stream to connection. */
	if (net2_acceptor_attach(&c1->n2c_socket,
	    net2_stream_acceptor_reduce(sa1)) ||
	    net2_acceptor_attach(&c2->n2c_socket,
	    net2_stream_acceptor_reduce(sa2))) {
		printf("net2_acceptor_attach() fail\n");
		return -1;
	}

	/* Send data into sa1. */
	if ((sent = doodle_buf()) == NULL) {
		printf("doodle_buf() fail\n");
		return -1;
	}
	net2_sa_tx_write(net2_stream_acceptor_tx(sa1), sent);
	net2_sa_tx_close(net2_stream_acceptor_tx(sa1));

	/*
	 * We need to wait until both the transmitter and
	 * receiver have completed.
	 */
	while (!finished || !recv_finished || !sa1_recv_finished) {
		/* Check why the eventloop ended. */
		if (finished == 1) {
			printf("\tprocessing finished\n");
			finished = 2;		/* Only print once. */
		}
		if (recv_finished == 1) {
			printf("\tsa2 finished\n");
			recv_finished = 2;	/* Only print once. */
		}
		if (detached == 1) {
			printf("\tFAIL: connection detached stream_acceptor\n");
			fail++;
			detached = 2;		/* Only print once. */
			return -1;
		}
		if (sa1_recv_finished == 1) {
			printf("\tsa1 receiver finished\n");
			sa1_recv_finished = 2;	/* Only print once. */
		}
	}

	/* TODO: read data from sa1 */
	received = net2_sa_rx_read(net2_stream_acceptor_rx(sa1), -1, 0);
	if (!net2_sa_rx_eof(net2_stream_acceptor_rx(sa1))) {
		printf("receiver has not received eof\n");
		fail++;
	}

	/* TODO: compare data from sa1 */
	if (net2_buffer_cmp(sent, received) != 0) {
		printf("sent and received data differ\n");
		fail++;
	}

	/* Dump C1 stats. */
	printf("%2s: Sent:     %16llu bytes in %12llu packets\n"
	    "    Received: %16llu bytes in %12llu packets\n",
	    "C1",
	    c1->n2c_stats.tx_bytes, c1->n2c_stats.tx_packets,
	    c1->n2c_stats.rx_bytes, c1->n2c_stats.rx_packets);
	/* Dump C2 stats. */
	printf("%2s: Sent:     %16llu bytes in %12llu packets\n"
	    "    Received: %16llu bytes in %12llu packets\n",
	    "C2",
	    c2->n2c_stats.tx_bytes, c2->n2c_stats.tx_packets,
	    c2->n2c_stats.rx_bytes, c2->n2c_stats.rx_packets);

	net2_promise_event_deinit(&sa1_rx_fin);
	net2_promise_event_deinit(&sa1_tx_fin);
	net2_promise_event_deinit(&sa2_rx_fin);
	net2_promise_event_deinit(&sa2_tx_fin);
	net2_buffer_free(sent);
	net2_buffer_free(received);
	net2_connection_destroy(c1);
	net2_connection_destroy(c2);
	net2_stream_acceptor_destroy(sa1);
	net2_stream_acceptor_destroy(sa2);

	test_ctx_free(protocol_ctx);
	net2_cleanup();

	test_fini();
	return fail;
}
