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
#include "testprotocol.h"
#include <ilias/net2/init.h>
#include <ilias/net2/udp_connection.h>
#include <ilias/net2/stream_acceptor.h>
#include <ilias/net2/evbase.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/packet.h>
#include <bsd_compat/secure_random.h>
#include <event2/event.h>
#include <event2/thread.h>
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
detach_flag(int fd, short what, void *base_ptr)
{
	struct net2_evbase	*base = base_ptr;

	printf("event: detached\n");
	detached = 1;
	event_base_loopbreak(base->evbase);
}
void
finish_flag(int fd, short what, void *base_ptr)
{
	struct net2_evbase	*base = base_ptr;

	printf("event: finished\n");
	finished = 1;
	event_base_loopbreak(base->evbase);
}
void
recv_finish_flag(int fd, short what, void *base_ptr)
{
	struct net2_evbase	*base = base_ptr;

	printf("event: finish_flag\n");
	recv_finished = 1;
	event_base_loopbreak(base->evbase);
}
void
sa1_recv_finish_flag(int fd, short what, void *base_ptr)
{
	struct net2_evbase	*base = base_ptr;

	printf("event: sa1_recv_finish_flag\n");
	sa1_recv_finished = 1;
	event_base_loopbreak(base->evbase);
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
	int			 thread_running = 0;

	/* Initializing libevent. */
#ifdef WIN32
	if (evthread_use_windows_threads()) {
		fprintf(stderr, "unable to set up windows threading "
		    "in libevent");
		return -1;
	}
#else
	if (evthread_use_pthreads()) {
		fprintf(stderr, "unable to set up posix threading "
		    "in libevent");
		return -1;
	}
#endif

	/* Initialize network. */
	net2_init();

	if (udp_socketpair(&fd[0], &fd[1], 1)) {
		printf("socketpair fail: %d %s\n", errno, strerror(errno));
		return -1;
	}

	if ((protocol_ctx = test_ctx()) == NULL) {
		printf("test_ctx() fail\n");
		return -1;
	}
	if ((evbase = net2_evbase_new()) == NULL) {
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
	net2_conn_set_stealth(c2);

	/* Create stream. */
	sa1 = net2_stream_acceptor_new();
	sa2 = net2_stream_acceptor_new();
	if (sa1 == NULL || sa2 == NULL) {
		printf("net2_stream_acceptor_new() fail\n");
		return -1;
	}

	/* Turn sa2 into an echo service. */
	{
		struct event		*mirror_ev, *recv_finish_ev;
		struct net2_sa_rx	*rx = net2_stream_acceptor_rx(sa2);
		struct net2_sa_tx	*tx = net2_stream_acceptor_tx(sa2);

		mirror_ev = event_new(evbase->evbase, -1, 0,
		    mirror_recv_event, sa2);
		recv_finish_ev = event_new(evbase->evbase, -1, 0,
		    recv_finish_flag, evbase);
		if (mirror_ev == NULL || recv_finish_ev == NULL) {
			printf("event_new fail\n");
			return -1;
		}

		if (net2_sa_rx_set_event(rx, NET2_SARX_ON_RECV,
		    mirror_ev, NULL) ||
		    net2_sa_rx_set_event(rx, NET2_SARX_ON_FINISH,
		    mirror_ev, NULL)) {
			printf("net2_sa_rx_set_event fail\n");
			return -1;
		}
		if (net2_sa_tx_set_event(tx, NET2_SATX_ON_FINISH,
		    recv_finish_ev, NULL)) {
			printf("net2_sa_tx_set_event fail\n");
			return -1;
		}
	}

	/* Set up the finish and detach events for sa1. */
	{
		struct event		*detach, *finish, *sa1_recv_finish;
		struct net2_sa_tx	*tx = net2_stream_acceptor_tx(sa1);
		struct net2_sa_rx	*rx = net2_stream_acceptor_rx(sa1);

		detach = event_new(evbase->evbase, -1, 0,
		    detach_flag, evbase);
		finish = event_new(evbase->evbase, -1, 0,
		    finish_flag, evbase);
		sa1_recv_finish = event_new(evbase->evbase, -1, 0,
		    sa1_recv_finish_flag, evbase);
		if (detach == NULL || finish == NULL || sa1_recv_finish == NULL) {
			printf("event_new fail\n");
			return -1;
		}

		if (net2_sa_tx_set_event(tx, NET2_SATX_ON_DETACH,
		    detach, NULL) ||
		    net2_sa_tx_set_event(tx, NET2_SATX_ON_FINISH,
		    finish, NULL)) {
			printf("net2_sa_tx_set_event fail\n");
			return -1;
		}
		if (net2_sa_rx_set_event(rx, NET2_SARX_ON_FINISH,
		    sa1_recv_finish, NULL)) {
			printf("net2_sa_rx_set_event fail\n");
			return -1;
		}
	}

	/* Attach stream to connection. */
	if (net2_acceptor_attach(&c1->n2c_socket,
	    net2_stream_acceptor_reduce(sa1)) ||
	    net2_acceptor_attach(&c2->n2c_socket,
	    net2_stream_acceptor_reduce(sa2))) {
		printf("net2_acceptor_attach() fail\n");
		return -1;
	}

	/*
	 * Start the evbase.
	 */
	if (net2_evbase_threadstart(evbase)) {
		printf("net2_evbase_threadstart fail\n");
		return -1;
	}
	thread_running = 1;

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
		if (!thread_running) {
			if (net2_evbase_threadstart(evbase)) {
				printf("net2_evbase_threadstart fail\n");
				return -1;
			}
			thread_running = 1;
		}

		/* Wait for event loop to process everything. */
		if (net2_evbase_threadstop(evbase, NET2_EVBASE_WAITONLY)) {
			printf("net2_evbase_threadstop fail\n");
			return -1;
		}
		thread_running = 0;

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

	net2_connection_destroy(c1);
	net2_connection_destroy(c2);
	net2_stream_acceptor_destroy(sa1);
	net2_stream_acceptor_destroy(sa2);
	test_ctx_free(protocol_ctx);
	net2_cleanup();

	return fail;
}
