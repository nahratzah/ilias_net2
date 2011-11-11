#include "testprotocol.h"
#include <ilias/net2/init.h>
#include <ilias/net2/udp_connection.h>
#include <ilias/net2/evbase.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/packet.h>
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
#define PH_LEN	net2_ph_overhead

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

int
main()
{
	int	fd[2];

	net2_init();

	if (udp_socketpair(&fd[0], &fd[1], 1)) {
		printf("socketpair fail: %d %s\n", errno, strerror(errno));
		return -1;
	}

	net2_cleanup();

	return fail;
}
