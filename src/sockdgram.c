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
#include <ilias/net2/sockdgram.h>
#include <ilias/net2/connection.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/bsd_compat/error.h>
#include <ilias/net2/config.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#ifdef WIN32
#include <WinSock2.h>
#include <ws2ipdef.h>
#include <WS2tcpip.h>
#include <io.h>
#else
#include <sys/syslimits.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netinet/in.h>
#endif

#ifdef WIN32	/* Windows compatibility. */
#define ioctl	ioctlsocket
#define ssize_t	ptrdiff_t

/* Only works here: errno is only used for checking send* and recvfrom. */
#ifdef errno
#undef errno
#endif /* errno */
#define errno	WSAGetLastError()
#endif

/*
 * Receive data from datagram socket.
 *
 * Returns -1 if the call failed.
 * *bufptr is NULL if no data is available.
 */
ILIAS_NET2_LOCAL int
net2_sockdgram_recv(evutil_socket_t sock, int *error_ptr,
    struct net2_buffer **buf_ptr, struct sockaddr *from, socklen_t *fromlen)
{
	int			 rdsz;
	struct net2_buffer	*buf;
	struct iovec		 iov;
	size_t			 n_vecs;
	ssize_t			 recvlen;
	int			 error;

	*recvptr = NULL;
	buf = NULL;
	error = NET2_CONNRECV_OK;

	/* Figure out next packet size. */
	if (ioctl(sock, FIONREAD, &rdsz) == -1) {
		warnx("ioctl(FIONREAD) fail");
		goto fail;
	}

	/* Allocate buffer. */
	if ((buf = net2_buffer_new()) == NULL) {
		warn("net2_buffer_new fail");
		goto fail;
	}

	/* Allocate buffer space. */
	if (rdsz == 0) {
		n_vecs = 0;
		iov.iov_base = NULL;
		iov.iov_len = 0;
	} else {
		n_vecs = 1;
		if (net2_buffer_reserve_space(buf, rdsz, &iov, &n_vecs)) {
			warn("net2_buffer_reserve_space fail");
			goto fail;
		}
	}

	/* Receive data. */
	recvlen = recvfrom(sock, iov.iov_base, iov.iov_len, 0,
	    (struct sockaddr*)from, fromlen);
	if (recvlen == -1) {
		switch (errno) {
#ifdef WIN32
		case WSAEWOULDBLOCK:
		case WSAEINTR:
#endif
		case EWOULDBLOCK: /* No data available. */
		case EINTR:	/* Interrupted, let libevent deal with it. */
			net2_buffer_free(buf);
			if (error_ptr != NULL)
				*error_ptr = 0;
			if (buf_ptr != NULL)
				*buf_ptr = NULL;
			return 0;
#ifdef WIN32
		case WSAEHOSTUNREACH:
		case WSAEHOSTDOWN:
		case WSAENETDOWN:
		case WSAECONNREFUSED:
#endif
		case EHOSTUNREACH: /* Unreachable host. */
#ifdef EHOSTDOWN
		case EHOSTDOWN:	/* Host is down. */
#endif
		case ENETDOWN:	/* Network is down. */
		case ECONNREFUSED: /* Connection rejected. */
			error = NET2_CONNRECV_REJECT;
			break;
#ifdef WIN32
		case WSAEBADF:
		case WSAENOTCONN:
		case WSAENOTSOCK:
		case WSAEFAULT:
		case WSAEINVAL:
#endif
		case EBADF:	/* Socket gone bad. */
		case ENOTCONN:	/* Socket not connected. */
		case ENOTSOCK:	/* Descriptor is no socket. */
		case EFAULT:	/* Ehm... */
		case EINVAL:	/* Recvlen too large. */
			warn("recvfrom fail");
			goto fail;
		default:
			warn("recvfrom fail with errno %d", (int)errno);
			goto fail;
		}
	} else if (recvlen == 0) {
		/* Don't push empty packets up the chain. */
		net2_buffer_free(buf);
		if (error_ptr != NULL)
			*error_ptr = 0;
		if (buf_ptr != NULL)
			*buf_ptr = NULL;
		return 0;
	}

	/* Commit received data to buffer. */
	iov.iov_len = recvlen;
	if (net2_buffer_commit_space(buf, &iov, 1) == -1) {
		warnx("net2_buffer_commit_space fail");
		goto fail;
	}

	/* Release buffer if an error occured. */
	if (buf != NULL) {
		if (error != NET2_CONNRECV_OK) {
			net2_buffer_free(buf);
			buf = NULL;
		}
	} else
		assert(error != 0);

	/* Succes. */
	if ((*recvptr = net2_malloc(sizeof(**recvptr))) == NULL)
		goto fail;
	if (error_ptr != NULL)
		*error_ptr = error;
	if (buf_ptr != NULL)
		*buf_ptr = buf;
	else
		net2_buffer_free(buf);
	return 0;

fail:
	/* Failure. Release resources and return error. */
	if (buf != NULL)
		net2_buffer_free(buf);
	return -1;
}

ILIAS_NET2_LOCAL int
net2_sockdgram_send(evutil_socket_t sock,
    struct net2_buffer *txbuf,
    struct sockaddr *remote, socklen_t remotelen)
{
	struct iovec		*vec;
	int			 numvec, i;
#ifdef HAVE_SENDMSG
	struct msghdr		 msg;
#endif
	int			 err;
	uint8_t			*buf = NULL, *bufp;
	int			 freebuf = 0;
	size_t			 buflen;
	size_t			 tbuf_len;

	tbuf_len = net2_buffer_length(txbuf);
	numvec = net2_buffer_peek(txbuf, tbuf_len, NULL, 0);
	if ((vec = net2_calloc(numvec, sizeof(*vec))) == NULL) {
		warn("%s: failed to allocate %d iovec", __FUNCTION__, numvec);
		return NET2_CONNFAIL_RESOURCE;
	}
	net2_buffer_peek(txbuf, tbuf_len, vec, numvec);

#ifdef HAVE_SENDMSG
	/* Ensure EMSGSIZE won't trigger due to too many iovs. */
	if (numvec > IOV_MAX)
		goto simple;

	msg.msg_name = remote;
	msg.msg_namelen = remotelen;
	msg.msg_iov = vec;
	msg.msg_iovlen = numvec;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	if (sendmsg(sock, &msg, 0) == -1)
		goto handle_errno;

	/* Transmission succesful. */
	err = 0;
	goto out;

simple:
#endif /* HAVE_SENDMSG */
	/*
	 * Ensure that buf will hold all data in the buffer.
	 * Only copy data if necessary, if the buffer already has a single
	 * datagram, use it directly.
	 */
	if (numvec == 1) {
		buf = vec[0].iov_base;
		buflen = vec[0].iov_len;
	} else {
		buflen = tbuf_len;
		if ((buf = net2_malloc(buflen)) == NULL) {
			err = NET2_CONNFAIL_RESOURCE;
			goto out;
		}
		freebuf = 1;

		for (bufp = buf, i = 0; i < numvec; i++) {
			memcpy(bufp, vec[i].iov_base, vec[i].iov_len);
			bufp += vec[i].iov_len;
		}
	}

	/*
	 * Transmit the buffer.
	 */
	if (remote) {
		if (sendto(sock, buf, buflen, 0,
		    remote, remotelen) == -1)
			goto handle_errno;
	} else {
		if (send(sock, buf, buflen, 0) == -1)
			goto handle_errno;
	}

	/* Transmission succesful. */
	err = 0;

out:
	if (freebuf)		/* buf was allocated. */
		net2_free(buf);
	net2_free(vec);
	return err;

handle_errno:
	/*
	 * Handle errno failure from send{,to,msg}.
	 *
	 * The end result is that either:
	 * - err is set to -1
	 * - a net2_conntransmit_fail is enqueued.
	 */
	switch (errno) {
#ifdef WIN32
	case WSAEBADF:
	case WSAENOTSOCK:
	case WSAEDESTADDRREQ:
	case WSAEISCONN:
	case WSAEAFNOSUPPORT:
	case WSAEHOSTUNREACH:
	case WSAEHOSTDOWN:
	case WSAENETDOWN:
	case WSAECONNREFUSED:
	case WSAENOPROTOOPT:
#endif
	case EBADF:		/* Connection is clearly broken. */
	case ENOTSOCK:		/* Connection is clearly broken. */
	case EDESTADDRREQ:	/* Connection is broken: need address. */
	case EACCES:		/* Network address is faulty. */
	case EISCONN:		/* Connection data is incorrect. */
	case EAFNOSUPPORT:	/* Connection data is incorrect. */
	case EHOSTUNREACH:	/* Unreachable. */
#ifdef EHOSTDOWN	/* not on WIN32 */
	case EHOSTDOWN:		/* Unreachable. */
#endif
	case ENETDOWN:		/* Unreachable. */
	case ECONNREFUSED:	/* Connection (no longer) exists. */
	case ENOPROTOOPT:	/* Connected socket failed to send. */
		err = NET2_CONNFAIL_BAD;
		break;
#ifdef WIN32
	case WSAEMSGSIZE:
#endif
	case EMSGSIZE:		/* Message too big. */
		err = NET2_CONNFAIL_TOOBIG;
		break;
#ifdef WIN32
	case WSAENOBUFS:
	case WSAEINVAL:
#endif
	case ENOBUFS:		/* OS needs to free up buffers. */
	case EINVAL:		/* OS doesn't grok our flags. */
		err = NET2_CONNFAIL_OS;
		break;
#ifdef WIN32
	case WSAEFAULT:
#endif
	case EFAULT:		/* Uh oh... */
		err = NET2_CONNFAIL_IO;
		break;
#ifdef WIN32
	case WSAEWOULDBLOCK:
#endif
	case EWOULDBLOCK:	/* Wait for write access. */
		err = -1;
		break;
	default:
		err = NET2_CONNFAIL_BAD;
		break;
	}

	goto out;
}


/*
 * Mark socket as nonblocking.
 */
ILIAS_NET2_LOCAL int
net2_sockdgram_nonblock(evutil_socket_t sock)
{
#ifdef WIN32
	u_long			arg;

	arg = 1;
	if (ioctlsocket(sock, FIONBIO, &arg) != NO_ERROR)
		return -1;
	return 0;
#else
	int			flags;

	if (sock == -1)
		return -1;

	flags = fcntl(sock, F_GETFL, 0);
	if (flags < 0)
		return -1;

	if (!(flags & O_NONBLOCK)) {
		flags |= O_NONBLOCK;
		if (fcntl(sock, F_SETFL, flags) == -1)
			return -1;
	}
	return 0;
#endif
}

#if defined(IP_DONTFRAGMENT) && !defined(IP_DONTFRAG)
#define IP_DONTFRAG IP_DONTFRAGMENT
#endif
/*
 * Set the do-not-fragment bit for udp connections.
 */
ILIAS_NET2_LOCAL int
net2_sockdgram_dnf(evutil_socket_t sock)
{
	struct sockaddr_storage	name;
	socklen_t		namelen;
#ifdef WIN32
	DWORD			opt;
#else
	int			opt;
#endif

	namelen = sizeof(name);
	if (getsockname(sock, (struct sockaddr*)&name, &namelen))
		return -1;

	switch (name.ss_family) {
#ifdef AF_INET
	case AF_INET:
#ifdef IP_DONTFRAG
		opt = 1;
		if (setsockopt(sock, IPPROTO_IP, IP_DONTFRAG,
		    &opt, sizeof(opt))) {
			switch (errno) {
			case EBADF:
			case ENOTSOCK:
				return -1;
			case EFAULT:
				abort();
				break;
			case ENOPROTOOPT:
				warn("do-not-fragment: "
				    "IP_DONTFRAG not recognized");
				/* Ignore. */
				break;
			}
		}
#endif

#ifdef IP_MTU_DISCOVER
		opt = IP_PMTUDISC_DO;
		if (setsockopt(sd, IPPROTO_IP, IP_MTU_DISCOVER,
		    &opt, sizeof(opt))) {
			switch (errno) {
			case EBADF:
			case ENOTSOCK:
				return -1;
			case EFAULT:
				abort();
				break;
			case ENOPROTOOPT:
				warn("do-not-fragment: "
				    "IP_MTU_DISCOVER not recognized");
				/* Ignore. */
				break;
			}
		}
#endif /* IP_MTU_DISCOVER */
#endif /* AF_INET */
#ifdef AF_INET6
	case AF_INET6:
		opt = 1;
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_DONTFRAG,
		    &opt, sizeof(opt))) {
			switch (errno) {
			case EBADF:
			case ENOTSOCK:
				return -1;
			case EFAULT:
				abort();
				break;
			case ENOPROTOOPT:
				warn("do-not-fragment: "
				    "IPV6_DONTFRAG not recognized");
				/* Ignore. */
				break;
			}
		}
#endif /* AF_INET6 */
	default:
		return 0;
	}

	return 0;
}
