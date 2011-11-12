#include <ilias/net2/sockdgram.h>
#include <ilias/net2/connection.h>
#include <ilias/net2/buffer.h>
#include <bsd_compat/error.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "config.h"

#ifdef WIN32
#include <WinSock2.h>
#include <io.h>
#else
#include <sys/syslimits.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#endif

#ifdef WIN32	/* Windows compatibility. */
#define ioctl	ioctlsocket
#define ssize_t	ptrdiff_t

/* Only works here: errno is only used for checking send* and recvfrom. */
#define errno	WSAGetLastError()
#endif

/*
 * Receive data from datagram socket.
 *
 * Returns -1 if the call failed.
 * *bufptr is NULL if no data is available.
 */
ILIAS_NET2_LOCAL int
net2_sockdgram_recv(int sock, struct net2_conn_receive **recvptr,
    struct sockaddr *from, socklen_t *fromlen)
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
		case EAGAIN:	/* Timed out. */
		case EINTR:	/* Interrupted, let libevent deal with it. */
			net2_buffer_free(buf);
			return 0;
		case EHOSTUNREACH: /* Unreachable host. */
#ifdef EHOSTDOWN
		case EHOSTDOWN:	/* Host is down. */
#endif
		case ENETDOWN:	/* Network is down. */
		case ECONNREFUSED: /* Connection rejected. */
			error = NET2_CONNRECV_REJECT;
			break;
		case EBADF:	/* Socket gone bad. */
		case ENOTCONN:	/* Socket not connected. */
		case ENOTSOCK:	/* Descriptor is no socket. */
		case EFAULT:	/* Ehm... */
		case EINVAL:	/* Recvlen too large. */
		default:
			warn("recvfrom fail");
			goto fail;
		}
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
	if ((*recvptr = malloc(sizeof(**recvptr))) == NULL)
		goto fail;
	(*recvptr)->error = error;
	(*recvptr)->buf = buf;
	return 0;

fail:
	/* Failure. Release resources and return error. */
	if (*recvptr != NULL) {
		*recvptr = NULL;
		free(*recvptr);
	}
	if (buf != NULL)
		net2_buffer_free(buf);
	return -1;
}

ILIAS_NET2_LOCAL int
net2_sockdgram_send(int sock, struct net2_connection *c,
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
	if ((vec = calloc(numvec, sizeof(*vec))) == NULL) {
		warn("%s: failed to allocate %d iovec", __FUNCTION__, numvec);
		return -1;
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
		if ((buf = malloc(buflen)) == NULL) {
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
		free(buf);
	free(vec);
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
	case EMSGSIZE:		/* Message too big. */
		err = NET2_CONNFAIL_TOOBIG;
		break;
	case ENOBUFS:		/* OS needs to free up buffers. */
	case EINVAL:		/* OS doesn't grok our flags. */
		err = NET2_CONNFAIL_OS;
		break;
	case EFAULT:		/* Uh oh... */
		err = NET2_CONNFAIL_IO;
		break;
	case EAGAIN:		/* Wait for write access. */
		err = -1;
		break;
	default:
		err = NET2_CONNFAIL_BAD;
		break;
	}

	goto out;
}
