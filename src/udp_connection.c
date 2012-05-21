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
#include <ilias/net2/udp_connection.h>
#include <ilias/net2/connection.h>
#include <ilias/net2/acceptor.h>
#include <ilias/net2/mutex.h>
#include <ilias/net2/sockdgram.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/memory.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#ifdef WIN32
#include <WinSock2.h>
#include <io.h>
#include <ws2def.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#endif
#include <ilias/net2/bsd_compat/error.h>
#include <ilias/net2/bsd_compat/sysexits.h>
#include <ilias/net2/bsd_compat/secure_random.h>
#include <assert.h>


struct net2_conn_p2p;

/* Read at most this many packets per read. */
#define DEQUEUE_MAX		256

ILIAS_NET2_LOCAL
void	net2_conn_p2p_destroy(struct net2_acceptor_socket*);
ILIAS_NET2_LOCAL
void	net2_conn_p2p_ready_to_send(struct net2_acceptor_socket*);
ILIAS_NET2_LOCAL
int	net2_conn_p2p_setev(struct net2_conn_p2p*, short);

ILIAS_NET2_LOCAL
void	net2_conn_p2p_recv(int, short, void*);
ILIAS_NET2_LOCAL
void	net2_udpsocket_recv(int, short, void*);

ILIAS_NET2_LOCAL
void	net2_udpsock_unlock(struct net2_udpsocket*);
ILIAS_NET2_LOCAL
void	net2_udpsock_conn_unlink(struct net2_udpsocket*,
	    struct net2_conn_p2p*);
ILIAS_NET2_LOCAL
void	net2_udpsock_conn_wantsend(struct net2_udpsocket*,
	    struct net2_conn_p2p*);


static const struct net2_acceptor_socket_fn udp_conn_fn = {
	0,
	net2_conn_p2p_destroy,
	net2_conn_p2p_ready_to_send,
	NULL,
	NULL,
	net2_conn_get_pvlist
};

/* UDP connection. */
struct net2_conn_p2p {
	struct net2_connection	 np2p_conn;	/* Basic connection. */
	int			 np2p_sock;	/* UDP socket. */
	struct sockaddr		*np2p_remote;	/* Remote address. */
	socklen_t		 np2p_remotelen; /* Remote address len. */
	struct event		*np2p_ev;	/* Send/receive event. */
	struct net2_udpsocket	*np2p_udpsock;	/* Shared UDP socket. */

	RB_ENTRY(net2_conn_p2p)	 np2p_socktree;	/* Link into udp socket. */
	TAILQ_ENTRY(net2_conn_p2p)
				 np2p_wantwriteq; /* Link want-write queue. */
	int			 np2p_flags;	/* State flags. */
#define NP2P_F_SENDQ		 0x80000000	/* On udpsock sendqueue. */
};

RB_HEAD(net2_udpsocket_conns, net2_conn_p2p);

/*
 * UDP socket.
 *
 * A udp socket exists until both its reference count drops to zero and
 * its connection queue becomes empty.
 */
struct net2_udpsocket {
	evutil_socket_t		 sock;		/* Socket. */
	size_t			 refcnt;	/* Reference counter. */
	struct net2_mutex	*guard;		/* Protect against races. */
	struct event		*ev;		/* Send/receive event. */
	struct net2_workq	*workq;		/* Thread context. */

	struct net2_udpsocket_conns
				 conns;		/* Active connections. */
	TAILQ_HEAD(, net2_conn_p2p)
				 wantwrite;	/* Transmit-ready conns. */
};

/*
 * Compare two network addresses.
 *
 * Only implemented for AF_INET and AF_INET6.
 */
ILIAS_NET2_LOCAL int
np2p_remote_cmp(struct net2_conn_p2p *c1, struct net2_conn_p2p *c2)
{
	int			 f1, f2;
	struct sockaddr_in	*sin_1, *sin_2;
	struct sockaddr_in6	*sin6_1, *sin6_2;
	int			 cmp;

	if (c1->np2p_remote == NULL || c2->np2p_remote == NULL) {
		err(EX_SOFTWARE, "np2p_remote_cmp: "
		    "comparison cannot complete because arguments are NULL");
	}

	if (c1->np2p_remotelen != c2->np2p_remotelen)
		return (c1->np2p_remotelen < c2->np2p_remotelen ? -1 : 1);

	f1 = c1->np2p_remote->sa_family;
	f2 = c2->np2p_remote->sa_family;
	if (f1 != f2)
		return (f1 < f2 ? -1 : 1);

	switch (f1) {
	case AF_INET:
		sin_1 = (struct sockaddr_in*)c1->np2p_remote;
		sin_2 = (struct sockaddr_in*)c1->np2p_remote;
		if (sin_1->sin_addr.s_addr != sin_2->sin_addr.s_addr) {
			return (sin_1->sin_addr.s_addr <
			    sin_2->sin_addr.s_addr ? -1 : 1);
		}
		if (sin_1->sin_port != sin_2->sin_port)
			return (sin_1->sin_port < sin_2->sin_port ? -1 : 1);
		break;
	case AF_INET6:
		sin6_1 = (struct sockaddr_in6*)c1->np2p_remote;
		sin6_2 = (struct sockaddr_in6*)c1->np2p_remote;
		cmp = memcmp(&sin6_1->sin6_addr, &sin6_2->sin6_addr,
		    sizeof(sin6_1->sin6_addr));
		if (cmp != 0)
			return cmp;
		if (sin6_1->sin6_port != sin6_2->sin6_port) {
			return (sin6_1->sin6_port < sin6_2->sin6_port ?
			    -1 : 1);
		}
		break;
	default:
		err(EX_SOFTWARE, "np2p_remote_cmp: "
		    "no comparison for address family %d", (int)f1);
	}

	return 0;
}

RB_PROTOTYPE_STATIC(net2_udpsocket_conns, net2_conn_p2p, np2p_socktree,
    np2p_remote_cmp);
RB_GENERATE_STATIC(net2_udpsocket_conns, net2_conn_p2p, np2p_socktree,
    np2p_remote_cmp);


/*
 * Create a new peer-to-peer connection.
 */
ILIAS_NET2_EXPORT struct net2_connection*
net2_conn_p2p_create_fd(struct net2_ctx *ctx,
    struct net2_workq_evbase *wqev, evutil_socket_t sock,
    struct sockaddr *remote, socklen_t remotelen)
{
	struct net2_conn_p2p	*c;
	struct net2_workq	*wq;

	/* Check arguments. */
	if (sock == -1)
		return NULL;
	/* Reserve space. */
	if ((c = net2_malloc(sizeof(*c))) == NULL)
		goto fail_0;
	/* Copy remote address. */
	if (remote) {
		if ((c->np2p_remote = net2_malloc(remotelen)) == NULL)
			goto fail_1;
		memcpy(c->np2p_remote, remote, remotelen);
		c->np2p_remotelen = remotelen;
	} else {
		c->np2p_remote = NULL;
		c->np2p_remotelen = 0;
	}
	/* Set socket. */
	c->np2p_sock = sock;
	c->np2p_udpsock = NULL;
	c->np2p_flags = 0;

	/* Perform base connection initialization. */
	if ((wq = net2_workq_new(wqev)) == NULL)
		goto fail_2;
	if (net2_connection_init(&c->np2p_conn, ctx, wq, &udp_conn_fn)) {
		net2_workq_release(wq);
		goto fail_2;
	}
	net2_workq_release(wq);

	/* Set socket to nonblocking mode. */
	if (net2_sockdgram_nonblock(sock) ||
	    net2_sockdgram_dnf(sock))
		goto fail_3;

	/* Set up libevent network-receive event. */
	c->np2p_ev = NULL;
	if (net2_conn_p2p_setev(c, EV_READ))
		goto fail_3;

	return &c->np2p_conn;

fail_3:
	net2_connection_deinit(&c->np2p_conn);
fail_2:
	net2_free(c->np2p_remote);
fail_1:
	net2_free(c);
fail_0:
	return NULL;
}

/*
 * Create a new peer-to-peer connection.
 */
ILIAS_NET2_EXPORT struct net2_connection*
net2_conn_p2p_create(struct net2_ctx *ctx,
    struct net2_udpsocket *sock, struct sockaddr *remote, socklen_t remotelen)
{
	struct net2_conn_p2p	*c;
	struct net2_workq	*wq = NULL;

	/* Check arguments. */
	if (ctx == NULL || sock == NULL)
		return NULL;

	if ((c = net2_malloc(sizeof(*c))) == NULL)
		return NULL;
	c->np2p_sock = -1;
	c->np2p_udpsock = sock;
	c->np2p_remote = NULL;
	c->np2p_remotelen = 0;
	c->np2p_ev = NULL;
	c->np2p_flags = 0;

	if (remote) {
		if ((c->np2p_remote = net2_malloc(remotelen)) == NULL)
			goto fail;
		memcpy(c->np2p_remote, remote, remotelen);
		c->np2p_remotelen = remotelen;
	}

	if ((wq = net2_workq_new(net2_workq_evbase(sock->workq))) == NULL)
		goto fail;
	if (net2_connection_init(&c->np2p_conn, ctx, wq, &udp_conn_fn))
		goto fail;

	net2_workq_release(wq); /* Still alive because of connection. */
	return &c->np2p_conn;

fail:
	if (wq)
		net2_workq_release(wq);
	if (c->np2p_remote)
		net2_free(c->np2p_remote);
	net2_free(c);
	return NULL;
}

/*
 * Create a UDP socket that can handle multiple connections.
 */
ILIAS_NET2_EXPORT struct net2_udpsocket*
net2_conn_p2p_socket(struct net2_workq_evbase *wqev, struct sockaddr *bindaddr,
    socklen_t bindaddrlen)
{
	evutil_socket_t		 fd = -1;
	int			 saved_errno;
	struct net2_udpsocket	*rv;
	struct net2_workq	*wq = NULL;

	/* Check argument. */
	if (bindaddr == NULL || wqev == NULL) {
		errno = EINVAL;
		goto fail;
	}

	/* Increase reference count to evbase. */
	if ((wq = net2_workq_new(wqev)) == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	/* Create socket. */
	if ((fd = socket(bindaddr->sa_family, SOCK_DGRAM, 0)) == -1)
		goto fail;
	if (bind(fd, bindaddr, bindaddrlen))
		goto fail;
	if (net2_sockdgram_nonblock(fd) || net2_sockdgram_dnf(fd))
		goto fail;

	/* Allocate result. */
	if ((rv = net2_malloc(sizeof(*rv))) == NULL)
		goto fail;
	rv->workq = wq;
	rv->sock = fd;
	rv->refcnt = 1;
	if ((rv->guard = net2_mutex_alloc()) == NULL)
		goto fail_guard;
	rv->ev = event_new(evbase->evbase, fd, EV_READ|EV_PERSIST,
	    &net2_udpsocket_recv, rv);
	if (rv->ev == NULL)
		goto fail_event_new;
	if (event_add(rv->ev, NULL))
		goto fail_event_add;

	return rv;

fail_event_add:
	event_del(rv->ev);
fail_event_new:
	net2_mutex_free(rv->guard);
fail_guard:
	net2_free(rv);
fail:
	if (fd != -1) {
		saved_errno = errno;
#ifdef WIN32
		closesocket(fd);
#else
		while (close(fd) && errno == EINTR);
#endif
		errno = saved_errno;
	}
	if (wq != NULL)
		net2_workq_release(wq);
	return NULL;
}

/* Increase reference counter on socket. */
ILIAS_NET2_EXPORT void
net2_conn_p2p_socket_ref(struct net2_udpsocket *sock)
{
	net2_mutex_lock(sock->guard);
	sock->refcnt++;
	assert(sock->refcnt > 0);
	net2_mutex_unlock(sock->guard);
}

/* Decrease reference counter on socket. */
ILIAS_NET2_EXPORT void
net2_conn_p2p_socket_release(struct net2_udpsocket *sock)
{
	net2_mutex_lock(sock->guard);
	assert(sock->refcnt > 0);
	sock->refcnt--;
	net2_udpsock_unlock(sock);
}

ILIAS_NET2_LOCAL void
net2_conn_p2p_destroy(struct net2_acceptor_socket *cptr)
{
	struct net2_conn_p2p	*c = (struct net2_conn_p2p*)cptr;
	struct net2_udpsocket	*udpsock;

	udpsock = c->np2p_udpsock;
	if (c->np2p_remote)
		net2_free(c->np2p_remote);
	if (c->np2p_sock != -1)
#ifdef WIN32
		closesocket(c->np2p_sock);
#else
		while (close(c->np2p_sock) && errno == EINTR);
#endif
	if (udpsock != NULL)
		net2_udpsock_conn_unlink(udpsock, c);
	if (c->np2p_ev) {
		event_del(c->np2p_ev);
		event_free(c->np2p_ev);
	}
	net2_connection_deinit(&c->np2p_conn);
	net2_free(cptr);
}

/*
 * Mark connection as ready-to-send.
 */
ILIAS_NET2_LOCAL void
net2_conn_p2p_ready_to_send(struct net2_acceptor_socket *cptr)
{
	struct net2_conn_p2p	*c = (struct net2_conn_p2p*)cptr;

	if (c->np2p_udpsock != NULL)
		net2_udpsock_conn_wantsend(c->np2p_udpsock, c);
	else {
		if (net2_conn_p2p_setev(c, EV_READ | EV_WRITE))
			warnx("p2p connection: may lose data...");
	}
}

/*
 * P2P connection specific implementation of receive.
 * Only to be used on connected datagram sockets.
 */
ILIAS_NET2_LOCAL void
net2_conn_p2p_recv(int sock, short what, void *cptr)
{
	struct net2_conn_p2p	*c = cptr;
	struct net2_conn_receive*r;
	int			 dequeued;
	struct net2_buffer	*buf;
	int			 rv;
	size_t			 wire_sz;

	assert(c->np2p_sock == sock);

	/*
	 * Read network input.
	 */
	if (what & EV_READ) {
		for (dequeued = 0; dequeued < DEQUEUE_MAX; dequeued++) {
			if (net2_sockdgram_recv(sock, &r, NULL, 0)) {
				/* TODO: kill connection */
				return;
			}

			/* GUARD */
			if (r == NULL)
				break;
			net2_connection_recv(&c->np2p_conn, r);
		}
	}

	/*
	 * Write network data.
	 */
	if (what & EV_WRITE) {
		wire_sz = c->np2p_conn.n2c_stats.wire_sz;
		if (secure_random_uniform(16) == 0) {
			if (c->np2p_conn.n2c_stats.over_sz == 0)
				wire_sz *= 2;
			else {
				/*
				 * Take the average between largest ack and
				 * smallest nack.
				 */
				wire_sz += c->np2p_conn.n2c_stats.over_sz;
				wire_sz /= 2;
			}
		}

		buf = NULL;
		if (net2_conn_gather_tx(&c->np2p_conn, &buf, wire_sz)) {
			/* TODO: kill connection */
			return;
		}
		if (buf == NULL) {
			/* Nothing to transmit, turn off write event. */
			net2_conn_p2p_setev(c, EV_READ);
			return;
		}

		rv = net2_sockdgram_send(sock, &c->np2p_conn, buf,
		    c->np2p_remote, c->np2p_remotelen);
		net2_buffer_free(buf);
		switch (rv) {
		case NET2_CONNFAIL_OK:
			break;
		case NET2_CONNFAIL_CLOSE:
			/* TODO kill connection */
			break;
		case NET2_CONNFAIL_TOOBIG:
			/* TODO: figure out what to do here,
			 * better yet, try to avoid it */
			break;
		case NET2_CONNFAIL_BAD:
			/* TODO: kill connection */
			break;
		case NET2_CONNFAIL_OS:
			/*
			 * Drop packet and let retransmission logic deal
			 * with it.
			 */
			break;
		case NET2_CONNFAIL_IO:
			/* Drop packet. */
			break;
		case NET2_CONNFAIL_RESOURCE:
			/*
			 * Out of memory... maybe kill this connection to make
			 * room? Or find a sacrificial goat somewhere...
			 */
			break;
		default:
			errx(EX_SOFTWARE, "net2_sockdgram_send "
			    "unexpected response %d", rv);
		}
	}
}

/* Event initialization for connection-based events. */
ILIAS_NET2_LOCAL int
net2_conn_p2p_setev(struct net2_conn_p2p *c, short what)
{
	struct net2_evbase	*evbase;
	int			 allocated = 0;
	int			 want_write, have_write;
	int			 want_read,  have_read;

	assert(c->np2p_udpsock == NULL);
	evbase = net2_acceptor_socket_evbase(&c->np2p_conn.n2c_socket);
	want_write = (what & EV_WRITE);
	want_read = (what & EV_READ);

	if (c->np2p_ev == NULL) {
		if ((c->np2p_ev = event_new(evbase->evbase,
		    c->np2p_sock, what | EV_PERSIST,
		    net2_conn_p2p_recv, c)) == NULL) {
			warnx("event_new fail");
			return -1;
		}
		allocated = 1;
	} else {
		/*
		 * Check if the event is already pending for the right
		 * event types.
		 */
		have_write = event_pending(c->np2p_ev, EV_WRITE, NULL);
		have_read  = event_pending(c->np2p_ev, EV_READ, NULL);
		if ((have_write == 0) == (want_write == 0) &&
		    (have_read  == 0) == (want_read  == 0)) {
			return 0;
		}

		/* Remove and reinitialize event. */
		event_free(c->np2p_ev);
		if ((c->np2p_ev = event_new(evbase->evbase,
		    c->np2p_sock, what | EV_PERSIST,
		    net2_conn_p2p_recv, c)) == NULL) {
			warnx("event_new fail");
			goto fail;
		}
	}

	/* Add event. */
	if (event_add(c->np2p_ev, NULL)) {
		warnx("event_add fail");
		goto fail;
	}
	return 0;

fail:
	if (allocated) {
		event_free(c->np2p_ev);
		c->np2p_ev = NULL;
	}
	return -1;
}

/*
 * UDP specific implementation of receive.
 */
ILIAS_NET2_LOCAL void
net2_udpsocket_recv(int sock, short what, void *udps_ptr)
{
	struct net2_udpsocket	*udps = udps_ptr;
	struct net2_conn_receive*r;
	struct sockaddr_storage	 from;
	socklen_t		 fromlen;
	struct net2_conn_p2p	*c, search;
	int			 dequeued;
	size_t			 wire_sz;
	struct net2_buffer	*buf;
	int			 rv;

	assert(udps->sock == sock);

	/*
	 * Read network input.
	 */
	if (what & EV_READ) {
		for (dequeued = 0; dequeued < DEQUEUE_MAX; dequeued++) {
			fromlen = sizeof(from);
			if (net2_sockdgram_recv(sock, &r,
			    (struct sockaddr*)&from, &fromlen)) {
				/* TODO: kill socket */
				return;
			}

			/* GUARD */
			if (r == NULL)
				break;

			/* Find connection. */
			search.np2p_remote = (struct sockaddr*)&from;
			search.np2p_remotelen = fromlen;
			net2_mutex_lock(udps->guard);	/* LOCK */
			c = RB_FIND(net2_udpsocket_conns, &udps->conns,
			    &search);

			/* Deliver data to connection. */
			if (c != NULL)
				net2_connection_recv(&c->np2p_conn, r);
			else {
				/* Unrecognized connection. */
				/* TODO: implement new connection callback */
				if (r->buf)
					net2_buffer_free(r->buf);
				net2_free(r);
			}
			net2_mutex_unlock(udps->guard);	/* UNLOCK */
		}
	}

	/*
	 * Invoke write callback
	 */
	if (what & EV_WRITE) {
retry_tx:
		net2_mutex_lock(udps->guard);	/* LOCK */

		if ((c = TAILQ_FIRST(&udps->wantwrite)) == NULL)
			goto empty_sendq;	/* Shouldn't happen. */

		/* Remove c from writeq. */
		TAILQ_REMOVE(&udps->wantwrite, c, np2p_wantwriteq);
		c->np2p_flags &= ~NP2P_F_SENDQ;

		net2_mutex_unlock(udps->guard);	/* UNLOCK */

		wire_sz = c->np2p_conn.n2c_stats.wire_sz;
		if (secure_random_uniform(16) == 0) {
			if (c->np2p_conn.n2c_stats.over_sz == 0)
				wire_sz *= 2;
			else {
				/*
				 * Take the average between largest ack and
				 * smallest nack.
				 */
				wire_sz += c->np2p_conn.n2c_stats.over_sz;
				wire_sz /= 2;
			}
		}

		buf = NULL;
		if (net2_conn_gather_tx(&c->np2p_conn, &buf, wire_sz)) {
			/* TODO: kill connection */
			return;
		}
		if (buf == NULL) {
			/* Nothing to transmit, try another connection. */
			goto retry_tx;
		}

		rv = net2_sockdgram_send(sock, &c->np2p_conn, buf,
		    c->np2p_remote, c->np2p_remotelen);
		net2_buffer_free(buf);
		switch (rv) {
		case NET2_CONNFAIL_OK:
			break;
		case NET2_CONNFAIL_CLOSE:
			/* TODO kill connection */
			break;
		case NET2_CONNFAIL_TOOBIG:
			/* TODO: figure out what to do here,
			 * better yet, try to avoid it */
			break;
		case NET2_CONNFAIL_BAD:
			/* TODO kill connection */
			break;
		case NET2_CONNFAIL_OS:
			/*
			 * Drop packet and let retransmission logic deal
			 * with it.
			 */
			break;
		case NET2_CONNFAIL_IO:
			/* Drop packet. */
			break;
		case NET2_CONNFAIL_RESOURCE:
			/*
			 * Out of memory... maybe kill this connection to make
			 * room? Or find a sacrificial goat somewhere...
			 */
			break;
		default:
			errx(EX_SOFTWARE, "net2_sockdgram_send "
			    "unexpected response %d", rv);
		}

		net2_mutex_lock(udps->guard);	/* LOCK */

		/* Put c back on the sendq, if it hasn't done so itself. */
		if (c != NULL && !(c->np2p_flags & NP2P_F_SENDQ)) {
			c->np2p_flags |= NP2P_F_SENDQ;
			TAILQ_INSERT_TAIL(&udps->wantwrite, c, np2p_wantwriteq);
		}

		/* Test if we still have pending writes. */
		if (TAILQ_EMPTY(&udps->wantwrite)) {
empty_sendq:
			event_free(udps->ev);
			if ((udps->ev = event_new(udps->evbase->evbase, sock,
			    EV_READ|EV_PERSIST, &net2_udpsocket_recv, udps)) ==
			    NULL)
				warnx("event_new fail");
			if (event_add(udps->ev, NULL))
				warnx("event_add fail");
		}

		net2_mutex_unlock(udps->guard);	/* UNLOCK */
	}
}

/* Unlock socket and remove it if it has no references. */
ILIAS_NET2_LOCAL void
net2_udpsock_unlock(struct net2_udpsocket *sock)
{
	int		do_rm;

	do_rm = RB_EMPTY(&sock->conns) &&
	    sock->refcnt == 0;
	if (do_rm)
		event_del(sock->ev);
	net2_mutex_unlock(sock->guard);

	if (do_rm) {
		net2_mutex_free(sock->guard);
		event_free(sock->ev);
		net2_evbase_release(sock->evbase);
		net2_free(sock);
	}
}

/* Remove a connection from a udp socket. */
ILIAS_NET2_LOCAL void
net2_udpsock_conn_unlink(struct net2_udpsocket *sock, struct net2_conn_p2p *c)
{
	net2_mutex_lock(sock->guard);
	if (RB_REMOVE(net2_udpsocket_conns, &sock->conns, c) != c)
		warnx("udpsocket: removal of connection that doesn't exist");
	net2_udpsock_unlock(sock);
}

ILIAS_NET2_LOCAL void
net2_udpsock_conn_wantsend(struct net2_udpsocket *sock, struct net2_conn_p2p *c)
{
	if (c->np2p_flags & NP2P_F_SENDQ)
		return;

	/* Acquire exclusive access to udpsocket. */
	net2_mutex_lock(sock->guard);

	/* Modify event to be pending for write. */
	if (!event_pending(sock->ev, EV_WRITE, NULL)) {
		if (event_del(sock->ev))
			errx(EX_UNAVAILABLE, "event_del fail");
		if (event_assign(sock->ev, sock->evbase->evbase, sock->sock,
		    EV_READ|EV_WRITE|EV_PERSIST, &net2_udpsocket_recv, sock))
			warnx("event_assign fail");
		if (event_add(sock->ev, NULL))
			warnx("event_add fail");
	}

	/* Add connection to wantwriteq. */
	assert(RB_FIND(net2_udpsocket_conns, &sock->conns, c) == c);
	c->np2p_flags |= NP2P_F_SENDQ;
	TAILQ_INSERT_TAIL(&sock->wantwrite, c, np2p_wantwriteq);

	/* Release exclusive access to udpsocket. */
	net2_mutex_unlock(sock->guard);
}
