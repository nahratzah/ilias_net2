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
#include <ilias/net2/workq.h>
#include <ilias/net2/workq_io.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/memory.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <WinSock2.h>
#include <io.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#endif
#include <ilias/net2/bsd_compat/error.h>
#include <ilias/net2/bsd_compat/minmax.h>
#include <ilias/net2/bsd_compat/sysexits.h>
#include <ilias/net2/bsd_compat/secure_random.h>
#include <assert.h>


struct net2_conn_p2p;

static void	 net2_conn_p2p_destroy(struct net2_acceptor_socket*);
static void	 net2_conn_p2p_ready_to_send(struct net2_acceptor_socket*);

static void	 net2_conn_p2p_recv(void*, struct net2_dgram_rx*);
static void	 net2_udpsocket_recv(void*, struct net2_dgram_rx*);
static struct net2_promise
		*net2_udpsocket_send(void*, size_t);

static void	 net2_udpsock_unlock(struct net2_udpsocket*);
static void	 net2_udpsock_conn_unlink(struct net2_udpsocket*,
		    struct net2_conn_p2p*);

static struct net2_promise
		*net2_udpsocket_gather(struct net2_connection*,
		    size_t, struct sockaddr*, socklen_t);


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
	struct net2_workq_io	*np2p_ev;	/* Send/receive event. */
	struct net2_udpsocket	*np2p_udpsock;	/* Shared UDP socket. */

	RB_ENTRY(net2_conn_p2p)	 np2p_socktree;	/* Link into udp socket. */
};

RB_HEAD(net2_udpsocket_conns, net2_conn_p2p);

/*
 * UDP socket.
 *
 * A udp socket exists until both its reference count drops to zero and
 * its connection queue becomes empty.
 */
struct net2_udpsocket {
	net2_socket_t		 sock;		/* Socket. */
	size_t			 refcnt;	/* Reference counter. */
	struct net2_mutex	*guard;		/* Protect against races. */
	struct net2_workq_io	*ev;		/* Send/receive event. */
	struct net2_workq	*workq;		/* Thread context. */

	struct net2_udpsocket_conns
				 conns;		/* Active connections. */
};

/*
 * Compare two network addresses.
 *
 * Only implemented for AF_INET and AF_INET6.
 */
static int
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
    struct net2_workq_evbase *wqev, net2_socket_t sock,
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
	if ((c->np2p_ev = net2_workq_io_new(wq, sock, &net2_conn_p2p_recv,
	    c)) == NULL)
		goto fail_3;
	net2_workq_io_activate_rx(c->np2p_ev);

	return &c->np2p_conn;

fail_4:
	net2_workq_io_destroy(c->np2p_ev);
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
	net2_socket_t		 fd = -1;
	int			 saved_errno;
	struct net2_udpsocket	*rv;
	struct net2_workq	*wq = NULL;

	/* Check argument. */
	if (bindaddr == NULL || wqev == NULL) {
		errno = EINVAL;
		goto fail;
	}

	/* Increase reference count to workq. */
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
	rv->ev = net2_workq_io_new(wq, fd, &net2_udpsocket_recv, rv);
	if (rv->ev == NULL)
		goto fail_event_new;

	net2_workq_io_activate_rx(rv->ev);
	return rv;

fail_event_add:
	net2_workq_io_destroy(rv->ev);
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

static void
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
	if (c->np2p_ev)
		net2_workq_io_destroy(c->np2p_ev);
	net2_connection_deinit(&c->np2p_conn);
	net2_free(cptr);
}

/*
 * Mark connection as ready-to-send.
 */
static void
net2_conn_p2p_ready_to_send(struct net2_acceptor_socket *cptr)
{
	struct net2_conn_p2p	*c = (struct net2_conn_p2p*)cptr;
	struct net2_promise	*p;
	struct net2_workq_io	*io;

	/* Figure out which io to use. */
	if (c->np2p_udpsock != NULL)
		io = c->np2p_udpsock->ev;
	else
		io = c->np2p_ev;
	/* Get a new promise. */
	if ((p = net2_udpsocket_gather(&c->np2p_conn, NET2_WORKQ_IO_MAXLEN,
	    c->np2p_remote, c->np2p_remotelen)) == NULL)
		return;
	/* Post the promise. */
	net2_workq_io_tx(io, p);
}

/*
 * P2P connection specific implementation of receive.
 * Only to be used on connected datagram sockets.
 */
static void
net2_conn_p2p_recv(void *cptr, struct net2_dgram_rx *rx)
{
	struct net2_conn_p2p	*c = cptr;
	struct net2_conn_receive*r;

	if ((r = net2_malloc(sizeof(*r))) == NULL)
		return;	/* Drop packet. */
	r->buf = rx->data;
	rx->data = NULL;
	r->error = rx->error;

	net2_connection_recv(&c->np2p_conn, r);
}

/*
 * UDP specific implementation of receive.
 */
static void
net2_udpsocket_recv(void *udps_ptr, struct net2_dgram_rx *rx)
{
	struct net2_udpsocket	*udps = udps_ptr;
	struct net2_conn_receive*r;
	struct net2_conn_p2p	*c, search;

	if ((r = net2_malloc(sizeof(*r))) == NULL)
		return;	/* Drop packet. */
	r->buf = rx->data;
	rx->data = NULL;
	r->error = rx->error;

	search.np2p_remote = (struct sockaddr*)&rx->addr;
	search.np2p_remotelen = rx->addrlen;
	c = RB_FIND(net2_udpsocket_conns, &udps->conns, &search);
	if (c != NULL)
		net2_connection_recv(&c->np2p_conn, r);
	else {
		/* Unrecognized connection. */
		/* XXX Implement new connection callback. */
		if (r->buf)
			net2_buffer_free(r->buf);
		net2_free(r);
	}
}

static void
udpsocket_txgather_2_pd(struct net2_promise *out, struct net2_promise **in,
    size_t n, void *pd_ptr)
{
	int			 fin;
	uint32_t		 err;
	struct net2_buffer	*buf;
	struct net2_dgram_tx_promdata
				*pd = pd_ptr;

	assert(n == 1);

	fin = net2_promise_get_result(in[0], (void**)&buf, &err);

	switch (fin) {
	case NET2_PROM_FIN_OK:
		if (buf != NULL)
			break;
		/* FALLTHROUGH */
	case NET2_PROM_FIN_CANCEL:
		net2_promise_set_cancel(out, 0);
		return;
	case NET2_PROM_FIN_UNFINISHED:
		abort();
	case NET2_PROM_FIN_UNREF:
	case NET2_PROM_FIN_FAIL:
	default:
		err = EIO;
	case NET2_PROM_FIN_ERROR:
		net2_promise_set_error(out, err, 0);
		return;
	}

	assert(buf != NULL);

	/* Take ownership of buffer. */
	net2_promise_dontfree(in[0]);
	/*
	 * Take full ownership of pd (since we want to move it from an
	 * input parameter to the result value.
	 */
	net2_promise_destroy_cb(out, NULL, NULL, NULL);

	/* Assign buffer. */
	pd->data = buf;
	/* Assign result. */
	if (net2_promise_set_finok(out, pd, &net2_workq_io_tx_pdata_free, NULL, 0)) {
		net2_workq_io_tx_pdata_free(pd, NULL);
		net2_promise_set_error(out, EIO, 0);
	}
}

static struct net2_promise*
net2_udpsocket_gather(struct net2_connection *c, size_t maxsz,
    struct sockaddr *remote, socklen_t remotelen)
{
	struct net2_dgram_tx_promdata
				*pd;
	size_t			 wire_sz;
	struct net2_promise	*p, *conn_prom;

	/* Figure out what wire size to use. */
	wire_sz = c->n2c_stats.wire_sz;
	if (secure_random_uniform(16) == 0) {
		if (c->n2c_stats.over_sz == 0)
			wire_sz *= 2;
		else {
			wire_sz += c->n2c_stats.over_sz;
			wire_sz /= 2;
		}
	}
	wire_sz = MIN(wire_sz, maxsz);

	/* Acquire promise from connection. */
	if ((conn_prom = net2_conn_gather_tx(c, wire_sz)) == NULL)
		return NULL;

	/* Allocate pd. */
	if ((pd = net2_malloc(sizeof(*pd))) == NULL)
		goto fail_0;

	assert(remotelen <= sizeof(pd->addr));
	memcpy(&pd->addr, remote, remotelen);
	pd->addrlen = remotelen;
	pd->data = NULL;
	pd->tx_done = NULL;

	/* Create a promise that will transform the packet data
	 * into a pd struct. */
	p = net2_promise_combine(
	    net2_acceptor_socket_workq(&c->n2c_socket),
	    &udpsocket_txgather_2_pd, pd, &conn_prom, 1);
	if (p == NULL)
		goto fail_1;
	net2_promise_destroy_cb(p, &net2_workq_io_tx_pdata_free, pd, NULL);

	/* Release conn_prom. */
	net2_promise_release(conn_prom);

	return p;


fail_2:
	net2_promise_cancel(p);
	net2_promise_release(p);
fail_1:
	net2_free(pd);
fail_0:
	net2_promise_cancel(conn_prom);
	net2_promise_release(conn_prom);
	return NULL;
}

/* Unlock socket and remove it if it has no references. */
static void
net2_udpsock_unlock(struct net2_udpsocket *sock)
{
	int		do_rm;
	int		want_err;

	do_rm = RB_EMPTY(&sock->conns) &&
	    sock->refcnt == 0; /* XXX and no acceptor fn */
	net2_mutex_unlock(sock->guard);

	if (do_rm) {
		want_err = net2_workq_want(sock->workq, 0);
		assert(want_err == 0 || want_err == EDEADLK);
		net2_workq_io_destroy(sock->ev);
		net2_mutex_free(sock->guard);
		if (want_err == 0)
			net2_workq_unwant(sock->workq);
		net2_workq_release(sock->workq);
		net2_free(sock);
	}
}

/* Remove a connection from a udp socket. */
static void
net2_udpsock_conn_unlink(struct net2_udpsocket *sock, struct net2_conn_p2p *c)
{
	net2_mutex_lock(sock->guard);
	if (RB_REMOVE(net2_udpsocket_conns, &sock->conns, c) != c)
		warnx("udpsocket: removal of connection that doesn't exist");
	net2_udpsock_unlock(sock);
}
