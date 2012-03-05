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
#include <ilias/net2/cluster/socket.h>
#include <event2/event.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <ilias/net2/bsd_compat/error.h>
#ifdef WIN32
#include <WinSock2.h>
#include <ws2ipdef.h>
#include <WS2tcpip.h>
#include <io.h>
#include <MSWSock.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#endif

static const struct ra_functions multicast_fun = {
	"multicast",
#if 0 /* notyet */
	multicast_destroy,
	multicast_transmit
#else
	NULL,NULL
#endif
};

/*
 *  Multicast state.
 */
struct n2ra_mcast {
	struct net2_evbase	*evbase;	/* Libevent base. */
	struct event		*ev_mcast;	/* Multicast libevent data. */
	struct event		*ev_rx;		/* Transmit libevent data. */
	int			 sock_mcast;	/* Multicast receive socket. */
	int			 sock_rx;	/* Transmit socket. */
	const char		*secret;	/* Network secret. */
};

/* Join the mcast group in res_mcast. */
ILIAS_NET2_LOCAL int
join_mcast1(int s, struct addrinfo *res_mcast, struct addrinfo *res)
{
	struct ip_mreq		ip_mreq;
	struct ipv6_mreq	ip6_mreq;

	/* Can't join multicast across protocol boundaries. */
	if (res != NULL && res->ai_family != res_mcast->ai_family)
		return -1;

	switch (res_mcast->ai_family) {
	case PF_INET:
		ip_mreq.imr_multiaddr =
		    ((struct sockaddr_in*)res_mcast->ai_addr)->sin_addr;
		if (res == NULL) {
			ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
		} else {
			ip_mreq.imr_interface =
			    ((struct sockaddr_in*)res->ai_addr)->sin_addr;
		}
		if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		    (void*)&ip_mreq, sizeof(ip_mreq)) == -1)
			return -1;
		break;
	case PF_INET6:
		ip6_mreq.ipv6mr_multiaddr =
		    ((struct sockaddr_in6*)res_mcast->ai_addr)->sin6_addr;
		ip6_mreq.ipv6mr_interface = 0;
		if (setsockopt(s, IPPROTO_IP, IPV6_JOIN_GROUP,
		    (void*)&ip6_mreq, sizeof(ip6_mreq)) == -1)
			return -1;
		break;
	default:
		return -1;
	}

	return 0;
}
/* Join an mcast group described in res_mcast. */
ILIAS_NET2_LOCAL int
join_mcast(int s, struct addrinfo *res_mcast, const char *ifname)
{
	struct addrinfo		 hints, *ifa;
	struct addrinfo		*mc;
	int			 err;

	/* Configure hint. */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = res_mcast->ai_family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	if (ifname == NULL) {
		ifa = NULL;
	} else {
		err = getaddrinfo(ifname, NULL, &hints, &ifa);
		if (err) {
			warnx("getaddrinfo(%s): %s", ifname, gai_strerror(err));
			return err;
		}
	}

	err = -1;
	for (mc = res_mcast; mc != NULL; mc = mc->ai_next) {
		err = join_mcast1(s, mc, ifa);
		if (err == 0)
			break;
	}

	if (ifa)
		freeaddrinfo(ifa);
	return err;
}
/*
 * Create a socket that connects to a multicast network on the given port.
 *
 * af: the address family (PF_INET or PF_INET6)
 * mcastname: the name (IP/IPv6 address) of the multicast group
 * ifname: the name (IP/IPv6 address) of the interface on which to connect,
 *   or NULL to let the OS choose
 * servname: the port number or service name on which to connect
 */
ILIAS_NET2_LOCAL int
multicast_socket(int af, const char *mcastname, const char *ifname,
    const char *servname)
{
	struct addrinfo		 hints;
	struct addrinfo		*res_mcast, *res_lstn, *res;
	int			 err;
	int			 s;
	int			 scratch;

	/* Primary validation of parameters. */
	if (mcastname == NULL || mcastname[0] == '\0' ||
	    servname == NULL || servname[0] == '\0' ||
	    (ifname != NULL && ifname[0] == '\0')) {
		warnx("multicast socket arguments invalid");
		return -1;
	}

	/* Configure hint. */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	/* Turn string arguments into sockaddrs. */
	err = getaddrinfo(mcastname, servname, &hints, &res_mcast);
	if (err) {
		warnx("%s", gai_strerror(err));
		return -1;
	}
	err = getaddrinfo(NULL, servname, &hints, &res_lstn);
	if (err) {
		freeaddrinfo(res_mcast);
		warnx("%s", gai_strerror(err));
		return -1;
	}

	/* Start the socket. */
	s = -1;
	for (res = res_lstn; res != NULL; res = res->ai_next) {
		/* Create socket. */
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1) {
			warn("socket");
			continue;
		}

		/* Allow address reuse. */
		scratch = 1;
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
		    (void*)&scratch, sizeof(scratch)) == -1)
			warn("setsockopt(SO_REUSEADDR)");
		scratch = 1;
#ifdef SO_REUSEPORT
		if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT,
		    (void*)&scratch, sizeof(scratch)) == -1)
			warn("setsockopt(SO_REUSEPORT)");
#endif

		/* Bind to listen address. */
		if (bind(s, res->ai_addr, res->ai_addrlen) == -1) {
			warn("AAA bind");
			goto fail;
		}

		/* Join multicast group. */
		if (join_mcast(s, res_mcast, ifname)) {
			warn("join_mcast");
			goto fail;
		}

		/* GUARD */
		break;

fail:
		while (close(s) && errno == EINTR);
		s = -1;
	}

	freeaddrinfo(res_mcast);
	freeaddrinfo(res_lstn);
	return s;
}

/*
 * Bind to a normal UDP socket.
 *
 * af: the address family (PF_INET or PF_INET6)
 * ifname: the name (IP/IPv6 address) of the interface on which to connect,
 *   or NULL to let the OS choose
 * servname: the port number or service name on which to connect,
 *   or NULL to let the OS choose
 */
ILIAS_NET2_LOCAL int
normal_socket(int af, const char *ifname, const char *servname)
{
	struct addrinfo		 hints;
	struct addrinfo		*res_lstn, *res;
	int			 err;
	int			 s;
	struct sockaddr_in	 sa_in;
	struct sockaddr_in6	 sa_in6;
	static const struct in6_addr
				 in6addr_any = IN6ADDR_ANY_INIT;

	/* Primary validation of parameters. */
	if ((servname != NULL && servname[0] == '\0') ||
	    (ifname != NULL && ifname[0] == '\0')) {
		warnx("normal_socket: invalid arguments");
		return -1;
	}

	if (ifname == NULL && servname == NULL) {
		s = socket(af, SOCK_DGRAM, IPPROTO_UDP);
		if (s == -1) {
			warn("socket");
			return -1;
		}

		switch (af) {
		case PF_INET:
			memset(&sa_in, 0, sizeof(sa_in));
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
			sa_in.sin_len = sizeof(sa_in);
#endif
			sa_in.sin_family = AF_INET;
			sa_in.sin_port = ntohs(0);
			sa_in.sin_addr.s_addr = INADDR_ANY;
			if (bind(s, (struct sockaddr*)&sa_in,
			    sizeof(sa_in)) == -1) {
				warn("bind");
				while (close(s) && errno == EINTR);
				return -1;
			}
			break;
		case PF_INET6:
			memset(&sa_in6, 0, sizeof(sa_in6));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN
			sa_in6.sin6_len = sizeof(sa_in6);
#endif
			sa_in6.sin6_family = AF_INET6;
			sa_in6.sin6_port = ntohs(0);
			sa_in6.sin6_addr = in6addr_any;
			if (bind(s, (struct sockaddr*)&sa_in6,
			    sizeof(sa_in6)) == -1) {
				warn("bind");
				while (close(s) && errno == EINTR);
				return -1;
			}
			break;
		default:
			while (close(s) && errno == EINTR);
			return -1;
		}

		return s;
	}

	/* Configure hint. */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;

	/* Turn string arguments into sockaddrs. */
	err = getaddrinfo(ifname, servname, &hints, &res_lstn);
	if (err) {
		warnx("%s", gai_strerror(err));
		return -1;
	}

	/* Start the socket. */
	s = -1;
	for (res = res_lstn; res != NULL; res = res->ai_next) {
		/* Create socket. */
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1) {
			warn("socket");
			continue;
		}

		/* Bind to listen address. */
		if (bind(s, res->ai_addr, res->ai_addrlen) == -1) {
			warn("bind");
			goto fail;
		}

		/* GUARD */
		break;

fail:
		while (close(s) && errno == EINTR);
		s = -1;
	}

	freeaddrinfo(res_lstn);
	return s;
}


/* Handle multicast IO. */
ILIAS_NET2_LOCAL void
multicast_io(int sock, short what, void *state_ptr)
{
	struct n2ra_mcast	*state = state_ptr;

	assert(state->sock_mcast == sock);
}
/* Handle normal IO. */
ILIAS_NET2_LOCAL void
mcast_normal_io(int sock, short what, void *state_ptr)
{
	struct n2ra_mcast	*state = state_ptr;

	assert(state->sock_rx == sock);
}


/*
 * Create a remote-access for multicast traffic.
 */
ILIAS_NET2_EXPORT struct remote_access*
n2ra_init_mcast(struct net2_evbase *evbase, int af,
    const char *mcastname, const char *ifname, const char *servname,
    const char *secret)
{
	struct n2ra_mcast	*state;
	struct remote_access	*ra;
#ifdef WIN32
	u_long			 iMode = 1;
#else
	int			 fcntl_flags;
#endif

	if ((ra = malloc(sizeof(*ra))) == NULL) {
		warn("malloc");
		return NULL;
	}
	if ((state = malloc(sizeof(*state))) == NULL) {
		warn("malloc");
		free(ra);
		return NULL;
	}

	/* Prepare remote access result. */
	ra->state = state;
	ra->impl = &multicast_fun;

	/* mcast: create mcast socket. */
	state->sock_mcast = multicast_socket(af, mcastname, ifname, servname);
	if (state->sock_mcast == -1)
		goto fail_mcast;

	/* rx: create normal socket. */
	state->sock_rx = normal_socket(af, ifname, NULL);
	if (state->sock_rx == -1)
		goto fail_rx;

	/* nonblock: change sockets to non-blocking IO. */
#ifdef WIN32
	if (ioctlsocket(state->sock_mcast, FIONBIO, &iMode) ||
	    ioctlsocket(state->sock_rx,    FIONBIO, &iMode)) {
		warnx("ioctlsocket(FIONBIO, 1): %ld", WSAGetLastError());
		goto fail_nonblock;
	}
#else
	fcntl_flags = O_NONBLOCK;
	if (fcntl(state->sock_mcast, F_SETFL, &fcntl_flags) == -1 ||
	    fcntl(state->sock_rx,    F_SETFL, &fcntl_flags) == -1) {
		warn("fcntl(O_NONBLOCK)");
		goto fail_nonblock;
	}
#endif

	/* evbase: acquire ownership of event base. */
	if (evbase == NULL) {
		if ((evbase = net2_evbase_new()) == NULL) {
			warn("net2_evbase_new");
			goto fail_evbase;
		}
	} else
		net2_evbase_ref(evbase);
	state->evbase = evbase;

	/* evbase_setup: setup listeners for evbase. */
	state->ev_mcast = event_new(evbase->evbase, state->sock_mcast,
	    EV_READ | EV_PERSIST, multicast_io, state);
	state->ev_rx = event_new(evbase->evbase, state->sock_rx,
	    EV_READ | EV_PERSIST, mcast_normal_io, state);
	if (state->ev_mcast == NULL || state->ev_rx == NULL) {
		warn("event_new");
		goto fail_evbase_setup;
	}
	if (event_add(state->ev_mcast, NULL) == -1 ||
	    event_add(state->ev_rx, NULL) == -1) {
		warnx("event_add fail");
		goto fail_evbase_setup;
	}

	/* Copy network secret. */
	if ((state->secret = strdup(secret)) == NULL) {
		warn("strdup");
		goto fail_evbase_setup;
	}

	return ra;


	/*
	 * Failure unwind code.
	 */
fail_evbase_setup:
	if (state->ev_mcast) {
		event_del(state->ev_mcast);
		event_free(state->ev_mcast);
	}
	if (state->ev_rx) {
		event_del(state->ev_rx);
		event_free(state->ev_rx);
	}
	net2_evbase_release(evbase);
fail_evbase:
fail_nonblock:
	while (close(state->sock_rx) && errno == EINTR);
fail_rx:
	while (close(state->sock_mcast) && errno == EINTR);
fail_mcast:
	free(ra);
	free(state);
	return NULL;
}
