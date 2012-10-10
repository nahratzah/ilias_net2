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
#ifndef ILIAS_NET2_CONNECTION_H
#define ILIAS_NET2_CONNECTION_H

#include <ilias/net2/types.h>
#include <ilias/net2/connstats.h>
#include <ilias/net2/connwindow.h>
#include <ilias/net2/conn_negotiator.h>
#include <ilias/net2/conn_keys.h>
#include <ilias/net2/acceptor.h>
#include <ilias/net2/workq.h>

ILIAS_NET2__begin_cdecl


struct packet_header;

/*
 * A net2_connection receive datagram.
 *
 * Iff error is set, buf is NULL.
 * Iff buf is set, error is OK (no error).
 */
struct net2_conn_receive {
	/* Buffer that is received. */
	struct net2_buffer	*buf;
	/* Error that is received. */
	int			 error;

#define NET2_CONNRECV_OK	0	/* No error, buf is set. */
#define NET2_CONNRECV_REJECT	1	/* Connection closed.
					 * - host down
					 * - host unreachable
					 * - network unreachable
					 * - connection refused
					 * - not connected
					 */

	TAILQ_ENTRY(net2_conn_receive)
				 recvq;	/* Link into connection receive list. */
};

/* Basic properties of a connection. */
struct net2_connection {
	struct net2_acceptor_socket
				 n2c_socket;	/* Acceptor socket base. */
	struct net2_conn_keys	 n2c_keys;
	struct net2_conn_negotiator
				 n2c_negotiator; /* Protocol negotiator. */

	struct net2_mutex	*n2c_recvmtx,	/* Protect recvq. */
				*n2c_sendmtx;	/* Protect sendq. */
	TAILQ_HEAD(, net2_conn_receive)
				 n2c_recvq;	/* List of received data. */
	TAILQ_HEAD(, net2_conn_txgather)
				 n2c_sendq;	/* List of outstanding tx. */
	size_t			 n2c_recvqsz;	/* Size of n2c_recvq. */
	struct net2_workq_job	 n2c_recv_ev;	/* Handle received data. */

	struct net2_connwindow	 n2c_window;	/* Low level window. */
	struct net2_connstats	 n2c_stats;	/* Connection stats. */

	size_t			 n2c_stealth_bytes; /* Bytes received. */
	int			 n2c_stealth;	/* Stealth state flags. */
#define NET2_CONN_STEALTH_ENABLED	0x00000001	/* Enable stealth. */
#define NET2_CONN_STEALTH_UNSTEALTH	0x00000002	/* Disengaged. */
#define NET2_CONN_STEALTH_SEND_OK	0x00000004	/* Can send. */
#define NET2_CONN_STEALTH_WANTSEND	0x00000008	/* Want-to-send. */

	/* XXX more members as required. */
};


ILIAS_NET2_EXPORT
int	 net2_connection_init(struct net2_connection*,
	    struct net2_ctx*, struct net2_workq*,
	    const struct net2_acceptor_socket_fn*);
ILIAS_NET2_EXPORT
void	 net2_connection_deinit(struct net2_connection*);
ILIAS_NET2_EXPORT
void	 net2_connection_destroy(struct net2_connection*);
ILIAS_NET2_EXPORT
void	 net2_connection_recv(struct net2_connection*,
	    struct net2_conn_receive*);

ILIAS_NET2_EXPORT
struct net2_promise
	*net2_conn_gather_tx(struct net2_connection*, size_t);
ILIAS_NET2_EXPORT
int	 net2_conn_get_pvlist(struct net2_acceptor_socket*,
	    struct net2_pvlist*);
ILIAS_NET2_EXPORT
void	 net2_conn_set_stealth(struct net2_connection*);

static __inline void
net2_connection_close(struct net2_connection *c)
{
	net2_acceptor_socket_close(&c->n2c_socket);
}


ILIAS_NET2__end_cdecl

#ifdef __cplusplus

namespace ilias {

class buffer;
class workq;

class abstract_connection :
	private net2_connection
{
private:
	static ILIAS_NET2_LOCAL abstract_connection* conn_cast(struct net2_acceptor_socket*) ILIAS_NET2_NOTHROW;
	static ILIAS_NET2_LOCAL void cwrap_destroy(struct net2_acceptor_socket*) ILIAS_NET2_NOTHROW;
	static ILIAS_NET2_LOCAL void cwrap_ready_to_send(struct net2_acceptor_socket*) ILIAS_NET2_NOTHROW;
	static ILIAS_NET2_LOCAL void cwrap_accept(struct net2_acceptor_socket*,
	    struct net2_buffer*) ILIAS_NET2_NOTHROW;
	static ILIAS_NET2_LOCAL int cwrap_get_transmit(struct net2_acceptor_socket*,
	    struct net2_buffer**,
	    struct net2_tx_callback*, int, size_t) ILIAS_NET2_NOTHROW;
	static ILIAS_NET2_LOCAL int cwrap_get_pvlist(struct net2_acceptor_socket*,
	    struct net2_pvlist*) ILIAS_NET2_NOTHROW;

	static const net2_acceptor_socket_fn m_vtable;

public:
	abstract_connection(struct net2_ctx*, const workq&);
	virtual ~abstract_connection() ILIAS_NET2_NOTHROW;

#if HAS_DELETE_FN
	abstract_connection(const abstract_connection&) = delete;
	abstract_connection& operator=(const abstract_connection&) = delete;
#else
private:
	abstract_connection(const abstract_connection&);
	abstract_connection& operator=(const abstract_connection&);
#endif


private:
	virtual void ready_to_send() = 0;
	virtual void accept(buffer&) = 0;
	virtual int get_transmit(buffer&, tx_callback&, int, size_t) = 0;
	virtual int get_pvlist(struct net2_pvlist*) = 0;


protected:
#if HAS_RVALUE_REF
	workq&& get_workq() const ILIAS_NET2_NOTHROW;
#else
	workq get_workq() const ILIAS_NET2_NOTHROW;
#endif
};


inline
abstract_connection::abstract_connection(struct net2_ctx* nctx, const workq& wq)
{
	net2_connection_init(this, nctx, wq.c_workq(), &m_vtable);
}

inline
#if HAS_RVALUE_REF
workq&&
#else
workq
#endif
abstract_connection::get_workq() const ILIAS_NET2_NOTHROW
{
	workq wq(net2_acceptor_socket_workq(&const_cast<abstract_connection*>(this)->n2c_socket));

#if HAS_RVALUE_REF
	return std::move(wq);
#else
	return wq;
#endif
}


}

#endif /* __cplusplus */
#endif /* ILIAS_NET2_CONNECTION_H */
