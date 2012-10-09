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
#ifndef ILIAS_NET2_ACCEPTOR_H
#define ILIAS_NET2_ACCEPTOR_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/tx_callback.h>
#include <sys/types.h>
#include <stdint.h>
#include <errno.h>

ILIAS_NET2__begin_cdecl

struct net2_acceptor_socket;
struct net2_acceptor;
struct net2_buffer;	/* From ilias/net2/buffer.h */
struct net2_tx_callback; /* From ilias/net2/tx_callback.h */
struct net2_pvlist;	/* From ilias/net2/protocol.h */

/* Acceptor socket function table. */
struct net2_acceptor_socket_fn {
	int	 flags;			/* Acceptor socket flags. */
#define NET2_SOCKET_RELIABLE	0x01	/* Reliable transmission: each
					 * datagram will arrive exactly
					 * once. */
#define NET2_SOCKET_SEQUENTIAL	0x02	/* Sequential delivery: each
					 * datagram will arrive in the
					 * order they were provided. */
#define NET2_SOCKET_SECURE	0x10	/* Socket is secure: communication
					 * is protected from tampering
					 * and eavesdropping.
					 *
					 * This is commonly implemented by
					 * a connection negotiating signing
					 * and encryption, but as an
					 * alternative, a loopback connection
					 * could be marked as secure. */

	/* Destructor. */
	void	(*destroy)(struct net2_acceptor_socket*);
	/* Mark acceptor socket as having data ready. */
	void	(*ready_to_send)(struct net2_acceptor_socket*);

	/* Optional accept processor. */
	void	(*accept)(struct net2_acceptor_socket*, struct net2_buffer*);
	/* Optional get_transmit processor. */
	int	(*get_transmit)(struct net2_acceptor_socket*,
		    struct net2_buffer**,
		    struct net2_tx_callback*, int first, size_t maxlen);

	/* Acquire PVlist. */
	int	(*get_pvlist)(struct net2_acceptor_socket*,
		    struct net2_pvlist*);
};

/* Acceptor function table. */
struct net2_acceptor_fn {
	/* Detach function. */
	void	(*detach)(struct net2_acceptor_socket*, struct net2_acceptor*);
	/* Attach function. */
	int	(*attach)(struct net2_acceptor_socket*, struct net2_acceptor*);
	/* Datagram acceptor. */
	void	(*accept)(struct net2_acceptor*, struct net2_buffer*);
	/* Check if the acceptor has pending transmissions. */
	int	(*get_transmit)(struct net2_acceptor*, struct net2_buffer**,
		    struct net2_tx_callback*, int first, size_t maxlen);
	/* On connection close event. */
	void	(*on_close)(struct net2_acceptor*);
};

/*
 * Acceptor socket.
 *
 * Holds on to a single acceptor.
 * Interfaces with that acceptor.
 */
struct net2_acceptor_socket {
	const struct net2_acceptor_socket_fn
				*fn;		/* Implementation functions. */
	struct net2_acceptor	*acceptor;	/* Current acceptor. */
	struct net2_workq	*wq;		/* Workq. */
	int			 state;		/* State bits. */
#define NET2_ACCSOCK_CLOSED	0x00000001	/* Connection was closed. */
};

/*
 * Acceptor.
 *
 * Generates messages to send and processes received messages.
 */
struct net2_acceptor {
	const struct net2_acceptor_fn
				*fn;		/* Acceptor function table. */
	struct net2_acceptor_socket
				*socket;	/* Socket implementation. */
};


ILIAS_NET2_EXPORT
int	 net2_acceptor_socket_init(struct net2_acceptor_socket*,
	    struct net2_workq*, const struct net2_acceptor_socket_fn*);
ILIAS_NET2_EXPORT
void	 net2_acceptor_socket_deinit(struct net2_acceptor_socket*);
ILIAS_NET2_EXPORT
void	 net2_acceptor_socket_destroy(struct net2_acceptor_socket*);
ILIAS_NET2_EXPORT
int	 net2_acceptor_attach(struct net2_acceptor_socket*,
	    struct net2_acceptor*);
ILIAS_NET2_EXPORT
void	 net2_acceptor_detach(struct net2_acceptor_socket*);
ILIAS_NET2_EXPORT
void	 net2_acceptor_socket_ready_to_send(struct net2_acceptor_socket*);
ILIAS_NET2_EXPORT
void	 net2_acceptor_ready_to_send(struct net2_acceptor*);
ILIAS_NET2_EXPORT
int	 net2_acceptor_get_transmit(struct net2_acceptor*,
	    struct net2_buffer**, struct net2_tx_callback*, int, size_t);
ILIAS_NET2_EXPORT
int	 net2_acceptor_socket_get_transmit(struct net2_acceptor_socket*,
	    struct net2_buffer**, struct net2_tx_callback*, int, size_t);
ILIAS_NET2_EXPORT
void	 net2_acceptor_accept(struct net2_acceptor*, struct net2_buffer*);
ILIAS_NET2_EXPORT
void	 net2_acceptor_socket_accept(struct net2_acceptor_socket*,
	    struct net2_buffer*);
ILIAS_NET2_EXPORT
int	 net2_acceptor_init(struct net2_acceptor*,
	    const struct net2_acceptor_fn*);
ILIAS_NET2_EXPORT
void	 net2_acceptor_deinit(struct net2_acceptor*);

ILIAS_NET2_EXPORT
int	 net2_acceptor_pvlist(struct net2_acceptor*, struct net2_pvlist*);
ILIAS_NET2_EXPORT
int	 net2_acceptor_socket_pvlist(struct net2_acceptor_socket*,
	    struct net2_pvlist*);
ILIAS_NET2_EXPORT
struct net2_workq
	*net2_acceptor_socket_workq(struct net2_acceptor_socket*);
ILIAS_NET2_EXPORT
struct net2_workq
	*net2_acceptor_workq(struct net2_acceptor*);

ILIAS_NET2_EXPORT
struct net2_acceptor_socket
	*net2_acceptor_socket(struct net2_acceptor*);
ILIAS_NET2_EXPORT
struct net2_acceptor
	*net2_acceptor(struct net2_acceptor_socket*);

ILIAS_NET2_EXPORT
void	 net2_acceptor_socket_close(struct net2_acceptor_socket*);

ILIAS_NET2__end_cdecl

#ifdef __cplusplus

#include <cassert>
#include <cerrno>
#include <exception>
#include <stdexcept>
#include <utility>

namespace ilias {


class buffer;
class workq;
class tx_callback;

class ILIAS_NET2_EXPORT abstract_acceptor :
	private net2_acceptor
{
private:
	static ILIAS_NET2_LOCAL void cwrap_detach(struct net2_acceptor_socket*,
	    struct net2_acceptor*) throw ();
	static ILIAS_NET2_LOCAL int cwrap_attach(struct net2_acceptor_socket*,
	    struct net2_acceptor*) throw ();
	static ILIAS_NET2_LOCAL void cwrap_accept(struct net2_acceptor*,
	    struct net2_buffer*) throw ();
	static ILIAS_NET2_LOCAL int cwrap_get_transmit(struct net2_acceptor*,
	    struct net2_buffer**, struct net2_tx_callback*, int, size_t) throw ();
	static ILIAS_NET2_LOCAL void cwrap_on_close(struct net2_acceptor*) throw ();

	static const net2_acceptor_fn m_vtable;

public:
	abstract_acceptor();
	virtual ~abstract_acceptor() throw ();

#if HAS_DELETE_FN
	abstract_acceptor(const abstract_acceptor&) = delete;
	abstract_acceptor& operator=(const abstract_acceptor&) = delete;
#else
private:
	abstract_acceptor(const abstract_acceptor&);
	abstract_acceptor& operator=(const abstract_acceptor&);
#endif


private:
	virtual void detach(struct net2_acceptor_socket*) = 0;
	virtual int attach(struct net2_acceptor_socket*) = 0;
	virtual void accept(buffer&) = 0;
	virtual int get_transmit(buffer&, tx_callback&, int, size_t) = 0;
	virtual void on_close() = 0;


protected:
#if HAS_RVALUE_REF
	workq&& get_workq() const throw (std::invalid_argument);
#else
	workq get_workq() const throw (std::invalid_argument);
#endif

	void ready_to_send() const throw ();
};

class ILIAS_NET2_EXPORT abstract_acceptor_socket :
	private net2_acceptor_socket
{
private:
	static void cwrap_destroy(struct net2_acceptor_socket*) throw ();
	static void cwrap_ready_to_send(struct net2_acceptor_socket*) throw ();
	static void cwrap_accept(struct net2_acceptor_socket*,
	    struct net2_buffer*) throw ();
	static int cwrap_get_transmit(struct net2_acceptor_socket*,
	    struct net2_buffer**,
	    struct net2_tx_callback*, int, size_t) throw ();
	static int cwrap_get_pvlist(struct net2_acceptor_socket*,
	    struct net2_pvlist*) throw ();

	static const net2_acceptor_socket_fn m_vtable;

public:
	abstract_acceptor_socket(const workq&);
	virtual ~abstract_acceptor_socket() throw ();

#if HAS_DELETE_FN
	abstract_acceptor_socket(const abstract_acceptor_socket&) = delete;
	abstract_acceptor_socket& operator=(const abstract_acceptor_socket&) = delete;
#else
private:
	abstract_acceptor_socket(const abstract_acceptor_socket&);
	abstract_acceptor_socket& operator=(const abstract_acceptor_socket&);
#endif


private:
	virtual void ready_to_send() = 0;
	virtual void accept(buffer&) = 0;
	virtual int get_transmit(buffer&, tx_callback&, int, size_t) = 0;
	virtual int get_pvlist(struct net2_pvlist*) = 0;


protected:
#if HAS_RVALUE_REF
	workq&& get_workq() const throw (std::invalid_argument);
#else
	workq get_workq() const throw (std::invalid_argument);
#endif
};


inline
abstract_acceptor::abstract_acceptor()
{
	int error = net2_acceptor_init(this, &m_vtable);
	switch (error) {
	case ENOMEM:
		throw std::bad_alloc();
	case EINVAL:
		throw std::invalid_argument("net2_acceptor_init");
	case 0:
		break;
	default:
		throw std::exception();
	}
}

inline
#if HAS_RVALUE_REF
workq&&
#else
workq
#endif
abstract_acceptor::get_workq() const throw (std::invalid_argument)
{
	struct net2_workq *wq = net2_acceptor_workq(const_cast<abstract_acceptor*>(this));
	if (wq == NULL)
		throw std::invalid_argument("unconnected acceptor has no workq");

	workq rv(wq);

#if HAS_RVALUE_REF
	return std::move(rv);
#else
	return rv;
#endif
}

inline void
abstract_acceptor::ready_to_send() const throw ()
{
	net2_acceptor_ready_to_send(const_cast<abstract_acceptor*>(this));
}


inline
abstract_acceptor_socket::abstract_acceptor_socket(const workq& wq)
{
	int error = net2_acceptor_socket_init(this, wq.c_workq(), &m_vtable);
	switch (error) {
	case ENOMEM:
		throw std::bad_alloc();
	case EINVAL:
		throw std::invalid_argument("net2_acceptor_init");
	case 0:
		break;
	default:
		throw std::exception();
	}
}

inline
#if HAS_RVALUE_REF
workq&&
#else
workq
#endif
abstract_acceptor_socket::get_workq() const throw (std::invalid_argument)
{
	struct net2_workq *wq = net2_acceptor_socket_workq(const_cast<abstract_acceptor_socket*>(this));
	if (wq == NULL)
		throw std::invalid_argument("unconnected acceptor has no workq");

	workq rv(wq);

#if HAS_RVALUE_REF
	return std::move(rv);
#else
	return rv;
#endif
}


}


#endif /* __cplusplus */
#endif /* ILIAS_NET2_ACCEPTOR_H */
