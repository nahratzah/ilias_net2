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
#include <ilias/net2/connection.h>
#include <ilias/net2/acceptor.h>
#include <ilias/net2/buffer.h>

namespace ilias {


ILIAS_NET2_LOCAL abstract_connection*
abstract_connection::conn_cast(struct net2_acceptor_socket *as) ILIAS_NET2_NOTHROW
{
	net2_connection *c = reinterpret_cast<net2_connection*>(as);
	assert(&c->n2c_socket == as);
	return static_cast<abstract_connection*>(c);
}


ILIAS_NET2_LOCAL void
abstract_connection::cwrap_destroy(struct net2_acceptor_socket *as) ILIAS_NET2_NOTHROW
{
	delete conn_cast(as);
}

ILIAS_NET2_LOCAL void
abstract_connection::cwrap_ready_to_send(struct net2_acceptor_socket *as) ILIAS_NET2_NOTHROW
{
	conn_cast(as)->ready_to_send();
}

ILIAS_NET2_LOCAL void
abstract_connection::cwrap_accept(struct net2_acceptor_socket *as,
    struct net2_buffer *buf) ILIAS_NET2_NOTHROW
{
	buffer b(buf);

	try {
		conn_cast(as)->accept(b);
	} catch (...) {
		b.release();
		throw;
	}

	b.release();
}

ILIAS_NET2_LOCAL int
abstract_connection::cwrap_get_transmit(struct net2_acceptor_socket *as,
    struct net2_buffer **buf,
    struct net2_tx_callback *c_txcb, int first, size_t maxlen) ILIAS_NET2_NOTHROW
{
	assert(!*buf);

	buffer b = ilias::BUFFER_CREATE;
	tx_callback txcb;
	int rv;

	try {
		rv = conn_cast(as)->get_transmit(b, txcb,
		    first, maxlen);
	} catch (const std::bad_alloc&) {
		return ENOMEM;
	} catch (const std::invalid_argument&) {
		return EINVAL;
	} catch (...) {
		return EIO;
	}

	if (rv == 0) {
		*buf = b.release();
		txcb.merge_out(c_txcb);
	}
	return rv;
}

ILIAS_NET2_LOCAL int
abstract_connection::cwrap_get_pvlist(struct net2_acceptor_socket *as,
    struct net2_pvlist *pv) ILIAS_NET2_NOTHROW
{
	try {
		return conn_cast(as)->get_pvlist(pv);
	} catch (const std::bad_alloc&) {
		return ENOMEM;
	} catch (const std::invalid_argument&) {
		return EINVAL;
	} catch (...) {
		return EIO;
	}
}

const net2_acceptor_socket_fn abstract_connection::m_vtable = {
	0,
	abstract_connection::cwrap_destroy,
	abstract_connection::cwrap_ready_to_send,
	abstract_connection::cwrap_accept,
	abstract_connection::cwrap_get_transmit,
	abstract_connection::cwrap_get_pvlist
};

abstract_connection::~abstract_connection() ILIAS_NET2_NOTHROW
{
	net2_connection_deinit(this);
}


}
