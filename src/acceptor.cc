#include <ilias/net2/acceptor.h>
#include <ilias/net2/buffer.h>

namespace ilias {


ILIAS_NET2_LOCAL void
abstract_acceptor::cwrap_detach(struct net2_acceptor_socket* as,
    struct net2_acceptor *a) throw ()
{
	static_cast<ilias::abstract_acceptor*>(a)->detach(as);
}

ILIAS_NET2_LOCAL int
abstract_acceptor::cwrap_attach(struct net2_acceptor_socket *as,
    struct net2_acceptor *a) throw ()
{
	try {
		return static_cast<ilias::abstract_acceptor*>(a)->attach(as);
	} catch (const std::bad_alloc&) {
		return ENOMEM;
	} catch (const std::invalid_argument&) {
		return EINVAL;
	} catch (...) {
		return EIO;
	}
}

ILIAS_NET2_LOCAL void
abstract_acceptor::cwrap_accept(struct net2_acceptor *a,
    struct net2_buffer *buf) throw ()
{
	buffer b(buf);

	try {
		static_cast<ilias::abstract_acceptor*>(a)->accept(b);
	} catch (...) {
		b.release();
		throw;
	}

	b.release();
}

ILIAS_NET2_LOCAL int
abstract_acceptor::cwrap_get_transmit(struct net2_acceptor *a,
    struct net2_buffer **buf,
    struct net2_tx_callback *txcb, int first, size_t maxlen) throw ()
{
	assert(!*buf);

	ilias::buffer b = ilias::BUFFER_CREATE;
	int rv;

	try {
		rv = static_cast<ilias::abstract_acceptor*>(a)->get_transmit(b, txcb,
		    first, maxlen);
	} catch (const std::bad_alloc&) {
		return ENOMEM;
	} catch (const std::invalid_argument&) {
		return EINVAL;
	} catch (...) {
		return EIO;
	}

	if (rv == 0)
		*buf = b.release();
	return rv;
}

ILIAS_NET2_LOCAL void
abstract_acceptor::cwrap_on_close(struct net2_acceptor *a) throw ()
{
	static_cast<ilias::abstract_acceptor*>(a)->on_close();
}


const net2_acceptor_fn abstract_acceptor::m_vtable = {
	&abstract_acceptor::cwrap_detach,
	&abstract_acceptor::cwrap_attach,
	&abstract_acceptor::cwrap_accept,
	&abstract_acceptor::cwrap_get_transmit,
	&abstract_acceptor::cwrap_on_close
};

abstract_acceptor::~abstract_acceptor() throw ()
{
	net2_acceptor_deinit(this);
}


ILIAS_NET2_LOCAL void
abstract_acceptor_socket::cwrap_destroy(struct net2_acceptor_socket *as) throw ()
{
	delete static_cast<abstract_acceptor_socket*>(as);
}

ILIAS_NET2_LOCAL void
abstract_acceptor_socket::cwrap_ready_to_send(struct net2_acceptor_socket *as) throw ()
{
	static_cast<abstract_acceptor_socket*>(as)->ready_to_send();
}

ILIAS_NET2_LOCAL void
abstract_acceptor_socket::cwrap_accept(struct net2_acceptor_socket *as,
    struct net2_buffer *buf) throw ()
{
	buffer b(buf);

	try {
		static_cast<ilias::abstract_acceptor_socket*>(as)->accept(b);
	} catch (...) {
		b.release();
		throw;
	}

	b.release();
}

ILIAS_NET2_LOCAL int
abstract_acceptor_socket::cwrap_get_transmit(struct net2_acceptor_socket *as,
    struct net2_buffer **buf,
    struct net2_tx_callback *txcb, int first, size_t maxlen) throw ()
{
	assert(!*buf);

	ilias::buffer b = ilias::BUFFER_CREATE;
	int rv;

	try {
		rv = static_cast<ilias::abstract_acceptor_socket*>(as)->get_transmit(b, txcb,
		    first, maxlen);
	} catch (const std::bad_alloc&) {
		return ENOMEM;
	} catch (const std::invalid_argument&) {
		return EINVAL;
	} catch (...) {
		return EIO;
	}

	if (rv == 0)
		*buf = b.release();
	return rv;
}

ILIAS_NET2_LOCAL int
abstract_acceptor_socket::cwrap_get_pvlist(struct net2_acceptor_socket *as,
    struct net2_pvlist *pv) throw ()
{
	try {
		return static_cast<abstract_acceptor_socket*>(as)->get_pvlist(pv);
	} catch (const std::bad_alloc&) {
		return ENOMEM;
	} catch (const std::invalid_argument&) {
		return EINVAL;
	} catch (...) {
		return EIO;
	}
}

const net2_acceptor_socket_fn abstract_acceptor_socket::m_vtable = {
	0,
	abstract_acceptor_socket::cwrap_destroy,
	abstract_acceptor_socket::cwrap_ready_to_send,
	abstract_acceptor_socket::cwrap_accept,
	abstract_acceptor_socket::cwrap_get_transmit,
	abstract_acceptor_socket::cwrap_get_pvlist
};

abstract_acceptor_socket::~abstract_acceptor_socket() throw ()
{
	net2_acceptor_socket_deinit(this);
}


}
