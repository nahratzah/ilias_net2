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
#ifndef ILIAS_NET2_TX_CALLBACK_H
#define ILIAS_NET2_TX_CALLBACK_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/workq.h>
#include <ilias/net2/config.h>
#include <stdlib.h>

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <ilias/net2/bsd_compat/queue.h>
#endif

ILIAS_NET2__begin_cdecl


struct net2_workq;	/* From ilias/net2/workq.h */

typedef void (*net2_tx_callback_fn)(void*, void*);

/*
 * Optional entry queue.
 *
 * Can be used to cancel outstanding txcb.
 */
struct net2_txcb_entryq {
	struct net2_mutex	*mtx;
	TAILQ_HEAD(, net2_txcb_entry)
				 entries;
};

/* TX callbacks. */
struct net2_tx_callback {
	struct net2_mutex	*mtx;
	TAILQ_HEAD(, net2_txcb_entry)
				 entries;
};


ILIAS_NET2_EXPORT
int	net2_txcb_init(struct net2_tx_callback*);
ILIAS_NET2_EXPORT
void	net2_txcb_deinit(struct net2_tx_callback*);
ILIAS_NET2_EXPORT
void	net2_txcb_ack(struct net2_tx_callback*);
ILIAS_NET2_EXPORT
void	net2_txcb_nack(struct net2_tx_callback*);
ILIAS_NET2_EXPORT
void	net2_txcb_timeout(struct net2_tx_callback*);
ILIAS_NET2_EXPORT
void	net2_txcb_merge(struct net2_tx_callback*, struct net2_tx_callback*);
ILIAS_NET2_EXPORT
int	net2_txcb_add(struct net2_tx_callback*, struct net2_workq*,
	    struct net2_txcb_entryq*,
	    net2_tx_callback_fn, net2_tx_callback_fn, net2_tx_callback_fn,
	    net2_tx_callback_fn, void*, void*);

ILIAS_NET2_EXPORT
int	 net2_txcb_entryq_init(struct net2_txcb_entryq*);
ILIAS_NET2_EXPORT
void	 net2_txcb_entryq_deinit(struct net2_txcb_entryq*);
ILIAS_NET2_EXPORT
int	 net2_txcb_entryq_empty(struct net2_txcb_entryq*, int which);
ILIAS_NET2_EXPORT
void	 net2_txcb_entryq_clear(struct net2_txcb_entryq*, int which);
ILIAS_NET2_EXPORT
void	 net2_txcb_entryq_merge(struct net2_txcb_entryq*,
	    struct net2_txcb_entryq*);

#define NET2_TXCB_EQ_TIMEOUT	0x00000001
#define NET2_TXCB_EQ_ACK	0x00000002
#define NET2_TXCB_EQ_NACK	0x00000004
#define NET2_TXCB_EQ_DESTROY	0x00000008
#define NET2_TXCB_EQ_ALL						\
	(NET2_TXCB_EQ_TIMEOUT |						\
	 NET2_TXCB_EQ_ACK |						\
	 NET2_TXCB_EQ_NACK |						\
	 NET2_TXCB_EQ_DESTROY)

ILIAS_NET2_EXPORT
int	net2_txcb_empty(struct net2_tx_callback*);


ILIAS_NET2__end_cdecl

#ifdef __cplusplus

namespace ilias {


class tx_callback
{
private:
	mutable struct net2_tx_callback m_txcb;

public:
	tx_callback();
	~tx_callback() throw ();
#if HAS_RVALUE_REF
	tx_callback(tx_callback&&);
#endif

#if HAS_DELETED_FN
	tx_callback(const tx_callback&) = delete;
	tx_callback& operator=(const tx_callback&) = delete;
#else
private:
	tx_callback(const tx_callback&);
	tx_callback& operator=(const tx_callback&);
#endif

public:
#if HAS_RVALUE_REF
	void merge(tx_callback&& other);
#endif
	void merge(tx_callback& other);

	void merge_out(tx_callback&) throw ();
	void merge_out(struct net2_tx_callback*) throw ();

	bool empty() const throw ();

	void ack() throw ();
	void nack() throw ();
	void timeout() throw ();
};


class txcb_entryq
{
private:
	mutable struct net2_txcb_entryq m_txcbq;

public:
	static const int TIMEOUT = NET2_TXCB_EQ_TIMEOUT;
	static const int ACK = NET2_TXCB_EQ_ACK;
	static const int NACK = NET2_TXCB_EQ_NACK;
	static const int DESTROY = NET2_TXCB_EQ_DESTROY;
	static const int ALL = NET2_TXCB_EQ_ALL;

	txcb_entryq();
	~txcb_entryq() throw ();

#if HAS_RVALUE_REF
	txcb_entryq(txcb_entryq&&);
#endif

#if HAS_DELETED_FN
	txcb_entryq(const txcb_entryq&) = delete;
	txcb_entryq& operator=(const txcb_entryq&) = delete;
#else
private:
	txcb_entryq(const txcb_entryq&);
	txcb_entryq& operator=(const txcb_entryq&);
#endif

	bool empty(int = ALL) const throw ();
	void clear(int = ALL) throw ();
#if HAS_RVALUE_REF
	void merge(txcb_entryq&&) throw ();
#endif
	void merge(txcb_entryq&) throw ();
};


inline
tx_callback::tx_callback()
{
	int error = net2_txcb_init(&this->m_txcb);
	switch (error) {
	case ENOMEM:
		throw std::bad_alloc();
	case EINVAL:
		throw std::invalid_argument("tx callback initialization");
	case 0:
		break;
	default:
		throw std::exception();
	}
}

#if HAS_RVALUE_REF
inline
tx_callback::tx_callback(tx_callback&& o)
{
	int error = net2_txcb_init(&this->m_txcb);
	switch (error) {
	case ENOMEM:
		throw std::bad_alloc();
	case EINVAL:
		throw std::invalid_argument("tx callback initialization");
	case 0:
		break;
	default:
		throw std::exception();
	}

	this->merge(o);
}
#endif /* HAS_RVALUE_REF */

inline
tx_callback::~tx_callback() throw ()
{
	net2_txcb_deinit(&this->m_txcb);
}

#if HAS_RVALUE_REF
inline void
tx_callback::merge(tx_callback&& o)
{
	net2_txcb_merge(&this->m_txcb, &o.m_txcb);
}
#endif /* HAS_RVALUE_REF */

inline void
tx_callback::merge(tx_callback& o)
{
	net2_txcb_merge(&this->m_txcb, &o.m_txcb);
}

inline void
tx_callback::merge_out(tx_callback& o) throw ()
{
	this->merge_out(&o.m_txcb);
}

inline void
tx_callback::merge_out(struct net2_tx_callback *o) throw ()
{
	net2_txcb_merge(o, &this->m_txcb);
}

inline bool
tx_callback::empty() const throw ()
{
	return net2_txcb_empty(&this->m_txcb);
}

inline void
tx_callback::ack() throw ()
{
	net2_txcb_ack(&this->m_txcb);
}

inline void
tx_callback::nack() throw ()
{
	net2_txcb_nack(&this->m_txcb);
}

inline void
tx_callback::timeout() throw ()
{
	net2_txcb_timeout(&this->m_txcb);
}


inline
txcb_entryq::txcb_entryq()
{
	int error = net2_txcb_entryq_init(&this->m_txcbq);
	switch (error) {
	case ENOMEM:
		throw std::bad_alloc();
	case EINVAL:
		throw std::invalid_argument("tx callback initialization");
	case 0:
		break;
	default:
		throw std::exception();
	}
}

inline
txcb_entryq::~txcb_entryq() throw ()
{
	net2_txcb_entryq_deinit(&this->m_txcbq);
}

#if HAS_RVALUE_REF
inline
txcb_entryq::txcb_entryq(txcb_entryq&& o)
{
	int error = net2_txcb_entryq_init(&this->m_txcbq);
	switch (error) {
	case ENOMEM:
		throw std::bad_alloc();
	case EINVAL:
		throw std::invalid_argument("tx callback initialization");
	case 0:
		break;
	default:
		throw std::exception();
	}

	net2_txcb_entryq_merge(&this->m_txcbq, &o.m_txcbq);
}
#endif

inline bool
txcb_entryq::empty(int which) const throw ()
{
	return net2_txcb_entryq_empty(&this->m_txcbq, which);
}

inline void
txcb_entryq::clear(int which) throw ()
{
	net2_txcb_entryq_clear(&this->m_txcbq, which);
}

inline void
txcb_entryq::merge(txcb_entryq&& o) throw ()
{
	net2_txcb_entryq_merge(&this->m_txcbq, &o.m_txcbq);
}

inline void
txcb_entryq::merge(txcb_entryq& o) throw ()
{
	net2_txcb_entryq_merge(&this->m_txcbq, &o.m_txcbq);
}


}

#endif /* __cplusplus */

#endif /* ILIAS_NET2_TX_CALLBACK_H */
