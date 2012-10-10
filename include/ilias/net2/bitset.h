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
#ifndef ILIAS_NET2_BITSET_H
#define ILIAS_NET2_BITSET_H

#include <ilias/net2/ilias_net2_export.h>
#include <sys/types.h>
#include <stdint.h>

ILIAS_NET2__begin_cdecl

struct net2_bitset {
	size_t			 size;
	union {
		uintptr_t	*indir;
		uintptr_t	 immed;
	};
};


#define net2_bitset_size(_s)	((_s)->size + 0)
ILIAS_NET2_EXPORT
void	net2_bitset_init(struct net2_bitset*);
ILIAS_NET2_EXPORT
int	net2_bitset_init_copy(struct net2_bitset*, const struct net2_bitset*);
ILIAS_NET2_EXPORT
void	net2_bitset_init_move(struct net2_bitset*, struct net2_bitset*);
ILIAS_NET2_EXPORT
void	net2_bitset_deinit(struct net2_bitset*);
ILIAS_NET2_EXPORT
int	net2_bitset_get(const struct net2_bitset*, size_t, int*);
ILIAS_NET2_EXPORT
int	net2_bitset_set(struct net2_bitset*, size_t, int, int*);
ILIAS_NET2_EXPORT
int	net2_bitset_resize(struct net2_bitset*, size_t, int);
ILIAS_NET2_EXPORT
int	net2_bitset_allset(const struct net2_bitset*);
ILIAS_NET2_EXPORT
int	net2_bitset_allclear(const struct net2_bitset*);

ILIAS_NET2__end_cdecl

#ifdef __cplusplus

#include <stdexcept>
#include <exception>

namespace ilias {

class bitset :
	public net2_bitset
{
private:
	class boolref;

public:
	typedef size_t size_type;

	/* XXX should write an iterator class. */

	bitset() ILIAS_NET2_NOTHROW;
	bitset(const bitset&);
#if HAS_RVALUE_REF
	bitset(bitset&&) ILIAS_NET2_NOTHROW;
#endif
	~bitset() ILIAS_NET2_NOTHROW;

	bitset& operator= (const bitset&);
	bitset& operator= (bitset&&) ILIAS_NET2_NOTHROW;
	bool operator[](size_type) const;
	boolref operator[](size_type);

	void resize(size_type, bool = false);
	bool empty() const ILIAS_NET2_NOTHROW;
	size_type size() const ILIAS_NET2_NOTHROW;

	bool allset() const ILIAS_NET2_NOTHROW;
	bool allclear() const ILIAS_NET2_NOTHROW;
};

class bitset::boolref
{
private:
	bitset& m_bitset;
	bitset::size_type m_idx;

public:
	boolref(bitset&, bitset::size_type) ILIAS_NET2_NOTHROW;

	operator bool() const;
	boolref& operator=(bool);
	bool exchange(bool);
}


inline
bitset::bitset() ILIAS_NET2_NOTHROW
{
	net2_bitset_init(this);
}

inline
bitset::bitset(const bitset& o)
{
	int error = net2_bitset_init_copy(this, &o);
	switch (error) {
	case 0:
		break;
	case ENOMEM:
		throw std::bad_alloc();
	case EINVAL:
		throw std::invalid_argument("bitset copy");
	default:
		throw std::exception();
	}
}

#if HAS_RVALUE_REF
inline
bitset::bitset(bitset&& o) ILIAS_NET2_NOTHROW
{
	net2_bitset_init_move(this, &o);
}
#endif

inline
bitset::~bitset() ILIAS_NET2_NOTHROW
{
	net2_bitset_deinit(this);
}

inline bitset&
bitset::operator=(const bitset& o)
{
	net2_bitset tmp;

	net2_bitset_init_move(&tmp, this);
	int error = net2_bitset_init_copy(this, &o);
	if (error == 0) {
		net2_bitset_deinit(&tmp);
		return *this;
	}
	net2_bitset_init_move(this, &tmp);

	switch (error) {
	case ENOMEM:
		throw std::bad_alloc();
	case EINVAL:
		throw std::invalid_argument("bitset copy");
	default:
		throw std::exception();
	}
}

inline bitset&
bitset::operator=(bitset&& o) ILIAS_NET2_NOTHROW
{
	net2_bitset_deinit(this);
	net2_bitset_init_move(this, &o);
}

inline bool
bitset::operator[](size_type idx) const
{
	int rv;

	int error = net2_bitset_get(this, idx, &rv);
	switch (error) {
	case 0:
		return (rv != 0);
	case EINVAL:
		throw std::invalid_argument("bitset operator[]");
	default:
		throw std::exception();
	}
}

inline bitset::boolref
bitset::operator[](size_type idx)
{
	if (idx >= this->size())
		throw std::invalid_argument("bitset operator[]");
	return boolref(*this, idx);
}

inline void
bitset::resize(size_type len, bool newval)
{
	net2_bitset_resize(this, len, newval);
}

inline bool
bitset::empty() const ILIAS_NET2_NOTHROW
{
	return (net2_bitset_size(this) == 0);
}

inline bitset::size_type
bitset::size() const ILIAS_NET2_NOTHROW
{
	return net2_bitset_size(this);
}

inline bool
bitset::allset() const ILIAS_NET2_NOTHROW
{
	return net2_bitset_allset(this);
}

inline bool
bitset::allclear() const ILIAS_NET2_NOTHROW
{
	return net2_bitset_allclear(this);
}


inline
bitset::boolref::boolref(bitset& b, bitset::size_type idx) ILIAS_NET2_NOTHROW :
	m_bitset(b),
	m_idx(idx)
{
	return;
}

inline
bitset::boolref::operator bool() const
{
	return m_bitset[m_idx];
}

inline boolref&
bitset::boolref::operator=(bool newval)
{
	int error = net2_bitset_set(&m_bitset, m_idx, newval, NULL);
	switch (error) {
	case 0:
		break;
	case EINVAL:
		throw std::invalid_argument("bitset assignment");
	default:
		throw std::exception();
	}
}

inline bool
bitset::boolref::exchange(bool)
{
	int rv;

	int error = net2_bitset_set(&m_bitset, m_idx, newval, &rv);
	switch (error) {
	case 0:
		break;
	case EINVAL:
		throw std::invalid_argument("bitset assignment");
	default:
		throw std::exception();
	}
	return (rv != 0);
}


}


#endif /* __cplusplus */

#endif /* ILIAS_NET2_BITSET_H */
