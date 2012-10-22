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
#ifndef ILIAS_NET2_BUFFER_H
#define ILIAS_NET2_BUFFER_H
/*
 * Additional support functions for libevents buffers.
 */

#include <ilias/net2/ilias_net2_export.h>
#include <sys/types.h>
#include <stdint.h>

#ifdef WIN32
/* Redefine iovec type and fields to wsabuf. */
#include <WinSock2.h>

#define iovec		_WSABUF
#define	iov_len		len
#define iov_base	buf
#else
#include <sys/uio.h>
#endif


namespace ilias {


template<typename T>
class realloc_allocator
{
public:
	typedef size_t size_type;
	typedef ptrdiff_t difference_type;

	typedef typename std::remove_reference<T>::type element_type;
	typedef element_type* pointer;
	typedef const element_type* const_pointer;
	typedef element_type& reference;
	typedef const element_type& const_reference;

private:
	static size_type element_size = sizeof(element_type);

public:
	pointer
	allocate(size_type n, typename realloc_iterator<void>::pointer hint)
	{
		if (n > this->maxsize())
			throw std::bad_alloc();

		const pointer ptr = reinterpret_cast<pointer>(net2_malloc(n * this->element_size));
		if (!ptr)
			throw std::bad_alloc();
		return ptr;
	}

	pointer
	deallocate(pointer ptr, size_type n ILIAS_NET2__unused)
	{
		net2_free(ptr);
	}

	pointer
	reallocate(pointer orig_ptr, size_type oldsz ILIAS_NET2__unused, size_type newsz)
	{
		if (newsz > this->maxsize())
			throw std::bad_alloc();

		const pointer ptr = net2_realloc(orig_ptr, newsz * this->element_size);
		if (!ptr)
			throw std::bad_alloc();
		return ptr;
	}

	void
	reallocate_inplace(pointer ptr, size_type oldsz, size_type newsz)
	{
		if (newsz > oldsz)
			throw std::bad_alloc();
	}

#if HAS_VARARG_TEMPLATES
	template<typename... Args>
	void
	construct(pointer ptr, Args... args)
	{
		new (ptr) element_type(args...);
	}
#else
	void
	construct(pointer ptr)
	{
		new (ptr) element_type();
	}

	template<typename Arg>
	void
	construct(pointer ptr, const Arg& arg)
	{
		new (ptr) element_type(arg);
	}
#endif

	void
	destroy(pointer ptr)
	{
		ptr->~value_type();
	}

	size_type
	maxsz() const ILIAS_NET2_NOTHROW
	{
		return (std::numeric_limits<size_t>::max() / element_size);
	}

	template<typename U>
	struct rebind
	{
		typedef realloc_allocator<U> other;
	};
};


class buffer
{
public:
	typedef uintptr_t size_type;

	/* Segment interface. */
	class segment
	{
	friend void reference(const segment*);
	friend bool release(const segment*);

	public:
		typedef buffer::size_type size_type;

	private:
		mutable std::atomic<unsigned int> refcnt;

	public:
		segment() :
			refcnt(0)
		{
			return;
		}

		virtual ~segment() ILIAS_NET2_NOTHROW = 0;
		virtual const void* at(size_type) const = 0;
		virtual bool contig() const ILIAS_NET2_NOTHROW = 0;
		virtual size_type len() const ILIAS_NET2_NOTHROW = 0;

		virtual void copyout(void*, size_type) const;
		virtual bool grow(size_type, const void*, size_type) ILIAS_NET2_NOTHROW;
	};

private:
	class segment_ref
	{
	private:
		refpointer<segment> m_segment;

		size_type m_off;
		size_type m_len;

		segment_ref() = delete;

	public:
		segment_ref(segment_ref&& o) ILIAS_NET2_NOTHROW :
			m_segment(std::move(o.m_segment)),
			m_off(std::move(o.m_off)),
			m_len(std::move(o.m_len))
		{
			return;
		}

		segment_ref(const segment_ref& o) :
			m_segment(o.m_segment),
			m_off(o.m_off),
			m_len(o.m_len)
		{
			return;
		}

		segment_ref&
		operator= (const segment_ref& o) ILIAS_NET2_NOTHROW
		{
			this->m_segment = o.m_segment;
			this->m_off = o.m_off;
			this->m_len = o.m_len;
			return *this;
		}

		segment_ref&
		operator= (segment_ref&& o) ILIAS_NET2_NOTHROW
		{
			this->m_segment = std::move(o.m_segment);
			this->m_off = std::move(o.m_off);
			this->m_len = std::move(o.m_len);
			return *this;
		}

		void*
		at(size_type off = 0) const ILIAS_NET2_NOTHROW
		{
			assert(off < this->m_len);
			return this->m_segment->at(off);
		}

		void
		truncate(size_type len) ILIAS_NET2_NOTHROW
		{
			assert(len > 0 && len <= this->m_len);
			this->m_len = len;
		}

		void
		drain(size_type len) ILIAS_NET2_NOTHROW
		{
			assert(len < this->m_len);
			this->m_off += len;
		}

		bool
		merge(const segment_ref& o) ILIAS_NET2_NOTHROW
		{
			if (this->m_segment == o->m_segment &&
			    this->m_off + this->m_len == o.m_off) {
				this->m_len += o.m_len;
				return true;
			}
			return false;
		}

		bool
		grow(const void* data, size_type datalen) ILIAS_NET2_NOTHROW
		{
			if (!this->m_segment->grow(this->m_off + this->m_len, data, datalen))
				return false;

			this->m_len += datalen;
			return true;
		}
	};

	typedef std::vector<segment_ref, realloc_allocator<segment_ref> > list_type;

	list_type m_list;
	size_type m_size;

public:
	buffer() ILIAS_NET2_NOTHROW :
		m_list(),
		m_size(0)
	{
		return;
	}

	buffer(const buffer& rhs) :
		m_list(rhs.m_list),
		m_size(rhs.m_size)
	{
		return;
	}

	buffer(buffer&& rhs) ILIAS_NET2_NOTHROW :
		m_list(std::move(rhs.m_list)),
		m_size(rhs.m_size)
	{
		rhs.m_size = 0;
	}

	~buffer() ILIAS_NET2_NOTHROW
	{
		return;
	}

	size_type
	size() const ILIAS_NET2_NOTHROW
	{
		return this->m_size;
	}

	bool
	empty() const ILIAS_NET2_NOTHROW
	{
		return this->m_list.empty();
	}

	buffer&
	operator= (const buffer& o)
	{
		this->m_list = o.m_list;
		this->m_size = o.m_size;
		return *this;
	}

	buffer&
	operator= (buffer&& o) ILIAS_NET2_NOTHROW
	{
		this->m_list = std::move(o.m_list);
		this->m_size = o.m_size;
		return *this;
	}

	buffer&
	operator+= (const buffer& o)
	{
		/* Ensure enough capacity is available. */
		if (this->m_list.capacity() < this->m_list.size() + o.m_list.size())
			this->m_list.reserve(this->m_list.size() + o.m_list.size());

		/* Copy contents. */
		this->m_list.push_back(o.m_list.begin(), o.m_list.end());
		this->m_size += o.m_size;

		return *this;
	}

	buffer&
	operator+= (buffer&& o)
	{
		/* Ensure enough capacity is available. */
		if (this->m_list.capacity() < this->m_list.size() + o.m_list.size())
			this->m_list.reserve(this->m_list.size() + o.m_list.size());

		/* Copy contents. */
		this->m_list.push_back(o.m_list.begin(), o.m_list.end());
		this->m_size += o.m_size;

		/* Clear old vector. */
		o.m_list.clear();
		o.m_size = 0;

		return *this;
	}

	buffer&&
	operator+ (const buffer& o) const
	{
		buffer clone;

		/* Reserve memory. */
		clone.m_list.reserve(this->m_list.size() + o.m_list.size());

		/* Copy contents. */
		clone += *this;
		clone += o;

		return std::move(clone);
	}

	buffer&&
	operator+ (buffer&& o) const
	{
		buffer clone;

		/* Reserve memory. */
		clone.m_list.reserve(this->m_list.size() + o.m_list.size());

		/* Copy contents. */
		clone += *this;
		clone += o;

		return std::move(clone);
	}

	buffer&
	operator= (const buffer& o)
	{
		this->m_list = o.m_list;
		this->m_size = o.m_size;
		return *this;
	}

	buffer&
	operator= (buffer&& o) ILIAS_NET2_NOTHROW
	{
		this->m_list = std::move(o.m_list);
		this->m_size = o.m_size;
		o.m_size = 0;
		return *this;
	}

	void
	truncate(size_type len) ILIAS_NET2_NOTHROW
	{
		if (this->m_size <= len)
			return;

		list_type::iterator i = this->m_list.begin();
		size_type rlen = len;

		/* Skip any elements that fit in len. */
		while (i->m_len >= rlen) {
			rlen -= i->m_len;
			i++;
		}
		/* Truncate partial fit. */
		if (rlen > 0) {
			i->m_len = rlen;
			rlen = 0;
			i++;
		}
		/* Erase remaining elements. */
		this->m_list.resize(i - this->m_list.begin());
		this->m_size = len;

		return *this;
	}

private:
	void
	internal_drain(size_type len, buffer* opt_dst)
	{
		if (this->m_size <= len) {
			if (opt_dst)
				*opt_dst += *this; /* May throw. */
			this->clear();
			return;
		}

		list_type::iterator i = this->m_list.begin();
		size_type rlen = len;

		/* Skip any elements that fit in len. */
		while (i->m_len >= rlen) {
			rlen -= i->m_len;
			i++;
		}

		/* Add removed elements to opt_dst. */
		if (opt_dst) {
			opt_dst->m_list.reserve(opt_dst->m_list.size() + (i - this->m_list.begin()) + (rlen > 0 ? 1 : 0));
				/* May throw. */
			opt_dst->m_list.push_back(this->m_list.begin(), i);
			if (rlen > 0) {
				segment_ref tail = *i;
				tail.m_len = rlen;
				opt_dst->m_list.emplace_back(std::move(tail));
			}
		}

		/* Drain from partial segment. */
		i->m_off += rlen;

		/* Move all elements forward. */
		for (list_type::iterator dst = this->m_list.begin();
		    i != this->m_list.end();
		    ++dst, ++i)
			*dst = i->release();

		/* Erase now outdated elements. */
		this->m_list.resize(dst - this->m_list.begin());

		return;
	}

public:
	void
	drain(size_type len) ILIAS_NET2_NOTHROW
	{
		internal_drain(len, nullptr);
	}

	void
	drain(size_type len, buffer& dst)
	{
		internal_drain(len, &dst);
	}

	void
	swap(buffer& o) ILIAS_NET2_NOTHROW
	{
		std::swap(this->m_list, o.m_list);
		std::swap(this->m_size, o.m_size);
	}

	buffer&&
	subrange(size_type off = 0, size_type len = std::numeric_limits<size_type>::max())
	{
		buffer result;

		/* Handle empty result early. */
		if (off >= this->m_size || len <= 0)
			return std::move(result);
		/* Handle overflow and oversized request. */
		if (off + len < off || off + len > this->m_size)
			len = this->m_size - off;

		size_type roff = off;
		size_type rlen = len;

		/* Find first segments that needs to be copied. */
		list_type::iterator first = this->m_list.begin();
		while (first->m_len <= roff) {
			roff -= first->m_len;
			++first;
		}

		/* Find last segment that needs to be copied. */
		list_type::iterator last = first;
		rlen += roff; /* Add remainder. */
		while (last->m_len < rlen) {
			rlen -= last->m_len;
			++last;
		}
		last++;

		/*
		 * We now have [first, last) describing segments
		 * that need to be copied.
		 */
		result.m_list.reserve(last - first); /* May throw. */
		result.m_list.push_back(first, last);

		/* Eat bytes from first segment. */
		result.m_list.front().m_off += roff;
		/* Eat bytes from last segment. */
		result.m_list.back().m_len -= rlen;
		/* Set length of result. */
		result.m_size = len;

		return std::move(result);
	}

	buffer&
	prepend(const buffer& o)
	{
		list_type all;

		all.reserve(this->m_list.size() + o.m_list.size());
		all.push_back(o.m_list.begin(), o.m_list.end());
		all.push_back(this->m_list.begin(), this->m_list.end());
		this->m_list = std::move(all);
		this->m_size += o.m_size;
		return *this;
	}

	buffer&
	prepend(buffer&& o)
	{
		o += *this;
		this->clear();
		this->swap(o);
		return *this;
	}

	void
	clear() ILIAS_NET2_NOTHROW
	{
		this->m_list.clear();
		this->m_size = 0;
	}
};


}

namespace std {
	inline void
	swap(buffer& lhs, buffer& rhs) ILIAS_NET2_NOTHROW
	{
		lhs.swap(rhs);
	}
}


ILIAS_NET2__begin_cdecl


struct net2_buffer;

/*
 * A pointer in a buffer.
 *
 * Safe to copy via simple struct assignment.
 * May be invalidated on operations that modify the buffer.
 */
struct net2_buffer_ptr {
	size_t		 pos;
	size_t		 segment;
	size_t		 off;
};

/* A buffer pointer that points at position 0. */
extern ILIAS_NET2_EXPORT const struct net2_buffer_ptr
			 net2_buffer_ptr0;

ILIAS_NET2_EXPORT
struct net2_buffer	*net2_buffer_new();
ILIAS_NET2_EXPORT
void			 net2_buffer_free(struct net2_buffer*);
ILIAS_NET2_EXPORT
struct net2_buffer	*net2_buffer_copy(const struct net2_buffer*);
ILIAS_NET2_EXPORT
int			 net2_buffer_add(struct net2_buffer*,
			    const void*, size_t);
ILIAS_NET2_EXPORT
int			 net2_buffer_add_reference(struct net2_buffer*, void*, size_t,
			    void (*)(void*), void*);
ILIAS_NET2_EXPORT
int			 net2_buffer_append(struct net2_buffer*,
			    const struct net2_buffer*);
ILIAS_NET2_EXPORT
int			 net2_buffer_prepend(struct net2_buffer*,
			    const struct net2_buffer*);
ILIAS_NET2_EXPORT
void			*net2_buffer_pullup(struct net2_buffer*, size_t);
ILIAS_NET2_EXPORT
size_t			 net2_buffer_length(const struct net2_buffer*);
ILIAS_NET2_EXPORT
int			 net2_buffer_empty(const struct net2_buffer*);

ILIAS_NET2_EXPORT
size_t			 net2_buffer_peek(const struct net2_buffer*, size_t,
			    struct iovec*, size_t);

ILIAS_NET2_EXPORT
size_t			 net2_buffer_copyout(const struct net2_buffer*,
			    void*, size_t);
ILIAS_NET2_EXPORT
size_t			 net2_buffer_remove(struct net2_buffer*,
			    void*, size_t);
#define net2_buffer_drain(buf, len)					\
			 net2_buffer_remove((buf), (void*)0, (len))
ILIAS_NET2_EXPORT
void			 net2_buffer_truncate(struct net2_buffer*, size_t);
ILIAS_NET2_EXPORT
size_t			 net2_buffer_remove_buffer(struct net2_buffer*,
			    struct net2_buffer*, size_t);

ILIAS_NET2_EXPORT
int			 net2_buffer_ptr_advance(const struct net2_buffer*,
			    struct net2_buffer_ptr*, size_t);
ILIAS_NET2_EXPORT
int			 net2_buffer_search(const struct net2_buffer*,
			    struct net2_buffer_ptr*,
			    const void*, size_t, struct net2_buffer_ptr*);

ILIAS_NET2_EXPORT
int			 net2_buffer_cmp(const struct net2_buffer*,
			    const struct net2_buffer*);

ILIAS_NET2_EXPORT
int			 net2_buffer_reserve_space(struct net2_buffer*,
			    size_t, struct iovec*, size_t*);
ILIAS_NET2_EXPORT
int			 net2_buffer_commit_space(struct net2_buffer*,
			    struct iovec*, size_t);

ILIAS_NET2_EXPORT
char			*net2_buffer_hex(const struct net2_buffer*,
			    void *(*)(size_t));

ILIAS_NET2_EXPORT
struct net2_buffer	*net2_buffer_subrange(const struct net2_buffer*,
			    size_t, size_t);

ILIAS_NET2_EXPORT
int			 net2_buffer_sensitive(struct net2_buffer*);


ILIAS_NET2__end_cdecl


#ifdef __cplusplus

#include <stdexcept>
#include <string>
#include <utility>

namespace ilias {


enum buffer_create_t { BUFFER_CREATE };


class buffer;
class buffer_iterator;


class buffer
{
public:
	typedef size_t size_type;

private:
	struct net2_buffer	*buf;

public:
	buffer() ILIAS_NET2_NOTHROW;
	explicit buffer(struct net2_buffer*) throw (std::invalid_argument);
	buffer(buffer_create_t) throw (std::bad_alloc);
	buffer(const buffer&) throw (std::bad_alloc);
#if HAS_RVALUE_REF
	buffer(buffer&&) ILIAS_NET2_NOTHROW;
#endif
	buffer(const void*, size_type) throw (std::bad_alloc);
	~buffer() ILIAS_NET2_NOTHROW;

	buffer& operator= (const buffer& rhs) throw (std::bad_alloc);
#if HAS_RVALUE_REF
	buffer& operator= (buffer&& rhs) ILIAS_NET2_NOTHROW;
#endif

	buffer& operator+= (const buffer& rhs) throw (std::bad_alloc);
#if HAS_RVALUE_REF
	buffer& operator+= (buffer&& rhs) throw (std::bad_alloc);
#endif

#if HAS_RVALUE_REF
	buffer&& operator+ (const buffer& rhs) const throw (std::bad_alloc);
	buffer&& operator+ (const buffer&& rhs) const throw (std::bad_alloc);
#else
	buffer operator+ (const buffer& rhs) const throw (std::bad_alloc);
	buffer operator+ (const buffer&& rhs) const throw (std::bad_alloc);
#endif

	bool empty() const ILIAS_NET2_NOTHROW;
	size_type size() const ILIAS_NET2_NOTHROW;
	bool operator== (const buffer&) const ILIAS_NET2_NOTHROW;
	bool operator!= (const buffer&) const ILIAS_NET2_NOTHROW;
	bool operator< (const buffer&) const ILIAS_NET2_NOTHROW;
	bool operator> (const buffer&) const ILIAS_NET2_NOTHROW;
	bool operator<= (const buffer&) const ILIAS_NET2_NOTHROW;
	bool operator>= (const buffer&) const ILIAS_NET2_NOTHROW;

	buffer& append(const void *, size_type) throw (std::bad_alloc);
	buffer& add_reference(const void *, size_type, void (*)(void*), void*) throw (std::bad_alloc);
	buffer& add_reference(const void *, size_type, void (*)(void*)) throw (std::bad_alloc);

	void truncate(size_type) ILIAS_NET2_NOTHROW;
	void drain(size_type) ILIAS_NET2_NOTHROW;
	void clear() ILIAS_NET2_NOTHROW;

	size_type copyout(void*, size_type) const ILIAS_NET2_NOTHROW;
	size_type move(void*, size_type) ILIAS_NET2_NOTHROW;
	void* pullup(size_type) throw (std::bad_alloc, std::out_of_range);
	bool sensitive() ILIAS_NET2_NOTHROW;

	buffer subrange(size_type, size_type) const throw (std::bad_alloc, std::out_of_range);
	buffer subrange(buffer_iterator, size_type) const throw (std::bad_alloc, std::out_of_range);

	struct net2_buffer* c_buffer(bool) throw (std::bad_alloc);
	struct net2_buffer* c_buffer() const throw (std::bad_alloc);
#if HAS_RVALUE_REF
	std::string&& hex() const throw (std::bad_alloc);
#else
	std::string hex() const throw (std::bad_alloc);
#endif

	struct net2_buffer *release() ILIAS_NET2_NOTHROW;
};

class buffer_iterator
{
public:
	typedef buffer::size_type size_type;

private:
	struct net2_buffer	*buf;
	struct net2_buffer_ptr	 ptr;

public:
	buffer_iterator() ILIAS_NET2_NOTHROW;
	buffer_iterator(const buffer&) ILIAS_NET2_NOTHROW;
	buffer_iterator(const buffer&, size_type) throw (std::out_of_range);
	buffer_iterator(struct net2_buffer*, struct net2_buffer_ptr*) throw (std::invalid_argument);

	size_type pos() const ILIAS_NET2_NOTHROW;
	size_type segment() const ILIAS_NET2_NOTHROW;
	size_type segment_offset() const ILIAS_NET2_NOTHROW;

	void advance(size_type) throw (std::out_of_range);
	buffer_iterator& operator++ () throw (std::out_of_range);
	buffer_iterator operator++ (int) throw (std::out_of_range);
	buffer_iterator& operator+= (size_type) throw (std::out_of_range);
	buffer_iterator operator+ (size_type) const throw(std::out_of_range);

	bool find(void*, size_type) ILIAS_NET2_NOTHROW;
};


inline
buffer::buffer() ILIAS_NET2_NOTHROW :
	buf(0)
{
	return;
}

inline
buffer::buffer(struct net2_buffer* buf) throw (std::invalid_argument) :
	buf(buf)
{
	if (!buf)
		throw std::invalid_argument("buf");
}

inline
buffer::buffer(buffer_create_t) throw (std::bad_alloc) :
	buf(net2_buffer_new())
{
	if (!buf)
		throw std::bad_alloc();
}

inline
buffer::buffer(const buffer& rhs) throw (std::bad_alloc) :
	buf(0)
{
	if (rhs.buf && !(buf = net2_buffer_copy(rhs.buf)))
		throw std::bad_alloc();
}

#if HAS_RVALUE_REF
inline
buffer::buffer(buffer&& rhs) ILIAS_NET2_NOTHROW :
	buf(rhs.buf)
{
	rhs.buf = 0;
}
#endif

inline
buffer::buffer(const void* data, buffer::size_type len) throw (std::bad_alloc) :
	buf(net2_buffer_new())
{
	if (!buf)
		throw std::bad_alloc();
	append(data, len);
}

inline
buffer::~buffer() ILIAS_NET2_NOTHROW
{
	if (buf)
		net2_buffer_free(buf);
}

inline buffer&
buffer::operator= (const buffer& rhs) throw (std::bad_alloc)
{
	if (this != &rhs) {
		struct net2_buffer *newbuf = 0;
		if (rhs.buf) {
			net2_buffer_copy(rhs.buf);
			if (!newbuf)
				throw std::bad_alloc();
		}
		if (buf)
			net2_buffer_free(buf);
		buf = newbuf;
	}

	return *this;
}

#if HAS_RVALUE_REF
inline buffer&
buffer::operator= (buffer&& rhs) ILIAS_NET2_NOTHROW
{
	if (buf)
		net2_buffer_free(buf);
	buf = rhs.buf;
	rhs.buf = 0;
	return *this;
}
#endif

inline buffer&
buffer::operator+= (const buffer& rhs) throw (std::bad_alloc)
{
	bool undo_free = false;

	if (!rhs.buf)
		return *this;

	if (!buf) {
		undo_free = true;
		if (!(buf = net2_buffer_new()))
			throw std::bad_alloc();
	}

	if (net2_buffer_append(buf, rhs.buf)) {
		if (undo_free) {
			net2_buffer_free(buf);
			buf = 0;
		}
		throw std::bad_alloc();
	}

	return *this;
}

#if HAS_RVALUE_REF
inline buffer&
buffer::operator+= (buffer&& rhs) throw (std::bad_alloc)
{
	if (rhs.empty())
		return *this;

	if (empty()) {
		if (buf)
			net2_buffer_free(buf);
		buf = rhs.buf;
		rhs.buf = 0;
		return *this;
	}

	if (net2_buffer_remove_buffer(rhs.buf, buf, -1) == 0)
		throw std::bad_alloc();

	return *this;
}
#endif

#if HAS_RVALUE_REF
inline buffer&&
buffer::operator+ (const buffer& rhs) const throw (std::bad_alloc)
{
	buffer clone = *this;
	clone += rhs;
	return std::move(clone);
}
#else
inline buffer
buffer::operator+ (const buffer& rhs) const throw (std::bad_alloc)
{
	buffer clone = *this;
	clone += rhs;
	return clone;
}
#endif

#if HAS_RVALUE_REF
inline buffer&&
buffer::operator+ (const buffer&& rhs) const throw (std::bad_alloc)
{
	buffer clone = *this;
	clone += std::move(rhs);
	return std::move(clone);
}
#else
inline buffer
buffer::operator+ (const buffer&& rhs) const throw (std::bad_alloc)
{
	buffer clone = *this;
	clone += std::move(rhs);
	return clone;
}
#endif

inline bool
buffer::empty() const ILIAS_NET2_NOTHROW
{
	return !buf || net2_buffer_empty(buf);
}

inline buffer::size_type
buffer::size() const ILIAS_NET2_NOTHROW
{
	return (buf ? net2_buffer_length(buf) : 0);
}

inline bool
buffer::operator== (const buffer& rhs) const ILIAS_NET2_NOTHROW
{
	if (!buf && !rhs.buf)
		return true;
	else if (!buf || !rhs.buf)
		return false;
	else
		return net2_buffer_cmp(buf, rhs.buf) == 0;
}

inline bool
buffer::operator!= (const buffer& rhs) const ILIAS_NET2_NOTHROW
{
	return !(*this == rhs);
}

inline bool
buffer::operator< (const buffer& rhs) const ILIAS_NET2_NOTHROW
{
	if (!buf)
		return !rhs.empty();
	else if (!rhs.buf)
		return false;
	else
		return net2_buffer_cmp(buf, rhs.buf) < 0;
}

inline bool
buffer::operator> (const buffer& rhs) const ILIAS_NET2_NOTHROW
{
	if (!rhs.buf)
		return !empty();
	else if (!buf)
		return false;
	else
		return net2_buffer_cmp(buf, rhs.buf) > 0;
}

inline bool
buffer::operator<= (const buffer& rhs) const ILIAS_NET2_NOTHROW
{
	if (!buf)
		return true;
	else if (!rhs.buf)
		return empty();
	else
		return net2_buffer_cmp(buf, rhs.buf) <= 0;
}

inline bool
buffer::operator>= (const buffer& rhs) const ILIAS_NET2_NOTHROW
{
	if (!rhs.buf)
		return true;
	else if (!buf)
		return rhs.empty();
	else
		return net2_buffer_cmp(buf, rhs.buf) >= 0;
}

inline buffer&
buffer::append(const void* data, buffer::size_type len) throw (std::bad_alloc)
{
	if (!buf) {
		if (!(buf = net2_buffer_new()))
			throw std::bad_alloc();
	}

	if (net2_buffer_add(buf, data, len))
		throw std::bad_alloc();

	return *this;
}

inline buffer&
buffer::add_reference(const void* data, buffer::size_type len, void (*release)(void*), void* release_arg) throw (std::bad_alloc)
{
	if (!buf) {
		if (!(buf = net2_buffer_new()))
			throw std::bad_alloc();
	}

	if (net2_buffer_add_reference(buf, const_cast<void*>(data), len, release, release_arg))
		throw std::bad_alloc();

	return *this;
}

inline buffer&
buffer::add_reference(const void* data, buffer::size_type len, void (*release)(void*)) throw (std::bad_alloc)
{
	return add_reference(data, len, release, const_cast<void*>(data));
}

inline void
buffer::truncate(buffer::size_type len) ILIAS_NET2_NOTHROW
{
	if (buf)
		net2_buffer_truncate(buf, len);
}

inline void
buffer::drain(buffer::size_type len) ILIAS_NET2_NOTHROW
{
	if (buf)
		net2_buffer_drain(buf, len);
}

inline void
buffer::clear() ILIAS_NET2_NOTHROW
{
	if (buf) {
		net2_buffer_free(buf);
		buf = 0;
	}
}

inline struct net2_buffer*
buffer::c_buffer(bool null_ok) throw (std::bad_alloc)
{
	if (!null_ok && !buf) {
		if (!(buf = net2_buffer_new()))
			throw std::bad_alloc();
	}
	return buf;
}

inline struct net2_buffer*
buffer::c_buffer() const throw (std::bad_alloc)
{
	return buf;
}

inline buffer::size_type
buffer::copyout(void* addr, size_type len) const ILIAS_NET2_NOTHROW
{
	if (!buf)
		return 0;
	return net2_buffer_copyout(buf, addr, len);
}

inline buffer::size_type
buffer::move(void* addr, size_type len) ILIAS_NET2_NOTHROW
{
	if (!buf)
		return 0;
	return net2_buffer_remove(buf, addr, len);
}

inline void*
buffer::pullup(size_type len) throw (std::bad_alloc, std::out_of_range)
{
	/* Filter corner cases. */
	if (len == 0)
		return 0;
	if (!buf)
		throw std::out_of_range("len");

	void* rv = net2_buffer_pullup(buf, len);
	if (rv)
		return rv;	/* Success. */

	/* Handle failure. */
	if (len > size())
		throw std::out_of_range("len");
	else
		throw std::bad_alloc();
}

inline bool
buffer::sensitive() ILIAS_NET2_NOTHROW
{
	return net2_buffer_sensitive(buf) != 0;
}

inline buffer
buffer::subrange(size_type off, size_type len) const throw (std::bad_alloc, std::out_of_range)
{
	struct net2_buffer *out = net2_buffer_subrange(buf, off, len);
	if (out)
		return buffer(out);

	/* Handle failure. */
	if (SIZE_MAX - off < len || off + len > size())
		throw std::out_of_range("off + len");
	throw std::bad_alloc();
}

inline buffer
buffer::subrange(buffer_iterator pos, size_type len) const throw (std::bad_alloc, std::out_of_range)
{
	return subrange(pos.pos(), len);
}


inline
buffer_iterator::buffer_iterator() ILIAS_NET2_NOTHROW :
	buf(0),
	ptr(net2_buffer_ptr0)
{
	return;
}

inline
buffer_iterator::buffer_iterator(const buffer& b) ILIAS_NET2_NOTHROW :
	buf(b.c_buffer()),
	ptr(net2_buffer_ptr0)
{
	return;
}

inline
buffer_iterator::buffer_iterator(const buffer& b, buffer_iterator::size_type off) throw (std::out_of_range) :
	buf(b.c_buffer()),
	ptr(net2_buffer_ptr0)
{
	if (!buf)
		throw std::out_of_range("off");
	if (net2_buffer_ptr_advance(buf, &ptr, off))
		throw std::out_of_range("off");
}

inline
buffer_iterator::buffer_iterator(struct net2_buffer* b, struct net2_buffer_ptr* p) throw (std::invalid_argument) :
	buf(b),
	ptr(*p)
{
	if (!buf && ptr.pos != 0)
		throw std::invalid_argument("buf");
}

inline buffer_iterator::size_type
buffer_iterator::pos() const ILIAS_NET2_NOTHROW
{
	return ptr.pos;
}

inline buffer_iterator::size_type
buffer_iterator::segment() const ILIAS_NET2_NOTHROW
{
	return ptr.segment;
}

inline buffer_iterator::size_type
buffer_iterator::segment_offset() const ILIAS_NET2_NOTHROW
{
	return ptr.off;
}

inline void
buffer_iterator::advance(buffer_iterator::size_type delta) throw (std::out_of_range)
{
	if (delta == 0)
		return;
	if (!buf)
		throw std::out_of_range("delta");
	if (net2_buffer_ptr_advance(buf, &ptr, delta))
		throw std::out_of_range("delta");
}

inline buffer_iterator&
buffer_iterator::operator++ () throw (std::out_of_range)
{
	advance(1);
	return *this;
}

inline buffer_iterator
buffer_iterator::operator++ (int) throw (std::out_of_range)
{
	buffer_iterator clone = *this;
	advance(1);
	return std::move(clone);
}

inline buffer_iterator&
buffer_iterator::operator+= (buffer_iterator::size_type delta) throw (std::out_of_range)
{
	advance(delta);
	return *this;
}

inline buffer_iterator
buffer_iterator::operator+ (buffer_iterator::size_type delta) const throw (std::out_of_range)
{
	buffer_iterator clone = *this;
	clone.advance(delta);
	return std::move(clone);
}

inline bool
buffer_iterator::find(void* needle, size_type len) ILIAS_NET2_NOTHROW
{
	if (!buf)
		return false;

	return net2_buffer_search(buf, &ptr, needle, len, &ptr) == 0;
}

#ifdef HAS_RVALUE_REF
inline std::string&&
buffer::hex() const throw (std::bad_alloc)
{
	std::string out;

	if (buf) {
		char *hex = net2_buffer_hex(buf, &malloc);
		try {
			out = hex;
		} catch (...) {
			free(hex);
			throw;
		}
		free(hex);
	}
	return std::move(out);
}
#else
inline std::string
buffer::hex() const throw (std::bad_alloc)
{
	std::string out;

	if (buf) {
		char *hex = net2_buffer_hex(buf, &malloc);
		try {
			out = hex;
		} catch (...) {
			free(hex);
			throw;
		}
		free(hex);
	}
	return out;
}
#endif

inline struct net2_buffer*
buffer::release() ILIAS_NET2_NOTHROW
{
	struct net2_buffer *rv = this->buf;
	this->buf = 0;
	return rv;
}


} /* namespace ilias */

#endif /* __cplusplus */


#endif /* ILIAS_NET2_BUFFER_H */
