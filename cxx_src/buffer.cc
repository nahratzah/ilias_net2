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
#include <ilias/net2/buffer.h>
#include <ilias/net2/types.h>
#include <array>
#include <cstring>
#include <cstdint>
#include <limits>


#ifdef _MSC_VER
#pragma warning( disable: 4290 )
#pragma warning( disable: 4800 )
#endif


namespace ilias {


const buffer::size_type buffer::npos = std::numeric_limits<size_type>::max();

/*
 * Buffer segment pool.
 *
 * The pool creates elements aligned to at least 64 bytes.
 * The pool will select an optimum size to contain entries between 256 byte and 8 kilobyte.
 * The mem_segment will be offset such that the first data byte starts at the specified alignment.
 */
const std::size_t buffer::mem_segment::m_pool_align = (pool::default_align > 64 ? pool::default_align : std::size_t(64));
const std::size_t buffer::mem_segment::m_pool_overhead = pool::round_up(sizeof(mem_segment), pool::default_align);
const std::size_t buffer::mem_segment::m_pool_offset = m_pool_align - ((m_pool_overhead - 1) % m_pool_align + 1);
pool buffer::mem_segment::m_pool(
    pool::recommend_size(buffer::mem_segment::m_pool_overhead + 256,
	buffer::mem_segment::m_pool_overhead + 8192,
	m_pool_align, m_pool_offset),
    m_pool_align,
    m_pool_offset);


buffer::segment_ref::~segment_ref() ILIAS_NET2_NOTHROW
{
	return;
}

bool
buffer::segment_ref::grow(const void* data, size_type datalen, bool sensitive) ILIAS_NET2_NOTHROW
{
	if (!this->m_segment)
		return false;

	void* ptr = this->m_segment->allocate_at(std::nothrow, this->m_off + this->m_len, datalen);
	if (!ptr)
		return false;

	if (sensitive)
		this->mark_sensitive();
	this->m_len += datalen;
	copy_memory(ptr, data, datalen);
	return true;
}

void
buffer::mem_segment::free(const mem_segment* ms) ILIAS_NET2_NOTHROW
{
	/* Retrieve data we want to hang on to. */
	void*const ptr = const_cast<mem_segment*>(ms);
	const size_type sz = ms->alloc_size();
	const bool sensitive = ms->m_sensitive.load(std::memory_order_relaxed);

	/* Destroy segment. */
	ms->~mem_segment();

	/* If the segment contained sensitive data, wipe it. */
	if (sensitive)
		zero_memory(ptr, sz);

	/* Free memory to pool. */
	bool ok = m_pool.deallocate_bytes(std::nothrow, ptr, sz);
	assert(ok);
}


buffer::buffer(const buffer& rhs) throw (std::bad_alloc) :
	m_list(rhs.m_list),
	m_reserve(0)
{
	return;
}

buffer::~buffer() ILIAS_NET2_NOTHROW
{
	return;
}

buffer::size_type
buffer::size() const ILIAS_NET2_NOTHROW
{
	if (this->m_list.empty())
		return 0;

	list_type::const_reference back = this->m_list.back();
	return back.first + back.second.length();
}

/*
 * Nothrow implace_back with correct offset.
 * Must be called with vector having sufficient spare capacity.
 */
inline void
buffer::push_back(const buffer::segment_ref& sr) ILIAS_NET2_NOTHROW
{
	assert(this->m_list.capacity() - this->m_list.size() > this->m_reserve);

	size_type off = 0;

	if (!this->m_list.empty()) {
		list_type::reference b = this->m_list.back();
		if (b.second.merge(sr))
			return;
		off = b.first + b.second.length();
	}

	this->m_list.emplace_back(off, sr);

	assert(this->m_list.capacity() - this->m_list.size() >= this->m_reserve);
}

#if HAS_RVALUE_REF
/*
 * Nothrow implace_back with correct offset.
 * Must be called with vector having sufficient spare capacity.
 */
inline void
buffer::push_back(buffer::segment_ref&& sr) ILIAS_NET2_NOTHROW
{
	assert(this->m_list.capacity() - this->m_list.size() > this->m_reserve);

	size_type off = 0;

	if (!this->m_list.empty()) {
		list_type::reference b = this->m_list.back();
		if (b.second.merge(sr))
			return;
		off = b.first + b.second.length();
	}

	this->m_list.emplace_back(off, MOVE(sr));

	assert(this->m_list.capacity() - this->m_list.size() >= this->m_reserve);
}
#endif

buffer::list_type::iterator
buffer::find_offset(buffer::size_type offset) ILIAS_NET2_NOTHROW
{
	typedef list_type::const_reference const_ref;
	typedef list_type::iterator iter;

	/* Find the last entry with its offset less than sought after offset. */
	iter i = binsearch_lowerbound(this->m_list.begin(), this->m_list.end(), [offset](const_ref lhs) {
		return (lhs.first <= offset);
	});

	/* The above will return the last valid entry of the list if no entry applies. */
	if (i->first + i->second.length() <= offset)
		++i;

	return i;
}
buffer::list_type::const_iterator
buffer::find_offset(buffer::size_type offset) const ILIAS_NET2_NOTHROW
{
	typedef list_type::const_reference const_ref;
	typedef list_type::const_iterator iter;

	/* Find the last entry with its offset less than sought after offset. */
	iter i = binsearch_lowerbound(this->m_list.begin(), this->m_list.end(), [offset](const_ref lhs) {
		return (lhs.first <= offset);
	});

	/* The above will return the last valid entry of the list if no entry applies. */
	if (i->first + i->second.length() <= offset)
		++i;

	return i;
}

buffer&
buffer::operator= (const buffer& o) throw (std::bad_alloc)
{
	assert(this->m_reserve == 0);

	list_type copy = o.m_list;
	this->m_list.swap(copy);
	return *this;
}

buffer&
buffer::operator+= (const buffer& o) throw (std::bad_alloc)
{
	/* Reserve space in advance. */
	this->reserve_immediate(o.m_list.size());

	std::for_each(o.m_list.begin(), o.m_list.end(), [this](list_type::const_reference sr) {
		this->push_back(sr.second);
	});
	return *this;
}

void
buffer::clear() ILIAS_NET2_NOTHROW
{
	this->m_list.clear();
}

/* Only called by buffer::drain. */
inline buffer::list_type::iterator
buffer::drain_internal(void* out, buffer::size_type len) ILIAS_NET2_NOTHROW
{
	buffer::list_type::iterator i = this->m_list.begin();

	/* Copy entire buffers. */
	while (i != this->m_list.end() && i->second.length() <= len) {
		const size_type cplen = i->second.copyout(out);

		out = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(out) + cplen);
		len -= cplen;
		++i;
	}

	/* Copy last, partial buffer. */
	if (len > 0) {
		assert(i != this->m_list.end());
		assert(i->second.length() >= len);
		i->second.copyout(out, len);
	}

	return i;
}

void
buffer::drain(void* out, buffer::size_type len) throw (std::out_of_range)
{
	/* Algorithm below cannot deal with len=0, so handle that now. */
	if (len == 0)
		return;

	if (len > this->size())
		throw std::out_of_range("drain len exceeds buffer length");

	/* Find last entry starting at/after len. */
	list_type::iterator nw_start = (out ? this->drain_internal(out, len) : this->find_offset(len));

	/*
	 * If no such entry exists, simply clear the list.
	 */
	if (nw_start == this->m_list.end()) {
		this->clear();
		return;
	}

	/* Drain what needs to be drained from first entry. */
	nw_start->second.drain(len - nw_start->first);
	nw_start->first = len;

	/* Move list elements to head, subtracting drained bytes from offset. */
	const bool do_move = (nw_start != this->m_list.begin());
	if (do_move) {
		std::transform(nw_start, this->m_list.end(), this->m_list.begin(),
		    [len](list_type::reference sr) -> list_type::value_type {
			return list_type::value_type(sr.first - len, MOVE(sr.second));
		});
	} else {
		std::for_each(nw_start, this->m_list.end(),
		    [len](list_type::reference sr) {
			sr.first -= len;
		});
	}

	/* Truncate list. */
	this->m_list.resize(this->m_list.end() - nw_start);
}

void
buffer::truncate(buffer::size_type len) throw (std::out_of_range)
{
	/* Algorithm below cannot deal with len=0, so handle that now. */
	if (len == 0) {
		this->clear();
		return;
	}

	/* Find last entry starting at/after len. */
	list_type::iterator nw_fin = this->find_offset(len - 1);
	/*
	 * If no such entry exists, len is larger than this->size().
	 */
	if (nw_fin == this->m_list.end())
		throw std::out_of_range("truncate len exceeds buffer length");

	/* Truncate last entry that remains on the list. */
	nw_fin->second.truncate(len - nw_fin->first);
	/* Remove everything after nw_fin. */
	this->m_list.resize(++nw_fin - this->m_list.begin());
}

void
buffer::prepend(const buffer& o) throw (std::bad_alloc)
{
	if (o.empty())
		return;

	const size_type offset = o.size();
	const size_type oldlen = this->m_list.size();

	this->m_list.resize(oldlen + o.m_list.size());

	/* Move existing entries back. */
	std::transform(this->m_list.rend() - oldlen, this->m_list.rend(), this->m_list.rbegin(),
	    [offset](list_type::reference r) -> list_type::value_type {
		return list_type::value_type(r.first + offset, MOVE(r.second));
	});

	/* Copy existing entries to the front. */
	std::transform(o.m_list.begin(), o.m_list.end(), this->m_list.begin(),
	    [](list_type::const_reference r) -> list_type::const_reference {
		return r;
	});
}

void
buffer::append(const void* addr, buffer::size_type len, bool sensitive) throw (std::bad_alloc)
{
	if (!this->empty() && this->m_list.back().second.grow(addr, len)) {
		if (sensitive)
			this->m_list.back().second.mark_sensitive();
		return;
	}

	this->m_list.emplace_back(this->size(), segment_ref(addr, len, sensitive));
}

/*
 * Mark the entire buffer as sensitive.
 */
void
buffer::mark_sensitive() ILIAS_NET2_NOTHROW
{
	std::for_each(this->m_list.begin(), this->m_list.end(), [](list_type::reference r) {
		r.second.mark_sensitive();
	});
}

/*
 * Implementation of buffer::subrange().
 *
 * Takes an empty buffer and fills it with the range described by off, len.
 * Implementation exists so there won't be an interface boundary for rvalues.
 */
buffer
buffer::subrange(buffer::size_type off, buffer::size_type len) const throw (std::bad_alloc, std::out_of_range)
{
	buffer result;

	if (len == 0)
		return result;

	/* Find where the subrange starts and ends. */
	list_type::const_iterator b = this->find_offset(off);
	list_type::const_iterator e = this->find_offset(off + len - 1);
	if (e == this->m_list.end())
		throw std::out_of_range("off + len exceeds buffer length");
	++e;

	/* Copy all entries that make up the new buffer. */
	result.reserve_immediate(e - b);
	std::for_each(b, e, [&result](list_type::const_reference r) {
		result.m_list.emplace_back(r);
	});

	/* Drain from begin. */
	result.m_list.front().second.drain(off - result.m_list.front().first);
	result.m_list.front().first = off;

	/* Truncate trailing bytes. */
	result.m_list.back().second.truncate(off + len - result.m_list.back().first);

	/* Fix offsets. */
	std::for_each(result.m_list.begin(), result.m_list.end(), [off](list_type::reference r) {
		r.first -= off;
	});

	return result;
}

int
buffer::cmp(const buffer& o) const ILIAS_NET2_NOTHROW
{
	list_type::const_iterator i = this->m_list.begin(), j = o.m_list.begin();
	const list_type::const_iterator i_end = this->m_list.end(), j_end = o.m_list.end();

	size_type i_off = 0, j_off = 0;
	while (i != i_end && j != j_end) {
		/* Calculate which data we can compare right now. */
		void* i_data = i->second.data(i_off);
		void* j_data = j->second.data(j_off);
		const size_type len = std::min(i->second.length(), j->second.length());

		/* Comparison of data. */
		const int c = std::memcmp(i_data, j_data, len);
		if (c != 0)
			return c;

		/* Increment data pointers. */
		i_off += len;
		j_off += len;

		/* Skip to next iterator position. */
		if (i_off == i->second.length()) {
			i_off = 0;
			++i;
		}
		if (j_off == j->second.length()) {
			j_off = 0;
			++j;
		}
	}

	/* Return 0 if both are of equal length. */
	return (i == i_end ? -1 : 0) + (j == j_end ? 1 : 0);
}


namespace find_string_detail {


class histogram
{
public:
	typedef std::array<int, 1 << std::numeric_limits<std::uint8_t>::digits> array_type;

private:
	array_type m_data;
	unsigned int m_zeroes;

public:
#ifdef _MSC_VER
#pragma warning( push )
#pragma warning( disable: 4267 )	/* Prevent unsigned truncation warning in histogram::m_zeroes construction. */
#endif
	histogram() ILIAS_NET2_NOTHROW :
		m_data(),
		m_zeroes(this->m_data.size())
	{
		/* Zero all data. */
		std::for_each(this->m_data.begin(), this->m_data.end(), [](array_type::reference i) {
			i = 0;
		});
	}

	histogram(const std::uint8_t* data, std::size_t len, int delta) ILIAS_NET2_NOTHROW :
		m_data(),
		m_zeroes(this->m_data.size())
	{
		/* Zero all data. */
		std::for_each(this->m_data.begin(), this->m_data.end(), [](array_type::reference i) {
			i = 0;
		});
		/* Apply argument data. */
		std::for_each(data, data + len, [this, delta](std::uint8_t idx) {
			this->apply(idx, delta);
		});
	}
#ifdef _MSC_VER
#pragma warning( pop )
#endif

	bool
	all_zeroes() const ILIAS_NET2_NOTHROW
	{
		return (this->m_zeroes == this->m_data.size());
	}

	void
	apply(std::uint8_t idx, int delta) ILIAS_NET2_NOTHROW
	{
		array_type::reference datum = this->m_data[idx];
		if (datum == 0)
			--m_zeroes;
		datum += delta;
		if (datum == 0)
			++m_zeroes;
	}
};

/* Low level memory comparison function. */
template<typename Iter>
inline bool
compare(const void* data, buffer::size_type len, Iter i, buffer::size_type i_off) ILIAS_NET2_NOTHROW
{
	/* Compare all memory. */
	while (len > 0) {
		const void* i_data = i->second.data(i_off);
		const buffer::size_type cmplen = std::min(i->second.length() - i_off, len);

		/* Compare memory. */
		if (memcmp(data, i_data, cmplen) != 0)
			return false;

		/* Update data, len for next iteration. */
		data = reinterpret_cast<const void*>(reinterpret_cast<uintptr_t>(data) + cmplen);
		len -= cmplen;

		/* Update iterator. */
		i_off = 0;
		++i;
	}

	/* Loop end triggered, data is the same. */
	return true;
}

template<typename Iter>
class iter_off
{
public:
	typedef buffer::size_type size_type;

private:
	Iter iter;
	histogram& hist;
	size_type off;
	const int delta;

public:
	iter_off(const Iter& self, histogram& hist, int delta, buffer::size_type off = 0) ILIAS_NET2_NOTHROW :
		iter(self),
		hist(hist),
		off(off),
		delta(delta)
	{
		assert(off < iter->second.length());
		return;
	}

	iter_off&
	operator++() ILIAS_NET2_NOTHROW
	{
		/* Read data that is being move over. */
		const std::uint8_t passed = *reinterpret_cast<const std::uint8_t*>(iter->second.data(off++));

		/* Update histogram. */
		hist.apply(passed, delta);

		/* Skip to next iterator. */
		if (off == iter->second.length()) {
			++iter;
			off = 0;
		}

		return *this;
	}

	iter_off&
	operator+=(size_type d) ILIAS_NET2_NOTHROW
	{
		while (d-- > 0)
			++(*this);
		return *this;
	}

	bool
	at_end(const Iter& end_iter) const ILIAS_NET2_NOTHROW
	{
		return iter == end_iter;
	}

	size_type
	bufpos() const ILIAS_NET2_NOTHROW
	{
		return this->iter->first + this->off;
	}

	size_type
	rel_off() const ILIAS_NET2_NOTHROW
	{
		return this->off;
	}

	const Iter&
	get_iter() const ILIAS_NET2_NOTHROW
	{
		return this->iter;
	}
};


} /* namespace ilias::find_string_detail */

buffer::size_type
buffer::find_string(const void* data, buffer::size_type len, buffer::size_type buf_off) const ILIAS_NET2_NOTHROW
{
	using namespace ilias::find_string_detail;

	/* Handle requests that do not fit in this buffer. */
	{
		const size_type l = this->size();
		if (buf_off > l || len > l - buf_off)
			return buffer::npos;
		if (len == 0)
			return buf_off;
	}

	/* Initialize histogram. */
	histogram hist(reinterpret_cast<const std::uint8_t*>(data), len, -1);

	/* Create iterators describing the actual range of segments in which to look. */
	const list_type::const_iterator end = this->m_list.end();
	const list_type::const_iterator begin = this->find_offset(buf_off);
	assert(begin != end);

	/* Create histogram iterators. */
	iter_off<list_type::const_iterator> head(begin, hist,  1, buf_off - begin->first);
	iter_off<list_type::const_iterator> tail(begin, hist, -1, buf_off - begin->first);

	/* Move the head iterator forward, so [tail, head) describes len bytes. */
	head += len;

	for (;;) {
		/* Test if the data is the same. */
		if (hist.all_zeroes() && compare(data, len, tail.get_iter(), tail.rel_off()))
			return tail.bufpos();

		/* Test if we exhausted the buffer. */
		if (head.at_end(end))
			return buffer::npos;	/* Failed to find data. */

		/* Skip forward to next element. */
		++head;
		++tail;
	}
}

void
buffer::copyout(void* dst, buffer::size_type len) const throw (std::out_of_range)
{
	visit([&dst, this](const void* p, size_type l) {
		copy_memory(dst, p, l);
		dst = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(dst) + l);
	}, len);
}

const void*
buffer::pullup() throw (std::bad_alloc)
{
	/* Empty buffers return a nullptr. */
	if (this->empty())
		return nullptr;
	/* If the buffer is already pulled up, nothing needs to be done. */
	if (this->m_list.size() == 1)
		return this->m_list.front().second.data();

	/* Create new segment to copy entire buffer. */
	const size_type fullcopy_len = this->size();
	segment_ref copy(segment_ref::reserve_tag(), nullptr, fullcopy_len, false);
	void* copy_ptr = copy.data();
	/* Copy entire buffer, including sensitive-data markers. */
	std::for_each(this->m_list.begin(), this->m_list.end(), [this, &copy, &copy_ptr](list_type::const_reference s) {
		if (s.second.is_sensitive())
			copy.mark_sensitive();
		copy_memory(copy_ptr, s.second.data(), s.second.length());
		copy_ptr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(copy_ptr) + s.second.length());
	});
	/* Make the new segment the only one in the list. */
	this->m_list.front().second = std::move(copy);
	this->m_list.resize(1);
	return this->m_list.front().second.data();
}


buffer::prepare::prepare(buffer& b, buffer::size_type len, bool sensitive) :
	prepare_bufref(b),
	m_segment(segment_ref::reserve_tag(), (b.m_list.empty() ? nullptr : &b.m_list.back().second), len, sensitive)
{
	if (len == 0)
		throw std::invalid_argument("attempt to reserve 0 bytes");
}

buffer::prepare::~prepare() ILIAS_NET2_NOTHROW
{
	return;
}

void
buffer::prepare::commit() ILIAS_NET2_NOTHROW
{
	assert(this->valid());

	buffer& b = *this->release();
	b.push_back(MOVE(this->m_segment));
	this->m_segment = MOVE(segment_ref());
}

void
buffer::prepare::reset() ILIAS_NET2_NOTHROW
{
	this->release();
	this->m_segment = MOVE(segment_ref());
}


} /* namespace ilias */
