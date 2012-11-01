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

namespace ilias {


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
buffer::mem_segment::free(mem_segment* ms) ILIAS_NET2_NOTHROW
{
	/* Retrieve data we want to hang on to. */
	void*const ptr = ms;
	const size_type sz = ms->alloc_size();
	const bool sensitive = ms->m_sensitive.load(std::memory_order_relaxed);

	/* Destroy segment. */
	ms->~mem_segment();

	/* If the segment contained sensitive data, wipe it. */
	if (sensitive)
		net2_secure_zero(ptr, sz);

	/* Free memory to pool. */
	bool ok = m_pool.deallocate_bytes(std::nothrow, ptr, sz);
	assert(ok);
}


buffer::buffer(const buffer& rhs) :
	m_list(rhs.m_list)
{
	return;
}

buffer::~buffer() ILIAS_NET2_NOTHROW
{
	return;
}

void
buffer::push_back(const buffer::segment_ref& sr)
{
	size_type off = 0;

	if (!this->m_list.empty()) {
		list_type::reference b = this->m_list.back();
		if (b.second.merge(sr))
			return;
		off = b.first + b.second.length();
	}

	this->m_list.emplace_back(off, sr);
}

#if HAS_RVALUE_REF
void
buffer::push_back(buffer::segment_ref&& sr)
{
	size_type off = 0;

	if (!this->m_list.empty()) {
		list_type::reference b = this->m_list.back();
		if (b.second.merge(sr))
			return;
		off = b.first + b.second.length();
	}

	this->m_list.emplace_back(off, MOVE(sr));
}
#endif

RVALUE(buffer::list_type::iterator)
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

	return MOVE(i);
}
RVALUE(buffer::list_type::const_iterator)
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

	return MOVE(i);
}

buffer&
buffer::operator= (const buffer& o)
{
	this->m_list = o.m_list;
	return *this;
}

buffer&
buffer::operator+= (const buffer& o)
{
	/* Reserve space in advance. */
	if (this->m_list.capacity() < this->m_list.size() + o.m_list.size())
		this->m_list.reserve(this->m_list.size() + o.m_list.size());

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

void
buffer::drain(void* out, buffer::size_type len) ILIAS_NET2_NOTHROW
{
	/* Algorithm below cannot deal with len=0, so handle that now. */
	if (len == 0)
		return;

	/* Find last entry starting at/after len. */
	list_type::iterator nw_start = this->find_offset(len);

	if (out) {
		/* Copy all contents up to nw_start. */
		for (list_type::const_iterator i = this->m_list.begin(); i != nw_start; ++i) {
			const size_type cplen = i->second.length();
			assert(len >= i->first + cplen);
			i->second.copyout(out, cplen);
			out = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(out) + cplen);
		}

		/* Copy part of nw_start that will be drained. */
		if (nw_start != this->m_list.end()) {
			const size_type cplen = len - nw_start->first;
			nw_start->second.copyout(out, cplen);
			out = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(out) + cplen);
		}
	}

	/*
	 * If no such entry exists, simply clear the list.
	 * XXX maybe throw an exception instead?
	 */
	if (nw_start == this->m_list.end()) {
		this->m_list.clear();
		return;
	}

	/* Drain what needs to be drained from first entry. */
	nw_start->second.drain(len - nw_start->first);
	nw_start->first = len;

	/* Move list elements to head, subtracting drained bytes from offset. */
	std::transform(nw_start, this->m_list.end(), this->m_list.begin(),
	    [len](list_type::reference sr) -> RVALUE(list_type::value_type) {
		return MOVE(list_type::value_type(sr.first - len, MOVE(sr.second)));
	});

	/* Truncate list. */
	this->m_list.resize(nw_start + 1 - this->m_list.begin());
}

void
buffer::truncate(buffer::size_type len) ILIAS_NET2_NOTHROW
{
	/* Algorithm below cannot deal with len=0, so handle that now. */
	if (len == 0) {
		this->clear();
		return;
	}

	/* Find last entry starting at/after len. */
	list_type::iterator nw_fin = this->find_offset(len - 1);
	/*
	 * If no such entry exists, no change is required.
	 * XXX maybe throw an exception since this->size() < len?
	 */
	if (nw_fin == this->m_list.end())
		return;

	/* Truncate last entry that remains on the list. */
	nw_fin->second.truncate(len - nw_fin->first);
	/* Remove everything after nw_fin. */
	this->m_list.resize(++nw_fin - this->m_list.begin());
}

void
buffer::prepend(const buffer& o)
{
	const size_type offset = o.size();
	const size_type oldlen = this->m_list.size();

	this->m_list.resize(oldlen + o.m_list.size());

	/* Move existing entries back. */
	std::transform(this->m_list.rend() - oldlen, this->m_list.rend(), this->m_list.rend(),
	    [offset](list_type::reference r) -> RVALUE(list_type::value_type) {
		return MOVE(list_type::value_type(r.first + offset, MOVE(r.second)));
	});

	/* Copy existing entries to the front. */
	std::transform(o.m_list.begin(), o.m_list.end(), this->m_list.begin(),
	    [](list_type::const_reference r) -> list_type::const_reference {
		return r;
	});
}

void
buffer::append(const void* addr, buffer::size_type len, bool sensitive)
{
	if (!this->empty() && this->m_list.back().second.grow(addr, len)) {
		if (sensitive)
			this->m_list.back().second.mark_sensitive();
		return;
	}

	this->m_list.emplace_back(this->size(), MOVE(segment_ref(addr, len, sensitive)));
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
buffer&
buffer::subrange_adapter(buffer& result, buffer::size_type off, buffer::size_type len) const
{
	if (len == 0)
		return result;

	/* Find where the subrange starts and ends. */
	list_type::const_iterator b = this->find_offset(off);
	list_type::const_iterator e = this->find_offset(off + len - 1);
	if (e != this->m_list.end())
		++e;
	if (b == e)
		return result;

	/* Copy all entries that make up the new buffer. */
	result.m_list.reserve(e - b);
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


} /* namespace ilias */
