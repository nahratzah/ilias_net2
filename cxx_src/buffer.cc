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

namespace ilias {


void
buffer::segment::copyout(void* dst, size_type len) const
{
	if (!this->contig())
		throw std::invalid_argument("buffer::segment needs specialized implementation of copyout");
	if (this->len() < len)
		throw std::invalid_argument("buffer::segment::copyout: len too large");

	memcpy(dst, this->at(0), len);
}

bool
buffer::segment::grow(size_type off, const void* data, size_type len) ILIAS_NET2_NOTHROW
{
	return false;
}


static std::atomic<size_t> pagesize;

static inline size_t
get_pagesize() ILIAS_NET2_NOTHROW
{
	size_t rv = pagesize.load(memory_order_relaxed);
	if (rv == 0) {
		rv = sysconf(_SC_PAGESIZE);
		assert((rv & (rv - 1)) == 0);	/* Ensure pagesize is a power of 2. */
		pagesize.store(rv, memory_order_relaxed);
	}
	return rv;
}

static size_t
alloc_max_idx() ILIAS_NET2_NOTHROW
{
	const size_t pgsz = get_pagesize();
	if (pgsz < 256)
		return 0;
	return MIN(pgsz / 256, 8) - 1;
}

static size_t
alloc_in_size() ILIAS_NET2_NOTHROW
{
	const size_t pgsz = get_pagesize();
	const size_t maxidx = alloc_max_idx();
	if (maxidx == 0)
		return 0;
	return pgsz / maxidx;
}

struct membase {
	LL_ENTRY(membase) q;
	std::atomic<unsigned int> bitmap;
};

LL_HEAD(membase_q_type, membase);
static membase_q_type membase_q = LL_HEAD_INITIALIZER(membase_q);

void*
alloc_mem_primary(size_t& len) ILIAS_NET2_NOTHROW
{
	std::tuple<void*, size_t> result;

	/* Large allocation. */
	if (len > alloc_in_size()) {
		const size_t pgsz = get_pagesize();
		len = (len + pgsz - 1) & ~(pgsz - 1);
		void* ptr = mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
		return (ptr == MAP_FAILED ? nullptr : ptr);
	}

	/* Small allocation using a freelist. */
	membase* mb = reinterpret_cast<membase*>(ll_pop_front(&membase_q, 1));
	if (!mb) {
		mb = mmap(nullptr, get_pagesize(), PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
		if (mb == MAP_FAILED)
			return nullptr;

		LL_INIT_ENTRY(&mb->q);
		mb->bitmap.store(0x0U, memory_order_relaxed);
	}

	/* Allocate index. */
	size_t idx;
	for (idx = 0;
	    mb->bitmap.fetch_or(0x1U << idx, memory_order_acquire) & (0x1U << idx);
	    ++idx);
	assert(idx < alloc_max_idx());

	/* Push element back on the queue. */
	if (idx + 1 < alloc_max_idx())
		ll_insert_head(&membase_q, &mb->q, 0);

	len = alloc_in_size();
	return idx_to_pointer(mb, idx);
}

static void
free_mem_primary(void* addr)
{
}

static void
free_mem_secondary(void* addr, size_t sz)
{
}


class buffer::mem_segment :
	public buffer::segment
{
private:
	std::atomic<size_t> m_capacity;
	std::atomic<size_t> m_len;

public:
	mem_segment() = delete;
	mem_segment(const mem_segment&) = delete;
	mem_segment& operator= (const mem_segment) = delete;
	bool operator== (const mem_segment&) const = delete;

	mem_segment(size_type alloc_size) ILIAS_NET2_NOTHROW :
		buffer::segment(),
		m_maxsize(alloc_size - sizeof(*this)),
		m_len(0)
	{
		return;
	}

	~mem_segment() ILIAS_NET2_NOTHROW;

	static operator delete(void* ptr) ILIAS_NET2_NOTHROW
	{
		free_mem_primary(ptr);
	}

	static operator delete[](void*) ILIAS_NET2_NOTHROW = delete;

	size_type
	capacity() const ILIAS_NET2_NOTHROW
	{
		return this->m_capacity.load(memory_order_acquire);
	}

	bool
	extend_capacity(size_type new_capacity) ILIAS_NET2_NOTHROW
	{
		return (new_capacity <= this->m_capacity.load(memory_order_acquire));
	}

	void*
	address(size_type off = 0) const ILIAS_NET2_NOTHROW
	{
		return reinterpret_cast<const void*>(reinterpret_cast<uintptr_t>(this) + sizeof(*this) + off);
	}

	const void* at(size_type) const;
	bool contig() const ILIAS_NET2_NOTHROW;
	size_type len() const ILIAS_NET2_NOTHROW;

	bool grow(size_type, const void*, size_type) ILIAS_NET2_NOTHROW;
};


buffer::mem_segment::~mem_segment() ILIAS_NET2_NOTHROW
{
	free_mem_secondary(this, sizeof(*this) + this->m_capacity);
}

buffer::segment::size_type
buffer::mem_segment::len() const ILIAS_NET2_NOTHROW
{
	return this->m_len;
}

const void*
buffer::mem_segment::at(size_type off) const
{
	if (off > this->m_len)
		throw std::invalid_argument("off");

	return address(off);
}

bool
buffer::mem_segment::grow(size_type off, const void* data, size_type datalen) ILIAS_NET2_NOTHROW
{
	/* Protect against overflow. */
	if (off + datalen < off)
		return false;

	/* Try to extend capacity. */
	if (!extend_capacity(off + datalen))
		return false;

	/* Claim storage. */
	auto len = this->m_len.load(memory_order_relaxed);
	do {
		if (off < len)
			return false;
	} while (!this->m_len.compare_exchange_weak(len, off + datalen, memory_order_acquire, memory_order_relaxed));
	/* Copy data (safe since no other thread will access the new area). */
	memcpy(address(off), data, datalen);
}

bool
buffer::mem_segment::contig() const ILIAS_NET2_NOTHROW
{
	return true;
}


}
