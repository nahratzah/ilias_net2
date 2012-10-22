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
#include <ilias/net2/buf_alloc.h>
#include <ilias/net2/ll.h>
#include <atomic>


namespace ilias {


class ILIAS_NET2_LOCAL alloc_data :
	public ll_elem
{
private:
	std::atomic<unsigned int> m_bitmap;
	const size_t m_idx_size;

public:
	static size_t sys_pagesize() ILIAS_NET2_NOTHROW;
	static void* sys_pagealloc(size_t) ILIAS_NET2_NOTHROW;
	static bool sys_pagefree(void*, size_t) ILIAS_NET2_NOTHROW;

	static void* operator new(size_t, const std::nothrow_t&) ILIAS_NET2_NOTHROW;
	static void* operator new(size_t sz);
	static void operator delete(void*, const std::nothrow_t&) ILIAS_NET2_NOTHROW;
	static void operator delete(void*) ILIAS_NET2_NOTHROW;

	/* Truncate sz to a multiple of mul. */
	static constexpr size_t
	align_down(size_t sz, size_t mul) ILIAS_NET2_NOTHROW
	{
		return ((mul & (mul - 1)) == 0 ? (sz & ~(mul - 1)) : (sz - sz % mul));
	}
	/* Increase sz to a multiple of mul. */
	static constexpr size_t
	align_up(size_t sz, size_t mul) ILIAS_NET2_NOTHROW
	{
		return align_down((sz + mul - 1), mul);
	}
	/* Calculate offset of memory in alloc_data. */
	static constexpr size_t
	offset() const ILIAS_NET2_NOTHROW
	{
		return align_up(sizeof(*this), sizeof(void*));
	}

	/* Fetch OS pagesize. */
	static size_t pagesize() ILIAS_NET2_NOTHROW;

	/* Maximum size of allocations that will use free list. */
	static size_t
	list_max_size() const ILIAS_NET2_NOTHROW
	{
		return align_down(pagesize() - offset(), sizeof(void*));
	}

	/*
	 * Initialize alloc_data.
	 * idx_size: size of allocations per index.
	 */
	alloc_data(size_t idx_size) ILIAS_NET2_NOTHROW :
		m_bitmap(0),
		m_idx_size(align_up(idx_size, sizeof(void*)))
	{
		LL_INIT(this);
	}

	/* Calculate where allocation data starts. */
	void*
	mem_start() const ILIAS_NET2_NOTHROW
	{
		const void*const vptr = this;
		assert((vptr & (pagesize() - 1)) == 0);
		return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(vptr) + offset());
	}

	/* Max size per allocation. */
	size_t
	max_size() const ILIAS_NET2_NOTHROW
	{
		return this->m_idx_size;
	}

	/* Maximum number of indices. */
	size_t
	max_idx() const ILIAS_NET2_NOTHROW
	{
		return std::max(1U, (pagesize() - offset()) / max_size());
	}

	/* Test if all memory in this alloc_data is free. */
	bool
	empty() const ILIAS_NET2_NOTHROW
	{
		return (this->m_bitmap.load(memory_order_relaxed) == 0U);
	}

	/* Test if all memory in this alloc_data is in use. */
	bool
	full() const ILIAS_NET2_NOTHROW
	{
		return (this->m_bitmap.load(memory_order_relaxed) == (1U << max_idx()) - 1);
	}

private:
	/*
	 * Allocate index.
	 *
	 * Returns 0 if no indices are available.
	 * Returns 1-based index on succes.
	 */
	size_t
	alloc_idx(size_t sz) ILIAS_NET2_NOTHROW
	{
		size_t idx;

		/* Find free space. */
		for (idx = 0; idx < max_idx; ++idx) {
			const unsigned int mask = (1U << idx);

			if (!(this->m_bitmap.fetch_or(mask, memory_order_relaxed) & mask))
				break;
		}
		if (idx == max_idx())
			return 0;

		return idx + 1;
	}

	/*
	 * Convert index (obtained via alloc_idx()) to pointer.
	 *
	 * Index 0 yields the nullpointer.
	 * Other indices generate a valid memory address.
	 */
	void*
	idx_to_pointer(size_t idx) const ILIAS_NET2_NOTHROW
	{
		if (idx == 0)
			return nullptr;

		const uintptr_t addr = reinterpret_cast<uintptr_t>(this->mem_start()) + max_size() * (idx - 1);
		assert((addr & (pagesize() - 1)) != 0);
		return reinterpret_cast<void*>(addr);
	}

public:
	/*
	 * Allocate sz bytes of memory from this alloc_data.
	 * Returns nullptr on failure.
	 */
	void*
	alloc(size_t& sz, const std::nothrow_t& unused ILIAS_NET2__unused) ILIAS_NET2_NOTHROW
	{
		if (sz > max_size())
			return nullptr;

		void* ptr = idx_to_pointer(alloc_idx(sz));
		if (ptr != nullptr)
			sz = max_size();
		return ptr;
	}

	/*
	 * Allocate sz bytes of memory from this alloc_data.
	 * Throws std::bad_alloc on failure.
	 */
	void*
	alloc(size_t& sz)
	{
		void* ptr = alloc(sz, std::nothrow);
		if (ptr == nullptr)
			throw std::bad_alloc();
		return ptr;
	}

	/*
	 * Free memory at ptr.
	 * Returns false if the operation fails (i.e. the pointer was invalid).
	 */
	bool
	free(void* ptr, const std::nothrow_t& unused ILIAS_NET__unused) ILIAS_NET2_NOTHROW
	{
		uintptr_t p = reinterpret_cast<uintptr_t>(ptr);
		uintptr_t mstart = reinterpret_cast<uintptr_t>(void_self()) + align_up(sizeof(*this), sizeof(void*));

		if (p < mstart)
			return false;
		p -= mstart;
		if (p % max_size() != 0)
			return false;

		p /= max_size();
		if (p >= max_idx())
			return false;

		unsigned int mask = (1U << p);
		unsigned int old_bitmap = this->m_bitmap.fetch_and(~mask, memory_order_relaxed);

		/* XXX if old_bitmap == mask -> free this */

		return ((old_bitmap & mask) != 0);
	}

	/*
	 * Free memory at ptr.
	 * Throw std::invalid_argument if the pointer is invalid.
	 */
	void
	free(void* ptr)
	{
		if (!this->free(ptr, std::nothrow))
			throw std::invalid_argument("ptr invalid");
	}
};


#if WIN32
size_t
alloc_data::sys_pagesize() ILIAS_NET2_NOTHROW
{
	SYSTEM_INFO info;

	GetSystemInfo(&info);
	return info.dwPageSize;
}

/* Select a random number in range. */
uintptr_t
random_mem_addr(uintptr_t range)
{
	/* Optimization: range is a power of 2. */
	if ((range & (range - 1U)) == 0U) {
		uintptr_t result;
		win32_secure_random_buf(&result, sizeof(result));
		return (result & (range - 1U));
	}

	/*
	 * min = (std::numeric_limits<uintptr_t>::max() + 1) % range
	 */
	uintptr_t min;
	if (range + range < range)
		min = 1U + ~range;
	else
		min = ((std::numeric_limits<uintptr_t>::max() - (2 * range)) + 1) % range;

	/*
	 * Reject result until result >= min.
	 * Each has a p > 0.5 chance of success.
	 */
	uintptr_t result;
	do {
		win32_secure_random_buf(&result, sizeof(result));
	} while (result < min);

	return result % range;
}

void*
alloc_data::sys_pagealloc(size_t sz) ILIAS_NET2_NOTHROW
{
	assert((sz & (pagesize() - 1)) == 0);

	/* Figure out allocation granularity and address range. */
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	const uintptr_t alloc_mul = info.dwAllocationGranularity;
	const uintptr_t min_addr = align_up(reinterpret_cast<uintptr_t>(info.lpMinimumApplicationAddress), alloc_mul);
	const uintptr_t max_addr = align_down(reinterpret_cast<uintptr_t>(info.lpMaximumApplicationAddress), alloc_mul);

	/* Sanity check on retrieved values. */
	assert(alloc_mul >= pagesize() && alloc_mul % pagesize() == 0);
	assert(max_addr > min_addr);

	if (sz > max_addr - min_addr)
		return nullptr; /* Impossible to fit. */

	/* Generate a random address, since VirtualAlloc will not do this for us. */
	uintptr_t addr = min_addr + random_mem_addr((max_addr - min_addr - sz) / alloc_mul);
	addr *= alloc_mul;

	/* Allocate memory at our random address or somewhere close. */
	void* ptr = VirtualAlloc(reinterpret_cast<void*>(addr), sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	/*
	 * Retry, spanning the entire address range (this is similar to wrapping around the top of memory,
	 * if the VirtualAlloc is a forward-search-only allocator.
	 */
	if (ptr == nullptr)
		ptr = VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	assert(reinterpret_cast<uintptr_t>(ptr) % alloc_mul == 0);
	return ptr;
}

bool
alloc_data::sys_pagefree(void* ptr, size_t sz) ILIAS_NET2_NOTHROW
{
	assert((sz & (pagesize() - 1)) == 0);

	SYSTEM_INFO info;
	GetSystemInfo(&info);
	const uintptr_t alloc_mul = info.dwAllocationGranularity;

	if ((reinterpret_cast<uintptr_t>(ptr) % alloc_mul) != 0)
		return false;
	VirtualFree(ptr, 0, MEM_RELEASE);
}
#else
size_t
alloc_data::sys_pagesize() ILIAS_NET2_NOTHROW
{
	const long sc_rv = sysconf(_SC_PAGESIZE);
	assert(sc_rv != -1);			/* Sysconf may not fail. */
	assert(sc_rv > 0);			/* Sane number. */
	assert((sc_rv & (sc_rv - 1)) == 0);	/* Page size must be power-of-2. */
	pgsz.store(sc_rv, memory_order_relaxed);
	return sc_rv;
}

void*
alloc_data::sys_pagealloc(size_t sz) ILIAS_NET2_NOTHROW
{
	assert((sz & (pagesize() - 1)) == 0);

	void* ptr = mmap(nullptr, sz, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
	if (ptr == MAP_FAILED)
		return nullptr;
	assert((ptr & (pagesize() - 1)) == 0);	/* Common but possibly not guaranteed for all mmap implementations. */
	return ptr;
}

bool
alloc_data::sys_pagefree(void* ptr, size_t sz) ILIAS_NET2_NOTHROW
{
	assert((sz & (pagesize() - 1)) == 0);

	if ((reinterpret_cast<uintptr_t>(ptr) & (pagesize() - 1)) != 0)
		return false;

	return (munmap(ptr, pagesize()) == 0)
}
#endif

size_t
alloc_data::pagesize() ILIAS_NET2_NOTHROW
{
	static std::atomic<size_t> pgsz;

	size_t rv = pgsz.load(memory_order_relaxed);
	if (rv == 0)
		pgsz.store(rv = sys_pagesize(), memory_order_relaxed);
	return rv;
}

void*
alloc_data::operator new(size_t sz, const std::nothrow_t& unused ILIAS_NET2__unused) ILIAS_NET2_NOTHROW
{
	return sys_pagealloc(align_up(sz, pagesize()));
}

void*
alloc_data::operator new(size_t sz)
{
	void* ptr = sys_pagealloc(align_up(sz, pagesize()));
	if (!ptr)
		throw std::bad_alloc();
	return ptr;
}

void
alloc_data::operator delete(void* ptr, const std::nothrow_t& nt) ILIAS_NET2_NOTHROW
{
	return sys_pagefree(ptr, pagesize());
}

void
alloc_data::operator delete(void* ptr)
{
	return sys_pagefree(ptr, pagesize());
}


LL_HEAD(buf_alloc_list_type, alloc_data);
static buf_alloc_list_type buf_alloc_list = LL_HEAD_INITIALIZER(buf_alloc_list);
static const size_t buf_alloc_size = 512;

static inline bool
buf_alloc_on_list(size_t sz)
{
	return sz <= MIN(buf_alloc_size, alloc_data::list_max_size());
}


ILIAS_NET2_LOCAL void*
buf_alloc(size_t& sz, const std::nothrow_t& unused ILIAS_NET2__unused) ILIAS_NET2_NOTHROW
{
	if (buf_alloc_on_list(sz)) {
	}
}

ILIAS_NET2_LOCAL bool
buf_extend(void* ptr, size_t& sz, const std::nothrow_t& unused ILIAS_NET2__unused) ILIAS_NET2_NOTHROW
{
}

}
