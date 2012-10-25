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


class pool_osdep
{
private:
	enum init_state {
		NONE,
		BUSY,
		DONE
	};

	std::atomic<init_state> m_state;

	void init() ILIAS_NET2_NOTHROW;

#ifdef WIN32
	SYSTEM_INFO info;
#else
	long pagesize;
#endif

	constexpr osdep() :
		m_state(NONE)
	{
		return;
	}

	static pool_osdep singleton;

	void
	init() ILIAS_NET2_NOTHROW
	{
		init_state curstate = NONE;
		if (m_state.compare_exchange_strong(curstate, BUSY, memory_order_acquire, memory_order_acquire)) {
#ifdef WIN32
			GetSystemInfo(&info);
#else
			pagesize = sysconf(_SC_PAGESIZE);
			assert(pagesize != -1);	/* XXX Would this ever fail? */
#endif
			m_state.store(DONE, memory_order_release);
		} else {
			while (curstate != DONE)
				curstate = m_state.load(memory_order_acquire);
		}
	}

public:
	static uintptr_t
	pagesize() ILIAS_NET2_NOTHROW
	{
		singleton.init();
#ifdef WIN32
		return singleton.info.dwPageSize;
#else
		return singleton.pagesize;
#endif
	}

	static uintptr_t
	alloc_align() ILIAS_NET2_NOTHROW
	{
		singleton.init();
#ifdef WIN32
		return singleton.info.dwAllocationGranularity;
#else
		return singleton.pagesize;
#endif
	}

#ifdef WIN32
	static uintptr_t
	min_addr() ILIAS_NET2_NOTHROW
	{
		singleton.init();
		return reinterpret_cast<uintptr_t>(singleton.info.lpMinimumApplicationAddress);
	}

	static uintptr_t
	max_addr() ILIAS_NET2_NOTHROW
	{
		singleton.init();
		return reinterpret_cast<uintptr_t>(singleton.info.lpMaximumApplicationAddress);
	}
#endif

	static void* valloc(uintptr_t size, uintptr_t commit_size) ILIAS_NET2_NOTHROW;
	static bool vfree(void* ptr, uintptr_t size) ILIAS_NET2_NOTHROW;
	static bool activate(void* ptr, uintptr_t commit_size) ILIAS_NET2_NOTHROW;
	static bool deactivate(void* ptr, uintptr_t commit_size) ILIAS_NET2_NOTHROW;
};


void*
pool_osdep::valloc(uintptr_t size, uintptr_t commit_size) ILIAS_NET2_NOTHROW
{
	assert(commit_size <= size);

	singleton.init();

	const uintptr_t align = singleton.info.dwAllocationGranularity;
	const uintptr_t pagesize = singleton.info.dwPageSize;
	const uintptr_t min_addr = round_up(reinterpret_cast<uintptr_t>(singleton.info.lpMinimumApplicationAddress), align);
	const uintptr_t max_addr = reinterpret_cast<uintptr_t>(singleton.info.lpMinimumApplicationAddress);

	assert(min_addr < max_addr);	/* Sanity. */
	if (max_addr - min_addr < size)
		return nullptr;		/* Too large. */

	/* Generate a random address for VirtualAlloc, since it lacks aslr semantics. */
	const uintptr_t aslr = min_addr + random_mem_addr((max_addr - min_addr - size) / align) * align;

	/* Allocate memory at our aslr address. */
	void* ptr = VirtualAlloc(reinterpret_cast<void*>(aslr), roundup(sz, pagesize), MEM_RESERVE, PAGE_READWRITE);
	if (ptr == nullptr) {
		/* Retry allocation, allowing any address. */
		ptr = VirtualAlloc(nullptr, roundup(sz, pagesize), MEM_RESERVE, PAGE_READWRITE);
	}
	/* Handle allocation failure. */
	if (ptr == nullptr)
		return nullptr;

}


struct pool::page_hdr :
	public ll_entry
{
private:
	const uintptr_t magic;			/* Magic value. */
	size_t len;				/* Allocation length in bytes. */
	const size_t entries_per_page;		/* # bitmaps per page. */
	const size_t entry_size;		/* Size per entries. */
	const size_t align;			/* Alignment. */
	const size_t offset;			/* Offset in alignment. */
	std::atomic<unsigned int> flags;	/* Flag bits. */

	static constexpr unsigned int FL_DEINIT = 0x0002;
	static constexpr unsigned int FL_QMANIP = 0x0001;

public:
	/* Type used to index bitmap lengths. */
	typedef std::atomic<unsigned short> bitmap_len_type;

	/* Offset at which bitmap starts. */
	static constexpr size_t
	ph_bitmap_offset() ILIAS_NET2_NOTHROW
	{
		return roundup(sizeof(page_hdr), sizeof(page_hdr::bitmap_len_type));
	}

	/* Return bitmap array address for given page header. */
	static constexpr bitmap_len_type&
	ph_bitmap(page_hdr* ph) ILIAS_NET2_NOTHROW
	{
		return *reinterpret_cast<bitmap_len_type*>(reinterpret_cast<uintptr_t>(ph) + ph_bitmap_offset());
	}
	/* Return bitmap array address for given page header. */
	static constexpr const bitmap_len_type&
	ph_bitmap(const page_hdr* ph) ILIAS_NET2_NOTHROW
	{
		return *reinterpret_cast<const bitmap_len_type*>(reinterpret_cast<uintptr_t>(ph) + ph_bitmap_offset());
	}
	/* Return bitmap array address for given page header. */
	static constexpr bitmap_len_type&
	ph_bitmap(page_hdr* ph, size_t idx) ILIAS_NET2_NOTHROW
	{
		return ph_bitmap(ph)[idx];
	}
	/* Return bitmap array address for given page header. */
	static constexpr const bitmap_len_type&
	ph_bitmap(const page_hdr* ph, size_t idx) ILIAS_NET2_NOTHROW
	{
		return ph_bitmap(ph)[idx];
	}

	/* Test if this page header has a bitmap. */
	bool
	has_bitmap() const ILIAS_NET2_NOTHROW
	{
		return (this->len == 0);
	}

	/* Calculate the offset in page where entries start. */
	uintptr_t
	entries_offset() const ILIAS_NET2_NOTHROW
	{
		/* Calculate end of bitmap. */
		const uintptr_t delta = ph_bitmap_offset() + this->entries_per_page * sizeof(bitmap_len_type);

		/* Subtract offset of entries. */
		if (this->offset >= delta)
			delta = 0;
		else
			delta -= this->offset;

		/* Align delta to alignment constraint. */
		delta = round_up(delta, this->align);
		/* Add offset. */
		delta += this->offset;

		return delta;
	}

	/* Find the entry with the given index. */
	void*
	entry_ptr(size_t idx = 0) const ILIAS_NET2_NOTHROW
	{
		uintptr_t ptr = reinterpret_cast<uintptr_t>(static_cast<const void*>(this));
		ptr += this->entries_offset();
		ptr += idx * this->entry_size;
		return reinterpret_cast<void*>(ptr);
	}

	/*
	 * Find the index that a given pointer points to.
	 *
	 * Returns (std::numeric_limits<size_t>::max(), false) when the pointer falls outside this page.
	 * Returns (index, true) if the pointer matches index exactly.
	 * Returns (index, false) if the pointer is at index, but does not meet exactly.
	 */
	std::pair<size_t, bool>
	entry_idx(const void* p) const ILIAS_NET2_NOTHROW
	{
		typedef std::pair<size_t, bool> result_type;

		uintptr_t ptr = reinterpret_cast<uintptr_t>(p);
		uintptr_t base = round_down(ptr, pool_osdep::alloc_align());
		if (base != reinterpret_cast<uintptr_t>(static_cast<const void*>(this)))
			return result_type(std::numeric_limits<size_t>::max(), false);

		uintptr_t off = ptr - this->offset - (base + entries_offset);
		result_type rv(off / this->entry_size, off % this->entry_size == 0);

		if (rv.off >= this->entries_per_page && this->entries_per_page != 0)
			return result_type(std::numeric_limits<size_t>::max(), false);
		return rv;
	}

	/* Shared page initialization. */
	page_hdr(pool& pl) ILIAS_NET2_NOTHROW :
		magic(pl.magic()),
		len(0),
		entries_per_page(pl.entries_per_page()),
		entry_size(pl.alloc_sz),
		align(pl.align),
		offset(pl.offset),
		flags(0)
	{
		assert(reinterpret_cast<uintptr_t>(this) % pool_osdep::alloc_align() == 0);

		LL_INIT_ENTRY(this);

		for (size_t i = 0; i < this->entries_per_page; ++i)
			new (&ph_bitmap(this, i)) bitmap_len_type(0);
	}

	/* Big page initialization. */
	page_hdr(pool& pl, size_t len) ILIAS_NET2_NOTHROW :
		magic(pl.magic()),
		len(len),
		entries_per_page(0),
		entry_size(0),
		align(pl.align),
		offset(pl.offset),
		flags(0)
	{
		assert(reinterpret_cast<uintptr_t>(this) % pool_osdep::alloc_align() == 0);
		assert(len >= pool_osdep::page_size());

		LL_INIT_ENTRY(this);
	}

	/*
	 * Mark page header for deinit.
	 *
	 * Ensures pageheader will be off the queue and never reappear there.
	 * Returns true if this thread acquired the deinit lock.
	 */
	bool
	deinit_mark(pool& pl) ILIAS_NET2_NOTHROW
	{
		assert(pl.magic() == this->magic);

		/* Acquire deinit lock. */
		auto fl = this->flags.fetch_or(FL_DEINIT, memory_order_acquire);
		if (fl & FL_DEINIT)
			return false;
		if (this->has_bitmap() && !this->empty()) {
			this->flags.fetch_and(~FL_DEINIT, memory_order_release);
			ll_insert_tail(&pl.head, this, 0);
			return false;
		}

		/* Wait until queue manipulation ends. */
		while (fl & FL_QMANIP)
			fl = this->flags.load(memory_order_acquire);

		/* Ensure this is not on the queue. */
		ll_unlink(&pl.head, this, 1);

		return true;
	}

	/*
	 * Test if the page is empty.
	 * Returns false for big pages.
	 */
	bool
	empty() const ILIAS_NET2_NOTHROW
	{
		for (size_t i = 0; i < this->entries_per_page; i++) {
			if (ph_bitmap(this, i).load(memory_order_acquire) != 0)
				return false;
		}
		return this->has_bitmap();
	}


#ifdef HAS_DELETED_FN
	page_hdr() = delete;
	page_hdr(const page_hdr&) = delete;
	bool operator==(const page_hdr&) const = delete;
	page_hdr& operator=(const page_hdr&) = delete;
#else
private:
	page_hdr();
	page_hdr(const page_hdr&);
	bool operator==(const page_hdr&) const;
	page_hdr& operator=(const page_hdr&);
#endif
};


class pool
{
public:
	typedef size_t size_type;
	typedef void* pointer;

private:
	/* Round v up to multiple of mul. */
	template<typename Scalar>
	static constexpr Scalar
	round_up(Scalar v, Scalar mul) ILIAS_NET2_NOTHROW
	{
		/* Ternary operator to select power-of-2 optimization. */
		return ((mul & (mul - 1)) == 0 ? (v & ~(mul - 1)) : (v - v % mul));
	}
	/* Round v down to multiple of mul. */
	template<typename Scalar>
	static constexpr Scalar
	round_down(Scalar v, Scalar mul) ILIAS_NET2_NOTHROW
	{
		return round_down(v + mul - 1, mul);
	}

	uintptr_t
	magic() const ILIAS_NET2_NOTHROW
	{
		static const uintptr_t MASK = 0x706f6f6cU;	/* 'pool' in hex ascii */
		return reinterpret_cast<uintptr_t>(this) ^ MASK;
	}

	/* Alignment of allocations. */
	const size_type align;
	/* Size per allocation, rounded for alignment considerations. */
	const size_type alloc_sz;
	/* Offset in alignment. */
	const size_type offset;

	/* List of pages with free room. */
	ll_head head;

	/* # entries per allocation. */
	size_type
	entries_per_page() const ILIAS_NET2_NOTHROW
	{
		/*
		 * Calculate requirement:
		 * - 1 page header
		 * - [items] number of bitmap_len_type (so extended allocations can be written down)
		 * - [items] alloc_sz (to store the actual data in)
		 */
		size_type items = (pool_osdep::alloc_align() - sizeof(page_hdr)) / (alloc_sz + sizeof(page_hdr::bitmap_len_type));

		/* Validate above calculation (I'm paranoid). */
		assert(sizeof(page_hdr) + items * sizeof(bitmap_len_type) + items * alloc_sz <= pool_osdep::alloc_align());

		return items;
	}

	/* Figure out where the page header to the given pointer lives. */
	page_hdr*
	find_page_hdr(pointer ptr) const ILIAS_NET2_NOTHROW
	{
		page_hdr*const ph = reinterpret_cast<page_hdr*>(round_down(reinterpret_cast<uintptr_t>(ptr), pool_osdep::alloc_align()));

		if (ph == nullptr || ph->magic != this->magic())
			return nullptr;
		return ph;
	}

	/*
	 * Create a new shared page.
	 *
	 * The new page is not added to the list of pages.
	 */
	page_hdr*
	new_shared_page() ILIAS_NET2_NOTHROW
	{
		page_hdr*const ph = pool_osdep::valloc(pool_osdep::alloc_align(), pool_osdep::pagesize());
		if (ph == nullptr)
			return nullptr;

		new (ph) page_hdr(*this);
		return ph;
	}

	/*
	 * Delete a shared page.
	 * Returns true on succes, false on failure.
	 */
	bool
	delete_shared_page(page_hdr* ph) ILIAS_NET2_NOTHROW
	{
		assert(ph->magic == this->magic());
		assert(ph->len == 0);

		if (!ph->deinit_mark())
			return false;
		ll_unlink(&head, ph, 1);

		ph::~page_hdr();
		pool_osdep::vfree(ph, pool_osdep::alloc_align());
		return true;
	}

public:
	constexpr pool(size_type size, size_type align = std::max(sizeof(double), sizeof(void*)), size_type offset = 0) :
		align(align),
		offset(offset),
		alloc_sz(round_up(size, std::max(sizeof(bitmap_len_type), align)))
	{
		LL_INIT__LL_HEAD(&this->head);
	}

	pointer
	allocate_bytes(size_type bytes) ILIAS_NET2_NOTHROW
	{
		/* Figure out how many entries are required. */
		size_type n_entries = std::max(1U, (bytes + alloc_sz - 1) / alloc_sz);

		if (n_entries > entries_per_page()) {
			/* Allocate a big, non-shared page. */
			...
		} else {
			/* Allocate from a shared page. */
			...
		}
	}

	bool
	deallocate_bytes(pointer ptr, size_type bytes) ILIAS_NET2_NOTHROW
	{
		/* Figure out how many entries are required. */
		size_type n_entries = std::max(1U, (bytes + alloc_sz - 1) / alloc_sz);

		page_hdr* ph = find_page_hdr(ptr);
		if (ph == nullptr)
			return false;

		if (ph->len != 0) {
			/* Free a big, non-shared page. */
			...
		} else {
			/* Free from a shared page. */
			...
		}
	}
};


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
