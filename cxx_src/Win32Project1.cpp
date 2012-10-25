// Win32Project1.cpp : Defines the exported functions for the DLL application.
//

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define NOMINMAX			// Exclude min/max macros.

#include "Win32Project1.h"

#include <atomic>
#include <functional>
#include <limits>
#include <memory>
#include <stdexcept>
#include <Windows.h>
#include <NTSecAPI.h>


/* Compatibility defines. */
#ifdef _MSC_VER
#define constexpr	/* Unsupported. */
#define constexpr_value	const
#else
#define constexpr_value	constexpr
#endif


class pool
{
public:
	typedef size_t size_type;
	typedef ptrdiff_t difference_type;

private:
	class osdep;
	class page;

	template<typename T>
	static T&&
	round_down(const T& v, const T& r)
	{
		return std::move((r & (r - 1)) == 0 ? (v & ~(r - 1)) : (v - v % r));
	}

	template<typename T>
	static T&&
	round_up(const T& v, const T& r)
	{
		return std::move(round_down(v + r - 1, r));
	}

public:
	const size_type align;
	const size_type offset;
	const size_type size;

	static constexpr_value size_t default_align = (sizeof(double) > sizeof(void*) ? sizeof(double) : sizeof(void*));
	static constexpr_value size_t default_offset = 0;

	constexpr pool(size_type size, size_type align = default_align, size_type offset = default_offset) :
		align(std::min(align, 1U)),
		offset(offset % this->align),
		size(round_up(size, this->align))
	{
		return;
	}

private:
	inline size_t entries_per_page() const;

	void page_enqueue(page*);
	void dealloc_page(page*);

	struct deleter_type;
	typedef std::unique_ptr<page, deleter_type> page_ptr;

	page_ptr&& alloc_page();
	page_ptr&& pop_page();
	page_ptr&& alloc_big_page(size_t);

public:
	void* allocate(size_type, void*);
	void deallocate(void*, size_type);
	bool resize(void*, size_type, size_type);

	constexpr size_type
	maxsize() const
	{
		return (std::numeric_limits<size_type>::max() / this->size);
	}

	constexpr size_type
	maxsize_bytes() const
	{
		return maxsize() * this->size;
	}

	void*
	allocate_bytes(size_type bytes, void* hint)
	{
		return allocate((bytes + this->size - 1) / this->size, hint);
	}

	void
	deallocate_bytes(void* addr, size_type bytes)
	{
		return deallocate(addr, (bytes + this->size - 1) / this->size);
	}

	bool
	resize_bytes(void* addr, size_type old_bytes, size_type new_bytes)
	{
		const size_type old_n = (old_bytes + this->size - 1) / this->size;
		const size_type new_n = (new_bytes + this->size - 1) / this->size;
		return resize(addr, old_n, new_n);
	}

private:
	static inline size_type waste(size_type, size_type, size_type);

public:
	static size_type recommend_size(size_type min, size_type max, size_type align = default_align, size_type offset = default_offset);
};


template<typename T, size_t Align = pool::default_align, size_t Offset = pool::default_offset>
class pool_allocator :
	private pool
{
public:
	/* Declare allocator member types. */
	typedef T value_type;
	typedef value_type& reference;
	typedef const value_type& const_reference;
	typedef value_type* pointer;
	typedef const value_type* const_pointer;

	/* Import pool member types. */
	using pool::size_type;
	using pool::difference_type;

	/* Expose pool constants. */
	using pool::align;
	using pool::offset;
	using pool::size;

	template<typename U, size_t U_Align = Align, size_t U_Offset = Offset>
	struct rebind {
		typedef pool_allocator<U, U_Align, U_Offset> type;
	};

	constexpr pool_allocator() :
		pool(sizeof(T), Align, Offset)
	{
		return;
	}

	pool_allocator(const pool_allocator&) = delete;
	pool_allocator& operator=(const pool_allocator&) = delete;

	pointer
	allocate(size_type n, typename pool_allocator<void>::pointer hint = nullptr)
	{
		return this->pool::allocate(n, hint);
	}

	pointer
	deallocate(typename pool_allocator<void>::pointer ptr, size_type n)
	{
		this->pool::deallocate(ptr, n);
	}

	bool
	resize(pointer p, size_type old_n, size_type new_n)
	{
		this->pool::resize(p, old_n, new_n);
	}

	static pointer
	address(reference v) const
	{
		typedef char& casted;
		return reinterpret_cast<pointer>(&reinterpret_cast<casted>(v));
	}

	static const_pointer
	address(const_reference v) const
	{
		typedef const char& casted;
		return reinterpret_cast<const_pointer>(&reinterpret_cast<casted>(v));
	}

	template<typename U, typename... Args>
	static void
	construct(U* p, Args&&... args)
	{
		new(p) value_type(args...);
	}

	static void
	construct(pointer p, const_reference v)
	{
		new(p) value_type(v);
	}

	template<typename U>
	static void
	destroy(U* p)
	{
		p->~value_type();
	}

	static void
	destroy(pointer p)
	{
		p->~value_type();
	}
};

/*
 * pool_allocator<void> is not instantiable.
 */
template<size_t Align, size_t Offset>
class pool_allocator<void, Align, Offset>
{
public:
	/* Declare allocator member types. */
	typedef void value_type;
	typedef value_type* pointer;
	typedef const value_type* const_pointer;

	/* Import pool member types. */
	typedef pool::size_type size_type;
	typedef pool::difference_type difference_type;

	pool_allocator() = delete;
	pool_allocator(const pool_allocator&) = delete;
	pool_allocator& operator=(const pool_allocator&) = delete;
};


/*
 * Tracking of allocation data.
 */
class pool::page
{
public:
	enum page_type {
		SHARED_PAGE,
		BIG_PAGE
	};

	const page_type type;
	size_t alloclen;
	size_t n_entries;
	const size_t entry_size;
	const size_t align;
	const size_t offset;

private:
	template<typename T>
	struct atomic_type;

	template<typename T>
	struct atomic_type< std::atomic<T> > {
		typedef T type;
	};

	typedef std::atomic<uintptr_t> entry_type;
	static const size_t bitmap_bits = std::numeric_limits<atomic_type<entry_type>::type>::digits;

	static constexpr size_t
	entries_offset()
	{
		return round_up(sizeof(page), sizeof(entry_type));
	}

	static constexpr size_t
	bitmap_space(size_t n_entries)
	{
		return (n_entries + bitmap_bits - 1) / bitmap_bits;
	}

public:
	/* Calculate which amount of space at the beginning of the allocation is used for keeping track. */
	static constexpr size_t
	overhead(size_t n_entries, size_t align, size_t offset)
	{
		return round_up(std::max(entries_offset() + bitmap_space(n_entries), offset) - offset, align) + offset;
	}
	/* Calculate which amount of space at the beginning of the allocation is used for keeping track. */
	size_t
	overhead() const
	{
		size_t n_entries;

		switch (this->type) {
		case BIG_PAGE:
			n_entries = 0;
			break;
		case SHARED_PAGE:
			n_entries = this->n_entries;
			break;
		}
		return overhead(this->n_entries, this->align, this->offset);
	}

	/* Calculate the number of entries that will fit in a page (allocation size osdep::page_align()). */
	static size_t
	page_entries_max(size_t sz, size_t align, size_t offset)
	{
		const auto delta = round_up(sz, align);	/* Round up to alignment. */
		const osdep& os = osdep::get();

		/*
		 * Calculate number of entries that fit.
		 * Note that alignment constraints may force us to reduce the number found here.
		 */
		size_t n_entries = (os.alloc_align() - entries_offset()) / (delta + sizeof(entry_type));
		while (n_entries > 1 && overhead(n_entries, align, offset) + n_entries * delta > os.alloc_align())
			n_entries--;

		return (n_entries <= 1 ? 0 : n_entries);
	}

private:
	/* Calculate array size for bitmap. */
	static constexpr size_t
	bitmap_maxidx(size_t n_entries)
	{
		return (bitmap_space(n_entries) / sizeof(entry_type));
	}

	/* Return bitmap array. */
	entry_type*
	bitmap()
	{
		return reinterpret_cast<entry_type*>(reinterpret_cast<uintptr_t>(static_cast<void*>(this)) + entries_offset());
	}
	/* Return bitmap array. */
	const entry_type*
	bitmap() const
	{
		return reinterpret_cast<const entry_type*>(reinterpret_cast<uintptr_t>(static_cast<const void*>(this)) + entries_offset());
	}

public:
	/* Return address to data. */
	void*
	data() const
	{
		return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(static_cast<const void*>(this)) + overhead());
	}

	/* Return address to data at index. */
	void*
	data(size_t idx) const
	{
		return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(data()) + idx * this->entry_size);
	}

private:
	/*
	 * Lookup the index of the entry containing ptr.
	 *
	 * Returns index, bool of the entry.
	 * The bool is true if the pointer points exactly at entry.
	 */
	std::pair<size_t, bool>
	index(void* ptr) const
	{
		typedef std::pair<size_t, bool> result_type;

		assert(ptr >= data());
		uintptr_t p = reinterpret_cast<uintptr_t>(ptr);
		p -= reinterpret_cast<uintptr_t>(data());
		return result_type(p / this->entry_size, p % this->entry_size == 0);
	}

	template<typename T, size_t p>
	struct log2_inner {
	private:
		typedef struct log2_inner<T, p / 2> log2_succ;

		template<typename size_t q>
		struct mask_generator {
			static constexpr_value T pred = mask_generator<q / 2>::value;
			static constexpr_value T value = pred | (pred << (q / 2));
		};

		template<>
		struct mask_generator<2 * p>
		{
			static constexpr_value T value = (((T(1) << p) - 1) << p);
		};

		static constexpr_value V mask = mask_generator<std::numeric_limits<T>::digits>::value;

	public:
		static constexpr unsigned int
		get(const T& v)
		{
			return ((v & mask) ? p, 0) + log2_succ::get(v);
		}
	};

	template<typename T>
	struct log2_inner<T, 0> {
		static constexpr unsigned int
		operator()(const T& v)
		{
			return 0;
		}
	};

	/* Calculate the largest log2 where 2^result <= value. */
	template<typename T>
	static constexpr unsigned int
	log2_down(const T& value)
	{
		return log2_inner<T, std::numeric_limits<T>::digits / 2>::get(v);
	}
	/* Calculate the smallest log2 where 2^result >= value. */
	template<typename T>
	static constexpr unsigned int
	log2_up(const T& value)
	{
		return log2_down(2 * value - 1);
	}

	template<typename T>
	static constexpr T&&
	invert_bits(const T& v, const unsigned int& pow2_max)
	{
		T rv = v;

		for (unsigned int i = 0; i < pow2_max / 2; i++) {
			l_mask = 0x1 << i;
			r_mask = 0x1 << (limit - 1 - i);

			const bool l = ((rv & l_mask) == 0);
			const bool r = ((rv & r_mask) == 0);
			if (l != r)
				rv ^= (l_mask | r_mask);
		}
		return std::move(rv);
	}

	/*
	 * Calculate the mask describing [first..last).
	 */
	static constexpr atomic_type<entry_type>::type
	mask(size_t first, size_t last)
	{
		typedef atomic_type<entry_type>::type u_type;
		const u_type one = 1;

		assert(first >= 0);
		assert(last <= bitmap_bits);
		assert(first <= last);

		if (first == last)
			return 0;

		const u_type last_mask = (std::numeric_limits<u_type>::max() >> (bitmap_bits - last));
		const u_type first_mask = (one << first);
		return (first_mask & last_mask);
	}

	/*
	 * Acquire all bits describing entries [idx .. idx + count).
	 * Returns true on succes.
	 * No change on failure.
	 */
	bool
	acquire(size_t idx, size_t count, bool mark_inuse = true)
	{
		assert(this->type == SHARED_PAGE);	/* Shared pages only. */

		/* Argument check: if the allocation cannot fail/succeed, return appropriate error immediately. */
		if (count == 0)
			return true;
		if (idx + count < idx || idx + count >= this->n_entries)
			return false;

		entry_type*const arr = this->bitmap() + (idx / bitmap_bits);
		const auto off = idx % bitmap_bits;
		const auto last = (off + count);

		/* Mark the first entry_type bits for allocation. */
		const auto first_mask = mask(off, std::min(bitmap_bits, last));
		const auto orig = (arr[0].fetch_or(first_mask, std::memory_order_relaxed) & first_mask);
		if (orig != 0)
			goto undo_first;
		/* Test if this is one of those allocations that fits in a single entry. */
		if (last <= bitmap_bits)
			return true;

		/* Mark intermediate bits for allocation. */
		size_t i;
		for (i = 1; i < (last - 1) / bitmap_bits; ++i) {
			atomic_type<entry_type>::type zero = 0;
			if (!arr[i].compare_exchange_strong(zero, mask(0, bitmap_bits), std::memory_order_relaxed, std::memory_order_relaxed))
				goto undo_between;
		}

		/* Mark final bits for allocation. */
		const size_t last_idx = (last - 1) / bitmap_bits;
		const auto last_mask = mask(0, (last - 1) % bitmap_bits + 1);
		const auto last_orig = arr[last_idx].fetch_or(last_mask, std::memory_order_relaxed) & last_mask;
		if (last_orig != 0)
			goto undo_last;

		/* Commit memory. */
		if (mark_inuse) {
			const osdep& os = osdep::get();
			const uintptr_t start_addr = round_down(reinterpret_cast<uintptr_t>(data(idx)), os.pagesize());
			const uintptr_t end_addr = round_up(reinterpret_cast<uintptr_t>(data(idx + count)), os.pagesize());
			assert(end_addr - start_addr <= std::numeric_limits<size_t>::max());
			if (!os.commit_mem(reinterpret_cast<void*>(start_addr), end_addr - start_addr))
				goto undo_last;
		}

		/* All bits were succesfully acquired, allocation succeeded. */
		return true;


		/* Undo after failure routines. */
undo_last:
		arr[last_idx].fetch_and(last_orig | ~last_mask, std::memory_order_relaxed);
undo_between:
		while (--i > 0)
			arr[i].store(0, std::memory_order_relaxed);
undo_first:
		arr[0].fetch_and(orig | ~first_mask, std::memory_order_relaxed);
		/* Return failure. */
		return false;
	}

	/*
	 * Release memory previously acquired using acquire.
	 * All memory must be in use (assert failure).
	 */
	void
	release(size_t idx, size_t count, bool mark_unused = true)
	{
		assert(this->type == SHARED_PAGE);	/* Shared pages only. */

		assert(idx + count > idx);	/* Fails on overflow. */
		assert(idx + count <= this->n_entries);

		/* Release of 0 bytes is a no-op. */
		if (count == 0)
			return;

		entry_type*const arr = this->bitmap() + (idx / bitmap_bits);
		const auto off = idx % bitmap_bits;
		const auto last = (off + count);

		/* Mark the first entry_type bits for allocation. */
		const auto first_mask = mask(off, std::min(bitmap_bits, last));
		const auto orig = (arr[0].fetch_and(~first_mask, std::memory_order_relaxed) & first_mask);
		assert(orig == first_mask);
		/* Test if this is one of those allocations that fits in a single entry. */
		if (last <= bitmap_bits)
			return;

		/* Mark intermediate bits for allocation. */
		for (size_t i = 1; i < (last - 1) / bitmap_bits; ++i) {
			auto prev = arr[i].exchange(0, std::memory_order_relaxed);
			assert(~prev == 0);
		}

		/* Mark final bits for allocation. */
		const size_t last_idx = (last - 1) / bitmap_bits;
		const auto last_mask = mask(0, (last - 1) % bitmap_bits + 1);
		const auto last_orig = arr[last_idx].fetch_or(last_mask, std::memory_order_relaxed) & last_mask;
		assert(last_orig == last_mask);

		/*
		 * Inform the OS of any pages in this range that are no longer in use.
		 *
		 * This is an optimization and thus we allow it to fail.
		 * The idea is that the OS can re-use the physical pages from this memory
		 * more efficiently than leaving it commited to this freed memory.
		 */
		if (mark_unused) {
			const osdep& os = osdep::get();
			const uintptr_t start_addr = std::max(
			    round_down(reinterpret_cast<uintptr_t>(data(idx)), os.pagesize()),
			    round_up(overhead(), os.pagesize()));
			const uintptr_t end_addr = round_up(reinterpret_cast<uintptr_t>(data(idx + count)), os.pagesize());

			for (uintptr_t addr = start_addr; addr < end_addr; addr += os.pagesize()) {
				const auto start_idx = index(reinterpret_cast<void*>(addr)).first;
				const auto end_idx = index(reinterpret_cast<void*>(addr + os.pagesize() - 1)).first + 1;
				if (!acquire(start_idx, end_idx - start_idx, false))
					continue;

				/* XXX collate these calls into bigger calls? */
				os.release_mem(reinterpret_cast<void*>(addr), os.pagesize());	/* Failure is acceptable. */
				release(start_idx, end_idx - start_idx, false);
			}
		}
	}

public:
	/* Constructor. */
	page(page_type type, size_t alloclen, size_t n_entries, size_t entry_size, size_t align, size_t offset) :
		type(type),
		alloclen(alloclen),
		n_entries(n_entries),
		entry_size(round_up(entry_size, align)),
		align(align),
		offset(offset)
	{
		const osdep& os = osdep::get();
		assert(reinterpret_cast<uintptr_t>(static_cast<void*>(this)) % os.alloc_align() == 0);
		assert(n_entries > 0);

		/* Initialize the bitmap. */
		switch (type) {
		case SHARED_PAGE:
			entry_type* bm = this->bitmap();
			for (size_t i = 0; i < bitmap_maxidx(n_entries); ++i, ++bm)
				new (bm) entry_type(0);
			break;
		case BIG_PAGE:
			assert(reinterpret_cast<uintptr_t>(static_cast<void*>(this)) + alloclen >= reinterpret_cast<uintptr_t>(this->data(n_entries)));
			break;
		}
		return;
	}

	/* Destructor. */
	~page()
	{
		assert(this->empty());

		/* Destroy the bitmap. */
		switch (this->type) {
		case SHARED_PAGE:
			{
				entry_type* bm = this->bitmap();
				for (size_t i = 0; i < bitmap_maxidx(n_entries); ++i, ++bm)
					bm->~entry_type();
			}
			break;
		case BIG_PAGE:
			break;
		}
	}

	/* Test if the page is empty (nothing is in use). */
	bool
	empty() const
	{
		switch (this->type) {
		case SHARED_PAGE:
			{
				const entry_type* bm = this->bitmap();
				for (size_t i = 0; i != this->bitmap_maxidx(this->n_entries); ++i, ++bm) {
					if (bm->load(std::memory_order_relaxed) != 0U)
						return false;
				}
				return true;
			}
			break;
		case BIG_PAGE:
			return (this->n_entries == 0);
			break;
		}
	}

	/* Allocate space for count contiguous entries. */
	void*
	allocate(size_t count)
	{
		if (this->type != SHARED_PAGE)
			return nullptr;
		if (count > this->n_entries)
			return nullptr;

		/*
		 * This for-loop simulates a breadth-first tree search.
		 * For example, n_entries = 8:
		 * [0, 4, 2, 6, 1, 5, 3, 7].
		 *
		 * Since invert_bits requires a power-of-2, rejection is used to skip indices
		 * that are out-of-bounds.
		 */
		for (size_t i = 0; i < log2_up(this->n_entries); ++i) {
			const size_t idx = invert_bits(i, log2_up(this->n_entries));
			if (idx + count > this->n_entries || idx + count < idx)
				continue;	/* Reject oversized indices. */

			if (this->acquire(idx, count))
				return this->data(idx);
		}
		return nullptr;
	}

	/* Allocate entries at a specific address. */
	void*
	allocate(void* p, size_t offset, size_t count)
	{
		if (this->type != SHARED_PAGE)
			return nullptr;
		if (offset > this->n_entries || count > this->n_entries)
			return nullptr;
		const auto idx = index(p);
		if (!idx.second)
			return false;
		if (idx.first > this->n_entries - offset)
			return false;
		if (this->n_entries - idx.first < offset + count)
			return false;

		if (this->acquire(idx.first + offset, count))
			return this->data(idx.first + offset);
		return nullptr;
	}

	/* Free space for count contiguous entries. */
	bool
	deallocate(void* ptr, size_t count)
	{
		if (this->type != SHARED_PAGE)
			return false;

		/* Check if this pointer is valid. */
		if (count > this->n_entries || ptr < data() || ptr >= data(this->n_entries - count))
			return false;

		/* Lookup index and ensure pointer is an exact match. */
		const auto idx = index(ptr);
		if (!idx.second)
			return false;

		this->release(idx.first, count);
		return true;
	}

	/* Free space at pointer relative to offset. */
	bool
	deallocate(void* ptr, size_t offset, size_t count)
	{
		if (this->type != SHARED_PAGE)
			return false;

		/* Check if this pointer is valid. */
		if (count + offset > this->n_entries || ptr < data() || ptr >= data(this->n_entries - (count + offset)))
			return false;

		/* Lookup index and ensure pointer is an exact match. */
		const auto idx = index(ptr);
		if (!idx.second)
			return false;

		this->release(idx.first + offset, count);
		return true;
	}

	/* Change the number of entries in a big page. */
	bool
	resize(void* ptr, size_t old_n, size_t new_n)
	{
		if (this->type != BIG_PAGE)
			return false;

		if (this->n_entries != old_n || ptr != this->data())
			return false;
		if (new_n == old_n)
			return true;

		const osdep& os = osdep::get();
		const uintptr_t new_addr = round_up(reinterpret_cast<uintptr_t>(data(new_n)), os.pagesize());
		const uintptr_t old_addr = round_up(reinterpret_cast<uintptr_t>(data(old_n)), os.pagesize());
		const uintptr_t base = reinterpret_cast<uintptr_t>(static_cast<void*>(this));
		const uintptr_t top = base + this->alloclen;

		if (new_n < old_n) {
			this->n_entries = new_n;

			if (old_addr != new_addr)
				os.release_mem(reinterpret_cast<void*>(new_addr), old_addr - new_addr);
		} else {
			/* Allocate more virtual memory at the end of this. */
			if (new_addr > top) {
				const uintptr_t new_top = round_up(new_addr, os.alloc_align());
				if (!os.valloc(reinterpret_cast<void*>(top), new_top - top))
					return false;
				this->alloclen = new_top - base;
			}

			/* Commit more memory in the allocated range. */
			if (new_addr > old_addr && !os.commit_mem(reinterpret_cast<void*>(old_addr), new_addr - old_addr)) {
				return false;
			}

			/* Allocation succesful. */
			this->n_entries = new_n;
		}

		/* End of function reached means resize operation was succesful. */
		assert(ptr == this->data());	/* Failure means data() calculation is wrong for big pages. */
		return true;
	}
};


/*
 * Abstraction of OS dependant routines.
 */
class pool::osdep
{
private:
#ifdef WIN32
	SYSTEM_INFO info;

	osdep()
	{
		GetSystemInfo(&info);
	}
#else
	long pagesize;

	osdep() :
		pagesize(sysconf(_SC_PAGESIZE))
	{
		assert(pagesize > 0);
	}
#endif /* WIN32 */

public:
	static const osdep&
	get()
	{
		static osdep singleton;
		return singleton;
	}

	uintptr_t
	pagesize() const
	{
#ifdef WIN32
		return this->info.dwPageSize;
#else
		return this->pagesize;
#endif
	}

	uintptr_t
	alloc_align() const
	{
#ifdef WIN32
		return this->info.dwAllocationGranularity;
#else
		return this->pagesize;
#endif
	}

#ifdef WIN32
	uintptr_t
	min_vaddr() const
	{
		return reinterpret_cast<uintptr_t>(this->info.lpMinimumApplicationAddress);
	}

	uintptr_t
	max_vaddr() const
	{
		return reinterpret_cast<uintptr_t>(this->info.lpMaximumApplicationAddress);
	}

private:
	/* Generate a random address for use in VirtualAlloc(). */
	uintptr_t
	generate_aslr(size_t sz) const
	{
		/*
		 * Delta:  the range of virtual addresses suitable for allocation,
		 * divided by the number of bytes per allocation alignment.
		 */
		uintptr_t delta = this->max_vaddr() - this->min_vaddr();
		if (delta <= sz)
			return this->min_vaddr();
		delta -= sz;
		delta /= this->alloc_align();

		/*
		 * Calculate: 2 ^ N % delta  (with N = number of bits in uintptr_t).
		 * Given: delta < 2 ^ N.
		 *
		 * 2 * sz > 2 ^ N  ==>  2 ^ N - delta = 2 ^ N % delta
		 * 2 * sz < 2 ^ N  ==>  (2 ^ N - delta) % delta = 2 ^ N % delta
		 *
		 * Since modulo applied repeatedly still grants the same modulo:
		 * (2 ^ N - delta) % delta = 2 ^ N % delta
		 *
		 * Note that 2 ^ N = std::numeric_limit<uintptr_t>::max() + 1
		 * (but that overflows, so +1 should be last operation).
		 */
		uintptr_t min = (std::numeric_limits<uintptr_t>::max() - sz + 1) % delta;

		uintptr_t rnd;
		do {
			if (!RtlGenRandom(&rnd, sizeof(rnd)))
				abort();	/* XXX poor failure handling, I know... */
		} while (rnd < min);

		return this->min_vaddr() + this->alloc_align() * (rnd % delta);
	}
#endif /* WIN32 */


public:
	/*
	 * Allocate virtual memory.
	 * This memory is not accessable until commit_mem() has been called.
	 * The returned memory is aligned to alloc_align() bytes.
	 */
	void* valloc(size_t) const;
	/*
	 * Allocate virtual memory at specific address.
	 * This memory is not accessable until commit_mem() has been called.
	 * The memory will be allocated at the given address, which must be aligned to alloc_align() bytes.
	 */
	void* valloc(void*, size_t) const;
	/*
	 * Free virtual memory.
	 * Will uncommit the memory if it is in commited state.
	 * The memory must have been allocated using a previous call to valloc().
	 *
	 * A single vfree() may free multiple valloc() memory, as long as there are no gaps
	 * (free space for instance) between the valloc() regions.
	 */
	bool vfree(void*, size_t) const;
	/*
	 * Acquire memory.
	 * The memory must be in a range previously allocated using valloc().
	 * Pointer and size must be multiples of pagesize().
	 */
	bool commit_mem(void*, size_t) const;
	/*
	 * Release memory.
	 * The memory must be in a range previously allocated using valloc().
	 * Pointer and size must be multiples of pagesize().
	 */
	bool release_mem(void*, size_t) const;
};


#ifdef WIN32
/* Reserve memory in the given address space. */
void*
pool::osdep::valloc(size_t sz) const
{
	assert(sz % this->alloc_align() == 0);

	if (sz == 0 || sz > this->max_vaddr() - this->min_vaddr())
		return nullptr;

	/* Generate a random address at which to place memory. */
	uintptr_t aslr = this->generate_aslr(sz);

	/* Allocate memory. */
	void* ptr = VirtualAlloc(reinterpret_cast<void*>(aslr), sz, MEM_RESERVE, PAGE_READWRITE);
	if (ptr == nullptr)
		ptr = VirtualAlloc(nullptr, sz, MEM_RESERVE, PAGE_READWRITE);

	/* Check that returned value meets constraints. */
	assert(ptr == nullptr || reinterpret_cast<uintptr_t>(ptr) % this->alloc_align() == 0);
	return ptr;
}
/* Reserve memory at the given address. */
void*
pool::osdep::valloc(void* position, size_t sz) const
{
	assert(sz % this->alloc_align() == 0);
	assert(reinterpret_cast<uintptr_t>(position) % this->alloc_align() == 0);

	if (sz == 0 || reinterpret_cast<uintptr_t>(position) < this->min_vaddr() || sz > this->max_vaddr() - reinterpret_cast<uintptr_t>(position))
		return nullptr;

	/* Allocate memory. */
	void* ptr = VirtualAlloc(position, sz, MEM_RESERVE, PAGE_READWRITE);
	if (ptr == nullptr)
		return nullptr;
	if (ptr != position) {
		VirtualFree(ptr, 0, MEM_RELEASE);
		return nullptr;
	}
	return ptr;
}

/* Free virtual memory. */
bool
pool::osdep::vfree(void* ptr, size_t sz) const
{
	assert(reinterpret_cast<uintptr_t>(ptr) % this->alloc_align() == 0);
	assert(sz % this->pagesize() == 0);
	assert(sz > 0);

	/*
	 * VirtualFree() pointers must match VirtualAlloc() pointers.
	 * Since we extend and contract our memory and there is no way to inform the kernel
	 * that we did so, we have to manually walk the kernel data structures
	 * to figure out the correct pointers to VirtualFree().
	 */
	while (sz > 0) {
		MEMORY_BASIC_INFORMATION mem_info;
		VirtualQuery(ptr, &mem_info, sizeof(mem_info));

		if (mem_info.AllocationBase != ptr)
			return false;
		if (mem_info.RegionSize > sz)
			return false;
		switch (mem_info.State) {
		case MEM_COMMIT:
		case MEM_RESERVE:
			break;
		default:
			return false;
		}

		if (!VirtualFree(ptr, 0, MEM_RELEASE))
			return false;
		sz -= mem_info.RegionSize;
	}
}

/* Enable access to address range. */
bool
pool::osdep::commit_mem(void* ptr, size_t sz) const
{
	assert(reinterpret_cast<uintptr_t>(ptr) % this->pagesize() == 0);
	assert(sz % this->pagesize() == 0);
	assert(sz > 0);

	return (VirtualAlloc(ptr, sz, MEM_COMMIT, PAGE_READWRITE) != nullptr);
}

/* Block access to address range and release the underlying memory. */
bool
pool::osdep::release_mem(void* ptr, size_t sz) const
{
	assert(reinterpret_cast<uintptr_t>(ptr) % this->pagesize() == 0);
	assert(sz % this->pagesize() == 0);
	assert(sz > 0);

	return VirtualFree(ptr, sz, MEM_DECOMMIT);
}
#else /* Unix/posix. */
/* Reserve memory in the given address space. */
void*
pool::osdep::valloc(size_t sz) const
{
	assert(sz % this->alloc_align() == 0);

	/* Allocate memory. */
	void* ptr = mmap(nullptr, sz, PROT_NONE, MAP_ANON, -1, 0);
	if (ptr == MAP_FAILED)
		return nullptr;

	/* Check that returned value meets constraints. */
	assert(ptr == nullptr || reinterpret_cast<uintptr_t>(ptr) % this->alloc_align() == 0);
	return ptr;
}

/* Reserve memory at the given address. */
void*
pool::osdep::valloc(void* position, size_t sz) const
{
	assert(sz % this->alloc_align() == 0);
	assert(reinterpret_cast<uintptr_t>(position) % this->alloc_align() == 0);

	if (sz == 0 || reinterpret_cast<uintptr_t>(position) < this->min_vaddr() || sz > this->max_vaddr() - reinterpret_cast<uintptr_t>(position))
		return nullptr;

	void* ptr = mmap(position, sz, PROT_NONE, MAP_ANON, -1, 0);
	if (ptr == MAP_FAILED)
		return nullptr;
	if (ptr != position) {
		munmap(ptr, sz);
		return nullptr;
	}
	return ptr;
}

/* Free virtual memory. */
bool
pool::osdep::vfree(void* ptr, size_t sz) const
{
	assert(reinterpret_cast<uintptr_t>(ptr) % this->alloc_align() == 0);
	assert(sz % this->pagesize() == 0);
	assert(sz > 0);

	return (munmap(ptr, sz) == 0);
}

/* Enable access to address range. */
bool
pool::osdep::commit_mem(void* ptr, size_t sz) const
{
	assert(reinterpret_cast<uintptr_t>(ptr) % this->pagesize() == 0);
	assert(sz % this->pagesize() == 0);
	assert(sz > 0);

	if (mprotect(ptr, sz, PROT_READ | PROT_WRITE) != 0)
		return false;
#if defined(MADV_WILLNEED)
	madvise(ptr, sz, MADV_WILLNEED);	/* Failure is allowed. */
#endif
	return true;
}

/* Block access to address range and release the underlying memory. */
bool
pool::osdep::release_mem(void* ptr, size_t sz) const
{
	assert(reinterpret_cast<uintptr_t>(ptr) % this->pagesize() == 0);
	assert(sz % this->pagesize() == 0);
	assert(sz > 0);

	/* Protect pages with PROT_NONE. */
	if (mprotect(ptr, sz, PROT_NONE) != 0)
		return false;

	/*
	 * Inform OS that we don't need those pages anymore.
	 * We try the madvise() system call with option:
	 * - MADV_FREE
	 * - MADV_REMOVE
	 * - MADV_DONTNEED
	 * where we stop at the first succesful call.
	 *
	 * Note that at this point, we always return true, since the actual
	 * mprotect() call succeeded; this is just to allow optimization
	 * by the OS.
	 */
#if defined(MADV_FREE)
	if (madvise(ptr, sz, MADV_FREE) == 0)
		return true;
#endif
#if defined(MADV_REMOVE)
	if (madvise(ptr, sz, MADV_REMOVE) == 0)
		return true;
#endif
#if defined(MADV_DONTNEED)
	if (madvise(ptr, sz, MADV_DONTNEED))
		return true;
#endif
	return true;
}
#endif /* WIN32 */


/* Pool page handler: puts page on queue or releases it after use. */
struct pool::deleter_type
{
private:
	pool* m_pool;

public:
	constexpr deleter_type() :
		m_pool(nullptr)
	{
		return;
	}

	constexpr deleter_type(pool& m_pool) :
		m_pool(&m_pool)
	{
		return;
	}

	void
	operator()(page* p) const
	{
		assert(this->m_pool != nullptr);

		if (p->empty())
			this->m_pool->dealloc_page(p);
		else {
			switch (p->type) {
			case page::SHARED_PAGE:
				this->m_pool->page_enqueue(p);
				break;
			case page::BIG_PAGE:
				break;
			}
		}
	}
};


inline size_t
pool::entries_per_page() const
{
	return page::page_entries_max(this->size, this->align, this->offset);
}

pool::page_ptr&&
pool::alloc_page()
{
	page_ptr pp(nullptr, deleter_type(*this));
	const osdep& os = osdep::get();
	const size_t pgsz = os.alloc_align();
	const size_t n_entries = this->entries_per_page();

	void* ptr = os.valloc(pgsz);
	if (ptr == nullptr)
		return std::move(pp);
	if (!os.commit_mem(ptr, page::overhead(n_entries, this->align, this->offset))) {
		os.vfree(ptr, pgsz);
		return std::move(pp);
	}

	page* p = nullptr;
	try {
		p = new (ptr) page(page::SHARED_PAGE, pgsz, n_entries, this->size, this->align, this->offset);
	} catch (...) {
		os.vfree(ptr, pgsz);
		throw;
	}
	pp.reset(p);
	return std::move(pp);
}

void
pool::dealloc_page(page* p)
{
	assert(p->empty());

	const auto len = p->alloclen;
	p->~page();
	const bool vfree_ok = osdep::get().vfree(p, len);
	assert(vfree_ok);
}

pool::page_ptr&&
pool::alloc_big_page(size_t n)
{
	page_ptr pp(nullptr, deleter_type(*this));
	const osdep& os = osdep::get();
	const size_t alloc_sz = round_up(page::overhead(0, this->align, this->offset) + n * this->size, os.alloc_align());
	const size_t pgsz = round_up(page::overhead(0, this->align, this->offset) + n * this->size, os.pagesize());

	void* ptr = os.valloc(alloc_sz);
	if (ptr == nullptr)
		return std::move(pp);
	if (!os.commit_mem(ptr, pgsz)) {
		os.vfree(ptr, alloc_sz);
		return std::move(pp);
	}

	page* p = nullptr;
	try {
		p = new (ptr) page(page::BIG_PAGE, alloc_sz, n, this->size, this->align, this->offset);
	} catch (...) {
		os.vfree(ptr, alloc_sz);
		throw;
	}
	pp.reset(p);
	return std::move(pp);
}

void*
pool::allocate(size_type n, void*)
{
	/* Big allocations are easy: simply allocate a gigantic page. */
	if (n > this->entries_per_page()) {
		page_ptr pg = alloc_big_page(n);
		void* ptr = pg->data();
		return ptr;
	}

	/*
	 * Small allocation: first try a page on the freelist.
	 * Failing that, create a new page, allocate from it and then store it.
	 */
	... /* XXX implement queue. */

	/*
	 * Allocation from existing page failed.
	 * Create a new page.
	 */
	page_ptr pg = alloc_page();
	void* ptr = pg->allocate(n);
	return ptr;
}

void
pool::deallocate(void* ptr, size_type n)
{
	const osdep& os = osdep::get();
	page_ptr pg(nullptr, deleter_type(*this));

	/*
	 * Derive page from the pointer.
	 * Some sanity checking is done to verify it really is a page created by this pool.
	 */
	{
		page*const pg_ptr = reinterpret_cast<page*>(round_down(reinterpret_cast<uintptr_t>(ptr), os.alloc_align()));

		/* Check that the parameters of this page match this pool. */
		if (pg_ptr->align != this->align ||
		    pg_ptr->entry_size != this->size ||
		    pg_ptr->offset != this->offset)
			throw std::invalid_argument("ptr");

		/* Check that the page type is recognized. */
		switch (pg_ptr->type) {
		case page::SHARED_PAGE:
		case page::BIG_PAGE:
			break;
		default:
			throw std::invalid_argument("ptr");
		}

		/* Looks valid... let's try and use it. */
		pg.reset(pg_ptr);
	}

	switch (pg->type) {
	case page::SHARED_PAGE:
		if (n > 0 && !pg->deallocate(ptr, n))
			throw std::invalid_argument("pool::deallocate: (ptr, n)");
		break;
	case page::BIG_PAGE:
		if (n > 0 && !pg->resize(ptr, n, 0))
			throw std::invalid_argument("pool::deallocate: (ptr, n)");
		break;
	default:
		throw std::invalid_argument("pool::deallocate: ptr");
	}
}

bool
pool::resize(void* ptr, size_type old_n, size_type new_n)
{
	const osdep& os = osdep::get();
	page_ptr pg(nullptr, deleter_type(*this));

	/*
	 * Derive page from the pointer.
	 * Some sanity checking is done to verify it really is a page created by this pool.
	 */
	{
		page*const pg_ptr = reinterpret_cast<page*>(round_down(reinterpret_cast<uintptr_t>(ptr), os.alloc_align()));

		/* Check that the parameters of this page match this pool. */
		if (pg_ptr->align != this->align ||
		    pg_ptr->entry_size != this->size ||
		    pg_ptr->offset != this->offset)
			throw std::invalid_argument("ptr");

		/* Check that the page type is recognized. */
		switch (pg_ptr->type) {
		case page::SHARED_PAGE:
		case page::BIG_PAGE:
			break;
		default:
			throw std::invalid_argument("ptr");
		}

		/* Looks valid... let's try and use it. */
		pg.reset(pg_ptr);
	}

	switch (pg->type) {
	case page::SHARED_PAGE:
		if (new_n > old_n)	/* Region is grown. */
			return pg->allocate(ptr, old_n, new_n - old_n);
		else if (new_n < old_n)	/* Region is shrunk. */
			return pg->deallocate(ptr, new_n, old_n - new_n);
		else
			return true;
		break;
	case page::BIG_PAGE:
		return pg->resize(ptr, old_n, new_n));
		break;
	default:
		throw std::invalid_argument("pool::deallocate: ptr");
	}
}


/*
 * Calculate the amount of space wasted by the given allocation parameters.
 *
 * Note that we calculate address space waste, not physical page waste.
 * The wasted address space is a very good indicator of physical page waste however.
 */
inline pool::size_type
pool::waste(size_type sz, size_type align, size_type offset)
{
	const osdep& os = osdep::get();

	/* Space from entry[n] to entry[n+1]. */
	const auto delta = round_up(sz, align);
	/* Unused space between two entries. */
	const auto delta_waste = sz % align;

	/* Number of entries per allocation. */
	const auto n = page::page_entries_max(delta, align, offset);
	/* Space used for tracking data. */
	const auto tracking = page::overhead(n, 1, 0);
	/* Space wasted between tracking data and first entry. */
	const auto tracking_waste = page::overhead(n, align, offset) - tracking;
	/* Top of the allocation. */
	const auto top = page::overhead(n, align, offset) + std::max(n, 1U) * delta;
	/* Unused space at end of allocation. */
	const auto top_waste = os.alloc_align() - top % os.alloc_align();

	/* Total wasted space. */
	return std::min(n, 1U) * delta_waste + tracking_waste + top_waste;
}

/*
 * Recommend a size between min and max (inclusive) that will waste the smallest amount of memory.
 *
 * Note: this is currently a brute-force operation, try to call it sparingly.
 */
pool::size_type
pool::recommend_size(size_type min, size_type max, size_type align, size_type offset)
{
	if (min >= max)
		return min; /* Don't clog our iteration below. */

	const osdep& os = osdep::get();
	align = std::min(align, 1U);
	offset %= align;

	size_type best = min;
	size_type best_waste = waste(min, align, offset);

	for (size_type i = round_up(min + 1, align); i < max + 1; i += align) {
		const size_type i_waste = waste(i, align, offset);

		if (i_waste < best_waste) {
			best = i;
			best_waste = i_waste;
		}
	}
	return best;
}






// This is an example of an exported variable
WIN32PROJECT1_API int nWin32Project1=0;

// This is an example of an exported function.
WIN32PROJECT1_API int fnWin32Project1(void)
{
	return 42;
}

// This is the constructor of a class that has been exported.
// see Win32Project1.h for the class definition
CWin32Project1::CWin32Project1()
{
	return;
}
