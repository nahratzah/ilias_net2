#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define NOMINMAX			// Exclude min/max macros.

#include "ilias/net2/pool.h"

#include <atomic>
#include <cassert>
#include <functional>
#include <limits>
#include <stdexcept>

#ifdef WIN32
#include <Windows.h>
#include <NTSecAPI.h>
#else
#include <unistd.h>
#include <sys/mman.h>
#endif


namespace ilias {
namespace {

/*
 * Repeats a bit pattern every Shift bytes.
 */
template<typename T, size_t Shift, bool Stop = (Shift >= std::numeric_limits<T>::digits)>
struct shift_repeat
{
	static constexpr T
	get(const T& v)
	{
		return shift_repeat<T, 2 * Shift>::get(v | (v << Shift));
	}
};
template<typename T, size_t Shift>
struct shift_repeat<T, Shift, true>
{
	static constexpr T
	get(const T& v)
	{
		return v;
	}
};

/*
 * Create a bitpattern mask: infinite repeat of P ones followed by P zeroes
 */
template<typename T, size_t P>
struct mask
{
	static constexpr_value T value = shift_repeat<T, 2 * P>::get(((T(1) << P) - 1) << P);
};

/*
 * Recursive invocation to find the log2 of a value.
 */
template<typename T, size_t Shift, bool Stop = (Shift >= std::numeric_limits<T>::digits)>
struct log_repeat
{
	static constexpr size_t
	get(const T& v)
	{
		return ((v & mask<T, Shift>::value) ? Shift : 0) +
		    log_repeat<T, 2 * Shift>::get(v);
	}
};
template<typename T, size_t Shift>
struct log_repeat<T, Shift, true>
{
	static constexpr size_t
	get(const T&)
	{
		return 0;
	}
};

} /* ilias::[unnamed namespace] */

/* Calculate the largest log2 where 2^result <= value. */
template<typename T>
static constexpr unsigned int
log2_down(const T& value)
{
	return log_repeat<T, 1>::get(value);
}
/* Calculate the smallest log2 where 2^result >= value. */
template<typename T>
static constexpr unsigned int
log2_up(const T& value)
{
	/*
	 * If value is a power of 2, log2_up(value) == log2_down(value),
	 * otherwise, log2_down(value) is 1 too small.
	 */
	return ((value & (value - 1)) != 0 ? 1 : 0) + log2_down(value);
}


/* Allow undo of atomic_fetch_or operation. */
template<typename T>
class atomic_or_undo;

template<typename T>
class atomic_or_undo< std::atomic<T> >
{
public:
	typedef T value_type;
	typedef std::atomic<value_type> atomic_type;

private:
	atomic_type& m_atom;	/* Variable on which the action is applied. */
	bool m_commit;		/* True if commit() has been called. */
	const std::memory_order m_rollback;

public:
	const value_type mask;		/* Mask of applied bits. */
	const value_type orig;		/* Original value of bits prior to masking. */

public:
	atomic_or_undo(atomic_type& atom, const value_type& mask, const std::memory_order& order, const std::memory_order& rollback) ILIAS_NET2_NOTHROW :
		m_atom(atom),
		m_commit(false),
		mask(mask),
		orig((mask == 0 ? value_type(0) : atom.fetch_or(mask, order) & mask)),
		m_rollback(rollback)
	{
		return;
	}

#if HAS_RVALUE_REF
	atomic_or_undo(atomic_or_undo&& o) ILIAS_NET2_NOTHROW :
		m_atom(o.m_atom),
		m_commit(o.m_commit),
		mask(o.mask),
		orig(o.orig),
		m_rollback(o.m_rollback)
	{
		/* Rollback is now our responsibility, mark o as commited to prevent rollback. */
		o.m_commit = true;
	}
#endif

	~atomic_or_undo() ILIAS_NET2_NOTHROW
	{
		if (!this->m_commit && this->mask != value_type(0))
			m_atom.fetch_and(this->orig | ~this->mask, this->m_rollback);
	}

	void
	commit() ILIAS_NET2_NOTHROW
	{
		this->m_commit = true;
	}

	/* Convenience test: true if all bits in mask were originally 0. */
	bool
	complete() const ILIAS_NET2_NOTHROW
	{
		return (this->orig == 0);
	}
};

/*
 * Attempt to set all bits in range.
 *
 * Evaluates to true if succesful.
 * Fails if any of the bits in range is already set, in which case the operation will be rolled back.
 *
 * Begin, end follow array semantics (i.e. begin is the first bit that will be set, up to but not including end).
 *
 * Note that on failure, part of its data may be set until destruction of the range.
 */
template<typename T>
struct range_set;

template<typename T>
struct range_set< std::atomic<T> >
{
public:
	typedef T value_type;
	typedef std::atomic<value_type> atomic_type;

private:
	bool m_succes;		/* Set if all bits in the range were 0. */
	bool m_commit;		/* True if commit() has been called. */
	const std::memory_order m_rollback;

	/* Range of atomics that were at least partially within the range. */
	atomic_type*const m_begin;
	atomic_type*const m_end;
	/* Undo for first atomic. */
	atomic_or_undo<atomic_type> m_begin_undo;
	/* Unfor for last atomic. */
	atomic_or_undo<atomic_type> m_end_undo;

	/* Limits of value type. */
	typedef std::numeric_limits<value_type> limits;
	static constexpr std::size_t digits = limits::digits;

	static constexpr bool
	do_end(std::size_t begin, std::size_t end) ILIAS_NET2_NOTHROW
	{
		return (end - pool::round_down(begin, digits) <= digits);
	}
	template<typename U>
	static constexpr const U&
	do_end(std::size_t begin, std::size_t end, const U& yes, const U& no) ILIAS_NET2_NOTHROW
	{
		return (do_end(begin, end) ? yes : no);
	}
	static value_type
	mask(std::size_t begin, std::size_t end) ILIAS_NET2_NOTHROW
	{
		assert(end <= std::numeric_limits<value_type>::digits);
		assert(begin <= end);

		return (value_type(1) << end) - (value_type(1) << begin);
	}

public:
	explicit operator bool() const ILIAS_NET2_NOTHROW
	{
		return this->m_succes;
	}

	range_set(atomic_type* atomics, std::size_t begin, std::size_t end,
	    const std::memory_order& order, const std::memory_order& rollback) ILIAS_NET2_NOTHROW :
		m_succes(false),
		m_commit(false),
		m_rollback(rollback),
		m_begin(&atomics[begin / digits]),
				/* round_down(begin, digits) / digits */
		m_end(&atomics[(end + digits - 1) / digits]),
				/* round_up(end, digits) / digits */
		m_begin_undo(*this->m_begin,
		    mask(begin % digits, std::min(end - pool::round_down(begin, digits), digits)),
		    order, rollback),
		m_end_undo(*this->m_end,
		    do_end(begin, end, mask(0, end % digits), value_type(0)),
		    order, rollback)
	{
		/* The in-between entries assume succes unless proven to fail, so switch m_succes. */
		this->m_succes = this->m_begin_undo.complete() && this->m_end_undo.complete();

		if (this->m_succes) {
			auto i = this->m_begin;
			while (++i < this->m_end) {
				value_type zero = value_type(0);
				if (!i->compare_exchange_strong(zero, ~zero, order, this->m_rollback)) {
					m_succes = false;
					while (--i != m_begin)
						i->store(value_type(0), this->m_rollback);
					break;
				}
			}
		}
	}

#ifdef HAS_RVALUE_REF
	range_set(range_set&& o) ILIAS_NET2_NOTHROW :
		m_succes(o.m_succes),
		m_commit(o.m_commit),
		m_rollback(o.m_rollback),
		m_begin(o.m_begin),
		m_end(o.m_end),
		m_begin_undo(std::move(o.m_begin_undo)),
		m_end_undo(std::move(o.m_end_undo))
	{
		/* Move responsibility for rollback from o to this. */
		o.m_commit = true;
	}
#endif

	~range_set() ILIAS_NET2_NOTHROW
	{
		if (this->m_succes && !this->m_commit) {
			auto i = this->m_begin;
			while (++i < this->m_end)
				i->store(value_type(0), this->m_rollback);
		}
	}

	void
	commit()
	{
		if (!this->m_succes)
			throw std::logic_error("commit called on failed range");
		this->m_begin_undo.commit();
		this->m_end_undo.commit();
		this->m_commit = true;
	}
};


/*
 * Abstraction of OS dependant routines.
 */
class ILIAS_NET2_LOCAL pool::osdep
{
private:
#ifdef WIN32
	SYSTEM_INFO info;

	osdep()
	{
		GetSystemInfo(&info);
	}
#else
	long m_pagesize;

	osdep() :
		m_pagesize(sysconf(_SC_PAGESIZE))
	{
		assert(m_pagesize > 0);
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
		return this->m_pagesize;
#endif
	}

	uintptr_t
	alloc_align() const
	{
#ifdef WIN32
		return this->info.dwAllocationGranularity;
#else
		return this->m_pagesize;
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
	generate_aslr(std::size_t sz) const
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
	void* valloc(std::size_t) const;
	/*
	 * Allocate virtual memory at specific address.
	 * This memory is not accessable until commit_mem() has been called.
	 * The memory will be allocated at the given address, which must be aligned to alloc_align() bytes.
	 */
	void* valloc(void*, std::size_t) const;
	/*
	 * Free virtual memory.
	 * Will uncommit the memory if it is in commited state.
	 * The memory must have been allocated using a previous call to valloc().
	 *
	 * A single vfree() may free multiple valloc() memory, as long as there are no gaps
	 * (free space for instance) between the valloc() regions.
	 */
	bool vfree(void*, std::size_t) const;
	/*
	 * Acquire memory.
	 * The memory must be in a range previously allocated using valloc().
	 * Pointer and size must be multiples of pagesize().
	 */
	bool commit_mem(void*, std::size_t) const;
	/*
	 * Release memory.
	 * The memory must be in a range previously allocated using valloc().
	 * Pointer and size must be multiples of pagesize().
	 */
	bool release_mem(void*, std::size_t) const;
};


/*
 * Tracking of allocation data.
 */
class ILIAS_NET2_LOCAL pool::page :
	private ll_base_hook<>
{
friend class ll_base<page>;

public:
	enum page_type {
		SHARED_PAGE,
		BIG_PAGE
	};

	const page_type type;
	std::size_t alloclen;
	std::size_t n_entries;
	const std::size_t entry_size;
	const std::size_t align;
	const std::size_t offset;

private:
	template<typename T>
	struct atomic_type;

	template<typename T>
	struct atomic_type< std::atomic<T> > {
		typedef T type;
	};

	typedef std::atomic<uintptr_t> entry_type;

	static constexpr std::size_t
	bitmap_bits() ILIAS_NET2_NOTHROW
	{
		/* XXX a function, because a static constexpr value results in linker failure... */
		return std::numeric_limits<atomic_type<entry_type>::type>::digits;
	}

	static constexpr std::size_t
	entries_offset()
	{
		return round_up(sizeof(page), sizeof(entry_type));
	}

	static constexpr std::size_t
	bitmap_space(std::size_t n_entries)
	{
		return (n_entries + bitmap_bits() - 1) / bitmap_bits();
	}

public:
	/* Calculate which amount of space at the beginning of the allocation is used for keeping track. */
	static constexpr std::size_t
	overhead(std::size_t n_entries, std::size_t align, std::size_t offset)
	{
		/*
		 * The horrible syntax is to avoid std::max (which is supposed to be a constexpr,
		 * but library writers are slower than compiler writers) and thus do things the hard
		 * way.
		 * I just wish the hard way wasn't so unreadable.
		 */
		return round_up(
		    (entries_offset() + bitmap_space(n_entries) <= offset ? 0 : entries_offset() + bitmap_space(n_entries) - offset),
		    align) + offset;
	}
	/* Calculate which amount of space at the beginning of the allocation is used for keeping track. */
	std::size_t
	overhead() const
	{
		std::size_t n_entries;

		switch (this->type) {
		case BIG_PAGE:
			n_entries = 0;
			break;
		case SHARED_PAGE:
			n_entries = this->n_entries;
			break;
		}
		return overhead(n_entries, this->align, this->offset);
	}

	/* Calculate the number of entries that will fit in a page (allocation size osdep::page_align()). */
	static std::size_t
	page_entries_max(std::size_t sz, std::size_t align, std::size_t offset)
	{
		const auto delta = round_up(sz, align);	/* Round up to alignment. */
		const osdep& os = osdep::get();

		/*
		 * Calculate number of entries that fit.
		 * Note that alignment constraints may force us to reduce the number found here.
		 */
		std::size_t n_entries = (os.alloc_align() - entries_offset()) / (delta + sizeof(entry_type));
		while (n_entries > 1 && overhead(n_entries, align, offset) + n_entries * delta > os.alloc_align())
			n_entries--;

		return (n_entries <= 1 ? 0 : n_entries);
	}

private:
	/* Calculate array size for bitmap. */
	static constexpr std::size_t
	bitmap_maxidx(std::size_t n_entries)
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
	data(std::size_t idx) const
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

	template<typename T>
	static RVALUE(T)
	invert_bits(const T& v, const unsigned int& log2_max)
	{
		T rv = v;

		for (unsigned int i = 0; i < log2_max / 2; i++) {
			const T l_mask = T(1) << i;
			const T r_mask = T(1) << (log2_max - 1 - i);

			const bool l = ((rv & l_mask) == 0);
			const bool r = ((rv & r_mask) == 0);
			if (l != r)
				rv ^= (l_mask | r_mask);
		}
#ifdef HAS_RVALUE_REF
		return std::move(rv);
#else
		return rv;
#endif
	}

	/*
	 * Calculate the mask describing [first..last).
	 */
	static atomic_type<entry_type>::type
	mask(std::size_t first, std::size_t last)
	{
		typedef atomic_type<entry_type>::type u_type;
		const u_type one = 1;

		assert(first >= 0);
		assert(last <= bitmap_bits());
		assert(first <= last);

		if (first == last)
			return 0;

		const u_type last_mask = (std::numeric_limits<u_type>::max() >> (bitmap_bits() - last));
		const u_type first_mask = (one << first);
		return (first_mask & last_mask);
	}

	/*
	 * Acquire all bits describing entries [idx .. idx + count).
	 * Returns true on succes.
	 * No change on failure.
	 */
	bool
	acquire(std::size_t idx, std::size_t count, bool mark_inuse = true) ILIAS_NET2_NOTHROW
	{
		assert(this->type == SHARED_PAGE);	/* Shared pages only. */

		/* Argument check: if the allocation cannot fail/succeed, return appropriate error immediately. */
		if (count == 0)
			return true;
		if (idx + count < idx || idx + count >= this->n_entries)
			return false;

		range_set<entry_type> rs(this->bitmap(), idx, idx + count, std::memory_order_relaxed, std::memory_order_relaxed);
		if (!rs)
			return false;

		/* Commit memory. */
		if (mark_inuse) {
			const osdep& os = osdep::get();
			const uintptr_t start_addr = round_down(reinterpret_cast<uintptr_t>(data(idx)), os.pagesize());
			const uintptr_t end_addr = round_up(reinterpret_cast<uintptr_t>(data(idx + count)), os.pagesize());
			assert(end_addr - start_addr <= std::numeric_limits<size_t>::max());
			if (!os.commit_mem(reinterpret_cast<void*>(start_addr), end_addr - start_addr))
				return false;
		}
		rs.commit();

		/* All bits were succesfully acquired, allocation succeeded. */
		return true;
	}

	/*
	 * Release memory previously acquired using acquire.
	 * All memory must be in use (assert failure).
	 */
	void
	release(std::size_t idx, std::size_t count, bool mark_unused = true)
	{
		assert(this->type == SHARED_PAGE);	/* Shared pages only. */

		assert(idx + count > idx);	/* Fails on overflow. */
		assert(idx + count <= this->n_entries);

		/* Release of 0 bytes is a no-op. */
		if (count == 0)
			return;

		entry_type*const arr = this->bitmap() + (idx / bitmap_bits());
		const auto off = idx % bitmap_bits();
		const auto last = (off + count);

		/* Mark the first entry_type bits for allocation. */
		const auto first_mask = mask(off, std::min(bitmap_bits(), last));
		const auto orig = (arr[0].fetch_and(~first_mask, std::memory_order_relaxed) & first_mask);
		assert(orig == first_mask);
		/* Test if this is one of those allocations that fits in a single entry. */
		if (last <= bitmap_bits())
			return;

		/* Mark intermediate bits for allocation. */
		for (std::size_t i = 1; i < (last - 1) / bitmap_bits(); ++i) {
			auto prev = arr[i].exchange(0, std::memory_order_relaxed);
			assert(~prev == 0);
		}

		/* Mark final bits for allocation. */
		const std::size_t last_idx = (last - 1) / bitmap_bits();
		const auto last_mask = mask(0, (last - 1) % bitmap_bits() + 1);
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
	page(page_type type, std::size_t alloclen, std::size_t n_entries, std::size_t entry_size,
	    std::size_t align, std::size_t offset) ILIAS_NET2_NOTHROW :
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
			{
				entry_type* bm = this->bitmap();
				for (std::size_t i = 0; i < bitmap_maxidx(n_entries); ++i, ++bm)
					new (bm) entry_type(0);
			}
			break;
		case BIG_PAGE:
			assert(reinterpret_cast<uintptr_t>(static_cast<void*>(this)) + alloclen >= reinterpret_cast<uintptr_t>(this->data(n_entries)));
			break;
		}
		return;
	}

	/* Destructor. */
	~page() ILIAS_NET2_NOTHROW
	{
		assert(this->empty());

		/* Destroy the bitmap. */
		switch (this->type) {
		case SHARED_PAGE:
			{
				entry_type* bm = this->bitmap();
				for (std::size_t i = 0; i < bitmap_maxidx(n_entries); ++i, ++bm)
					bm->~entry_type();
			}
			break;
		case BIG_PAGE:
			break;
		}
	}

	/* Test if the page is empty (nothing is in use). */
	bool
	empty() const ILIAS_NET2_NOTHROW
	{
		switch (this->type) {
		case SHARED_PAGE:
			{
				const entry_type* bm = this->bitmap();
				for (std::size_t i = 0; i != this->bitmap_maxidx(this->n_entries); ++i, ++bm) {
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
	void* allocate(std::size_t) ILIAS_NET2_NOTHROW;
	/* Allocate entries at a specific address. */
	void* allocate(void*, std::size_t, std::size_t) ILIAS_NET2_NOTHROW;

	/* Free space for count contiguous entries. */
	bool deallocate(void*, std::size_t) ILIAS_NET2_NOTHROW;
	/* Free space at pointer relative to offset. */
	bool deallocate(void*, std::size_t, std::size_t) ILIAS_NET2_NOTHROW;

	/* Change the number of entries in a big page. */
	bool resize(void*, std::size_t, std::size_t) ILIAS_NET2_NOTHROW;
};


#ifdef WIN32
/* Reserve memory in the given address space. */
void*
pool::osdep::valloc(std::size_t sz) const
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
pool::osdep::valloc(void* position, std::size_t sz) const
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
pool::osdep::vfree(void* ptr, std::size_t sz) const
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
pool::osdep::commit_mem(void* ptr, std::size_t sz) const
{
	assert(reinterpret_cast<uintptr_t>(ptr) % this->pagesize() == 0);
	assert(sz % this->pagesize() == 0);
	assert(sz > 0);

	return (VirtualAlloc(ptr, sz, MEM_COMMIT, PAGE_READWRITE) != nullptr);
}

/* Block access to address range and release the underlying memory. */
bool
pool::osdep::release_mem(void* ptr, std::size_t sz) const
{
	assert(reinterpret_cast<uintptr_t>(ptr) % this->pagesize() == 0);
	assert(sz % this->pagesize() == 0);
	assert(sz > 0);

	return VirtualFree(ptr, sz, MEM_DECOMMIT);
}
#else /* Unix/posix. */
/* Reserve memory in the given address space. */
void*
pool::osdep::valloc(std::size_t sz) const
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
pool::osdep::valloc(void* position, std::size_t sz) const
{
	assert(sz % this->alloc_align() == 0);
	assert(reinterpret_cast<uintptr_t>(position) % this->alloc_align() == 0);

	if (sz == 0)
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
pool::osdep::vfree(void* ptr, std::size_t sz) const
{
	assert(reinterpret_cast<uintptr_t>(ptr) % this->alloc_align() == 0);
	assert(sz % this->pagesize() == 0);
	assert(sz > 0);

	return (munmap(ptr, sz) == 0);
}

/* Enable access to address range. */
bool
pool::osdep::commit_mem(void* ptr, std::size_t sz) const
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
pool::osdep::release_mem(void* ptr, std::size_t sz) const
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


void*
pool::page::allocate(std::size_t count) ILIAS_NET2_NOTHROW
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
	for (std::size_t i = 0; i < log2_up(this->n_entries); ++i) {
		const std::size_t idx = invert_bits(i, log2_up(this->n_entries));
		if (idx + count > this->n_entries || idx + count < idx)
			continue;	/* Reject oversized indices. */

		if (this->acquire(idx, count))
			return this->data(idx);
	}
	return nullptr;
}

void*
pool::page::allocate(void* p, std::size_t offset, std::size_t count) ILIAS_NET2_NOTHROW
{
	if (this->type != SHARED_PAGE)
		return nullptr;
	if (offset > this->n_entries || count > this->n_entries)
		return nullptr;
	const auto idx = index(p);
	if (!idx.second)
		return nullptr;
	if (idx.first > this->n_entries - offset)
		return nullptr;
	if (this->n_entries - idx.first < offset + count)
		return nullptr;

	if (this->acquire(idx.first + offset, count))
		return this->data(idx.first + offset);
	return nullptr;
}

bool
pool::page::deallocate(void* ptr, std::size_t count) ILIAS_NET2_NOTHROW
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

bool
pool::page::deallocate(void* ptr, std::size_t offset, std::size_t count) ILIAS_NET2_NOTHROW
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

bool
pool::page::resize(void* ptr, std::size_t old_n, std::size_t new_n) ILIAS_NET2_NOTHROW
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


/* Pool page handler: puts page on queue or releases it after use. */
struct pool::deleter_type
{
private:
	pool* m_pool;

public:
	constexpr deleter_type() :
		m_pool(nullptr)
	{
		/* Empty body. */
	}

	constexpr deleter_type(pool& m_pool) :
		m_pool(&m_pool)
	{
		/* Empty body. */
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


void
pool::page_enqueue(page* pg)
{
	if (pg)
		this->head.push_front(*pg);
}

inline std::size_t
pool::entries_per_page() const
{
	return page::page_entries_max(this->size, this->align, this->offset);
}

ILIAS_NET2_LOCAL pool::page_ptr&&
pool::alloc_page()
{
	page_ptr pp(nullptr, deleter_type(*this));
	const osdep& os = osdep::get();
	const std::size_t pgsz = os.alloc_align();
	const std::size_t n_entries = this->entries_per_page();

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

ILIAS_NET2_LOCAL void
pool::dealloc_page(page* p)
{
	assert(p->empty());

	const auto len = p->alloclen;
	p->~page();
	const bool vfree_ok = osdep::get().vfree(p, len);
	assert(vfree_ok);
}

ILIAS_NET2_LOCAL pool::page_ptr&&
pool::alloc_big_page(std::size_t n)
{
	page_ptr pp(nullptr, deleter_type(*this));
	const osdep& os = osdep::get();
	const std::size_t alloc_sz = round_up(page::overhead(0, this->align, this->offset) + n * this->size, os.alloc_align());
	const std::size_t pgsz = round_up(page::overhead(0, this->align, this->offset) + n * this->size, os.pagesize());

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
pool::allocate(std::nothrow_t, size_type n, void*) ILIAS_NET2_NOTHROW
{
	/* Big allocations are easy: simply allocate a gigantic page. */
	if (n > this->entries_per_page()) {
		page_ptr pg = alloc_big_page(n);
		return (pg ? pg->data() : nullptr);
	}

	/*
	 * Small allocation: first try a page on the freelist.
	 * Failing that, create a new page, allocate from it and then store it.
	 */
	for (ll_list_type::iterator i = this->head.begin(), end = this->head.end(); i != end; ++i) {
		void* ptr = i->allocate(n);
		if (ptr) {
			try {
				page_ptr pg(i.get(), deleter_type(*this));
				this->head.erase(i);
			} catch (...) {
				i->deallocate(ptr, n);
				throw;
			}
			return ptr;
		}
	}

	/*
	 * Allocation from existing page failed.
	 * Create a new page.
	 */
	page_ptr pg = alloc_page();
	void* ptr = pg->allocate(n);
	return ptr;
}

bool
pool::deallocate(std::nothrow_t, void* ptr, size_type n) ILIAS_NET2_NOTHROW
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
			return false;

		/* Check that the page type is recognized. */
		switch (pg_ptr->type) {
		case page::SHARED_PAGE:
		case page::BIG_PAGE:
			break;
		default:
			return false;
		}

		/* Looks valid... let's try and use it. */
		pg.reset(pg_ptr);
	}

	switch (pg->type) {
	case page::SHARED_PAGE:
		if (n > 0 && !pg->deallocate(ptr, n))
			return false;
		break;
	case page::BIG_PAGE:
		if (n > 0 && !pg->resize(ptr, n, 0))
			return false;
		break;
	default:
		return false;
	}
	return true;
}

bool
pool::resize(std::nothrow_t, void* ptr, size_type old_n, size_type new_n) ILIAS_NET2_NOTHROW
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
			return false;

		/* Check that the page type is recognized. */
		switch (pg_ptr->type) {
		case page::SHARED_PAGE:
		case page::BIG_PAGE:
			break;
		default:
			return false;
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
		return pg->resize(ptr, old_n, new_n);
		break;
	default:
		return false;
	}
}


/*
 * Calculate the amount of space wasted by the given allocation parameters.
 *
 * Note that we calculate address space waste, not physical page waste.
 * The wasted address space is a very good indicator of physical page waste however.
 */
inline pool::size_type
pool::waste(size_type sz, size_type align, size_type offset) ILIAS_NET2_NOTHROW
{
	const osdep& os = osdep::get();

	/* Space from entry[n] to entry[n+1]. */
	const auto delta = round_up(sz, align);
	/* Unused space between two entries. */
	const auto delta_waste = sz % align;

	/* Number of entries per allocation. */
	const size_type n = page::page_entries_max(delta, align, offset);
	/* Space used for tracking data. */
	const auto tracking = page::overhead(n, 1, 0);
	/* Space wasted between tracking data and first entry. */
	const auto tracking_waste = page::overhead(n, align, offset) - tracking;
	/* Top of the allocation. */
	const auto top = page::overhead(n, align, offset) + std::max(n, size_type(1U)) * delta;
	/* Unused space at end of allocation. */
	const auto top_waste = os.alloc_align() - top % os.alloc_align();

	/* Total wasted space. */
	return std::min(n, size_type(1U)) * delta_waste + tracking_waste + top_waste;
}

/*
 * Recommend a size between min and max (inclusive) that will waste the smallest amount of memory.
 *
 * Note: this is currently a brute-force operation, try to call it sparingly.
 */
pool::size_type
pool::recommend_size(size_type min, size_type max, size_type align, size_type offset) ILIAS_NET2_NOTHROW
{
	if (min >= max)
		return min; /* Don't clog our iteration below. */

	const osdep& os = osdep::get();
	align = std::min(align, size_type(1U));
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


} /* namespace ilias */
