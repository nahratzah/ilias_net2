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
#include <ilias/net2/pool.h>
#include <ilias/net2/refcnt.h>
#include <atomic>
#include <cstdint>
#include <vector>

#ifdef WIN32
#include <WinSock2.h>
#else
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#endif


#ifdef _MSC_VER
#pragma warning( push )
#pragma warning( disable: 4251 )
#pragma warning( disable: 4290 )
#endif


namespace ilias {


class ILIAS_NET2_EXPORT buffer
{
public:
	typedef uintptr_t size_type;

	/* Indicator of invalid offset. */
	static const size_type npos;

#if WIN32
	typedef _WSABUF iovec;

	static std::size_t
	iov_len(const iovec& v) ILIAS_NET2_NOTHROW
	{
		return v.len;
	}

	static void
	set_iov_len(iovec& v, std::size_t len) throw (std::domain_error)
	{
		if (len > std::numeric_limits<decltype(v.len)>::max())
			throw std::domain_error("IOV len (WSABUF) truncation.");
#ifdef _MSC_VER
#pragma warning( push )
#pragma warning( disable: 4267 )	/* Silence truncation error, since it is handled by exception above. */
#endif
		v.len = len;
#ifdef _MSC_VER
#pragma warning( pop )
#endif
	}

	static void*
	iov_base(const iovec& v) ILIAS_NET2_NOTHROW
	{
		return v.buf;
	}

	static void
	set_iov_base(iovec& v, void* addr) ILIAS_NET2_NOTHROW
	{
		v.buf = reinterpret_cast<char*>(addr);
	}
#else
	typedef ::iovec iovec;

	static std::size_t
	iov_len(const iovec& v) ILIAS_NET2_NOTHROW
	{
		return v.iov_len;
	}

	static void
	set_iov_len(iovec& v, std::size_t len) throw (std::domain_error)
	{
		if (len > std::numeric_limits<decltype(v.iov_len)>::max())
			throw std::domain_error("IOV len (WSABUF) truncation.");
		v.iov_len = len;
	}

	static void*
	iov_base(const iovec& v) ILIAS_NET2_NOTHROW
	{
		return v.iov_base;
	}

	static void
	set_iov_base(iovec& v, void* addr) ILIAS_NET2_NOTHROW
	{
		v.iov_base = addr;
	}
#endif

	/*
	 * A memcpy that attempts not to pollute the CPU cache.
	 */
	static void copy_memory(void*, const void*, size_type) ILIAS_NET2_NOTHROW;

	/*
	 * A bzero that attempts not to pollute the CPU cache.
	 */
	static void zero_memory(void*, size_type) ILIAS_NET2_NOTHROW;

private:
	class mem_segment;

	/* Helper for mem_segment destruction. */
	class mem_segment_free
	{
	public:
		void operator()(mem_segment* ms) const ILIAS_NET2_NOTHROW;
	};

	/*
	 * Memory segment.
	 *
	 * This is a byte allocator that cannot free, but keeps extending to fit in new data.
	 * The allocator is thread-safe.
	 *
	 * Buffer uses these to write once to memory held in a segment, then sharing it with
	 * other buffers.  When the buffer is extended, it will try to extend the segment.
	 */
	class mem_segment :
		public refcount_base<mem_segment, mem_segment_free>
	{
	friend class buffer::mem_segment_free;

	private:
		static ILIAS_NET2_LOCAL const std::size_t m_pool_align;
		static ILIAS_NET2_LOCAL const std::size_t m_pool_offset;
		static ILIAS_NET2_LOCAL const std::size_t m_pool_overhead;
		static ILIAS_NET2_LOCAL pool m_pool;	/* Pool from which these are allocated. */

		static size_type
		overhead() ILIAS_NET2_NOTHROW
		{
			return m_pool_overhead;
		}

		std::atomic<size_type> alloc;		/* Memory after this. */
		std::atomic<size_type> use;		/* Memory used. */
		std::atomic<size_type> avail;		/* Memory available. */
		std::atomic<bool> alloc_guard;		/* Protect against concurrent extend. */
		std::atomic<bool> m_sensitive;		/* Memory contains sensitive data. */

		/*
		 * Trivial scoped lock for alloc_guard.
		 * Spins.
		 * I made this since std::mutex pulls in std::chrono
		 * which fails to compile on my OS.
		 */
		class alloc_guard_lock
		{
		private:
			std::atomic<bool>& alloc_guard;
			bool m_locked;

		public:
			alloc_guard_lock(std::atomic<bool>& alloc_guard, bool do_lock = true) ILIAS_NET2_NOTHROW :
				alloc_guard(alloc_guard),
				m_locked(false)
			{
				if (do_lock)
					this->lock();
			}

			~alloc_guard_lock() ILIAS_NET2_NOTHROW
			{
				if (this->m_locked)
					this->unlock();
			}

			bool
			try_lock() ILIAS_NET2_NOTHROW
			{
				assert(!this->m_locked);

				if (!alloc_guard.exchange(true, std::memory_order_acquire)) {
					this->m_locked = true;
					return true;
				}
				return false;
			}

			void
			lock() ILIAS_NET2_NOTHROW
			{
				assert(!this->m_locked);

				bool orig = false;
				while (this->alloc_guard.compare_exchange_weak(orig, true,
				    std::memory_order_acquire, std::memory_order_relaxed))
					orig = false;
				this->m_locked = true;
			}

			void
			unlock() ILIAS_NET2_NOTHROW
			{
				assert(this->m_locked);

				const bool orig = this->alloc_guard.exchange(false, std::memory_order_release);
				assert(orig);
				this->m_locked = false;
			}


#if HAS_DELETED_FN
			alloc_guard_lock(const alloc_guard_lock&) = delete;
			alloc_guard_lock operator=(const alloc_guard_lock&) = delete;
#else
		private:
			alloc_guard_lock(const alloc_guard_lock&);
			alloc_guard_lock operator=(const alloc_guard_lock&);
#endif
		};

		/*
		 * Total memory allocated for this mem_segment.
		 * This is not atomic and will yield incorrect information if called with a data race.
		 * (Call with alloc_guard locked to prevent races).
		 */
		size_type
		alloc_size(std::memory_order order = std::memory_order_relaxed) const ILIAS_NET2_NOTHROW
		{
			return overhead() + this->alloc.load(order);
		}

		mem_segment(size_type sz) ILIAS_NET2_NOTHROW :
			alloc(sz),
			use(0),
			avail(sz),
			alloc_guard(),
			m_sensitive(false)
		{
			/* Empty body. */
		}

		~mem_segment() ILIAS_NET2_NOTHROW
		{
			return;
		}

		/* Destroy and deallocate mem_segment. */
		static void free(mem_segment* ms) ILIAS_NET2_NOTHROW;

	public:
		/* Create a new mem_segment that is able to hold at least sz bytes. */
		static refpointer<mem_segment>
		create(std::nothrow_t, size_type sz) ILIAS_NET2_NOTHROW
		{
			refpointer<mem_segment> ms;

			void* ptr = m_pool.allocate_bytes(std::nothrow, overhead() + sz);
			if (ptr)
				ms.reset(::new(ptr) mem_segment(sz));
			return ms;
		}

		/* Create a new mem_segment that is able to hold at least sz bytes. */
		static refpointer<mem_segment>
		create(size_type sz) throw (std::bad_alloc)
		{
			refpointer<mem_segment> ptr = create(std::nothrow, sz);
			if (!ptr)
				throw std::bad_alloc();
			return ptr;
		}

	private:
		/*
		 * Extend the memory held by this mem_segment.
		 *
		 * Returns true if the operation was done, false if the operation failed due to lock contention.
		 * If the operation completes, newly allocated memory is stored in out.
		 * If no more memory is available, the operation returns true, but out will be nullptr.
		 *
		 * If claim is false, the newly allocated memory will not be claimed.
		 */
		bool
		extend(size_type sz, void*& out, bool claim) ILIAS_NET2_NOTHROW
		{
			out = nullptr;	/* Default to failure. */

			/* Attempt to acquire the allocation lock. */
			alloc_guard_lock lck(this->alloc_guard, false);
			if (!lck.try_lock())
				return false;	/* Lock contention. */

			/* Read amount of memory in use. */
			size_type space = this->alloc;

			/* Attempt to acquire some extra memory, in case more allocations follow. */
			size_type extra = pool::round_up(std::max((space + sz) * 2, size_type(128)), m_pool.align) - sz;

			/* Attempt to acquire memory. */
			void* base = this;
			bool succes = m_pool.resize_bytes(std::nothrow, base, overhead() + space, overhead() + space + sz + extra);
			if (!succes) {
				extra = 0;
				succes = m_pool.resize_bytes(std::nothrow, base, overhead() + space, overhead() + space + sz + extra);
			}

			if (succes) {
				/* Update this->alloc. */
				assert(this->alloc == space);
				this->alloc += sz + extra;

				const size_type offset = (claim ? use.fetch_add(sz, std::memory_order_acquire) : 0);
				avail.fetch_add(extra + (claim ? 0 : sz), std::memory_order_relaxed);
				out = this->data(offset);
			}
			/* We made it through the lock, so out will indicate if memory was available. */
			return true;
		}

		/*
		 * Returns true if space was claimed.
		 * Returns false with ptr set if space was made available using extend.
		 * Returns false with ptr cleared if no space is available.
		 *
		 * In other words: if true is returned, space is claimed but not yet commited.
		 *
		 * If claim is false, no memory will be claimed immediately.
		 */
		bool
		claim_reserve(size_type sz, void*& ptr, bool claim = true) ILIAS_NET2_NOTHROW
		{
			/*
			 * Reserve some of the available memory.
			 */
			size_type avail = sz;
			while (!this->avail.compare_exchange_weak(avail,
			    avail - sz,
			    std::memory_order_acquire, std::memory_order_relaxed)) {
				if (avail < sz) {
					if (this->extend(sz, ptr, claim) && claim)
						return false;
					avail += sz;	/* Ensure avail >= sz. */
				}
			}
			assert(avail >= sz);		/* Fails if we subtracted too much. */

			return true;
		}

	public:
		/* Allocate sz bytes of space.  Returns nullptr on failure. */
		void*
		allocate(std::nothrow_t, size_type sz) ILIAS_NET2_NOTHROW
		{
			void* ptr;
			if (!claim_reserve(sz, ptr))
				return ptr;

			/*
			 * Commit the memory claimed via avail.
			 */
			const size_type offset = use.fetch_add(sz, std::memory_order_acquire);
			return this->data(offset);
		}

		/* Allocate sz bytes of space.  Throws std::bad_alloc on failure. */
		void*
		allocate(size_type sz) throw (std::bad_alloc)
		{
			void* ptr = this->allocate(std::nothrow, sz);
			if (!ptr)
				throw std::bad_alloc();
			return ptr;
		}

		/*
		 * Allocate memory at the specified address.
		 *
		 * If the top of the mem_segment is not exactly at this offset, the allocation will fail.
		 * (I.e. this cannot be used to allocate gaps, nor will it overwrite already claimed memory.)
		 *
		 * Returns a nullptr on failure.
		 */
		void*
		allocate_at(std::nothrow_t, const size_type& offset, size_type sz) ILIAS_NET2_NOTHROW
		{
			/* Claim space, but don't commit it yet. */
			{
				void* ptr;
				if (!this->claim_reserve(sz, ptr, false))
					return nullptr;
			}

			/* Attempt to commit memory at given offset. */
			size_type orig = offset;
			if (this->use.compare_exchange_strong(orig, offset + sz))
				return this->data(offset);

			/* Offset is not available. */
			this->avail.fetch_add(sz, std::memory_order_relaxed);
			return nullptr;
		}

		/*
		 * Allocate memory at the specified address.
		 *
		 * If the top of the mem_segment is not exactly at this offset, the allocation will fail.
		 * (I.e. this cannot be used to allocate gaps, nor will it overwrite already claimed memory.)
		 *
		 * Throws std::bad_alloc on failure.
		 */
		void*
		allocate_at(const size_type& offset, size_type sz)
		{
			void* ptr = this->allocate_at(std::nothrow, offset, sz);
			if (!ptr)
				throw std::bad_alloc();
			return ptr;
		}

		/*
		 * Returns a pointer to the memory address at the given offset.
		 */
		void*
		data(size_type offset = 0) const ILIAS_NET2_NOTHROW
		{
			/*
			 * Note that the conversion from const to non-const is safe,
			 * since the non-const data resides outside this.
			 */
			const void* base = this;
			return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(base) + overhead() + offset);
		}

		/* Mark this segment as containing sensitive information. */
		void
		mark_sensitive() ILIAS_NET2_NOTHROW
		{
			this->m_sensitive.store(true, std::memory_order_relaxed);
		}


		/*
		 * Prevent construction of this class.
		 * Also prevent the delete operator, since it cannot work
		 * (its implementation would need to access data on the destroyed object).
		 */
#if HAS_DELETED_FN
		static void* operator new(std::size_t) = delete;
		static void* operator new(std::size_t, const std::nothrow_t&) = delete;
		static void operator delete(void*) = delete;
		static void operator delete(void*, const std::nothrow_t&) = delete;

		mem_segment(const mem_segment&) = delete;
		mem_segment& operator=(const mem_segment&) = delete;
#else
	private:
		static void* operator new(std::size_t) { std::terminate(); };
		static void* operator new(std::size_t, const std::nothrow_t&) { std::terminate(); };
		static void operator delete(void*) { std::terminate(); };
		static void operator delete(void*, const std::nothrow_t&) { std::terminate(); };

		mem_segment(const mem_segment&);
		mem_segment& operator=(const mem_segment&);
#endif
	};

	/* Segment reference, manages shared ownership of a segment. */
	class segment_ref
	{
	private:
		refpointer<mem_segment> m_segment;
		size_type m_off;
		size_type m_len;

	public:
		segment_ref() ILIAS_NET2_NOTHROW :
			m_segment(),
			m_off(0),
			m_len(0)
		{
			return;
		}

		segment_ref(const segment_ref& o) ILIAS_NET2_NOTHROW :
			m_segment(o.m_segment),
			m_off(o.m_off),
			m_len(o.m_len)
		{
			return;
		}

#if HAS_RVALUE_REF
		segment_ref(segment_ref&& o) ILIAS_NET2_NOTHROW :
			m_segment(std::move(o.m_segment)),
			m_off(std::move(o.m_off)),
			m_len(std::move(o.m_len))
		{
			return;
		}
#endif

		explicit segment_ref(const void* data, size_type len, bool sensitive) :
			m_segment(mem_segment::create(len)),
			m_off(0),
			m_len(len)
		{
			if (sensitive)
				this->m_segment->mark_sensitive();

			void*const dst = this->m_segment->allocate(len);
			this->m_off = reinterpret_cast<uintptr_t>(dst) -
			    reinterpret_cast<uintptr_t>(this->m_segment->data());
			copy_memory(dst, data, len);
		}

		struct reserve_tag {};

		/* Create a segment with reserved memory. */
		segment_ref(const reserve_tag&, const segment_ref* opt_sibling, size_type len, bool sensitive) :
			m_segment(),
			m_off(0),
			m_len(len)
		{
			void* data;

			if (opt_sibling && (data = opt_sibling->m_segment->allocate(std::nothrow, len)))
				this->m_segment = opt_sibling->m_segment;
			else {
				this->m_segment = mem_segment::create(len);
				data = this->m_segment->allocate(len);
			}

			if (sensitive)
				this->m_segment->mark_sensitive();
			this->m_off = reinterpret_cast<uintptr_t>(data) -
			    reinterpret_cast<uintptr_t>(this->m_segment->data());
		}

		~segment_ref() ILIAS_NET2_NOTHROW;

		void
		mark_sensitive() ILIAS_NET2_NOTHROW
		{
			if (this->m_segment)
				this->m_segment->mark_sensitive();
		}

		size_type
		length() const ILIAS_NET2_NOTHROW
		{
			return this->m_len;
		}

		segment_ref&
		operator= (const segment_ref& o) ILIAS_NET2_NOTHROW
		{
			this->m_segment = o.m_segment;
			this->m_off = o.m_off;
			this->m_len = o.m_len;
			return *this;
		}

#if HAS_RVALUE_REF
		segment_ref&
		operator= (segment_ref&& o) ILIAS_NET2_NOTHROW
		{
			this->m_segment = std::move(o.m_segment);
			this->m_off = std::move(o.m_off);
			this->m_len = std::move(o.m_len);
			return *this;
		}
#endif

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
			this->m_len -= len;
		}

		bool
		merge(const segment_ref& o) ILIAS_NET2_NOTHROW
		{
			if (this->m_segment &&
			    this->m_segment == o.m_segment &&
			    this->m_off + this->m_len == o.m_off) {
				this->m_len += o.m_len;
				return true;
			}
			return false;
		}

		bool grow(const void*, size_type, bool = false) ILIAS_NET2_NOTHROW;

		void
		copyout(void* dst, size_type len) const ILIAS_NET2_NOTHROW
		{
			assert(len <= this->m_len);
			assert(this->m_segment);

			copy_memory(dst, this->m_segment->data(this->m_off), len);
		}

		size_type
		copyout(void* dst) const ILIAS_NET2_NOTHROW
		{
			copy_memory(dst, this->m_segment->data(this->m_off), this->m_len);
			return this->m_len;
		}

		void*
		data(size_type off = 0) const ILIAS_NET2_NOTHROW
		{
			return ((off >= this->m_len || !this->m_segment) ?
			    nullptr :
			    this->m_segment->data(this->m_off + off));
		}
	};

	/* The type of the segment list. */
	typedef std::vector<std::pair<size_type, segment_ref> > list_type;

	/* The list of segments. */
	list_type m_list;
	/* Reserved space in m_list for prepare/commit entries. */
	size_type m_reserve;

	/*
	 * Ensure the list can hold extra segments without violating the reserve guarantee.
	 */
	void
	reserve_immediate(size_type extra) throw (std::bad_alloc)
	{
		const size_type required = this->m_list.size() + this->m_reserve + extra;
		if (this->m_list.capacity() < required)
			this->m_list.reserve(required);
	}

	/*
	 * Append segment.
	 * Will attempt to merge the segment with its predecessor.
	 */
	void push_back(const segment_ref& sr) ILIAS_NET2_NOTHROW;
#if HAS_RVALUE_REF
	/*
	 * Append segment.
	 * Will attempt to merge the segment with its predecessor.
	 */
	void push_back(segment_ref&& sr) ILIAS_NET2_NOTHROW;
#endif

	/*
	 * Find the last R for which pred(R, v) is true.
	 */
	template<typename Iter, typename Pred>
	static Iter
	binsearch_lowerbound(Iter begin, Iter end, const Pred& pred = std::less<typename Iter::value_type>())
	{
		/*
		 * Invariant: pred(end + 1) = false.
		 * Invariant: pred(begin) = true.
		 */
		while (begin != end) {
			const typename Iter::difference_type delta = (end - begin);

			Iter mid = begin + (delta + 1) / 2;
			if (mid == end || !pred(*mid))
				end = MOVE_IF_NOEXCEPT(--mid);
			else
				begin = MOVE_IF_NOEXCEPT(mid);
		}
		return begin;
	}
	/*
	 * Find the first R for which pred(R) is false.
	 */
	template<typename Iter, typename Pred>
	static Iter
	binsearch_upperbound(Iter begin, Iter end, const Pred& pred = std::less<typename Iter::value_type>())
	{
		/*
		 * Invariant: pred(end) = false.
		 * Invariant: pred(begin - 1) = true.
		 */
		while (begin != end) {
			const typename Iter::difference_type delta = (end - begin);

			Iter mid = begin + delta / 2;
			if (pred(*mid))
				begin = MOVE_IF_NOEXCEPT(++mid);
			else
				end = MOVE_IF_NOEXCEPT(mid);
		}
		return end;
	}

	/*
	 * Find the segment ref that contains the given offset.
	 * Returns list.end() if no entry describes the offset.
	 */
	ILIAS_NET2_LOCAL list_type::iterator find_offset(size_type) ILIAS_NET2_NOTHROW;

	/*
	 * Find the segment ref that contains the given offset.
	 * Returns list.end() if no entry describes the offset.
	 */
	ILIAS_NET2_LOCAL list_type::const_iterator find_offset(size_type) const ILIAS_NET2_NOTHROW;

public:
	/* Default constructor. */
	buffer() ILIAS_NET2_NOTHROW :
		m_list(),
		m_reserve(0)
	{
		return;
	}

	/* Copy constructor. */
	buffer(const buffer& rhs) throw (std::bad_alloc);

#if HAS_RVALUE_REF
	/* Move constructor. */
	buffer(buffer&& rhs) ILIAS_NET2_NOTHROW :
		m_list(std::move(rhs.m_list)),
		m_reserve(0)
	{
		return;
	}
#endif

	buffer(const void* data, size_type len) :
		m_list(),
		m_reserve()
	{
		this->append(data, len);
	}

	~buffer() ILIAS_NET2_NOTHROW;

	/* Test if the buffer is empty. */
	bool
	empty() const ILIAS_NET2_NOTHROW
	{
		return this->m_list.empty();
	}

	/* Return the size (in bytes) of this buffer. */
	size_type size() const ILIAS_NET2_NOTHROW;

	/* Return the number of segments in this buffer. */
	size_type
	segments() const ILIAS_NET2_NOTHROW
	{
		return this->m_list.size();
	}

	/* Assignment. */
	buffer& operator= (const buffer& o) throw (std::bad_alloc);

#if HAS_RVALUE_REF
	/* Move assignment. */
	buffer&
	operator= (buffer&& o) ILIAS_NET2_NOTHROW
	{
		assert(this->m_reserve == 0);

		this->m_list = std::move(o.m_list);
		return *this;
	}
#endif

	/* Append a buffer. */
	buffer& operator+= (const buffer& o) throw (std::bad_alloc);

	/* Create a buffer that is this buffer and another buffer concatenated. */
	buffer
	operator+ (const buffer& o) const throw (std::bad_alloc)
	{
		buffer copy = *this;
		copy += o;
		return copy;
	}

	/* Swap the contents of two buffers. */
	void
	swap(buffer& o) ILIAS_NET2_NOTHROW
	{
		assert(this->m_reserve == 0 && o.m_reserve == 0);
		this->m_list.swap(o.m_list);
	}

	/* Swap the contents of two buffers. */
	friend void
	swap(buffer& lhs, buffer& rhs) ILIAS_NET2_NOTHROW
	{
		lhs.swap(rhs);
	}

private:
	/*
	 * Performs copyout and returns the iterator to the end of the drained region.
	 * Internal use only, will (probably) be inlined only.
	 */
	ILIAS_NET2_LOCAL list_type::iterator drain_internal(void*, size_type) ILIAS_NET2_NOTHROW;

public:
	/* Clear the buffer. */
	void clear() ILIAS_NET2_NOTHROW;
	/* Drain bytes from the buffer into supplied void* buffer. */
	void drain(void*, size_type) throw (std::out_of_range);
	/* Truncate the buffer to the given size. */
	void truncate(size_type) throw (std::out_of_range);
	/* Prepend a buffer (this is an expensive operation). */
	void prepend(const buffer& o) throw (std::bad_alloc);
	/* Append data to the buffer.  Set the boolean to true if this data is sensitive. */
	void append(const void*, size_type, bool = false) throw (std::bad_alloc);
	/* Mark the entire buffer as containing sensitive data. */
	void mark_sensitive() ILIAS_NET2_NOTHROW;

	/* Remove the first len bytes from this buffer. */
	void
	drain(size_type len) throw (std::out_of_range)
	{
		this->drain(nullptr, len);
	}

	/*
	 * Append the memory in value directly to the buffer.
	 * Intended if your type is contiguous and contains data in the proper byte order already.
	 *
	 * Note: severely discouraged for non-POD types!
	 */
	template<typename T>
	void
	append_literal(const T& value) throw (std::bad_alloc)
	{
		this->append(reinterpret_cast<const void*>(&value), sizeof(value));
	}

	/*
	 * Drain info the memory of value directly from the buffer.
	 * Intended if your type is contiguous and will deal with the byte order in the buffer.
	 *
	 * Note: severely discouraged for non-POD types!
	 */
	template<typename T>
	T
	drain_literal() throw (std::out_of_range)
	{
		T rv;
		this->drain(reinterpret_cast<void*>(&rv), sizeof(rv));
		return rv;
	}

private:
	buffer& subrange_adapter(buffer& result, size_type off, size_type len) const throw (std::bad_alloc, std::out_of_range);

public:
	/* Return a buffer with the range described by off, len. */
	buffer
	subrange(size_type off, size_type len) const throw (std::bad_alloc, std::out_of_range)
	{
		buffer result;
		subrange_adapter(result, off, len);
		return result;
	}

	/*
	 * Buffer comparison.
	 *
	 * Returns -1 if this is lexicographically before o.
	 * Returns  1 if this is lexicographically after  o.
	 * Returns  0 if the two buffers are identical.
	 */
	int cmp(const buffer& o) const ILIAS_NET2_NOTHROW;

	bool
	operator== (const buffer& o) const ILIAS_NET2_NOTHROW
	{
		return (this->cmp(o) == 0);
	}

	bool
	operator!= (const buffer& o) const ILIAS_NET2_NOTHROW
	{
		return (this->cmp(o) != 0);
	}

	bool
	operator< (const buffer& o) const ILIAS_NET2_NOTHROW
	{
		return (this->cmp(o) < 0);
	}

	bool
	operator> (const buffer& o) const ILIAS_NET2_NOTHROW
	{
		return (this->cmp(o) > 0);
	}

	bool
	operator<= (const buffer& o) const ILIAS_NET2_NOTHROW
	{
		return (this->cmp(o) <= 0);
	}

	bool
	operator>= (const buffer& o) const ILIAS_NET2_NOTHROW
	{
		return (this->cmp(o) >= 0);
	}

	/* Try to find a string in the buffer, starting at offset. */
	size_type find_string(const void*, size_type, size_type = 0) const ILIAS_NET2_NOTHROW;

	/*
	 * Visit each range in the buffer with the visitor.
	 *
	 * The visitor will be called with f(const void*, size_type).
	 */
	template<typename Functor>
	void
	visit(Functor f) const
	{
		for (list_type::const_iterator i = this->m_list.begin(); i != this->m_list.end(); ++i) {
			const void* p = i->second.data();
			f(p, i->second.length());
		}
	}

	/*
	 * Visit each range in the buffer with the visitor, stopping after len bytes have been visited.
	 *
	 * The visitor will be called with f(const void*, size_type).
	 */
	template<typename Functor>
	void
	visit(Functor f, size_type len) const
	{
		/* Check if we can fulfill the request. */
		if (len > this->size())
			throw std::out_of_range("len argument exceeds buffer length");

		for (list_type::const_iterator i = this->m_list.begin(); i != this->m_list.end() && len > 0; ++i) {
			const void* p = i->second.data();
			size_type vlen = std::min(i->second.length(), len);
			f(p, vlen);
			len -= vlen;
		}
	}

	/*
	 * Fill io vectors with data contained in buffer.
	 */
	template<typename IovecOutIter>
	IovecOutIter
	peek(IovecOutIter iter) const
	{
		/*
		 * Capturing this, since gcc 4.6.2 attempts to use non-static set_iov_{base,len} for some off reason.
		 */
		this->visit([&iter, this](const void *p, size_type len) {
			buffer::iovec rv;
			set_iov_base(rv, const_cast<void*>(p));
			set_iov_len(rv, len);
			*iter++ = rv;
		});
		return iter;
	}

	/*
	 * Fill io vectors with data contained in buffer.
	 *
	 * Stops after len bytes have been visited.
	 */
	template<typename IovecOutIter>
	IovecOutIter
	peek(IovecOutIter iter, size_type len) const
	{
		/*
		 * Capturing this, since gcc 4.6.2 attempts to use non-static set_iov_{base,len} for some off reason.
		 */
		this->visit([&iter, this](const void* p, size_type len) {
			buffer::iovec rv;
			set_iov_base(rv, const_cast<void*>(p));
			set_iov_len(rv, len);
			*iter++ = rv;
		}, len);
		return iter;
	}

	/* Copy len bytes from buffer to output. */
	void copyout(void*, size_type) const throw (std::out_of_range);

private:
	class prepare_bufref;

public:
	/* Prepared buffer insert. */
	class prepare;
};


inline void
buffer::mem_segment_free::operator()(buffer::mem_segment* ms) const ILIAS_NET2_NOTHROW
{
	mem_segment::free(ms);
}


class buffer::prepare_bufref
{
private:
	buffer* m_buf;

public:
	prepare_bufref() ILIAS_NET2_NOTHROW :
		m_buf(nullptr)
	{
		/* Empty body. */
	}

	prepare_bufref(buffer& b) :
		m_buf(&b)
	{
		b.reserve_immediate(1);
		++b.m_reserve;
	}

#if HAS_RVALUE_REF
	prepare_bufref(prepare_bufref&& o) ILIAS_NET2_NOTHROW :
		m_buf(nullptr)
	{
		this->swap(o);
	}
#endif

	~prepare_bufref() ILIAS_NET2_NOTHROW
	{
		this->release();
	}

	buffer*
	release() ILIAS_NET2_NOTHROW
	{
		buffer* orig = this->m_buf;
		if (this->m_buf) {
			--this->m_buf->m_reserve;
			this->m_buf = nullptr;
		}
		return orig;
	}

	buffer*
	get_buffer() const ILIAS_NET2_NOTHROW
	{
		return this->m_buf;
	}

	void
	swap(prepare_bufref& o) ILIAS_NET2_NOTHROW
	{
		using std::swap;
		swap(this->m_buf, o.m_buf);
	}


#if HAS_DELETED_FN
	prepare_bufref(const prepare_bufref&) = delete;
	prepare_bufref& operator=(const prepare_bufref&) = delete;
#else
private:
	prepare_bufref(const prepare_bufref&);
	prepare_bufref& operator=(const prepare_bufref&);
#endif
};

class buffer::prepare :
	private buffer::prepare_bufref
{
private:
	segment_ref m_segment;

public:
	prepare() ILIAS_NET2_NOTHROW :
		prepare_bufref(),
		m_segment()
	{
		/* Empty body. */
	}

	prepare(buffer& b, size_type len, bool sensitive = false);

#if HAS_RVALUE_REF
	prepare(prepare&& p) ILIAS_NET2_NOTHROW :
		prepare_bufref(std::move(p)),
		m_segment(std::move(p.m_segment))
	{
		/* Empty body. */
	}
#endif

	~prepare() ILIAS_NET2_NOTHROW;

	/*
	 * Return the address of memory at offset.
	 * Will return nullptr if off falls outside of the range.
	 */
	void*
	data(size_type off = 0) const ILIAS_NET2_NOTHROW
	{
		return this->m_segment.data(off);
	}

	/* Returns the size of the reserved area. */
	size_type
	size() const ILIAS_NET2_NOTHROW
	{
		return this->m_segment.length();
	}

	/* Test if this prepare is active (i.e. it can be commited). */
	bool
	valid() const ILIAS_NET2_NOTHROW
	{
		return (this->get_buffer() != nullptr);
	}

	/*
	 * Mark the in-progress buffer as sensitive.
	 * Silently ignored if the prepare isn't valid.
	 */
	void
	mark_sensitive() ILIAS_NET2_NOTHROW
	{
		this->m_segment.mark_sensitive();
	}

	/*
	 * Commit prepared state to buffer.
	 * This operation will always place the data at the rear of the buffer.
	 * Calling commit() on an prepare that isn't valid will yield undefined
	 * behaviour (it may assert or it may corrupt the buffer).
	 */
	void commit() ILIAS_NET2_NOTHROW;

	/*
	 * Cancel the prepare.
	 */
	void reset() ILIAS_NET2_NOTHROW;
};


} /* namespace ilias */


#ifdef _MSC_VER
#pragma warning( pop )
#endif


#endif /* ILIAS_NET2_BUFFER_H */
