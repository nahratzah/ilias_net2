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

#ifdef WIN32
#include <WinSock2.h>
#else
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#endif


namespace ilias {


class ILIAS_NET2_EXPORT buffer
{
public:
	typedef uintptr_t size_type;

#if WIN32
	typedef _WSABUF iovec;

	static std::size_t
	iov_len(const iovec& v) ILIAS_NET2_NOTHROW
	{
		return v.len;
	}

	static void*
	iov_base(const iovec& v) ILIAS_NET2_NOTHROW
	{
		return v.buf;
	}
#else
	typedef ::iovec iovec;

	static std::size_t
	iov_len(const iovec& v) ILIAS_NET2_NOTHROW
	{
		return v.iov_len;
	}

	static void*
	iov_base(const iovec& v) ILIAS_NET2_NOTHROW
	{
		return v.iov_base;
	}
#endif

	/*
	 * A memcpy that attempts not to pollute the CPU cache.
	 */
	static void copy_memory(void*, const void*, size_type) ILIAS_NET2_NOTHROW;

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
			/* Empty body. */
		}

		/* Destroy and deallocate mem_segment. */
		static void free(mem_segment* ms) ILIAS_NET2_NOTHROW;

	public:
		/* Create a new mem_segment that is able to hold at least sz bytes. */
		static RVALUE(refpointer<mem_segment>)
		create(std::nothrow_t, size_type sz) ILIAS_NET2_NOTHROW
		{
			refpointer<mem_segment> ms;

			void* ptr = m_pool.allocate_bytes(std::nothrow, overhead() + sz);
			if (ptr)
				ms.reset(::new(ptr) mem_segment(sz));
			return MOVE(ms);
		}

		/* Create a new mem_segment that is able to hold at least sz bytes. */
		static RVALUE(refpointer<mem_segment>)
		create(size_type sz) throw (std::bad_alloc)
		{
			refpointer<mem_segment> ptr = create(std::nothrow, sz);
			if (!ptr)
				throw std::bad_alloc();
			return MOVE(ptr);
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
		allocate_at(const size_type& offset, size_type sz) ILIAS_NET2_NOTHROW
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
		static void* operator new(std::size_t);
		static void* operator new(std::size_t, const std::nothrow_t&);
		static void operator delete(void*);
		static void operator delete(void*, const std::nothrow_t&);

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
			m_len(0)
		{
			if (sensitive)
				this->m_segment->mark_sensitive();

			void*const dst = this->m_segment->allocate(len);
			copy_memory(dst, data, len);
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
	};

	/* The type of the segment list. */
	typedef std::vector<std::pair<size_t, segment_ref> > list_type;

	/* The list of segments. */
	list_type m_list;

private:
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
	static RVALUE(Iter)
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
		return MOVE(begin);
	}
	/*
	 * Find the first R for which pred(R) is false.
	 */
	template<typename Iter, typename Pred>
	static RVALUE(Iter)
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
		return MOVE(end);
	}

	/*
	 * Find the segment ref that contains the given offset.
	 * Returns list.end() if no entry describes the offset.
	 */
	ILIAS_NET2_LOCAL RVALUE(list_type::iterator) find_offset(size_type) ILIAS_NET2_NOTHROW;

	/*
	 * Find the segment ref that contains the given offset.
	 * Returns list.end() if no entry describes the offset.
	 */
	ILIAS_NET2_LOCAL RVALUE(list_type::const_iterator) find_offset(size_type) const ILIAS_NET2_NOTHROW;

public:
	/* Default constructor. */
	buffer() ILIAS_NET2_NOTHROW :
		m_list()
	{
		return;
	}

	/* Copy constructor. */
	buffer(const buffer& rhs) throw (std::bad_alloc);

#if HAS_RVALUE_REF
	/* Move constructor. */
	buffer(buffer&& rhs) ILIAS_NET2_NOTHROW :
		m_list(std::move(rhs.m_list))
	{
		return;
	}
#endif

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
		this->m_list = std::move(o.m_list);
		return *this;
	}
#endif

	/* Append a buffer. */
	buffer& operator+= (const buffer& o) throw (std::bad_alloc);

	/* Create a buffer that is this buffer and another buffer concatenated. */
	RVALUE(buffer)
	operator+ (const buffer& o) const throw (std::bad_alloc)
	{
		buffer copy = *this;
		copy += o;
		return MOVE(copy);
	}

	/* Swap the contents of two buffers. */
	void
	swap(buffer& o) ILIAS_NET2_NOTHROW
	{
		this->m_list.swap(o.m_list);
	}

	/* Swap the contents of two buffers. */
	friend void
	swap(buffer& lhs, buffer& rhs) ILIAS_NET2_NOTHROW
	{
		lhs.swap(rhs);
	}

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

private:
	buffer& subrange_adapter(buffer& result, size_type off, size_type len) const throw (std::bad_alloc, std::out_of_range);

public:
	/* Return a buffer with the range described by off, len. */
	RVALUE_REF(buffer)
	subrange(size_type off, size_type len) const throw (std::bad_alloc, std::out_of_range)
	{
		buffer result;
		subrange_adapter(result, off, len);
		return MOVE(result);
	}
};


inline void
buffer::mem_segment_free::operator()(buffer::mem_segment* ms) const ILIAS_NET2_NOTHROW
{
	mem_segment::free(ms);
}


} /* namespace ilias */


#endif /* ILIAS_NET2_BUFFER_H */
