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
#ifndef ILIAS_NET2_POOL_H
#define ILIAS_NET2_POOL_H

#ifdef __cplusplus

#include <ilias/net2/ilias_net2_export.h>
#include <algorithm>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <ilias/net2/ll.h>

namespace ilias {


class ILIAS_NET2_EXPORT pool
{
public:
	typedef std::size_t size_type;
	typedef std::ptrdiff_t difference_type;

private:
	class osdep;
	class page;
	typedef ll_list< ll_base<page> > ll_list_type;

public:
	/* Helper functions. */
	template<typename T>
	static constexpr T
	round_down(const T& v, const T& r)
	{
		return ((r & (r - 1)) == 0 ? (v & ~(r - 1)) : (v - v % r));
	}

	/* Helper functions. */
	template<typename T>
	static constexpr T
	round_up(const T& v, const T& r)
	{
		return round_down(v + r - 1, r);
	}

	const size_type align;
	const size_type offset;
	const size_type size;
	ll_list_type head;

	static constexpr_value size_type default_align = (sizeof(double) > sizeof(void*) ? sizeof(double) : sizeof(void*));
	static constexpr_value size_type default_offset = 0;

	pool(size_type size, size_type align = default_align, size_type offset = default_offset) :
		align(align <= 0 ? 1 : align),
		offset(offset % this->align),
		size(round_up(size, this->align)),
		head()
	{
		/* Empty body. */
	}

private:
	inline size_type entries_per_page() const;

	ILIAS_NET2_LOCAL void page_enqueue(page*);
	ILIAS_NET2_LOCAL void dealloc_page(page*);

	struct deleter_type;
	typedef std::unique_ptr<page, deleter_type> page_ptr;

	ILIAS_NET2_LOCAL page_ptr&& alloc_page();
	ILIAS_NET2_LOCAL page_ptr&& pop_page();
	ILIAS_NET2_LOCAL page_ptr&& alloc_big_page(size_type);

public:
	void* allocate(std::nothrow_t, size_type, void* = nullptr) ILIAS_NET2_NOTHROW;
	bool deallocate(std::nothrow_t, void*, size_type) ILIAS_NET2_NOTHROW;
	bool resize(std::nothrow_t, void*, size_type, size_type) ILIAS_NET2_NOTHROW;

	void*
	allocate(size_type sz, void* hint = nullptr) throw (std::bad_alloc)
	{
		void* rv = allocate(std::nothrow, sz, hint);
		if (!rv)
			throw std::bad_alloc();
		return rv;
	}

	void
	deallocate(void* addr, size_type sz) throw (std::invalid_argument)
	{
		if (!deallocate(std::nothrow, addr, sz))
			throw std::invalid_argument("pool deallocate");
	}

	void
	resize(void* addr, size_type old_sz, size_type new_sz) throw (std::bad_alloc)
	{
		if (!resize(std::nothrow, addr, old_sz, new_sz))
			throw std::bad_alloc();
	}

	size_type
	maxsize() const ILIAS_NET2_NOTHROW
	{
		return (std::numeric_limits<size_type>::max() / this->size);
	}

	size_type
	maxsize_bytes() const ILIAS_NET2_NOTHROW
	{
		return maxsize() * this->size;
	}

	void*
	allocate_bytes(size_type bytes, void* hint = nullptr) throw (std::bad_alloc)
	{
		return allocate((bytes + this->size - 1) / this->size, hint);
	}

	void*
	allocate_bytes(std::nothrow_t, size_type bytes, void* hint = nullptr) ILIAS_NET2_NOTHROW
	{
		return allocate(std::nothrow, (bytes + this->size - 1) / this->size, hint);
	}

	void
	deallocate_bytes(void* addr, size_type bytes) throw (std::invalid_argument)
	{
		deallocate(addr, (bytes + this->size - 1) / this->size);
	}

	void
	deallocate_bytes(std::nothrow_t, void* addr, size_type bytes) ILIAS_NET2_NOTHROW
	{
		deallocate(std::nothrow, addr, (bytes + this->size - 1) / this->size);
	}

	void
	resize_bytes(void* addr, size_type old_bytes, size_type new_bytes) throw (std::bad_alloc)
	{
		const size_type old_n = (old_bytes + this->size - 1) / this->size;
		const size_type new_n = (new_bytes + this->size - 1) / this->size;
		resize(addr, old_n, new_n);
	}

	bool
	resize_bytes(std::nothrow_t, void* addr, size_type old_bytes, size_type new_bytes) ILIAS_NET2_NOTHROW
	{
		const size_type old_n = (old_bytes + this->size - 1) / this->size;
		const size_type new_n = (new_bytes + this->size - 1) / this->size;
		return resize(std::nothrow, addr, old_n, new_n);
	}

private:
	static inline size_type waste(size_type, size_type, size_type) ILIAS_NET2_NOTHROW;

public:
	static size_type recommend_size(size_type min, size_type max, size_type align = default_align, size_type offset = default_offset) ILIAS_NET2_NOTHROW;
};


template<typename T, std::size_t Align = (sizeof(T) < pool::default_align ? sizeof(T) : pool::default_align), std::size_t Offset = pool::default_offset>
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

	template<typename U, std::size_t U_Align = Align, std::size_t U_Offset = Offset>
	struct rebind {
		typedef pool_allocator<U, U_Align, U_Offset> type;
	};

	pool_allocator() :
		pool(sizeof(T), Align, Offset)
	{
		/* Empty body. */
	}

	pool_allocator(const pool_allocator&) = delete;
	pool_allocator& operator=(const pool_allocator&) = delete;

	pointer
	allocate(size_type n, void* hint = nullptr) throw (std::bad_alloc)
	{
		return this->pool::allocate(n, hint);
	}

	pointer
	allocate(std::nothrow_t, size_type n, void* hint = nullptr) ILIAS_NET2_NOTHROW
	{
		return this->pool::allocate(std::nothrow, n, hint);
	}

	void
	deallocate(pointer ptr, size_type n) throw (std::invalid_argument)
	{
		if (ptr)
			this->pool::deallocate(ptr, n);
	}

	void
	deallocate(std::nothrow_t, pointer ptr, size_type n) ILIAS_NET2_NOTHROW
	{
		if (ptr)
			this->pool::deallocate(std::nothrow, ptr, n);
	}

	void
	resize(pointer p, size_type old_n, size_type new_n) throw (std::bad_alloc)
	{
		if (!p)
			throw std::bad_alloc();
		this->pool::resize(p, old_n, new_n);
	}

	bool
	resize(std::nothrow_t, pointer p, size_type old_n, size_type new_n) ILIAS_NET2_NOTHROW
	{
		if (!p)
			return false;
		return this->pool::resize(std::nothrow, p, old_n, new_n);
	}

	static pointer
	address(reference v) ILIAS_NET2_NOTHROW
	{
		typedef char& casted;
		return reinterpret_cast<pointer>(&reinterpret_cast<casted>(v));
	}

	static const_pointer
	address(const_reference v) ILIAS_NET2_NOTHROW
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
template<std::size_t Align, std::size_t Offset>
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

} /* namespace ilias */

#endif /* __cplusplus */

#endif /* ILIAS_NET2_POOL_H */
