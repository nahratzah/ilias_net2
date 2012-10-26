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

#include <ilias/net2/ilias_net2_export.h>
#include <algorithm>
#include <cstdint>
#include <memory>

class ILIAS_NET2_EXPORT pool
{
public:
	typedef std::size_t size_type;
	typedef std::ptrdiff_t difference_type;

private:
	class osdep;
	class page;

	template<typename T>
	static constexpr RVALUE(T)
	round_down(const T& v, const T& r)
	{
		return std::move((r & (r - 1)) == 0 ? (v & ~(r - 1)) : (v - v % r));
	}

	template<typename T>
	static constexpr RVALUE(T)
	round_up(const T& v, const T& r)
	{
		return std::move(round_down(v + r - 1, r));
	}

public:
	const size_type align;
	const size_type offset;
	const size_type size;

	static constexpr_value size_type default_align = (sizeof(double) > sizeof(void*) ? sizeof(double) : sizeof(void*));
	static constexpr_value size_type default_offset = 0;

	constexpr pool(size_type size, size_type align = default_align, size_type offset = default_offset) :
		align(align <= 0 ? 1 : align),
		offset(offset % this->align),
		size(round_up(size, this->align))
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
	void* allocate(size_type, void*) ILIAS_NET2_NOTHROW;
	void deallocate(void*, size_type) ILIAS_NET2_NOTHROW;
	bool resize(void*, size_type, size_type) ILIAS_NET2_NOTHROW;

	constexpr size_type
	maxsize() const ILIAS_NET2_NOTHROW
	{
		return (std::numeric_limits<size_type>::max() / this->size);
	}

	constexpr size_type
	maxsize_bytes() const ILIAS_NET2_NOTHROW
	{
		return maxsize() * this->size;
	}

	void*
	allocate_bytes(size_type bytes, void* hint) ILIAS_NET2_NOTHROW
	{
		return allocate((bytes + this->size - 1) / this->size, hint);
	}

	void
	deallocate_bytes(void* addr, size_type bytes) ILIAS_NET2_NOTHROW
	{
		return deallocate(addr, (bytes + this->size - 1) / this->size);
	}

	bool
	resize_bytes(void* addr, size_type old_bytes, size_type new_bytes) ILIAS_NET2_NOTHROW
	{
		const size_type old_n = (old_bytes + this->size - 1) / this->size;
		const size_type new_n = (new_bytes + this->size - 1) / this->size;
		return resize(addr, old_n, new_n);
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

	constexpr pool_allocator() :
		pool(sizeof(T), Align, Offset)
	{
		/* Empty body. */
	}

	pool_allocator(const pool_allocator&) = delete;
	pool_allocator& operator=(const pool_allocator&) = delete;

	pointer
	allocate(size_type n, void* hint = nullptr)
	{
		const pointer ptr = this->pool::allocate(n, hint);
		if (!ptr)
			throw std::bad_alloc();
		return ptr;
	}

	void
	deallocate(pointer ptr, size_type n) ILIAS_NET2_NOTHROW
	{
		if (ptr)
			this->pool::deallocate(ptr, n);
	}

	bool
	resize(pointer p, size_type old_n, size_type new_n) ILIAS_NET2_NOTHROW
	{
		if (ptr)
			return this->pool::resize(p, old_n, new_n);
		else
			return false;
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

#endif /* ILIAS_NET2_POOL_H */
