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
#ifndef ILIAS_NET2_REFCNT_H
#define ILIAS_NET2_REFCNT_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/booltest.h>
#include <algorithm>
#include <atomic>
#include <cassert>
#include <memory>
#include <utility>

#ifdef HAS_CONSTRUCTOR_TRAITS
#include <type_traits>
#endif


#ifdef _MSC_VER
#pragma warning( push )
#pragma warning( disable: 4800 )
#endif


namespace ilias {


/*
 * Reference counted base class.
 *
 * Derived: derived type of the class.
 * Deleter: deletion invocation on release of last reference.
 */
template<typename Derived, typename Deleter = std::default_delete<const Derived> >
class refcount_base
{
private:
	mutable std::atomic<unsigned int> m_refcount;
	Deleter m_deleter;

protected:
	refcount_base() ILIAS_NET2_NOTHROW :
		m_refcount(0),
		m_deleter()
	{
		/* Empty body. */
	}

	refcount_base(const Deleter& m_deleter)
#ifdef HAS_CONSTRUCTOR_TRAITS
		ILIAS_NET2_NOTHROW_CND(std::is_nothrow_copy_constructible<Deleter>::value)
#endif
	    :
		m_refcount(0),
		m_deleter(m_deleter)
	{
		/* Empty body. */
	}

#if HAS_RVALUE_REF
	refcount_base(Deleter&& m_deleter)
#ifdef HAS_CONSTRUCTOR_TRAITS
		ILIAS_NET2_NOTHROW_CND(std::is_nothrow_move_constructible<Deleter>::value)
#endif
	    :
		m_refcount(0),
		m_deleter(m_deleter)
	{
		/* Empty body. */
	}
#endif

	refcount_base(const refcount_base&) ILIAS_NET2_NOTHROW :
		m_refcount(0),
		m_deleter()
	{
		/* Empty body. */
	}

	~refcount_base() ILIAS_NET2_NOTHROW
	{
		assert(this->m_refcount.load(std::memory_order_seq_cst) == 0);
	}

	refcount_base&
	operator=(const refcount_base&) ILIAS_NET2_NOTHROW
	{
		return *this;
	}

	friend void
	refcnt_acquire(const Derived& o) ILIAS_NET2_NOTHROW
	{
		const refcount_base& self = o;
		self.m_refcount.fetch_add(1, std::memory_order_acquire);
	}

	friend void
	refcnt_release(const Derived& o)
#if defined(HAS_CONSTRUCTOR_TRAITS) && HAS_RVALUE_REF
		ILIAS_NET2_NOTHROW_CND(
		    noexcept(o.refcount_base::m_deleter(&o)) &&
		    (std::is_nothrow_move_constructible<Deleter>::value || std::is_nothrow_copy_constructible<Deleter>::value) &&
		    std::is_nothrow_destructible<Deleter>::value)
#endif
	{
		const refcount_base& self = o;
		if (self.m_refcount.fetch_sub(1, std::memory_order_release) == 1) {
			Deleter deleter = MOVE_IF_NOEXCEPT(self.m_deleter);
			deleter(&o);
		}
	}

	/* Returns true if only one active reference exists to o. */
	friend bool
	refcnt_is_solo(const Derived& o) ILIAS_NET2_NOTHROW
	{
		const refcount_base& self = o;
		return (self.m_refcount.load(std::memory_order_relaxed) == 1);
	}

	friend bool
	refcnt_is_zero(const Derived& o) ILIAS_NET2_NOTHROW
	{
		const refcount_base& self = o;
		return (self.m_refcount.load(std::memory_order_relaxed) == 0);
	}
};

template<typename Type>
struct default_refcount_mgr
{
	void
	acquire(const Type& v) ILIAS_NET2_NOTHROW
	{
		refcnt_acquire(v);
	}

	void
	release(const Type& v) ILIAS_NET2_NOTHROW
	{
		refcnt_release(v);
	}
};

template<typename Type, typename AcqRel = default_refcount_mgr<Type> >
class refpointer :
	public bool_test<refpointer<Type> >,
	private AcqRel
{
public:
	typedef Type element_type;
	typedef element_type* pointer;
	typedef element_type& reference;

private:
	pointer m_ptr;

public:
	refpointer() ILIAS_NET2_NOTHROW :
		m_ptr(nullptr)
	{
		return;
	}

	refpointer(std::nullptr_t, bool = true) ILIAS_NET2_NOTHROW :
		m_ptr(nullptr)
	{
		return;
	}

	refpointer(const refpointer& o) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(AcqRel::acquire(*this->m_ptr))) :
		m_ptr(nullptr)
	{
		this->reset(o);
	}

#if HAS_RVALUE_REF
	refpointer(refpointer&& o) ILIAS_NET2_NOTHROW :
		m_ptr(nullptr)
	{
		std::swap(this->m_ptr, o.m_ptr);
	}
#endif

	template<typename U, typename U_AcqRel>
	refpointer(const refpointer<U, U_AcqRel>& o) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(AcqRel::acquire(*this->m_ptr))) :
		m_ptr(nullptr)
	{
		this->reset(o.get());
	}

	refpointer(pointer p, bool do_acquire = true) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(AcqRel::acquire(*this->m_ptr))) :
		m_ptr(nullptr)
	{
		this->reset(p, do_acquire);
	}

	~refpointer() ILIAS_NET2_NOTHROW_CND_TEST(noexcept(AcqRel::release(*this->m_ptr)))
	{
		this->reset();
	}

	void
	reset() ILIAS_NET2_NOTHROW_CND_TEST(noexcept(AcqRel::release(*this->m_ptr)))
	{
		if (this->m_ptr) {
			this->AcqRel::release(*this->m_ptr);
			this->m_ptr = nullptr;
		}
	}

	void
	reset(const refpointer& o) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(AcqRel::release(*this->m_ptr)) && noexcept(AcqRel::acquire(*this->m_ptr)))
	{
		const pointer old = this->m_ptr;
		if (o.m_ptr) {
			this->AcqRel::acquire(*o.m_ptr);
			this->m_ptr = o.m_ptr;
		} else
			this->m_ptr = nullptr;

		if (old)
			this->AcqRel::release(*old);
	}

#if HAS_RVALUE_REF
	void
	reset(refpointer&& o) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(refcnt_release(*this->m_ptr)))
	{
		const pointer old = this->m_ptr;
		this->m_ptr = o.m_ptr;
		o.m_ptr = nullptr;

		if (old)
			this->AcqRel::release(*old);
	}
#endif

	void
	reset(pointer p, bool do_acquire = true) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(AcqRel::release(*this->m_ptr)) && noexcept(AcqRel::acquire(*this->m_ptr)))
	{
		const pointer old = this->m_ptr;
		if (p) {
			if (do_acquire)
				this->AcqRel::acquire(*p);
			this->m_ptr = p;
		} else
			this->m_ptr = nullptr;

		if (old)
			this->AcqRel::release(*old);
	}

	template<typename U, typename U_AcqRel>
	void
	reset(const refpointer<U, U_AcqRel>& o) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(AcqRel::release(*this->m_ptr)) && noexcept(AcqRel::acquire(*this->m_ptr)))
	{
		this->reset(o.get(), true);
	}

	refpointer&
	operator=(std::nullptr_t) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(AcqRel::release(*this->m_ptr)))
	{
		this->reset();
		return *this;
	}

	refpointer&
	operator=(const refpointer& o) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(AcqRel::release(*this->m_ptr)) && noexcept(AcqRel::acquire(*this->m_ptr)))
	{
		this->reset(o);
		return *this;
	}

#if HAS_RVALUE_REF
	refpointer&
	operator=(refpointer&& o) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(AcqRel::release(*this->m_ptr)))
	{
		this->reset(o);
		return *this;
	}
#endif

	refpointer&
	operator=(pointer p) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(AcqRel::release(*this->m_ptr)) && noexcept(AcqRel::acquire(*this->m_ptr)))
	{
		this->reset(p);
		return *this;
	}

	bool
	operator==(const refpointer& o) const ILIAS_NET2_NOTHROW
	{
		return (this->get() == o.get());
	}

	template<typename U>
	bool
	operator==(const refpointer<U>& o) const ILIAS_NET2_NOTHROW
	{
		return (this->get() == o.get());
	}

	template<typename Ptr>
	bool
	operator==(Ptr* p) const ILIAS_NET2_NOTHROW
	{
		return (this->get() == p);
	}

	template<typename U>
	bool
	operator!=(const U& o) const ILIAS_NET2_NOTHROW
	{
		return !(*this == o);
	}

	bool
	booltest() const ILIAS_NET2_NOTHROW
	{
		return this->get();
	}

	pointer
	get() const ILIAS_NET2_NOTHROW
	{
		return this->m_ptr;
	}

	pointer
	release() ILIAS_NET2_NOTHROW
	{
		const pointer rv = this->m_ptr;
		this->m_ptr = nullptr;
		return rv;
	}

	reference
	operator*() const ILIAS_NET2_NOTHROW
	{
		return *this->get();
	}

	pointer
	operator->() const ILIAS_NET2_NOTHROW
	{
		return this->get();
	}

	void
	swap(refpointer& o) ILIAS_NET2_NOTHROW
	{
		std::swap(this->m_ptr, o.m_ptr);
	}

	friend void
	swap(refpointer& lhs, refpointer& rhs) ILIAS_NET2_NOTHROW
	{
		lhs.swap(rhs);
	}
};


template<typename U, typename T, typename AcqRel>
refpointer<U, AcqRel>
static_pointer_cast(const refpointer<T, AcqRel>& ptr) ILIAS_NET2_NOTHROW
{
	return refpointer<U, AcqRel>(static_cast<typename refpointer<U, AcqRel>::pointer>(ptr.get()));
}

template<typename U, typename T, typename AcqRel>
refpointer<U, AcqRel>
static_pointer_cast(refpointer<T, AcqRel>&& ptr) ILIAS_NET2_NOTHROW
{
	return refpointer<U, AcqRel>(static_cast<typename refpointer<U, AcqRel>::pointer>(ptr.release()), false);
}


template<typename U, typename T, typename AcqRel>
refpointer<U, AcqRel>
dynamic_pointer_cast(const refpointer<T, AcqRel>& ptr) ILIAS_NET2_NOTHROW
{
	return refpointer<U, AcqRel>(dynamic_cast<typename refpointer<U, AcqRel>::pointer>(ptr.get()));
}


template<typename U, typename T, typename AcqRel>
refpointer<U, AcqRel>
const_pointer_cast(const refpointer<T, AcqRel>& ptr) ILIAS_NET2_NOTHROW
{
	return refpointer<U, AcqRel>(const_cast<typename refpointer<U, AcqRel>::pointer>(ptr.get()));
}

template<typename U, typename T, typename AcqRel>
refpointer<U, AcqRel>
const_pointer_cast(refpointer<T, AcqRel>&& ptr) ILIAS_NET2_NOTHROW
{
	return refpointer<U, AcqRel>(const_cast<typename refpointer<U, AcqRel>::pointer>(ptr.release()), false);
}


template<typename Type, typename AcqRel = default_refcount_mgr<Type> >
struct refpointer_acquire
{
	refpointer<Type, AcqRel>
	operator()(Type* p) const ILIAS_NET2_NOTHROW
	{
		return refpointer<Type, AcqRel>(p, false);
	}
};

template<typename Type, typename AcqRel = default_refcount_mgr<Type> >
struct refpointer_release
{
	Type*
	operator()(refpointer<Type, AcqRel> p) const ILIAS_NET2_NOTHROW
	{
		return p.release();
	}
};


} /* namespace ilias */


#ifdef _MSC_VER
#pragma warning( pop )
#endif


#endif /* ILIAS_NET2_REFCNT_H */
