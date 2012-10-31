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
#ifndef LL_H
#define LL_H

#include <ilias/net2/ilias_net2_export.h>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <iterator>
#include <utility>
#ifdef HAVE_TYPE_TRAITS
#include <type_traits>
#endif


namespace ilias {
namespace ll_detail {


class hook;
class hook_ptr;
class ll_ptr;
class list;

typedef std::pair<hook_ptr, bool> pointer_flag;


/*
 * Type of predecessor and successor pointers.
 */
class ll_ptr
{
public:
	typedef std::uintptr_t internal_type;
	typedef std::atomic<internal_type> impl_type;
	typedef hook_ptr pointer;

private:
	static const internal_type FLAG = 0x2;
	static const internal_type DEREF = 0x1;
	static const internal_type MASK = (FLAG | DEREF);

	mutable impl_type m_value;

	static hook*
	decode_ptr(internal_type v) ILIAS_NET2_NOTHROW
	{
		return reinterpret_cast<hook*>(v & ~MASK);
	}

	static constexpr bool
	decode_flag(internal_type v) ILIAS_NET2_NOTHROW
	{
		return (v & FLAG);
	}

	static RVALUE(pointer_flag) decode(internal_type, bool = true) ILIAS_NET2_NOTHROW;

	static internal_type
	encode(const hook* p, bool f)
	{
		return reinterpret_cast<internal_type>(p) | (f ? FLAG : uintptr_t(0));
	}

	static internal_type encode(const hook_ptr&, bool);

	static internal_type encode(const pointer_flag&) ILIAS_NET2_NOTHROW;

	internal_type
	lock() const ILIAS_NET2_NOTHROW
	{
		internal_type v;
		do {
			v = this->m_value.fetch_or(DEREF, std::memory_order_acquire);
		} while (v & DEREF);
		return v;
	}

	bool
	lock_conditional(const hook* h, bool f) const ILIAS_NET2_NOTHROW
	{
		const internal_type v_clean = encode(h, f);

		internal_type v = v_clean;
		do {
			v &= ~DEREF;
			if (this->m_value.compare_exchange_weak(v, v | DEREF,
			    std::memory_order_acquire, std::memory_order_relaxed))
				return true;
		} while ((v & ~DEREF) == v_clean);
		return false;
	}

	bool
	lock_conditional(const hook* h) const ILIAS_NET2_NOTHROW
	{
		const internal_type v_clean = encode(h, false);

		internal_type v = v_clean;
		do {
			v &= ~DEREF;
			if (this->m_value.compare_exchange_weak(v, v | DEREF,
			    std::memory_order_acquire, std::memory_order_relaxed))
				return true;
		} while ((v & ~MASK) == v_clean);
		return false;
	}

	bool
	lock_conditional(bool f) const ILIAS_NET2_NOTHROW
	{
		internal_type v = (f ? FLAG : 0);
		do {
			v &= ~DEREF;
			if (this->m_value.compare_exchange_weak(v, v | DEREF,
			    std::memory_order_acquire, std::memory_order_relaxed))
				return true;
		} while ((v & FLAG) == (f ? FLAG : 0));
		return false;
	}

	void
	unlock() const ILIAS_NET2_NOTHROW
	{
		const internal_type old = this->m_value.fetch_and(~DEREF, std::memory_order_release);
		assert(old & DEREF);
	}

	internal_type
	unlock_exchange(internal_type nv) ILIAS_NET2_NOTHROW
	{
		assert(!(nv & DEREF));

		const internal_type old = this->m_value.exchange(nv, std::memory_order_release);
		assert(old & DEREF);
		return old;
	}

	bool
	locked() const ILIAS_NET2_NOTHROW
	{
		internal_type v = this->m_value.load(std::memory_order_relaxed);
		return (v & DEREF);
	}

public:
	template<typename LLPtr>
	class deref_lock
	{
	private:
		LLPtr& m_self;
		bool m_locked;

	public:
		deref_lock(LLPtr& self, bool do_lock = true) ILIAS_NET2_NOTHROW :
			m_self(self),
			m_locked(false)
		{
			if (do_lock)
				this->lock();
		}

		~deref_lock() ILIAS_NET2_NOTHROW
		{
			if (this->m_locked)
				this->unlock();
		}

		internal_type
		lock() ILIAS_NET2_NOTHROW
		{
			assert(!this->m_locked);
			const internal_type rv = this->m_self.lock();
			this->m_locked = true;
			return rv;
		}

		bool
		lock_conditional(const hook* h, bool f) ILIAS_NET2_NOTHROW
		{
			assert(!this->m_locked);
			return (this->m_locked = this->m_self.lock_conditional(h, f));
		}

		bool
		lock_conditional(const hook* h) ILIAS_NET2_NOTHROW
		{
			assert(!this->m_locked);
			return (this->m_locked = this->m_self.lock_conditional(h));
		}

		bool
		lock_conditional(bool f) ILIAS_NET2_NOTHROW
		{
			assert(!this->m_locked);
			return (this->m_locked = this->m_self.lock_conditional(f));
		}

		void
		lock_take_ownership() ILIAS_NET2_NOTHROW
		{
			assert(!this->m_locked);
			assert(this->m_self.locked());
			this->m_locked = true;
		}

		void
		unlock() ILIAS_NET2_NOTHROW
		{
			assert(this->m_locked);
			this->m_self.unlock();
			this->m_locked = false;
		}

		RVALUE(pointer_flag) unlock(RVALUE(pointer_flag)) ILIAS_NET2_NOTHROW;
#if HAS_RVALUE_REF
		RVALUE(pointer_flag) unlock(const pointer_flag&) ILIAS_NET2_NOTHROW;
#endif

		bool
		locked() const ILIAS_NET2_NOTHROW
		{
			return this->m_locked;
		}

		LLPtr&
		lockable() const ILIAS_NET2_NOTHROW
		{
			return this->m_self;
		}

#if HAS_DELETED_FN
		deref_lock(const deref_lock&) = delete;
		deref_lock& operator=(const deref_lock&) = delete;
#else
	private:
		deref_lock(const deref_lock&);
		deref_lock& operator=(const deref_lock&);
#endif
	};

	ll_ptr() ILIAS_NET2_NOTHROW :
		m_value(0)
	{
		/* Empty body. */
	}

	ll_ptr(std::nullptr_t) ILIAS_NET2_NOTHROW :
		m_value(0)
	{
		/* Empty body. */
	}

	~ll_ptr() ILIAS_NET2_NOTHROW;

	hook*
	get_ptr() const ILIAS_NET2_NOTHROW
	{
		return decode_ptr(this->m_value.load(std::memory_order_relaxed) & FLAG);
	}

	bool
	is_set() const ILIAS_NET2_NOTHROW
	{
		return (this->m_value.load(std::memory_order_relaxed) != 0);
	}

	RVALUE(pointer_flag)
	get() const ILIAS_NET2_NOTHROW
	{
		deref_lock<const ll_ptr> lck(*this, false);
		return decode(lck.lock());
	}

	bool
	get_flag() const ILIAS_NET2_NOTHROW
	{
		return decode_flag(this->m_value.load(std::memory_order_consume) & FLAG);
	}

	RVALUE(pointer_flag) exchange(RVALUE(hook_ptr)) ILIAS_NET2_NOTHROW;
#if HAS_RVALUE_REF
	RVALUE(pointer_flag) exchange(const hook_ptr&) ILIAS_NET2_NOTHROW;
#endif

	RVALUE(pointer_flag) exchange(RVALUE(hook_ptr), bool) ILIAS_NET2_NOTHROW;
#if HAS_RVALUE_REF
	RVALUE(pointer_flag) exchange(const hook_ptr&, bool) ILIAS_NET2_NOTHROW;
#endif

	RVALUE(pointer_flag) exchange(RVALUE_CREF(pointer_flag)) ILIAS_NET2_NOTHROW;
#if HAS_RVALUE_REF
	RVALUE(pointer_flag) exchange(const pointer_flag&) ILIAS_NET2_NOTHROW;
#endif

private:
	bool cas_internal(pointer_flag&, internal_type, deref_lock<ll_ptr>*) ILIAS_NET2_NOTHROW;

public:
	bool compare_exchange(pointer_flag&, RVALUE(pointer_flag), deref_lock<ll_ptr>* = nullptr) ILIAS_NET2_NOTHROW;
#if HAS_RVALUE_REF
	bool compare_exchange(pointer_flag&, const pointer_flag&, deref_lock<ll_ptr>* = nullptr) ILIAS_NET2_NOTHROW;
#endif

	bool compare_exchange(hook_ptr&, RVALUE(hook_ptr), deref_lock<ll_ptr>* = nullptr) ILIAS_NET2_NOTHROW;
#if HAS_RVALUE_REF
	bool compare_exchange(hook_ptr&, const hook_ptr&, deref_lock<ll_ptr>* = nullptr) ILIAS_NET2_NOTHROW;
#endif

	bool compare_exchange(pointer_flag&, RVALUE(hook_ptr), deref_lock<ll_ptr>* = nullptr) ILIAS_NET2_NOTHROW;
#if HAS_RVALUE_REF
	bool compare_exchange(pointer_flag&f, const hook_ptr&, deref_lock<ll_ptr>* = nullptr) ILIAS_NET2_NOTHROW;
#endif
};


class hook
{
friend class hook_ptr;
friend class list;

private:
	mutable ll_ptr m_pred, m_succ;
	mutable std::atomic<std::size_t> m_refcnt;

public:
	struct HEAD {};
	static constexpr_value HEAD LIST_HEAD = {};

	explicit hook(HEAD) ILIAS_NET2_NOTHROW;

	hook() ILIAS_NET2_NOTHROW :
		m_pred(),
		m_succ(),
		m_refcnt(0)
	{
		/* Empty body. */
	}

#if HAS_DELETED_FN
	hook(const hook&) = delete;
	hook& operator=(const hook&) = delete;
#else
private:
	hook(const hook&);
	hook& operator=(const hook&);
#endif
};


/*
 * Low level pointer to node.
 * Points at the hook, derived pointer is required to cast to actual elements.
 */
class ILIAS_NET2_LOCAL hook_ptr
{
public:
	typedef hook hook_type;

private:
	hook* m_ptr;

public:
	constexpr hook_ptr() ILIAS_NET2_NOTHROW :
		m_ptr(nullptr)
	{
		/* Empty body. */
	}

	constexpr hook_ptr(std::nullptr_t) ILIAS_NET2_NOTHROW :
		m_ptr(nullptr)
	{
		/* Empty body. */
	}

	hook_ptr(const hook_ptr& o) ILIAS_NET2_NOTHROW :
		m_ptr(o.m_ptr)
	{
		if (this->m_ptr)
			this->m_ptr->m_refcnt.fetch_add(1, std::memory_order_acquire);
	}

#if HAS_RVALUE_REF
	hook_ptr(hook_ptr&& o) ILIAS_NET2_NOTHROW :
		m_ptr(o.m_ptr)
	{
		o.m_ptr = nullptr;
	}
#endif

	hook_ptr(hook* p, bool acquire = true) ILIAS_NET2_NOTHROW :
		m_ptr(p)
	{
		if (this->m_ptr && acquire)
			this->m_ptr->m_refcnt.fetch_add(1, std::memory_order_acquire);
	}

	~hook_ptr() ILIAS_NET2_NOTHROW
	{
		this->reset();
	}

	hook_ptr&
	operator=(std::nullptr_t) ILIAS_NET2_NOTHROW
	{
		if (this->m_ptr) {
			this->m_ptr->m_refcnt.fetch_sub(1, std::memory_order_release);
			this->m_ptr = nullptr;
		}
		return *this;
	}

	hook_ptr&
	operator=(const hook_ptr& o) ILIAS_NET2_NOTHROW
	{
		if (this->m_ptr == o.m_ptr)
			return *this;

		if (this->m_ptr)
			this->m_ptr->m_refcnt.fetch_sub(1, std::memory_order_release);
		this->m_ptr = o.m_ptr;
		if (this->m_ptr)
			this->m_ptr->m_refcnt.fetch_add(1, std::memory_order_acquire);
		return *this;
	}

	hook_ptr&
	operator=(hook_ptr&& o) ILIAS_NET2_NOTHROW
	{
		assert(this != &o);

		if (this->m_ptr)
			this->m_ptr->m_refcnt.fetch_sub(1, std::memory_order_release);
		this->m_ptr = o.m_ptr;
		o.m_ptr = nullptr;
		return *this;
	}

	bool
	operator==(const hook_ptr& o) const ILIAS_NET2_NOTHROW
	{
		return (this->m_ptr == o.m_ptr);
	}

	bool
	operator==(const hook* p) const ILIAS_NET2_NOTHROW
	{
		return (this->m_ptr == p);
	}

	friend bool
	operator==(const hook* p, const hook_ptr& hp) ILIAS_NET2_NOTHROW
	{
		return (hp == p);
	}

	bool
	operator==(std::nullptr_t) const ILIAS_NET2_NOTHROW
	{
		return (this->m_ptr == nullptr);
	}

	template<typename Arg>
	bool
	operator!=(const Arg& o) const ILIAS_NET2_NOTHROW
	{
		return !(*this == o);
	}

	template<typename Arg>
	friend bool
	operator!=(const Arg& o, const hook_ptr& hp) ILIAS_NET2_NOTHROW
	{
		return (hp != o);
	}

	explicit operator bool() const ILIAS_NET2_NOTHROW
	{
		return (this->m_ptr != nullptr);
	}

	void
	reset() ILIAS_NET2_NOTHROW
	{
		*this = nullptr;
	}

	void
	reset(std::nullptr_t) ILIAS_NET2_NOTHROW
	{
		*this = nullptr;
	}

	void
	reset(const hook_ptr& o) ILIAS_NET2_NOTHROW
	{
		*this = o;
	}

#if HAS_RVALUE_REF
	void
	reset(hook_ptr&& o) ILIAS_NET2_NOTHROW
	{
		*this = o;
	}
#endif

	void
	reset(hook_type* p, bool acquire = true) ILIAS_NET2_NOTHROW
	{
		*this = MOVE(hook_ptr(p, acquire));
	}

	hook_type*
	get() const ILIAS_NET2_NOTHROW
	{
		return this->m_ptr;
	}

	hook_type*
	release() ILIAS_NET2_NOTHROW
	{
		hook_type*const rv = this->m_ptr;
		this->m_ptr = nullptr;
		return rv;
	}

	hook_type&
	operator*() const ILIAS_NET2_NOTHROW
	{
		return *this->get();
	}

	hook_type*
	operator->() const ILIAS_NET2_NOTHROW
	{
		return this->get();
	}

	static bool
	deleted(const hook_type& v) ILIAS_NET2_NOTHROW
	{
		return v.m_pred.get_flag();
	}

	bool
	deleted() const ILIAS_NET2_NOTHROW
	{
		return deleted(**this);
	}

	RVALUE(pointer_flag) succ() const ILIAS_NET2_NOTHROW;
	RVALUE(pointer_flag) pred() const ILIAS_NET2_NOTHROW;
	std::size_t succ_end_distance(const hook*) const ILIAS_NET2_NOTHROW;

private:
	bool unlink_nowait() const ILIAS_NET2_NOTHROW;
	void unlink_wait(const hook&) const ILIAS_NET2_NOTHROW;

public:
	bool unlink(const hook&) const ILIAS_NET2_NOTHROW;
	
private:
	bool
	insert_lock() const ILIAS_NET2_NOTHROW
	{
		pointer_flag expect(nullptr, false);
		pointer_flag assign(nullptr, true);
		if (!(*this)->m_succ.compare_exchange(expect, assign))
			return false;

		/* Wait until m_pred is cleared. */
		while ((*this)->m_pred.is_set()) {
			//SPINWAIT();
		}
		return true;
	}

	bool
	insert_between(const hook_ptr& pred, const hook_ptr& succ) const ILIAS_NET2_NOTHROW
	{
		pointer_flag orig_pred = (*this)->m_pred.exchange(pred, false);
		pointer_flag orig_succ = (*this)->m_succ.exchange(succ, false);
		assert(orig_pred.first == nullptr && !orig_pred.second);
		assert(orig_succ.first == nullptr && orig_succ.second);

		/*
		 * Ensure pred will not go away from under us.
		 *
		 * We use a conditional lock, to ensure pred will only lock
		 * if it isn't deleted.
		 */
		ll_ptr::deref_lock<ll_ptr> pred_lck(pred->m_pred, false);
		if (!pred_lck.lock_conditional(false)) {
			(*this)->m_succ.exchange(MOVE(orig_succ));
			(*this)->m_pred.exchange(MOVE(orig_pred));
			return false;
		}

		/* Change successor in pred from succ to this. */
		hook_ptr expect = succ;
		if (!pred->m_succ.compare_exchange(expect, *this)) {
			(*this)->m_succ.exchange(MOVE(orig_succ));
			(*this)->m_pred.exchange(MOVE(orig_pred));
			return false;
		}

		/* We are linked, unlock predecessor. */
		pred_lck.unlock();

		/* Fix predessor of succ. */
		succ.pred();

		return true;
	}

public:
	bool
	insert_after(const hook_ptr& pred) const ILIAS_NET2_NOTHROW
	{
		if (!this->insert_lock())
			return false;

		hook_ptr succ;
		do {
			succ = MOVE(pred.succ().first);
		} while (!this->insert_between(pred, succ));

		return true;
	}

	bool
	insert_before(const hook_ptr& succ) const ILIAS_NET2_NOTHROW
	{
		if (!this->insert_lock())
			return false;

		hook_ptr pred;
		do {
			pred = MOVE(succ.pred().first);
		} while (!this->insert_between(pred, succ));

		return true;
	}
};

/* Base list implementation. */
class ILIAS_NET2_EXPORT list
{
public:
	class simple_iterator;

private:
	hook m_head;

public:
	list() ILIAS_NET2_NOTHROW :
		m_head(hook::LIST_HEAD)
	{
		/* Empty body. */
	}

protected:
	/*
	 * This slightly weird initialization is to create a stable interface
	 * regardless of having move semantics.
	 * The stable interface ensures multiple compilers with different features
	 * will operate correct with the interface.
	 */
	simple_iterator& first(simple_iterator&) const ILIAS_NET2_NOTHROW;
	simple_iterator& last(simple_iterator&) const ILIAS_NET2_NOTHROW;
	simple_iterator& listhead(simple_iterator&) const ILIAS_NET2_NOTHROW;
	hook* pop_front() ILIAS_NET2_NOTHROW;
	hook* pop_back() ILIAS_NET2_NOTHROW;
	bool push_back(const hook_ptr& hp) ILIAS_NET2_NOTHROW;
	bool push_front(const hook_ptr& hp) ILIAS_NET2_NOTHROW;
	simple_iterator& iter_to(simple_iterator&, hook&) const ILIAS_NET2_NOTHROW;

public:
	bool
	empty() const ILIAS_NET2_NOTHROW
	{
		return (this->m_head.m_succ.get_ptr() == &this->m_head);
	}

#if HAS_DELETED_FN
	list(const list&) = delete;
	list& operator=(const list&) = delete;
#else
private:
	list(const list&);
	list& operator=(const list&);
#endif
};

class ILIAS_NET2_EXPORT list::simple_iterator
{
friend class list;

public:
	typedef std::ptrdiff_t difference_type;

private:
	hook_ptr listhead;
	hook_ptr element;

public:
	simple_iterator() ILIAS_NET2_NOTHROW :
		listhead(),
		element()
	{
		/* Empty body. */
	}

	simple_iterator(const simple_iterator& o) ILIAS_NET2_NOTHROW :
		listhead(o.listhead),
		element(o.element)
	{
		/* Empty body. */
	}

#if HAS_RVALUE_REF
	simple_iterator(simple_iterator&& o) ILIAS_NET2_NOTHROW :
		listhead(std::move(o.listhead)),
		element(std::move(o.element))
	{
		/* Empty body. */
	}
#endif

private:
	void
	reset(const hook_ptr& listhead, const hook_ptr& element)
	{
		this->listhead = listhead;
		this->element = element;

		if (this->element == this->listhead)
			this->element = nullptr;
	}

	void
	reset(const hook_ptr& listhead)
	{
		this->listhead = listhead;
		this->element = nullptr;
	}

#if HAS_RVALUE_REF
	void
	reset(hook_ptr&& listhead, hook_ptr&& element)
	{
		this->listhead = listhead;
		this->element = element;

		if (this->element == this->listhead)
			this->element = nullptr;
	}

	void
	reset(const hook_ptr& listhead, hook_ptr&& element)
	{
		this->listhead = listhead;
		this->element = element;

		if (this->element == this->listhead)
			this->element = nullptr;
	}

	void
	reset(hook_ptr&& listhead)
	{
		this->listhead = listhead;
		this->element = nullptr;
	}
#endif

public:
	void step_forward() ILIAS_NET2_NOTHROW;
	void step_backward() ILIAS_NET2_NOTHROW;

	const hook_ptr&
	get_internal() const ILIAS_NET2_NOTHROW
	{
		return element;
	}

	simple_iterator&
	operator=(const simple_iterator& o) ILIAS_NET2_NOTHROW
	{
		this->listhead = o.listhead;
		this->element = o.element;
		return *this;
	}
#if HAS_RVALUE_REF
	simple_iterator&
	operator=(simple_iterator&& o) ILIAS_NET2_NOTHROW
	{
		this->listhead = std::move(o.listhead);
		this->element = std::move(o.element);
		return *this;
	}
#endif

	bool
	operator==(const simple_iterator& o) const ILIAS_NET2_NOTHROW
	{
		return (this->listhead == o.listhead && this->element == o.element);
	}

	bool
	operator!=(const simple_iterator& o) const ILIAS_NET2_NOTHROW
	{
		return !(*this == o);
	}

	/*
	 * Attempt to give an indication of distance between two iterators.
	 * Note that this is not an atomic operation, hence the distance is only an indication,
	 * unless the caller ensures no insert/unlink operations will take place.
	 *
	 * The only way to measure distance between two iterators, is to compare their distance to the list head.
	 * Trying to reach one from the other is unreliable, since either can be unlinked during the operation,
	 * causing the operation to fail.
	 */
	friend difference_type
	distance(const simple_iterator& first, const simple_iterator& last) ILIAS_NET2_NOTHROW
	{
		const std::size_t first_dist = (first.element ? first.element.succ_end_distance(first.listhead.get()) : 0);
		const std::size_t last_dist = (last.element ? last.element.succ_end_distance(last.listhead.get()) : 0);

		return difference_type(last_dist) - difference_type(first_dist);
	}

	bool
	unlink(list& lst) const ILIAS_NET2_NOTHROW
	{
		assert(this->listhead == &lst.m_head);
		assert(this->element);
		return this->element.unlink(lst.m_head);
	}
};


inline
hook::hook(HEAD) ILIAS_NET2_NOTHROW :
	m_pred(),
	m_succ(),
	m_refcnt(0)
{
	hook_ptr self(this);
	m_pred.exchange(self);
	m_succ.exchange(self);

	assert(this->m_pred.get_ptr() == this);
	assert(this->m_succ.get_ptr() == this);
	assert(!this->m_pred.get_flag());
	assert(!this->m_succ.get_flag());
	assert(this->m_refcnt.load(std::memory_order_relaxed) == 2);
}

inline RVALUE(pointer_flag)
ll_ptr::decode(ll_ptr::internal_type v, bool acquire) ILIAS_NET2_NOTHROW
{
	hook_ptr p(reinterpret_cast<hook*>(v & ~MASK), acquire);
	return MOVE(pointer_flag(MOVE(p), v & FLAG));
}

inline ll_ptr::internal_type
ll_ptr::encode(const hook_ptr& p, bool f)
{
	return encode(p.get(), f);
}

inline ll_ptr::internal_type
ll_ptr::encode(const pointer_flag& pf) ILIAS_NET2_NOTHROW
{
	return encode(pf.first, pf.second);
}

inline
ll_ptr::~ll_ptr() ILIAS_NET2_NOTHROW
{
	hook_ptr hp_null;
	this->exchange(MOVE(hp_null));
}

inline RVALUE(pointer_flag)
ll_ptr::exchange(RVALUE(hook_ptr) p) ILIAS_NET2_NOTHROW
{
	deref_lock<ll_ptr> lck(*this, false);
	bool f = decode_flag(lck.lock());
	pointer_flag pf(MOVE(p), f);
	return lck.unlock(MOVE(pf));
}
#if HAS_RVALUE_REF
inline RVALUE(pointer_flag)
ll_ptr::exchange(const hook_ptr& p) ILIAS_NET2_NOTHROW
{
	hook_ptr copy = p;
	return this->exchange(std::move(copy));
}
#endif

inline RVALUE(pointer_flag)
ll_ptr::exchange(RVALUE(hook_ptr) p, bool f) ILIAS_NET2_NOTHROW
{
	pointer_flag pf(MOVE(p), f);
	deref_lock<ll_ptr> lck(*this);
	return lck.unlock(MOVE(pf));
}
#if HAS_RVALUE_REF
inline RVALUE(pointer_flag)
ll_ptr::exchange(const hook_ptr& p, bool f) ILIAS_NET2_NOTHROW
{
	hook_ptr copy = p;
	return this->exchange(std::move(copy), f);
}
#endif

inline RVALUE(pointer_flag)
ll_ptr::exchange(RVALUE_CREF(pointer_flag) pf) ILIAS_NET2_NOTHROW
{
	return this->exchange(MOVE(pf.first), pf.second);
}
#if HAS_RVALUE_REF
inline RVALUE(pointer_flag)
ll_ptr::exchange(const pointer_flag& pf) ILIAS_NET2_NOTHROW
{
	return this->exchange(pf.first, pf.second);
}
#endif

template<typename LLPtr>
RVALUE(pointer_flag)
ll_ptr::deref_lock<LLPtr>::unlock(RVALUE(pointer_flag) pf) ILIAS_NET2_NOTHROW
{
	assert(this->m_locked);
	internal_type nv = encode(pf.first.release(), pf.second);
	assert(!(nv & DEREF));

	internal_type old = this->m_self.unlock_exchange(nv);
	this->m_locked = false;
	return decode(old, false);
}
#if HAS_RVALUE_REF
template<typename LLPtr>
RVALUE(pointer_flag)
ll_ptr::deref_lock<LLPtr>::unlock(const pointer_flag& pf) ILIAS_NET2_NOTHROW
{
	pointer_flag copy = pf;
	return this->unlock(std::move(copy));
}
#endif

inline bool
ll_ptr::cas_internal(pointer_flag& o_pf, ll_ptr::internal_type n, ll_ptr::deref_lock<ll_ptr>* opt_lck) ILIAS_NET2_NOTHROW
{
	assert(opt_lck == nullptr || !opt_lck->locked());
	assert(opt_lck == nullptr || &opt_lck->lockable() == this);
	assert(!(n & DEREF));

	const std::memory_order succes = (opt_lck ? std::memory_order_acquire : std::memory_order_acq_rel);
	const internal_type o_expect = encode(o_pf);
	internal_type o = o_expect;
	if (opt_lck)
		n |= DEREF;

	do {
		if (this->m_value.compare_exchange_weak(o, n, succes, std::memory_order_relaxed)) {
			if (opt_lck)
				opt_lck->lock_take_ownership();
			decode(o, false);	/* Release ownership of o. */
			return true;
		}
		o &= ~DEREF;
	} while (o == o_expect);

	o_pf = decode(o);
	return false;
}

inline bool
ll_ptr::compare_exchange(pointer_flag& o_pf, RVALUE(pointer_flag) n_pf, ll_ptr::deref_lock<ll_ptr>* opt_lck) ILIAS_NET2_NOTHROW
{
	const bool rv = cas_internal(o_pf, encode(n_pf), opt_lck);
	if (rv)
		n_pf.first.release();
	return rv;
}
#if HAS_RVALUE_REF
inline bool
ll_ptr::compare_exchange(pointer_flag& o_pf, const pointer_flag& n_pf, ll_ptr::deref_lock<ll_ptr>* opt_lck) ILIAS_NET2_NOTHROW
{
	pointer_flag copy = n_pf;
	return this->compare_exchange(o_pf, std::move(copy), opt_lck);
}
#endif

inline bool
ll_ptr::compare_exchange(hook_ptr& ov, RVALUE(hook_ptr) nv, ll_ptr::deref_lock<ll_ptr>* opt_lck) ILIAS_NET2_NOTHROW
{
	pointer_flag o_pf(ov, false);
	pointer_flag n_pf(nv, false);

	while (!this->compare_exchange(o_pf, n_pf, opt_lck)) {
		if (o_pf.first != ov) {
			ov = MOVE(o_pf.first);
			return false;
		}
		n_pf.second = o_pf.second;
	}
	return true;
}
#if HAS_RVALUE_REF
inline bool
ll_ptr::compare_exchange(hook_ptr& ov, const hook_ptr& nv, ll_ptr::deref_lock<ll_ptr>* opt_lck) ILIAS_NET2_NOTHROW
{
	hook_ptr copy = nv;
	return this->compare_exchange(ov, std::move(copy), opt_lck);
}
#endif

inline bool
ll_ptr::compare_exchange(pointer_flag& o_pf, RVALUE(hook_ptr) nv, ll_ptr::deref_lock<ll_ptr>* opt_lck) ILIAS_NET2_NOTHROW
{
	pointer_flag n_pf(nv, o_pf.second);
	return this->compare_exchange(o_pf, MOVE(n_pf), opt_lck);
}
#if HAS_RVALUE_REF
inline bool
ll_ptr::compare_exchange(pointer_flag& o_pf, const hook_ptr& nv, ll_ptr::deref_lock<ll_ptr>* opt_lck) ILIAS_NET2_NOTHROW
{
	hook_ptr copy = nv;
	return this->compare_exchange(o_pf, std::move(copy), opt_lck);
}
#endif

/*
 * Calculate offset of m_hook member in HookType.
 */
template<typename HookType>
struct hook_offset
{
public:
	static const std::ptrdiff_t offset = reinterpret_cast<std::ptrdiff_t>(&reinterpret_cast<HookType*>(0U)->m_hook);
};
/*
 * Given the m_hook member of HookType, find the address of HookType.
 */
template<typename HookType>
inline HookType*
hook_resolve(hook* h) ILIAS_NET2_NOTHROW
{
	if (h == nullptr)
		return nullptr;
	return reinterpret_cast<HookType*>(reinterpret_cast<uintptr_t>(h) - hook_offset<HookType>::offset);
}
/*
 * Given the m_hook member of HookType, find the address of HookType.
 */
template<typename HookType>
inline const HookType*
hook_resolve(const hook* h) ILIAS_NET2_NOTHROW
{
	if (h == nullptr)
		return nullptr;
	return reinterpret_cast<const HookType*>(reinterpret_cast<uintptr_t>(h) - hook_offset<HookType>::offset);
}


} /* namespace ilias::ll_detail */


class ll_member_hook;
template<typename Tag = void> class ll_base_hook;
template<typename Type, ll_member_hook Type::*MemberPtr> class ll_member;
template<typename Type, typename Tag = void> class ll_base;


class ll_member_hook
{
template<typename Type, ll_member_hook Type::*MemberPtr> friend class ll_member;
friend struct ll_detail::hook_offset<ll_member_hook>;

private:
	ll_detail::hook m_hook;

public:
	ll_member_hook() ILIAS_NET2_NOTHROW :
		m_hook()
	{
		/* Empty body. */
	}

	ll_member_hook(const ll_member_hook&) ILIAS_NET2_NOTHROW :
		m_hook()
	{
		/* Empty body. */
	}

	ll_member_hook&
	operator=(const ll_member_hook&) ILIAS_NET2_NOTHROW
	{
		return *this;
	}
};

template<typename Tag>
class ll_base_hook
{
template<typename Type, typename TTag> friend class ll_base;
friend struct ll_detail::hook_offset<ll_base_hook<Tag> >;

private:
	ll_detail::hook m_hook;

public:
	ll_base_hook() ILIAS_NET2_NOTHROW :
		m_hook()
	{
		/* Empty body. */
	}

	ll_base_hook(const ll_base_hook&) ILIAS_NET2_NOTHROW :
		m_hook()
	{
		/* Empty body. */
	}

	ll_base_hook&
	operator=(const ll_base_hook&) ILIAS_NET2_NOTHROW
	{
		return *this;
	}
};

template<typename Type, ll_member_hook Type::*MemberPtr>
class ll_member
{
private:
	typedef ll_member_hook hook_type;

public:
	typedef Type value_type;
	typedef value_type* pointer;
	typedef const value_type* const_pointer;
	typedef value_type& reference;
	typedef const value_type& const_reference;

private:
	static const std::ptrdiff_t offset = reinterpret_cast<std::ptrdiff_t>(&(reinterpret_cast<pointer>(0U)->*MemberPtr));

public:
	static ll_detail::hook*
	hook(pointer p) ILIAS_NET2_NOTHROW
	{
		return (p ? &(p->*MemberPtr).m_hook : nullptr);
	}

	static const ll_detail::hook*
	hook(const_pointer p) ILIAS_NET2_NOTHROW
	{
		return (p ? &(p->*MemberPtr).m_hook : nullptr);
	}

	static pointer
	node(ll_detail::hook *h) ILIAS_NET2_NOTHROW
	{
		hook_type* mh = ll_detail::hook_resolve<hook_type>(h);
		return (mh ? reinterpret_cast<pointer>(reinterpret_cast<std::uintptr_t>(mh) - offset) : nullptr);
	}

	static const_pointer
	node(const ll_detail::hook* h) ILIAS_NET2_NOTHROW
	{
		const hook_type* mh = ll_detail::hook_resolve<hook_type>(h);
		return (mh ? reinterpret_cast<const_pointer>(reinterpret_cast<std::uintptr_t>(mh) - offset) : nullptr);
	}
};

template<typename Type, typename Tag>
class ll_base
{
private:
	typedef ll_base_hook<Tag> hook_type;

public:
	typedef Type value_type;
	typedef value_type* pointer;
	typedef const value_type* const_pointer;
	typedef value_type& reference;
	typedef const value_type& const_reference;

	static ll_detail::hook*
	hook(pointer p) ILIAS_NET2_NOTHROW
	{
		return &p->hook_type::m_hook;
	}

	static const ll_detail::hook*
	hook(const_pointer p) ILIAS_NET2_NOTHROW
	{
		return &p->hook_type::m_hook;
	}

	static pointer
	node(ll_detail::hook* h) ILIAS_NET2_NOTHROW
	{
		return (h ? static_cast<pointer>(ll_detail::hook_resolve<hook_type>(h)) : nullptr);
	}

	static const_pointer
	node(const ll_detail::hook* h) ILIAS_NET2_NOTHROW
	{
		return (h ? static_cast<const_pointer>(ll_detail::hook_resolve<hook_type>(h)) : nullptr);
	}
};

template<typename Defn>
class ll_list :
	public ll_detail::list
{
private:
	typedef Defn definition_type;

public:
	typedef typename definition_type::value_type value_type;
	typedef typename definition_type::reference reference;
	typedef typename definition_type::const_reference const_reference;
	typedef typename definition_type::pointer pointer;
	typedef typename definition_type::const_pointer const_pointer;

	/* Iterator types. */
	class iterator;
	class const_iterator;
	class reverse_iterator;
	class const_reverse_iterator;

private:
	/* Aspects of iterators, combined to create actual iterators. */
	template<typename Type, typename Derived> class iterator_resolver;
	template<typename Derived> class iterator_forward_traverse;
	template<typename Derived> class iterator_backward_traverse;

public:
	constexpr ll_list() ILIAS_NET2_NOTHROW { /* Empty body. */ }

	pointer
	pop_front()
	{
		return definition_type::node(this->list::pop_front());
	}

	pointer
	pop_back()
	{
		return definition_type::node(this->list::pop_back());
	}

	RVALUE(iterator)
	begin() ILIAS_NET2_NOTHROW
	{
		iterator rv;
		this->ll_detail::list::first(rv);
		return MOVE(rv);
	}

	RVALUE(iterator)
	end() ILIAS_NET2_NOTHROW
	{
		iterator rv;
		this->ll_detail::list::listhead(rv);
		return MOVE(rv);
	}

	RVALUE(const_iterator)
	begin() const ILIAS_NET2_NOTHROW
	{
		const_iterator rv;
		this->ll_detail::list::first(rv);
		return MOVE(rv);
	}

	RVALUE(const_iterator)
	end() const ILIAS_NET2_NOTHROW
	{
		const_iterator rv;
		this->ll_detail::list::listhead(rv);
		return MOVE(rv);
	}

	RVALUE(reverse_iterator)
	rbegin() ILIAS_NET2_NOTHROW
	{
		reverse_iterator rv;
		this->ll_detail::list::last(rv);
		return MOVE(rv);
	}

	RVALUE(reverse_iterator)
	rend() ILIAS_NET2_NOTHROW
	{
		reverse_iterator rv;
		this->ll_detail::list::listhead(rv);
		return MOVE(rv);
	}

	RVALUE(const_reverse_iterator)
	rbegin() const ILIAS_NET2_NOTHROW
	{
		const_reverse_iterator rv;
		this->ll_detail::list::last(rv);
		return MOVE(rv);
	}

	RVALUE(const_reverse_iterator)
	rend() const ILIAS_NET2_NOTHROW
	{
		const_reverse_iterator rv;
		this->ll_detail::list::listhead(rv);
		return MOVE(rv);
	}

	bool
	erase_element(const iterator& i) ILIAS_NET2_NOTHROW
	{
		return i.simple_iterator::unlink(*this);
	}

	bool
	erase_element(const reverse_iterator& i) ILIAS_NET2_NOTHROW
	{
		return i.simple_iterator::unlink(*this);
	}

	RVALUE(iterator)
	erase(const iterator& i) ILIAS_NET2_NOTHROW
	{
		this->erase_element(i);
		iterator rv = i;
		++rv;
		return MOVE(rv);
	}

	RVALUE(iterator)
	erase(const reverse_iterator& i) ILIAS_NET2_NOTHROW
	{
		this->erase_element(i);
		iterator rv = i;
		++rv;
		return MOVE(rv);
	}

	template<typename Dispose>
	RVALUE(iterator)
	erase_and_dispose(const iterator& i, Dispose dispose)
		/* XXX needs noexcept specification. */
	{
		pointer disposable = nullptr;
		if (this->erase_element(i))
			disposable = i.get();
		iterator rv = i++;
		if (disposable) {
			i = iterator();
			dispose(disposable);
		}
		return MOVE(rv);
	}

	template<typename Dispose>
	RVALUE(reverse_iterator)
	erase_and_dispose(const reverse_iterator& i, Dispose dispose)
		/* XXX needs noexcept specification. */
	{
		pointer disposable = nullptr;
		if (this->erase_element(i))
			disposable = i.get();
		reverse_iterator rv = i++;
		if (disposable) {
			i = reverse_iterator();
			dispose(disposable);
		}
		return MOVE(rv);
	}

	bool
	push_back_element(value_type* v) ILIAS_NET2_NOTHROW
	{
		return this->list::push_back(ll_detail::hook_ptr(definition_type::hook(v)));
	}

	bool
	push_front_element(value_type* v) ILIAS_NET2_NOTHROW
	{
		return this->list::push_front(ll_detail::hook_ptr(definition_type::hook(v)));
	}

	bool
	push_back(reference v) ILIAS_NET2_NOTHROW
	{
		return this->push_back_element(&v);
	}

	bool
	push_front(reference v) ILIAS_NET2_NOTHROW
	{
		return this->push_front_element(&v);
	}

	void
	remove(const value_type& v) ILIAS_NET2_NOTHROW
	{
		const iterator e = this->end();
		for (iterator i = this->begin(); i != e; ++i) {
			if (*i == v)
				this->erase_element(i);
		}
	}

	template<typename Disposer>
	void
	remove_and_dispose(const value_type& v, Disposer disposer)
		/* XXX needs dynamic exception specification. */
	{
		const iterator e = this->end();
		iterator i = this->begin();
		while (i != e) {
			value_type* to_dispose = nullptr;
			if (*i == v && this->erase_element(i))
				to_dispose = i.get();
			/* Note that we move iterator out of disposed element prior to dispose operation. */
			++i;
			if (to_dispose)
				disposer(to_dispose);
		}
	}

	template<typename Predicate>
	void
	remove_if(Predicate p)
		/* XXX needs dynamic exception specification. */
	{
		const iterator e = this->end();
		for (iterator i = this->begin(); i != e; ++i) {
			if (p(*i))
				this->erase_element(i);
		}
	}

	template<typename Predicate, typename Disposer>
	void
	remove_and_dispose_if(Predicate p, Disposer disposer)
		/* XXX needs dynamic exception specification. */
	{
		const iterator e = this->end();
		iterator i = this->begin();
		while (i != e) {
			value_type* to_dispose = nullptr;
			if (p(*i) && this->erase_element(i))
				to_dispose = i.get();
			/* Note that we move iterator out of disposed element prior to dispose operation. */
			++i;
			if (to_dispose)
				disposer(to_dispose);
		}
	}

	RVALUE(iterator)
	iterator_to(reference v) ILIAS_NET2_NOTHROW
	{
		iterator iter;
		this->list::iter_to(iter, v);
		return MOVE(iter);
	}

	RVALUE(const_iterator)
	iterator_to(const_reference v) ILIAS_NET2_NOTHROW
	{
		const_iterator iter;
		this->list::iter_to(iter, v);
		return MOVE(iter);
	}

	void
	clear() ILIAS_NET2_NOTHROW
	{
		while (this->pop_front());
	}

	template<typename Disposer>
	void
	clear_and_dispose(Disposer dispose)
		/* XXX needs exception specification. */
	{
		pointer p;
		while ((p = this->pop_front()))
			dispose(*p);
	}
};

template<typename Defn>
template<typename Type, typename Derived>
class ll_list<Defn>::iterator_resolver
{
public:
	typedef Type value_type;
	typedef value_type* pointer;
	typedef value_type& reference;

protected:
	iterator_resolver() ILIAS_NET2_NOTHROW
	{
		return;
	}

	iterator_resolver(const iterator_resolver&) ILIAS_NET2_NOTHROW
	{
		return;
	}

	~iterator_resolver() ILIAS_NET2_NOTHROW
	{
		return;
	}

public:
	pointer
	get() const ILIAS_NET2_NOTHROW
	{
		const Derived& self = static_cast<const Derived&>(*this);
		return Defn::node(self.simple_iterator::get_internal().get());
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

	bool
	operator==(const ll_list<Defn>::iterator& o) const ILIAS_NET2_NOTHROW
	{
		const simple_iterator& self = static_cast<const Derived&>(*this);
		return self == o;
	}

	bool
	operator==(const ll_list<Defn>::const_iterator& o) const ILIAS_NET2_NOTHROW
	{
		const simple_iterator& self = static_cast<const Derived&>(*this);
		return self == o;
	}

	bool
	operator==(const ll_list<Defn>::reverse_iterator& o) const ILIAS_NET2_NOTHROW
	{
		const simple_iterator& self = static_cast<const Derived&>(*this);
		return self == o;
	}

	bool
	operator==(const ll_list<Defn>::const_reverse_iterator& o) const ILIAS_NET2_NOTHROW
	{
		const simple_iterator& self = static_cast<const Derived&>(*this);
		return self == o;
	}

	template<typename Iter>
	bool
	operator!=(const Iter& o) const ILIAS_NET2_NOTHROW
	{
		return !(*this == o);
	}
};

template<typename Defn>
template<typename Derived>
class ll_list<Defn>::iterator_forward_traverse
{
public:
	typedef std::ptrdiff_t difference_type;
	typedef std::bidirectional_iterator_tag iterator_category;

protected:
	iterator_forward_traverse() ILIAS_NET2_NOTHROW
	{
		return;
	}

	iterator_forward_traverse(const iterator_forward_traverse&) ILIAS_NET2_NOTHROW
	{
		return;
	}

	~iterator_forward_traverse() ILIAS_NET2_NOTHROW
	{
		return;
	}

public:
	Derived&
	operator++() ILIAS_NET2_NOTHROW
	{
		Derived& self = static_cast<Derived&>(*this);
		self.simple_iterator::step_forward();
		return self;
	}

	RVALUE(Derived)
	operator++(int) ILIAS_NET2_NOTHROW
	{
		Derived copy = static_cast<Derived&>(*this);
		++copy;
		return MOVE(copy);
	}

	Derived&
	operator--() ILIAS_NET2_NOTHROW
	{
		Derived& self = static_cast<Derived&>(*this);
		self.simple_iterator::step_backward();
		return self;
	}

	RVALUE(Derived)
	operator--(int) ILIAS_NET2_NOTHROW
	{
		Derived copy = static_cast<Derived&>(*this);
		--copy;
		return MOVE(copy);
	}
};

template<typename Defn>
template<typename Derived>
class ll_list<Defn>::iterator_backward_traverse
{
public:
	typedef std::ptrdiff_t difference_type;
	typedef std::bidirectional_iterator_tag iterator_category;

protected:
	iterator_backward_traverse() ILIAS_NET2_NOTHROW
	{
		return;
	}

	iterator_backward_traverse(const iterator_backward_traverse&) ILIAS_NET2_NOTHROW
	{
		return;
	}

	~iterator_backward_traverse() ILIAS_NET2_NOTHROW
	{
		return;
	}

public:
	Derived&
	operator--() ILIAS_NET2_NOTHROW
	{
		Derived& self = static_cast<Derived&>(*this);
		self.simple_iterator::step_forward();
		return self;
	}

	RVALUE(Derived)
	operator--(int) ILIAS_NET2_NOTHROW
	{
		Derived copy = static_cast<Derived&>(*this);
		--copy;
		return MOVE(copy);
	}

	Derived&
	operator++() ILIAS_NET2_NOTHROW
	{
		Derived& self = static_cast<Derived&>(*this);
		self.simple_iterator::step_backward();
		return self;
	}

	RVALUE(Derived)
	operator++(int) ILIAS_NET2_NOTHROW
	{
		Derived copy = static_cast<Derived&>(*this);
		++copy;
		return MOVE(copy);
	}
};

template<typename Defn>
class ll_list<Defn>::iterator :
	protected simple_iterator,
	public iterator_resolver<value_type, iterator>,
	public iterator_forward_traverse<iterator>
{
friend class ll_list<Defn>;

public:
	using simple_iterator::difference_type;

	iterator() ILIAS_NET2_NOTHROW :
		simple_iterator()
	{
		/* Empty body. */
	}

	iterator(const iterator& i) ILIAS_NET2_NOTHROW :
		simple_iterator(i)
	{
		/* Empty body. */
	}

	iterator(const reverse_iterator& i) ILIAS_NET2_NOTHROW :
		simple_iterator(i)
	{
		/* Empty body. */
	}

#ifdef HAS_RVALUE_REF
	iterator(iterator&& i) ILIAS_NET2_NOTHROW :
		simple_iterator(i)
	{
		/* Empty body. */
	}

	iterator(reverse_iterator&& i) ILIAS_NET2_NOTHROW :
		simple_iterator(i)
	{
		/* Empty body. */
	}
#endif

	iterator&
	operator=(const iterator& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}

	iterator&
	operator=(const reverse_iterator& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}

#if HAS_RVALUE_REF
	iterator&
	operator=(iterator&& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}

	iterator&
	operator=(reverse_iterator&& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}
#endif
};

template<typename Defn>
class ll_list<Defn>::reverse_iterator :
	protected simple_iterator,
	public iterator_resolver<value_type, reverse_iterator>,
	public iterator_backward_traverse<reverse_iterator>
{
friend class ll_list<Defn>;

public:
	using simple_iterator::difference_type;

	reverse_iterator() ILIAS_NET2_NOTHROW :
		simple_iterator()
	{
		/* Empty body. */
	}

	reverse_iterator(const iterator& i) ILIAS_NET2_NOTHROW :
		simple_iterator(i)
	{
		/* Empty body. */
	}

	reverse_iterator(const reverse_iterator& i) ILIAS_NET2_NOTHROW :
		simple_iterator(i)
	{
		/* Empty body. */
	}

#ifdef HAS_RVALUE_REF
	reverse_iterator(iterator&& i) ILIAS_NET2_NOTHROW :
		simple_iterator(i)
	{
		/* Empty body. */
	}

	reverse_iterator(reverse_iterator&& i) ILIAS_NET2_NOTHROW :
		simple_iterator(i)
	{
		/* Empty body. */
	}
#endif

	RVALUE(iterator)
	base() const ILIAS_NET2_NOTHROW
	{
		return MOVE(iterator(*this));
	}

	reverse_iterator&
	operator=(const iterator& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}

	reverse_iterator&
	operator=(const reverse_iterator& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}

#if HAS_RVALUE_REF
	reverse_iterator&
	operator=(iterator&& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}

	reverse_iterator&
	operator=(reverse_iterator&& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}
#endif
};

template<typename Defn>
class ll_list<Defn>::const_iterator :
	protected simple_iterator,
	public iterator_resolver<const value_type, const_iterator>,
	public iterator_forward_traverse<const_iterator>
{
friend class ll_list<Defn>;

public:
	using simple_iterator::difference_type;

	const_iterator() ILIAS_NET2_NOTHROW :
		simple_iterator()
	{
		/* Empty body. */
	}

	const_iterator(const const_iterator& i) ILIAS_NET2_NOTHROW :
		simple_iterator(i)
	{
		/* Empty body. */
	}

	const_iterator(const const_reverse_iterator& i) ILIAS_NET2_NOTHROW :
		simple_iterator(i)
	{
		/* Empty body. */
	}

#ifdef HAS_RVALUE_REF
	const_iterator(const_iterator&& i) ILIAS_NET2_NOTHROW :
		simple_iterator(i)
	{
		/* Empty body. */
	}

	const_iterator(const_reverse_iterator&& i) ILIAS_NET2_NOTHROW :
		simple_iterator(i)
	{
		/* Empty body. */
	}
#endif

	const_iterator&
	operator=(const iterator& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}

	const_iterator&
	operator=(const reverse_iterator& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}

#if HAS_RVALUE_REF
	const_iterator&
	operator=(iterator&& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}

	const_iterator&
	operator=(reverse_iterator&& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}
#endif

	const_iterator&
	operator=(const const_iterator& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}

	const_iterator&
	operator=(const const_reverse_iterator& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}

#if HAS_RVALUE_REF
	const_iterator&
	operator=(const_iterator&& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}

	const_iterator&
	operator=(const_reverse_iterator&& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}
#endif
};

template<typename Defn>
class ll_list<Defn>::const_reverse_iterator :
	protected simple_iterator,
	public iterator_resolver<const value_type, const_reverse_iterator>,
	public iterator_backward_traverse<const_reverse_iterator>
{
friend class ll_list<Defn>;

public:
	using simple_iterator::difference_type;

	const_reverse_iterator() ILIAS_NET2_NOTHROW :
		simple_iterator()
	{
		/* Empty body. */
	}

	const_reverse_iterator(const const_iterator& i) ILIAS_NET2_NOTHROW :
		simple_iterator(i)
	{
		/* Empty body. */
	}

	const_reverse_iterator(const const_reverse_iterator& i) ILIAS_NET2_NOTHROW :
		simple_iterator(i)
	{
		/* Empty body. */
	}

#ifdef HAS_RVALUE_REF
	const_reverse_iterator(const_iterator&& i) ILIAS_NET2_NOTHROW :
		simple_iterator(i)
	{
		/* Empty body. */
	}

	const_reverse_iterator(const_reverse_iterator&& i) ILIAS_NET2_NOTHROW :
		simple_iterator(i)
	{
		/* Empty body. */
	}
#endif

	RVALUE(const_iterator)
	base() const ILIAS_NET2_NOTHROW
	{
		return MOVE(const_iterator(*this));
	}

	const_reverse_iterator&
	operator=(const iterator& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}

	const_reverse_iterator&
	operator=(const reverse_iterator& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}

#if HAS_RVALUE_REF
	const_reverse_iterator&
	operator=(iterator&& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}

	const_reverse_iterator&
	operator=(reverse_iterator&& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}
#endif

	const_reverse_iterator&
	operator=(const const_iterator& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}

	const_reverse_iterator&
	operator=(const const_reverse_iterator& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}

#if HAS_RVALUE_REF
	const_reverse_iterator&
	operator=(const_iterator&& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}

	const_reverse_iterator&
	operator=(const_reverse_iterator&& i) ILIAS_NET2_NOTHROW
	{
		this->simple_iterator::operator=(i);
		return *this;
	}
#endif
};


}


#endif /* LL_H */
