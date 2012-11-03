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
#ifndef ILIAS_NET2_PROMISE_H
#define ILIAS_NET2_PROMISE_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/refcnt.h>
#include <atomic>
#include <cassert>
#include <utility>
#include <memory>
#include <stdexcept>
#include <exception>

#if defined(HAVE_TYPE_TRAITS) && HAS_VARARG_TEMPLATES && HAS_DECLTYPE && HAS_RVALUE_REF
#include <type_traits>	/* For combi promise templates. */
#endif /* HAS_VARARG_TEMPLATES && HAS_DECLTYPE && HAS_RVALUE_REF */

namespace ilias {


class basic_promise;
class basic_future;
template<typename Result> class promise;
template<typename Result> class future;


class ILIAS_NET2_EXPORT broken_promise :
	public std::runtime_error
{
public:
	broken_promise();
	virtual ~broken_promise() ILIAS_NET2_NOTHROW;
};

class ILIAS_NET2_EXPORT uninitialized_promise :
	public std::logic_error
{
public:
	/* Throw this exception. */
	static void throw_me();

	uninitialized_promise();
	virtual ~uninitialized_promise() ILIAS_NET2_NOTHROW;
};


/* Type-agnostic base of promise. */
class ILIAS_NET2_EXPORT basic_promise
{
friend class basic_future;

protected:
	class basic_state;

private:
	struct ILIAS_NET2_EXPORT mark_unreferenced
	{
		void operator() (basic_state*) const ILIAS_NET2_NOTHROW;
	};

protected:
	class ILIAS_NET2_EXPORT basic_state :
		public refcount_base<basic_state>
	{
	private:
		enum ready_state_t {
			NIL,
			ASSIGNING,
			DONE
		};

		std::exception_ptr m_except;
		std::atomic<ready_state_t> m_ready;

	protected:
		class state_lock
		{
		private:
			basic_state& self;
			bool m_locked;

		public:
			state_lock(basic_state& self, bool acquire = true) ILIAS_NET2_NOTHROW :
				self(self),
				m_locked(false)
			{
				if (acquire)
					this->lock();
			}

			~state_lock() ILIAS_NET2_NOTHROW
			{
				if (this->m_locked)
					this->unlock();
			}

			bool
			lock() ILIAS_NET2_NOTHROW
			{
				assert(!this->m_locked);
				ready_state_t expect = NIL;
				while (!this->self.m_ready.compare_exchange_weak(expect, ASSIGNING,
				    std::memory_order_acquire, std::memory_order_relaxed)) {
					if (expect == DONE)
						return false;
					expect = NIL;
				}

				this->m_locked = true;
				return true;
			}

			void
			unlock() ILIAS_NET2_NOTHROW
			{
				assert(this->m_locked);
				ready_state_t old = this->self.m_ready.exchange(NIL, std::memory_order_release);
				assert(old == ASSIGNING);
				this->m_locked = false;
			}

			void
			commit() ILIAS_NET2_NOTHROW
			{
				assert(this->m_locked);
				ready_state_t old = this->self.m_ready.exchange(DONE, std::memory_order_release);
				assert(old == ASSIGNING);
				this->m_locked = false;
			}

			explicit operator bool() const ILIAS_NET2_NOTHROW
			{
				return this->m_locked;
			}


#if HAS_DELETED_FN
			state_lock(const state_lock&) = delete;
			state_lock& operator=(const state_lock&) = delete;
#else
		private:
			state_lock(const state_lock&);
			state_lock& operator=(const state_lock&);
#endif
		};

		basic_state() ILIAS_NET2_NOTHROW :
			m_except(),
			m_ready(NIL)
		{
			/* Empty body. */
		}

	public:
		virtual ~basic_state() ILIAS_NET2_NOTHROW;

		bool
		ready() const ILIAS_NET2_NOTHROW
		{
			return (m_ready.load(std::memory_order_acquire) == DONE);
		}

		void
		wait_ready() const ILIAS_NET2_NOTHROW
		{
			while (!this->ready()) {
				// XXX std::thread::yield();
			}
		}

		bool
		has_exception() const ILIAS_NET2_NOTHROW
		{
			return this->ready() && this->m_except;
		}

		const std::exception_ptr&
		get_exception() const ILIAS_NET2_NOTHROW
		{
			assert(this->ready());
			return this->m_except;
		}

		bool
		set_exception(const std::exception_ptr& p) ILIAS_NET2_NOTHROW
		{
			assert(p);

			state_lock lck(*this);
			if (!lck)
				return false;

			this->m_except = p;
			lck.commit();
			return true;
		}

#if HAS_RVALUE_REF
		bool
		set_exception(std::exception_ptr&& p) ILIAS_NET2_NOTHROW
		{
			assert(p);

			state_lock lck(*this);
			if (!lck)
				return false;

			this->m_except = std::move(p);
			lck.commit();
			return true;
		}
#endif

		template<typename Exception, typename... Args>
		bool
		emplace_exception(Args&&... args)
		{
			state_lock lck(*this);
			if (!lck)
				return false;

			this->m_except = std::make_exception_ptr(std::move(args)...);
			lck.commit();
			return true;
		}


#if HAS_DELETED_FN
		basic_state(const basic_state&) = delete;
		basic_state& operator=(const basic_state&) = delete;
#else
	private:
		basic_state(const basic_state&);
		basic_state& operator=(const basic_state&);
#endif
	};

private:
	typedef std::unique_ptr<basic_state, mark_unreferenced> state_ptr_type;
	state_ptr_type m_state;

protected:
	basic_promise(basic_promise&& p) ILIAS_NET2_NOTHROW :
		m_state(std::move(p.m_state))
	{
		/* Empty body. */
	}

	explicit basic_promise(refpointer<basic_state>& state_ptr) ILIAS_NET2_NOTHROW :
		m_state(state_ptr.release())	/* Decrement of refcount done by deleter. */
	{
		/* Empty body. */
	}

	~basic_promise() ILIAS_NET2_NOTHROW;

#if HAS_RVALUE_REF
	basic_promise&
	operator= (basic_promise&& p) ILIAS_NET2_NOTHROW
	{
		this->m_state = std::move(p.m_state);
		return *this;
	}
#endif

	basic_state*
	get_state() const ILIAS_NET2_NOTHROW
	{
		return this->m_state.get();
	}

public:
	bool
	valid() const ILIAS_NET2_NOTHROW
	{
		return this->get_state();
	}

	bool
	set_exception(const std::exception_ptr& p)
	{
		basic_state*const s = this->get_state();
		if (!s)
			uninitialized_promise::throw_me();

		return s->set_exception(std::move(p));
	}

#if HAS_RVALUE_REF
	bool
	set_exception(std::exception_ptr&& p)
	{
		basic_state*const s = this->get_state();
		if (!s)
			uninitialized_promise::throw_me();

		return s->set_exception(std::move(p));
	}
#endif

	template<typename... Args>
	bool
	emplace_exception(Args&&... args)
	{
		basic_state*const s = this->get_state();
		if (!s)
			uninitialized_promise::throw_me();

		return s->emplace_exception(std::move(args)...);
	}


#if HAS_DELETED_FN
	basic_promise() = delete;
	basic_promise(const basic_promise&) = delete;
	basic_promise& operator=(const basic_promise&) = delete;
#else
private:
	basic_promise();
	basic_promise(const basic_promise&);
	basic_promise& operator=(const basic_promise&);
#endif
};

class ILIAS_NET2_EXPORT basic_future
{
protected:
	typedef basic_promise::basic_state basic_state;

private:
	refpointer<basic_state> m_state;

protected:
	/* Constructor with initial state. */
	basic_future(basic_state* s);

	basic_future() ILIAS_NET2_NOTHROW :
		m_state()
	{
		/* Empty body. */
	}

	basic_future(const basic_future& f) ILIAS_NET2_NOTHROW :
		m_state(f.m_state)
	{
		/* Empty body. */
	}

#if HAS_RVALUE_REF
	basic_future(basic_future&& f) ILIAS_NET2_NOTHROW :
		m_state(std::move(f.m_state))
	{
		/* Empty body. */
	}
#endif

	basic_state*
	get_state() const ILIAS_NET2_NOTHROW
	{
		return this->m_state.get();
	}

public:
	bool
	valid() const ILIAS_NET2_NOTHROW
	{
		return this->get_state();
	}

	bool ready() const ILIAS_NET2_NOTHROW;
	bool has_exception() const ILIAS_NET2_NOTHROW;
};


template<typename Result>
class promise :
	public basic_promise
{
friend class future<Result>;

public:
	typedef const Result result_type;
	typedef result_type& reference;
	typedef result_type* pointer;

private:
	class state :
		public basic_state
	{
	private:
		std::atomic<bool> m_value_isset;

		/* Using a union to allow late initialization of the value. */
		union container {
			result_type value;

			container()
			{
				/* Nothing. */
			}
		};

		container m_container;

	public:
		state() ILIAS_NET2_NOTHROW :
			basic_state(),
			m_value_isset(false)
		{
			/* Empty body. */
		}

		~state() ILIAS_NET2_NOTHROW
		{
			if (this->m_value_isset)
				this->m_container.value.~result_type();
		}

		template<typename... Args>
		bool
		assign(Args&&... args)
		{
			state_lock lck(*this);
			if (!lck)
				return false;

			if (this->m_value_isset)
				return false;

			new (&this->m_container.m_value) result_type(std::move(args)...);
			this->m_value_isset = true;
		}

		bool
		has_value() const ILIAS_NET2_NOTHROW
		{
			return this->ready() && m_value_isset;
		}

		reference
		get_value() const ILIAS_NET2_NOTHROW
		{
			assert(this->has_value());
			return this->m_container.value;
		}


#if HAS_DELETED_FN
		state(const state&) = delete;
		state operator=(const state&) = delete;
#else
	private:
		state(const state&);
		state operator=(const state&);
#endif
	};

	state*
	get_state() const ILIAS_NET2_NOTHROW
	{
		basic_state* bs = this->basic_promise::get_state();
		return (bs ? static_cast<state*>(bs) : nullptr);
	}

	static RVALUE(refpointer<state>)
	create_state() throw (std::bad_alloc)
	{
		refpointer<state> p(new state());
		return MOVE(p);
	}

public:
	/* Create a new promise. */
	promise() :
		basic_promise(create_state())
	{
		/* Empty body. */
	}

#if HAS_RVALUE_REF
	/* Move constructor. */
	promise(promise&& p) ILIAS_NET2_NOTHROW :
		basic_promise(std::move(p))
	{
		/* Empty body. */
	}

	/* Move assignment. */
	promise&
	operator= (promise&& p) ILIAS_NET2_NOTHROW
	{
		this->basic_promise::operator= (std::move(p));
		return *this;
	}
#endif

	/* Set the value of the promise, using value_type constructor. */
	template<typename... Args>
	bool
	set_value(Args&&... args)
	{
		state*const s = this->get_state();
		if (!s)
			uninitialized_promise::throw_me();

		return s->assign(std::move(args)...);
	}

	RVALUE(future<Result>)
	get_future() const
	{
		return future<Result>(this->get_state());
	}


#if HAS_DELETED_FN
	promise(const promise&) = delete;
	promise& operator=(const promise&) = delete;
#else
private:
	promise(const promise&);
	promise& operator=(const promise&);
#endif
};

template<typename Result>
class future :
	public basic_future
{
friend class promise<Result>;

public:
	typedef typename promise<Result>::result_type result_type;
	typedef typename promise<Result>::reference reference;
	typedef typename promise<Result>::pointer pointer;

private:
	typedef typename promise<Result>::state state;

	state*
	get_state() const ILIAS_NET2_NOTHROW
	{
		basic_state* bs = this->basic_future::get_state();
		return (bs ? static_cast<state*>(bs) : nullptr);
	}

	/* Special constructor called by promise<Result>::get_future(). */
	future(state* s) ILIAS_NET2_NOTHROW :
		basic_future(s)
	{
		/* Empty body. */
	}

public:
	future() ILIAS_NET2_NOTHROW :
		basic_future()
	{
		/* Empty body. */
	}

	future(const future& f) ILIAS_NET2_NOTHROW :
		basic_future(f)
	{
		/* Empty body. */
	}

#if HAS_RVALUE_REF
	future(future&& f) ILIAS_NET2_NOTHROW :
		basic_future(f)
	{
		/* Empty body. */
	}
#endif

	reference
	get() const
	{
		state*const s = this->get_state();
		if (!s)
			uninitialized_promise::throw_me();

		s->wait_ready();
		assert(s->ready());
		assert((s->has_exception() ? 1 : 0) + (s->has_value() ? 1 : 0) == 1);

		/* Test for value presence. */
		if (s->has_value())
			return s->get_value();

		/* Test for exception presence. */
		if (s->has_exception()) {
			const std::exception_ptr& e = s->get_exception();
			assert(e);	/* Exception must be set. */
			std::rethrow_exception(e);
		}

		/* UNREACHABLE */
		std::terminate();
	}

	bool
	has_value() const ILIAS_NET2_NOTHROW
	{
		state*const s = this->get_state();
		return (s && s->has_value());
	}
};


} /* namespace ilias */

#endif /* ILIAS_NET2_PROMISE_H */
