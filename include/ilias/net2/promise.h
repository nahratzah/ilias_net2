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
#include <ilias/net2/workq.h>
#include <atomic>
#include <cassert>
#include <utility>
#include <memory>
#include <vector>
#include <mutex>
#include <stdexcept>
#include <exception>
#include <type_traits>

#include <thread>


#ifdef _MSC_VER
#pragma warning( push )
#pragma warning( once: 4275 )
#pragma warning( disable: 4251 )
#pragma warning( disable: 4290 )
#endif


namespace ilias {


class basic_promise;
class basic_future;
template<typename Result> class promise;
template<typename Result> class future;


class broken_promise :
	public std::runtime_error
{
public:
	ILIAS_NET2_EXPORT broken_promise();
	ILIAS_NET2_EXPORT virtual ~broken_promise() ILIAS_NET2_NOTHROW;
};

class uninitialized_promise :
	public std::logic_error
{
public:
	/* Throw this exception. */
	ILIAS_NET2_EXPORT static void throw_me();

	ILIAS_NET2_EXPORT uninitialized_promise();
	ILIAS_NET2_EXPORT virtual ~uninitialized_promise() ILIAS_NET2_NOTHROW;
};


/* Type-agnostic base of promise. */
class ILIAS_NET2_EXPORT basic_promise
{
friend class basic_future;

protected:
	class basic_state;

private:
	struct ILIAS_NET2_LOCAL mark_unreferenced
	{
		void operator() (const basic_state*) const ILIAS_NET2_NOTHROW;

		void acquire(const basic_state&) const ILIAS_NET2_NOTHROW;
		void release(const basic_state&) const ILIAS_NET2_NOTHROW;
		ILIAS_NET2_EXPORT void unreferenced(basic_state&) const ILIAS_NET2_NOTHROW;
	};

protected:
	class ILIAS_NET2_EXPORT basic_state :
		public refcount_base<basic_state>
	{
	friend struct basic_promise::mark_unreferenced;

	private:
		/*
		 * ready_state_t is actually an enum, but it seems at least
		 * clang-3.1 doesn't generate atomic instructions for
		 * std::atomic<ready_state_t> (it calls an external function
		 * instead).
		 *
		 * To help the compiler a bit, we use an int instead.
		 *
		 * enum ready_state_t {
		 *	NIL,
		 *	ASSIGNING,
		 *	DONE
		 * };
		 */

		typedef int ready_state_t;
		static const ready_state_t NIL = 17;
		static const ready_state_t ASSIGNING = 19;
		static const ready_state_t DONE = 23;

		std::exception_ptr m_except;
		std::atomic<ready_state_t> m_ready;
		mutable std::atomic<unsigned int> m_prom_refcnt;
		std::atomic<bool> m_start;	/* Set if the promise needs to start. */

	protected:
		class ILIAS_NET2_LOCAL state_lock :
			public bool_test<state_lock>
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

				this->self.on_assign();
			}

			bool
			booltest() const ILIAS_NET2_NOTHROW
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

		basic_state() ILIAS_NET2_NOTHROW;

	public:
		virtual ~basic_state() ILIAS_NET2_NOTHROW;

	protected:
		virtual void on_assign() ILIAS_NET2_NOTHROW;
		virtual bool has_lazy() const ILIAS_NET2_NOTHROW;

	public:
		virtual bool start(bool wait) ILIAS_NET2_NOTHROW;

		bool
		is_started() const ILIAS_NET2_NOTHROW
		{
			return this->m_start.load(std::memory_order_relaxed);
		}

		bool
		ready() const ILIAS_NET2_NOTHROW
		{
			return (m_ready.load(std::memory_order_acquire) == DONE);
		}

		void
		wait_ready() const ILIAS_NET2_NOTHROW
		{
			while (!this->ready())
				std::this_thread::yield();
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

#if HAS_VARARG_TEMPLATES
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
#endif


#if HAS_DELETED_FN
		basic_state(const basic_state&) = delete;
		basic_state& operator=(const basic_state&) = delete;
#else
	private:
		basic_state(const basic_state&);
		basic_state& operator=(const basic_state&);
#endif
	};

	typedef ilias::refpointer<basic_state, mark_unreferenced> state_ptr_type;

private:
	state_ptr_type m_state;

protected:
	basic_promise() ILIAS_NET2_NOTHROW :
		m_state()
	{
		/* Empty body. */
	}

	basic_promise(const basic_promise& p) ILIAS_NET2_NOTHROW :
		m_state(p.m_state)
	{
		/* Empty body. */
	}

	basic_promise(basic_promise&& p) ILIAS_NET2_NOTHROW :
		m_state(std::move(p.m_state))
	{
		/* Empty body. */
	}

	explicit basic_promise(state_ptr_type&& state_ptr) ILIAS_NET2_NOTHROW :
		m_state(std::move(state_ptr))
	{
		/* Empty body. */
	}

	explicit basic_promise(const state_ptr_type& state_ptr) ILIAS_NET2_NOTHROW :
		m_state(state_ptr)
	{
		/* Empty body. */
	}

	~basic_promise() ILIAS_NET2_NOTHROW;

	basic_promise&
	operator=(const basic_promise& p) ILIAS_NET2_NOTHROW
	{
		this->m_state = p.m_state;
		return *this;
	}

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
	start() ILIAS_NET2_NOTHROW
	{
		basic_state*const s = this->get_state();
		if (!s)
			uninitialized_promise::throw_me();

		return s->start(false);
	}

	bool
	valid() const ILIAS_NET2_NOTHROW
	{
		return (this->get_state() != nullptr);
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

#if HAS_VARARG_TEMPLATES
	template<typename... Args>
	bool
	emplace_exception(Args&&... args)
	{
		basic_state*const s = this->get_state();
		if (!s)
			uninitialized_promise::throw_me();

		return s->emplace_exception(std::move(args)...);
	}
#endif
};

/* Promise refcount acquire method. */
inline void
basic_promise::mark_unreferenced::acquire(const basic_state& s) const ILIAS_NET2_NOTHROW
{
	if (s.m_prom_refcnt.fetch_add(1, std::memory_order_acquire) == 0)
		refcnt_acquire(s);
}

/* Promise refcount release method: once no promises refer to the shared state, the shared state is marked unreferenced. */
inline void
basic_promise::mark_unreferenced::release(const basic_state& s) const ILIAS_NET2_NOTHROW
{
	const auto old = s.m_prom_refcnt.fetch_sub(1, std::memory_order_release);
	assert(old > 0);
	if (old == 1 && s.has_lazy())
		this->unreferenced(const_cast<basic_state&>(s));
}

class ILIAS_NET2_EXPORT basic_future
{
protected:
	typedef basic_promise::basic_state basic_state;

private:
	refpointer<basic_state> m_state;

protected:
	/* Constructor with initial state. */
	basic_future(refpointer<basic_state> s) ILIAS_NET2_NOTHROW :
		m_state(std::move(s))
	{
		/* Empty body. */
	}

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

	basic_future&
	operator=(const basic_future& o) ILIAS_NET2_NOTHROW
	{
		this->m_state = o.m_state;
		return *this;
	}

#if HAS_RVALUE_REF
	basic_future&
	operator=(basic_future&& o) ILIAS_NET2_NOTHROW
	{
		this->m_state = std::move(o.m_state);
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
	start() ILIAS_NET2_NOTHROW
	{
		basic_state*const s = this->get_state();
		if (!s)
			uninitialized_promise::throw_me();

		return s->start(false);
	}

	bool
	valid() const ILIAS_NET2_NOTHROW
	{
		return (this->get_state() != nullptr);
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
	public:
		/* Definition of how functors to initialize the promise should look. */
		typedef typename std::remove_const<result_type>::type initfn_type();
		typedef void callback_type(reference);

	private:
		typedef std::vector<std::function<callback_type> > direct_cb_list;

		/* Using a union to allow late initialization of the value. */
		union container {
			typename std::remove_const<result_type>::type value;

			container()
			{
				/* Nothing. */
			}
		};

		std::atomic<bool> m_value_isset;

		mutable std::mutex m_mtx;	/* Protect callbacks. */
		std::function<initfn_type> m_lazy;
		workq_job_ptr m_lazy_job;
		direct_cb_list m_direct_cb;

		container m_container;

		void
		resolve_lazy(bool wait) ILIAS_NET2_NOTHROW
		{
			if (this->ready())
				return;

			/* Run lazy initializaton. */
			if (this->m_lazy) {
				try {
					this->assign(this->m_lazy());
				} catch (...) {
					this->set_exception(std::current_exception());
				}
			}

			/* Activate the workq job. */
			if (this->m_lazy_job)
				this->m_lazy_job->activate(wait ? workq_job::ACT_IMMED : 0);
		}

	protected:
		virtual void
		on_assign() ILIAS_NET2_NOTHROW OVERRIDE
		{
			assert(this->ready());

			/* Move the list out of the lock. */
			std::unique_lock<std::mutex> lck(this->m_mtx);
			direct_cb_list cbs = m_direct_cb;
			lck.unlock();

			/* Invoke each of the callbacks, iff the promise completed with a value. */
			if (this->has_value()) {
				for (auto cb : cbs)
					cb(this->get_value());
			}
		}

	public:
		state() ILIAS_NET2_NOTHROW :
			basic_state(),
			m_value_isset(false)
		{
			/* Empty body. */
		}

		virtual ~state() ILIAS_NET2_NOTHROW
		{
			if (this->m_value_isset)
				this->m_container.value.~result_type();
		}

		virtual bool
		has_lazy() const ILIAS_NET2_NOTHROW OVERRIDE
		{
			std::lock_guard<std::mutex> lck(this->m_mtx);
			return (this->m_lazy || this->m_lazy_job);
		}

		void
		set_lazy(std::function<initfn_type> fn) throw (std::invalid_argument, std::logic_error)
		{
			if (!fn)
				throw std::invalid_argument("promise: lazy resolution is invalid");

			std::lock_guard<std::mutex> lck(this->m_mtx);
			if (this->m_lazy || this->m_lazy_job)
				throw std::logic_error("promise: lazy resolution set twice");
			this->m_lazy = std::move(fn);

			if (this->is_started())
				this->resolve_lazy(false);
		}

	private:
		struct wq_resolver
		{
			std::function<initfn_type> fn;
			state& s;

			wq_resolver(state& s, std::function<initfn_type> fn) ILIAS_NET2_NOTHROW :
				fn(std::move(fn)),
				s(s)
			{
				/* Empty body. */
			}

			wq_resolver(const wq_resolver& o) :
				fn(o.fn),
				s(o.s)
			{
				/* Empty body. */
			}

			wq_resolver(wq_resolver&& o) ILIAS_NET2_NOTHROW :
				fn(std::move(o.fn)),
				s(o.s)
			{
				/* Empty body. */
			}

			void
			operator()() const ILIAS_NET2_NOTHROW
			{
				try {
					s.assign(fn());
				} catch (...) {
					s.set_exception(std::current_exception());
				}
			}
		};

	public:
		void
		set_lazy(workq_ptr wq, unsigned int type, std::function<initfn_type> fn)
		    throw (std::bad_alloc, std::invalid_argument, std::logic_error)
		{
			if (!fn)
				throw std::invalid_argument("promise: lazy resolution is invalid");

			std::lock_guard<std::mutex> lck(this->m_mtx);
			if (this->m_lazy || this->m_lazy_job)
				throw std::logic_error("promise: lazy resolution set twice");
			this->m_lazy_job = wq->new_job(type | workq_job::TYPE_ONCE, wq_resolver(*this, std::move(fn)));

			if (this->is_started())
				this->resolve_lazy(false);
		}

		void
		add_callback(std::function<callback_type> fn) throw (std::invalid_argument, std::bad_alloc)
		{
			/* Validate functor. */
			if (!fn)
				throw std::invalid_argument("promise: callback is invalid");

			/*
			 * Only push the callback on the list, if the promise is not ready.
			 * Uses the doubly-checked lock pattern.
			 */
			if (!this->ready()) {
				std::unique_lock<std::mutex> lck(this->m_mtx);
				if (!this->ready()) {
					this->m_direct_cb.push_back(std::move(fn));
					return;
				}
			}

			/*
			 * Promise is ready, invoke functor now if it is ready.
			 * Note that the functor is only invoked if a value is present.
			 */
			if (this->has_value())
				fn(this->get_value());
		}

		virtual bool
		start(bool wait) ILIAS_NET2_NOTHROW OVERRIDE
		{
			std::lock_guard<std::mutex> lck(this->m_mtx);
			if (this->basic_state::start(wait)) {
				this->resolve_lazy(wait);
				return true;
			}
			return false;
		}

		bool
		assign(const result_type& v)
		{
			state_lock lck(*this);
			if (!lck)
				return false;

			if (this->m_value_isset)
				return false;

			new (&this->m_container.value) result_type(v);
			this->m_value_isset = true;
			return true;
		}

#if HAS_RVALUE_REF
		bool
		assign(result_type&& v)
		{
			state_lock lck(*this);
			if (!lck)
				return false;

			if (this->m_value_isset)
				return false;

			new (&this->m_container.value) result_type(std::move(v));
			this->m_value_isset = true;
			return true;
		}
#endif

#if HAS_VARARG_TEMPLATES
		template<typename... Args>
		bool
		assign(Args&&... args)
		{
			state_lock lck(*this);
			if (!lck)
				return false;

			if (this->m_value_isset)
				return false;

			new (&this->m_container.value) result_type(std::move(args)...);
			this->m_value_isset = true;
			return true;
		}
#endif

		bool
		has_value() const ILIAS_NET2_NOTHROW
		{
			return this->ready() && this->m_value_isset;
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

public:
	typedef typename state::initfn_type initfn_type;

private:
	state*
	get_state() const ILIAS_NET2_NOTHROW
	{
		basic_state* bs = this->basic_promise::get_state();
		return (bs ? static_cast<state*>(bs) : nullptr);
	}

	static state_ptr_type
	create_state() throw (std::bad_alloc)
	{
		return state_ptr_type(new state());
	}

	promise(state_ptr_type&& s) ILIAS_NET2_NOTHROW :
		basic_promise(std::move(s))
	{
		/* Empty body. */
	}

public:
	static promise
	new_promise() throw (std::bad_alloc)
	{
		return promise(create_state());
	}

	/* Create a new promise. */
	promise() :
		basic_promise(create_state())
	{
		/* Empty body. */
	}

	promise(const promise& p) ILIAS_NET2_NOTHROW :
		basic_promise(p)
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
#endif

	/* Move assignment. */
	promise&
	operator= (const promise& p) ILIAS_NET2_NOTHROW
	{
		this->basic_promise::operator= (p);
		return *this;
	}

#if HAS_RVALUE_REF
	/* Move assignment. */
	promise&
	operator= (promise&& p) ILIAS_NET2_NOTHROW
	{
		this->basic_promise::operator= (std::move(p));
		return *this;
	}
#endif

	/* Set lazy promise resolution. */
	void
	set(std::function<initfn_type> fn) throw (uninitialized_promise, std::invalid_argument, std::logic_error)
	{
		state*const s = this->get_state();
		if (!s)
			uninitialized_promise::throw_me();

		s->set_lazy(fn);
	}

	/* Set the value of the promise, using value_type copy constructor. */
	bool
	set(const result_type& v)
	{
		state*const s = this->get_state();
		if (!s)
			uninitialized_promise::throw_me();

		return s->assign(v);
	}

	/* Set the value of the promise, using value_type move constructor. */
	bool
	set(result_type&& v)
	{
		state*const s = this->get_state();
		if (!s)
			uninitialized_promise::throw_me();

		return s->assign(std::move(v));
	}

#if HAS_VARARG_TEMPLATES
	/* Set the value of the promise, using value_type constructor. */
	template<typename... Args>
	bool
	set(Args&&... args)
	{
		state*const s = this->get_state();
		if (!s)
			uninitialized_promise::throw_me();

		return s->assign(std::move(args)...);
	}
#endif

	template<typename Functor>
	void
	set_lazy(Functor f) throw (uninitialized_promise, std::invalid_argument, std::logic_error)
	{
		state* s = this->get_state();
		if (!s)
			uninitialized_promise::throw_me();
		s->set_lazy(std::move(f));
	}

	template<typename Functor>
	void
	set_lazy(workq_ptr wq, unsigned int type, Functor f) throw (uninitialized_promise, std::invalid_argument, std::logic_error)
	{
		state* s = this->get_state();
		if (!s)
			uninitialized_promise::throw_me();
		s->set_lazy(std::move(wq), type, std::move(f));
	}

	future<typename std::remove_const<result_type>::type>
	get_future() const throw (uninitialized_promise)
	{
		refpointer<state> s = this->get_state();
		if (!s)
			uninitialized_promise::throw_me();
		return future<typename std::remove_const<result_type>::type>(s);
	}
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
	future(refpointer<state> s) ILIAS_NET2_NOTHROW :
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


/* Create a new promise returning the given type. */
template<typename Type>
promise<Type>
new_promise() throw (std::bad_alloc)
{
	return promise<Type>::new_promise();
}

/* Create a future that will resolve when its get() or start() method is called. */
template<typename Functor>
auto
lazy_future(Functor f) throw (std::bad_alloc)
    -> future<typename std::remove_reference<typename std::remove_cv<decltype(f())>::type>::type>
{
	typedef typename std::remove_reference<typename std::remove_cv<decltype(f())>::type>::type result_type;

	auto p = new_promise<result_type>();
	p.set_lazy(std::move(f));
	return p.get_future();
}

template<typename Functor>
auto
lazy_future(workq_ptr wq, unsigned int type, Functor f) throw (std::invalid_argument, std::bad_alloc)
    -> future<typename std::remove_reference<typename std::remove_cv<decltype(f())>::type>::type>
{
	typedef typename std::remove_reference<typename std::remove_cv<decltype(f())>::type>::type result_type;

	auto p = new_promise<result_type>();
	p.set_lazy(std::move(wq), type, std::move(f));
	return p.get_future();
}


} /* namespace ilias */


#ifdef _MSC_VER
#pragma warning( pop )
#endif


#endif /* ILIAS_NET2_PROMISE_H */
