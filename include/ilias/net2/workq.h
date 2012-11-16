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
#ifndef ILIAS_NET2_WORKQ_H
#define ILIAS_NET2_WORKQ_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/ll.h>
#include <ilias/net2/refcnt.h>
#include <atomic>
#include <functional>
#include <utility>
#include <vector>


#ifdef _MSC_VER
#pragma warning( push )
#pragma warning( disable: 4275 )
#endif


namespace ilias {


class workq_job;
class workq;
class workq_service;

typedef refpointer<workq> workq_ptr;
typedef refpointer<workq_service> workq_service_ptr;

ILIAS_NET2_EXPORT workq_service_ptr new_workq_service(workq_service_ptr) throw (std::bad_alloc);


namespace workq_detail {


struct runq_tag {};
struct coroutine_tag {};
struct parallel_tag {};


template<typename Type> struct workq_intref_mgr;

class workq_int
{
template<typename Type> friend struct workq_intref_mgr;

private:
	mutable std::atomic<std::uintptr_t> int_refcnt;

protected:
	workq_int() ILIAS_NET2_NOTHROW :
		int_refcnt(0)
	{
		return;
	}

	workq_int(const workq_int&) ILIAS_NET2_NOTHROW :
		int_refcnt(0)
	{
		return;
	}

	~workq_int() ILIAS_NET2_NOTHROW
	{
		assert(int_refcnt == 0);
	}

	workq_int&
	operator=(const workq_int&) ILIAS_NET2_NOTHROW
	{
		return *this;
	}

	ILIAS_NET2_LOCAL void wait_unreferenced() const ILIAS_NET2_NOTHROW;
};

template<typename Type>
struct workq_intref_mgr
{
	void
	acquire(const Type& v) ILIAS_NET2_NOTHROW
	{
		const workq_int& i = v;
		const auto o = i.int_refcnt.fetch_add(1, std::memory_order_acquire);
		assert(o + 1 != 0);
	}

	void
	release(const Type& v) ILIAS_NET2_NOTHROW
	{
		const workq_int& i = v;
		const auto o = i.int_refcnt.fetch_sub(1, std::memory_order_release);
		assert(o > 0);
	}
};

#if HAS_ALIAS_TEMPLATES
template<typename Type> using workq_intref = refpointer<Type, workq_intref_mgr<Type> >;
#else
/* Fallback code for MSVC and other compilers that are slow to implement new features. */
template<typename Type>
class workq_intref :
	public refpointer<Type, workq_intref_mgr<Type> >
{
private:
	typedef refpointer<Type, workq_intref_mgr<Type> > impl_type;

public:
	workq_intref() ILIAS_NET2_NOTHROW :
		impl_type()
	{
		/* Empty body. */
	}

	template<typename V>
	workq_intref(const V& v) ILIAS_NET2_NOTHROW :
		impl_type(v)
	{
		/* Empty body. */
	}

	template<typename V>
	workq_intref(V&& v) ILIAS_NET2_NOTHROW :
		impl_type(std::move(v))
	{
		/* Empty body. */
	}

	template<typename V, typename U>
	workq_intref(const V& v, const U& u) ILIAS_NET2_NOTHROW :
		impl_type(v, u)
	{
		/* Empty body. */
	}

	using impl_type::operator=;
	using impl_type::operator==;
};
#endif

/* Deleter for workq and workq_service. */
struct wq_deleter
{
	ILIAS_NET2_EXPORT void operator()(const workq_job*) const ILIAS_NET2_NOTHROW;
	ILIAS_NET2_EXPORT void operator()(const workq*) const ILIAS_NET2_NOTHROW;
	ILIAS_NET2_EXPORT void operator()(const workq_service*) const ILIAS_NET2_NOTHROW;
};


class wq_run_lock;


} /* namespace ilias::workq_detail */


typedef std::unique_ptr<workq_job, workq_detail::wq_deleter> workq_job_ptr;	/* XXX probably needs change. */


class workq_job :
	public workq_detail::workq_int,
	public ll_base_hook<workq_detail::runq_tag>,
	public ll_base_hook<workq_detail::parallel_tag>
{
friend class workq;	/* Because MSVC and GCC cannot access private types in friend definitions. :P */
friend class workq_service;
friend class workq_detail::wq_run_lock;
friend void workq_detail::wq_deleter::operator()(const workq_job*) const ILIAS_NET2_NOTHROW;

public:
	enum run_lck {
		RUNNING,
		BUSY
	};

	static const unsigned int STATE_RUNNING = 0x0001;
	static const unsigned int STATE_HAS_RUN = 0x0002;
	static const unsigned int STATE_ACTIVE = 0x0004;

	static const unsigned int TYPE_ONCE = 0x0001;
	static const unsigned int TYPE_PERSIST = 0x0002;
	static const unsigned int TYPE_PARALLEL = 0x0004;
	static const unsigned int TYPE_MASK = (TYPE_ONCE | TYPE_PERSIST | TYPE_PARALLEL);

	const unsigned int m_type;

private:
	mutable std::atomic<unsigned int> m_run_gen;
	mutable std::atomic<unsigned int> m_state;
	const workq_ptr m_wq;

protected:
	ILIAS_NET2_EXPORT virtual run_lck lock_run() ILIAS_NET2_NOTHROW;
	ILIAS_NET2_EXPORT virtual void unlock_run(run_lck rl) ILIAS_NET2_NOTHROW;

	ILIAS_NET2_EXPORT workq_job(workq_ptr, unsigned int = 0) throw (std::invalid_argument);
	ILIAS_NET2_EXPORT virtual ~workq_job() ILIAS_NET2_NOTHROW;
	ILIAS_NET2_EXPORT virtual void run() ILIAS_NET2_NOTHROW = 0;

public:
	ILIAS_NET2_EXPORT void activate() ILIAS_NET2_NOTHROW;
	ILIAS_NET2_EXPORT void deactivate() ILIAS_NET2_NOTHROW;
	ILIAS_NET2_EXPORT const workq_ptr& get_workq() const ILIAS_NET2_NOTHROW;
	ILIAS_NET2_EXPORT const workq_service_ptr& get_workq_service() const ILIAS_NET2_NOTHROW;


#if HAS_DELETED_FN
	workq_job(const workq_job&) = delete;
	workq_job& operator=(const workq_job&) = delete;
#else
private:
	workq_job(const workq_job&);
	workq_job& operator=(const workq_job&);
#endif
};


namespace workq_detail {


class co_runnable :
	public ll_base_hook<coroutine_tag>,
	public workq_job
{
friend class ilias::workq_service;

private:
	std::atomic<unsigned int> m_runcount;

public:
	ILIAS_NET2_EXPORT virtual ~co_runnable() ILIAS_NET2_NOTHROW;

protected:
	ILIAS_NET2_EXPORT co_runnable(workq_ptr, unsigned int = 0) throw (std::invalid_argument);

	ILIAS_NET2_EXPORT virtual void unlock_run(run_lck rl) ILIAS_NET2_NOTHROW OVERRIDE;
	ILIAS_NET2_EXPORT void release(std::size_t n) ILIAS_NET2_NOTHROW;

	ILIAS_NET2_EXPORT virtual void co_run() ILIAS_NET2_NOTHROW = 0;
	ILIAS_NET2_EXPORT virtual void run() ILIAS_NET2_NOTHROW OVERRIDE;
	ILIAS_NET2_EXPORT virtual std::size_t size() const ILIAS_NET2_NOTHROW = 0;
};


} /* namespace workq_detail */


class workq FINAL :
	public workq_detail::workq_int,
	public ll_base_hook<workq_detail::runq_tag>,
	public refcount_base<workq, workq_detail::wq_deleter>
{
friend class workq_service;
friend class workq_detail::wq_run_lock;
friend void workq_job::activate() ILIAS_NET2_NOTHROW;
friend void workq_job::unlock_run(workq_job::run_lck rl) ILIAS_NET2_NOTHROW;
friend void workq_detail::wq_deleter::operator()(const workq*) const ILIAS_NET2_NOTHROW;
friend void workq_detail::wq_deleter::operator()(const workq_job*) const ILIAS_NET2_NOTHROW;

public:
	enum run_lck {
		RUN_SINGLE,
		RUN_PARALLEL
	};

private:
	typedef ll_smartptr_list<workq_detail::workq_intref<workq_job>,
	    ll_base<workq_job, workq_detail::runq_tag>,
	    refpointer_acquire<workq_job, workq_detail::workq_intref_mgr<workq_job> >,
	    refpointer_release<workq_job, workq_detail::workq_intref_mgr<workq_job> > > job_runq;

	typedef ll_smartptr_list<workq_detail::workq_intref<workq_job>,
	    ll_base<workq_job, workq_detail::parallel_tag>,
	    refpointer_acquire<workq_job, workq_detail::workq_intref_mgr<workq_job> >,
	    refpointer_release<workq_job, workq_detail::workq_intref_mgr<workq_job> > > job_p_runq;

	job_runq m_runq;
	job_p_runq m_p_runq;
	const workq_service_ptr m_wqs;
	std::atomic<bool> m_run_single;
	std::atomic<unsigned int> m_run_parallel;

	ILIAS_NET2_LOCAL run_lck lock_run() ILIAS_NET2_NOTHROW;
	ILIAS_NET2_LOCAL run_lck lock_run_parallel() ILIAS_NET2_NOTHROW;
	ILIAS_NET2_LOCAL void unlock_run(run_lck rl) ILIAS_NET2_NOTHROW;
	ILIAS_NET2_LOCAL run_lck lock_run_downgrade(run_lck rl) ILIAS_NET2_NOTHROW;

	ILIAS_NET2_LOCAL workq(workq_service_ptr wqs) throw (std::invalid_argument);
	ILIAS_NET2_LOCAL ~workq() ILIAS_NET2_NOTHROW;

public:
	ILIAS_NET2_EXPORT const workq_service_ptr& get_workq_service() const ILIAS_NET2_NOTHROW;

private:
	ILIAS_NET2_LOCAL void job_to_runq(workq_detail::workq_intref<workq_job>) ILIAS_NET2_NOTHROW;

public:
	ILIAS_NET2_EXPORT workq_job_ptr new_job(unsigned int type, std::function<void()>)
	    throw (std::bad_alloc, std::invalid_argument);
	ILIAS_NET2_EXPORT workq_job_ptr new_job(unsigned int type, std::vector<std::function<void()> >)
	    throw (std::bad_alloc, std::invalid_argument);
	ILIAS_NET2_EXPORT void once(std::function<void()>)
	    throw (std::bad_alloc, std::invalid_argument);
	ILIAS_NET2_EXPORT void once(std::vector<std::function<void()> >)
	    throw (std::bad_alloc, std::invalid_argument);

	workq_job_ptr
	new_job(std::function<void()> fn) throw (std::bad_alloc, std::invalid_argument)
	{
		return this->new_job(0U, std::move(fn));
	}

	workq_job_ptr
	new_job(std::vector<std::function<void()> > fns) throw (std::bad_alloc, std::invalid_argument)
	{
		return this->new_job(0U, std::move(fns));
	}

#if HAS_VARARG_TEMPLATES
	template<typename... FN>
	workq_job_ptr
	new_job(unsigned int type, std::function<void()> fn0, std::function<void()> fn1, FN&&... fn)
	    throw (std::bad_alloc, std::invalid_argument)
	{
		std::vector<std::function<void()> > fns;
		fns.push_back(std::move(fn0));
		fns.push_back(std::move(fn1));
		fns.push_back(std::forward(fn)...);

		return this->new_job(type, std::move(fns));
	}

	template<typename... FN>
	workq_job_ptr
	new_job(std::function<void()> fn0, std::function<void()> fn1, FN&&... fn)
	    throw (std::bad_alloc, std::invalid_argument)
	{
		return this->new_job(0U, std::move(fn0), std::move(fn1), std::forward(fn)...);
	}

	template<typename... FN>
	void
	once(std::function<void()> fn0, std::function<void()> fn1, FN&&... fn)
	    throw (std::bad_alloc, std::invalid_argument)
	{
		std::vector<std::function<void()> > fns;
		fns.push_back(std::move(fn0), std::move(fn1), std::forward(fn)...);

		this->once(std::move(fns));
	}
#endif


#if HAS_DELETED_FN
	workq(const workq&) = delete;
	workq& operator=(const workq&) = delete;
#else
private:
	workq(const workq&);
	workq& operator=(const workq&);
#endif
};


class workq_service FINAL :
	public workq_detail::workq_int,
	public refcount_base<workq_service, workq_detail::wq_deleter>
{
friend class workq_detail::wq_run_lock;
friend workq_service_ptr new_workq_service() throw (std::bad_alloc);
friend void workq_detail::wq_deleter::operator()(const workq*) const ILIAS_NET2_NOTHROW;
friend void workq_detail::wq_deleter::operator()(const workq_service*) const ILIAS_NET2_NOTHROW;
friend void workq_detail::co_runnable::run() ILIAS_NET2_NOTHROW;
friend void workq::job_to_runq(workq_detail::workq_intref<workq_job>) ILIAS_NET2_NOTHROW;

private:
	typedef ll_smartptr_list<workq_detail::workq_intref<workq>,
	    ll_base<workq, workq_detail::runq_tag>,
	    refpointer_acquire<workq, workq_detail::workq_intref_mgr<workq> >,
	    refpointer_release<workq, workq_detail::workq_intref_mgr<workq> > > wq_runq;

	typedef ll_smartptr_list<workq_detail::workq_intref<workq_detail::co_runnable>,
	    ll_base<workq_detail::co_runnable, workq_detail::coroutine_tag>,
	    refpointer_acquire<workq_detail::co_runnable, workq_detail::workq_intref_mgr<workq_detail::co_runnable> >,
	    refpointer_release<workq_detail::co_runnable, workq_detail::workq_intref_mgr<workq_detail::co_runnable> > > co_runq;

	wq_runq m_wq_runq;
	co_runq m_co_runq;

	ILIAS_NET2_LOCAL workq_service() ILIAS_NET2_NOTHROW;
	ILIAS_NET2_LOCAL ~workq_service() ILIAS_NET2_NOTHROW;

	ILIAS_NET2_LOCAL void wq_to_runq(workq_detail::workq_intref<workq>) ILIAS_NET2_NOTHROW;
	ILIAS_NET2_LOCAL void co_to_runq(workq_detail::workq_intref<workq_detail::co_runnable>, unsigned int) ILIAS_NET2_NOTHROW;
	ILIAS_NET2_LOCAL void wakeup(unsigned int = 1) ILIAS_NET2_NOTHROW;

public:
	ILIAS_NET2_EXPORT workq_ptr new_workq() throw (std::bad_alloc);


#if HAS_DELETED_FN
	workq_service(const workq_service&) = delete;
	workq_service& operator=(const workq_service&) = delete;
#else
private:
	workq_service(const workq_service&);
	workq_service& operator=(const workq_service&);
#endif
};


} /* namespace ilias */

#endif /* ILIAS_NET2_WORKQ_H */
