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
#pragma warning( disable: 4290 )
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

	workq_intref(std::nullptr_t) ILIAS_NET2_NOTHROW :
		impl_type(nullptr)
	{
		/* Empty body. */
	}

	workq_intref(const impl_type& v) ILIAS_NET2_NOTHROW :
		impl_type(v)
	{
		/* Empty body. */
	}

	workq_intref(impl_type&& v) ILIAS_NET2_NOTHROW :
		impl_type(std::move(v))
	{
		/* Empty body. */
	}

	workq_intref(const typename pointer& p) ILIAS_NET2_NOTHROW :
		impl_type(p)
	{
		/* Empty body. */
	}

	workq_intref(const typename pointer& p, bool a) ILIAS_NET2_NOTHROW :
		impl_type(p, a)
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

	static const unsigned int ACT_IMMED = 0x0001;

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
	ILIAS_NET2_EXPORT virtual void run(workq_detail::wq_run_lock&) ILIAS_NET2_NOTHROW = 0;

public:
	ILIAS_NET2_EXPORT void activate(unsigned int flags = 0) ILIAS_NET2_NOTHROW;
	ILIAS_NET2_EXPORT void deactivate() ILIAS_NET2_NOTHROW;
	ILIAS_NET2_EXPORT const workq_ptr& get_workq() const ILIAS_NET2_NOTHROW;
	ILIAS_NET2_EXPORT const workq_service_ptr& get_workq_service() const ILIAS_NET2_NOTHROW;

	/* Test if the running bit is set. */
	bool
	is_running() const ILIAS_NET2_NOTHROW
	{
		return (this->m_state.load(std::memory_order_relaxed) & STATE_RUNNING);
	}


#if HAS_DELETED_FN
	workq_job(const workq_job&) = delete;
	workq_job& operator=(const workq_job&) = delete;
#else
private:
	workq_job(const workq_job&);
	workq_job& operator=(const workq_job&);
#endif
};


class workq FINAL :
	public workq_detail::workq_int,
	public ll_base_hook<workq_detail::runq_tag>,
	public refcount_base<workq, workq_detail::wq_deleter>
{
friend class workq_service;
friend class workq_detail::wq_run_lock;
friend void workq_job::activate(unsigned int) ILIAS_NET2_NOTHROW;
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

	ILIAS_NET2_EXPORT void aid(unsigned int = 1) ILIAS_NET2_NOTHROW;


#if HAS_DELETED_FN
	workq(const workq&) = delete;
	workq& operator=(const workq&) = delete;
#else
private:
	workq(const workq&);
	workq& operator=(const workq&);
#endif
};


namespace workq_detail {


class co_runnable;

/*
 * wq_run_lock: lock a workq and job for execution.
 *
 * This is an internal type that should only be passed around by reference.
 *
 * This forms the basis for locking a job to be executed.
 * If this is in the locked state, the job _must_ be run,
 * after which commit() is called.
 *
 * Destroying a locked, but uncommited wq_run_lock will
 * result in an assertion failure, since it would invalidate
 * the promise to a job (when the job is succesfully locked,
 * it is guaranteed to run and to unlock).
 */
class ILIAS_NET2_LOCAL wq_run_lock
{
friend class ilias::workq_service;
friend class co_runnable;	/* Can't get more specific, since the co_runnable requires wq_run_lock to be defined. */
friend void ilias::workq_job::activate(unsigned int) ILIAS_NET2_NOTHROW;
friend void ilias::workq::aid(unsigned int) ILIAS_NET2_NOTHROW;

private:
	workq_intref<workq> m_wq;
	workq_intref<workq_job> m_wq_job;
	workq::run_lck m_wq_lck;
	workq_job::run_lck m_wq_job_lck;
	bool m_commited;

public:
	wq_run_lock() ILIAS_NET2_NOTHROW :
		m_wq(),
		m_wq_job(),
		m_wq_lck(),
		m_wq_job_lck(),
		m_commited(false)
	{
		/* Empty body. */
	}

	~wq_run_lock() ILIAS_NET2_NOTHROW
	{
		this->unlock();
	}

private:
	wq_run_lock(wq_run_lock&& o) ILIAS_NET2_NOTHROW :
		m_wq(std::move(o.m_wq)),
		m_wq_job(std::move(o.m_wq_job)),
		m_wq_lck(o.m_wq_lck),
		m_wq_job_lck(o.m_wq_job_lck),
		m_commited(o.m_commited)
	{
		/* Empty body. */
	}

	wq_run_lock(workq_service& wqs) ILIAS_NET2_NOTHROW :
		m_wq(),
		m_wq_job(),
		m_wq_lck(),
		m_wq_job_lck(),
		m_commited(false)
	{
		this->lock(wqs);
	}

	wq_run_lock(workq& wq) ILIAS_NET2_NOTHROW :
		m_wq(),
		m_wq_job(),
		m_wq_lck(),
		m_wq_job_lck(),
		m_commited(false)
	{
		this->lock(wq);
	}

	wq_run_lock(workq_job& wqj) ILIAS_NET2_NOTHROW :
		m_wq(),
		m_wq_job(),
		m_wq_lck(),
		m_wq_job_lck(),
		m_commited(false)
	{
		this->lock(wqj);
	}

	wq_run_lock&
	operator=(wq_run_lock&& o) ILIAS_NET2_NOTHROW
	{
		assert(!this->m_wq && !this->m_wq_job);
		this->m_wq = std::move(o.m_wq);
		this->m_wq_job = std::move(o.m_wq_job);
		this->m_wq_lck = o.m_wq_lck;
		this->m_wq_job_lck = o.m_wq_job_lck;
		this->m_commited = o.m_commited;
		return *this;
	}

	const workq_intref<workq>&
	get_wq() const ILIAS_NET2_NOTHROW
	{
		return this->m_wq;
	}

	const workq_intref<workq_job>&
	get_wq_job() const ILIAS_NET2_NOTHROW
	{
		return this->m_wq_job;
	}

	void
	commit() ILIAS_NET2_NOTHROW
	{
		assert(this->is_locked() && !this->is_commited());
		this->m_commited = true;
	}

	void
	unlock() ILIAS_NET2_NOTHROW
	{
		assert(!this->is_locked() || this->m_commited);

		if (this->m_wq_job && this->m_wq_job_lck != workq_job::BUSY)
			this->m_wq_job->unlock_run(this->m_wq_job_lck);
		if (this->m_wq)
			this->m_wq->unlock_run(this->m_wq_lck);
		this->m_wq_job.reset();
		this->m_wq.reset();
		this->m_commited = false;
	}

	bool lock(workq& what) ILIAS_NET2_NOTHROW;
	bool lock(workq_job& what) ILIAS_NET2_NOTHROW;
	bool lock(workq_service& wqs) ILIAS_NET2_NOTHROW;

public:
	bool
	is_commited() const ILIAS_NET2_NOTHROW
	{
		return this->m_commited;
	}

	bool
	is_locked() const ILIAS_NET2_NOTHROW
	{
		return (this->m_wq_job_lck != workq_job::BUSY && this->get_wq() && this->get_wq_job());
	}


#if HAS_DELETED_FN
	wq_run_lock(const wq_run_lock&) = delete;
	wq_run_lock& operator=(const wq_run_lock&) = delete;
#else
private:
	wq_run_lock(const wq_run_lock&);
	wq_run_lock& operator=(const wq_run_lock&);
#endif
};


class co_runnable :
	public ll_base_hook<coroutine_tag>,
	public workq_job
{
friend class ilias::workq_service;

private:
	wq_run_lock m_rlck;
	std::atomic<unsigned int> m_runcount;

public:
	ILIAS_NET2_EXPORT virtual ~co_runnable() ILIAS_NET2_NOTHROW;

protected:
	ILIAS_NET2_EXPORT co_runnable(workq_ptr, unsigned int = 0) throw (std::invalid_argument);

	ILIAS_NET2_EXPORT virtual void unlock_run(run_lck rl) ILIAS_NET2_NOTHROW OVERRIDE;

	ILIAS_NET2_EXPORT void co_publish(wq_run_lock&, std::size_t) ILIAS_NET2_NOTHROW;
	ILIAS_NET2_EXPORT bool release(std::size_t) ILIAS_NET2_NOTHROW;

	ILIAS_NET2_EXPORT virtual bool co_run() ILIAS_NET2_NOTHROW = 0;
};


} /* namespace ilias::workq_detail */


class workq_service FINAL :
	public workq_detail::workq_int,
	public refcount_base<workq_service, workq_detail::wq_deleter>
{
friend class workq_detail::wq_run_lock;
friend workq_service_ptr new_workq_service() throw (std::bad_alloc);
friend void workq_detail::wq_deleter::operator()(const workq*) const ILIAS_NET2_NOTHROW;
friend void workq_detail::wq_deleter::operator()(const workq_service*) const ILIAS_NET2_NOTHROW;
friend void workq_detail::co_runnable::co_publish(workq_detail::wq_run_lock&, std::size_t) ILIAS_NET2_NOTHROW;
friend bool workq_detail::co_runnable::release(std::size_t n) ILIAS_NET2_NOTHROW;
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
	ILIAS_NET2_EXPORT void aid(unsigned int = 1) ILIAS_NET2_NOTHROW;


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


#ifdef _MSC_VER
#pragma warning( pop )
#endif

#endif /* ILIAS_NET2_WORKQ_H */
