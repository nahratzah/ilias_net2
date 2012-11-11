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
#include <ilias/net2/booltest.h>
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


class workq;
class workq_service;

namespace {

struct wq_runq_tag {};
struct wq_coroutine_tag {};

class workq_int_refcnt
{
private:
	std::atomic<unsigned int> int_refcnt;

protected:
	workq_int_refcnt() ILIAS_NET2_NOTHROW :
		int_refcnt(0)
	{
		/* Empty body. */
	}

	workq_int_refcnt(const workq_int_refcnt&) ILIAS_NET2_NOTHROW :
		int_refcnt(0)
	{
		/* Empty body. */
	}

	~workq_int_refcnt() ILIAS_NET2_NOTHROW
	{
		assert(this->int_refcnt == 0);
	}

	workq_int_refcnt& operator=(const workq_int_refcnt&) ILIAS_NET2_NOTHROW
	{
		return *this;
	}

	bool
	int_is_solo() const ILIAS_NET2_NOTHROW
	{
		return (this->int_refcnt.load(std::memory_order_relaxed) == 1);
	}

	friend void
	workq_int_acquire(workq_int_refcnt& wir) ILIAS_NET2_NOTHROW
	{
		const unsigned int old = wir.int_refcnt.fetch_add(1, std::memory_order_acquire);
		assert(old + 1 > 0);
	}

	friend void
	workq_int_release(workq_int_refcnt& wir) ILIAS_NET2_NOTHROW
	{
		const unsigned int old = wir.int_refcnt.fetch_sub(1, std::memory_order_release);
		assert(old > 0);
	}
};

class identity_comparable
{
protected:
	identity_comparable() ILIAS_NET2_NOTHROW { /* Empty body. */ }
	identity_comparable(const identity_comparable&) ILIAS_NET2_NOTHROW { /* Empty body. */ }

public:
	bool
	operator==(const identity_comparable& o) const ILIAS_NET2_NOTHROW
	{
		return (this == &o);
	}

	bool
	operator!=(const identity_comparable& o) const ILIAS_NET2_NOTHROW
	{
		return !(this == &o);
	}
};

} /* namespace ilias::<unnamed> */


/*
 * Internal pointer type for workq.
 *
 * This pointer indicates items that are borrowed.
 * The pointer does not have real ownership semantics, it only prevents object
 * destructors from running while the workq still needs an item.
 */
template<typename Type> class workq_int_pointer;


namespace {


template<typename Type>
struct workq_int_refcnt_acquire
{
	workq_int_pointer<Type>
	operator()(Type* p) const ILIAS_NET2_NOTHROW
	{
		return workq_int_pointer<Type>(p, false);
	}
};
template<typename Type>
struct workq_int_refcnt_release
{
	Type*
	operator()(workq_int_pointer<Type> p) const ILIAS_NET2_NOTHROW
	{
		return p.release();
	}
};


}


class workq_destroy
{
friend void refcnt_release(workq&);

private:
	void operator()(workq*) ILIAS_NET2_NOTHROW;
};

class ILIAS_NET2_LOCAL workq FINAL :
	public ll_base_hook<wq_runq_tag>,
	public workq_int_refcnt,
	public refcount_base<workq, workq_destroy>,
	public identity_comparable
{
friend class workq_service;	/* Needs access to coroutine_job, job. */
friend class workq_destroy;	/* Destructor. */

private:
	class job;
	class single_job;
	class coroutine_job;
	class runnable_job;
	class workq_service_workq;

	typedef ll_smartptr_list<workq_int_pointer<job>,
	    ll_base<job, wq_runq_tag>,
	    workq_int_refcnt_acquire<job>,
	    workq_int_refcnt_release<job> > runq_list;

	const refpointer<workq_service> wqs;
	runq_list runq;
	std::atomic<int> m_flags;

	static const int QMOD = 0x80000000;

protected:
	ILIAS_NET2_LOCAL workq(const refpointer<workq_service>&) ILIAS_NET2_NOTHROW;

public:
	workq_service&
	get_workq_service() const ILIAS_NET2_NOTHROW
	{
		assert(this->wqs);
		return *this->wqs;
	}

private:
	ILIAS_NET2_LOCAL runnable_job get_runnable_job() ILIAS_NET2_NOTHROW;
	ILIAS_NET2_EXPORT void destroy() ILIAS_NET2_NOTHROW;
};

void
workq_destroy::operator()(workq* wq) ILIAS_NET2_NOTHROW
{
	wq->destroy();
	delete wq;
}


class ILIAS_NET2_EXPORT workq::job :
	public ll_base_hook<wq_runq_tag>,
	public workq_int_refcnt,
	public identity_comparable
{
friend class workq::runnable_job;

private:
	const refpointer<workq> wq;	/* Associated workq. */
	std::atomic<int> m_state;	/* State indication bits. */
	const int m_type;		/* Type indication bits. */

public:
	static CONSTEXPR_VALUE int STATE_RUNNING = 0x0001;
	static CONSTEXPR_VALUE int STATE_ACTIVE = 0x0002;
	static CONSTEXPR_VALUE int STATE_HAS_RUN = 0x0004;

	static CONSTEXPR_VALUE int TYPE_PERSIST = 0x0001;
	static CONSTEXPR_VALUE int TYPE_ONCE = 0x0002;

protected:
	job(const refpointer<workq>& wq, int type) ILIAS_NET2_NOTHROW :
		wq(wq),
		m_state(0),
		m_type(type)
	{
		/* Empty body. */
	}

	void clear_running(const workq_int_pointer<job>&) ILIAS_NET2_NOTHROW;
#if HAS_RVALUE_REF
	void clear_running(workq_int_pointer<job>&&) ILIAS_NET2_NOTHROW;
#endif

public:
	virtual ~job() ILIAS_NET2_NOTHROW;

private:
	virtual std::size_t do_run(runnable_job&) ILIAS_NET2_NOTHROW = 0;

public:
	workq& get_workq() const ILIAS_NET2_NOTHROW;
	workq_service& get_workq_service() const ILIAS_NET2_NOTHROW;
};


class ILIAS_NET2_LOCAL workq::single_job FINAL :
	public workq::job
{
private:
	std::function<void()> fn;

public:
	virtual ~single_job() ILIAS_NET2_NOTHROW;

private:
	virtual std::size_t do_run(runnable_job&) ILIAS_NET2_NOTHROW OVERRIDE;
};


class ILIAS_NET2_LOCAL workq::coroutine_job FINAL :
	public workq::job,
	public ll_base_hook<wq_coroutine_tag>
{
friend class workq_service;	/* Grant access to class workq_service_coroutines. */

public:
	~coroutine_job() ILIAS_NET2_NOTHROW;

protected:
	using job::clear_running;

private:
	class workq_service_coroutines;

	typedef std::vector<std::function<void()> > fn_list;

	const fn_list fn;
	std::atomic<fn_list::size_type> m_idx;
	std::atomic<fn_list::size_type> m_incomplete;

	virtual std::size_t do_run(runnable_job&) ILIAS_NET2_NOTHROW OVERRIDE;
};


class ILIAS_NET2_LOCAL workq::coroutine_job::workq_service_coroutines
{
friend class workq::coroutine_job;

private:
	typedef ll_smartptr_list<workq_int_pointer<coroutine_job>,
	    ll_base<coroutine_job, wq_coroutine_tag>,
	    workq_int_refcnt_acquire<coroutine_job>,
	    workq_int_refcnt_release<coroutine_job> > coroutine_list;

	/* Active co-routines. */
	coroutine_list m_coroutines;

	void activate(coroutine_job&, runnable_job&) ILIAS_NET2_NOTHROW;
	std::pair<workq_int_pointer<coroutine_job>, fn_list::size_type> get_coroutine() ILIAS_NET2_NOTHROW;

	void push_coroutine(const workq_int_pointer<coroutine_job>&) ILIAS_NET2_NOTHROW;
#if HAS_RVALUE_REF
	void push_coroutine(workq_int_pointer<coroutine_job>&&) ILIAS_NET2_NOTHROW;
#endif

public:
	workq_service_coroutines() ILIAS_NET2_NOTHROW
	{
		/* Empty body. */
	}

	~workq_service_coroutines() ILIAS_NET2_NOTHROW
	{
		return;
	}

	/*
	 * Attempt to run a single co-routine.
	 *
	 * Returns true if it ran a co-routine.
	 * Returns false if the list is empty.
	 */
	bool run_coroutine(std::size_t&) ILIAS_NET2_NOTHROW;
};


class ILIAS_NET2_LOCAL workq::workq_service_workq
{
friend class workq;

private:
	typedef ll_smartptr_list<workq_int_pointer<workq>,
	    ll_base<workq, wq_runq_tag>,
	    workq_int_refcnt_acquire<workq>,
	    workq_int_refcnt_release<workq> > workq_list;

	/* Active workqs. */
	workq_list m_workqs;

public:
	workq_service_workq() ILIAS_NET2_NOTHROW
	{
		/* Empty body. */
	}

	~workq_service_workq() ILIAS_NET2_NOTHROW
	{
		return;
	}

	/*
	 * Attempt to run a single workq.
	 *
	 * Returns true if it ran a workq.
	 * Returns false if the list is empty.
	 */
	bool run_workq(std::size_t&) ILIAS_NET2_NOTHROW;
};


class ILIAS_NET2_LOCAL workq_service FINAL :
	public refcount_base<workq_service>,
	public workq_int_refcnt,
	public identity_comparable
{
friend std::size_t workq::coroutine_job::do_run(runnable_job&) ILIAS_NET2_NOTHROW;
friend void workq::destroy() ILIAS_NET2_NOTHROW;

private:
	workq::coroutine_job::workq_service_coroutines m_coroutines_srv;
	workq::workq_service_workq m_workq_srv;

public:
	ILIAS_NET2_LOCAL workq_service() ILIAS_NET2_NOTHROW
	{
		/* Empty body. */
	}

	ILIAS_NET2_EXPORT refpointer<workq> new_workq();

private:
	bool do_work(std::size_t) ILIAS_NET2_NOTHROW;

	void
	wakeup(std::size_t) ILIAS_NET2_NOTHROW
	{
		/* XXX STUB */
		assert(0);
	}
};


} /* namespace ilias */

#endif /* ILIAS_NET2_WORKQ_H */
