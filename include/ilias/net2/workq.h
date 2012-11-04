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
#include <functional>
#include <utility>

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

} /* namespace ilias::<unnamed> */


/*
 * Internal pointer type for workq.
 *
 * This pointer indicates items that are borrowed.
 * The pointer does not have real ownership semantics, it only prevents object
 * destructors from running while the workq still needs an item.
 */
template<typename Type> class workq_int_pointer;


class ILIAS_NET2_EXPORT workq :
	public ll_base_hook<wq_runq_tag>,
	public workq_int_refcnt,
	public refcount_base<workq>
{
friend class workq_service;	/* Needs access to coroutine_job, job. */

private:
	class job;
	class single_job;
	class coroutine_job;
	class runnable_job;

	typedef ll_list<ll_base<job, wq_runq_tag> > runq_list;

	const refpointer<workq_service> wqs;
	runq_list runq;

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
};


class ILIAS_NET2_EXPORT workq::job :
	public ll_base_hook<wq_runq_tag>,
	public workq_int_refcnt
{
friend class workq::runnable_job;

protected:
	const refpointer<workq> wq;	/* Associated workq. */
	std::atomic<int> m_state;	/* State indication bits. */
	const int m_type;		/* Type indication bits. */

public:
	static const int STATE_RUNNING = 0x0001;
	static const int STATE_ACTIVE = 0x0002;

	static const int TYPE_PERSIST = 0x0001;

protected:
	job(const refpointer<workq>& wq, int type) ILIAS_NET2_NOTHROW :
		wq(wq),
		m_state(0),
		m_type(type)
	{
		/* Empty body. */
	}

	void clear_running() ILIAS_NET2_NOTHROW;

public:
	virtual ~job() ILIAS_NET2_NOTHROW;

private:
	virtual void do_run(runnable_job&) ILIAS_NET2_NOTHROW = 0;

public:
	workq&
	get_workq() const ILIAS_NET2_NOTHROW
	{
		assert(this->wq);
		return *this->wq;
	}

	workq_service&
	get_workq_service() const ILIAS_NET2_NOTHROW
	{
		return this->get_workq().get_workq_service();
	}
};


class ILIAS_NET2_LOCAL workq::single_job :
	public workq::job
{
private:
	std::function<void()> fn;

	virtual void do_run(runnable_job&) ILIAS_NET2_NOTHROW;
};


class ILIAS_NET2_LOCAL workq::coroutine_job :
	public workq::job,
	public ll_base_hook<wq_coroutine_tag>
{
friend class workq_service;	/* Grant access to class workq_service_coroutines. */

private:
	class workq_service_coroutines;

	typedef std::vector<std::function<void()> > fn_list;

	const fn_list fn;
	std::atomic<fn_list::size_type> m_idx;
	std::atomic<fn_list::size_type> m_incomplete;

	virtual void do_run(runnable_job&) ILIAS_NET2_NOTHROW;
};


class ILIAS_NET2_LOCAL workq::coroutine_job::workq_service_coroutines
{
friend class workq::coroutine_job;

private:
	typedef ll_list<ll_base<workq::coroutine_job, wq_coroutine_tag> > coroutine_list;

	/* Active co-routines. */
	coroutine_list m_coroutines;

	void activate(coroutine_job&, runnable_job&) ILIAS_NET2_NOTHROW;
	std::pair<workq_int_pointer<coroutine_job>, fn_list::size_type> get_coroutine() ILIAS_NET2_NOTHROW;

	inline void
	push_coroutine(coroutine_job& crj) ILIAS_NET2_NOTHROW
	{
		workq_int_acquire(crj);
		const bool ok = this->m_coroutines.push_back(crj);
		assert(ok);
	}

	RVALUE(coroutine_list::iterator) unlink_coroutine(RVALUE_REF(coroutine_list::iterator)) ILIAS_NET2_NOTHROW;
	RVALUE(workq_int_pointer<coroutine_job>) unlink_coroutine(coroutine_job&) ILIAS_NET2_NOTHROW;

protected:
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
	bool run_coroutine() ILIAS_NET2_NOTHROW;
};


class workq_service :
	public refcount_base<workq_service>,
	public workq::coroutine_job::workq_service_coroutines
{
public:
	workq_service() ILIAS_NET2_NOTHROW
	{
		/* Empty body. */
	}

	void wakeup(std::size_t);	/* XXX stub. */
};


} /* namespace ilias */

#endif /* ILIAS_NET2_WORKQ_H */
