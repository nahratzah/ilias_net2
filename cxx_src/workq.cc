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
#include <ilias/net2/workq.h>
#include <thread>


namespace ilias {


using namespace workq_detail;


class workq::runnable_job
{
private:
	workq_int_pointer<job> m_ptr;
	bool m_locked;

public:
	runnable_job() ILIAS_NET2_NOTHROW :
		m_ptr(),
		m_locked(0)
	{
		/* Empty body. */
	}

	runnable_job(runnable_job&& rj) ILIAS_NET2_NOTHROW :
		m_ptr(std::move(rj.m_ptr)),
		m_locked(rj.m_locked)
	{
		rj.m_locked = false;
	}

	~runnable_job() ILIAS_NET2_NOTHROW
	{
		if (this->locked())
			this->unlock();
	}

	runnable_job&
	operator=(runnable_job&& rj) ILIAS_NET2_NOTHROW
	{
		assert(!this->m_locked);
		this->m_ptr = std::move(rj.m_ptr);
		this->m_locked = std::move(rj.m_locked);
		rj.m_locked = false;
		return *this;
	}

	std::size_t
	run() ILIAS_NET2_NOTHROW
	{
		return this->m_ptr->do_run(*this);
	}

	/* Assign and lock job. */
	bool
	lock(workq_int_pointer<job> j) ILIAS_NET2_NOTHROW
	{
		assert(!this->locked());

		this->m_ptr = MOVE(j);
		return this->lock();
	}

	const workq_int_pointer<job>&
	get() const ILIAS_NET2_NOTHROW
	{
		return this->m_ptr;
	}

	bool
	locked() const ILIAS_NET2_NOTHROW
	{
		return this->m_locked;
	}

	/*
	 * Transition from !running to running state.
	 * Clears the active bit, unless the job is a marked as persistant.
	 * This operation will fail if the job was not active.
	 */
	bool
	lock() ILIAS_NET2_NOTHROW
	{
		assert(!this->m_locked && this->m_ptr);
		auto old = this->m_ptr->m_state.load(std::memory_order_relaxed);
		auto set = old;
		do {
			/* Fail if the job is currently running or is not active. */
			if ((old & job::STATE_RUNNING) || !(old & job::STATE_ACTIVE))
				return false;
			/* Fail if the job is only allowed to run once and has already ran. */
			if ((old & job::STATE_HAS_RUN) && (this->m_ptr->m_type & job::TYPE_ONCE))
				return false;

			set = old | job::STATE_RUNNING | job::STATE_HAS_RUN;
			if (!(this->m_ptr->m_type & job::TYPE_PERSIST))
				set &= ~job::STATE_ACTIVE;
		} while (!this->m_ptr->m_state.compare_exchange_weak(old, set,
		    std::memory_order_acquire, std::memory_order_relaxed));

		/* Increment generation counter (must happen after job got marked runnable). */
		this->m_ptr->m_rungen.fetch_add(1, std::memory_order_acquire);

		this->m_locked = true;
		return true;
	}

	void
	unlock() ILIAS_NET2_NOTHROW
	{
		assert(this->m_locked);
		this->m_ptr->clear_running(MOVE(this->m_ptr));
		this->m_ptr.reset();
		this->m_locked = false;
	}

	workq_int_pointer<job>
	release() ILIAS_NET2_NOTHROW
	{
		workq_int_pointer<job> rv;
		if (this->m_locked) {
			this->m_locked = false;
			this->m_ptr.swap(rv);
		}
		return rv;
	}


#if HAS_DELETED_FN
	runnable_job(const runnable_job&) = delete;
	runnable_job& operator=(const runnable_job&) = delete;
#else
private:
	runnable_job(const runnable_job&);
	runnable_job& operator=(const runnable_job&);
#endif
};


workq::workq(const refpointer<workq_service>& wqs) ILIAS_NET2_NOTHROW :
	wqs(wqs)
{
	return;
}

/*
 * Ensure the workq is no longer in use.
 */
void
workq::destroy() ILIAS_NET2_NOTHROW
{
	assert(refcnt_is_solo(*this));

	workq_service_workq& s = this->get_workq_service().m_workq_srv;
	s.m_workqs.unlink_robust(s.m_workqs.iterator_to(*this));

	while (!this->int_is_solo())
		std::this_thread::yield();

	workq_int_refcnt_mgr().release(*this);
}

void
workq::activate() const ILIAS_NET2_NOTHROW
{
	/* XXX implement */
}

/* Returns a job, having marked it runnable. */
workq::runnable_job
workq::get_runnable_job() ILIAS_NET2_NOTHROW
{
	runnable_job rj;
	runq_list::unlink_wait j;

	while ((j = this->runq.pop_front_nowait())) {
		if (rj.lock(j.get()))
			return std::move(rj);

		j.release();
	}

	return rj;
}

void
workq::job::clear_running(workq_int_pointer<job> ptr) ILIAS_NET2_NOTHROW
{
	assert(this == ptr.get());	/* Ensure this pointer is owned. */

	/* Clear the running bit. */
	const auto old = this->m_state.fetch_and(~STATE_RUNNING, std::memory_order_release);
	/*
	 * Validate state: the job must have been running and,
	 * since it actually has run at least now, it must have the HAS_RUN bit set.
	 */
	assert(old & STATE_RUNNING);
	assert(old & STATE_HAS_RUN);

	/*
	 * Put job back on the runqueue if it is active.
	 * Note that if the job has the TYPE_ONCE bit, we cannot run it again
	 * therefore don't need to put it back on the runqueue either.
	 */
	if ((old & STATE_ACTIVE) && !(this->m_type & TYPE_ONCE))
		this->get_workq().runq.push_back(ptr);
}

workq&
workq::job::get_workq() const ILIAS_NET2_NOTHROW
{
	assert(this->wq);
	return *this->wq;
}

workq_service&
workq::job::get_workq_service() const ILIAS_NET2_NOTHROW
{
	return this->get_workq().get_workq_service();
}

workq::job::~job() ILIAS_NET2_NOTHROW
{
	return;
}

void
workq::job::activate() ILIAS_NET2_NOTHROW
{
	const int fl = this->m_state.fetch_or(STATE_ACTIVE, std::memory_order_relaxed);
	if (fl & (STATE_RUNNING | STATE_ACTIVE))
		return;
	if ((this->m_type & TYPE_ONCE) && (fl & STATE_HAS_RUN))
		return;
	workq& wq = this->get_workq();
	wq.runq.push_back(workq_int_pointer<job>(this));
	wq.activate();
}

void
workq::job::deactivate() ILIAS_NET2_NOTHROW
{
	const int gen = this->m_rungen.load(std::memory_order_acquire);
	int fl = this->m_state.fetch_and(~STATE_ACTIVE, std::memory_order_relaxed);

	while ((fl & STATE_RUNNING) &&
	    this->m_rungen.load(std::memory_order_relaxed) == gen) {
		std::this_thread::yield();
		fl = this->m_state.load(std::memory_order_relaxed);
	}
}


workq::single_job::~single_job() ILIAS_NET2_NOTHROW
{
	return;
}

std::size_t
workq::single_job::do_run(runnable_job&) ILIAS_NET2_NOTHROW
{
	this->fn();
	return 1;
}


workq::coroutine_job::~coroutine_job() ILIAS_NET2_NOTHROW
{
	return;
}

std::size_t
workq::coroutine_job::do_run(runnable_job& rj) ILIAS_NET2_NOTHROW
{
	/* XXX reference counting in this function is suspect! */
	assert(!this->fn.empty());
	const fn_list::size_type sz = this->fn.size();

	this->m_idx.store(0, std::memory_order_acquire);
	this->m_incomplete.store(sz, std::memory_order_acquire);

	workq_service& wqs = this->get_workq_service();
	wqs.m_coroutines_srv.activate(*this, rj);
	wqs.wakeup(sz);

	return 0;	/* We didn't execute any jobs, only changed the queueing of this job. */
}


void
workq::coroutine_job::workq_service_coroutines::activate(coroutine_job& cj, runnable_job& rj) ILIAS_NET2_NOTHROW
{
	workq_int_pointer<coroutine_job> cj_ptr(static_pointer_cast<workq::coroutine_job>(rj.release()));
	assert(cj_ptr.get() == &cj);

	const bool enqueue = this->m_coroutines.push_back(std::move(cj_ptr));
	assert(enqueue);
}

std::pair<workq_int_pointer<workq::coroutine_job>, workq::coroutine_job::fn_list::size_type>
workq::coroutine_job::workq_service_coroutines::get_coroutine() ILIAS_NET2_NOTHROW
{
	std::pair<workq_int_pointer<coroutine_job>, fn_list::size_type> rv;

	for (coroutine_list::iterator cr_iter = this->m_coroutines.begin();
	    cr_iter != this->m_coroutines.end();
	    cr_iter = this->m_coroutines.erase(cr_iter)) {
		rv.second = cr_iter->m_idx.fetch_add(1, std::memory_order_acquire);
		if (rv.second < cr_iter->fn.size()) {
			rv.first = &*cr_iter;
			break;
		}
	}

	return rv;
}

bool
workq::coroutine_job::workq_service_coroutines::run_coroutine(std::size_t& counter) ILIAS_NET2_NOTHROW
{
	if (counter == 0)
		return false;

	/* Find a runnable co-routine. */
	std::pair<workq_int_pointer<coroutine_job>, fn_list::size_type> crj =
	    this->get_coroutine();
	if (!crj.first)
		return false;

	/* Run said co-routine. */
	crj.first->fn[crj.second]();

	/* Decrement completion barrier. */
	const auto rel = crj.first->m_incomplete.fetch_sub(1, std::memory_order_release);
	assert(rel > 0);
	if (rel == 1) {
		/* Unlink from co-routine list. */
		{
			coroutine_list::iterator i = this->m_coroutines.iterator_to(*crj.first);
			this->m_coroutines.erase(i);
		}
		/* Clear running bit. */
		crj.first->clear_running(crj.first);
	}

	/* We ran a co-routine. */
	--counter;
	return true;
}


refpointer<workq>
workq_service::new_workq()
{
	return refpointer<workq>(new workq(this));
}

bool
workq::workq_service_workq::run_workq(std::size_t& counter) ILIAS_NET2_NOTHROW
{
	if (counter == 0)
		return false;

	/* Find a runnable workq. */
	runnable_job j;
	for (;;) {
		workq_list::unlink_wait wq;
		wq = this->m_workqs.pop_front_nowait();
		if (!wq)
			return false;

		j = wq->get_runnable_job();
		if (j.get()) {
			this->m_workqs.push_back(MOVE(wq));
			break;
		}
	}

	const std::size_t runcount = j.run();
	counter -= std::min(counter, runcount);
	return true;
}


void
workq_service::activate(workq_int_pointer<workq> wq)
{
	this->m_workq_srv.m_workqs.push_front(std::move(wq));
}

void
workq_service::activate(refpointer<workq> wq)
{
	this->activate(workq_int_pointer<workq>(wq.get()));
}

bool
workq_service::do_work(std::size_t n) ILIAS_NET2_NOTHROW
{
	bool rv = false;

	while (n > 0) {
		if (this->m_coroutines_srv.run_coroutine(n))
			rv = true;
		else if (this->m_workq_srv.run_workq(n))
			rv = true;
	}

	/* Return true if work was done. */
	return rv;
}


} /* namespace ilias */
