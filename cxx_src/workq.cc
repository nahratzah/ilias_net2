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


#ifdef _MSC_VER
#pragma warning( push )
#pragma warning( disable: 4290 )
#endif


namespace ilias {
namespace workq_detail {


bool
wq_run_lock::lock(workq& what) ILIAS_NET2_NOTHROW
{
	assert(!this->m_wq && !this->m_wq_job);

	this->m_commited = false;
	this->m_wq = &what;
	this->m_wq_lck = this->m_wq->lock_run();

	switch (this->m_wq_lck) {
	case workq::RUN_SINGLE:
		/*
		 * Find a job we can run.
		 *
		 * Loop terminates either with a locked job, or without job.
		 */
		while ((this->m_wq_job = this->m_wq->m_runq.pop_front())) {
			if ((this->m_wq_job_lck = this->m_wq_job->lock_run()) != workq_job::BUSY)
				break;		/* GUARD */
		}

		/* Take job away from parallel runq iff it is parallel. */
		if (this->m_wq_job && (this->m_wq_job->m_type & workq_job::TYPE_PARALLEL))
			this->m_wq->m_p_runq.erase(this->m_wq->m_p_runq.iterator_to(*this->m_wq_job));

		/* Downgrade to parallel lock iff job is a parallel job. */
		if (this->m_wq_job && (this->m_wq_job->m_type & workq_job::TYPE_PARALLEL)) {
			this->m_wq_lck = this->m_wq->lock_run_downgrade(this->m_wq_lck);
			assert(this->m_wq_lck == workq::RUN_SINGLE ||
			    this->m_wq_lck == workq::RUN_PARALLEL);
		}

		break;
	case workq::RUN_PARALLEL:
		/*
		 * Find a parallel job we can run.
		 *
		 * Loop terminates either with a locked job, or without job.
		 */
		while ((this->m_wq_job = this->m_wq->m_p_runq.pop_front())) {
			if ((this->m_wq_job_lck = this->m_wq_job->lock_run()) != workq_job::BUSY)
				break;		/* GUARD */
		}

		/* Take job away from single runq. */
		this->m_wq->m_runq.erase(this->m_wq->m_runq.iterator_to(*this->m_wq_job));

		break;
	}

	if (!this->is_locked()) {
		this->unlock();
		return false;
	} else
		assert(this->m_wq_job->is_running());
	return true;
}

bool
wq_run_lock::lock(workq_job& what) ILIAS_NET2_NOTHROW
{
	assert(!this->m_wq && !this->m_wq_job);

	this->m_commited = false;
	this->m_wq = what.get_workq();

	/* Acquire proper lock type on workq. */
	if (what.m_type & workq_job::TYPE_PARALLEL) {
		this->m_wq_lck = this->m_wq->lock_run_parallel();
		if (this->m_wq_lck != workq::RUN_PARALLEL) {
			this->unlock();
			return false;
		}
	} else {
		this->m_wq_lck = this->m_wq->lock_run();
		if (this->m_wq_lck != workq::RUN_SINGLE) {
			this->unlock();
			return false;
		}
	}

	/* Acquire run lock for the given job. */
	this->m_wq_job = &what;
	this->m_wq_job_lck = this->m_wq_job->lock_run();

	if (!this->is_locked()) {
		this->unlock();
		return false;
	} else
		assert(this->m_wq_job->is_running());

	/* Take job from the runqs. */
	this->m_wq->m_runq.erase(this->m_wq->m_runq.iterator_to(*this->m_wq_job));
	if (this->m_wq_job->m_type & workq_job::TYPE_PARALLEL)
		this->m_wq->m_p_runq.erase(this->m_wq->m_p_runq.iterator_to(*this->m_wq_job));

	return true;
}

bool
wq_run_lock::lock(workq_service& wqs) ILIAS_NET2_NOTHROW
{
	assert(!this->m_wq && !this->m_wq_job);

	/*
	 * Fetch a workq and hold on to it.
	 *
	 * Loop terminates when either we manage to lock a job on a workq,
	 * or when the runq is depleted.
	 */
	for (;;) {
		auto wq = wqs.m_wq_runq.pop_front_nowait();
		if (!wq)
			break;		/* GUARD */
		else if (this->lock(*wq)) {
			/* Acquired a job: workq may stay on the runq. */
			wqs.m_wq_runq.push_back(std::move(wq));
			wqs.wakeup();
			break;		/* GUARD */
		} else {
			/*
			 * No job acquired, workq is depleted and (automatically)
			 * removed from the runq:
			 * wq is unlinked when scope of the loop ends.
			 */
		}
	}
	return this->is_locked();
}


} /* namespace ilias::workq_detail */


void
workq_detail::workq_int::wait_unreferenced() const ILIAS_NET2_NOTHROW
{
	while (this->int_refcnt.load(std::memory_order_acquire) > 0)
		std::this_thread::yield();
}


workq_service_ptr
new_workq_service() throw (std::bad_alloc)
{
	return workq_service_ptr(new workq_service());
}

workq_service_ptr
new_workq_service(unsigned int threads) throw (std::bad_alloc)
{
	return workq_service_ptr(new workq_service(threads));
}


workq_job::workq_job(workq_ptr wq, unsigned int type) throw (std::invalid_argument) :
	m_type(type),
	m_run_gen(0),
	m_state(0),
	m_wq(std::move(wq))
{
	if (!this->m_wq)
		throw std::invalid_argument("workq_job: null workq");
	if ((type & TYPE_ONCE) && (type & TYPE_PERSIST))
		throw std::invalid_argument("workq_job: cannot create persistent job that only runs once");
	if ((type & TYPE_MASK) != type)
		throw std::invalid_argument("workq_job: invalid type (unrecognized flags)");
}

workq_job::~workq_job() ILIAS_NET2_NOTHROW
{
	assert(!(this->m_state.load(std::memory_order_relaxed) & STATE_RUNNING));
}

void
workq_job::activate(unsigned int flags) ILIAS_NET2_NOTHROW
{
	const auto s = this->m_state.fetch_or(STATE_ACTIVE, std::memory_order_relaxed);
	if (!(s & (STATE_RUNNING | STATE_ACTIVE)))
		this->get_workq()->job_to_runq(this);

	if (flags & ACT_IMMED) {
		workq_detail::wq_run_lock rlck(*this);
		if (rlck.is_locked()) {
			assert(rlck.get_wq_job().get() == this);
			rlck.commit();	/* XXX remove commit requirement? */
			this->run(rlck);
		}
	}
}

void
workq_job::deactivate() ILIAS_NET2_NOTHROW
{
	const auto gen = this->m_run_gen.load(std::memory_order_relaxed);
	auto s = this->m_state.fetch_and(~STATE_ACTIVE, std::memory_order_release);

	while ((s & STATE_RUNNING) &&
	    gen == this->m_run_gen.load(std::memory_order_relaxed)) {
		std::this_thread::yield();
		s = this->m_state.load(std::memory_order_relaxed);
	}
}

const workq_ptr&
workq_job::get_workq() const ILIAS_NET2_NOTHROW
{
	return this->m_wq;
}

const workq_service_ptr&
workq_job::get_workq_service() const ILIAS_NET2_NOTHROW
{
	return this->get_workq()->get_workq_service();
}

workq_job::run_lck
workq_job::lock_run() ILIAS_NET2_NOTHROW
{
	auto s = this->m_state.load(std::memory_order_relaxed);
	decltype(s) new_s;

	do {
		if (!(s & STATE_ACTIVE))
			return BUSY;
		if (s & STATE_RUNNING)
			return BUSY;
		if ((this->m_type & TYPE_ONCE) && (s & STATE_HAS_RUN))
			return BUSY;

		new_s = s | STATE_RUNNING;
		if (!(this->m_type & TYPE_PERSIST))
			new_s &= ~STATE_ACTIVE;
	} while (!this->m_state.compare_exchange_weak(s, new_s, std::memory_order_acquire, std::memory_order_relaxed));

	this->m_run_gen.fetch_add(1, std::memory_order_acquire);
	return RUNNING;
}

void
workq_job::unlock_run(workq_job::run_lck rl) ILIAS_NET2_NOTHROW
{
	switch (rl) {
	case RUNNING:
		{
			auto s = this->m_state.fetch_and(~STATE_RUNNING, std::memory_order_release);
			assert(s & STATE_RUNNING);
			if (this->m_type & TYPE_ONCE)
				return;
			if (s & STATE_ACTIVE)
				this->get_workq()->job_to_runq(this);
		}
		break;
	case BUSY:
		break;
	}
}


workq_detail::co_runnable::~co_runnable() ILIAS_NET2_NOTHROW
{
	return;
}

workq_detail::co_runnable::co_runnable(workq_ptr wq, unsigned int type) throw (std::invalid_argument) :
	workq_job(std::move(wq), type),
	m_runcount(0)
{
	/* Empty body. */
}

void
workq_detail::co_runnable::co_publish(workq_detail::wq_run_lock& rlck, std::size_t runcount) ILIAS_NET2_NOTHROW
{
	if (runcount > 0) {
		this->m_rlck = std::move(rlck);
		this->m_runcount.store(runcount, std::memory_order_acq_rel);
		this->get_workq_service()->co_to_runq(this, runcount);
	} else {
		/* Not publishing co-runnable, not eating lock, co-runnable will unlock on return. */
	}
}

void
workq_detail::co_runnable::unlock_run(workq_job::run_lck rl) ILIAS_NET2_NOTHROW
{
	switch (rl) {
	case RUNNING:
		return;	/* Handled by co_runnable::release, which will be called from co_run() as appropriate. */
	case BUSY:
		break;
	}
	this->workq_job::unlock_run(rl);
}

bool
workq_detail::co_runnable::release(std::size_t n) ILIAS_NET2_NOTHROW
{
	bool did_unlock = false;

	/*
	 * When release is called, the co-runnable cannot start more work.
	 * It must be unlinked from the co-runq.
	 * Note that this call will fail a lot, because multiple threads will attempt this operation
	 * but only one will succeed (which is fine, we simply don't want it to keep appearing on the
	 * co-runq).
	 *
	 * Note: this call must complete before the co-runnable ceases to run, otherwise a race
	 * could cause co-runnable insertion to fail when it is next activated.
	 */
	this->get_workq_service()->m_co_runq.erase(this->get_workq_service()->m_co_runq.iterator_to(*this));

	if (n > 0) {
		const std::size_t old = this->m_runcount.fetch_sub(n, std::memory_order_release);
		assert(old >= n);
		assert(this->m_rlck.is_locked());
		if (old == n) {
			this->m_rlck.unlock();
			did_unlock = true;
		}
	}
	return did_unlock;
}


workq::workq(workq_service_ptr wqs) throw (std::invalid_argument) :
	m_wqs(std::move(wqs)),
	m_run_single(false),
	m_run_parallel(0)
{
	if (!this->m_wqs)
		throw std::invalid_argument("workq: null workq service");
}

workq::~workq() ILIAS_NET2_NOTHROW
{
	assert(this->m_runq.empty());
	assert(!this->m_run_single.load(std::memory_order_acquire));
	assert(this->m_run_parallel.load(std::memory_order_acquire) == 0);
}

const workq_service_ptr&
workq::get_workq_service() const ILIAS_NET2_NOTHROW
{
	return this->m_wqs;
}

void
workq::job_to_runq(workq_detail::workq_intref<workq_job> j) ILIAS_NET2_NOTHROW
{
	bool activate = false;
	if ((j->m_type & workq_job::TYPE_PARALLEL) && this->m_p_runq.push_back(j))
		activate = true;
	if (this->m_runq.push_back(std::move(j)))
		activate = true;

	if (activate)
		this->get_workq_service()->wq_to_runq(this);
}

workq::run_lck
workq::lock_run() ILIAS_NET2_NOTHROW
{
	if (!this->m_run_single.exchange(true, std::memory_order_acquire))
		return RUN_SINGLE;
	this->m_run_parallel.fetch_add(1, std::memory_order_acquire);
	return RUN_PARALLEL;
}

workq::run_lck
workq::lock_run_parallel() ILIAS_NET2_NOTHROW
{
	this->m_run_parallel.fetch_add(1, std::memory_order_acquire);
	return RUN_PARALLEL;
}

void
workq::unlock_run(workq::run_lck rl) ILIAS_NET2_NOTHROW
{
	switch (rl) {
	case RUN_SINGLE:
		{
			const auto old_run_single = this->m_run_single.exchange(false, std::memory_order_release);
			assert(old_run_single);
		}
		break;
	case RUN_PARALLEL:
		{
			const auto old_run_parallel = this->m_run_parallel.fetch_sub(1, std::memory_order_release);
			assert(old_run_parallel > 0);
		}
		break;
	}
}

workq::run_lck
workq::lock_run_downgrade(workq::run_lck rl) ILIAS_NET2_NOTHROW
{
	switch (rl) {
	case RUN_SINGLE:
		{
			this->m_run_parallel.fetch_add(1, std::memory_order_acquire);
			const auto old_run_single = this->m_run_single.exchange(false, std::memory_order_release);
			assert(old_run_single);

			rl = RUN_PARALLEL;
		}
		break;
	case RUN_PARALLEL:
		break;
	}
	return rl;
}

bool
workq::aid(unsigned int count) ILIAS_NET2_NOTHROW
{
	unsigned int i;
	for (i = 0; i < count; ++i) {
		workq_detail::wq_run_lock rlck(*this);
		if (!rlck.is_locked())
			break;

		rlck.commit();
		rlck.get_wq_job()->run(rlck);
	}
	return (i > 0);
}


workq_service::workq_service() :
	m_workers([this]() -> bool { return !this->m_wq_runq.empty() || !this->m_co_runq.empty(); },
	    [this]() -> bool { return this->aid(32); })
{
	return;
}

workq_service::workq_service(unsigned int threads) :
	m_workers([this]() -> bool { return !this->m_wq_runq.empty() || !this->m_co_runq.empty(); },
	    [this]() -> bool { return this->aid(32); }, threads)
{
	return;
}

workq_service::~workq_service() ILIAS_NET2_NOTHROW
{
	assert(this->m_wq_runq.empty());
	assert(this->m_co_runq.empty());
}

void
workq_service::wq_to_runq(workq_detail::workq_intref<workq> wq) ILIAS_NET2_NOTHROW
{
	if (this->m_wq_runq.push_front(wq))
		this->wakeup();
}

void
workq_service::co_to_runq(workq_detail::workq_intref<workq_detail::co_runnable> co, unsigned int max_threads) ILIAS_NET2_NOTHROW
{
	assert(max_threads > 0);
	const bool pushback_succeeded = (this->m_co_runq.push_back(co));
	assert(pushback_succeeded);
	this->wakeup(max_threads);
}

void
workq_service::wakeup(unsigned int count) ILIAS_NET2_NOTHROW
{
	/* STUB */
}

workq_ptr
workq_service::new_workq() throw (std::bad_alloc)
{
	return workq_ptr(new workq(this));
}

bool
workq_service::aid(unsigned int count) ILIAS_NET2_NOTHROW
{
	using std::begin;
	using std::end;

	unsigned int i;
	auto co = begin(this->m_co_runq);
	for (i = 0; i < count; ++i) {
		/* Run co-runnables before workqs. */
		if (co != end(this->m_co_runq)) {
			do {
				if (co->co_run())
					++i;
			} while (i < count && co != end(this->m_co_runq));
			continue;
		}

		/* Run a workq. */
		workq_detail::wq_run_lock rlck(*this);
		if (!rlck.is_locked())
			break;	/* GUARD: No co-runnables, nor workqs available. */

		rlck.commit();
		rlck.get_wq_job()->run(rlck);

		/* Update co-routine iterator. */
		co = begin(this->m_co_runq);
	}

	return (i > 0);
}


namespace workq_detail {


void
wq_deleter::operator()(const workq_job* wqj) const ILIAS_NET2_NOTHROW
{
	wqj->get_workq()->m_runq.unlink_robust(wqj->get_workq()->m_runq.iterator_to(const_cast<workq_job&>(*wqj)));
	wqj->get_workq()->m_p_runq.unlink_robust(wqj->get_workq()->m_p_runq.iterator_to(const_cast<workq_job&>(*wqj)));
	const_cast<workq_job*>(wqj)->deactivate();

	/* XXX check if this job is being destroyed from within its own worker thread, then perform special handling. */

	/* Wait until the last reference to this job goes away. */
	wqj->wait_unreferenced();

	delete wqj;
}

void
wq_deleter::operator()(const workq* wq) const ILIAS_NET2_NOTHROW
{
	wq->get_workq_service()->m_wq_runq.unlink_robust(wq->get_workq_service()->m_wq_runq.iterator_to(const_cast<workq&>(*wq)));

	/* XXX check if this wq is being destroyed from within its own worker thread, then perform special handling. */

	/* Wait for the last internal reference to go away. */
	wq->wait_unreferenced();

	delete wq;
}

void
wq_deleter::operator()(const workq_service* wqs) const ILIAS_NET2_NOTHROW
{
	/* XXX check if this wqs is being destroyed from within its own worker thread, then perform special handling. */

	/* Wait for the last internal reference to go away. */
	wqs->wait_unreferenced();

	delete wqs;
}


} /* namespace ilias::workq_detail */


class ILIAS_NET2_LOCAL job_single :
	public workq_job
{
private:
	const std::function<void()> m_fn;

public:
	job_single(workq_ptr wq, std::function<void()> fn, unsigned int type = 0) throw (std::invalid_argument) :
		workq_job(std::move(wq), type),
		m_fn(std::move(fn))
	{
		if (!this->m_fn)
			throw std::invalid_argument("workq_job: functor invalid");
	}

	virtual ~job_single() ILIAS_NET2_NOTHROW;
	virtual void run(workq_detail::wq_run_lock&) ILIAS_NET2_NOTHROW OVERRIDE;
};

job_single::~job_single() ILIAS_NET2_NOTHROW
{
	return;
}

void
job_single::run(workq_detail::wq_run_lock&) ILIAS_NET2_NOTHROW
{
	this->m_fn();
}

workq_job_ptr
workq::new_job(unsigned int type, std::function<void()> fn) throw (std::bad_alloc, std::invalid_argument)
{
	return workq_job_ptr(new job_single(workq_ptr(this), std::move(fn), type));
}


class ILIAS_NET2_LOCAL coroutine_job :
	public workq_detail::co_runnable
{
private:
	typedef std::vector<std::function<void()> > co_list;

	const co_list m_coroutines;
	std::atomic<co_list::size_type> m_co_idx;

public:
	coroutine_job(workq_ptr ptr, std::vector<std::function<void()> > fns, unsigned int type) throw (std::invalid_argument) :
		workq_detail::co_runnable(std::move(ptr), type),
		m_coroutines(std::move(fns))
	{
		/* Validate co-routines. */
		if (this->m_coroutines.empty())
			throw std::invalid_argument("workq coroutine job: no functors");
		std::for_each(this->m_coroutines.begin(), this->m_coroutines.end(), [](const std::function<void()>& fn) {
			if (!fn)
				throw std::invalid_argument("workq coroutine job: invalid functor");
		});
	}

	virtual ~coroutine_job() ILIAS_NET2_NOTHROW;
	virtual void run(workq_detail::wq_run_lock&) ILIAS_NET2_NOTHROW OVERRIDE;
	virtual bool co_run() ILIAS_NET2_NOTHROW OVERRIDE;
};

coroutine_job::~coroutine_job() ILIAS_NET2_NOTHROW
{
	return;
}

void
coroutine_job::run(workq_detail::wq_run_lock& rlck) ILIAS_NET2_NOTHROW
{
	this->m_co_idx.store(0, std::memory_order_acq_rel);
	this->co_publish(rlck, this->m_coroutines.size());
}

bool
coroutine_job::co_run() ILIAS_NET2_NOTHROW
{
	std::size_t runcount = 0;
	for (co_list::size_type idx = this->m_co_idx.fetch_add(1, std::memory_order_acquire);
	    idx < this->m_coroutines.size();
	    idx = this->m_co_idx.fetch_add(1, std::memory_order_acquire)) {
		++runcount;
		this->m_coroutines[idx]();
	}
	this->release(runcount);
	return runcount > 0;
}

workq_job_ptr
workq::new_job(unsigned int type, std::vector<std::function<void()> > fn) throw (std::bad_alloc, std::invalid_argument)
{
	if (fn.empty())
		throw std::invalid_argument("new_job: empty co-routine");
	if (fn.size() == 1)
		return this->new_job(type, std::move(fn.front()));	/* Use simpler job type if there is only one function. */

	return workq_job_ptr(new coroutine_job(this, std::move(fn), type));
}


template<typename JobType>
class ILIAS_NET2_LOCAL job_once FINAL :
	public JobType
{
public:
	template<typename FN>
	job_once(workq_ptr ptr, FN&& fn) :
		JobType(std::move(ptr), std::forward<FN>(fn), workq_job::TYPE_ONCE)
	{
		if (this->m_type & workq_job::TYPE_ONCE)
			throw std::invalid_argument("job_once: TYPE_ONCE is implied");
	}

	virtual void
	run(workq_detail::wq_run_lock& rlck) ILIAS_NET2_NOTHROW OVERRIDE
	{
		/* Release internal reference to self. */
		workq_detail::wq_deleter expunge;
		expunge(this);
		/* Run the function. */
		this->JobType::run(rlck);
	}
};

void
workq::once(std::function<void()> fn) throw (std::bad_alloc, std::invalid_argument)
{
	/* Create a job that will run once and then kill itself. */
	workq_job_ptr j(new job_once<job_single>(this, std::move(fn)));

	/* Activate this job, so it will run. */
	j->activate();

	/* Keep this job alive until it has run. */
	j.release();
}

void
workq::once(std::vector<std::function<void()> > fns) throw (std::bad_alloc, std::invalid_argument)
{
	/* Create a job that will run once and then kill itself. */
	workq_job_ptr j(new job_once<coroutine_job>(workq_ptr(this), std::move(fns)));

	/* Activate this job, so it will run. */
	j->activate();	/* Never throws */

	/* Keep this job alive until it has run. */
	j.release();	/* Never throws */
}


} /* namespace ilias */
