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

#ifdef __OpenBSD__
#include <sched.h>
#else
#include <thread>
#endif


namespace ilias {
namespace workq_detail {


/*
 * wq_run_lock: lock a workq and job for execution.
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

	~wq_run_lock() ILIAS_NET2_NOTHROW
	{
		this->unlock();
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

	bool
	is_commited() const ILIAS_NET2_NOTHROW
	{
		return this->m_commited;
	}

	void
	commit() ILIAS_NET2_NOTHROW
	{
		assert(this->is_locked() && !this->is_commited());
		this->m_commited = true;
	}

	bool
	is_locked() const ILIAS_NET2_NOTHROW
	{
		return (this->m_wq_job_lck != workq_job::BUSY && this->get_wq() && this->get_wq_job());
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


#if HAS_DELETED_FN
	wq_run_lock(const wq_run_lock&) = delete;
	wq_run_lock& operator=(const wq_run_lock&) = delete;
#else
private:
	wq_run_lock(const wq_run_lock&);
	wq_run_lock& operator=(const wq_run_lock&);
#endif
};

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
	while (this->int_refcnt.load(std::memory_order_acquire) > 0) {
#ifdef __OpenBSD__
		sched_yield();
#else
		std::this_thread::yield();
#endif
	}
}


workq_service_ptr
new_workq_service() throw (std::bad_alloc)
{
	return workq_service_ptr(new workq_service());
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
			this->run();
			rlck.commit();
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
#ifdef __OpenBSD__
		sched_yield();
#else
		std::this_thread::yield();
#endif
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
workq_detail::co_runnable::run() ILIAS_NET2_NOTHROW
{
	const std::size_t runcount = this->size();

	this->m_runcount.store(this->size());
	this->get_workq_service()->co_to_runq(this, runcount);
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

void
workq_detail::co_runnable::release(std::size_t n) ILIAS_NET2_NOTHROW
{
	if (n > 0) {
		const std::size_t old = this->m_runcount.fetch_sub(n, std::memory_order_release);
		assert(old >= n);
		if (old == n)
			this->workq_job::unlock_run(RUNNING);
	}
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

void
workq::aid(unsigned int count) ILIAS_NET2_NOTHROW
{
	for (unsigned int i = 0; i < count; ++i) {
		workq_detail::wq_run_lock rlck(*this);
		if (!rlck.is_locked())
			break;

		rlck.get_wq_job()->run();
		rlck.commit();
	}
}


workq_service::workq_service() ILIAS_NET2_NOTHROW
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
workq_service::co_to_runq(workq_detail::workq_intref<workq_detail::co_runnable> co, unsigned int n) ILIAS_NET2_NOTHROW
{
	assert(n > 0);
	if (this->m_co_runq.push_back(co))
		this->wakeup(n);
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

void
workq_service::aid(unsigned int count) ILIAS_NET2_NOTHROW
{
	for (unsigned int i = 0; i < count; ++i) {
		workq_detail::wq_run_lock rlck(*this);
		if (!rlck.is_locked())
			break;

		rlck.get_wq_job()->run();
		rlck.commit();
	}
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
	virtual void run() ILIAS_NET2_NOTHROW OVERRIDE;
};

job_single::~job_single() ILIAS_NET2_NOTHROW
{
	return;
}

void
job_single::run() ILIAS_NET2_NOTHROW
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
	virtual void run() ILIAS_NET2_NOTHROW OVERRIDE;
	virtual void co_run() ILIAS_NET2_NOTHROW OVERRIDE;
	virtual std::size_t size() const ILIAS_NET2_NOTHROW OVERRIDE;
};

coroutine_job::~coroutine_job() ILIAS_NET2_NOTHROW
{
	return;
}

void
coroutine_job::run() ILIAS_NET2_NOTHROW
{
	this->m_co_idx.store(0, std::memory_order_acq_rel);
	this->co_runnable::run();
}

void
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
}

std::size_t
coroutine_job::size() const ILIAS_NET2_NOTHROW
{
	return this->m_coroutines.size();
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
	run() ILIAS_NET2_NOTHROW OVERRIDE
	{
		/* Release internal reference to self. */
		workq_detail::wq_deleter expunge;
		expunge(this);
		/* Run the function. */
		this->JobType::run();
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
