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


namespace ilias {


template<typename Type>
class workq_int_pointer
{
public:
	typedef Type element_type;
	typedef element_type* pointer;
	typedef element_type& reference;

private:
	pointer m_ptr;

public:
	workq_int_pointer() ILIAS_NET2_NOTHROW :
		m_ptr(nullptr)
	{
		return;
	}

	workq_int_pointer(std::nullptr_t, bool = true) ILIAS_NET2_NOTHROW :
		m_ptr(nullptr)
	{
		return;
	}

	workq_int_pointer(const workq_int_pointer& o) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(workq_int_acquire(*this->m_ptr))) :
		m_ptr(nullptr)
	{
		this->reset(o);
	}

#if HAS_RVALUE_REF
	workq_int_pointer(workq_int_pointer&& o) ILIAS_NET2_NOTHROW :
		m_ptr(nullptr)
	{
		std::swap(this->m_ptr, o.m_ptr);
	}
#endif

	workq_int_pointer(pointer p, bool do_acquire = true) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(workq_int_acquire(*this->m_ptr))) :
		m_ptr(nullptr)
	{
		this->reset(p, do_acquire);
	}

	~workq_int_pointer() ILIAS_NET2_NOTHROW_CND_TEST(noexcept(workq_int_release(*this->m_ptr)))
	{
		this->reset();
	}

	void
	reset() ILIAS_NET2_NOTHROW_CND_TEST(noexcept(workq_int_release(*this->m_ptr)))
	{
		if (this->m_ptr) {
			workq_int_release(*this->m_ptr);
			this->m_ptr = nullptr;
		}
	}

	void
	reset(const workq_int_pointer& o) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(workq_int_release(*this->m_ptr)) && noexcept(workq_int_acquire(*this->m_ptr)))
	{
		const pointer old = this->m_ptr;
		if (o.m_ptr) {
			workq_int_acquire(*o.m_ptr);
			this->m_ptr = o.m_ptr;
		} else
			this->m_ptr = nullptr;

		if (old)
			workq_int_release(*old);
	}

#if HAS_RVALUE_REF
	void
	reset(workq_int_pointer&& o) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(workq_int_release(*this->m_ptr)))
	{
		const pointer old = this->m_ptr;
		this->m_ptr = o.m_ptr;
		o.m_ptr = nullptr;

		if (old)
			workq_int_release(*old);
	}
#endif

	void
	reset(pointer p, bool do_acquire = true) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(workq_int_release(*this->m_ptr)) && noexcept(workq_int_acquire(*this->m_ptr)))
	{
		const pointer old = this->m_ptr;
		if (p) {
			if (do_acquire)
				workq_int_acquire(*p);
			this->m_ptr = p;
		} else
			this->m_ptr = nullptr;

		if (old)
			workq_int_release(*old);
	}

	template<typename U>
	void
	reset(const workq_int_pointer<U>& o) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(workq_int_release(*this->m_ptr)) && noexcept(workq_int_acquire(*this->m_ptr)))
	{
		this->reset(o.get(), true);
	}

#if HAS_RVALUE_REF
	template<typename U>
	void
	reset(workq_int_pointer<U>&& o) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(workq_int_release(*this->m_ptr)))
	{
		this->reset(o.release(), false);
	}
#endif

	void
	swap(workq_int_pointer& rv) ILIAS_NET2_NOTHROW
	{
		using std::swap;
		swap(this->m_ptr, rv.m_ptr);
	}

	friend void
	swap(workq_int_pointer& lhs, workq_int_pointer& rhs) ILIAS_NET2_NOTHROW
	{
		lhs.swap(rhs);
	}

	workq_int_pointer&
	operator=(std::nullptr_t) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(workq_int_release(*this->m_ptr)))
	{
		this->reset();
		return *this;
	}

	workq_int_pointer&
	operator=(const workq_int_pointer& o) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(workq_int_release(*this->m_ptr)) && noexcept(workq_int_acquire(*this->m_ptr)))
	{
		this->reset(o);
		return *this;
	}

#if HAS_RVALUE_REF
	workq_int_pointer&
	operator=(workq_int_pointer&& o) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(workq_int_release(*this->m_ptr)))
	{
		this->reset(o);
		return *this;
	}
#endif

	workq_int_pointer&
	operator=(pointer p) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(workq_int_release(*this->m_ptr)) && noexcept(workq_int_acquire(*this->m_ptr)))
	{
		this->reset(p);
		return *this;
	}

	bool
	operator==(const workq_int_pointer& o) const ILIAS_NET2_NOTHROW
	{
		return (this->get() == o.get());
	}

	template<typename U>
	bool
	operator==(const workq_int_pointer<U>& o) const ILIAS_NET2_NOTHROW
	{
		return (this->get() == o.get());
	}

	template<typename Ptr>
	bool
	operator==(Ptr* p) const ILIAS_NET2_NOTHROW
	{
		return (this->get() == p);
	}

	template<typename U>
	bool
	operator!=(const U& o) const ILIAS_NET2_NOTHROW
	{
		return !(*this == o);
	}

	explicit operator bool() const ILIAS_NET2_NOTHROW
	{
		return this->get();
	}

	pointer
	get() const ILIAS_NET2_NOTHROW
	{
		return this->m_ptr;
	}

	pointer
	release() ILIAS_NET2_NOTHROW
	{
		const pointer rv = this->m_ptr;
		this->m_ptr = nullptr;
		return rv;
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
};


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

	/* Assign and lock job. */
	bool
	lock(job& j, bool acquire_ref = true) ILIAS_NET2_NOTHROW
	{
		assert(!this->locked());

		this->m_ptr.reset(&j, acquire_ref);
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
			if ((old & job::STATE_RUNNING) || !(old & job::STATE_ACTIVE))
				return false;
			set = old | job::STATE_RUNNING;
			if (!(this->m_ptr->m_type & job::TYPE_PERSIST))
				set &= ~job::STATE_ACTIVE;
		} while (!this->m_ptr->m_state.compare_exchange_weak(old, set,
		    std::memory_order_acquire, std::memory_order_relaxed));

		this->m_locked = true;
		return true;
	}

	void
	unlock() ILIAS_NET2_NOTHROW
	{
		assert(this->m_locked);
		this->m_ptr->clear_running();
		this->m_ptr.reset();
	}

	RVALUE(workq_int_pointer<job>)
	release() ILIAS_NET2_NOTHROW
	{
		workq_int_pointer<job> rv;
		if (this->m_locked) {
			this->m_locked = false;
			this->m_ptr.swap(rv);
		}
		return MOVE(rv);
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

/* Returns a job, having marked it runnable. */
workq::runnable_job
workq::get_runnable_job() ILIAS_NET2_NOTHROW
{
	runnable_job rj;
	runq_list::unlink_wait j;

	while ((j = this->runq.pop_front_nowait())) {
		/* Move ownership (int refcnt) from list to pointer. */
		const workq_int_pointer<job> ptr(j.get(), false);

		if (rj.lock(*ptr))
			return std::move(rj);

		j.release();
	}

	return std::move(rj);
}

void
workq::job::clear_running() ILIAS_NET2_NOTHROW
{
	const auto old = this->m_state.fetch_and(~STATE_RUNNING, std::memory_order_release);
	assert(old & STATE_RUNNING);
	if (old & STATE_ACTIVE) {
		if (this->get_workq().runq.push_back(*this))
			workq_int_acquire(*this);
	}
}

workq::job::~job() ILIAS_NET2_NOTHROW
{
	return;
}


void
workq::single_job::do_run(runnable_job&) ILIAS_NET2_NOTHROW
{
	this->fn();
}


void
workq::coroutine_job::do_run(runnable_job& rj) ILIAS_NET2_NOTHROW
{
	/* XXX reference counting in this function is suspect! */
	assert(!this->fn.empty());
	const fn_list::size_type sz = this->fn.size();

	this->m_idx.store(0, std::memory_order_acquire);
	this->m_incomplete.store(sz, std::memory_order_acquire);

	workq_service& wqs = this->get_workq_service();
	wqs.activate(*this, rj);
	wqs.wakeup(sz - 1);
}


void
workq::coroutine_job::workq_service_coroutines::activate(coroutine_job& cj, runnable_job& rj) ILIAS_NET2_NOTHROW
{
	workq_int_pointer<job> p = rj.release();
	const bool enqueue = this->m_coroutines.push_back(cj);
	assert(enqueue);
	p.release();
}

std::pair<workq_int_pointer<workq::coroutine_job>, workq::coroutine_job::fn_list::size_type>
workq::coroutine_job::workq_service_coroutines::get_coroutine() ILIAS_NET2_NOTHROW
{
	std::pair<workq_int_pointer<coroutine_job>, fn_list::size_type> rv;

	for (coroutine_list::iterator cr_iter = this->m_coroutines.begin();
	    cr_iter != this->m_coroutines.end();
	    cr_iter = this->unlink_coroutine(MOVE(cr_iter))) {
		rv.second = cr_iter->m_idx.fetch_add(1, std::memory_order_acquire);
		if (rv.second < cr_iter->fn.size()) {
			rv.first = &*cr_iter;
			break;
		}
	}

	return MOVE(rv);
}

/*
 * Ensures the co-routine pointed to by the iterator is removed from the list and
 * returns its successor.
 */
RVALUE(workq::coroutine_job::workq_service_coroutines::coroutine_list::iterator)
workq::coroutine_job::workq_service_coroutines::unlink_coroutine(
    RVALUE_REF(workq::coroutine_job::workq_service_coroutines::coroutine_list::iterator) cr_iter) ILIAS_NET2_NOTHROW
{
	return this->m_coroutines.erase_and_dispose(cr_iter, [](coroutine_job* j) {
		workq_int_release(*j);
	});
}

/*
 * Unlinks the coroutine from the list of runnable co-routines.
 * Returns pointer with ownership on success, nullptr on failure.
 */
RVALUE(workq_int_pointer<workq::coroutine_job>)
workq::coroutine_job::workq_service_coroutines::unlink_coroutine(workq::coroutine_job& crj) ILIAS_NET2_NOTHROW
{
	workq_int_pointer<coroutine_job> ptr = nullptr;
	coroutine_list::iterator cr_iter = this->m_coroutines.iterator_to(crj);
	this->m_coroutines.erase_and_dispose(cr_iter, [&ptr](coroutine_job* j) {
		ptr.reset(j, false);
	});
	return MOVE(ptr);
}

bool
workq::coroutine_job::workq_service_coroutines::run_coroutine() ILIAS_NET2_NOTHROW
{
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
		this->m_coroutines.erase(this->m_coroutines.iterator_to(*crj.first));
		/* Clear running bit. */
		crj.first->clear_running();
	}

	/* We ran a co-routine. */
	return true;
}


} /* namespace ilias */
