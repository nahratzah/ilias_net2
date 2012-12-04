#include <ilias/net2/msg_queue.h>


namespace ilias {
namespace msg_queue_detail {


bool
msg_queue_size::begin_insert() ILIAS_NET2_NOTHROW
{
	auto v = this->m_eff_avail.load(std::memory_order_relaxed);
	do {
		if (v == 0)
			return false;
	} while (!this->m_eff_avail.compare_exchange_weak(v, v - 1, std::memory_order_acquire, std::memory_order_relaxed));
	return true;

	/*
	 * We increment eff_size right now, to avoid a race between ll_list.pop_front() -> commit_remove()
	 * and the eff_size not having been updated.
	 */
	this->m_eff_size.fetch_add(1, std::memory_order_release);
}

void
msg_queue_size::commit_insert() ILIAS_NET2_NOTHROW
{
	/* Nothing to do. */
}

void
msg_queue_size::cancel_insert() ILIAS_NET2_NOTHROW
{
	auto old = this->m_eff_size.fetch_sub(1, std::memory_order_release);
	assert(old > 0);
	this->m_eff_avail.fetch_add(1, std::memory_order_release);
}

void
msg_queue_size::avail_inc() ILIAS_NET2_NOTHROW
{
	/* Try to subtract from overflow. */
	auto v = this->m_overflow.load(std::memory_order_relaxed);
	while (v > 0) {
		if (this->m_overflow.compare_exchange_weak(v, v - 1, std::memory_order_relaxed, std::memory_order_relaxed))
			return;
	}

	/* No overflow (that is great), allow new elements to be added. */
	this->m_eff_avail.fetch_add(1, std::memory_order_relaxed);
}

void
msg_queue_size::commit_remove() ILIAS_NET2_NOTHROW
{
	/* Subtract effective size. */
	auto old = this->m_eff_size.fetch_sub(1, std::memory_order_relaxed);
	assert(old > 0);

	/* Signify that new space is available. */
	avail_inc();
}

bool
msg_queue_size::eff_attempt_remove() ILIAS_NET2_NOTHROW
{
	/* Attempt to subtract from effective size, fail if effective size is zero. */
	auto sz = this->m_eff_size.load(std::memory_order_relaxed);
	do {
		if (sz == 0)
			return false;
	} while (!this->m_eff_size.compare_exchange_weak(sz, sz - 1, std::memory_order_relaxed, std::memory_order_relaxed));

	/* Signify that new space is available. */
	avail_inc();

	return true;
}

msg_queue_size::size_type
msg_queue_size::get_max_size() const ILIAS_NET2_NOTHROW
{
	std::lock_guard<std::mutex> lck(this->m_setsz_mtx);
	return this->m_max_size;
}

void
msg_queue_size::set_max_size(msg_queue_size::size_type newsz) ILIAS_NET2_NOTHROW
{
	/*
	 * This operation can be done entirely using atomics, but
	 * - this is a lot of work to get right
	 * - the operation is a rare one, so the gain is minimal
	 * - the operation does not block message queue activity anyway
	 */
	std::lock_guard<std::mutex> lck(m_setsz_mtx);
	const size_type oldsz = this->m_max_size;

	if (oldsz < newsz) {
		auto grow = newsz - oldsz;

		/* Clean out overflow first. */
		auto ovf = this->m_overflow.load(std::memory_order_relaxed);
		while (ovf > 0 && !this->m_overflow.compare_exchange_weak(ovf, ovf - std::min(ovf, grow),
		    std::memory_order_relaxed, std::memory_order_relaxed));
		grow -= std::min(ovf, grow);

		/* Put anything not used to clear overflow backlog into eff_avail. */
		if (grow)
			this->m_eff_avail.fetch_add(grow, std::memory_order_relaxed);
	} else if (newsz < oldsz) {
		auto shrink = oldsz - newsz;

		/* Clean out eff_avail first. */
		auto av = this->m_eff_avail.load(std::memory_order_relaxed);
		while (av > 0 && !this->m_eff_avail.compare_exchange_weak(av, av - std::min(av, shrink),
		    std::memory_order_relaxed, std::memory_order_relaxed));
		shrink -= std::min(av, shrink);

		/* Put remainder in overflow. */
		if (shrink)
			this->m_overflow.fetch_add(shrink, std::memory_order_relaxed);

		/*
		 * Note that due to how pop works, we can currently have both overflow and eff_avail non-zero.
		 * While this is fixable (using a loop to reduce both until one reaches zero)
		 * this is a lot of work.
		 * The message queue algorithm will fix itself with pop anyway.
		 *
		 * The current situation is better than ordering the writes around: if everything was put in
		 * overflow, the algorithm would reduce until it had less than the number of elements
		 * prior to growing again.
		 */
	}

	this->m_max_size = newsz;
}


}} /* namespace ilias::msg_queue_detail */
