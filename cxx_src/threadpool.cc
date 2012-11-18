#include <ilias/net2/threadpool.h>

namespace ilias {


threadpool::threadpool(std::function<bool()> pred, std::function<bool()> worker, unsigned int threads) :
	m_factory([pred, worker](threadpool& self) -> thread_ptr {
		return thread_ptr(new thread(self, pred, worker));
	    }),
	m_idle(new idle_threads),
	m_all()
{
	for (unsigned int i = 0; i < threads; ++i)
		m_all.push_back(m_factory(*this));
}

/*
 * XXX this should be a delegating constructor, but gcc-4.6.2 doesn't have those yet
 * (and I'm sure many other compilers lack this as well).
 */
threadpool::threadpool(std::function<bool()> pred, std::function<bool()> worker) :
	m_factory([pred, worker](threadpool& self) -> thread_ptr {
		return thread_ptr(new thread(self, pred, worker));
	    }),
	m_idle(new idle_threads),
	m_all()
{
	const unsigned int threads = std::max(1U, std::thread::hardware_concurrency());
	for (unsigned int i = 0; i < threads; ++i)
		m_all.push_back(m_factory(*this));
}

threadpool::~threadpool() ILIAS_NET2_NOTHROW
{
	for (auto& thr : m_all) {
		thr->kill();
		thr->join();
	}
	this->m_all.clear();
}


threadpool::thread::thread(threadpool& tp, const std::function<bool()>& pred, const std::function<bool()>& worker) :
	m_state(STATE_ACTIVE),
	m_sleep_mtx(),
	m_wakeup(),
	m_idle(*tp.m_idle),
	m_self(&thread::run, this, pred, worker)
{
	/* Empty body. */
}

void
threadpool::thread::do_sleep(const std::function<bool()>& pred) ILIAS_NET2_NOTHROW
{
	int pstate = STATE_ACTIVE;

	/* Move to sleep-test state. */
	if (this->m_state.compare_exchange_strong(pstate, STATE_SLEEP_TEST,
	    std::memory_order_acquire, std::memory_order_relaxed)) {
		pstate = STATE_SLEEP_TEST;

		/*
		 * Publish idle state prior to testing predicate:
		 * if we publish after, there is a race where a wakeup will be missed,
		 * between the point the idle test completes and the publish operation
		 * happens.
		 */
		publish_idle pub(*this);

		if (pred()) {
			/* Don't go to sleep. */
			this->m_state.compare_exchange_strong(pstate, STATE_ACTIVE,
			    std::memory_order_acquire, std::memory_order_relaxed);
		} else {
			/* Go to sleep: predicate test failed to indicate more work is available. */
			std::unique_lock<std::mutex> slck(this->m_sleep_mtx);
			if (this->m_state.compare_exchange_strong(pstate, STATE_SLEEP,
			    std::memory_order_acq_rel, std::memory_order_relaxed)) {
				/* Sleep until our state changes to either active or dying. */
				this->m_wakeup.wait(slck, [this]() -> bool {
					return (this->get_state() != STATE_SLEEP);
				    });
			}
		}
	}

	/* Ensure state is valid on exit. */
	const auto end_state = this->get_state();
	assert(end_state == STATE_ACTIVE || end_state == STATE_DYING);
}

void
threadpool::thread::run(const std::function<bool()>& pred, const std::function<bool()>& functor)
{
	for (;;) {
		do {
			if (this->get_state() == STATE_DYING)
				return;
		} while (functor());
		do_sleep(pred);
	}
}

bool
threadpool::thread::wakeup() ILIAS_NET2_NOTHROW
{
	int pstate = STATE_SLEEP;

	/* Change from sleep to active. */
	while (!this->m_state.compare_exchange_weak(pstate, STATE_ACTIVE,
	    std::memory_order_acquire, std::memory_order_relaxed)) {
		/* Failure: worker is not sleeping. */
		if (pstate != STATE_SLEEP || pstate != STATE_SLEEP_TEST)
			return false;
	}

	/* Signal wakeup. */
	if (pstate == STATE_SLEEP) {
		std::lock_guard<std::mutex> slck(this->m_sleep_mtx);
		this->m_idle.erase_element(this->m_idle.iterator_to(*this));
		this->m_wakeup.notify_one();
	}
	return true;
}

bool
threadpool::thread::kill() ILIAS_NET2_NOTHROW
{
	int pstate = this->m_state.exchange(STATE_DYING, std::memory_order_release);

	/* Signal wakeup. */
	if (pstate == STATE_SLEEP) {
		std::lock_guard<std::mutex> slck(this->m_sleep_mtx);
		this->m_idle.erase_element(this->m_idle.iterator_to(*this));
		this->m_wakeup.notify_one();
	}

	return (pstate != STATE_DYING);
}

void
threadpool::thread::join() ILIAS_NET2_NOTHROW
{
	this->m_self.join();
}

threadpool::thread::~thread() ILIAS_NET2_NOTHROW
{
	return;
}


} /* namespace ilias */
