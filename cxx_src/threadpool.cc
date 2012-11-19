#include <ilias/net2/threadpool.h>

namespace ilias {


threadpool::thread*&
threadpool::thread::tls_self() ILIAS_NET2_NOTHROW
{
	static THREAD_LOCAL threadpool::thread* tls;
	return tls;
}


threadpool::threadpool(std::function<bool()> pred, std::function<bool()> worker, unsigned int threads) :
	m_factory([pred, worker](threadpool& self, unsigned int idx) -> thread_ptr {
		return thread_ptr(new thread(self, idx, pred, worker));
	    }),
	m_idle(new idle_threads),
	m_all()
{
	for (unsigned int i = 0; i < threads; ++i)
		m_all.push_back(m_factory(*this, i));
}

/*
 * XXX this should be a delegating constructor, but gcc-4.6.2 doesn't have those yet
 * (and I'm sure many other compilers lack this as well).
 */
threadpool::threadpool(std::function<bool()> pred, std::function<bool()> worker) :
	m_factory([pred, worker](threadpool& self, unsigned int idx) -> thread_ptr {
		return thread_ptr(new thread(self, idx, pred, worker));
	    }),
	m_idle(new idle_threads),
	m_all()
{
	const unsigned int threads = std::max(1U, std::thread::hardware_concurrency());
	for (unsigned int i = 0; i < threads; ++i)
		m_all.push_back(m_factory(*this, i));
}

bool
threadpool::curthread_is_threadpool() ILIAS_NET2_NOTHROW
{
	const thread* t = thread::tls_self();
	return (t && &t->m_idle == this->m_idle.get());
}

threadpool::~threadpool() ILIAS_NET2_NOTHROW
{
	for (auto& thr : m_all) {
		switch (thr->kill()) {
		case thread::KILL_OK:
			thr->join();
			break;
		case thread::KILL_SUICIDE:
			thr.release();	/* Thread will free itself. */
			break;
		default:
			std::terminate();
		}
	}
	this->m_all.clear();
}


class threadpool::thread::publish_idle
{
private:
	thread& m_self;

public:
	publish_idle(thread& s) ILIAS_NET2_NOTHROW :
		m_self(s)
	{
		this->m_self.m_idle.push_back(this->m_self);
	}

	~publish_idle() ILIAS_NET2_NOTHROW
	{
		this->m_self.m_idle.erase_element(this->m_self.m_idle.iterator_to(this->m_self));
	}


#if HAS_DELETED_FN
	publish_idle(const publish_idle&) = delete;
	publish_idle& operator=(const publish_idle&) = delete;
#else
private:
	publish_idle(const publish_idle&);
	publish_idle& operator=(const publish_idle&);
#endif
};

threadpool::thread::thread(threadpool& tp, unsigned int idx, const std::function<bool()>& pred, const std::function<bool()>& worker) :
	m_state(STATE_ACTIVE),
	m_sleep_mtx(),
	m_wakeup(),
	m_idle(*tp.m_idle),
	m_idx(idx),
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
	assert(end_state == STATE_ACTIVE || end_state == STATE_DYING || end_state == STATE_SUICIDE);
}

std::unique_ptr<threadpool::thread>
threadpool::thread::run(const std::function<bool()>& pred, const std::function<bool()>& functor)
{
	std::unique_ptr<threadpool::thread> cyanide;	/* Used to pass this to parent in order for it to clean up. */

	struct tls_storage
	{
		tls_storage(thread* self) ILIAS_NET2_NOTHROW
		{
			assert(self);
			assert(!tls_self());
			tls_self() = self;
		}

		~tls_storage() ILIAS_NET2_NOTHROW
		{
			assert(tls_self());
			tls_self() = nullptr;
		}
	};


	{
		/* Publish thread, so we can detect suicide cases. */
		tls_storage identification(this);

		while (this->get_state() == STATE_ACTIVE) {
			if (!functor())
				do_sleep(pred);
		}
	}

	/* Swallow the pill to kill ourselves. */
	if (this->get_state() == STATE_SUICIDE)
		cyanide.reset(this);
	return cyanide;
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

threadpool::thread::kill_result
threadpool::thread::kill() ILIAS_NET2_NOTHROW
{
	const int setstate = (this->get_id() == std::this_thread::get_id() ?
	    STATE_SUICIDE : STATE_DYING);

	int pstate = STATE_ACTIVE;
	while (!this->m_state.compare_exchange_weak(pstate, setstate,
	    std::memory_order_release, std::memory_order_relaxed)) {
		if (pstate == STATE_DYING || pstate == STATE_SUICIDE)
			return KILL_TWICE;
	}

	/* Signal wakeup. */
	if (pstate == STATE_SLEEP) {
		std::lock_guard<std::mutex> slck(this->m_sleep_mtx);
		this->m_idle.erase_element(this->m_idle.iterator_to(*this));
		this->m_wakeup.notify_one();
	}

	if (setstate == STATE_SUICIDE)
		this->m_self.detach();	/* Will destroy this on thread finish. */

	return (setstate == STATE_SUICIDE ? KILL_SUICIDE : KILL_OK);
}

void
threadpool::thread::join() ILIAS_NET2_NOTHROW
{
	assert(this->get_state() == STATE_DYING);
	this->m_self.join();
}

threadpool::thread::~thread() ILIAS_NET2_NOTHROW
{
	return;
}


} /* namespace ilias */
