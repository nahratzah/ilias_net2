#include <ilias/net2/ll.h>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace ilias {


class ILIAS_NET2_LOCAL threadpool
{
private:
	struct idle_tag {};
	class thread;
	typedef std::unique_ptr<thread> thread_ptr;
	typedef std::vector<thread_ptr> all_threads;
	typedef ll_list<ll_base<thread, idle_tag> > idle_threads;

	std::function<thread_ptr(threadpool&, unsigned int)> m_factory;
	std::unique_ptr<idle_threads> m_idle;
	all_threads m_all;

	ILIAS_NET2_LOCAL static thread_ptr
	factory_impl(threadpool& self, unsigned int idx,
	    const std::function<bool()>& pred, const std::function<bool()>& work);

public:
	ILIAS_NET2_EXPORT threadpool(std::function<bool()> pred, std::function<bool()> work,
	    unsigned int threads = std::max(1U, std::thread::hardware_concurrency()));
	ILIAS_NET2_EXPORT threadpool(threadpool&& o) ILIAS_NET2_NOTHROW;
	ILIAS_NET2_EXPORT ~threadpool() ILIAS_NET2_NOTHROW;

	ILIAS_NET2_EXPORT bool curthread_is_threadpool() ILIAS_NET2_NOTHROW;


#if HAS_DELETED_FN
	threadpool() = delete;
	threadpool(const threadpool&) = delete;
	threadpool& operator=(const threadpool&) = delete;
#else
private:
	threadpool();
	threadpool(const threadpool&);
	threadpool& operator=(const threadpool&);
#endif
};


class ILIAS_NET2_LOCAL threadpool::thread FINAL :
	public ll_base_hook<threadpool::idle_tag>
{
public:
	/*
	 * DFA.  Allowed transisitions:
	 *             -> { ACTIVE }
	 * ACTIVE      -> { SLEEP_TEST, DYING, SUICIDE }
	 * SLEEP_TEST  -> { ACTIVE, SLEEP, DYING, SUICIDE }
	 * SLEEP       -> { ACTIVE, DYING, SUICIDE }
	 * DYING       -> {  }
	 * SUICIDE     -> {  }
	 *
	 * Const outside class, since gcc 4.6.2 blows up during link stage.
	 */
	static const int STATE_ACTIVE;
	static const int STATE_SLEEP_TEST;
	static const int STATE_SLEEP;
	static const int STATE_DYING;	/* Worker died and needs to be joined. */
	static const int STATE_SUICIDE;	/* Worker killed itself and detached. */

	enum kill_result {
		KILL_TWICE,	/* Was already dying. */
		KILL_OK,	/* Was killed by current invocation. */
		KILL_SUICIDE	/* Call to kill was suicide. */
	};

private:
	class publish_idle
	{
	private:
		thread& m_self;

	public:
		publish_idle(thread& s) ILIAS_NET2_NOTHROW;
		~publish_idle() ILIAS_NET2_NOTHROW;


#if HAS_DELETED_FN
		publish_idle() = delete;
		publish_idle(const publish_idle&) = delete;
		publish_idle& operator=(const publish_idle&) = delete;
#else
	private:
		publish_idle();
		publish_idle(const publish_idle&);
		publish_idle& operator=(const publish_idle&);
#endif
	};

	std::atomic<int> m_state;
	std::mutex m_sleep_mtx;
	std::condition_variable m_wakeup;

public:
	idle_threads& m_idle;
	const unsigned int m_idx;
	std::thread m_self;	/* Must be the last variable in this class. */

	int
	get_state() const ILIAS_NET2_NOTHROW
	{
		return this->m_state.load(std::memory_order_relaxed);
	}

private:
	ILIAS_NET2_LOCAL void do_sleep(const std::function<bool()>& pred) ILIAS_NET2_NOTHROW;
	ILIAS_NET2_LOCAL std::unique_ptr<threadpool::thread> run(const std::function<bool()>& pred,
	    const std::function<bool()>& functor) ILIAS_NET2_NOTHROW;

public:
	thread(threadpool& tp, unsigned int idx,
	    const std::function<bool()>& pred, const std::function<bool()>& worker) :
		m_state(STATE_ACTIVE),
		m_sleep_mtx(),
		m_wakeup(),
		m_idle(*tp.m_idle),
		m_idx(idx),
		m_self(&thread::run, this, pred, worker)
	{
		/* Empty body. */
	}

	bool wakeup() ILIAS_NET2_NOTHROW;
	kill_result kill() ILIAS_NET2_NOTHROW;
	void join() ILIAS_NET2_NOTHROW;
	~thread() ILIAS_NET2_NOTHROW;

	static thread*& tls_self() ILIAS_NET2_NOTHROW;

	std::thread::id
	get_id() const ILIAS_NET2_NOTHROW
	{
		return this->m_self.get_id();
	}


#if HAS_DELETED_FN
	thread() = delete;
	thread(const thread&) = delete;
	thread& operator=(const thread&) = delete;
#else
private:
	thread();
	thread(const thread&);
	thread& operator=(const thread&);
#endif
};


inline
threadpool::thread::publish_idle::publish_idle(thread& s) ILIAS_NET2_NOTHROW :
	m_self(s)
{
	this->m_self.m_idle.push_back(this->m_self);
}

inline
threadpool::thread::publish_idle::~publish_idle() ILIAS_NET2_NOTHROW
{
	this->m_self.m_idle.erase_element(this->m_self.m_idle.iterator_to(this->m_self));
}


} /* namespace ilias */
