#include <ilias/net2/ll.h>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <type_traits>
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

public:
	ILIAS_NET2_EXPORT threadpool(std::function<bool()>, const std::function<bool()>, unsigned int threads);
	ILIAS_NET2_EXPORT threadpool(std::function<bool()>, const std::function<bool()>);

	ILIAS_NET2_EXPORT threadpool(threadpool&& o) ILIAS_NET2_NOTHROW :
		m_factory(std::move(o.m_factory)),
		m_idle(std::move(o.m_idle)),
		m_all(std::move(o.m_all))
	{
		/* Empty body. */
	}

	ILIAS_NET2_EXPORT bool curthread_is_threadpool() ILIAS_NET2_NOTHROW;

	ILIAS_NET2_EXPORT ~threadpool() ILIAS_NET2_NOTHROW;


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
	 */
	static CONSTEXPR_VALUE int STATE_ACTIVE = 0;
	static CONSTEXPR_VALUE int STATE_SLEEP_TEST = 1;
	static CONSTEXPR_VALUE int STATE_SLEEP = 2;
	static CONSTEXPR_VALUE int STATE_DYING = 0xff;		/* Worker died and needs to be joined. */
	static CONSTEXPR_VALUE int STATE_SUICIDE = 0xfe;	/* Worker killed itself and detached. */

	enum kill_result {
		KILL_TWICE,	/* Was already dying. */
		KILL_OK,	/* Was killed by current invocation. */
		KILL_SUICIDE	/* Call to kill was suicide. */
	};

private:
	class publish_idle;

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
	void do_sleep(const std::function<bool()>& pred) ILIAS_NET2_NOTHROW;
	std::unique_ptr<threadpool::thread> run(const std::function<bool()>& pred, const std::function<bool()>& functor);

public:
	thread(threadpool& tp, unsigned int idx, const std::function<bool()>& pred, const std::function<bool()>& worker);
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


} /* namespace ilias */
