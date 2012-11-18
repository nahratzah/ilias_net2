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

	std::function<thread_ptr(threadpool&)> m_factory;
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
private:
	static CONSTEXPR_VALUE int STATE_ACTIVE = 0;
	static CONSTEXPR_VALUE int STATE_SLEEP_TEST = 1;
	static CONSTEXPR_VALUE int STATE_SLEEP = 2;
	static CONSTEXPR_VALUE int STATE_DYING = 0xff;

	std::atomic<int> m_state;
	std::mutex m_sleep_mtx;
	std::condition_variable m_wakeup;
	idle_threads& m_idle;
	std::thread m_self;	/* Must be the last variable in this class. */

	class publish_idle
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


	int
	get_state() const ILIAS_NET2_NOTHROW
	{
		return this->m_state.load(std::memory_order_relaxed);
	}

	void do_sleep(const std::function<bool()>& pred) ILIAS_NET2_NOTHROW;
	void run(const std::function<bool()>& pred, const std::function<bool()>& functor);

public:
	thread(threadpool& tp, const std::function<bool()>& pred, const std::function<bool()>& worker);
	bool wakeup() ILIAS_NET2_NOTHROW;
	bool kill() ILIAS_NET2_NOTHROW;
	void join() ILIAS_NET2_NOTHROW;
	~thread() ILIAS_NET2_NOTHROW;


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
