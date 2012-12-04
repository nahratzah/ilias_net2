#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/ll.h>
#include <ilias/net2/workq.h>
#include <cassert>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>

#if defined(HAVE_TYPE_TRAITS)
#include <type_traits>
#endif

namespace ilias {
namespace msg_queue_detail {


/* Adapter, to push Type on a ll_list. */
template<typename Type>
class msgq_ll_data :
	public ll_base_hook<>
{
public:
	typedef Type value_type;

private:
	typedef value_type m_value;

public:
	template<typename... Args>
	msgq_ll_data(Args&&... args) ILIAS_NET2_NOTHROW_TRAITS(std::is_nothrow_constructible<value_type, Args...>::value) :
		m_value(std::forward<Args>(args)...)
	{
		/* Empty body. */
	}

	value_type
	move_if_noexcept()
	    ILIAS_NET2_NOTHROW_TRAITS(std::is_nothrow_move_constructible<value_type>::value || std::is_nothrow_copy_constructible<value_type>::value)
	{
		return MOVE_IF_NOEXCEPT(this->m_value);
	}
};


/* Optional element content for message queue (comparable to boost::optional). */
template<typename Type>
class msgq_opt_data :
	public bool_test<msgq_opt_data<Type> >
{
public:
	typedef Type value_type;
	typedef value_type& reference;
	typedef const value_type& const_reference;
	typedef value_type* pointer;
	typedef const value_type* const_pointer;

private:
	bool m_has_value;
	union { value_type impl; } m_value;

public:
	msgq_opt_data() ILIAS_NET2_NOTHROW :
		m_has_value(false)
	{
		/* Empty body. */
	}

	msgq_opt_data(const msgq_opt_data& o) ILIAS_NET2_NOTHROW_TRAITS(std::is_nothrow_copy_constructible<value_type>::value) :
		m_has_value(false)
	{
		if (o.m_has_value) {
			::new(&this->m_value.impl) value_type(o.m_value.impl);
			this->m_has_value = true;
		}
	}

	msgq_opt_data(msgq_opt_data&& o)
	    ILIAS_NET2_NOTHROW_TRAITS((std::is_nothrow_move_constructible<value_type>::value || std::is_nothrow_copy_constructible<value_type>::value) && std::is_nothrow_destructable<value_type>::value) :
		m_has_value(false)
	{
		this->swap(o);
	}

	explicit msgq_opt_data(const value_type& v) ILIAS_NET2_NOTHROW_TRAITS(std::is_nothrow_copy_constructible<value_type>::value) :
		m_has_value(true)
	{
		::new(&this->m_value.impl) value_type(v);
	}

	explicit msgq_opt_data(value_type&& v) ILIAS_NET2_NOTHROW_TRAITS(std::is_nothrow_move_constructible<value_type>::value) :
		m_has_value(true)
	{
		::new(&this->m_value.impl) value_type(std::move(v));
	}

	~msgq_opt_data() ILIAS_NET2_NOTHROW_TRAITS(std::is_nothrow_destructable<value_type>::value)
	{
		if (this->m_has_value)
			this->m_value.impl.~value_type();
	}

	msgq_opt_data&
	operator=(msgq_opt_data o)
	    ILIAS_NET2_NOTHROW_TRAITS((std::is_nothrow_move_constructible<value_type>::value || std::is_nothrow_copy_constructible<value_type>::value) && std::is_nothrow_destructable<value_type>::value)
	{
		this->swap(o);
		return *this;
	}

	void
	swap(msgq_opt_data& o)
	    ILIAS_NET2_NOTHROW_TRAITS((std::is_nothrow_move_constructible<value_type>::value || std::is_nothrow_copy_constructible<value_type>::value) && std::is_nothrow_destructable<value_type>::value)
	{
		using std::swap;

		if (this->m_has_value && o.m_has_value)
			swap(this->m_value.impl, o.m_value.impl);
		else if (this->m_has_value) {
			::new(&o.m_value.impl) value_type(MOVE_IF_NOEXCEPT(this->m_value.impl));
			swap(this->m_has_value, o.m_has_value);
			this->m_value.impl.~value_type();
		} else if (o.m_has_value) {
			::new(&this->m_value.impl) value_type(MOVE_IF_NOEXCEPT(o.m_value.impl));
			swap(this->m_has_value, o.m_has_value);
			o.m_value.impl.~value_type();
		}
	}

	friend void
	swap(msgq_opt_data& a, msgq_opt_data& b)
	    ILIAS_NET2_NOTHROW_TRAITS((std::is_nothrow_move_constructible<value_type>::value || std::is_nothrow_copy_constructible<value_type>::value) && std::is_nothrow_destructable<value_type>::value)
	{
		a.swap(b);
	}

	pointer
	get() ILIAS_NET2_NOTHROW
	{
		return (this->m_has_value ? nullptr : &this->m_value.impl);
	}

	const_pointer
	get() const ILIAS_NET2_NOTHROW
	{
		return (this->m_has_value ? nullptr : &this->m_value.impl);
	}

	reference
	operator*() ILIAS_NET2_NOTHROW
	{
		return *this->get();
	}

	const_reference
	operator*() const ILIAS_NET2_NOTHROW
	{
		return *this->get();
	}

	pointer
	operator->() ILIAS_NET2_NOTHROW
	{
		return this->get();
	}

	const_pointer
	operator->() const ILIAS_NET2_NOTHROW
	{
		return this->get();
	}

	bool
	booltest() const ILIAS_NET2_NOTHROW
	{
		return this->m_has_value;
	}
};


/* Allocator adapter, to abstract Alloc away. */
template<typename DataType, typename Alloc>
class msg_queue_alloc
{
public:
	typedef DataType* alloc_pointer;
#if HAS_ALLOCATOR_TRAITS
	typedef typename std::allocator_traits<Alloc>::template rebind<DataType>::other allocator_type;
#else
	typedef typename Alloc::template rebind<DataType>::other allocator_type;
#endif

#if HAS_ALLOCATOR_TRAITS
	typedef std::allocator_traits<allocator_type> allocator_traits;
#else
	/* Fallback allocator traits, only works for pre-c++11 allocators. */
	struct allocator_traits
	{
		typedef msg_queue_alloc::allocator_type allocator_type;
		typedef typename allocator_type::value_type value_type;
		typedef typename allocator_type::pointer pointer;
		typedef typename allocator_type::const_pointer const_pointer;
		typedef void* void_pointer;
		typedef const void* const_void_pointer;
		typedef typename allocator_type::difference_type difference_type;
		typedef typename allocator_type::size_type size_type;

		static pointer
		allocate(allocator_type& alloc, size_type sz)
		{
			return alloc.allocate(sz);
		}

		static pointer
		allocate(allocator_type& a, size_type n, const_void_pointer hint)
		{
			return a.allocate(n, hint);
		}

		static void
		deallocate(allocator_type& a, pointer p, size_type n)
		{
			a.deallocate(p, n);
		}

		static void
		construct(allocator_type& a, pointer p, const value_type& v)
		{
			a.construct(p, v);
		}

#if HAS_RVALUE_REF
		static void
		construct(allocator_type& a, pointer p, value_type&& v)
		{
			a.construct(p, std::move(v));
		}
#endif

#if HAS_RVALUE_REF && HAS_VARARG_TEMPLATES
		template<typename... Args>
		static void
		construct(allocator_type& a, pointer p, Args&&... args)
		{
			a.construct(a, p, std::forward<Args>(args)...);
		}
#endif

		static void
		destroy(allocator_type& a, pointer p)
		{
			a.destroy(p);
		}

		static size_type
		max_size(allocator_type& a)
		{
			return a.max_size();
		}
	};
#endif

private:
	allocator_type m_alloc;

public:
	template<typename... Args>
	alloc_pointer
	create(Args&&... args)
	{
		alloc_pointer rv;

		const auto p = allocator_traits::allocate(this->m_alloc, 1);
		try {
			rv = alloc_pointer(allocator_traits::construct(this->m_alloc, p, std::forward<Args>(args)...));
		} catch (...) {
			allocator_traits::deallocate(this->m_alloc, p, 1);
			throw;
		}
		assert(rv);
		return rv;
	}

	void
	destroy(alloc_pointer p)
	{
		if (p) {
			allocator_traits::destroy(this->m_alloc, p);
			allocator_traits::deallocate(this->m_alloc, p, 1);
		}
	}

	typename allocator_traits::size_type
	max_size() const ILIAS_NET2_NOTHROW
	{
		return allocator_traits::max_size(this->m_alloc);
	}


#if HAS_RVALUE_REF
	msg_queue_alloc(const msg_queue_alloc&) = delete;
	msg_queue_alloc& operator=(const msg_queue_alloc&) = delete;
#else
private:
	msg_queue_alloc(const msg_queue_alloc&);
	msg_queue_alloc& operator=(const msg_queue_alloc&);
#endif
};


/* Limitations for message queue. */
class msg_queue_size
{
public:
	typedef std::size_t size_type;

private:
	std::atomic<size_type> m_eff_size;
	std::atomic<size_type> m_eff_avail;
	std::atomic<size_type> m_overflow;
	size_type m_max_size;
	mutable std::mutex m_setsz_mtx;	/* Protect modification of max_size. */

	ILIAS_NET2_EXPORT bool begin_insert() ILIAS_NET2_NOTHROW;
	ILIAS_NET2_EXPORT void commit_insert() ILIAS_NET2_NOTHROW;
	ILIAS_NET2_EXPORT void cancel_insert() ILIAS_NET2_NOTHROW;
	void avail_inc() ILIAS_NET2_NOTHROW;

protected:
	ILIAS_NET2_EXPORT void commit_remove() ILIAS_NET2_NOTHROW;

	class insert_lock
	{
	private:
		msg_queue_size* self;

	public:
		insert_lock() ILIAS_NET2_NOTHROW :
			self(nullptr)
		{
			/* Empty body. */
		}

		insert_lock(msg_queue_size& self) :
			self(&self)
		{
			if (!self.begin_insert())
				throw std::length_error("msg_queue: full");
		}

		insert_lock(insert_lock&& il) ILIAS_NET2_NOTHROW :
			self(nullptr)
		{
			this->swap(il);
		}

		~insert_lock() ILIAS_NET2_NOTHROW
		{
			if (this->self)
				self->cancel_insert();
		}

		insert_lock&
		operator=(insert_lock&& il) ILIAS_NET2_NOTHROW
		{
			insert_lock(std::move(il)).swap(*this);
			return *this;
		}

		void
		commit() ILIAS_NET2_NOTHROW
		{
			assert(self);
			self->commit_insert();
			self = nullptr;
		}

		msg_queue_size*
		get_lockable() const ILIAS_NET2_NOTHROW
		{
			return this->self;
		}

		void
		swap(insert_lock& il) ILIAS_NET2_NOTHROW
		{
			using std::swap;

			swap(this->self, il.self);
		}

		friend void
		swap(insert_lock& a, insert_lock& b) ILIAS_NET2_NOTHROW
		{
			a.swap(b);
		}


#if HAS_DELETED_FN
		insert_lock(const insert_lock&) = delete;
		insert_lock& operator=(const insert_lock&) = delete;
#else
	private:
		insert_lock(const insert_lock&);
		insert_lock& operator=(const insert_lock&);
#endif
	};

	bool
	eff_empty() const ILIAS_NET2_NOTHROW
	{
		return (this->m_eff_size.load(std::memory_order_relaxed) == 0);
	}

	ILIAS_NET2_EXPORT bool eff_attempt_remove() ILIAS_NET2_NOTHROW;

public:
	msg_queue_size(size_type maxsz = SIZE_MAX) ILIAS_NET2_NOTHROW :
		m_eff_size(0U),
		m_eff_avail(maxsz),
		m_overflow(0U),
		m_max_size(maxsz),
		m_setsz_mtx()
	{
		/* Empty body. */
	}

	ILIAS_NET2_EXPORT size_type get_max_size() const ILIAS_NET2_NOTHROW;
	ILIAS_NET2_EXPORT void set_max_size(size_type newsz) ILIAS_NET2_NOTHROW;
};


/*
 * Message queue data.
 *
 * Hold elements in the message queue, provide push/pop operations.
 */
template<typename Type, typename Alloc>
class msg_queue_data :
	protected msg_queue_alloc<msgq_ll_data<Type>, Alloc>,
	public msg_queue_size
{
public:
	typedef Type element_type;
	typedef msgq_opt_data<element_type> opt_element_type;
	typedef std::size_t size_type;

protected:
	typedef msgq_ll_data<Type> ll_data_type;
	typedef ilias::ll_list<ll_base_hook<ll_data_type> > list_type;

private:
	list_type m_list;

public:
	msg_queue_data() :
		m_list()
	{
		/* Empty body. */
	}

	msg_queue_data(size_type maxsize) :
		msg_queue_size(std::min(maxsize, this->max_size())),
		m_list()
	{
		/* Empty body. */
	}

	~msg_queue_data() ILIAS_NET2_NOTHROW_CND_TEST(noexcept(msg_queue_alloc<Type, Alloc>::destroy(ll_data_type*)))
	{
		using namespace std::placeholders;

		this->m_list.clear_and_dispose(std::bind(&msg_queue_alloc<Type, Alloc>::destroy, this, _1));
	}

	bool
	empty() const ILIAS_NET2_NOTHROW
	{
		return this->m_list.empty();
	}

	bool
	full() const ILIAS_NET2_NOTHROW
	{
		return (this->m_eff_avail.load(std::memory_order_relaxed) == 0);
	}

protected:
	void
	push(element_type v)
	{
		this->push(this->create(std::move(v)));
	}

	template<typename... Args>
	void
	emplace(Args&&... args)
	{
		this->push(this->create(std::forward<Args>(args)...));
	}

	void
	push(ll_data_type* ld)
	{
		this->push(insert_lock(*this), ld);
	}

	void
	push(insert_lock&& lck, ll_data_type* ld) ILIAS_NET2_NOTHROW
	{
		assert(lck.get_lockable() == this);
		auto rv = this->m_list.push_back(ld);
		assert(rv);
		lck.commit();
	}

	opt_element_type
	pop() ILIAS_NET2_NOTHROW_CND_TEST(noexcept(ll_data_type::move_if_noexcept()))
	{
		opt_element_type rv;

		ll_data_type* p = this->m_list.pop_front();
		if (p) {
			this->commit_remove();

			try {
				rv = opt_element_type(p->move_if_noexcept());
			} catch (...) {
				this->destroy(p);
				throw;
			}
			this->destroy(p);
		}
		return rv;
	}
};


/*
 * Message queue specialization for void.
 *
 * Since void can hold no data, no list is required to keep track of the data either.
 */
template<typename Alloc>
class msg_queue_data<void, Alloc> :
	public msg_queue_size
{
public:
	typedef void element_type;
	typedef bool opt_element_type;

	msg_queue_data() ILIAS_NET2_NOTHROW :
		msg_queue_size()
	{
		/* Empty body. */
	}

	msg_queue_data(size_type maxsz) ILIAS_NET2_NOTHROW :
		msg_queue_size(maxsz)
	{
		/* Empty body. */
	}

	bool
	empty() const ILIAS_NET2_NOTHROW
	{
		return this->eff_empty();
	}

protected:
	void
	push()
	{
		this->push(insert_lock(*this));
	}

	void
	push(insert_lock&& lck) ILIAS_NET2_NOTHROW
	{
		assert(lck.get_lockable() == this);
		lck.commit();
	}

	bool
	pop() ILIAS_NET2_NOTHROW
	{
		return this->eff_attempt_remove();
	}
};


/* Hang on to a pointer in the given msg_queue_alloc. */
template<typename DataType, typename Alloc>
class prepare_hold
{
public:
	typedef msg_queue_alloc<DataType, Alloc> alloc_type;
	typedef typename DataType::value_type value_type;

private:
	alloc_type* m_alloc;
	typename alloc_type::alloc_pointer m_ptr;

public:
	prepare_hold() ILIAS_NET2_NOTHROW :
		m_alloc(nullptr),
		m_ptr(nullptr)
	{
		return;
	}

	template<typename... Args>
	prepare_hold(alloc_type& alloc, Args&&... args) ILIAS_NET2_NOTHROW :
		m_alloc(&alloc),
		m_ptr(nullptr)
	{
		this->m_ptr = this->m_alloc->create(std::forward<Args>(args)...);
	}

	prepare_hold(prepare_hold&& o) ILIAS_NET2_NOTHROW :
		m_alloc(o.alloc),
		m_ptr(o.m_ptr)
	{
		o.m_ptr = nullptr;
	}

	~prepare_hold() ILIAS_NET2_NOTHROW_CND_TEST(noexcept(alloc_type::destroy(alloc::alloc_pointer)))
	{
		if (this->m_ptr) {
			assert(this->m_alloc);
			this->m_alloc->destroy(this->m_ptr);
		}
	}

	prepare_hold&
	operator=(prepare_hold&& o)
	{
		this->swap(o);
		return *this;
	}

	void
	assign(const value_type& v)
	{
		if (!this->m_alloc)
			throw std::invalid_argument("prepare: assign called without allocator");
		if (this->m_ptr)
			**this->m_ptr = v;
		else
			this->m_ptr = this->m_alloc->create(v);
	}

	void
	assign(value_type&& v)
	{
		if (!this->m_alloc)
			throw std::invalid_argument("prepare: assign called without allocator");
		if (this->m_ptr)
			**this->m_ptr = std::move(v);
		else
			this->m_ptr = this->m_alloc->create(std::move(v));
	}

	template<typename... Args>
	void
	assign(Args&&... args)
	{
		if (!this->m_alloc)
			throw std::invalid_argument("prepare: assign called without allocator");
		if (this->m_ptr)
			**this->m_ptr = value_type(std::forward<Args>(args)...);
		else
			this->m_ptr = this->m_alloc->create(std::forward<Args>(args)...);
	}

protected:
	void
	swap(prepare_hold& o) ILIAS_NET2_NOTHROW
	{
		using std::swap;

		swap(this->m_alloc, o.m_alloc);
		swap(this->m_ptr, o.m_ptr);
	}

	Alloc*
	get_alloc() const ILIAS_NET2_NOTHROW
	{
		return this->m_alloc;
	}

	typename alloc_type::alloc_pointer
	get_ptr() const ILIAS_NET2_NOTHROW
	{
		return this->m_ptr;
	}

	typename alloc_type::alloc_pointer
	release_ptr() const ILIAS_NET2_NOTHROW
	{
		auto rv = this->m_ptr;
		this->m_ptr = nullptr;
		return rv;
	}


#if HAS_DELETED_FN
	prepare_hold(const prepare_hold&) = delete;
	prepare_hold& operator=(const prepare_hold&) = delete;
#else
private:
	prepare_hold(const prepare_hold&);
	prepare_hold& operator=(const prepare_hold&);
#endif
};


/*
 * Prepared push operation.
 *
 * Allows preparation of a push, with guaranteed succes on commit.
 */
template<typename MQ, typename ElemType = typename MQ::element_type>
class prepared_push :
	private prepare_hold<typename MQ::ll_data_type, typename MQ::allocator_type>
{
private:
	typedef prepare_hold<typename MQ::ll_data_type, typename MQ::allocator_type> parent_type;
	typedef MQ msgq_type;

public:
	typedef typename msgq_type::element_type value_type;

private:
	bool m_assigned;
	typename msgq_type::insert_lock m_lck;

public:
	prepared_push() ILIAS_NET2_NOTHROW :
		parent_type(),
		m_assigned(false),
		m_lck()
	{
		/* Empty body. */
	}

	prepared_push(prepared_push&& pp) ILIAS_NET2_NOTHROW :
		parent_type(),
		m_assigned(false),
		m_lck()
	{
		this->swap(pp);
	}

	template<typename... Args>
	explicit prepared_push(msgq_type& self, Args&&... args) :
		parent_type(self, std::forward<Args>(args)...),
		m_assigned(sizeof...(args) > 0)
	{
		/* Empty body. */
	}

	prepared_push&
	operator=(prepared_push&& pp) ILIAS_NET2_NOTHROW
	{
		prepare_push(std::move(pp)).swap(*this);
		return *this;
	}

	template<typename... Args>
	void
	assign(Args&&... args)
	{
		this->parent_type::assign(std::forward<Args>(args)...);
		this->m_assigned = true;
	}

	/*
	 * Commit prepared insert.
	 *
	 * Only throws (std::runtime_error) if no value was assigned.
	 */
	void
	commit()
	{
		if (!this->m_assigned)
			throw std::runtime_error("msg_queue prepared push: no value was assigned");
		assert(this->get_alloc() && this->get_ptr() && this->m_lck.get_lockable());	/* Implied by above. */

		msgq_type& self = static_cast<msgq_type&>(*this->get_alloc());
		self.push(std::move(this->m_lck), this->get_ptr());
		this->release_ptr();
	}

	void
	swap(prepared_push& pp) ILIAS_NET2_NOTHROW
	{
		using std::swap;

		this->parent_type::swap(pp);
		this->m_lck.swap(pp.m_lck);
		swap(this->m_assigned, pp.m_assigned);
	}

	friend void
	swap(prepared_push& a, prepared_push& b) ILIAS_NET2_NOTHROW
	{
		a.swap(b);
	}


#if HAS_DELETED_FN
	prepared_push(const prepared_push&) = delete;
	prepared_push& operator=(const prepared_push&) = delete;
#else
private:
	prepared_push(const prepared_push&);
	prepared_push& operator=(const prepared_push&);
#endif
};


/*
 * Prepared push, specialized for void element type.
 */
template<typename MQ>
class prepared_push<MQ, void>
{
private:
	typedef MQ msgq_type;

public:
	typedef void value_type;

private:
	msgq_type* m_self;
	typename msgq_type::insert_lock m_lck;

public:
	prepared_push() ILIAS_NET2_NOTHROW :
		m_self(nullptr),
		m_lck()
	{
		/* Empty body. */
	}

	prepared_push(prepared_push&& pp) ILIAS_NET2_NOTHROW :
		m_self(nullptr),
		m_lck()
	{
		this->swap(pp);
	}

	explicit prepared_push(msgq_type& self) :
		m_self(&self),
		m_lck(self)
	{
		/* Empty body. */
	}

	prepared_push&
	operator=(prepared_push&& pp) ILIAS_NET2_NOTHROW
	{
		prepared_push(std::move(pp)).swap(*this);
		return *this;
	}

	void
	commit()
	{
		if (!this->m_self)
			throw std::runtime_error("msg_queue prepared push: no message queue for void push");

		this->m_self->push(std::move(this->m_lck));
		this->m_self = nullptr;
	}

	void
	swap(prepared_push&& pp) ILIAS_NET2_NOTHROW
	{
		using std::swap;

		swap(this->m_self, pp.m_self);
		swap(this->m_lck, pp.m_lck);
	}

	friend void
	swap(prepared_push& a, prepared_push& b) ILIAS_NET2_NOTHROW
	{
		a.swap(b);
	}


#if HAS_DELETED_FN
	prepared_push(const prepared_push&) = delete;
	prepared_push& operator=(const prepared_push&) = delete;
#else
private:
	prepared_push(const prepared_push&);
	prepared_push& operator=(const prepared_push&);
#endif
};


/*
 * Eliminate allocator for void type.
 */
template<typename Type, typename Alloc>
struct select_allocator
{
	typedef Alloc type;
};
template<typename Alloc>
struct select_allocator<void, Alloc>
{
	typedef void type;
};

/*
 * Select default allocator for type.
 */
template<typename Type>
struct default_allocator : public select_allocator<Type, std::allocator<Type> > {};


} /* namespace ilias::msg_queue_detail */


template<typename Type, typename Alloc = typename msg_queue_detail::default_allocator<Type>::type >
class msg_queue :
	public msg_queue_detail::msg_queue_data<Type, typename msg_queue_detail::select_allocator<Type, Alloc>::type>
{
friend class msg_queue_detail::prepared_push<msg_queue>;

public:
	typedef msg_queue_detail::msg_queue_data<Type, typename msg_queue_detail::select_allocator<Type, Alloc>::type> parent_type;
	typedef typename parent_type::size_type size_type;
	typedef typename parent_type::opt_element_type opt_element_type;
	typedef msg_queue_detail::prepared_push<msg_queue> prepared_push;

	msg_queue() :
		parent_type()
	{
		/* Empty body. */
	}

	msg_queue(size_type maxsize) :
		parent_type(maxsize)
	{
		/* Empty body. */
	}

protected:
	template<typename... Args>
	void
	push(Args&&... args) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(parent_type::push(Args...)))
	{
		this->parent_type::push(std::forward<Args>(args)...);
		/* XXX read-event */
		if (!this->full()) {
			/* XXX write-event */
		}
	}

	template<typename... Args>
	opt_element_type
	pop(Args&&... args) ILIAS_NET2_NOTHROW_CND_TEST(noexcept(parent_type::pop(Args...)))
	{
		auto rv = this->parent_type::pop(std::forward<Args>(args)...);
		if (!this->full()) {
			/* XXX write-event */
		}
		if (!this->empty()) {
			/* XXX read-event */
		}
		return rv;
	}
};


} /* namespace ilias */
