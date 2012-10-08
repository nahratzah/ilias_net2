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
#ifndef ILIAS_NET2_WORKQ_H
#define ILIAS_NET2_WORKQ_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/config.h>
#include <ilias/net2/bsd_compat/atomic.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>

ILIAS_NET2__begin_cdecl


#ifndef WIN32
struct ev_loop;		/* From libev. */
#endif

struct net2_workq;
struct net2_workq_job;
struct net2_workq_job_int;
struct net2_workq_evbase;
typedef void (*net2_workq_cb)(void*, void*);
typedef void (*net2_workq_job_cbfn)(struct net2_workq_job*);

#define NET2_WORKQ_PERSIST	0x80000000	/* Job persists. */
#define NET2_WORKQ_PARALLEL	0x40000000	/* Job can run parallel
						 * to sibling jobs. */

#define NET2_WQ_ACT_IMMED	0x00000001	/* Try to run activated job
						 * immediately. */
#define NET2_WQ_ACT_RECURS	0x00000002	/* Allow immediate running
						 * when active workq and
						 * job workq match. */

struct net2_workq_job {
	atomic_uint	 refcnt;		/* Prefent deactivation
						 * during access. */
	_Atomic(struct net2_workq_job_int*)
			 internal;		/* Internal data. */
};

ILIAS_NET2_EXPORT
int	 net2_workq_set_thread_count(struct net2_workq_evbase*, int, int);
ILIAS_NET2_EXPORT
struct net2_workq_evbase
	*net2_workq_evbase_new(const char*, int, int);
ILIAS_NET2_EXPORT
void	 net2_workq_evbase_ref(struct net2_workq_evbase*);
ILIAS_NET2_EXPORT
void	 net2_workq_evbase_release(struct net2_workq_evbase*);

ILIAS_NET2_EXPORT
struct net2_workq
	*net2_workq_new(struct net2_workq_evbase*);
ILIAS_NET2_EXPORT
void	 net2_workq_ref(struct net2_workq*);
ILIAS_NET2_EXPORT
void	 net2_workq_release(struct net2_workq*);
ILIAS_NET2_EXPORT
struct net2_workq_evbase
	*net2_workq_evbase(struct net2_workq*);

ILIAS_NET2_EXPORT
int	 net2_workq_init_work(struct net2_workq_job*, struct net2_workq*,
	    net2_workq_cb, void*, void*, int);
ILIAS_NET2_EXPORT
void	 net2_workq_deinit_work(struct net2_workq_job*);
ILIAS_NET2_EXPORT
void	 net2_workq_activate(struct net2_workq_job*, int);
ILIAS_NET2_EXPORT
void	 net2_workq_deactivate(struct net2_workq_job*);

ILIAS_NET2_EXPORT
struct net2_workq
	*net2_workq_get(struct net2_workq_job*);

#define NET2_WQ_WANT_TRY	0x00000001
#define NET2_WQ_WANT_RECURSE	0x00000002
ILIAS_NET2_EXPORT
int	 net2_workq_want(struct net2_workq*, int);
ILIAS_NET2_EXPORT
void	 net2_workq_unwant(struct net2_workq*);
ILIAS_NET2_EXPORT
int	 net2_workq_is_self(struct net2_workq*);

ILIAS_NET2_EXPORT
int	net2_workq_surf(struct net2_workq*, int);

/*
 * Initialize a null workq job.
 *
 * Null jobs have no workq and no function to be called.
 * Activation and deactivation of the null job are no-ops.
 * Using a null job is easier than using a pointer to a job.
 */
static __inline void
net2_workq_init_work_null(struct net2_workq_job *j)
{
	atomic_init(&j->internal, NULL);
	atomic_init(&j->refcnt, 0);
}

/* Test if a workq job is a null job. */
static __inline int
net2_workq_work_is_null(struct net2_workq_job *j)
{
	return atomic_load_explicit(&j->internal, memory_order_relaxed) ==
	    NULL;
}

ILIAS_NET2_EXPORT
int	 net2_workq_aid(struct net2_workq*, int);
ILIAS_NET2_EXPORT
struct net2_workq
	*net2_workq_current();


#if defined(ilias_net2_EXPORTS)

#ifndef HAS_TLS
ILIAS_NET2_LOCAL
int	 net2_workq_init();
ILIAS_NET2_LOCAL
void	 net2_workq_fini();
#else
#define	 net2_workq_init()	(0)
#define	 net2_workq_fini()	do { /* nothing */ } while (0)
#endif


#ifdef WIN32
ILIAS_NET2_LOCAL
struct net2_workq_timer_container
	*net2_workq_get_timer(struct net2_workq*);
ILIAS_NET2_LOCAL
struct net2_workq_io_container
	*net2_workq_get_io(struct net2_workq*);
#else
ILIAS_NET2_LOCAL
void	 net2_workq_evbase_evloop_changed(struct net2_workq_evbase*);
ILIAS_NET2_LOCAL
struct ev_loop
	*net2_workq_get_evloop(struct net2_workq_evbase*);
#endif

#endif /* ilias_net2_EXPORTS */

ILIAS_NET2__end_cdecl


#ifdef __cplusplus

#include <cassert>
#include <cerrno>
#include <exception>
#include <memory>
#include <stdexcept>
#include <utility>

namespace ilias {


class workq;
class workq_evbase;
class workq_sync;


/* Workq synchronization failure. */
class ILIAS_NET2_EXPORT workq_sync_error :
	public virtual std::exception
{
public:
	virtual ~workq_sync_error() throw ();
	virtual const char* what() const throw ();
};
/* Synchronization failed due to current callstack running on the workq. */
class ILIAS_NET2_EXPORT workq_sync_self :
	public virtual workq_sync_error
{
public:
	virtual ~workq_sync_self() throw ();
	virtual const char* what() const throw ();
};
/* Workq was busy. */
class ILIAS_NET2_EXPORT workq_sync_tryfail :
	public virtual workq_sync_error
{
public:
	virtual ~workq_sync_tryfail() throw ();
	virtual const char* what() const throw ();
};


class workq
{
private:
	struct net2_workq *wq;
	static net2_workq *wq_from_wqev(struct net2_workq_evbase*) throw (std::invalid_argument, std::bad_alloc);

#if HAS_DELETED_FN
	workq() = delete;
#else
	workq();
#endif

public:
	workq(workq_evbase&) throw (std::bad_alloc);
	explicit workq(struct net2_workq_evbase*) throw (std::invalid_argument, std::bad_alloc);
	explicit workq(struct net2_workq*) throw (std::invalid_argument);
	workq(const workq&) throw ();
#if HAS_RVALUE_REF
	workq(workq&&) throw ();
#endif
	~workq() throw ();

	workq& operator= (const workq&) throw ();
#if HAS_RVALUE_REF
	workq& operator= (workq&&) throw ();
#endif
	bool operator== (const workq&) const throw ();
	bool operator!= (const workq&) const throw ();

	void surf(bool = false) const throw (std::bad_alloc);
	bool aid(int = 1) const throw (std::bad_alloc, std::invalid_argument);

#if HAS_RVALUE_REF
	workq_evbase&& evbase() const throw ();
#endif

	struct net2_workq *c_workq() const throw ();
};

class workq_evbase
{
private:
	struct net2_workq_evbase	*wqev;

public:
	workq_evbase() throw (std::bad_alloc);
	workq_evbase(const char*) throw (std::bad_alloc);
	workq_evbase(const std::string&) throw (std::bad_alloc);
	explicit workq_evbase(struct net2_workq_evbase*) throw (std::invalid_argument);
	workq_evbase(const workq_evbase&) throw ();
#if HAS_RVALUE_REF
	workq_evbase(workq_evbase&&) throw ();
#endif
	~workq_evbase() throw ();

	workq_evbase& operator= (const workq_evbase&) throw ();
#if HAS_RVALUE_REF
	workq_evbase& operator= (workq_evbase&&) throw ();
#endif
	bool operator== (const workq_evbase&) const throw ();
	bool operator!= (const workq_evbase&) const throw ();

	struct net2_workq_evbase *c_workq_evbase() const throw ();
};

class workq_sync
{
private:
	const workq wq;

	ILIAS_NET2_EXPORT static void do_error(int) throw (std::bad_alloc, std::invalid_argument, workq_sync_error);

public:
	static const int TRY = NET2_WQ_WANT_TRY;
	static const int RECURSE = NET2_WQ_WANT_RECURSE;

	workq_sync(const workq&, int = 0) throw (std::bad_alloc, std::invalid_argument, workq_sync_error);
	~workq_sync() throw ();

	/* Remove copy/assignment. */
#if HAS_DELETED_FN
	workq_sync(const workq_sync&) = delete;
	workq_sync& operator=(const workq_sync&) = delete;
#else
private:
	workq_sync(const workq_sync&);
	workq_sync& operator=(const workq_sync&);
#endif
};

class workq_job
{
private:
	mutable struct net2_workq_job job;
	void *functor;
	void (*deletor)(void*);

	template<typename Functor>
	static void delete_fun(void*);
	template<typename Functor>
	static void invoke_fun(void*, void*);

public:
	static const int PERSIST = NET2_WORKQ_PERSIST;
	static const int PARALLEL = NET2_WORKQ_PARALLEL;

	workq_job() throw ();
	~workq_job() throw ();

	template<typename Functor>
	workq_job(const workq&, const Functor&, int = 0) throw (std::bad_alloc, std::invalid_argument);
#if HAS_RVALUE_REF
	template<typename Functor>
	workq_job(const workq&, Functor&&, int = 0) throw (std::bad_alloc, std::invalid_argument);
#endif

	void reset() throw ();

	template<typename Functor>
	void reset(const workq&, const Functor&, int = 0) throw (std::bad_alloc, std::invalid_argument);
#if HAS_RVALUE_REF
	template<typename Functor>
	void reset(const workq&, Functor&&, int = 0) throw (std::bad_alloc, std::invalid_argument);
#endif

	bool is_null() const throw ();
#if HAS_RVALUE_REF
	workq&& get_workq() const;
#endif

	void activate(int = 0) const throw ();
	void deactivate() const throw ();

	/* Remove copy/assignment. */
#if HAS_DELETED_FN
	workq_job(const workq_job&) = delete;
	workq_job& operator=(const workq_job&) = delete;
#else
private:
	workq_job(const workq_job&);
	workq_job& operator=(const workq_job&);
#endif
};


inline struct net2_workq*
workq::wq_from_wqev(struct net2_workq_evbase* wqev) throw (std::invalid_argument, std::bad_alloc)
{
	if (!wqev)
		throw std::invalid_argument("wqev");
	struct net2_workq *wq = net2_workq_new(wqev);
	if (!wq)
		throw std::bad_alloc();
	return wq;
}

inline
workq::workq(workq_evbase& wqev) throw (std::bad_alloc) :
	wq(net2_workq_new(wqev.c_workq_evbase()))
{
	if (!wq)
		throw std::bad_alloc();
}

inline
workq::workq(struct net2_workq_evbase *wqev) throw (std::invalid_argument, std::bad_alloc) :
	wq(wq_from_wqev(wqev))
{
	return;
}

inline
workq::workq(struct net2_workq *wq) throw (std::invalid_argument) :
	wq(wq)
{
	if (!wq)
		throw std::invalid_argument("wq");
	net2_workq_ref(wq);
}

inline
workq::workq(const workq& rhs) throw () :
	wq(rhs.wq)
{
	net2_workq_ref(wq);
}

#if HAS_RVALUE_REF
inline
workq::workq(workq&& rhs) throw () :
	wq(rhs.wq)
{
	rhs.wq = 0;
}
#endif

inline
workq::~workq() throw ()
{
	if (wq)
		net2_workq_release(wq);
}

inline workq&
workq::operator= (const workq& rhs) throw ()
{
	net2_workq_release(wq);
	wq = rhs.wq;
	net2_workq_ref(wq);
	return *this;
}

#if HAS_RVALUE_REF
inline workq&
workq::operator= (workq&& rhs) throw ()
{
	net2_workq_release(wq);
	wq = rhs.wq;
	rhs.wq = 0;
	return *this;
}
#endif

inline bool
workq::operator== (const workq& rhs) const throw ()
{
	return wq == rhs.wq;
}

inline bool
workq::operator!= (const workq& rhs) const throw ()
{
	return !(*this == rhs);
}

inline void
workq::surf(bool parallel) const throw (std::bad_alloc)
{
	int error = net2_workq_surf(this->wq, parallel);
	switch (error) {
	case 0:
		break;
	case ENOMEM:
		throw std::bad_alloc();
	default:
		/* UNREACHABLE */
		assert(0);
	}
}

inline bool
workq::aid(int count) const throw (std::bad_alloc, std::invalid_argument)
{
	int error = net2_workq_aid(this->wq, count);
	switch (error) {
	case 0:
		return true;
	case ENOMEM:
		throw std::bad_alloc();
	case EINVAL:
		throw std::invalid_argument("workq::aid(count)");
	}
	return false;
}

#if HAS_RVALUE_REF
inline workq_evbase&&
workq::evbase() const throw ()
{
	struct net2_workq_evbase *wqev = net2_workq_evbase(this->wq);
	net2_workq_evbase_ref(wqev);
	return std::move(workq_evbase(wqev));
}
#endif

inline struct net2_workq*
workq::c_workq() const throw ()
{
	return wq;
}


inline
workq_evbase::workq_evbase() throw (std::bad_alloc) :
	wqev(net2_workq_evbase_new(NULL, 0, 0))
{
	if (!wqev)
		throw std::bad_alloc();
}

inline
workq_evbase::workq_evbase(const char *name) throw (std::bad_alloc) :
	wqev(net2_workq_evbase_new(name, 0, 0))
{
	if (!wqev)
		throw std::bad_alloc();
}

inline
workq_evbase::workq_evbase(const std::string& name) throw (std::bad_alloc) :
	wqev(net2_workq_evbase_new(name.c_str(), 0, 0))
{
	if (!wqev)
		throw std::bad_alloc();
}

inline
workq_evbase::workq_evbase(struct net2_workq_evbase* wqev) throw (std::invalid_argument) :
	wqev(wqev)
{
	if (!wqev)
		throw std::invalid_argument("wqev");
}

inline
workq_evbase::workq_evbase(const workq_evbase& rhs) throw () :
	wqev(rhs.wqev)
{
	net2_workq_evbase_ref(wqev);
}

#if HAS_RVALUE_REF
inline
workq_evbase::workq_evbase(workq_evbase&& rhs) throw () :
	wqev(rhs.wqev)
{
	rhs.wqev = 0;
}
#endif

inline
workq_evbase::~workq_evbase() throw ()
{
	if (wqev)
		net2_workq_evbase_release(wqev);
}

inline workq_evbase&
workq_evbase::operator= (const workq_evbase& rhs) throw ()
{
	net2_workq_evbase_release(wqev);
	wqev = rhs.wqev;
	net2_workq_evbase_ref(wqev);
	return *this;
}

#if HAS_RVALUE_REF
inline workq_evbase&
workq_evbase::operator= (workq_evbase&& rhs) throw ()
{
	net2_workq_evbase_release(wqev);
	wqev = rhs.wqev;
	rhs.wqev = 0;
	return *this;
}
#endif

inline bool
workq_evbase::operator== (const workq_evbase& rhs) const throw ()
{
	return wqev == rhs.wqev;
}

inline bool
workq_evbase::operator!= (const workq_evbase& rhs) const throw ()
{
	return !(*this == rhs);
}

inline struct net2_workq_evbase *
workq_evbase::c_workq_evbase() const throw ()
{
	return wqev;
}


inline
workq_sync::workq_sync(const workq& wq, int flags) throw (std::bad_alloc, std::invalid_argument, workq_sync_error) :
	wq(wq)
{
	int error = net2_workq_want(wq.c_workq(), flags);
	if (error)
		do_error(error);
}

inline
workq_sync::~workq_sync() throw ()
{
	net2_workq_unwant(wq.c_workq());
}


inline
workq_job::workq_job() throw ()
{
	net2_workq_init_work_null(&this->job);
}

template<typename Functor>
workq_job::workq_job(const workq& wq, const Functor& f, int flags) throw (std::bad_alloc, std::invalid_argument)
{
	net2_workq_init_work_null(&this->job);
	this->reset(wq, f, flags);
}

#if HAS_RVALUE_REF
template<typename Functor>
workq_job::workq_job(const workq& wq, Functor&& f, int flags) throw (std::bad_alloc, std::invalid_argument)
{
	net2_workq_init_work_null(&this->job);
	this->reset(wq, f, flags);
}
#endif

inline
workq_job::~workq_job() throw ()
{
	this->reset();
}

template<typename Functor>
void
workq_job::invoke_fun(void *f_ptr, void *unused ILIAS_NET2__unused)
{
	Functor *f = reinterpret_cast<void*>(f_ptr);
	(*f)();
}

template<typename Functor>
void
workq_job::delete_fun(void *f_ptr)
{
	Functor *f = reinterpret_cast<void*>(f_ptr);
	delete f;
}

inline void
workq_job::reset() throw ()
{
	net2_workq_deinit_work(&this->job);
	if (this->functor)
		(*this->deletor)(this->functor);
	this->deletor = 0;
	this->functor = 0;
}

template<typename Functor>
void
workq_job::reset(const workq& wq, const Functor& f, int flags) throw (std::bad_alloc, std::invalid_argument)
{
	std::auto_ptr<Functor> arg;

	this->reset();

	arg = new Functor(f);
	int error = net2_workq_init_work(&this->job, wq.c_workq(), &workq_job::invoke_fun<Functor>, reinterpret_cast<void*>(arg.get()), NULL, flags);
	switch (error) {
	case 0:
		break;
	case ENOMEM:
		throw std::bad_alloc();
	case EINVAL:
		throw std::invalid_argument("workq_job assignment");
	default:
		/* UNREACHABLE */
		assert(0);
	}

	this->functor = reinterpret_cast<void*>(arg.release());
	this->deletor = &workq_job::delete_fun<Functor>;
}

#if HAS_RVALUE_REF
template<typename Functor>
void
workq_job::reset(const workq& wq, Functor&& f, int flags) throw (std::bad_alloc, std::invalid_argument)
{
	std::auto_ptr<Functor> arg;

	this->reset();

	arg = new Functor(f);
	int error = net2_workq_init_work(&this->job, wq.c_workq(), &workq_job::invoke_fun<Functor>, reinterpret_cast<void*>(arg.get()), NULL, flags);
	switch (error) {
	case 0:
		break;
	case ENOMEM:
		throw std::bad_alloc();
	case EINVAL:
		throw std::invalid_argument("workq_job assignment");
	default:
		/* UNREACHABLE */
		assert(0);
	}

	this->functor = reinterpret_cast<void*>(arg.release());
	this->deletor = &workq_job::delete_fun<Functor>;
}
#endif

inline bool
workq_job::is_null() const throw ()
{
	return net2_workq_work_is_null(&this->job);
}

#if HAS_RVALUE_REF
inline workq&&
workq_job::get_workq() const
{
	struct net2_workq *wq;

	workq result(wq = net2_workq_get(&this->job));
	if (wq)
		net2_workq_release(wq);
	return std::move(result);
}
#endif

inline void
workq_job::activate(int flags) const throw ()
{
	net2_workq_activate(&this->job, flags);
}

inline void
workq_job::deactivate() const throw ()
{
	net2_workq_deactivate(&this->job);
}


} /* namespace ilias */

#endif /* __cplusplus */

#endif /* ILIAS_NET2_WORKQ_H */
