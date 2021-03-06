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
#ifndef ILIAS_NET2_PROMISE_H
#define ILIAS_NET2_PROMISE_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/config.h>
#include <ilias/net2/workq.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <ilias/net2/bsd_compat/queue.h>
#endif

ILIAS_NET2__begin_cdecl


struct net2_promise;
/* Combined promise callback. */
typedef void (*net2_promise_ccb)(struct net2_promise*, struct net2_promise**,
    size_t, void*);

/* An event associated with promise. */
struct net2_promise_event {
	struct net2_promise	*owner;
	net2_workq_cb		 fn;
	TAILQ_ENTRY(net2_promise_event)
				 promq;
	struct net2_workq_job	 job;
	int			 evno;
	void			*arg0;
};


#define NET2_PROM_FIN_UNFINISHED	0	/* Promise hasn't completed. */
#define NET2_PROM_FIN_OK		1	/* Executed succesful. */
#define NET2_PROM_FIN_CANCEL		2	/* Execution cancelled. */
#define NET2_PROM_FIN_ERROR		3	/* Execution failed. */
#define NET2_PROM_FIN_UNREF		4	/* Unreferenced at run. */
#define NET2_PROM_FIN_FAIL		0xf	/* Failed to run. */

#define NET2_PROMFLAG_RELEASE		0x00000001	/* In-call release. */

#define NET2_PROM_ON_FINISH		0	/* On-finish event. */
#define NET2_PROM_ON_RUN		1	/* On-run event: fired when a
						 * thread asks for the result
						 * and the running state hasn't
						 * been set. */
#define NET2_PROM__NUM_EVENTS		2


ILIAS_NET2_EXPORT
struct net2_promise	*net2_promise_new();
ILIAS_NET2_EXPORT
void			 net2_promise_destroy_cb(struct net2_promise*,
			    void (*fn)(void*, void*), void*, void*);
ILIAS_NET2_EXPORT
void			 net2_promise_release(struct net2_promise*);
ILIAS_NET2_EXPORT
void			 net2_promise_ref(struct net2_promise*);
ILIAS_NET2_EXPORT
int			 net2_promise_set_error(struct net2_promise*,
			    uint32_t errcode, int flags);
ILIAS_NET2_EXPORT
int			 net2_promise_is_cancelreq(struct net2_promise*);
ILIAS_NET2_EXPORT
void			 net2_promise_cancel(struct net2_promise*);
ILIAS_NET2_EXPORT
int			 net2_promise_set_cancel(struct net2_promise*, int);
ILIAS_NET2_EXPORT
int			 net2_promise_set_running(struct net2_promise*);
ILIAS_NET2_EXPORT
int			 net2_promise_is_running(struct net2_promise*);
ILIAS_NET2_EXPORT
int			 net2_promise_set_finok(struct net2_promise*, void*,
			    void (*)(void*, void*), void *, int);
ILIAS_NET2_EXPORT
int			 net2_promise_dontfree(struct net2_promise*);
ILIAS_NET2_EXPORT
int			 net2_promise_is_finished(struct net2_promise*);
ILIAS_NET2_EXPORT
int			 net2_promise_get_result(struct net2_promise*,
			    void**, uint32_t*);
ILIAS_NET2_EXPORT
void			 net2_promise_wait(struct net2_promise*);
ILIAS_NET2_EXPORT
void			 net2_promise_start(struct net2_promise*);

ILIAS_NET2_EXPORT
int			 net2_promise_event_init(struct net2_promise_event*,
			    struct net2_promise*, int, struct net2_workq*,
			    net2_workq_cb, void*, void*);
ILIAS_NET2_EXPORT
void			 net2_promise_event_deinit(struct net2_promise_event*);

ILIAS_NET2_EXPORT
struct net2_promise	*net2_promise_combine(struct net2_workq*,
			    net2_promise_ccb, void*,
			    struct net2_promise**, size_t);

/* Convert promise event to workq job. */
static __inline struct net2_workq_job*
net2_promise_event_wqjob(struct net2_promise_event *ev)
{
	return &ev->job;
}

/* Initialize a null event. */
static __inline void
net2_promise_event_init_null(struct net2_promise_event *ev)
{
	net2_workq_init_work_null(net2_promise_event_wqjob(ev));
}

/* Test if the event is a null event. */
static __inline int
net2_promise_event_is_null(struct net2_promise_event *ev)
{
	return net2_workq_work_is_null(net2_promise_event_wqjob(ev));
}


ILIAS_NET2__end_cdecl


#ifdef __cplusplus

#include <cassert>
#include <exception>
#include <stdexcept>
#include <utility>

#if defined(HAVE_TYPE_TRAITS) && HAS_VARARG_TEMPLATES && HAS_DECLTYPE && HAS_RVALUE_REF
#include <type_traits>	/* For combi promise templates. */
#endif /* HAS_VARARG_TEMPLATES && HAS_DECLTYPE && HAS_RVALUE_REF */

namespace ilias {


/* Generic promise error. */
class ILIAS_NET2_EXPORT promise_error :
	public virtual std::exception
{
public:
	virtual ~promise_error() ILIAS_NET2_NOTHROW;
	virtual const char *what() const ILIAS_NET2_NOTHROW;
};
/* Uninitialized promise error, promise was not properly initialized. */
class ILIAS_NET2_EXPORT promise_noinit_error :
	public virtual promise_error
{
public:
	virtual ~promise_noinit_error() ILIAS_NET2_NOTHROW;
	virtual const char *what() const ILIAS_NET2_NOTHROW;
};
class ILIAS_NET2_EXPORT promise_fin_error :
	public virtual promise_error
{
public:
	virtual ~promise_fin_error() ILIAS_NET2_NOTHROW;
	virtual const char *what() const ILIAS_NET2_NOTHROW;
};
/* Promise dereference error, thrown when result is unavailable. */
class ILIAS_NET2_EXPORT promise_deref_error :
	public virtual promise_error
{
public:
	virtual ~promise_deref_error() ILIAS_NET2_NOTHROW;
	virtual const char *what() const ILIAS_NET2_NOTHROW;
};
/* Promise dereference error for uninitialized promise. */
class ILIAS_NET2_EXPORT promise_deref_noinit_error :
	public virtual promise_deref_error,
	public virtual promise_noinit_error
{
public:
	virtual ~promise_deref_noinit_error() ILIAS_NET2_NOTHROW;
	virtual const char *what() const ILIAS_NET2_NOTHROW;
};
/* Promise was canceled. */
class ILIAS_NET2_EXPORT promise_canceled :
	public virtual promise_deref_error
{
public:
	virtual ~promise_canceled() ILIAS_NET2_NOTHROW;
	virtual const char *what() const ILIAS_NET2_NOTHROW;
};
/* Promise has not finished. */
class ILIAS_NET2_EXPORT promise_unfinished :
	public virtual promise_deref_error
{
public:
	virtual ~promise_unfinished() ILIAS_NET2_NOTHROW;
	virtual const char *what() const ILIAS_NET2_NOTHROW;
};
/* Promise finished with error code. */
class ILIAS_NET2_EXPORT promise_finerr_error :
	public virtual promise_deref_error
{
public:
	const uint32_t	error;	/* Error code. */

	promise_finerr_error(uint32_t error) :
		promise_deref_error(),
		error(error)
	{
		return;
	}

	virtual ~promise_finerr_error() ILIAS_NET2_NOTHROW;
	virtual const char *what() const ILIAS_NET2_NOTHROW;
};
/* Promise became unreferenced before result was set. */
class ILIAS_NET2_EXPORT promise_unref_error :
	public virtual promise_deref_error
{
public:
	virtual ~promise_unref_error() ILIAS_NET2_NOTHROW;
	virtual const char *what() const ILIAS_NET2_NOTHROW;
};
/* Promise failed to execute. */
class ILIAS_NET2_EXPORT promise_fail_error :
	public virtual promise_deref_error
{
public:
	virtual ~promise_fail_error() ILIAS_NET2_NOTHROW;
	virtual const char *what() const ILIAS_NET2_NOTHROW;
};
class ILIAS_NET2_EXPORT promise_fin_twice_error :
	public virtual promise_fin_error
{
public:
	virtual ~promise_fin_twice_error() ILIAS_NET2_NOTHROW;
	virtual const char *what() const ILIAS_NET2_NOTHROW;
};
class ILIAS_NET2_EXPORT promise_fin_noinit_error :
	public virtual promise_noinit_error,
	public virtual promise_fin_error
{
public:
	virtual ~promise_fin_noinit_error() ILIAS_NET2_NOTHROW;
	virtual const char *what() const ILIAS_NET2_NOTHROW;
};


enum promise_create_t { PROMISE_CREATE };	/* Tag for constructor. */


ILIAS_NET2_EXPORT
void do_promise_deref_exception(struct net2_promise*, int, uint32_t)
    throw (promise_deref_error);
ILIAS_NET2_EXPORT
void do_promise_fin_exception(struct net2_promise*, int)
    throw (std::bad_alloc, std::invalid_argument, promise_fin_error);


/* Promise wrapper. */
template<typename Result>
class promise {
public:
	typedef Result result_type;

private:
	struct net2_promise *p;

public:
	promise() ILIAS_NET2_NOTHROW;
	promise(promise_create_t) throw (std::bad_alloc);
	explicit promise(struct net2_promise*) ILIAS_NET2_NOTHROW;
	promise(const promise&) ILIAS_NET2_NOTHROW;
#if HAS_RVALUE_REF
	promise(promise&&) ILIAS_NET2_NOTHROW;
#endif
	~promise() ILIAS_NET2_NOTHROW;

	promise& operator= (const promise&) ILIAS_NET2_NOTHROW;
#if HAS_RVALUE_REF
	promise& operator= (promise&&) ILIAS_NET2_NOTHROW;
#endif
	bool operator== (const promise&) ILIAS_NET2_NOTHROW;

	struct net2_promise *c_promise() const ILIAS_NET2_NOTHROW;

	bool is_running() const ILIAS_NET2_NOTHROW;
	bool is_cancel_req() const ILIAS_NET2_NOTHROW;
	bool is_finished() const ILIAS_NET2_NOTHROW;

	void start() throw (promise_noinit_error);
	void wait() const throw (promise_noinit_error);
	void cancel() throw (promise_noinit_error);

	result_type* get(bool) const throw (promise_deref_error);
	result_type& operator* () const throw (promise_deref_error);
	result_type* operator-> () const throw (promise_deref_error);

	template<typename Finalizer>
	void fin_ok(result_type*, Finalizer fin) throw (std::bad_alloc, std::invalid_argument, promise_fin_error);
	void fin_ok(result_type*) throw (std::bad_alloc, std::invalid_argument, promise_fin_error);
	void fin_error(uint32_t) throw (std::bad_alloc, std::invalid_argument, promise_fin_error);
	void fin_cancel() throw (std::bad_alloc, std::invalid_argument, promise_fin_error);

private:
	result_type* get_internal(bool, int*, uint32_t*) const ILIAS_NET2_NOTHROW;
	static void do_delete(result_type*, void*) ILIAS_NET2_NOTHROW;
};


template<typename T>
promise<T>::promise() ILIAS_NET2_NOTHROW :
	p(0)
{
	return;
}

template<typename T>
promise<T>::promise(promise_create_t) throw (std::bad_alloc) :
	p(net2_promise_new())
{
	if (!p)
		throw std::bad_alloc();
}

template<typename T>
promise<T>::promise(struct net2_promise *np) ILIAS_NET2_NOTHROW :
	p(np)
{
	if (p)
		net2_promise_ref(p);
}

template<typename T>
promise<T>::promise(const promise<T>& rhs) ILIAS_NET2_NOTHROW :
	p(rhs.p)
{
	if (p)
		net2_promise_ref(p);
}

#if HAS_RVALUE_REF
template<typename T>
promise<T>::promise(promise<T>&& rhs) ILIAS_NET2_NOTHROW :
	p(rhs.p)
{
	rhs.p = 0;
	if (p)
		net2_promise_ref(p);
}
#endif

template<typename T>
promise<T>::~promise() ILIAS_NET2_NOTHROW
{
	if (p)
		net2_promise_release(p);
}

template<typename T>
promise<T>&
promise<T>::operator= (const promise<T>& rhs) ILIAS_NET2_NOTHROW
{
	if (p)
		net2_promise_release(p);
	p = rhs.p;
	if (p)
		net2_promise_ref(p);
	return *this;
}

#if HAS_RVALUE_REF
template<typename T>
promise<T>&
promise<T>::operator= (promise<T>&& rhs) ILIAS_NET2_NOTHROW
{
	if (p)
		net2_promise_release(p);
	p = rhs.p;
	rhs.p = 0;
	return *this;
}
#endif

template<typename T>
bool
promise<T>::operator== (const promise& rhs) ILIAS_NET2_NOTHROW
{
	return p == rhs.p;
}

template<typename T>
net2_promise*
promise<T>::c_promise() const ILIAS_NET2_NOTHROW
{
	return p;
}

template<typename T>
bool
promise<T>::is_running() const ILIAS_NET2_NOTHROW
{
	return p && net2_promise_is_running(p);
}

template<typename T>
bool
promise<T>::is_cancel_req() const ILIAS_NET2_NOTHROW
{
	return p && net2_promise_is_cancelreq(p);
}

template<typename T>
bool
promise<T>::is_finished() const ILIAS_NET2_NOTHROW
{
	return p && net2_promise_is_finished(p);
}

template<typename T>
void
promise<T>::start() throw (promise_noinit_error)
{
	if (!p)
		throw promise_noinit_error();
	net2_promise_start(p);
}

template<typename T>
void
promise<T>::wait() const throw (promise_noinit_error)
{
	if (!p)
		throw promise_noinit_error();
	net2_promise_wait(p);
}

template<typename T>
void
promise<T>::cancel() throw (promise_noinit_error)
{
	if (!p)
		throw promise_noinit_error();
	net2_promise_cancel(p);
}

template<typename T>
typename promise<T>::result_type*
promise<T>::get_internal(bool do_wait, int* fin, uint32_t* err) const ILIAS_NET2_NOTHROW
{
	void		*vptr;

	if (p) {
		if (do_wait)
			this->wait();
		*fin = net2_promise_get_result(p, &vptr, err);
		if (*fin == NET2_PROM_FIN_OK && vptr != 0)
			return reinterpret_cast<result_type*>(vptr);
	}
	return 0;
}

template<typename T>
typename promise<T>::result_type&
promise<T>::operator* () const throw (promise_deref_error)
{
	int		fin;
	uint32_t	err;

	result_type *rv = get_internal(true, &fin, &err);
	if (!rv)
		do_promise_deref_exception(p, fin, err);
	return *rv;
}

template<typename T>
typename promise<T>::result_type*
promise<T>::operator-> () const throw (promise_deref_error)
{
	int		fin;
	uint32_t	err;

	result_type *rv = get_internal(true, &fin, &err);
	if (!rv)
		do_promise_deref_exception(p, fin, err);
	return rv;
}

template<typename T>
typename promise<T>::result_type*
promise<T>::get(bool do_wait) const throw (promise_deref_error)
{
	int		fin;
	uint32_t	err;

	if (!p)
		return 0;
	result_type *rv = get_internal(do_wait, &fin, &err);
	if (!rv && fin != NET2_PROM_FIN_UNFINISHED)
		do_promise_deref_exception(p, fin, err);
	return *rv;
}


template<typename Finalizer>
void
_run_finalizer(void* ILIAS_NET2__unused unused, void *f_ptr) ILIAS_NET2_NOTHROW
{
	Finalizer	*f = reinterpret_cast<Finalizer>(f);

	(*f)();
	delete f;
}

template<typename T>
template<typename Finalizer>
void
promise<T>::fin_ok(typename promise<T>::result_type *r, Finalizer fin) throw (std::bad_alloc, std::invalid_argument, promise_fin_error)
{
	Finalizer	*fin_functor = new Finalizer(fin);
	void		(*free)(void*, void*) = &_run_finalizer<Finalizer>;

	int err = net2_promise_set_finok(p, reinterpret_cast<void*>(r),
	    free, fin_functor, 0);
	if (err != 0) {
		delete fin_functor;
		do_promise_fin_exception(p, err);
	}
}

template<typename T>
void
promise<T>::do_delete(typename promise<T>::result_type *r, void*) ILIAS_NET2_NOTHROW
{
	delete r;
}

template<typename T>
void
promise<T>::fin_ok(typename promise<T>::result_type *r) throw (std::bad_alloc, std::invalid_argument, promise_fin_error)
{
	void		(*free)(result_type*, void*) =
	    &promise<T>::do_delete;

	int err = net2_promise_set_finok(p, reinterpret_cast<void*>(r),
	    reinterpret_cast<void (*)(void*, void*)>(free), 0, 0);
	if (err)
		do_promise_fin_exception(p, err);
}

template<typename T>
void
promise<T>::fin_error(uint32_t v) throw (std::bad_alloc, std::invalid_argument, promise_fin_error)
{
	int err = net2_promise_set_error(p, v, 0);
	if (err)
		do_promise_fin_exception(p, err);
}

template<typename T>
void
promise<T>::fin_cancel() throw (std::bad_alloc, std::invalid_argument, promise_fin_error)
{
	int err = net2_promise_set_cancel(p, 0);
	if (err)
		do_promise_fin_exception(p, err);
}


#if defined(HAVE_TYPE_TRAITS) && HAS_VARARG_TEMPLATES && HAS_DECLTYPE && HAS_RVALUE_REF


/*
 * Intermediary invoker.
 * Converts one element from in[] promises to a c++ promise, recursively transforming all
 * into a set of c++ promises.
 */
template<typename Prom0, typename... Promises, typename Functor, typename Result, typename... Args>
void
_invoke(const Functor& functor, promise<Result>& result, net2_promise** in, Args&&... args) ILIAS_NET2_NOTHROW
{
	_invoke<Promises...>(functor, result, in + 1, args..., std::move(Prom0(*in)));
}
/*
 * Final invoker.
 * Called with all promises converted.
 * Invokes the functor and assigns the result.
 */
template<typename Functor, typename Result, typename... Args>
void
_invoke(const Functor& functor, promise<Result>& result, net2_promise** ILIAS_NET2__unused in, Args&&... args) ILIAS_NET2_NOTHROW
{
	Result	*v;

	try {
		v = functor(args...);
	} catch (const promise_finerr_error& e) {
		result.fin_error(e.error);
		return;
	} catch (const promise_canceled& e) {
		result.fin_cancel();
		return;
	} catch (...) {
		/* Promise internals will assign fin_fail. */
		return;
	}

	try {
		result.fin_ok(v);
	} catch (...) {
		if (v)
			result.do_delete(v, 0);
	}
}
/*
 * Combiner callback wrapper.
 * Invokes the functor via _invoke() transformation.
 */
template<typename Functor, typename Result, typename... Promises>
void
_invoke_promise_combiner(struct net2_promise *out, struct net2_promise **in, size_t insz, void *arg) ILIAS_NET2_NOTHROW
{
	promise<Result> cxx_out(out);
	Functor *functor = reinterpret_cast<Functor*>(arg);

	assert(sizeof...(Promises) == insz);
	_invoke<Promises...>(*functor, cxx_out, in);
}
/*
 * Templated destructor.
 */
template<typename Functor>
void
_promise_delete_functor(void *f_ptr, void *unused ILIAS_NET2__unused) ILIAS_NET2_NOTHROW
{
	Functor *f = reinterpret_cast<Functor*>(f_ptr);
	if (f)
		delete f;
}

/*
 * Promise combiner.
 * Combines the functor and promises into a combi promise.
 */
template<typename Functor, typename... Promises>
auto promise_combine(const workq& wq, const Functor& f, const Promises&... promises) ->
    promise<typename std::remove_reference<decltype(*f(promises...))>::type>&&
{
	typedef promise<typename std::remove_reference<decltype(*f(promises...))>::type> out_type;

	struct net2_promise	*c_proms[] = { promises.c_promise()... };
	net2_promise_ccb	 ccb = &_invoke_promise_combiner<Functor, typename out_type::result_type, Promises...>;
	Functor			*arg = new Functor(f);

	struct net2_promise	*result = net2_promise_combine(wq.c_workq(), ccb, reinterpret_cast<void*>(arg), c_proms, sizeof...(Promises));
	if (!result) {
		delete arg;
		throw std::bad_alloc();
	}
	net2_promise_destroy_cb(result, &_promise_delete_functor<Functor>, arg, NULL);
	return std::move(out_type(result));
}

/*
 * Promise combiner.
 * Combines the functor and promises into a combi promise.
 * Using move constructor for functor.
 */
template<typename Functor, typename... Promises>
auto promise_combine(const workq& wq, Functor&& f, const Promises&... promises) ->
    promise<typename std::remove_reference<decltype(*f(promises...))>::type>&&
{
	typedef promise<typename std::remove_reference<decltype(*f(promises...))>::type> out_type;

	struct net2_promise	*c_proms[] = { promises.c_promise()... };
	net2_promise_ccb	 ccb = &_invoke_promise_combiner<Functor, typename out_type::result_type, Promises...>;
	Functor			*arg = new Functor(f);

	struct net2_promise	*result = net2_promise_combine(wq.c_workq(), ccb, reinterpret_cast<void*>(arg), c_proms, sizeof...(Promises));
	if (!result) {
		delete arg;
		throw std::bad_alloc();
	}
	net2_promise_destroy_cb(result, &_promise_delete_functor<Functor>, arg, NULL);
	return std::move(out_type(result));
}


#endif /* defined(HAVE_TYPE_TRAITS) && HAS_VARARG_TEMPLATES && HAS_DECLTYPE && HAS_RVALUE_REF */


}

#endif /* __cplusplus */

#endif /* ILIAS_NET2_PROMISE_H */
