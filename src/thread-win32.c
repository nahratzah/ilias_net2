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
#include <ilias/net2/thread.h>
#include <ilias/net2/bsd_compat/error.h>
#include <ilias/net2/memory.h>
#include <stdlib.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <process.h>

#include <ilias/net2/config.h>
#ifdef HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include <ilias/net2/bsd_compat/tree.h>
#endif

struct net2_thread {
	HANDLE		 handle;
	void		*result;
	void		*(*fn)(void*);
	void		*arg;
	unsigned	 tid;
	int		 detached;

	RB_ENTRY(net2_thread)
			 rb;
};

/* Store threads in a set, based on the tid; s is the protector. */
static CRITICAL_SECTION s;
static RB_HEAD(win32_threads, net2_thread) global = RB_INITIALIZER(&global);

static __inline int
tid_cmp(struct net2_thread *t1, struct net2_thread *t2)
{
	return (t1->tid < t2->tid ? -1 : t1->tid > t2->tid);
}

RB_PROTOTYPE_STATIC(win32_threads, net2_thread, rb, tid_cmp);

static DWORD __stdcall
thread_wrapper(void *tptr)
{
	struct net2_thread *t = tptr;

	t->result = t->fn(t->arg);
	_endthreadex(0);

	/* Close the handle ourselves, if the thread is detached. */
	EnterCriticalSection(&s);
	if (t->detached)
		CloseHandle(t->handle);
	LeaveCriticalSection(&s);
	return 0;
}

/*
 * Start a new thread.
 *
 * Note that the critical section (s) is held at startup of the thread,
 * until the global list of threads has been updated.
 * This ensures the newly created thread will block before trying to
 * update global itself (for example because the first instruction in
 * the thread is to detach itself).
 */
ILIAS_NET2_LOCAL struct net2_thread*
net2_thread_new(void *(*fn)(void*), void *arg, const char *name)
{
	struct net2_thread	*t;

	if ((t = net2_malloc(sizeof(*t))) == NULL)
		return NULL;
	t->fn = fn;
	t->arg = arg;
	t->result = NULL;

	EnterCriticalSection(&s);
	t->handle = (HANDLE)_beginthreadex(NULL, 0, &thread_wrapper, t,
	    CREATE_SUSPENDED, &t->tid);
	/*
	 * Comments on MSDN suggest the function may also return 0.
	 * Since the result is a HANDLE, NULL is unlikely to be valid.
	 * Therefore check against both -1 and 0, just to be on the safe side.
	 */
	if (t->handle == ((HANDLE)((uintptr_t)-1)) ||
	    t->handle == ((HANDLE)((uintptr_t) 0))) {
		LeaveCriticalSection(&s);
		net2_free(t);
		return NULL;
	}

	RB_INSERT(win32_threads, &global, t);
	LeaveCriticalSection(&s);
	ResumeThread(t->handle);

	return t;
}

/* Join a thread. */
ILIAS_NET2_LOCAL int
net2_thread_join(struct net2_thread *t, void **out)
{
	if (WaitForSingleObject(t->handle, INFINITE) != WAIT_OBJECT_0)
		return -1;
	CloseHandle(t->handle);
	if (out != NULL)
		*out = t->result;
	EnterCriticalSection(&s);
	RB_REMOVE(win32_threads, &global, t);
	t->detached = 1;
	LeaveCriticalSection(&s);
	return 0;
}

/* Free a thread. */
ILIAS_NET2_LOCAL void
net2_thread_free(struct net2_thread *t)
{
	EnterCriticalSection(&s);
	if (!t->detached)
		RB_REMOVE(win32_threads, &global, t);
	LeaveCriticalSection(&s);
	net2_free(t);
}

/* Test if the given thread is the current thread. */
ILIAS_NET2_LOCAL int
net2_thread_is_self(struct net2_thread *t)
{
	return t->tid == GetCurrentThreadId();
}

/* Compare 2 threads for equality. */
ILIAS_NET2_LOCAL int
net2_thread_eq(struct net2_thread *t1, struct net2_thread *t2)
{
	return t1->tid == t2->tid;
}

/* Acquire the current thread. */
ILIAS_NET2_LOCAL struct net2_thread*
net2_thread_self()
{
	struct net2_thread	*t;

	if ((t = net2_malloc(sizeof(*t))) == NULL)
		return NULL;
	t->detached = 1;
	t->tid = GetCurrentThreadId();
	return t;
}

/* Detach the current thread. */
ILIAS_NET2_LOCAL void
net2_thread_detach_self()
{
	struct net2_thread	*t, search;

	search.tid = GetCurrentThreadId();
	EnterCriticalSection(&s);
	t = RB_FIND(win32_threads, &global, &search);
	if (t != NULL && !t->detached) {
		t->detached = 1;
		RB_REMOVE(win32_threads, &global, t);
	}
	LeaveCriticalSection(&s);
}

/* Initialize thread mutex. */
ILIAS_NET2_LOCAL int
net2_thread_init()
{
	InitializeCriticalSection(&s);
	return 0;
}

/* Destroy thread mutex. */
ILIAS_NET2_LOCAL void
net2_thread_fini()
{
	DeleteCriticalSection(&s);
}

RB_GENERATE_STATIC(win32_threads, net2_thread, rb, tid_cmp);
