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
#include <assert.h>
#include <errno.h>

enum state {
	ATTACHED,	/* Collect me or detach me. */
	ATTACHED_FREE,	/* Go to DETACHED_FREE. */
	DETACHED,	/* Don't collect me: HANDLE = NULL. */
	DETACHED_FREE,	/* Thread is last owner: HANDLE = NULL. */
	DYING,		/* Collect me. */
	DEAD,		/* Collected or detached dead thread: HANDLE = null */
	FAKE		/* Not a thread: HANDLE = null */
};

struct net2_thread {
	CRITICAL_SECTION s;
	enum state	 state;
	unsigned	 tid;
	HANDLE		 handle;
	void		*result;
	void		*(*fn)(void*);
	void		*arg;
};

__declspec(thread) static struct net2_thread *tls_thread;

static DWORD __stdcall
thread_wrapper(void *tptr)
{
	struct net2_thread *t = tptr;

	tls_thread = t;
	t->result = t->fn(t->arg);
	tls_thread = NULL;

	/* Close the handle ourselves, if the thread is detached. */
	EnterCriticalSection(&t->s);
	switch (t->state) {
	case ATTACHED:
		t->state = DYING;
		LeaveCriticalSection(&t->s);
		break;
	case DETACHED:
		t->state = DEAD;
		LeaveCriticalSection(&t->s);
		break;
	case ATTACHED_FREE:
		CloseHandle(t->handle);
		/* FALLTHROUGH */
	case DETACHED_FREE:
		/* We are the last owner of this. */
		LeaveCriticalSection(&t->s);
		DeleteCriticalSection(&t->s);
		net2_free(t);
		break;
	default:
		abort();
	}
	_endthreadex(0);
	return 0;
}

/* Thread name exception (MSVC debugger listens to this). */
static const DWORD MS_VC_EXCEPTION=0x406D1388;

#pragma pack(push,8)
typedef struct tagTHREADNAME_INFO
{
	DWORD dwType; // Must be 0x1000.
	LPCSTR szName; // Pointer to name (in user addr space).
	DWORD dwThreadID; // Thread ID (-1=caller thread).
	DWORD dwFlags; // Reserved for future use, must be zero.
} THREADNAME_INFO;
#pragma pack(pop)

static void
SetThreadName(DWORD dwThreadID, char *threadName)
{
	THREADNAME_INFO info;
	info.dwType = 0x1000;
	info.szName = threadName;
	info.dwThreadID = dwThreadID;
	info.dwFlags = 0;

	__try
	{
		RaiseException(MS_VC_EXCEPTION, 0,
		    sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
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
	InitializeCriticalSection(&t->s);
	t->state = ATTACHED;

	t->handle = (HANDLE)_beginthreadex(NULL, 0, &thread_wrapper, t,
	    CREATE_SUSPENDED, &t->tid);
	/*
	 * Comments on MSDN suggest the function may also return 0.
	 * Since the result is a HANDLE, NULL is unlikely to be valid.
	 * Therefore check against both -1 and 0, just to be on the safe side.
	 */
	if (t->handle == ((HANDLE)((uintptr_t)-1)) ||
	    t->handle == ((HANDLE)((uintptr_t) 0))) {
		DeleteCriticalSection(&t->s);
		net2_free(t);
		return NULL;
	}

	/* Assign thread name. */
	SetThreadName(t->tid, (char*)name);
	/* Start the thread now its thread structure is complete. */
	ResumeThread(t->handle);

	return t;
}

/* Join a thread. */
ILIAS_NET2_LOCAL int
net2_thread_join(struct net2_thread *t, void **out)
{
	/* Cannot join detached or fake threads. */
	assert(t->tid != GetCurrentThreadId());
	EnterCriticalSection(&t->s);
	assert(t->state == ATTACHED || t->state == DYING);
	LeaveCriticalSection(&t->s);

	if (WaitForSingleObject(t->handle, INFINITE) != WAIT_OBJECT_0)
		return -1;
	EnterCriticalSection(&t->s);
	assert(t->state == DYING);
	t->state = DEAD;
	LeaveCriticalSection(&t->s);
	CloseHandle(t->handle);
	t->handle = NULL;
	if (out != NULL)
		*out = t->result;
	return 0;
}

/* Free a thread. */
ILIAS_NET2_LOCAL void
net2_thread_free(struct net2_thread *t)
{
	EnterCriticalSection(&t->s);
	switch (t->state) {
	case DYING:
		/* We need to collect the thread. */
		if (WaitForSingleObject(t->handle, INFINITE) != WAIT_OBJECT_0)
			abort();
		CloseHandle(t->handle);
		t->state = DEAD;
		/* FALLTHROUGH */
	case DEAD:
	case FAKE:
		LeaveCriticalSection(&t->s);
		net2_free(t);
		return;
	case ATTACHED:
		t->state = ATTACHED_FREE;
		break;
	case DETACHED_FREE:
		break;
	case DETACHED:
		t->state = DETACHED_FREE;
		break;
	case ATTACHED_FREE:
		abort();
	}
	LeaveCriticalSection(&t->s);
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
	InitializeCriticalSection(&t->s);
	t->state = FAKE;
	t->tid = GetCurrentThreadId();
	return t;
}

/* Detach the current thread. */
ILIAS_NET2_LOCAL void
net2_thread_detach_self()
{
	struct net2_thread	*t = tls_thread;

	assert(t != NULL);
	EnterCriticalSection(&t->s);
	switch (t->state) {
	case ATTACHED:
		t->state = DETACHED;
		break;
	case ATTACHED_FREE:
		t->state = DETACHED_FREE;
		break;
	case DETACHED:
	case DETACHED_FREE:
		/* Already detached, allow multi call. */
		break;
	default:
		abort();
	}
	LeaveCriticalSection(&t->s);
}
