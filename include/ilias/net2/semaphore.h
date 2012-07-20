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
#ifndef ILIAS_NET2_SEMAPHORE_H
#define ILIAS_NET2_SEMAPHORE_H

#include <ilias/net2/ilias_net2_export.h>

ILIAS_NET2__begin_cdecl


#ifdef _WIN32
#include <windows.h>

struct net2_semaphore {
	HANDLE			 s;
	CRITICAL_SECTION	 down_excl;
};

static __inline int
net2_semaphore_initval(struct net2_semaphore *s, unsigned int initval)
{
	if ((s->s = CreateSemaphore(NULL, initval, (unsigned int)-1, NULL)) == NULL)
		return ENOMEM;
	InitializeCriticalSection(&s->down_excl);
	return 0;
}

static __inline void
net2_semaphore_deinit(struct net2_semaphore *s)
{
	CloseHandle(s->s);
	DeleteCriticalSection(&s->down_excl);
}

static __inline void
net2_semaphore_up(struct net2_semaphore *s, unsigned int count)
{
	ReleaseSemaphore(s->s, count, NULL);
}

static __inline void
net2_semaphore_down(struct net2_semaphore *s, unsigned int count)
{
	EnterCriticalSection(&s->down_excl);
	while (count > 0) {
		if (WaitForSingleObject(s->s, INFINITE) == WAIT_OBJECT_0)
			count--;
	}
	LeaveCriticalSection(&s->down_excl);
}

static __inline int
net2_semaphore_trydown(struct net2_semaphore *s, unsigned int count)
{
	unsigned int		 dec;
	DWORD			 wait;

	dec = 0;
	EnterCriticalSection(&s->down_excl);
	while (dec < count) {
		wait = WaitForSingleObject(s->s, 0);
		if (wait == WAIT_OBJECT_0)
			dec++;
		else if (wait == WAIT_TIMEOUT) {
			/* Undo the damage and report failure. */
			ReleaseSemaphore(s->s, dec, NULL);
			LeaveCriticalSection(&s->down_excl);
			return 0;
		}
	}
	LeaveCriticalSection(&s->down_excl);
	return 1;
}

#elif defined(HAVE_STDATOMIC_H)
#include <stdatomic.h>

struct net2_semaphore {
	atomic_uint		 v;
};

static __inline int
net2_semaphore_initval(struct net2_semaphore *s, unsigned int initial)
{
	atomic_init(&s->v, initial);
	return 0;
}

static __inline void
net2_semaphore_deinit(struct net2_semaphore *s ILIAS_NET2__unused)
{
	return;
}

static __inline void
net2_semaphore_up(struct net2_semaphore *s, unsigned int count)
{
	atomic_fetch_add_explicit(&s->v, count, memory_order_release);
}

static __inline int
net2_semaphore_down(struct net2_semaphore *s, unsigned int count)
{
	unsigned int		 v, new_v, dec;

	v = atomic_load_explicit(&s->v, memory_order_consume);
	while (count > 0) {
		do {
			while (v == 0) {
				pthread_yield();
				v = atomic_load_explicit(&s->v, memory_order_consume);
			}
			dec = (v < count ? v : count);
			new_v = v - dec;
		} while (!atomic_compare_exchange_weak_explicit(&s->v, v, new_v, memory_order_acquire, memory_order_consume));
		count -= dec;
		v = new_v;
	}
}

static __inline int
net2_semaphore_trydown(struct net2_semaphore *s, unsigned int count)
{
	unsigned int		 v, new_v;

	v = atomic_load_explicit(&s->v, memory_order_consume);
	do {
		if (v < count)
			return 0;
		new_v = v - count;
	} while (!atomic_compare_exchange_weak_explicit(&s->v, v, new_v, memory_order_acquire, memory_order_consume));
	return 1;
}

#else /* !HAVE_STDATOMIC_H */
#include <ilias/net2/mutex.h>

struct net2_semaphore {
	struct net2_mutex	*mtx;
	struct net2_condition	*cnd;
	unsigned int		 v;
};

ILIAS_NET2_LOCAL int
net2_semaphore_initval(struct net2_semaphore *s, unsigned int initial)
{
	if ((s->mtx = net2_mutex_alloc()) == NULL)
		goto fail_0;
	if ((s->cnd = net2_cond_alloc()) == NULL)
		goto fail_1;
	s->v = initial;
	return 0;


fail_2:
	net2_cond_free(s->cnd);
fail_1:
	net2_mutex_free(s->mtx);
fail_0:
	return ENOMEM;
}

ILIAS_NET2_LOCAL void
net2_semaphore_deinit(struct net2_semaphore *s)
{
	net2_cond_free(s->cnd);
	net2_mutex_free(s->mtx);
}

ILIAS_NET2_LOCAL void
net2_semaphore_up(struct net2_semaphore *s, unsigned int count)
{
	net2_mutex_lock(s->mtx);
	s->v += count;
	while (count-- > 0)
		net2_cond_signal(s->cnd);
	net2_mutex_unlock(s->mtx);
}

ILIAS_NET2_LOCAL void
net2_semaphore_down(struct net2_semaphore *s, unsigned int count)
{
	net2_mutex_lock(s->mtx);
	while (count > 0) {
		while (s->v == 0)
			net2_cond_wait(s->cnd, s->mtx);
		if (s->v >= count) {
			s->v -= count;
			count = 0;
		} else {
			count -= s->v;
			s->v = 0;
		}
	}
	net2_mutex_unlock(s->mtx);
}

ILIAS_NET2_LOCAL int
net2_semaphore_trydown(struct net2_semaphore *s, unsigned int count)
{
	int	succeeded;

	net2_mutex_lock(s->mtx);
	if (v < count)
		succeeded = 0;
	else {
		v -= count;
		succeeded = 1;
	}
	net2_mutex_unlock(s->mtx);
	return succeeded;
}
#endif /* HAVE_STDATOMIC_H */

static __inline int
net2_semaphore_init(struct net2_semaphore *s)
{
	return net2_semaphore_init(s, 0);
}


ILIAS_NET2__end_cdecl
#endif /* ILIAS_NET2_SEMAPHORE_H */
