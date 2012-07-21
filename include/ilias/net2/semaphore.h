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
#include <ilias/net2/config.h>

ILIAS_NET2__begin_cdecl


#ifdef _WIN32
#include <windows.h>

struct net2_semaphore {
	HANDLE			 s;
};

static __inline int
net2_semaphore_initval(struct net2_semaphore *s, unsigned int initval)
{
	if ((s->s = CreateSemaphore(NULL, initval, (unsigned int)-1, NULL)) == NULL)
		return ENOMEM;
	return 0;
}

static __inline void
net2_semaphore_deinit(struct net2_semaphore *s)
{
	CloseHandle(s->s);
}

static __inline void
net2_semaphore_up(struct net2_semaphore *s, unsigned int count)
{
	ReleaseSemaphore(s->s, count, NULL);
}

static __inline void
net2_semaphore_down(struct net2_semaphore *s)
{
	while (WaitForSingleObject(s->s, INFINITE) != WAIT_OBJECT_0);
}

static __inline int
net2_semaphore_trydown(struct net2_semaphore *s)
{
	return (WaitForSingleObject(s->s, 0) == WAIT_OBJECT_0);
}

#elif defined(HAVE_STDATOMIC_H) && defined(HAS_NANOSLEEP)
#include <stdatomic.h>
#include <time.h>

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

static __inline void
net2_semaphore_down(struct net2_semaphore *s)
{
	unsigned int		 v;
	const struct timespec	 yield = { 0, 1000 };

	v = atomic_load_explicit(&s->v, memory_order_consume);
	do {
		while (v == 0) {
			nanosleep(&yield, NULL);
			v = atomic_load_explicit(&s->v, memory_order_consume);
		}
	} while (!atomic_compare_exchange_weak_explicit(&s->v, &v, v - 1, memory_order_acquire, memory_order_consume));
}

static __inline int
net2_semaphore_trydown(struct net2_semaphore *s)
{
	unsigned int		 v;

	v = atomic_load_explicit(&s->v, memory_order_consume);
	do {
		if (v == 0)
			return 0;
	} while (!atomic_compare_exchange_weak_explicit(&s->v, &v, v - 1, memory_order_acquire, memory_order_consume));
	return 1;
}

#elif defined(HAVE_SEMAPHORE_H)
#include <semaphore.h>

struct net2_semaphore {
	sem_t			 s;
};

static __inline int
net2_semaphore_initval(struct net2_semaphore *s, unsigned int initial)
{
	int			 rv;

	if (sem_init(&s->s, 0, initial)) {
		if (errno == ENOSPC || errno == ENOMEM)
			return ENOMEM;
		return EINVAL;
	}
	return 0;
}

static __inline void
net2_semaphore_deinit(struct net2_semaphore *s)
{
	sem_destroy(&s->s);
}

static __inline void
net2_semaphore_up(struct net2_semaphore *s, unsigned int count)
{
	while (count-- > 0)
		sem_post(&s->s);
}

static __inline void
net2_semaphore_down(struct net2_semaphore *s)
{
	while (sem_wait(&s->s))
		assert(errno == EINTR);
}

static __inline int
net2_semaphore_trydown(struct net2_semaphore *s)
{
	return !sem_trywait(&s->s);
}

#else /* !HAVE_STDATOMIC_H, !HAVE_SEMAPHORE_H */
#include <ilias/net2/mutex.h>

struct net2_semaphore {
	struct net2_mutex	*mtx;
	struct net2_condition	*cnd;
	unsigned int		 v;
};

ILIAS_NET2_LOCAL
int	net2_semaphore_initval(struct net2_semaphore*, unsigned int);
ILIAS_NET2_LOCAL
void	net2_semaphore_deinit(struct net2_semaphore*);
ILIAS_NET2_LOCAL
void	net2_semaphore_up(struct net2_semaphore*, unsigned int);
ILIAS_NET2_LOCAL
void	net2_semaphore_down(struct net2_semaphore*);
ILIAS_NET2_LOCAL
int	net2_semaphore_trydown(struct net2_semaphore*);
#endif /* HAVE_STDATOMIC_H */

static __inline int
net2_semaphore_init(struct net2_semaphore *s)
{
	return net2_semaphore_initval(s, 0);
}


ILIAS_NET2__end_cdecl
#endif /* ILIAS_NET2_SEMAPHORE_H */
