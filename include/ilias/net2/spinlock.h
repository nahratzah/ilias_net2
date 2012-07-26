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
#ifndef ILIAS_NET2_SPINLOCK_H
#define ILIAS_NET2_SPINLOCK_H

#include <ilias/net2/ilias_net2_export.h>

ILIAS_NET2__begin_cdecl

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef CRITICAL_SECTION	net2_spinlock;

static __inline int
net2_spinlock_init(net2_spinlock *l)
{
	InitializeCriticalSectionAndSpinCount(l, 0x4000);
	return 0;
}
static __inline void
net2_spinlock_deinit(net2_spinlock *l)
{
	DeleteCriticalSection(l);
}
static __inline void
net2_spinlock_lock(net2_spinlock *l)
{
	EnterCriticalSection(l);
}
static __inline int
net2_spinlock_trylock(net2_spinlock *l)
{
	return TryEnterCriticalSection(l);
}
static __inline void
net2_spinlock_unlock(net2_spinlock *l)
{
	LeaveCriticalSection(l);
}
#else	/* Posix implementation. */
#include <pthread.h>
#include <errno.h>
#include <assert.h>

typedef pthread_spinlock_t	net2_spinlock;

static __inline int
net2_spinlock_init(net2_spinlock *l)
{
	int		 rv;

	rv = pthread_spin_init(l, PTHREAD_PROCESS_PRIVATE);
	assert(rv != EINVAL && rv != EBUSY);
	return rv;
}
static __inline void
net2_spinlock_deinit(net2_spinlock *l)
{
	int		 rv;

	rv = pthread_spin_destroy(l);
	assert(rv == 0);
}
static __inline void
net2_spinlock_lock(net2_spinlock *l)
{
	int		 rv;

	rv = pthread_spin_lock(l);
	assert(rv == 0);
}
static __inline int
net2_spinlock_trylock(net2_spinlock *l)
{
	int		 rv;

	rv = pthread_spin_lock(l);
	if (rv == EBUSY)
		return 0;
	assert(rv == 0);
	return 1;
}
static __inline void
net2_spinlock_unlock(net2_spinlock *l)
{
	int		 rv;

	rv = pthread_spin_unlock(l);
	assert(rv == 0);
}
#endif


ILIAS_NET2__end_cdecl
#endif /* ILIAS_NET2_SPINLOCK_H */
