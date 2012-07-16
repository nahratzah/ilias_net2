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
#ifndef ILIAS_NET2_REFCNT_H
#define ILIAS_NET2_REFCNT_H

#include <ilias/net2/config.h>
#include <ilias/net2/mutex.h>
#include <assert.h>


#define NET2_REFCNT_LOCK_ENTER	0x00000001	/* Has lock on entry. */
#define NET2_REFCNT_LOCK_EXIT	0x00000002	/* Keep lock on exit. */

#if defined(HAVE_STDATOMIC_H) || defined(__clang__)
#ifndef HAVE_STDATOMIC_H
#include <ilias/net2/bsd_compat/stdatomic.h>
#else
#include <stdatomic.h>
#endif
#include <sys/types.h>
#include <stdint.h>

ILIAS_NET2__begin_cdecl

#define NET2_MUTEX_FOR_REFCNT(_x)	/* No mutex required. */
#define NET2_MUTEX_GET_REFCNT(_x)	(NULL)
#define NET2_REFCNT_IS_ATOMIC	1
typedef atomic_size_t net2_refcnt_t;

static inline void
net2_refcnt_ref(net2_refcnt_t *refcnt, struct net2_mutex *mtx, int flags)
{
	if (mtx) {
		if (!(flags & NET2_REFCNT_LOCK_ENTER) &&
		    (flags & NET2_REFCNT_LOCK_EXIT))
			net2_mutex_lock(mtx);
	}

	if (atomic_fetch_add(refcnt, 1) == (size_t)-1)
		assert(0);	/* Overflow. */

	if (mtx) {
		if ((flags & NET2_REFCNT_LOCK_ENTER) &&
		    !(flags & NET2_REFCNT_LOCK_EXIT))
			net2_mutex_unlock(mtx);
	}
}
static inline int
net2_refcnt_release(net2_refcnt_t *refcnt, struct net2_mutex *mtx, int flags)
{
	int			 do_free;

	if (mtx) {
		if (!(flags & NET2_REFCNT_LOCK_ENTER) &&
		    (flags & NET2_REFCNT_LOCK_EXIT))
			net2_mutex_lock(mtx);
	}

	do_free = (atomic_fetch_sub(refcnt, 1) == 1);

	if (mtx) {
		if ((flags & NET2_REFCNT_LOCK_ENTER) &&
		    !(flags & NET2_REFCNT_LOCK_EXIT))
			net2_mutex_unlock(mtx);
	}

	return do_free;
}
static inline void
net2_refcnt_set(net2_refcnt_t *refcnt, unsigned initial)
{
	atomic_init(refcnt, initial);
}
static inline int
net2_refcnt_iszero(net2_refcnt_t *refcnt)
{
	return atomic_load(refcnt) == 0;
}
static inline size_t
net2_refcnt_get(net2_refcnt_t *refcnt, struct net2_mutex *mtx, int flags)
{
	size_t			 rv;

	if (mtx) {
		if (!(flags & NET2_REFCNT_LOCK_ENTER) &&
		    (flags & NET2_REFCNT_LOCK_EXIT))
			net2_mutex_lock(mtx);
	}

	rv = atomic_load(refcnt);

	if (mtx) {
		if ((flags & NET2_REFCNT_LOCK_ENTER) &&
		    !(flags & NET2_REFCNT_LOCK_EXIT))
			net2_mutex_unlock(mtx);
	}

	return rv;
}

ILIAS_NET2__end_cdecl
#else	/* no stdatomic.h */
#include <sys/types.h>
#include <stdint.h>

ILIAS_NET2__begin_cdecl

#define NET2_MUTEX_FOR_REFCNT(_x)	struct net2_mutex *_x
#define NET2_MUTEX_REFCNT(_x)		(_x)
typedef size_t net2_refcnt_t;

static inline void
net2_refcnt_ref(net2_refcnt_t *refcnt, struct net2_mutex *mtx, int flags)
{
	if (!(flags & NET2_REFCNT_LOCK_ENTER))
		net2_mutex_lock(mtx);
	(*refcnt)++;
	assert(*refcnt > 0);
	if (!(flags & NET2_REFCNT_LOCK_EXIT))
		net2_mutex_unlock(mtx);
}
static inline int
net2_refcnt_release(net2_refcnt_t *refcnt, struct net2_mutex *mtx, int flags)
{
	int			 do_free;

	if (!(flags & NET2_REFCNT_LOCK_ENTER))
		net2_mutex_lock(mtx);
	assert(*refcnt > 0);
	do_free = (--(*refcnt) == 0);
	if (!(flags & NET2_REFCNT_LOCK_EXIT))
		net2_mutex_unlock(mtx);

	return do_free;
}
static inline void
net2_refcnt_set(net2_refcnt_t *refcnt, unsigned initial)
{
	*refcnt = initial;
}
static inline int
net2_refcnt_iszero(net2_refcnt_t *refcnt)
{
	return *refcnt == 0;
}
static inline size_t
net2_refcnt_get(net2_refcnt_t *refcnt, struct net2_mutex *mtx, int flags)
{
	size_t			 rv;

	if (!(flags & NET2_REFCNT_LOCK_ENTER))
		net2_mutex_lock(mtx);
	rv = *refcnt;
	if (!(flags & NET2_REFCNT_LOCK_EXIT))
		net2_mutex_unlock(mtx);

	return rv;
}

ILIAS_NET2__end_cdecl
#endif

#endif /* ILIAS_NET2_REFCNT_H */
