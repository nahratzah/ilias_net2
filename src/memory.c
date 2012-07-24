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
#include <ilias/net2/memory.h>

#ifdef NET2_USE_EXUDE_DEBUG

#include <ilias/net2/mutex.h>
#include <exude.h>
#include <clog.h>

static struct net2_mutex	*exude_mtx = NULL;

/*
 * Allocate memory mutex.
 *
 * Note: this is before ilias_net2 uses any threads.
 */
void
net2_memory_init()
{
	exude_mtx = net2_mutex_alloc();
}

/*
 * Free memory mutex.
 *
 * Note: this is after ilias_net2 uses any threads.
 */
void
net2_memory_fini()
{
	struct net2_mutex	*mtx;
	mtx = exude_mtx;
	exude_mtx = NULL;

	net2_mutex_free(mtx);
}


#define LOCK()								\
	do {								\
		if (exude_mtx != NULL)					\
			net2_mutex_lock(exude_mtx);			\
	} while (0)
#define UNLOCK()							\
	do {								\
		if (exude_mtx != NULL)					\
			net2_mutex_unlock(exude_mtx);			\
	} while (0)

/*
 * Wrappers around exude allocators.
 *
 * These provide exclusion using exude_mtx as declared and initialized above.
 */

ILIAS_NET2_LOCAL void*
net2_malloc_(size_t s, const char *file, const char *function, int line)
{
	void		*p;

	LOCK();
	p = e_malloc_debug(s, file, function, line);
	UNLOCK();
	return p;
}

ILIAS_NET2_LOCAL void*
net2_realloc_(void *p, size_t s, const char *file, const char *function, int line)
{
	LOCK();
	p = e_realloc_debug(p, s, file, function, line);
	UNLOCK();
	return p;
}

ILIAS_NET2_LOCAL void*
net2_calloc_(size_t n, size_t s, const char *file, const char *function, int line)
{
	void		*p;

	LOCK();
	p = e_calloc_debug(n, s, file, function, line);
	UNLOCK();
	return p;
}

ILIAS_NET2_LOCAL char*
net2_strdup_(const char *s, const char *file, const char *function, int line)
{
	char		*p;

	LOCK();
	p = e_strdup_debug(s, file, function, line);
	UNLOCK();
	return p;
}

ILIAS_NET2_LOCAL void
net2_free_(void *p, const char *file, const char *function, int line)
{
	LOCK();
	e_free_debug(&p, file, function, line);
	UNLOCK();
}

#endif /* NET2_USE_EXUDE_DEBUG */
