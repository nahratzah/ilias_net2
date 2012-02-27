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
#ifndef ILIAS_NET2_MEMORY_H
#define ILIAS_NET2_MEMORY_H


#ifdef BUILDING_ILIAS_NET2

#include <sys/types.h>
#include <stdint.h>

#ifdef NET2_USE_EXUDE_DEBUG


#include <ilias/net2/ilias_net2_export.h>

ILIAS_NET2_LOCAL void	*net2_malloc_(size_t, const char*, const char*, int);
ILIAS_NET2_LOCAL void	*net2_realloc_(void*, size_t, const char*, const char*, int);
ILIAS_NET2_LOCAL void	*net2_calloc_(size_t, size_t, const char*, const char*, int);
ILIAS_NET2_LOCAL char	*net2_strdup_(const char*, const char*, const char*, int);
ILIAS_NET2_LOCAL void	 net2_free_(void**, const char*, const char*, int);

ILIAS_NET2_LOCAL void	 net2_memory_init();
ILIAS_NET2_LOCAL void	 net2_memory_fini();

#define net2_malloc(s)							\
	net2_malloc_((s), __FILE__, __FUNCTION__, __LINE__)
#define net2_free(p)							\
	do {								\
		if (p != NULL)						\
			net2_free_((void**)&(p), __FILE__,		\
			    __FUNCTION__, __LINE__);			\
	} while (0)
#define net2_realloc(p, s)						\
	net2_realloc_((p), (s), __FILE__, __FUNCTION__, __LINE__)
#define net2_calloc(n, s)						\
	net2_calloc_((n), (s), __FILE__, __FUNCTION__, __LINE__)
#define net2_strdup(s)							\
	net2_strdup_((s), __FILE__, __FUNCTION__, __LINE__)


#else /* NET2_USE_EXUDE_DEBUG */


#include <stdlib.h>

#define net2_malloc(s)							\
	malloc((s))
#define net2_free(p)							\
	free((p))
#define net2_realloc(p, s)						\
	realloc((p), (s))
#define net2_calloc(n, s)						\
	calloc((n), (s))
#define net2_strdup(s)							\
	strdup((s))

#define net2_memory_init()						\
	do {} while (0)
#define net2_memory_fini()						\
	do {} while (0)


#endif /* NET2_USE_EXUDE_DEBUG */

#define net2_recalloc(p, n, s)						\
	((n) > SIZE_MAX / (s) ? NULL : net2_realloc((p), (n) * (s)))

#endif /* BUILDING_ILIAS_NET2 */


#endif /* ILIAS_NET2_MEMORY_H */
