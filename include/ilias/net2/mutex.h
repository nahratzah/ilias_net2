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
#ifndef ILIAS_NET2_MUTEX_H
#define ILIAS_NET2_MUTEX_H

#include <ilias/net2/ilias_net2_export.h>

ILIAS_NET2__begin_cdecl


struct net2_mutex;
struct net2_condition;

#ifdef BUILDING_ILIAS_NET2
#if MEMDEBUG
#define MTX_ARGS	const char *, const char *, int
#define MTX_ARGS_	, MTX_ARGS
#endif

ILIAS_NET2_LOCAL
struct net2_mutex	*net2_mutex_alloc(MTX_ARGS);
ILIAS_NET2_LOCAL
void			 net2_mutex_free(struct net2_mutex* MTX_ARGS_);
ILIAS_NET2_LOCAL
void			 net2_mutex_lock(struct net2_mutex*);
ILIAS_NET2_LOCAL
int			 net2_mutex_trylock(struct net2_mutex*);
ILIAS_NET2_LOCAL
void			 net2_mutex_unlock(struct net2_mutex*);

ILIAS_NET2_LOCAL
struct net2_condition	*net2_cond_alloc(MTX_ARGS);
ILIAS_NET2_LOCAL
void			 net2_cond_free(struct net2_condition* MTX_ARGS_);
ILIAS_NET2_LOCAL
void			 net2_cond_signal(struct net2_condition*);
ILIAS_NET2_LOCAL
void			 net2_cond_broadcast(struct net2_condition*);
ILIAS_NET2_LOCAL
void			 net2_cond_wait(struct net2_condition*,
			    struct net2_mutex*);

#if MEMDEBUG
#define net2_mutex_alloc()						\
	net2_mutex_alloc(__FILE__, __FUNCTION__, __LINE__)
#define net2_mutex_free(m)						\
	net2_mutex_free((m), __FILE__, __FUNCTION__, __LINE__)
#define net2_cond_alloc()						\
	net2_cond_alloc(__FILE__, __FUNCTION__, __LINE__)
#define net2_cond_free(c)						\
	net2_cond_free((c), __FILE__, __FUNCTION__, __LINE__)
#endif
#endif /* BUILDING_ILIAS_NET2 */


ILIAS_NET2__end_cdecl
#endif /* ILIAS_NET2_MUTEX_H */
