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
ILIAS_NET2_LOCAL
struct net2_mutex	*net2_mutex_alloc();
ILIAS_NET2_LOCAL
void			 net2_mutex_free(struct net2_mutex*);
ILIAS_NET2_LOCAL
void			 net2_mutex_lock(struct net2_mutex*);
ILIAS_NET2_LOCAL
int			 net2_mutex_trylock(struct net2_mutex*);
ILIAS_NET2_LOCAL
void			 net2_mutex_unlock(struct net2_mutex*);

ILIAS_NET2_LOCAL
struct net2_condition	*net2_cond_alloc();
ILIAS_NET2_LOCAL
void			 net2_cond_free(struct net2_condition*);
ILIAS_NET2_LOCAL
void			 net2_cond_signal(struct net2_condition*);
ILIAS_NET2_LOCAL
void			 net2_cond_broadcast(struct net2_condition*);
ILIAS_NET2_LOCAL
void			 net2_cond_wait(struct net2_condition*,
			    struct net2_mutex*);
#endif /* BUILDING_ILIAS_NET2 */


ILIAS_NET2__end_cdecl
#endif /* ILIAS_NET2_MUTEX_H */
