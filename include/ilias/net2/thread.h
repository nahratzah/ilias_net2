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
#ifndef ILIAS_NET2_THREAD_H
#define ILIAS_NET2_THREAD_H

#include <ilias/net2/ilias_net2_export.h>

ILIAS_NET2__begin_cdecl


struct net2_thread;

#ifdef BUILDING_ILIAS_NET2
ILIAS_NET2_LOCAL
struct net2_thread	*net2_thread_new(void *(*)(void*), void*, const char*);
ILIAS_NET2_LOCAL
int			 net2_thread_join(struct net2_thread*, void**);
ILIAS_NET2_LOCAL
void			 net2_thread_free(struct net2_thread*);
ILIAS_NET2_LOCAL
int			 net2_thread_is_self(struct net2_thread*);
ILIAS_NET2_LOCAL
int			 net2_thread_eq(struct net2_thread*,
			    struct net2_thread*);
ILIAS_NET2_LOCAL
struct net2_thread	*net2_thread_self();
ILIAS_NET2_LOCAL
void			 net2_thread_detach_self();
ILIAS_NET2_LOCAL
void			 net2_thread_yield();
#endif /* BUILDING_ILIAS_NET2 */


ILIAS_NET2__end_cdecl
#endif /* ILIAS_NET2_THREAD_H */
