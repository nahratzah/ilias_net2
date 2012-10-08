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
#ifndef ILIAS_NET2_WORKQ_TIMER_H
#define ILIAS_NET2_WORKQ_TIMER_H

#include <ilias/net2/workq.h>

ILIAS_NET2__begin_cdecl


struct net2_workq_timer;
struct timeval;

ILIAS_NET2_EXPORT
void	 net2_workq_timer_set(struct net2_workq_timer*, const struct timeval*);
ILIAS_NET2_EXPORT
void	 net2_workq_timer_stop(struct net2_workq_timer*);
ILIAS_NET2_EXPORT
struct net2_workq_timer
	*net2_workq_timer_new(struct net2_workq*, net2_workq_cb,
	    void*, void*);
ILIAS_NET2_EXPORT
void	 net2_workq_timer_free(struct net2_workq_timer*);

#ifdef WIN32
ILIAS_NET2_LOCAL
struct net2_workq_timer_container
	*net2_workq_timer_container_new();
ILIAS_NET2_LOCAL
void	 net2_workq_timer_container_destroy(
	    struct net2_workq_timer_container*);
#endif /* WIN32 */


ILIAS_NET2__end_cdecl
#endif /* ILIAS_NET2_WORKQ_TIMER_H */
