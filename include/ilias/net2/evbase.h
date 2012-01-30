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
#ifndef ILIAS_NET2_EVBASE_H
#define ILIAS_NET2_EVBASE_H

#include <ilias/net2/types.h>
#include <ilias/net2/ilias_net2_export.h>
#include <sys/types.h>

/*
 * A shared event base.
 *
 * The event base is reference counted and can be shared across network code.
 */
struct net2_evbase {
	struct net2_mutex	*mtx;		/* Protect the refcnt. */
	struct event_base	*evbase;	/* Libevent base. */
	size_t			 refcnt;	/* Reference counter. */

	struct net2_thread	*thread;	/* Active thread. */
	struct event		*threadlive;	/* Keep thread alive. */
};

ILIAS_NET2_EXPORT
struct net2_evbase		*net2_evbase_new();
ILIAS_NET2_EXPORT
void				 net2_evbase_release(struct net2_evbase*);
ILIAS_NET2_EXPORT
void				 net2_evbase_ref(struct net2_evbase*);
ILIAS_NET2_EXPORT
int				 net2_evbase_threadstart(struct net2_evbase*);
ILIAS_NET2_EXPORT
int				 net2_evbase_threadstop(struct net2_evbase*,
				    int);
#define NET2_EVBASE_WAITONLY	0x00000001	/* Don't kill the thread. */

#endif /* ILIAS_NET2_EVBASE_H */
