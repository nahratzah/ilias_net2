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
#ifndef ILIAS_NET2_WORKQ_H
#define ILIAS_NET2_WORKQ_H

#include <sys/types.h>
#include <stdint.h>
#include <ilias/net2/config.h>
#include <ilias/net2/ilias_net2_export.h>

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <ilias/net2/bsd_compat/queue.h>
#endif

struct net2_workq_job {
	struct net2_workq
			*workq;			/* Owner workq. */
	int		 flags;			/* Flags/options. */
#define NET2_WORKQ_PERSIST	0x00000001	/* Job persists. */

	void		(*fn)(void*, void*);	/* Callback. */
	void		(*destroy)(void*, void*); /* Optional destructor. */
	void		*cb_arg[2];		/* Callback arguments. */

	TAILQ_ENTRY(net2_workq_job)
			 readyq;		/* Link into ready queue. */

	struct event	*ev;			/* Libevent event. */
};

struct net2_workq {
	struct net2_mutex
			*mtx;			/* Mutex. */
	struct net2_workq_evbase
			*evbase;		/* Event base for IO/timers. */

	TAILQ_HEAD(, net2_workq_job)
			 runqueue;		/* Jobs that are to run now. */
	TAILQ_ENTRY(net2_workq)
			 wqe_member;		/* Membership of evbase. */
	TAILQ_ENTRY(net2_workq)
			 wqe_runq;		/* Runqueue of evbase. */
	size_t		 refcnt;		/* Reference counter. */

	/*
	 * Below is locked using evbase->mtx.
	 */
	struct net2_condition
			*dying;			/* After running, fire. */
	struct net2_thread
			*execing;		/* Executing in this thread. */
	int		 flags;			/* Workq flags. */
	int		*died;			/* Pointer to boolean, only
						 * set if thread is in the
						 * running state. */
};


ILIAS_NET2_EXPORT
int	 net2_workq_set_thread_count(struct net2_workq_evbase*, size_t);
ILIAS_NET2_EXPORT
struct net2_workq_evbase
	*net2_workq_evbase_new(const char*);
ILIAS_NET2_EXPORT
void	 net2_workq_evbase_ref(struct net2_workq_evbase*);
ILIAS_NET2_EXPORT
void	 net2_workq_evbase_release(struct net2_workq_evbase*);

ILIAS_NET2_EXPORT
struct net2_workq
	*net2_workq_new(struct net2_workq_evbase*);
ILIAS_NET2_EXPORT
void	 net2_workq_ref(struct net2_workq*);
ILIAS_NET2_EXPORT
void	 net2_workq_release(struct net2_workq*);

#endif /* ILIAS_NET2_WORKQ_H */
