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

struct net2_workq;
struct net2_workq_job;
struct net2_workq_evbase;
typedef void (*net2_workq_cb)(void*, void*);
typedef void (*net2_workq_job_cb)(struct net2_workq_job*);

struct net2_workq_job_cb {
	net2_workq_job_cb
			 on_activate,
			 on_deactivate,
			 on_destroy,
			 on_wqdestroy;
};

struct net2_workq_job {
	struct net2_mutex
			*mtx;			/* Protect workq pointer. */
	struct net2_condition
			*wq_death;		/* Workq death event. */
	struct net2_workq
			*workq;			/* Owner workq. */
	int		 flags;			/* Flags/options. */
#define NET2_WORKQ_PERSIST	0x00000001	/* Job persists. */

	net2_workq_cb	 fn;			/* Callback. */
	void		*cb_arg[2];		/* Callback arguments. */

	TAILQ_ENTRY(net2_workq_job)
			 readyq,		/* Link into ready queue. */
			 memberq;		/* Link into workq. */

	struct event	*ev;			/* Libevent event. */
	int		*died;			/* Set only if running. */

	const struct net2_workq_job_cb
			*callbacks;		/* Special callbacks. */
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

ILIAS_NET2_EXPORT
int	 net2_workq_init_work(struct net2_workq_job*, struct net2_workq*,
	    net2_workq_cb, void*, void*, int);
ILIAS_NET2_EXPORT
void	 net2_workq_deinit_work(struct net2_workq_job*);
ILIAS_NET2_EXPORT
void	 net2_workq_activate(struct net2_workq_job*);
ILIAS_NET2_EXPORT
void	 net2_workq_deactivate(struct net2_workq_job*);

ILIAS_NET2_EXPORT
void	*net2_workq_get_evloop(struct net2_workq*);
ILIAS_NET2_EXPORT
struct net2_workq
	*net2_workq_get(struct net2_workq_job*);

#define net2_workq_set_callbacks(j, cb)					\
	do { (j)->callbacks = (cb); } while (0)

#endif /* ILIAS_NET2_WORKQ_H */
