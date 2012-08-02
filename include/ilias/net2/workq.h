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

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/config.h>
#include <ilias/net2/bsd_compat/atomic.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <ilias/net2/bsd_compat/queue.h>
#endif

ILIAS_NET2__begin_cdecl


struct ev_loop;		/* From libev. */

struct net2_workq;
struct net2_workq_job;
struct net2_workq_evbase;
typedef void (*net2_workq_cb)(void*, void*);
typedef void (*net2_workq_job_cbfn)(struct net2_workq_job*);

#define NET2_WORKQ_PERSIST	0x00000001	/* Job persists. */

#define NET2_WQ_ACT_IMMED	0x00000001	/* Try to run activated job
						 * immediately. */

struct net2_workq_job_cb {
	net2_workq_job_cbfn
			 on_destroy,
			 on_wqdestroy;
};

struct net2_workq_job {
	TAILQ_ENTRY(net2_workq_job)
			 runqueue;		/* Run queue. */

	net2_workq_cb	 fn;			/* Callback. */
	void		*cb_arg[2];		/* Callback arguments. */

	atomic_uint	 flags;			/* State bits. */
	struct net2_workq
			*wq;			/* Associated workq. */
	atomic_uint	 runwait;		/* # threads waiting for job
						 * to cease running state. */

	TAILQ_ENTRY(net2_workq_job)
			 members;		/* WQ membership. */

	const struct net2_workq_job_cb
			*callbacks;
};

ILIAS_NET2_EXPORT
int	 net2_workq_set_thread_count(struct net2_workq_evbase*, int, int);
ILIAS_NET2_EXPORT
struct net2_workq_evbase
	*net2_workq_evbase_new(const char*, int, int);
ILIAS_NET2_EXPORT
void	 net2_workq_evbase_ref(struct net2_workq_evbase*);
ILIAS_NET2_EXPORT
void	 net2_workq_evbase_release(struct net2_workq_evbase*);
ILIAS_NET2_LOCAL
void	 net2_workq_evbase_evloop_changed(struct net2_workq_evbase*);

ILIAS_NET2_EXPORT
struct net2_workq
	*net2_workq_new(struct net2_workq_evbase*);
ILIAS_NET2_EXPORT
void	 net2_workq_ref(struct net2_workq*);
ILIAS_NET2_EXPORT
void	 net2_workq_release(struct net2_workq*);
ILIAS_NET2_EXPORT
struct net2_workq_evbase
	*net2_workq_evbase(struct net2_workq*);

ILIAS_NET2_EXPORT
int	 net2_workq_init_work(struct net2_workq_job*, struct net2_workq*,
	    net2_workq_cb, void*, void*, int);
ILIAS_NET2_EXPORT
void	 net2_workq_deinit_work(struct net2_workq_job*);
ILIAS_NET2_EXPORT
void	 net2_workq_activate(struct net2_workq_job*, int);
ILIAS_NET2_EXPORT
void	 net2_workq_deactivate(struct net2_workq_job*);

ILIAS_NET2_EXPORT
struct net2_workq
	*net2_workq_get(struct net2_workq_job*);

ILIAS_NET2_EXPORT
int	 net2_workq_want(struct net2_workq*, int);
ILIAS_NET2_EXPORT
void	 net2_workq_unwant(struct net2_workq*);

/* Assign callbacks for workq modifications. */
static __inline void
net2_workq_set_callbacks(struct net2_workq_job *j,
    const struct net2_workq_job_cb *cb)
{
	j->callbacks = cb;
}

/* Initialize a null workq job. */
static __inline void
net2_workq_init_work_null(struct net2_workq_job *j)
{
	j->fn = NULL;
}

ILIAS_NET2_LOCAL
struct ev_loop
	*net2_workq_get_evloop(struct net2_workq*);

ILIAS_NET2_EXPORT
int	 net2_workq_aid(struct net2_workq*, int);


ILIAS_NET2__end_cdecl
#endif /* ILIAS_NET2_WORKQ_H */
