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

ILIAS_NET2__begin_cdecl


#ifndef WIN32
struct ev_loop;		/* From libev. */
#endif

struct net2_workq;
struct net2_workq_job;
struct net2_workq_job_int;
struct net2_workq_evbase;
typedef void (*net2_workq_cb)(void*, void*);
typedef void (*net2_workq_job_cbfn)(struct net2_workq_job*);

#define NET2_WORKQ_PERSIST	0x80000000	/* Job persists. */
#define NET2_WORKQ_PARALLEL	0x40000000	/* Job can run parallel
						 * to sibling jobs. */

#define NET2_WQ_ACT_IMMED	0x00000001	/* Try to run activated job
						 * immediately. */
#define NET2_WQ_ACT_RECURS	0x00000002	/* Allow immediate running
						 * when active workq and
						 * job workq match. */

struct net2_workq_job {
	atomic_uint	 refcnt;		/* Prefent deactivation
						 * during access. */
	_Atomic(struct net2_workq_job_int*)
			 internal;		/* Internal data. */
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
ILIAS_NET2_EXPORT
int	 net2_workq_is_self(struct net2_workq*);

ILIAS_NET2_EXPORT
int	net2_workq_surf(struct net2_workq*, int);

/*
 * Initialize a null workq job.
 *
 * Null jobs have no workq and no function to be called.
 * Activation and deactivation of the null job are no-ops.
 * Using a null job is easier than using a pointer to a job.
 */
static __inline void
net2_workq_init_work_null(struct net2_workq_job *j)
{
	atomic_init(&j->internal, NULL);
	atomic_init(&j->refcnt, 0);
}

/* Test if a workq job is a null job. */
static __inline int
net2_workq_work_is_null(struct net2_workq_job *j)
{
	return atomic_load_explicit(&j->internal, memory_order_relaxed) ==
	    NULL;
}

ILIAS_NET2_EXPORT
int	 net2_workq_aid(struct net2_workq*, int);
ILIAS_NET2_EXPORT
struct net2_workq
	*net2_workq_current();


#ifndef HAS_TLS
ILIAS_NET2_LOCAL
int	 net2_workq_init();
ILIAS_NET2_LOCAL
void	 net2_workq_fini();
#else
#define	 net2_workq_init()	(0)
#define	 net2_workq_fini()	do { /* nothing */ } while (0)
#endif


#ifdef WIN32
ILIAS_NET2_LOCAL
struct net2_workq_timer_container
	*net2_workq_get_timer(struct net2_workq*);
ILIAS_NET2_LOCAL
struct net2_workq_io_container
	*net2_workq_get_io(struct net2_workq*);
#else
ILIAS_NET2_LOCAL
void	 net2_workq_evbase_evloop_changed(struct net2_workq_evbase*);
ILIAS_NET2_LOCAL
struct ev_loop
	*net2_workq_get_evloop(struct net2_workq_evbase*);
#endif


ILIAS_NET2__end_cdecl
#endif /* ILIAS_NET2_WORKQ_H */
