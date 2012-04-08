#ifndef ILIAS_NET2_WORKQ_H
#define ILIAS_NET2_WORKQ_H

#include <sys/types.h>
#include <stdint.h>
#include <ilias/net2/config.h>

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

	int		 flags;			/* Workq flags. */
#define NET2_WQ_F_RUNNING	0x00000001	/* Workq is executing. */
#define NET2_WQ_F_ONQUEUE	0x00000002	/* Workq is on runqueue. */
};


int	 net2_workq_set_thread_count(struct net2_workq_evbase*, size_t);
struct net2_workq_evbase
	*net2_workq_evbase_new(const char*);

#endif /* ILIAS_NET2_WORKQ_H */
