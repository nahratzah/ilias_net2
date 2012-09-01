#ifndef ILIAS_NET2_DATAPIPE_H
#define ILIAS_NET2_DATAPIPE_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/config.h>
#include <ilias/net2/spinlock.h>
#include <ilias/net2/bsd_compat/atomic.h>
#include <ilias/net2/workq.h>

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <ilias/net2/bsd_compat/queue.h>
#endif

struct net2_workq;		/* From ilias/net2/workq.h */

struct net2_datapipe_in;
struct net2_datapipe_out;
struct net2_dp_elem;

typedef void *(*net2_dp_transform)(void*, void*);
typedef void  (*net2_dp_free)(void*, void*);
typedef void *(*net2_dp_producer)(void*);
typedef void  (*net2_dp_consumer)(void*, void*);

struct net2_datapipe_in_prepare {
	struct net2_dp_elem	*elem;
	struct net2_datapipe_in	*in;
};

#define NET2_DPEV_INACTIVE	 1		/* Event is inactive. */
#define NET2_DPEV_ACTIVE	 2		/* Event is active. */
#define NET2_DPEV_RUNNING	 3		/* Event is running. */

/*
 * Input event on datapipe.
 *
 * spl is only valid if this is nut a null event.
 */
struct net2_datapipe_event_in {
	struct net2_workq	*wq;		/* Connected workq. */
	struct net2_datapipe_in	*dp;		/* Connected datapipe. */

	struct {
		net2_dp_producer fn;		/* Producer function. */
		void		*arg;		/* Argument to producer. */
	}			 producer;	/* Producer info. */

	TAILQ_ENTRY(net2_datapipe_event_in)
				 q;		/* Link into datapipe. */

	atomic_int		 state;		/* Inactive/active/running. */
	unsigned int		 generation;
	net2_spinlock		 spl;		/* Protect dp. */
	volatile int		*dead;
};
/*
 * Output event on datapipe.
 *
 * spl is only valid if this is nut a null event.
 */
struct net2_datapipe_event_out {
	struct net2_workq	*wq;		/* Connected workq. */
	struct net2_datapipe_out*dp;		/* Connected datapipe. */

	struct {
		net2_dp_consumer fn;		/* Consumer function. */
		void		*arg;		/* Argument to consumer. */
	}			 consumer;	/* Consumer info. */

	TAILQ_ENTRY(net2_datapipe_event_out)
				 q;		/* Link into queue. */

	atomic_int		 state;		/* Inactive/active/running. */
	unsigned int		 generation;
	net2_spinlock		 spl;		/* Protect dp. */
	volatile int		*dead;
};

/*
 * Workq job events on datapipe.
 */
struct net2_datapipe_event {
	int			 evtype;	/* Event type. */
#define NET2_DP_EVTYPE_IN	0x10000000	/* Input side event. */
#define NET2_DP_EVTYPE_OUT	0x00000000	/* Output side event. */
#define NET2_DP_EVTYPE_MASK	(NET2_DP_EVTYPE_IN | NET2_DP_EVTYPE_OUT)
#define NET2_DP_EVTYPE_AVAIL	0x00000000	/* In/out available. */
#define NET2_DP_EVTYPE_FIN	0x00000001	/* No more in/out. */
#define NET2_DP_EVTYPE__SIZE	0x00000002	/* Number of events. */
	struct net2_dp_queue	*owner;		/* Refer to datapipe. */
	struct net2_workq_job	 job;		/* Workq job. */
	TAILQ_ENTRY(net2_datapipe_event)
				 dpevq;		/* Link into events. */
};


/* Initialize null input event. */
static __inline void
net2_datapipe_event_in_init_null(struct net2_datapipe_event_in *in_ev)
{
	in_ev->dp = NULL;
	in_ev->wq = NULL;
}
/* Initialize null output event. */
static __inline void
net2_datapipe_event_out_init_null(struct net2_datapipe_event_out *out_ev)
{
	out_ev->dp = NULL;
	out_ev->wq = NULL;
}
/* Initialize a null event. */
static __inline void
net2_datapipe_event_init_null(struct net2_datapipe_event *ev)
{
	ev->owner = NULL;
	net2_workq_init_work_null(&ev->job);
}
/* Test if an event is a null event. */
static __inline int
net2_datapipe_event_in_is_null(struct net2_datapipe_event_in *in_ev)
{
	return in_ev->dp == NULL && in_ev->wq == NULL;
}
/* Test if an output event is a null event. */
static __inline int
net2_datapipe_event_out_is_null(struct net2_datapipe_event_out *out_ev)
{
	return out_ev->dp == NULL && out_ev->wq == NULL;
}
/* Test if an event is a null event. */
static __inline int
net2_datapipe_event_is_null(struct net2_datapipe_event *ev)
{
	return net2_workq_work_is_null(&ev->job);
}


ILIAS_NET2_EXPORT
void	 net2_dpin_ref(struct net2_datapipe_in*);
ILIAS_NET2_EXPORT
void	 net2_dpout_ref(struct net2_datapipe_out*);
ILIAS_NET2_EXPORT
void	 net2_dpin_release(struct net2_datapipe_in*);
ILIAS_NET2_EXPORT
void	 net2_dpout_release(struct net2_datapipe_out*);

ILIAS_NET2_EXPORT
int	 net2_dpin_set_maxlen(struct net2_datapipe_in*, size_t);
ILIAS_NET2_EXPORT
int	 net2_dpout_set_maxlen(struct net2_datapipe_out*, size_t);

ILIAS_NET2_EXPORT
int	 net2_dp_push_prepare(struct net2_datapipe_in_prepare*,
	    struct net2_datapipe_in*);
ILIAS_NET2_EXPORT
int	 net2_dp_push_commit(struct net2_datapipe_in_prepare*, void*);
ILIAS_NET2_EXPORT
int	 net2_dp_push_rollback(struct net2_datapipe_in_prepare*);
ILIAS_NET2_EXPORT
int	 net2_dp_push(struct net2_datapipe_in*, void*);
ILIAS_NET2_EXPORT
void	*net2_dp_pop(struct net2_datapipe_out*);

ILIAS_NET2_EXPORT
int	 net2_datapipe_event_in_init(struct net2_datapipe_event_in*,
	    struct net2_datapipe_in*, struct net2_workq*,
	    net2_dp_producer, void*);
ILIAS_NET2_EXPORT
void	 net2_datapipe_event_in_deinit(struct net2_datapipe_event_in*);
ILIAS_NET2_EXPORT
int	 net2_datapipe_event_out_init(struct net2_datapipe_event_out*,
	    struct net2_datapipe_out*, struct net2_workq*,
	    net2_dp_consumer, void*);
ILIAS_NET2_EXPORT
void	 net2_datapipe_event_out_deinit(struct net2_datapipe_event_out*);
ILIAS_NET2_EXPORT
int	 net2_datapipe_event_init_in(struct net2_datapipe_event*,
	    struct net2_datapipe_in*, int, struct net2_workq*,
	    net2_workq_cb, void*, void*);
ILIAS_NET2_EXPORT
int	 net2_datapipe_event_init_out(struct net2_datapipe_event*,
	    struct net2_datapipe_out*, int, struct net2_workq*,
	    net2_workq_cb, void*, void*);
ILIAS_NET2_EXPORT
void	 net2_datapipe_event_deinit(struct net2_datapipe_event*);

ILIAS_NET2_EXPORT
void	 net2_datapipe_event_in_activate(struct net2_datapipe_event_in*);
ILIAS_NET2_EXPORT
void	 net2_datapipe_event_in_deactivate(struct net2_datapipe_event_in*);
ILIAS_NET2_EXPORT
void	 net2_datapipe_event_out_activate(struct net2_datapipe_event_out*);
ILIAS_NET2_EXPORT
void	 net2_datapipe_event_out_deactivate(struct net2_datapipe_event_out*);

#endif /* ILIAS_NET2_DATAPIPE_H */
