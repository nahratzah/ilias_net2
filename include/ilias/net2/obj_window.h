#ifndef ILIAS_NET2_OBJ_WINDOW_H
#define ILIAS_NET2_OBJ_WINDOW_H

#include <ilias/net2/ilias_net2_export.h>
#include <sys/types.h>
#include <stdint.h>
#include <bsd_compat.h>

#ifdef HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include <bsd_compat/tree.h>
#endif

#ifdef HASE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <bsd_compat/queue.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct net2_objwin_barrier;
struct net2_objwin_recv;
struct net2_objwin_tx;
struct net2_buffer;

/*
 * Receiver window for object requests.
 */
struct net2_objwin {
	RB_HEAD(net2_objwin_barriers, net2_objwin_barrier)
				barriers;
	RB_HEAD(net2_objwin_recvs, net2_objwin_recv)
				recvs;

	uint32_t		window_start;		/* Recv seq start. */
	uint32_t		window_barrier;		/* Expected barrier. */
	uint32_t		first_barrier;		/* First in set. */
	uint32_t		last_barrier;		/* Last in set. */
};


ILIAS_NET2_LOCAL
int	 n2ow_supersede(struct net2_objwin*, uint32_t, uint32_t, int*);
ILIAS_NET2_LOCAL
int	 n2ow_receive(struct net2_objwin*, uint32_t, uint32_t, int*);
ILIAS_NET2_LOCAL
struct net2_objwin_recv
	*n2ow_get_pending(struct net2_objwin*);
ILIAS_NET2_LOCAL
void	 n2ow_finished(struct net2_objwin_recv*);
ILIAS_NET2_LOCAL
int	 n2ow_init(struct net2_objwin*);
ILIAS_NET2_LOCAL
void	 n2ow_deinit(struct net2_objwin*);

/*
 * Transmit side of objwin.
 */
struct net2_objwin_stub {
	RB_HEAD(net2_objwin_txs, net2_objwin_tx)
				 txs;			/* Message transit. */
	TAILQ_HEAD(, net2_objwin_tx)
				 sendq;			/* Need transmit. */
	TAILQ_HEAD(, net2_objwin_tx)
				 unsentq;		/* To be sent. */
	int			 flags;			/* State flags. */
	uint32_t		 window_start;		/* Oldest un-acked. */
	uint32_t		 window_end;		/* First unsent. */
	uint32_t		 barrier;		/* Current barrier. */

	struct net2_mutex	*mtx;			/* Guard. */
	size_t			 refcnt;
};

ILIAS_NET2_LOCAL
struct net2_objwin_stub	*n2ow_init_stub();
ILIAS_NET2_LOCAL
void			 n2ow_ref_stub(struct net2_objwin_stub*);
ILIAS_NET2_LOCAL
void			 n2ow_release_stub(struct net2_objwin_stub*);
ILIAS_NET2_LOCAL
int			 n2ow_transmit_get(struct net2_objwin_stub*,
			    struct net2_objwin_tx**,
			    uint32_t*, uint32_t*, struct net2_buffer**,
			    size_t, size_t);
ILIAS_NET2_LOCAL
void			 n2ow_transmit_timeout(struct net2_objwin_tx*);
ILIAS_NET2_LOCAL
void			 n2ow_transmit_ack(struct net2_objwin_tx*);
ILIAS_NET2_LOCAL
void			 n2ow_transmit_nack(struct net2_objwin_tx*);
ILIAS_NET2_LOCAL
void			 n2ow_tx_release(struct net2_objwin_tx*);
ILIAS_NET2_LOCAL
void			 n2ow_tx_cancel(struct net2_objwin_tx*);
ILIAS_NET2_LOCAL
void			 n2ow_tx_finished(struct net2_objwin_tx*);
ILIAS_NET2_LOCAL
struct net2_objwin_tx	*n2ow_tx_add(struct net2_objwin_stub*,
			    const struct net2_buffer*, int);

#define N2OW_TXADD_BARRIER_PRE		0x1
#define N2OW_TXADD_BARRIER_POST		0x2
#define N2OW_TXADD_AUTO_SUPERSEDE	0x4

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_OBJ_WINDOW_H */
