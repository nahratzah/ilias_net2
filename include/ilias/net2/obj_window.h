#ifndef ILIAS_NET2_OBJ_WINDOW_H
#define ILIAS_NET2_OBJ_WINDOW_H

#include <ilias/net2/ilias_net2_export.h>
#include <stdint.h>
#include <bsd_compat.h>

#ifdef HAVE_TREE_H
#include <sys/tree.h>
#else
#include <bsd_compat/tree.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct net2_objwin_barrier;
struct net2_objwin_recv;

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


ILIAS_NET2_EXPORT
int	 n2ow_supersede(struct net2_objwin*, uint32_t, uint32_t, int*);
ILIAS_NET2_EXPORT
int	 n2ow_receive(struct net2_objwin*, uint32_t, uint32_t, int*);
ILIAS_NET2_EXPORT
struct net2_objwin_recv
	*n2ow_get_pending(struct net2_objwin*);
ILIAS_NET2_EXPORT
void	 n2ow_finished(struct net2_objwin_recv*);
ILIAS_NET2_EXPORT
int	 n2ow_init(struct net2_objwin*);
ILIAS_NET2_EXPORT
void	 n2ow_deinit(struct net2_objwin*);

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_OBJ_WINDOW_H */
