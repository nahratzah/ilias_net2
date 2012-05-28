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
#ifndef ILIAS_NET2_OBJ_WINDOW_H
#define ILIAS_NET2_OBJ_WINDOW_H

#include <ilias/net2/ilias_net2_export.h>
#include <sys/types.h>
#include <stdint.h>
#include <ilias/net2/config.h>

#ifdef HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include <ilias/net2/bsd_compat/tree.h>
#endif

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <ilias/net2/bsd_compat/queue.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct net2_objwin_barrier;
struct net2_objwin_recv;
struct net2_objwin_tx;
struct net2_buffer;

/* Free implementation for data_ptr. */
typedef void (*net2_objwin_dataptr_free)(void*);
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
	net2_objwin_dataptr_free
				data_ptr_free;		/* Free function. */
};


ILIAS_NET2_LOCAL
int	 n2ow_supersede(struct net2_objwin*, uint32_t, uint32_t, int*, void**);
ILIAS_NET2_LOCAL
int	 n2ow_receive(struct net2_objwin*, uint32_t, uint32_t, int*, void*);
ILIAS_NET2_LOCAL
struct net2_objwin_recv
	*n2ow_get_pending(struct net2_objwin*);
ILIAS_NET2_LOCAL
void	 n2ow_finished(struct net2_objwin_recv*);
ILIAS_NET2_LOCAL
int	 n2ow_init(struct net2_objwin*, net2_objwin_dataptr_free);
ILIAS_NET2_LOCAL
void	 n2ow_deinit(struct net2_objwin*);
ILIAS_NET2_LOCAL
void	*n2ow_data_ptr(struct net2_objwin_recv*);

/* Transmission side of objwin. */
struct net2_objwin_stub;

#define NET2_OBJWIN_STUB_ON_READY_TO_SEND	0	/* Ready to send. */
#define NET2_OBJWIN_STUB__NUM_EVENTS		1	/* Number of events. */

ILIAS_NET2_LOCAL
struct net2_objwin_stub	*n2ow_new_stub();
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
ILIAS_NET2_LOCAL
int			 n2ow_stub_set_event(struct net2_objwin_stub*, int,
			    struct event*, struct event**);
ILIAS_NET2_LOCAL
struct event		*n2ow_stub_get_event(struct net2_objwin_stub*, int);

#define N2OW_TXADD_BARRIER_PRE		0x1
#define N2OW_TXADD_BARRIER_POST		0x2
#define N2OW_TXADD_AUTO_SUPERSEDE	0x4

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_OBJ_WINDOW_H */
