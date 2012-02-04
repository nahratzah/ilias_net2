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
#ifndef ILIAS_NET2_OBJ_MANAGER_H
#define ILIAS_NET2_OBJ_MANAGER_H

#include <ilias/net2/ilias_net2_export.h>

#ifdef ilias_net2_EXPORTS

#include <ilias/net2/acceptor.h>
#include <ilias/net2/protocol.h>
#include <bsd_compat/bsd_compat.h>

#ifdef HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include <bsd_compat/tree.h>
#endif

#endif /* ilias_net2_EXPORTS */

#ifdef __cplusplus
extern "C" {
#endif

struct net2_objmanager;

/* Callback argument return. */
typedef void (*net2_objman_return_cb)(int conn_error, int cb_error,
    void *cbarg, void *out_params);


#ifdef ilias_net2_EXPORTS
struct net2_objman_group;
struct net2_objman_tx_ticket;
struct net2_objman_rx_ticket;

RB_HEAD(net2_objman_groups, net2_objman_group);
RB_HEAD(net2_objman_ttx, net2_objman_tx_ticket);

/*
 * Object manager.
 *
 * Manages groups (which are 0 or more objects sharing a single window).
 * Manages requests (which are remote method invocations).
 */
struct net2_objmanager {
	struct net2_acceptor	 base;
	struct net2_evbase	*evbase;

	int			 flags;		/* State flags. */
	struct net2_pvlist	 pvlist;	/* Negotiated protocols. */

	struct net2_objman_groups
				 groups;	/* Local groups. */
	struct net2_objman_ttx	 tx_tickets;	/* Outstanding invocations. */

	struct net2_mutex	*mtx;		/* Guard. */
	size_t			 refcnt;	/* Reference counter. */
};
#endif /* ilias_net2_EXPORTS */


/* Cast objmanager to conn acceptor. */
static __inline struct net2_conn_acceptor*
net2_objmanager_reduce(struct net2_objmanager *m)
{
	return (struct net2_conn_acceptor*)m;
}


/* Create a new obj manager. */
ILIAS_NET2_EXPORT
struct net2_objmanager
		*net2_objmanager_new();

/* Reference an objmanager. */
ILIAS_NET2_EXPORT
void		 net2_objmanager_ref(struct net2_objmanager*);
/* Release an objmanager. */
ILIAS_NET2_EXPORT
void		 net2_objmanager_release(struct net2_objmanager*);

#ifdef ilias_net2_EXPORTS
ILIAS_NET2_LOCAL
struct net2_objman_tx_ticket*
		 net2_objmanager_find_tx_ticket(struct net2_objmanager*,
		    uint32_t, uint32_t);
ILIAS_NET2_LOCAL
const struct command_param*
		 net2_objman_ttx_type(struct net2_objman_tx_ticket*);
#endif /* ilias_net2_EXPORTS */

ILIAS_NET2_EXPORT
int		 net2_objman_rmi(struct net2_objmanager *,
		    struct net2_objman_group*,
		    const struct command_method*, const void*,
		    net2_objman_return_cb, void*, struct net2_evbase*,
		    struct net2_objman_tx_ticket**);
ILIAS_NET2_EXPORT
void		 net2_objman_rmi_release(struct net2_objman_tx_ticket*);

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_OBJ_MANAGER_H */
