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

ILIAS_NET2__begin_cdecl


struct net2_objmanager;
struct net2_objman_group;
struct net2_objman_tx_ticket;

struct net2_workq;	/* From ilias/net2/workq.h */
struct command_method;	/* From ilias/net2/cp.h */

/* Callback argument return. */
typedef void (*net2_objman_return_cb)(int conn_error, int cb_error,
    void *cbarg, void *out_params);


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

ILIAS_NET2_EXPORT
int		 net2_objman_rmi(struct net2_objmanager *,
		    struct net2_objman_group*,
		    const struct command_method*, const void*,
		    net2_objman_return_cb, void*, struct net2_workq*,
		    struct net2_objman_tx_ticket**);
ILIAS_NET2_EXPORT
void		 net2_objman_rmi_release(struct net2_objman_tx_ticket*);


ILIAS_NET2__end_cdecl
#endif /* ILIAS_NET2_OBJ_MANAGER_H */
