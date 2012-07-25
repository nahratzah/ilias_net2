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
#include <ilias/net2/obj_manager.h>
#include <ilias/net2/cp.h>
#include <stdlib.h>
#include <assert.h>


/* Create a new obj manager. */
ILIAS_NET2_EXPORT struct net2_objmanager*
net2_objmanager_new()
{
	return NULL; /* XXX implement */
}

/* Reference an objmanager. */
ILIAS_NET2_EXPORT void
net2_objmanager_ref(struct net2_objmanager *m)
{
	assert(m != NULL);

	assert(0); /* XXX implement */
}

/* Release an objmanager. */
ILIAS_NET2_EXPORT void
net2_objmanager_release(struct net2_objmanager *m)
{
	assert(m != NULL);

	assert(0); /* XXX implement. */
}


/* Invoke remote method. */
ILIAS_NET2_EXPORT int
net2_objman_rmi(struct net2_objmanager *m, struct net2_objman_group *g,
    const struct command_method *cm, const void *in_params,
    net2_objman_return_cb cb, void *cb_arg, struct net2_workq *wq,
    struct net2_objman_tx_ticket **txptr)
{
	assert(m != NULL &&
	    g != NULL &&
	    cm != NULL &&
	    in_params != NULL &&
	    cb != NULL &&
	    cb_arg != NULL &&
	    wq != NULL &&
	    txptr != NULL);
	assert(0); /* XXX this code is old. */
}

/* Release reference to tx ticket. */
ILIAS_NET2_EXPORT void
net2_objman_rmi_release(struct net2_objman_tx_ticket *tx)
{
	assert(tx != NULL);

	assert(0); /* XXX implement */
}
