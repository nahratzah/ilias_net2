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
#ifndef ILIAS_NET2_CLUSTER_SOCKET_H
#define ILIAS_NET2_CLUSTER_SOCKET_H

#include <event2/buffer.h>
#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/evbase.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Remote access implementation.
 *
 * This contains the functions used by a specific implementation of
 * communication.
 */
struct ra_functions {
	const char	*name;		/* Name of this implementation. */

	void		(*destroy)	(void*);
	void		(*transmit)	(void*, struct evbuffer*);
};

/*
 * Remote access structure.
 *
 * Each implementation is capable of transmitting data and having it be
 * received by each of its targets.
 */
struct remote_access {
	void		*state;		/* State of the access method. */
	const struct ra_functions
			*impl;		/* Implementation functions. */
};


ILIAS_NET2_EXPORT
struct remote_access	*n2ra_init_mcast(struct net2_evbase*, int,
			    const char*, const char*, const char*,
			    const char*);

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_CLUSTER_SOCKET_H */
