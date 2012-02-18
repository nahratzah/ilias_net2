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
#ifndef ILIAS_NET2_CONTEXT_H
#define ILIAS_NET2_CONTEXT_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/signset.h>
#include <ilias/net2/types.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Network context.
 *
 * A network context describes properties of the connection.
 * - signatures for this host
 * - signatures for remote host
 */
struct net2_ctx {
	struct net2_signset	 local_signs,	/* Signatures for localhost. */
				 remote_signs;	/* Signatures for remote. */
	size_t			 remote_min;	/* Minimum number of signatures
						 * that the remote must provide
						 * succesfully. */

	struct net2_promise*	(*xchange_factory)(int xchange, size_t keysize,
				    void *arg);
	void			*xchange_factory_arg;
};

ILIAS_NET2_EXPORT
int	net2_ctx_init(struct net2_ctx*);
ILIAS_NET2_EXPORT
void	net2_ctx_destroy(struct net2_ctx*);
ILIAS_NET2_EXPORT
int	net2_ctx_add_local_signature(struct net2_ctx*, int,
	    const void*, size_t);
ILIAS_NET2_EXPORT
int	net2_ctx_add_remote_signature(struct net2_ctx*, int,
	    const void*, size_t);
ILIAS_NET2_EXPORT
struct net2_promise
	*net2_ctx_get_xchange(struct net2_ctx*, int, size_t);

#define net2_ctx_local_signcount(s)	(net2_signset_size(&(s)->local_signs))
#define net2_ctx_remote_signcount(s)	(net2_signset_size(&(s)->remote_signs))


#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_CONTEXT_H */
