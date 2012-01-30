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
#include <ilias/net2/types.h>
#include <sys/types.h>

#include <bsd_compat/bsd_compat.h>
#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <bsd_compat/queue.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Network context.
 *
 * Network context setup happens before connections are built.
 * The network context module is not thread-safe.
 *
 * For each protocol, exactly one instance of net2_ctx is required.
 */
struct net2_ctx {
	/** Protocol in use. */
	const struct net2_protocol	*protocol;
	/* Protocol implementation version. */
	net2_protocol_t			 version;
#define NET2_CTX_NEGOTIATE		 0xffffffff
	/* All connections in the same cluster. */
	TAILQ_HEAD(, net2_connection)	 conn;
};

ILIAS_NET2_EXPORT
void			 net2_ctx_init(struct net2_ctx*,
			    const struct net2_protocol*);
ILIAS_NET2_EXPORT
void			 net2_ctx_destroy(struct net2_ctx*);

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_CONTEXT_H */
