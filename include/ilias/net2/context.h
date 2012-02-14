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
#include <ilias/net2/sign.h>
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
 * List of signatures for a host.
 */
struct net2_ctx_signatures {
	struct net2_sign_ctx	**signatures;
	size_t			 count;
};

/*
 * Network context.
 *
 * Network context setup happens before connections are built.
 * The network context module is not thread-safe.
 *
 * For each protocol, exactly one instance of net2_ctx is required.
 */
struct net2_ctx {
	struct net2_ctx_signatures
				 local_signs,	/* Signatures for localhost. */
				 remote_signs;	/* Signatures for remote. */
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

#define net2_ctx_local_signcount(s)	((const size_t)(s)->local_signs.count)
#define net2_ctx_remote_signcount(s)	((const size_t)(s)->remote_signs.count)

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_CONTEXT_H */
