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
#ifndef ILIAS_NET2_ENCDEC_CTX_H
#define ILIAS_NET2_ENCDEC_CTX_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/types.h>
#include <ilias/net2/protocol.h>

#ifdef __cplusplus
extern "C" {
#endif

struct net2_acceptor_socket;	/* From ilias/net2/acceptor.h */

/*
 * Encoding/decoding context.
 *
 * Contains parameters required to perform the encoding/decoding and
 * allows for rollback of failed operations.
 *
 * Whenever a message is prepared for transmission, a net2_encdec_ctx
 * is allocated to keep track of connection state modifications.
 * If for any reason, the transmission is cancelled or fails, the
 * net2_encdec_ctx is rolled back.
 */
struct net2_encdec_ctx {
	struct net2_pvlist	 ed_proto;	/* Protocol list. */
	struct net2_objmanager	*ed_objman;	/* Object manager. */
};

#ifdef ilias_net2_EXPORTS
struct net2_connection;
struct net2_objmanager;

ILIAS_NET2_LOCAL
int	 net2_encdec_ctx_init(struct net2_encdec_ctx*, struct net2_pvlist*,
			    struct net2_objmanager*);
ILIAS_NET2_LOCAL
void	 net2_encdec_ctx_rollback(struct net2_encdec_ctx*);
ILIAS_NET2_LOCAL
void	 net2_encdec_ctx_deinit(struct net2_encdec_ctx*);
ILIAS_NET2_LOCAL
int	 net2_encdec_ctx_newaccsocket(struct net2_encdec_ctx*,
	    struct net2_acceptor_socket*);
ILIAS_NET2_LOCAL
int	 net2_encdec_ctx_newobjman(struct net2_encdec_ctx*,
	    struct net2_objmanager*);
#endif /* ilias_net2_EXPORTS */

/* Returns the protocol version from this context. */
static __inline int
net2_encdec_ctx_p2v(struct net2_encdec_ctx *ctx, const struct net2_protocol *p,
    net2_protocol_t *v)
{
	return net2_pvlist_get(&ctx->ed_proto, p, v);
}

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_ENCDEC_CTX_H */
