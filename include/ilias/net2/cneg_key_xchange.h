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
#ifndef ILIAS_NET2_CNEG_KEY_XCHANGE_H
#define ILIAS_NET2_CNEG_KEY_XCHANGE_H

#include <ilias/net2/ilias_net2_export.h>
#include <sys/types.h>
#include <stdint.h>

struct net2_buffer;	/* From ilias/net2/buffer.h */

#define NET2_CNEG_S2_HASH	0	/* Secure hash key. */
#define NET2_CNEG_S2_ENC	1	/* Encryption key. */
#define NET2_CNEG_S2_MAX	2	/* # exchanges. */

/* Result output of key negotiation. */
struct net2_cneg_keyset {
	struct net2_buffer	*tx[NET2_CNEG_S2_MAX];
	struct net2_buffer	*rx[NET2_CNEG_S2_MAX];
};

ILIAS_NET2_EXPORT
void	 net2_cneg_keyset_free(struct net2_cneg_keyset*);
ILIAS_NET2_EXPORT
struct net2_cneg_keyset
	*net2_cneg_keyset_dup(struct net2_cneg_keyset*);

#endif /* ILIAS_NET2_CNEG_KEY_XCHANGE_H */
