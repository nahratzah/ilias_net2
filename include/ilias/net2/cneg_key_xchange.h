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

/* Result output of key negotiation. */
struct net2_cneg_key_result {
	const void		*key;
	size_t			 keylen;
};

ILIAS_NET2_EXPORT
void	 net2_cneg_key_result_deinit(struct net2_cneg_key_result*);
ILIAS_NET2_EXPORT
int	 net2_cneg_key_result_init(struct net2_cneg_key_result*, const void*,
	    size_t);
ILIAS_NET2_EXPORT
int	 net2_cneg_key_result_initbuf(struct net2_cneg_key_result*,
	    struct net2_buffer*);

#endif /* ILIAS_NET2_CNEG_KEY_XCHANGE_H */
