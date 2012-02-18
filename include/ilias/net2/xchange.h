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
#ifndef ILIAS_NET2_XCHANGE_H
#define ILIAS_NET2_XCHANGE_H

#include <ilias/net2/ilias_net2_export.h>
#include <sys/types.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Key exchange logic.
 *
 * Keys are always generated from input provided by both parties, so that if
 * one of the parties is unable to provide proper randomization, the key is
 * still at half strength.
 */
struct net2_xchange_ctx;
struct net2_buffer;

#define NET2_XCHANGE_F_INITIATOR	0x00000001

extern ILIAS_NET2_EXPORT const int net2_xchangemax;

ILIAS_NET2_EXPORT
const char		*net2_xchange_getname(int);
ILIAS_NET2_EXPORT
int			 net2_xchange_findname(const char*);

ILIAS_NET2_EXPORT
struct net2_xchange_ctx	*net2_xchangectx_prepare(int, size_t, int,
			    struct net2_buffer*);
ILIAS_NET2_EXPORT
struct net2_buffer	*net2_xchangectx_export(struct net2_xchange_ctx*);
ILIAS_NET2_EXPORT
int			 net2_xchangectx_import(struct net2_xchange_ctx*,
			    struct net2_buffer*);
ILIAS_NET2_EXPORT
struct net2_buffer	*net2_xchangectx_final(struct net2_xchange_ctx*);
ILIAS_NET2_EXPORT
void			 net2_xchangectx_free(struct net2_xchange_ctx*);
ILIAS_NET2_EXPORT
struct net2_buffer	*net2_xchangectx_finalfree(struct net2_xchange_ctx*);
ILIAS_NET2_EXPORT
struct net2_xchange_ctx	*net2_xchangectx_clone(const struct net2_xchange_ctx*);


#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_XCHANGE_H */
