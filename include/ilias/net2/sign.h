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
#ifndef ILIAS_NET2_SIGN_H
#define ILIAS_NET2_SIGN_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/buffer.h>
#include <sys/types.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

struct net2_sign_ctx;

extern ILIAS_NET2_EXPORT const int net2_signmax;

ILIAS_NET2_EXPORT
size_t			 net2_sign_getsignlen(int);
ILIAS_NET2_EXPORT
const char		*net2_sign_getname(int);
ILIAS_NET2_EXPORT
int			 net2_sign_findname(const char*);

ILIAS_NET2_EXPORT
struct net2_sign_ctx	*net2_signctx_pubnew(int, const void*, size_t);
ILIAS_NET2_EXPORT
struct net2_sign_ctx	*net2_signctx_privnew(int, const void*, size_t);
ILIAS_NET2_EXPORT
void			 net2_signctx_free(struct net2_sign_ctx*);
ILIAS_NET2_EXPORT
size_t			 net2_signctx_maxmsglen(struct net2_sign_ctx*);
ILIAS_NET2_EXPORT
int			 net2_signctx_sign(struct net2_sign_ctx*,
			    const struct net2_buffer*, struct net2_buffer*);
ILIAS_NET2_EXPORT
int			 net2_signctx_validate(struct net2_sign_ctx*,
			    const struct net2_buffer*,
			    const struct net2_buffer*);
ILIAS_NET2_EXPORT
const char		*net2_signctx_name(struct net2_sign_ctx*);

extern ILIAS_NET2_EXPORT const int net2_sign_ecdsa;


#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_SIGN_H */
