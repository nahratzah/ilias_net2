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
#ifndef ILIAS_NET2_ENC_H
#define ILIAS_NET2_ENC_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/buffer.h>
#include <sys/types.h>
#include <stdint.h>

ILIAS_NET2__begin_cdecl


struct net2_enc_ctx;
#define NET2_ENC_ENCRYPT	1	/* Perform encryption. */
#define NET2_ENC_DECRYPT	2	/* Perform decryption. */

extern ILIAS_NET2_EXPORT const int net2_encmax;

ILIAS_NET2_EXPORT
size_t			 net2_enc_getkeylen(int);
ILIAS_NET2_EXPORT
size_t			 net2_enc_getivlen(int);
ILIAS_NET2_EXPORT
const char		*net2_enc_getname(int);
ILIAS_NET2_EXPORT
size_t			 net2_enc_getoverhead(int);
ILIAS_NET2_EXPORT
int			 net2_enc_findname(const char*);

ILIAS_NET2_EXPORT
struct net2_enc_ctx	*net2_encctx_new(int, const void*, size_t,
			    const void*, size_t, int);
ILIAS_NET2_EXPORT
int			 net2_encctx_update(struct net2_enc_ctx*,
			    const void*, size_t);
ILIAS_NET2_EXPORT
int			 net2_encctx_updatebuf(struct net2_enc_ctx*,
			    const struct net2_buffer*);
ILIAS_NET2_EXPORT
struct net2_buffer	*net2_encctx_final(struct net2_enc_ctx*);
ILIAS_NET2_EXPORT
struct net2_buffer	*net2_encctx_finalfree(struct net2_enc_ctx*);

ILIAS_NET2_EXPORT
struct net2_buffer	*net2_encctx_encbuf(int, const void*, size_t,
			    const void*, size_t, int,
			    const struct net2_buffer*);


ILIAS_NET2__end_cdecl
#endif /* ILIAS_NET2_ENC_H */
