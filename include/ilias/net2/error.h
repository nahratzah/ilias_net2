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
#ifndef ILIAS_NET2_ERROR_H
#define ILIAS_NET2_ERROR_H


/* Ilias net2 specific error classes. */
#define NET2_ERRCLASS_MASK		 0xff000000 /* Classification matk. */
#define NET2_ERRCLASS_CONNECT		 0x01000000 /* Connect errors. */

/*
 * Ilias net2 specific error conditions.
 */

/* Connect failed, due to missing signing algorithms. */
#define NET2_ERR_CONN_REQ_SIGN		(0x00000001 | NET2_ERRCLASS_CONNECT)
/* Connect failed, due to missing encryption algorithms. */
#define NET2_ERR_CONN_REQ_ENC		(0x00000002 | NET2_ERRCLASS_CONNECT)
/* Connect failed, due to missing remote host signature. */
#define NET2_ERR_CONN_REQ_SIGNATURE	(0x00000003 | NET2_ERRCLASS_CONNECT)
/* Connect failed, due to signature mismatch (possibly foiled mitm attack). */
#define NET2_ERR_CONN_MITM		(0x00000004 | NET2_ERRCLASS_CONNECT)
/* Connect failed, due to response timeout. */
#define NET2_ERR_CONN_TIMEOUT		(0x00000005 | NET2_ERRCLASS_CONNECT)


#endif /* ILIAS_NET2_ERROR_H */
