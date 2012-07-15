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
#ifndef ILIAS_NET2_TYPES_H
#define ILIAS_NET2_TYPES_H

#include <ilias/net2/ilias_net2_export.h>
#include <sys/types.h>
#include <stdint.h>

ILIAS_NET2__begin_cdecl


typedef uint32_t	net2_command_t;
typedef uint32_t	net2_protocol_t;
struct			net2_connection;
struct			net2_encdec_ctx;
struct			net2_evbase;
struct			net2_obj;
struct			net2_objtype;
struct			net2_window;

#ifdef WIN32
typedef HANDLE		net2_socket_t;
#else
typedef int		net2_socket_t;
#endif

#ifdef BUILDING_ILIAS_NET2
/* Not a type, but it needs to be defined somewhere... */
ILIAS_NET2_LOCAL
void			net2_secure_zero(void*, size_t);
#endif /* BUILDING_ILIAS_NET2 */


ILIAS_NET2__end_cdecl
#endif /* ILIAS_NET2_TYPES_H */
