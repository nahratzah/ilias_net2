/*
 * Copyright (c) 2011, 2012 Ariane van der Steldt <ariane@stack.nl>
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
#ifndef ILIAS_NET2_BSD_COMPAT_ERROR_H
#define ILIAS_NET2_BSD_COMPAT_ERROR_H

#include <stdarg.h>
#include <ilias/net2/ilias_net2_export.h>

#ifdef __cplusplus__
extern "C" {
#endif /* __cplusplus__ */

typedef void (*error_handler_t)(int, const char*);
typedef void (*warn_handler_t)(const char*);
typedef void (*info_handler_t)(const char*);
typedef void (*debug_handler_t)(const char*);

ILIAS_NET2_EXPORT
error_handler_t		set_error_handler(error_handler_t);
ILIAS_NET2_EXPORT
warn_handler_t		set_warn_handler(warn_handler_t);
ILIAS_NET2_EXPORT
info_handler_t		set_info_handler(info_handler_t);
ILIAS_NET2_EXPORT
debug_handler_t		set_debug_handler(debug_handler_t);
ILIAS_NET2_EXPORT
void ILIAS_NET2__dead	verr(int, const char*, va_list);
ILIAS_NET2_EXPORT
void ILIAS_NET2__dead	verrx(int, const char*, va_list);
ILIAS_NET2_EXPORT
void ILIAS_NET2__dead	err(int, const char*, ...);
ILIAS_NET2_EXPORT
void ILIAS_NET2__dead	errx(int, const char*, ...);
ILIAS_NET2_EXPORT
void			vwarn(const char*, va_list);
ILIAS_NET2_EXPORT
void			vwarnx(const char*, va_list);
ILIAS_NET2_EXPORT
void			warn(const char*, ...);
ILIAS_NET2_EXPORT
void			warnx(const char*, ...);
ILIAS_NET2_EXPORT
void			vinfo(const char*, va_list);
ILIAS_NET2_EXPORT
void			info(const char*, ...);
ILIAS_NET2_EXPORT
void			vdebug(const char*, va_list);
ILIAS_NET2_EXPORT
void			debug(const char*, ...);

#ifdef __cplusplus__
}
#endif /* __cplusplus__ */

#endif /* ILIAS_NET2_BSD_COMPAT_ERROR_H */
