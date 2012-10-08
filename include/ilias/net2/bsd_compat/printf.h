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
#ifndef ILIAS_NET2_BSD_COMPAT_PRINTF_H
#define ILIAS_NET2_BSD_COMPAT_PRINTF_H


#include <ilias/net2/config.h>
#include <ilias/net2/ilias_net2_export.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>

#ifndef HAS_VASPRINTF
ILIAS_NET2_EXPORT
int vasprintf(char **ret, const char *format, va_list ap);
#endif /* HAS_VASPRINTF */

#ifndef HAS_ASPRINTF
ILIAS_NET2_EXPORT
int asprintf(char **ret, const char *format, ...);
#endif /* HAS_VASPRINTF */

#ifndef HAS_VSNPRINTF
ILIAS_NET2_EXPORT
int vsnprintf(char *ret, size_t len, const char *format, va_list ap);
#endif /* HAS_SNPRINTF */

#ifndef HAS_SNPRINTF
ILIAS_NET2_EXPORT
int snprintf(char *ret, size_t len, const char *format, ...);
#endif /* HAS_SNPRINTF */


#endif /* ILIAS_NET2_BSD_COMPAT_PRINTF_H */
