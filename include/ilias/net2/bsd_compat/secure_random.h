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
#ifndef ILIAS_NET2_BSD_COMPAT_SECURE_RANDOM_H
#define ILIAS_NET2_BSD_COMPAT_SECURE_RANDOM_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/config.h>
#include <sys/types.h>
#include <stdint.h>

#ifdef HAS_ARC4RANDOM

/*
 * Use arc4random supplied by operating system.
 */
#include <stdlib.h>

#define secure_random()			arc4random()
#define secure_random_buf(_ptr, _len)	arc4random_buf(_ptr, _len)
#define secure_random_uniform(_top)	arc4random_uniform(_top)
#define secure_random_init()		(0)
#define secure_random_deinit()		do { /* Nothing */ } while (0)

#elif WIN32

/*
 * Wrap windows cryptography framework.
 */
#include <stdint.h>

ILIAS_NET2__begin_cdecl

ILIAS_NET2_LOCAL
int			win32_secure_random_init();
ILIAS_NET2_LOCAL
void			win32_secure_random_deinit();
ILIAS_NET2_EXPORT
uint32_t		win32_secure_random();
ILIAS_NET2_EXPORT
void			win32_secure_random_buf(void*, size_t);
ILIAS_NET2_EXPORT
uint32_t		win32_secure_random_uniform(uint32_t);

ILIAS_NET2__end_cdecl

#define secure_random()			win32_secure_random()
#define secure_random_buf(_ptr, _len)	win32_secure_random_buf((_ptr), (_len))
#define secure_random_uniform(_top)	win32_secure_random_uniform((_top))
#define secure_random_init()		win32_secure_random_init()
#define secure_random_deinit()		win32_secure_random_deinit()

#else

/*
 * Fallback to using /dev/random.
 */

ILIAS_NET2__begin_cdecl

ILIAS_NET2_LOCAL
int			devrandom_secure_random_init();
ILIAS_NET2_LOCAL
void			devrandom_secure_random_deinit();
ILIAS_NET2_EXPORT
uint32_t		devrandom_secure_random();
ILIAS_NET2_EXPORT
void			devrandom_secure_random_buf(void*, size_t);
ILIAS_NET2_EXPORT
uint32_t		devrandom_secure_random_uniform(uint32_t);

ILIAS_NET2__end_cdecl

#define secure_random()			devrandom_secure_random()
#define secure_random_buf(_ptr, _len)	devrandom_secure_random_buf((_ptr), (_len))
#define secure_random_uniform(_top)	devrandom_secure_random_uniform((_top))
#define secure_random_init()		devrandom_secure_random_init()
#define secure_random_deinit()		devrandom_secure_random_deinit()

#endif


#endif /* ILIAS_NET2_BSD_COMPAT_SECURE_RANDOM_H */
