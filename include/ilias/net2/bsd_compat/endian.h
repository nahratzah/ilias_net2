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
#ifndef ILIAS_NET2_BSD_COMPAT_ENDIAN_H
#define ILIAS_NET2_BSD_COMPAT_ENDIAN_H


#include <sys/types.h>

__inline uint64_t
_byteswap64(uint64_t x)
{
	return
	    (x & 0xffULL) << 56 |
	    (x & 0xff00ULL) << 40 |
	    (x & 0xff0000ULL) << 24 |
	    (x & 0xff000000ULL) << 8 |
	    (x & 0xff00000000ULL) >> 8 |
	    (x & 0xff0000000000ULL) >> 24 |
	    (x & 0xff000000000000ULL) >> 40 |
	    (x & 0xff00000000000000ULL) >> 56;
}

__inline uint32_t
_byteswap32(uint32_t x)
{
	return
	    (x & 0xffU) << 24 |
	    (x & 0xff00U) << 8 |
	    (x & 0xff0000U) >> 8 |
	    (x & 0xff000000U) >> 24;
}

__inline uint16_t
_byteswap16(uint16_t x)
{
	return
	    (x & 0xff) << 8 |
	    (x & 0xff00) >> 8;
}

#ifndef htobe16
#ifdef IS_BIG_ENDIAN
#define htobe16(x)	(x)
#define betoh16(x)	(x)
#else
#define htobe16(x)	_byteswap16((x))
#define betoh16(x)	_byteswap16((x))
#endif
#endif	/* htobe16 */

#ifndef htobe32
#ifdef IS_BIG_ENDIAN
#define htobe32(x)	(x)
#define betoh32(x)	(x)
#else
#define htobe32(x)	_byteswap32((x))
#define betoh32(x)	_byteswap32((x))
#endif
#endif	/* htobe32 */

#ifndef htobe64
#ifdef IS_BIG_ENDIAN
#define htobe64(x)	(x)
#define betoh64(x)	(x)
#else
#define htobe64(x)	_byteswap64((x))
#define betoh64(x)	_byteswap64((x))
#endif
#endif	/* htobe64 */


#endif /* ILIAS_NET2_BSD_COMPAT_ENDIAN_H */
