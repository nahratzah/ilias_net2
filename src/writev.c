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
#include <ilias/net2/bsd_compat/writev.h>
#include <string.h>
#include <stdint.h>

#ifdef WIN32
#include <malloc.h>
#include <io.h>
#else
#include <unistd.h>
#endif

#ifdef WIN32
#define write		_write
#endif /* WIN32 */

ILIAS_NET2_EXPORT long
writev(int d, const struct iovec *iov, int iovcnt)
{
	size_t			 iolen = 0;
	const struct iovec	*i;
	uint8_t			*buf, *write_ptr;

	for (i = iov; i < iov + iovcnt; i++)
		iolen += i->iov_len;
	buf = write_ptr = (uint8_t*)alloca(iolen);
	for (i = iov; i < iov + iovcnt; i++) {
		memcpy(write_ptr, i->iov_base, i->iov_len);
		write_ptr += i->iov_len;
	}
	return write(d, buf, iolen);
}
