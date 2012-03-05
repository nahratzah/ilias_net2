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
#ifndef ILIAS_NET2_BSD_COMPAT_WRITEV_H
#define ILIAS_NET2_BSD_COMPAT_WRITEV_H

#include <ilias/net2/config.h>
#include <ilias/net2/ilias_net2_export.h>
#include <stdint.h>
#include <sys/types.h>

struct iovec {
	void	*iov_base;
	size_t	 iov_len;
};

#ifdef __cplusplus__
extern "C"
#endif
ILIAS_NET2_EXPORT
long writev(int, const struct iovec*, int);

#endif /* ILIAS_NET2_BSD_COMPAT_WRITEV_H */
