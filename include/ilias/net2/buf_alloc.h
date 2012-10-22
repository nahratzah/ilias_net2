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
#ifndef ILIAS_NET2_BUF_ALLOC_H
#define ILIAS_NET2_BUF_ALLOC_H

#include <ilias/net2/ilias_net2_export.h>

namespace ilias {


ILIAS_NET2_LOCAL void* buf_alloc(size_t& sz, const std::nothrow_t&) ILIAS_NET2_NOTHROW;
ILIAS_NET2_LOCAL bool buf_extend(void*, size_t& sz, const std::nothrow_t&) ILIAS_NET2_NOTHROW;
ILIAS_NET2_LOCAL void buf_free(void*) ILIAS_NET2_NOTHROW;
ILIAS_NET2_LOCAL size_t buf_allocsz(void*) ILIAS_NET2_NOTHROW;

inline void*
buf_alloc(size_t& sz)
{
	void* ptr = buf_alloc(sz, std::nothrow);
	if (!ptr)
		throw std::bad_alloc();
	return ptr;
}

inline void
buf_extend(void* ptr, size_t& sz)
{
	if (!buf_extend(ptr, sz, std::nothrow))
		throw std::bad_alloc();
}


}


#endif /* ILIAS_NET2_BUF_ALLOC_H */
