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
#ifndef ILIAS_NET2_BITSET_H
#define ILIAS_NET2_BITSET_H

#include <ilias/net2/ilias_net2_export.h>
#include <sys/types.h>
#include <stdint.h>

struct net2_bitset {
	size_t		 size;
	int		*data;
};


#ifdef ilias_net2_EXPORTS

#define net2_bitset_size(_s)	((const size_t)(_s)->size)
ILIAS_NET2_LOCAL
void	net2_bitset_init(struct net2_bitset*);
ILIAS_NET2_LOCAL
void	net2_bitset_deinit(struct net2_bitset*);
ILIAS_NET2_LOCAL
int	net2_bitset_get(const struct net2_bitset*, size_t, int*);
ILIAS_NET2_LOCAL
int	net2_bitset_set(struct net2_bitset*, size_t, int, int*);
ILIAS_NET2_LOCAL
int	net2_bitset_resize(struct net2_bitset*, size_t, int);
ILIAS_NET2_LOCAL
int	net2_bitset_allset(const struct net2_bitset*);
ILIAS_NET2_LOCAL
int	net2_bitset_allclear(const struct net2_bitset*);

#endif /* ilias_net2_EXPORTS */

#endif /* ILIAS_NET2_BITSET_H */
