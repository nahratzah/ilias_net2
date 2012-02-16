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
#ifndef ILIAS_NET2_SIGNSET_H
#define ILIAS_NET2_SIGNSET_H

#include <ilias/net2/ilias_net2_export.h>
#include <sys/types.h>
#include <stdint.h>
#include <bsd_compat/bsd_compat.h>

#ifdef HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include <bsd_compat/tree.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct net2_buffer;	/* From ilias/net2/buffer.h */

/* Element in the signature set. */
struct net2_signset_entry {
	struct net2_sign_ctx	*key;
	uint_fast32_t		 mini_hash;
	RB_ENTRY(net2_signset_entry)
				 tree;
};

/* Signature set. */
struct net2_signset {
	RB_HEAD(net2_signset_tree, net2_signset_entry)
				 data;
	size_t			 size;
};


ILIAS_NET2_EXPORT
int	 net2_signset_init(struct net2_signset*);
ILIAS_NET2_EXPORT
void	 net2_signset_deinit(struct net2_signset*);
ILIAS_NET2_EXPORT
struct net2_sign_ctx
	*net2_signset_find(const struct net2_signset*,
	    const struct net2_buffer*);
ILIAS_NET2_EXPORT
int	 net2_signset_insert(struct net2_signset *s,
	    struct net2_sign_ctx *key);
ILIAS_NET2_EXPORT
int	 net2_signset_all_fingerprints(struct net2_signset*,
	    struct net2_buffer***, size_t*);
#define	 net2_signset_size(s)	((const size_t)(s)->size)

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_SIGNSET_H */
