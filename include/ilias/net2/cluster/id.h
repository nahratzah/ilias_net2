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
#ifndef ILIAS_NET2_CLUSTER_ID_H
#define ILIAS_NET2_CLUSTER_ID_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Site identifier. */
struct site_id {
	uint32_t	 site_id;
};

/* Node identifier. */
struct node_id {
	struct site_id	 site;
	uint32_t	 node_id;
};

/* Object identifier. */
struct obj_id {
	struct node_id	 node;
	uint32_t	 obj_id;
};

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_CLUSTER_ID_H */
