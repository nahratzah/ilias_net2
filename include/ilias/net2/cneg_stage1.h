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
#ifndef ILIAS_NET2_CNEG_STAGE1_H
#define ILIAS_NET2_CNEG_STAGE1_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/types.h>
#include <stdint.h>


struct packet_header;		/* From ilias/net2/packet.h */
struct net2_buffer;		/* From ilias/net2/buffer.h */
struct net2_ctx;		/* From ilias/net2/context.h */
struct net2_workq;		/* From ilias/net2/workq.h */
struct net2_tx_callback;	/* From ilias/net2/tx_callback.h */
struct net2_cneg_stage1;


/* Protocol version and negotiated flags. */
struct net2_cneg_stage1_pver {
	net2_protocol_t		 proto0;	/* Protocol 0 version. */
	uint32_t		 flags;		/* Required options. */
};

/* Algorithm set. */
struct net2_cneg_stage1_algorithms {
	size_t			 sz;		/* # algs. */
	int			*algs;		/* Algorithms. */
};

/* Required signatures set. */
struct net2_cneg_stage1_req_signs {
	size_t			 sz;		/* # sctx. */
	struct net2_sign_ctx	**sctx;		/* Signatures. */
};


ILIAS_NET2_LOCAL
struct net2_cneg_stage1	*cneg_stage1_new(uint32_t, struct net2_ctx*,
			    struct net2_workq*);
ILIAS_NET2_LOCAL
void			 cneg_stage1_free(struct net2_cneg_stage1*);
ILIAS_NET2_LOCAL
int			 cneg_stage1_accept(struct net2_cneg_stage1*,
			    struct packet_header*, struct net2_buffer*);
ILIAS_NET2_LOCAL
int			 cneg_stage1_get_transmit(struct net2_cneg_stage1*,
			    struct net2_workq*,
			    struct net2_buffer*, struct net2_tx_callback*,
			    size_t, int, int);

ILIAS_NET2_LOCAL
struct net2_promise	*cneg_stage1_get_pver(struct net2_cneg_stage1*);
ILIAS_NET2_LOCAL
struct net2_promise	*cneg_stage1_get_xchange(struct net2_cneg_stage1*);
ILIAS_NET2_LOCAL
struct net2_promise	*cneg_stage1_get_hash(struct net2_cneg_stage1*);
ILIAS_NET2_LOCAL
struct net2_promise	*cneg_stage1_get_crypt(struct net2_cneg_stage1*);
ILIAS_NET2_LOCAL
struct net2_promise	*cneg_stage1_get_sign(struct net2_cneg_stage1*);
ILIAS_NET2_LOCAL
struct net2_promise	*cneg_stage1_get_advertised_signatures(
			    struct net2_cneg_stage1*);
ILIAS_NET2_LOCAL
struct net2_promise	*cneg_stage1_get_accepted_signatures(
			    struct net2_cneg_stage1*);
ILIAS_NET2_LOCAL
struct net2_promise	*cneg_stage1_get_transmit_signatures(
			    struct net2_cneg_stage1*);
ILIAS_NET2_LOCAL
struct net2_promise	*cneg_stage1_tx_complete(struct net2_cneg_stage1*);
ILIAS_NET2_LOCAL
struct net2_promise	*cneg_stage1_rx_complete(struct net2_cneg_stage1*);
ILIAS_NET2_LOCAL
struct net2_promise	*cneg_stage1_complete(struct net2_cneg_stage1*);

#endif /* ILIAS_NET2_CNEG_STAGE1_H */
