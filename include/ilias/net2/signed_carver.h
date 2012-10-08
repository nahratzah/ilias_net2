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
#ifndef ILIAS_NET2_SIGNED_CARVER_H
#define ILIAS_NET2_SIGNED_CARVER_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/workq.h>
#include <sys/types.h>
#include <stdint.h>

ILIAS_NET2__begin_cdecl


struct net2_signed_carver;
struct net2_signed_combiner;

struct net2_encdec_ctx;	/* from ilias/net2/encdec_ctx.h */
struct net2_buffer;	/* from ilias/net2/buffer.h */
struct net2_sign_ctx;	/* from ilias/net2/sign.h */
struct net2_promise;	/* from ilias/net2/promise.h */
struct net2_tx_callback;/* from ilias/net2/tx_callback.h */


ILIAS_NET2_EXPORT
struct net2_signed_carver
		*net2_signed_carver_new(struct net2_workq*,
		    struct net2_encdec_ctx*,
		    struct net2_buffer*, int, uint32_t, struct net2_sign_ctx**);
ILIAS_NET2_EXPORT
void		 net2_signed_carver_destroy(struct net2_signed_carver*);

ILIAS_NET2_EXPORT
struct net2_signed_combiner
		*net2_signed_combiner_new(struct net2_workq*,
		    struct net2_encdec_ctx*, uint32_t, struct net2_sign_ctx**);
ILIAS_NET2_EXPORT
void		 net2_signed_combiner_destroy(struct net2_signed_combiner*);

ILIAS_NET2_EXPORT
int		 net2_signed_carver_get_transmit(struct net2_signed_carver*,
		    struct net2_encdec_ctx*,
		    struct net2_workq*, struct net2_buffer*,
		    struct net2_tx_callback*, size_t);
ILIAS_NET2_EXPORT
int		 net2_signed_combiner_accept(struct net2_signed_combiner*,
		    struct net2_encdec_ctx*, struct net2_buffer*);

ILIAS_NET2_EXPORT
struct net2_promise
		*net2_signed_carver_complete(struct net2_signed_carver*);
ILIAS_NET2_EXPORT
struct net2_promise
		*net2_signed_carver_payload(struct net2_signed_carver*);

ILIAS_NET2_EXPORT
struct net2_promise
		*net2_signed_combiner_complete(struct net2_signed_combiner*);
ILIAS_NET2_EXPORT
struct net2_promise
		*net2_signed_combiner_payload(struct net2_signed_combiner*);

ILIAS_NET2_EXPORT
int		 net2_signed_carver_set_rts(struct net2_signed_carver*,
		    struct net2_workq*, net2_workq_cb, void*, void*);


ILIAS_NET2__end_cdecl
#endif /* ILIAS_NET2_SIGNED_CARVER_H */
