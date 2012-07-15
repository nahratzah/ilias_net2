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
#ifndef ILIAS_NET2_CP_H
#define ILIAS_NET2_CP_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/types.h>
#include <ilias/net2/buffer.h>

ILIAS_NET2__begin_cdecl


typedef int (*net2_cp_encfun) (struct net2_encdec_ctx*,
    struct net2_buffer*, const void*, const void*);
typedef int (*net2_cp_decfun) (struct net2_encdec_ctx*,
    void*, struct net2_buffer*, const void*);
typedef int (*net2_cp_initfun) (void*, const void*);
typedef int (*net2_cp_delfun) (void*, const void*);

struct command_param {
	int		 cp_flags;
#define CPT_NONE	 (0)
	size_t		 cp_size;
	const char	*cp_name;
	net2_cp_encfun	 cp_encode;
	net2_cp_decfun	 cp_decode;
	net2_cp_initfun	 cp_init;
	net2_cp_delfun	 cp_delete;
};

ILIAS_NET2_EXPORT
int net2_cp_encode(struct net2_encdec_ctx*, const struct command_param*,
    struct net2_buffer*, const void*, const void*);
ILIAS_NET2_EXPORT
int net2_cp_decode(struct net2_encdec_ctx*, const struct command_param*,
    void*, struct net2_buffer*, const void*);
ILIAS_NET2_EXPORT
int net2_cp_init(const struct command_param*, void*, const void*);
ILIAS_NET2_EXPORT
int net2_cp_destroy(const struct command_param*, void*, const void*);
ILIAS_NET2_EXPORT
int net2_cp_init_alloc(const struct command_param*,
    void**, const void*);
ILIAS_NET2_EXPORT
int net2_cp_destroy_alloc(const struct command_param*,
    void**, const void*);


struct net2_objmanager;	/* From ilias/net2/obj_manager.h */
struct net2_promise;	/* From ilias/net2/promise.h */

typedef void (*net2_cm_invocation) (struct net2_promise*,
    struct net2_encdec_ctx *ctx, void*);

struct command_method {
	const struct net2_protocol
			*cm_protocol;	/* Protocol of request. */
	const struct command_param
			*cm_in;		/* Input type. */
	const struct command_param
			*cm_out;	/* Output type. */
	int		 cm_flags;	/* Command method options. */
#define CM_ASYNC	0x00000001	/* Asynchronous method. */
#define CM_BARRIER_PRE	0x00000002	/* Raise barrier prior. */
#define CM_BARRIER_POST	0x00000004	/* Raise barrier after. */
	net2_cm_invocation
			 cm_method;	/* Implementation function. */
};

ILIAS_NET2_EXPORT
struct net2_promise
		*net2_invoke(struct net2_objmanager*,
		    const struct command_method*, void*);


ILIAS_NET2__end_cdecl
#endif /* ILIAS_NET2_CP_H */
