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
#ifndef ILIAS_NET2_PROTOCOL_H
#define ILIAS_NET2_PROTOCOL_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/types.h>
#include <sys/types.h>

ILIAS_NET2__begin_cdecl


/*
 * Protocol specification.
 *
 * This is a static datastructure that is initialized by the software using
 * the net2 library.
 */
struct net2_protocol {
	/* Name of the protocol. */
	const char			*name;
	/* Implementation version of the protocol. */
	net2_protocol_t			 version;

	/* CP serialization. */
	const struct command_param	**cp;
	/* Number of CP in this protocol. */
	size_t				 numcp;

	/* Method serialization. */
	const struct command_method	**methods;
	/* Number of methods in this protocol. */
	size_t				 nummethods;

	/* List of types in this context. */
	const struct net2_objtype	**types;
	/* Number of types in this context. */
	size_t				 numtypes;

	/* Protocol flags. */
	int				 flags;
#define NET2_CTX_CLUST_SRVR	 0x80000000	/* Server is a cluster. */
#define NET2_CTX_CLUST_CLNT	 0x40000000	/* Client is a cluster. */
#define NET2_CTX_HAS_CLIENT	 0x10000000	/* Client/server cluster. */
#define NET2_CTX_OBJMOVE	 0x00800000	/* Objects may hop nodes. */
};

/* Protocol with negotiated version number. */
struct net2_proto_version {
	const struct net2_protocol	*pv_protocol;
	net2_protocol_t			 pv_version;
};

/* List of protocols with corresponding version numbers. */
struct net2_pvlist {
	struct net2_proto_version	*list;
	size_t				 listsz;
};


/* Specification of the net2 protocol. */
extern ILIAS_NET2_EXPORT
const struct net2_protocol	 net2_proto;

ILIAS_NET2_EXPORT
const struct net2_objtype	*net2_protocol_type(
				    const struct net2_protocol*, uint32_t);
ILIAS_NET2_EXPORT
const struct command_method	*net2_protocol_method(
				    const struct net2_protocol*, uint32_t);
ILIAS_NET2_EXPORT
int				 net2_protocol_method_id(
				    const struct net2_protocol*,
				    const struct command_method*, uint32_t*);

ILIAS_NET2_EXPORT
int				 net2_pvlist_init(struct net2_pvlist*);
ILIAS_NET2_EXPORT
void				 net2_pvlist_deinit(struct net2_pvlist*);
ILIAS_NET2_EXPORT
int				 net2_pvlist_add(struct net2_pvlist*,
				    const struct net2_protocol*, net2_protocol_t);
ILIAS_NET2_EXPORT
int				 net2_pvlist_get(const struct net2_pvlist*,
				    const struct net2_protocol*, net2_protocol_t*);
ILIAS_NET2_EXPORT
int				 net2_pvlist_merge(struct net2_pvlist*,
				    const struct net2_pvlist*);
ILIAS_NET2_EXPORT
const struct net2_protocol	*net2_pvlist_get_by_id(const struct net2_pvlist*,
				    size_t idx);


ILIAS_NET2__end_cdecl
#endif /* ILIAS_NET2_PROTOCOL_H */
