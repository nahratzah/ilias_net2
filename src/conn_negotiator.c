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
#include <ilias/net2/conn_negotiator.h>
#include <ilias/net2/connection.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/bitset.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/cp.h>
#include <ilias/net2/packet.h>
#include <ilias/net2/promise.h>
#include <ilias/net2/evbase.h>
#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/context.h>
#include <ilias/net2/carver.h>
#include <stdlib.h>
#include <assert.h>
#include <bsd_compat/minmax.h>
#include <bsd_compat/bsd_compat.h>
#include <event2/event.h>

#include <ilias/net2/enc.h>
#include <ilias/net2/hash.h>
#include <ilias/net2/xchange.h>

#include "handshake.h"
#include "exchange.h"

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <bsd_compat/queue.h>
#endif

#define REQUIRE								\
	(NET2_CNEG_REQUIRE_ENCRYPTION | NET2_CNEG_REQUIRE_SIGNING)
#define UNKNOWN_SIZE		((size_t)-1)

#define CNEG_OFFSET							\
		(size_t)(&((struct net2_connection*)0)->n2c_negotiator)
#define CNEG_CONN(_cn)							\
		((struct net2_connection*)((char*)(_cn) - CNEG_OFFSET))

/* Set management. */
struct net2_conn_negotiator_set {
	int			 flags;
#define SET_F_ALLDONE		0x00000001
	struct net2_bitset	 data;
	size_t			 expected_size;

	int	(*callback_complete)(struct net2_conn_negotiator*);
};


/*
 * Key exchange data transport.
 *
 * Transports a data buffer and all associated signatures.
 */
struct cneg_keyex_ctx {
	int			 flags;
#define CNEG_KEYEX_IN		0x00000001
#define CNEG_KEYEX_OUT		0x00000002
#define CNEG_KEYEX_COMPLETE	0x80000000

	size_t			 num_signatures;

	union {
		struct {
			struct net2_carver
				 payload;
			struct net2_carver
				*signatures;
		}		 out;
		struct {
			struct net2_combiner
				 payload;
			struct net2_combiner
				*signatures;
		}		 in;
	};
};


/*
 * Connection negotiator stage 2 exchange state.
 */
struct net2_cneg_exchange {
	struct net2_conn_negotiator
				*cneg;		/* Exchange owner. */
	struct net2_xchange_ctx	*xchange;	/* Xchange context. */
	struct net2_promise	*promise;	/* Promise for xchange. */
	struct cneg_keyex_ctx	 initbuf;	/* Initial buffer. */
	struct cneg_keyex_ctx	 export;	/* Export buffer. */
	struct cneg_keyex_ctx	 import;	/* Import buffer. */
	int			 alg;		/* Algorithm ID. */
	int			 xchange_alg;	/* Selected exchange method. */
	uint32_t		 keysize;	/* Negotiated key size. */

	int			 state;		/* DFA state. */
#define S2_SETUP_KNOWN		0x00000001	/* Setup received/sent. */
#define S2_INITBUF_KNOWN	0x00000002	/* Initbuf received/send. */
#define S2_RESPONSE_RECEIVED	0x00000004	/* Response received. */
#define S2_READY		0x00000007	/* All of the above. */
#define S2_CARVER_INITDONE	0x80000000	/* Carvers/combiners have been
						 * initialized. */
};


static __inline int
encode_header(struct net2_buffer *out, const struct header *h)
{
	return net2_cp_encode(&net2_encdec_proto0, &cp_header, out, h, NULL);
}
static __inline int
decode_header(struct header *h, struct net2_buffer *in)
{
	return net2_cp_decode(&net2_encdec_proto0, &cp_header, h, in, NULL);
}

/* Notify connection that we want to send data. */
static __inline void
cneg_ready_to_send(struct net2_conn_negotiator *cn)
{
	net2_acceptor_socket_ready_to_send(&CNEG_CONN(cn)->n2c_socket);
}

/*
 * Initialize keyex without actual data.
 * Ensures that calling init or deinit on this is a safe operation.
 */
static __inline void
cneg_keyex_ctx_init(struct cneg_keyex_ctx *ctx)
{
	ctx->flags = 0;
}


static struct encoded_header
		*mk_encoded_header();
static void	 free_encoded_header(struct encoded_header*);
static void	 ack_cb(void*, void*);
static void	 nack_cb(void*, void*);
static void	 destroy_cb(void*, void*);

static int	 create_xhc_headers(struct net2_conn_negotiator*,
		    const char *(*)(int), int, uint32_t);
static int	 create_fingerprint_headers(struct net2_conn_negotiator*,
		    struct net2_signset*, uint32_t);
static int	 create_headers(struct net2_conn_negotiator*);

static int	 set_get(struct net2_conn_negotiator*, size_t,
		    struct net2_conn_negotiator_set**);
static int	 set_process(struct net2_conn_negotiator*, size_t, size_t,
		    int*);
static int	 set_process_size(struct net2_conn_negotiator*, uint32_t,
		    uint32_t);
static int	 set_done(struct net2_conn_negotiator_set*);
static int	 set_all_done(const struct net2_conn_negotiator*);
static int	 all_done(const struct net2_conn_negotiator*);

static int	 intlist_add(int**, size_t*, int);
static int	 hash_cmp(const void*, const void*);
static int	 enc_cmp(const void*, const void*);
static int	 xchange_cmp(const void*, const void*);
static int	 sign_cmp(const void*, const void*);

static int	 cneg_apply_header(struct net2_conn_negotiator*,
		    struct header*);

static int	 cneg_conclude_pristine(struct net2_conn_negotiator*);
static int	 cneg_prepare_key_exchange(struct net2_conn_negotiator*);

static int	 cneg_keyex_ctx_init_out(struct cneg_keyex_ctx*,
		    struct net2_encdec_ctx*, struct net2_buffer*,
		    int, struct net2_sign_ctx**, size_t);
static int	 cneg_keyex_ctx_init_in(struct cneg_keyex_ctx*, size_t);
static void	 cneg_keyex_deinit(struct cneg_keyex_ctx*);
static int	 cneg_keyex_is_done(struct cneg_keyex_ctx*);
static int	 cneg_keyex_ctx_encode_payload(struct net2_buffer**,
		    struct cneg_keyex_ctx*, struct net2_encdec_ctx*,
		    struct net2_evbase*, struct net2_cw_tx*, int, int,
		    size_t);
static int	 cneg_keyex_ctx_encode_signature(struct net2_buffer**,
		    struct cneg_keyex_ctx*, struct net2_encdec_ctx*,
		    struct net2_evbase*, struct net2_cw_tx*, int, int, size_t,
		    size_t);
static int	 cneg_keyex_ctx_encode(struct net2_buffer**,
		    struct cneg_keyex_ctx*, struct net2_encdec_ctx*,
		    struct net2_evbase*, struct net2_cw_tx*, int, int,
		    size_t);

static int	 net2_cneg_exchange_init(struct net2_conn_negotiator*,
		    struct net2_cneg_exchange*);
static void	 net2_cneg_exchange_deinit(struct net2_cneg_exchange*);
static int	 net2_cneg_exchange_get_transmit(struct net2_buffer**,
		    struct net2_cneg_exchange*, struct net2_encdec_ctx*,
		    struct net2_evbase*, struct net2_cw_tx*, int, size_t);
static int	 stage2_init_exchange(struct net2_ctx*,
		    struct net2_cneg_exchange*);
static int	 stage2_init_exchange_directly(struct net2_cneg_exchange*);
static int	 stage2_init_xchange_post(struct net2_cneg_exchange*,
		    struct net2_buffer*);
static void	 stage2_init_xchange_promise_cb(evutil_socket_t, short, void*);

static int	 cneg_stage1_accept(struct net2_conn_negotiator*,
		    struct packet_header*, struct net2_buffer*);


/* Queue encoded headers. */
struct encoded_header {
	TAILQ_ENTRY(encoded_header)
				 entry;

	int			 flags;
#define EHF_NEGOTIATOR_DIED	0x00000001
#define EHF_HEADER		0x00000010	/* This is a header. */
	union {
		struct header	 header;
	}			 data;
	struct net2_buffer	*buf;
};
/* Create a new encoded header from a buffer. */
static struct encoded_header*
mk_encoded_header()
{
	struct encoded_header	*eh;

	if ((eh = net2_malloc(sizeof(*eh))) == NULL)
		return NULL;
	if (net2_cp_init(NULL, &cp_header, &eh->data.header, NULL)) {
		net2_free(eh);
		return NULL;
	}
	eh->flags = EHF_HEADER;
	eh->buf = NULL;
	return eh;
}
/* Free an encoded header. */
static void
free_encoded_header(struct encoded_header *eh)
{
	if (eh->flags & EHF_HEADER)
		net2_cp_destroy(NULL, &cp_header, &eh->data.header, NULL);
	if (eh->buf)
		net2_buffer_free(eh->buf);
	net2_free(eh);
}
/* Encoded header connection-ack callback. */
static void
ack_cb(void *hptr, void *cnptr)
{
	struct encoded_header	*h = (struct encoded_header*)hptr;
	struct net2_conn_negotiator
				*cn = (struct net2_conn_negotiator*)cnptr;

	if (h->flags & EHF_NEGOTIATOR_DIED) {
		free_encoded_header(h);
		return;
	}

	if (h->data.header.flags == F_TYPE_PVER)
		cn->pver_acknowledged = 1;
	TAILQ_REMOVE(&cn->waitq, h, entry);
	free_encoded_header(h);
	if (TAILQ_EMPTY(&cn->waitq))
		cneg_ready_to_send(cn);
}
/* Encoded header connection-nack callback. */
static void
nack_cb(void *hptr, void *cnptr)
{
	struct encoded_header	*h = (struct encoded_header*)hptr;
	struct net2_conn_negotiator
				*cn = (struct net2_conn_negotiator*)cnptr;

	if (h->flags & EHF_NEGOTIATOR_DIED) {
		free_encoded_header(h);
		return;
	}

	TAILQ_REMOVE(&cn->waitq, h, entry);
	TAILQ_INSERT_TAIL(&cn->sendq, h, entry);
	cneg_ready_to_send(cn);
}
/* Encoded header connection-close callback. */
static void
destroy_cb(void *hptr, void *cnptr)
{
	struct encoded_header	*h = (struct encoded_header*)hptr;
	struct net2_conn_negotiator
				*cn = (struct net2_conn_negotiator*)cnptr;

	/* If cn didn't quite die just yet, prevent duplicate free. */
	if ((h->flags & EHF_NEGOTIATOR_DIED) == 0)
		TAILQ_REMOVE(&cn->waitq, h, entry);
	/* Kill h. */
	free_encoded_header(h);
}

/*
 * Generator: process all {xchange,hash,crypt} headers.
 *
 * set must point at an array of at least end types.
 */
static int
create_xhc_headers(struct net2_conn_negotiator *cn,
    const char *(*name_fn)(int), int end, uint32_t type)
{
	struct encoded_header	*h;
	int			 i, e;
	const char		**list;
	int			 error;

	/* Allocate the name list. */
	if ((list = net2_calloc(MAX(end, 1), sizeof(*list))) == NULL)
		return ENOMEM;

	/* Gather all names, skipping nulls. */
	for (i = e = 0; i < end; i++) {
		if ((list[e] = (*name_fn)(i)) != NULL)
			e++;
	}

	/* Transform names into buffers. */
	for (i = 0; i < e; i++) {
		if ((h = mk_encoded_header()) == NULL) {
			error = ENOMEM;
			goto fail;
		}

		if ((error = init_header_stringset(&h->data.header, i, list[i],
		    e - 1, type)) != 0) {
			free_encoded_header(h);
			goto fail;
		}
		TAILQ_INSERT_TAIL(&cn->sendq, h, entry);
	}

	/* Handle empty set. */
	if (e == 0) {
		if ((h = mk_encoded_header()) == NULL) {
			error = ENOMEM;
			goto fail;
		}

		if ((error = init_header_empty_set(&h->data.header,
		    type)) != 0) {
			free_encoded_header(h);
			goto fail;
		}
		TAILQ_INSERT_TAIL(&cn->sendq, h, entry);
	}

	net2_free(list);
	return 0;

fail:
	net2_free(list);
	return error;
}

/*
 * Encode fingerprints into headers.
 */
static int
create_fingerprint_headers(struct net2_conn_negotiator *cn, struct net2_signset *s,
    uint32_t which)
{
	struct encoded_header	*h;
	size_t			 i, e;
	struct net2_buffer	**list;
	int			 error;

	list = NULL;
	e = 0;
	/* Gather all fingerprints. */
	if (s != NULL) {
		if ((error = net2_signset_all_fingerprints(
		    s, &list, &e)) != 0)
			goto fail;
	}

	/* Add all fingerprints. */
	for (i = 0; i < e; i++) {
		if ((h = mk_encoded_header()) == NULL) {
			error = ENOMEM;
			goto fail;
		}

		if ((error = init_header_bufset(&h->data.header, i, list[i],
		    e - 1, which)) != 0) {
			free_encoded_header(h);
			goto fail;
		}
		TAILQ_INSERT_TAIL(&cn->sendq, h, entry);
	}

	/* Handle empty set. */
	if (e == 0) {
		if ((h = mk_encoded_header()) == NULL) {
			error = ENOMEM;
			goto fail;
		}

		if ((error = init_header_empty_set(&h->data.header,
		    which)) != 0) {
			free_encoded_header(h);
			goto fail;
		}
		TAILQ_INSERT_TAIL(&cn->sendq, h, entry);
	}

	/* Succes. */
	error = 0;

fail:
	if (list != NULL) {
		while (e > 0)
			net2_buffer_free(list[--e]);
		net2_free(list);
	}
	return error;
}

/*
 * Create buffers with all headers.
 */
static int
create_headers(struct net2_conn_negotiator *cn)
{
	struct encoded_header	*h;
	int			 error;
	uint16_t		 num_types;
	uint16_t		 num_settypes;
	struct net2_conn_negotiator_set
				*set4;

	if ((h = mk_encoded_header()) == NULL)
		return ENOMEM;
	/* TYPE[0]: Generate protocol header. */
	if ((error = init_header_protocol(&h->data.header, cn->flags)) != 0) {
		free_encoded_header(h);
		return error;
	}
	num_types = h->data.header.payload.num_types;
	num_settypes = h->data.header.payload.num_settypes;
	TAILQ_INSERT_TAIL(&cn->sendq, h, entry);

	assert(1 == num_types);

	/* SET[0]: Gather all exchange methods into set. */
	if ((error = create_xhc_headers(cn,
	    &net2_xchange_getname, net2_xchangemax, F_TYPE_XCHANGE)) != 0)
		return error;

	/* SET[1]: Gather all hash methods into set. */
	if ((error = create_xhc_headers(cn,
	    &net2_hash_getname, net2_hashmax, F_TYPE_HASH)) != 0)
		return error;

	/* SET[2]: Gather all crypt methods into set. */
	if ((error = create_xhc_headers(cn,
	    &net2_enc_getname, net2_encmax, F_TYPE_CRYPT)) != 0)
		return error;

	/* SET[3]: Gather all signature methods into set. */
	if ((error = create_xhc_headers(cn,
	    &net2_sign_getname, net2_signmax, F_TYPE_SIGN)) != 0)
		return error;

	/* SET[4]: Gather all fingerprints for localhost. */
	if ((error = create_fingerprint_headers(cn,
	    (cn->context == NULL ? NULL : &cn->context->local_signs),
	    F_TYPE_SIGNATURE)) != 0)
		return error;

	/* SET[5]: Done when remote host completes SET[4] transmission. */
	if ((error = set_get(cn, F_TYPE_SIGNATURE, &set4)) != 0)
		return error;
	set4->callback_complete = &cneg_prepare_key_exchange;

	assert(6 == num_settypes);

	return 0;
}


/* Retrieve specified set. */
static int
set_get(struct net2_conn_negotiator *cn, size_t which_set,
    struct net2_conn_negotiator_set **listptr)
{
	struct net2_conn_negotiator_set
				*list;

	if ((which_set & F_TYPEMASK) != which_set)
		return EINVAL;

	/* Remove the bit indicating this is a set. */
	which_set &= ~F_SET_ELEMENT;

	/* Grow list to include which_set. */
	list = cn->negotiated.sets;
	if (which_set >= cn->negotiated.sets_count) {
		list = net2_recalloc(list, which_set + 1, sizeof(*list));
		if (list == NULL)
			return ENOMEM;
		cn->negotiated.sets = list;

		while (cn->negotiated.sets_count <= which_set) {
			list[cn->negotiated.sets_count].flags = 0;
			list[cn->negotiated.sets_count].callback_complete =
			    NULL;
			list[cn->negotiated.sets_count].expected_size =
			    UNKNOWN_SIZE;
			net2_bitset_init(
			    &list[cn->negotiated.sets_count].data);

			cn->negotiated.sets_count++;
		}
	}

	*listptr = list + which_set;
	return 0;
}
/* Mark a received set element as received. */
static int
set_process(struct net2_conn_negotiator *cn, size_t which_set, size_t elem,
    int *oldval)
{
	struct net2_conn_negotiator_set
				*list;
	int			 error;
	size_t			 newsz;

	if ((error = set_get(cn, which_set, &list)) != 0)
		return error;

	/* Check that elem is within the size of the set. */
	if (list->expected_size != UNKNOWN_SIZE && list->expected_size <= elem)
		return EINVAL;
	/* Grow the set to include elem. */
	if (net2_bitset_size(&list->data) <= elem) {
		if (list->expected_size != UNKNOWN_SIZE)
			newsz = list->expected_size;
		else
			newsz = elem + 1;

		error = net2_bitset_resize(&list->data, newsz, 0);
		if (error != 0)
			return error;
	}

	/* Set elem as received. */
	return net2_bitset_set(&list->data, elem, 1, oldval);
}
/* Process the size of a set. */
static int
set_process_size(struct net2_conn_negotiator *cn, uint32_t which_set,
    uint32_t sz)
{
	struct net2_conn_negotiator_set
				*list;
	int			 error;

	if ((error = set_get(cn, which_set, &list)) != 0)
		return error;

	/* Check that duplicates are consistent. */
	if (list->expected_size != UNKNOWN_SIZE && list->expected_size != sz)
		return EINVAL;
	/* Check that no previously received elements exceed the new sz. */
	if (net2_bitset_size(&list->data) > sz)
		return EINVAL;
	/* Assign. */
	list->expected_size = sz;

	return 0;
}
/* Test if a set is complete. */
static int
set_done(struct net2_conn_negotiator_set *s)
{
	if (s == NULL)
		return 0;

	/*
	 * Use cached set_done check.
	 */
	if (s->flags & SET_F_ALLDONE)
		return 1;

	/*
	 * Only sets with a known size can be complete.
	 */
	if (s->expected_size == UNKNOWN_SIZE ||
	    s->expected_size != net2_bitset_size(&s->data))
		return 0;

	/*
	 * Test if all bits are set.
	 */
	if (!net2_bitset_allset(&s->data))
		return 0;

	/*
	 * Set is complete, store for future reference.
	 */
	s->flags |= SET_F_ALLDONE;
	return 1;
}
/* Test if all sets are complete. */
static int
set_all_done(const struct net2_conn_negotiator *cn)
{
	struct net2_conn_negotiator_set
				*list, *last;

	/* Check that all sets are present. */
	if (cn->negotiated.sets_count != cn->negotiated.sets_expected)
		return 0;

	/* Calculate last, for use in for loops. */
	last = cn->negotiated.sets + cn->negotiated.sets_count;

	/*
	 * First, check if all sets have their expected size
	 * (this test is very fast).
	 */
	for (list = cn->negotiated.sets; list != last; list++) {
		if (!set_done(list))
			return 0;
	}

	return 1;
}

/* Test if all data has been received. */
static int
all_done(const struct net2_conn_negotiator *cn)
{
	if (cn->negotiated.rcv_expected == UNKNOWN_SIZE ||
	    cn->negotiated.rcv_expected !=
	    net2_bitset_size(&cn->negotiated.received))
		return 0;
	return set_all_done(cn);
}


/* Append a value to the given int list. */
static int
intlist_add(int **list, size_t *sz, int val)
{
	int		*nl;
	size_t		 newsz;

	newsz = *sz + 1;
	if (newsz > SIZE_MAX / sizeof(*nl))
		return ENOMEM;
	nl = net2_recalloc(*list, newsz, sizeof(int));
	if (nl == NULL)
		return ENOMEM;
	*list = nl;

	nl[(*sz)++] = val;
	return 0;
}


/*
 * Compare hash algorithms.
 * Best algorithm compares higher.
 */
static int
hash_cmp(const void *a_ptr, const void *b_ptr)
{
	int		a, b;
	size_t		a_keylen, b_keylen;
	size_t		a_hashlen, b_hashlen;
	int		cmp;

	a = *(int*)a_ptr;
	b = *(int*)b_ptr;

	/* Choose largest key. */
	a_keylen = net2_hash_getkeylen(a);
	b_keylen = net2_hash_getkeylen(b);
	cmp = (a_keylen < b_keylen ? -1 : a_keylen > b_keylen);
	if (cmp != 0)
		return cmp;

	/* Choose largest hash. */
	a_hashlen = net2_hash_gethashlen(a);
	b_hashlen = net2_hash_gethashlen(b);
	cmp = (a_hashlen < b_hashlen ? -1 : a_hashlen > b_hashlen);
	return cmp;
}
/*
 * Compare encryption algorithms.
 * Best algorithm compares higher.
 */
static int
enc_cmp(const void *a_ptr, const void *b_ptr)
{
	int		a, b;
	size_t		a_keylen, b_keylen;
	size_t		a_ivlen, b_ivlen;
	size_t		a_overhead, b_overhead;
	int		cmp;

	a = *(int*)a_ptr;
	b = *(int*)b_ptr;

	/* Choose largest key. */
	a_keylen = net2_enc_getkeylen(a);
	b_keylen = net2_enc_getkeylen(b);
	cmp = (a_keylen < b_keylen ? -1 : a_keylen > b_keylen);
	if (cmp != 0)
		return cmp;

	/* Choose largest IV. */
	a_ivlen = net2_enc_getivlen(a);
	b_ivlen = net2_enc_getivlen(b);
	cmp = (a_ivlen < b_ivlen ? -1 : a_ivlen > b_ivlen);
	if (cmp != 0)
		return cmp;

	/* Choose smallest overhead. */
	a_overhead = net2_enc_getoverhead(a);
	b_overhead = net2_enc_getoverhead(b);
	cmp = (a_overhead > b_overhead ? -1 : a_overhead < b_overhead);
	return cmp;
}
/*
 * Compare xchange algorithms.
 */
static int
xchange_cmp(const void *a_ptr, const void *b_ptr)
{
	int		a, b;

	a = *(int*)a_ptr;
	b = *(int*)b_ptr;

	/*
	 * No useful parameters to base our sort on.
	 * Sort by ID, assuming that better algorithms will be appended
	 * to the full set.
	 */
	return (a < b ? -1 : a > b);
}
/*
 * Compare signature algorithms.
 */
static int
sign_cmp(const void *a_ptr, const void *b_ptr)
{
	int		a, b;

	a = *(int*)a_ptr;
	b = *(int*)b_ptr;

	/*
	 * No useful parameters to base our sort on.
	 * Sort by ID, assuming that better algorithms will be appended
	 * to the full set.
	 */
	return (a < b ? -1 : a > b);
}


/* Apply information in header to negotiator. */
static int
cneg_apply_header(struct net2_conn_negotiator *cn, struct header *h)
{
	int		 error;
	int		 idx;
	struct net2_sign_ctx
			*signature, **siglist;

	switch (h->flags & F_TYPEMASK) {
	case F_TYPE_PVER:
		if ((error = net2_pvlist_add(&cn->negotiated.proto,
		    &net2_proto, MIN(h->payload.version,
		    net2_proto.version))) != 0)
			return error;
		cn->negotiated.sets_expected = h->payload.num_settypes;
		cn->negotiated.rcv_expected = h->payload.num_types;

		/*
		 * Combine all flags:
		 * if any side requires a feature, both sides require
		 * it.
		 * 
		 * Features are always activated, unless:
		 * - the feature is not supported on either side,
		 * - the feature is not requested by either side.
		 */
		cn->negotiated.flags = mask_option(
		    MIN(h->payload.version, net2_proto.version),
		    h->payload.options | cn->flags);

		/* Check if we don't have too many received packets. */
		if (h->payload.num_types <
		    net2_bitset_size(&cn->negotiated.received))
			return EINVAL;

		break;

	case F_TYPE_XCHANGE:
		if ((h->flags & FT_MASK) != FT_STRING)
			return EINVAL;

		idx = net2_xchange_findname(h->payload.string);
		if (idx == -1)
			break;

		/* Store this idx. */
		if ((error = intlist_add(&cn->xchange.supported,
		    &cn->xchange.num_supported, idx)) != 0)
			return error;

		break;

	case F_TYPE_HASH:
		if ((h->flags & FT_MASK) != FT_STRING)
			return EINVAL;

		idx = net2_hash_findname(h->payload.string);
		if (idx == -1)
			break;

		/* Store this idx. */
		if ((error = intlist_add(&cn->hash.supported,
		    &cn->hash.num_supported, idx)) != 0)
			return error;

		break;

	case F_TYPE_CRYPT:
		if ((h->flags & FT_MASK) != FT_STRING)
			return EINVAL;

		idx = net2_enc_findname(h->payload.string);
		if (idx == -1)
			break;

		/* Store this idx. */
		if ((error = intlist_add(&cn->enc.supported,
		    &cn->enc.num_supported, idx)) != 0)
			return error;

		break;

	case F_TYPE_SIGN:
		if ((h->flags & FT_MASK) != FT_STRING)
			return EINVAL;

		idx = net2_sign_findname(h->payload.string);
		if (idx == -1)
			break;

		/* Store this idx. */
		if ((error = intlist_add(&cn->sign.supported,
		    &cn->sign.num_supported, idx)) != 0)
			return error;

		break;

	case F_TYPE_SIGNATURE:
		if ((h->flags & FT_MASK) != FT_BUFFER)
			return EINVAL;
		if (cn->context == NULL)
			break;

		/*
		 * If we have sufficient signatures, skip the remainder.
		 */
		if (net2_signset_size(&cn->remote_signs) == cn->context->remote_min)
			break;

		/* Find signature. */
		if ((signature = net2_signset_find(
		    &cn->context->remote_signs, h->payload.buf)) == NULL)
			break;

		/* Clone signature. */
		if ((signature = net2_signctx_clone(signature)) == NULL)
			return ENOMEM;

		/* Insert into known set. */
		if ((error = net2_signset_insert(&cn->remote_signs,
		    signature)) != 0) {
			net2_signctx_free(signature);
			return error;
		}

		break;

	case F_TYPE_SIGNATURE_ACCEPT:
		if ((h->flags & FT_MASK) != FT_BUFFER)
			return EINVAL;
		if (cn->context == NULL)
			return EINVAL;	/* TODO: put error header on the wire. */

		/* Find signature. */
		if ((signature = net2_signset_find(
		    &cn->context->local_signs, h->payload.buf)) == NULL)
			return EINVAL;	/* I didn't publish that... */

		/* Insert into to-sign set. */
		if (cn->signature_list.size <= h->seq) {
			/* Prevent overflow. */
			if ((size_t)h->seq + 1U > SIZE_MAX /
			    sizeof(*cn->signature_list.signatures))
				return ENOMEM;

			/* Resize the signature list. */
			if ((siglist = net2_recalloc(
			    cn->signature_list.signatures,
			    (size_t)h->seq + 1U,
			    sizeof(*cn->signature_list.signatures))) == NULL)
				return ENOMEM;
			cn->signature_list.signatures = siglist;
			/* Initialize new members to NULL. */
			while (cn->signature_list.size <= h->seq)
				siglist[cn->signature_list.size++] = NULL;
		}

		/* Clone signature. */
		if ((cn->signature_list.signatures[h->seq] =
		    net2_signctx_clone(signature)) == NULL)
			return ENOMEM;

		break;

	default:
		/*
		 * Unrecognized headers are allowed and silently ignored.
		 */
		break;
	}

	return 0;
}

/*
 * Calculate the conclusion of the pristine stage in negotiation.
 */
static int
cneg_conclude_pristine(struct net2_conn_negotiator *cn)
{
	int		error = 0;
	int		tx_xchange, tx_hash, tx_enc;

	/*
	 * Connection is not sufficiently ready to transmit the next batch.
	 * Both ends must have received the protocol version, so the next
	 * stage will be able to take advantage of the negotiated protocol.
	 */
	if (!cn->pver_acknowledged)
		return 0;

	/*
	 * Time to choose which protocols to use and
	 * what is to be negotiated.
	 *
	 * First, sort the protocols.
	 */
	qsort(cn->hash.supported, cn->hash.num_supported,
	    sizeof(int), hash_cmp);
	qsort(cn->enc.supported, cn->enc.num_supported,
	    sizeof(int), enc_cmp);
	qsort(cn->xchange.supported, cn->xchange.num_supported,
	    sizeof(int), xchange_cmp);
	qsort(cn->sign.supported, cn->sign.num_supported,
	    sizeof(int), sign_cmp);

	/* We require at least 1 supported hash, enc and xchange. */
	if (cn->hash.num_supported == 0 ||
	    cn->enc.num_supported == 0 ||
	    cn->xchange.num_supported == 0) {
		error = ENODEV;
		goto fail;
	}

	/*
	 * Always select the best key exchange mechanism.
	 */
	tx_xchange = cn->xchange.supported[cn->xchange.num_supported - 1];
	cn->stage2.xchanges[NET2_CNEG_S2_ENC | NET2_CNEG_S2_LOCAL].xchange_alg =
	    tx_xchange;
	cn->stage2.xchanges[NET2_CNEG_S2_HASH | NET2_CNEG_S2_LOCAL].xchange_alg =
	    tx_xchange;

	/* Select encryption algorithm. */
	if (!(cn->flags & NET2_CNEG_REQUIRE_ENCRYPTION)) {
		/*
		 * Select the weakest encryption algorithm.
		 * This usually is enc[0]: nil.
		 *
		 * If nil is not supported, the weakest algorithm will be
		 * selected.
		 */
		cn->stage2.xchanges[NET2_CNEG_S2_ENC | NET2_CNEG_S2_LOCAL].alg =
		    tx_enc = cn->enc.supported[0];
	} else {
		/*
		 * Select the best encryption algorithm.
		 */
		cn->stage2.xchanges[NET2_CNEG_S2_ENC | NET2_CNEG_S2_LOCAL].alg =
		    tx_enc = cn->enc.supported[cn->enc.num_supported - 1];
	}

	/* Select hashing algorithm. */
	if (!(cn->flags & NET2_CNEG_REQUIRE_SIGNING)) {
		/*
		 * Select the weakest signing algorithm.
		 * This usually is hash[0]: nil.
		 *
		 * If nil is not supported, the weakest algorithm will be
		 * selected.
		 */
		cn->stage2.xchanges[NET2_CNEG_S2_HASH | NET2_CNEG_S2_LOCAL].alg =
		    tx_hash = cn->enc.supported[0];
	} else {
		/*
		 * Select the best signing algorithm.
		 */
		cn->stage2.xchanges[NET2_CNEG_S2_HASH | NET2_CNEG_S2_LOCAL].alg =
		    tx_hash = cn->hash.supported[cn->hash.num_supported - 1];
	}

	/*
	 * If we require signing, ensure we don't select
	 * the nil algorithm.
	 */
	if (tx_hash == 0 &&
	    (cn->flags & NET2_CNEG_REQUIRE_SIGNING)) {
		error = ENODEV;
		goto fail;
	}
	/*
	 * If we require encryption, ensure we don't select
	 * the nil algorithm.
	 */
	if (tx_enc == 0 &&
	    (cn->flags & NET2_CNEG_REQUIRE_ENCRYPTION)) {
		error = ENODEV;
		goto fail;
	}

	/* Load required key lengths. */
	cn->stage2.xchanges[NET2_CNEG_S2_HASH | NET2_CNEG_S2_LOCAL].keysize =
	    net2_hash_getkeylen(tx_hash);
	cn->stage2.xchanges[NET2_CNEG_S2_ENC | NET2_CNEG_S2_LOCAL].keysize =
	    net2_enc_getkeylen(tx_enc);

	/*
	 * Ask context for exchange implementation.
	 * If the context returns NULL, make one ourselves.
	 */
	if (cn->context != NULL) {
		error = stage2_init_exchange(cn->context, &cn->stage2.xchanges[
		    NET2_CNEG_S2_HASH | NET2_CNEG_S2_LOCAL]);
		if (error)
			return error;

		error = stage2_init_exchange(cn->context, &cn->stage2.xchanges[
		    NET2_CNEG_S2_ENC | NET2_CNEG_S2_LOCAL]);
		if (error)
			return error;
	}

	/* Go to next stage. */
	cn->stage = NET2_CNEG_STAGE_KEY_EXCHANGE;
	cneg_ready_to_send(cn);

fail:
	return error;
}

/*
 * Decide which signatures are required to sign the key exchange.
 */
static int
cneg_prepare_key_exchange(struct net2_conn_negotiator *cn)
{
	int			 error;

	if ((error = create_fingerprint_headers(cn, &cn->remote_signs,
	    F_TYPE_SIGNATURE_ACCEPT)) != 0)
		return error;
	cneg_ready_to_send(cn);
	return 0;
}


/* Initialize keyex for outbound data. */
static int
cneg_keyex_ctx_init_out(struct cneg_keyex_ctx *ctx, struct net2_encdec_ctx *c,
    struct net2_buffer *payload,
    int hash_alg, struct net2_sign_ctx **signatures, size_t signatures_size)
{
	struct net2_signature	 sigdata;
	struct net2_buffer	*tmp;
	int			 error;
	size_t			 i;

	ctx->flags = CNEG_KEYEX_OUT;
	ctx->num_signatures = signatures_size;
	ctx->out.signatures = NULL;

	/* Allocate signature carvers. */
	if (signatures_size > 0) {
		if ((ctx->out.signatures = net2_calloc(signatures_size,
		    sizeof(*ctx->out.signatures))) == NULL)
			goto fail_0;
	}

	/* Prepare payload carver. */
	if ((error = net2_carver_init(&ctx->out.payload, NET2_CARVER_16BIT,
	    payload)) != 0)
		goto fail_1;

	/* Calculate each signature. */
	for (i = 0; i < signatures_size; i++) {
		if ((error = net2_signature_create(&sigdata, payload, hash_alg,
		    signatures[i])) != 0)
			goto fail_3;

		if ((tmp = net2_buffer_new()) == NULL) {
			error = ENOMEM;
			net2_signature_deinit(&sigdata);
			goto fail_3;
		}
		if ((error = net2_cp_encode(c, &cp_net2_signature, tmp,
		    &sigdata, NULL)) != 0) {
			net2_buffer_free(tmp);
			net2_signature_deinit(&sigdata);
			goto fail_3;
		}

		if ((error = net2_carver_init(&ctx->out.signatures[i],
		    NET2_CARVER_16BIT, tmp)) != 0) {
			net2_buffer_free(tmp);
			net2_signature_deinit(&sigdata);
			goto fail_3;
		}

		net2_buffer_free(tmp);
		net2_signature_deinit(&sigdata);
	}

	return 0;


fail_3:
	while (i > 0)
		net2_carver_deinit(&ctx->out.signatures[--i]);
fail_2:
	net2_carver_deinit(&ctx->out.payload);
fail_1:
	net2_free(ctx->out.signatures);
fail_0:
	assert(error != 0);
	return error;
}
/* Initialize keyex for inbound data. */
static int
cneg_keyex_ctx_init_in(struct cneg_keyex_ctx *ctx, size_t signatures_size)
{
	int			 error;
	size_t			 i;

	ctx->flags = CNEG_KEYEX_IN;
	ctx->num_signatures = signatures_size;
	ctx->in.signatures = NULL;

	/* Allocate signature combiners. */
	if (signatures_size > 0) {
		if ((ctx->in.signatures = net2_calloc(signatures_size,
		    sizeof(*ctx->in.signatures))) == NULL)
			goto fail_0;
	}

	/* Prepare payload combiner. */
	if ((error = net2_combiner_init(&ctx->in.payload,
	    NET2_CARVER_16BIT)) != 0)
		goto fail_1;

	/* Initialize receivers for signatures. */
	for (i = 0; i < signatures_size; i++) {
		if ((error = net2_combiner_init(&ctx->in.signatures[i],
		    NET2_CARVER_16BIT)) != 0)
			goto fail_3;
	}

	return 0;


fail_3:
	while (i > 0)
		net2_combiner_deinit(&ctx->in.signatures[--i]);
fail_2:
	net2_combiner_deinit(&ctx->in.payload);
fail_1:
	net2_free(ctx->in.signatures);
fail_0:
	assert(error != 0);
	return error;
}
/* Release resources of keyex. */
static void
cneg_keyex_deinit(struct cneg_keyex_ctx *ctx)
{
	size_t			 i;

	switch (ctx->flags & (CNEG_KEYEX_IN | CNEG_KEYEX_OUT)) {
	default:
		break;
	case CNEG_KEYEX_IN:
		net2_combiner_deinit(&ctx->in.payload);
		if (ctx->in.signatures != NULL) {
			for (i = 0; i < ctx->num_signatures; i++)
				net2_combiner_deinit(&ctx->in.signatures[i]);
			net2_free(ctx->in.signatures);
		}
		break;
	case CNEG_KEYEX_OUT:
		net2_carver_deinit(&ctx->out.payload);
		if (ctx->out.signatures != NULL) {
			for (i = 0; i < ctx->num_signatures; i++)
				net2_carver_deinit(&ctx->out.signatures[i]);
			net2_free(ctx->out.signatures);
		}
		break;
	}
	ctx->flags = 0;
}
/* Test if keyex is done. */
static int
cneg_keyex_is_done(struct cneg_keyex_ctx *ctx)
{
	size_t			 i;

	/* Already tested. */
	if (ctx->flags & CNEG_KEYEX_COMPLETE)
		return 1;

	switch (ctx->flags & (CNEG_KEYEX_IN | CNEG_KEYEX_OUT)) {
	default:
		return 0;
	case CNEG_KEYEX_IN:
		if (!net2_combiner_is_done(&ctx->in.payload))
			return 0;
		for (i = 0; i < ctx->num_signatures; i++) {
			if (!net2_combiner_is_done(&ctx->in.signatures[i]))
				return 0;
		}
		break;
	case CNEG_KEYEX_OUT:
		if (!net2_carver_is_done(&ctx->out.payload))
			return 0;
		for (i = 0; i < ctx->num_signatures; i++) {
			if (!net2_carver_is_done(&ctx->out.signatures[i]))
				return 0;
		}
		break;
	}

	ctx->flags |= CNEG_KEYEX_COMPLETE;
	return 1;
}

/* Encode payload of keyex. */
static int
cneg_keyex_ctx_encode_payload(struct net2_buffer **outptr,
    struct cneg_keyex_ctx *ctx, struct net2_encdec_ctx *c,
    struct net2_evbase *evbase, struct net2_cw_tx *tx, int slot, int msg_id,
    size_t maxsz)
{
	struct net2_buffer	*header, *carver_buf;
	struct exchange_msg	 msg;
	int			 error;
	int			 fatal; /* Set if errors are unrecoverable. */

	/* Argument check. */
	if (outptr == NULL || *outptr != NULL || ctx == NULL || c == NULL ||
	    evbase == NULL || tx == NULL)
		return EINVAL;
	if (slot == SLOT_FIN)
		return EINVAL;
	if (msg_id & XMSG_SIGNATURE)
		return EINVAL;
	fatal = 0;

	/* Can only encode output keyex. */
	if (!(ctx->flags & CNEG_KEYEX_OUT))
		return 0;

	/* Encode header. */
	if ((error = mk_exchange_msg_buf(&msg, slot, msg_id)) != 0)
		goto fail_0;
	if ((header = net2_buffer_new()) == NULL) {
		error = ENOMEM;
		goto fail_1;
	}
	if ((error = net2_cp_encode(c, &cp_exchange_msg, header, &msg,
	    NULL)) != 0)
		goto fail_2;

	/* Insufficient space. */
	if (net2_buffer_length(header) >= maxsz) {
		error = 0;
		goto fail_2;
	}

	/* Carver encoding invocation. */
	if ((carver_buf = net2_buffer_new()) == NULL) {
		error = ENOMEM;
		goto fail_2;
	}
	if (net2_carver_get_transmit(&ctx->out.payload, c, evbase, carver_buf,
	    tx, maxsz - net2_buffer_length(header)) != 0) {
		error = 0;
		goto fail_3;
	}

	/*
	 * tx now contains completion events, so this message may not succeed
	 * if below fails.
	 */
	fatal = 1;

	/* Combine header and carver payload. */
	if ((net2_buffer_append(header, carver_buf)) != 0)
		goto fail_3;

	/* Done. */
	*outptr = header;
	header = NULL;
	error = 0;

fail_3:
	net2_buffer_free(carver_buf);
fail_2:
	if (header != NULL)
		net2_buffer_free(header);
fail_1:
	net2_cp_destroy(c, &cp_exchange_msg, &msg, NULL);
fail_0:
	assert(error == 0 || *outptr == NULL);
	if (*outptr != NULL)
		assert(net2_buffer_length(*outptr) <= maxsz);
	return (fatal ? error : 0);
}

/* Encode payload of keyex. */
static int
cneg_keyex_ctx_encode_signature(struct net2_buffer **outptr,
    struct cneg_keyex_ctx *ctx, struct net2_encdec_ctx *c,
    struct net2_evbase *evbase, struct net2_cw_tx *tx, int slot, int msg_id,
    size_t sig_idx, size_t maxsz)
{
	struct net2_buffer	*header, *carver_buf;
	struct exchange_msg	 msg;
	int			 error;
	int			 fatal; /* Set if errors are unrecoverable. */

	/* Argument check. */
	if (outptr == NULL || *outptr != NULL || ctx == NULL || c == NULL ||
	    evbase == NULL || tx == NULL)
		return EINVAL;
	if (sig_idx >= ctx->num_signatures)
		return EINVAL;
	if (slot == SLOT_FIN)
		return EINVAL;
	if (msg_id & XMSG_SIGNATURE)
		return EINVAL;
	fatal = 0;

	/* Can only encode output keyex. */
	if (!(ctx->flags & CNEG_KEYEX_OUT))
		return 0;

	/* Encode header. */
	if ((error = mk_exchange_msg_signature(&msg, slot, msg_id,
	    sig_idx)) != 0)
		goto fail_0;
	if ((header = net2_buffer_new()) == NULL) {
		error = ENOMEM;
		goto fail_1;
	}
	if ((error = net2_cp_encode(c, &cp_exchange_msg, header, &msg,
	    NULL)) != 0)
		goto fail_2;

	/* Insufficient space. */
	if (net2_buffer_length(header) >= maxsz) {
		error = 0;
		goto fail_2;
	}

	/* Carver encoding invocation. */
	if ((carver_buf = net2_buffer_new()) == NULL) {
		error = ENOMEM;
		goto fail_2;
	}
	if (net2_carver_get_transmit(&ctx->out.signatures[sig_idx], c, evbase,
	    carver_buf, tx, maxsz - net2_buffer_length(header)) != 0) {
		error = 0;
		goto fail_3;
	}

	/*
	 * tx now contains completion events, so this message may not succeed
	 * if below fails.
	 */
	fatal = 1;

	/* Combine header and carver payload. */
	if ((net2_buffer_append(header, carver_buf)) != 0)
		goto fail_3;

	/* Done. */
	*outptr = header;
	header = NULL;
	error = 0;

fail_3:
	net2_buffer_free(carver_buf);
fail_2:
	if (header != NULL)
		net2_buffer_free(header);
fail_1:
	net2_cp_destroy(c, &cp_exchange_msg, &msg, NULL);
fail_0:
	assert(error == 0 || *outptr == NULL);
	if (*outptr != NULL)
		assert(net2_buffer_length(*outptr) <= maxsz);
	return (fatal ? error : 0);
}

/* Encode keyex. */
static int
cneg_keyex_ctx_encode(struct net2_buffer **outptr,
    struct cneg_keyex_ctx *ctx, struct net2_encdec_ctx *c,
    struct net2_evbase *evbase, struct net2_cw_tx *tx,
    int slot, int msg_id, size_t maxsz)
{
	struct net2_buffer	*out, *append;
	size_t			 i;
	int			 error;

	*outptr = NULL;
	if ((out = net2_buffer_new()) == NULL)
		return 0;	/* Non-fatal. */

	/* Encode as much of payload as possible (repeatedly). */
	while (net2_buffer_length(out) < maxsz) {
		append = NULL;
		error = cneg_keyex_ctx_encode_payload(&append, ctx, c, evbase,
		    tx, slot, msg_id, maxsz - net2_buffer_length(out));
		if (error != 0)
			goto fail;
		if (append == NULL)
			break;	/* GUARD */

		assert(!net2_buffer_empty(append));
		if (net2_buffer_append(out, append)) {
			net2_buffer_free(append);
			error = ENOMEM; /* Fatal: tx is modified. */
			goto fail;
		}
		net2_buffer_free(append);
	}

	/* Encode as many signatures as possible. */
	for (i = 0; i < ctx->num_signatures; i++) {
		while (net2_buffer_length(out) < maxsz) {
			append = NULL;
			error = cneg_keyex_ctx_encode_signature(&append, ctx,
			    c, evbase, tx, slot, msg_id, i,
			    maxsz - net2_buffer_length(out));
			if (error != 0)
				goto fail;
			if (append == NULL)
				break;	/* GUARD */

			assert(!net2_buffer_empty(append));
			if (net2_buffer_append(out, append)) {
				net2_buffer_free(append);
				error = ENOMEM; /* Fatal: tx is modified. */
				goto fail;
			}
			net2_buffer_free(append);
		}
	}

	/* Done. */
	assert(net2_buffer_length(out) <= maxsz);
	if (net2_buffer_empty(out)) {
		net2_buffer_free(out);
		return 0;
	}
	*outptr = out;
	return 0;


fail:
	net2_buffer_free(out);
	assert(error != 0);
	return error;
}


/* Post-allocation exchange initialization. */
static int
net2_cneg_exchange_init(struct net2_conn_negotiator *cn, struct net2_cneg_exchange *e)
{
	int		 error;

	/* Mini init: ensure destroying the buffer is safe. */
	cneg_keyex_ctx_init(&e->initbuf);
	cneg_keyex_ctx_init(&e->import);
	cneg_keyex_ctx_init(&e->export);

	e->cneg = cn;
	e->state = 0;
	e->xchange = NULL;
	e->promise = NULL;

	if ((error = cneg_keyex_ctx_init_in(&e->import,
	    cn->signature_list.size)) != 0)
		goto fail_1;

	return 0;

fail_1:
	cneg_keyex_deinit(&e->export);
	cneg_keyex_deinit(&e->import);
	cneg_keyex_deinit(&e->initbuf);
fail_0:
	assert(error != 0);
	return error;
}

/* Exchange destruction. */
static void
net2_cneg_exchange_deinit(struct net2_cneg_exchange *e)
{
	struct event		*ev;

	if (e->xchange != NULL)
		net2_xchangectx_free(e->xchange);
	if (e->promise != NULL) {
		net2_promise_set_event(e->promise, NET2_PROM_ON_FINISH, NULL,
		    &ev);
		if (ev != NULL)
			event_free(ev);

		net2_promise_cancel(e->promise);
		net2_promise_release(e->promise);
	}

	cneg_keyex_deinit(&e->initbuf);
	cneg_keyex_deinit(&e->export);
	cneg_keyex_deinit(&e->import);
}

/* Retrieve transmission for given exchange. */
static int
net2_cneg_exchange_get_transmit(struct net2_buffer **outptr,
    struct net2_cneg_exchange *e, struct net2_encdec_ctx *ctx,
    struct net2_evbase *evbase, struct net2_cw_tx *tx, int slot, size_t maxsz)
{
	struct net2_buffer	*out, *append;
	int			 error;

	*outptr = NULL;

	if ((out = net2_buffer_new()) == NULL)
		return 0; /* Not fatal here. */

	/* Encode initbuf. */
	append = NULL;
	error = cneg_keyex_ctx_encode(&append, &e->initbuf, ctx, evbase, tx,
	    slot, XMSG_INITBUF, maxsz - net2_buffer_length(out));
	if (append != NULL) {
		if (net2_buffer_append(out, append)) {
			error = ENOMEM;
			goto fail;
		}
		net2_buffer_free(append);
	}

	/* Encode response buffer. */
	append = NULL;
	error = cneg_keyex_ctx_encode(&append, &e->export, ctx, evbase, tx,
	    slot, XMSG_RESPONSE, maxsz - net2_buffer_length(out));
	if (append != NULL) {
		if (net2_buffer_append(out, append)) {
			error = ENOMEM;
			goto fail;
		}
		net2_buffer_free(append);
	}

	/* Apply result. */
	if (net2_buffer_empty(out))
		net2_buffer_free(out);
	else
		*outptr = out;
	return 0;

fail:
	net2_buffer_free(out);
	return error;
}

/* Initialize local exchange for stage 2. */
static int
stage2_init_exchange(struct net2_ctx *ctx,
    struct net2_cneg_exchange *e)
{
	struct event		*ev;
	struct net2_conn_negotiator
				*cn;
	struct net2_evbase	*evbase;
	struct net2_buffer	*empty;
	int			 error;

	cn = e->cneg;
	evbase = net2_acceptor_socket_evbase(&CNEG_CONN(cn)->n2c_socket);

	/* Do not use exchange for 0-length keys. */
	if (e->keysize == 0) {
		e->state |= S2_CARVER_INITDONE;
		return 0;
	}

	/* Create promise callback. */
	if (evbase == NULL)
		goto fail_promise;
	if ((ev = event_new(evbase->evbase, -1, 0,
	    &stage2_init_xchange_promise_cb, e)) == NULL)
		goto fail_promise;

	/* Require context with factory for promise. */
	if (ctx == NULL || ctx->xchange_factory == NULL) {
		event_free(ev);
		goto fail_promise;
	}

	/* Acquire promise from context. */
	e->promise = ctx->xchange_factory(e->xchange_alg, e->keysize,
	    ctx->xchange_factory_arg);
	if (e->promise == NULL) {
		event_free(ev);
		goto fail_promise;
	}

	/* Add event to promise. */
	if (net2_promise_set_event(e->promise, NET2_PROM_ON_FINISH,
	    ev, NULL)) {
		event_free(ev);
		net2_promise_cancel(e->promise);
		net2_promise_release(e->promise);
		e->promise = NULL;
		goto fail_promise;
	}

	return 0;


fail_promise:
	/*
	 * If the promise is not created, we'll have to make it ourselves.
	 */
	return stage2_init_exchange_directly(e);
}

/* Create exchange context without help from context. */
static int
stage2_init_exchange_directly(struct net2_cneg_exchange *e)
{
	struct net2_buffer	*initbuf;
	int			 error;

	/* Initialize initbuf. */
	if ((initbuf = net2_buffer_new()) == NULL)
		return ENOMEM;

	/* Initialize xchange context. */
	if ((e->xchange = net2_xchangectx_prepare(e->xchange_alg, e->keysize,
	    NET2_XCHANGE_F_INITIATOR, initbuf)) == NULL) {
		net2_buffer_free(initbuf);
		return ENOMEM;
	}

	error = stage2_init_xchange_post(e, initbuf);
	net2_buffer_free(initbuf);
	return error;
}

/*
 * Post exchange initialization
 * (requires initbuf and xchange to have been set).
 */
static int
stage2_init_xchange_post(struct net2_cneg_exchange *e,
    struct net2_buffer *initbuf)
{
	struct net2_buffer	*export = NULL;
	int			 error;
	int			 hash_alg;
	size_t			 idx;
	struct net2_encdec_ctx	 ctx;
	struct net2_conn_negotiator
				*cn;
	int			 alg;

	/* Validate that ranges are empty/uninitialized. */
	if (e->state & S2_CARVER_INITDONE)
		return EINVAL;

	/* Initialize special variables. */
	cn = e->cneg;
	if ((error = net2_encdec_ctx_newaccsocket(&ctx, &CNEG_CONN(cn)->n2c_socket)) != 0)
		goto fail_0;

	/* Find the hash algorithm with the largest hash size, that is non-zero. */
	if (cn->signature_list.size > 0) {
		hash_alg = -1;
		for (idx = cn->hash.num_supported; idx > 0; idx--) {
			alg = cn->hash.supported[idx - 1];
			assert(net2_hash_getname(alg) != NULL);
			if (net2_hash_gethashlen(alg) != 0 &&
			    net2_hash_getkeylen(alg) == 0) {
				hash_alg = alg;
				break;
			}
		}
		if (hash_alg == -1) {
			/* No suitable hash algorithm. */
			error = EINVAL;
			goto fail_1;
		}
	} else {
		hash_alg = -1;
		/* No signatures, so hash_alg will not be used. */
	}

	if (e->keysize == 0)
		export = net2_buffer_new();
	else
		export = net2_xchangectx_export(e->xchange);
	if (export == NULL) {
		error = ENOMEM;
		goto fail_1;
	}

	if ((error = cneg_keyex_ctx_init_out(&e->initbuf, &ctx, initbuf,
	    hash_alg, cn->signature_list.signatures,
	    cn->signature_list.size)) != 0)
		goto fail_2;
	if ((error = cneg_keyex_ctx_init_out(&e->export, &ctx, export,
	    hash_alg, cn->signature_list.signatures,
	    cn->signature_list.size)) != 0)
		goto fail_3;
	e->state |= S2_CARVER_INITDONE;

	/* Ensure the new unsent ranges will be processed. */
	cneg_ready_to_send(e->cneg);

	net2_buffer_free(export);
	net2_encdec_ctx_deinit(&ctx);

	return 0;


fail_4:
	e->state &= ~S2_CARVER_INITDONE;
	cneg_keyex_deinit(&e->export);
fail_3:
	cneg_keyex_deinit(&e->initbuf);
fail_2:
	net2_buffer_free(export);
fail_1:
	net2_encdec_ctx_deinit(&ctx);
fail_0:
	assert(error != 0);
	assert(!(e->state & S2_CARVER_INITDONE));
	return error;
}

/* Promise completion callback. */
static void
stage2_init_xchange_promise_cb(evutil_socket_t fd, short what, void *e_ptr)
{
	struct net2_cneg_exchange	*e = e_ptr;
	uint32_t			 prom_error;
	struct net2_ctx_xchange_factory_result
					*prom_result;
	int				 prom_fin;
	int				 error;
	struct event			*ev;

	/* Remove ourselves. */
	net2_promise_set_event(e->promise, NET2_PROM_ON_FINISH, NULL, &ev);
	if (ev != NULL)
		event_free(ev);

	prom_fin = net2_promise_get_result(e->promise, (void**)&prom_result,
	    &prom_error);

	/* We are in an on-completion hander... */
	assert(prom_fin != NET2_PROM_FIN_UNFINISHED);

	/* Read promise result; recover from error. */
	switch (prom_fin) {
	case NET2_PROM_FIN_OK:
		/* Claim ownership of data. */
		error = 0;
		e->xchange = prom_result->ctx;
		prom_result->ctx = NULL;	/* Claim ownership. */

		/* Perform post initialization now. */
		error = stage2_init_xchange_post(e, prom_result->initbuf);

		net2_promise_release(e->promise);
		e->promise = NULL;
		break;

	case NET2_PROM_FIN_CANCEL:
		/* Hmmm... shouldn't have fired. */
		return;	/* TODO: consider abort() instead? */

	case NET2_PROM_FIN_ERROR:
		/* If the promise had an error, we'll run into the same. */
		error = prom_error;
		break;

	case NET2_PROM_FIN_FAIL:	/* Recover from non-invocation. */
	default:			/* Recover from unknown result code. */
		net2_promise_release(e->promise);
		e->promise = NULL;
		error = stage2_init_exchange_directly(e);
	}

	/*
	 * Either:
	 * - error == 0 and we have e->xchange and e->initbuf set.
	 * - error != 0 and we have to fail.
	 */
	if (error != 0) {
		assert(0);	/* TODO: make conn_neg send an error and die. */
		return;
	}

	/*
	 * Validate assumptions.
	 */
	assert(e->state & S2_CARVER_INITDONE);

	/*
	 * Mark negotiator as ready to send
	 * since we just received data from our promise.
	 */
	cneg_ready_to_send(e->cneg);
}


/*
 * Handle stage 1 decoding and application.
 */
static int
cneg_stage1_accept(struct net2_conn_negotiator *cn, struct packet_header *ph,
    struct net2_buffer *buf)
{
	struct header		 h;
	int			 skip;
	int			 error;
	size_t			 i;
	struct net2_conn_negotiator_set
				*nset;

	for (;;) {
		/* Decode header. */
		if ((error = decode_header(&h, buf)) != 0)
			goto fail;
		/* GUARD: Stop after decoding the last header. */
		if (h.flags == F_LAST_HEADER) {
			deinit_header(&net2_encdec_proto0, &h);
			break;
		}

		skip = 0;
		if (h.flags == F_POETRY)
			goto skip;

		if (h.flags & F_SET_EMPTY) {
			if ((error = set_process_size(cn, h.flags & F_TYPEMASK,
			    0)) != 0)
				goto fail_wh;
			if ((error = set_get(cn, h.flags & F_TYPEMASK,
			    &nset)) != 0)
				goto fail_wh;

			/* Invoke callback for empty set. */
			if (nset->callback_complete != NULL) {
				error = (*nset->callback_complete)(cn);
				nset->callback_complete = NULL;
				if (error)
					goto fail_wh;
			}
			skip = 1;
		} else if (h.flags & F_SET_ELEMENT) {
			if (h.flags & F_SET_LASTELEM) {
				if ((error = set_process_size(cn,
				    h.flags & F_TYPEMASK,
				    (size_t)h.seq + 1)) != 0)
					goto fail_wh;
			}
			if ((error = set_process(cn, h.flags & F_TYPEMASK,
			    h.seq, &skip)) != 0)
				goto fail_wh;
		} else {
			i = h.flags & F_TYPEMASK;
			/* Don't accept anything over what was published. */
			if (cn->negotiated.rcv_expected != UNKNOWN_SIZE &&
			    i >= cn->negotiated.rcv_expected) {
				error = EINVAL;
				goto fail_wh;
			}

			if (i >= net2_bitset_size(&cn->negotiated.received)) {
				if ((error = net2_bitset_resize(
				    &cn->negotiated.received, i + 1, 0)) != 0)
					goto fail_wh;
			}

			if ((error = net2_bitset_set(&cn->negotiated.received,
			    i, 1, &skip)) != 0)
				goto fail_wh;
		}

		if (!skip) {
			if ((error = cneg_apply_header(cn, &h)) != 0)
				goto fail_wh;

			/* Invoke set completion callback. */
			if (h.flags & F_SET_ELEMENT) {
				if ((error = set_get(cn, h.flags & F_TYPEMASK,
				    &nset)) != 0)
					goto fail_wh;

				if (nset->callback_complete != NULL &&
				    set_done(nset)) {
					error = (*nset->callback_complete)(cn);
					nset->callback_complete = NULL;
					if (error)
						goto fail_wh;
				}
			}
		}


skip:
		/* Free header. */
		deinit_header(&net2_encdec_proto0, &h);
	}

	return 0;

fail_wh:
	deinit_header(&net2_encdec_proto0, &h);
fail:
	assert(error != 0);
	return error;
}

/*
 * Generate stage 1 buffer contents.
 */
static int
cneg_stage1_get_transmit(struct net2_conn_negotiator *cn,
    struct packet_header* ph,
    struct net2_buffer **bufptr, struct net2_cw_tx *tx, size_t maxlen,
    int stealth, int want_payload)
{
	struct encoded_header	*eh, *eh_next;
	struct net2_buffer	*buf;
	int			 error;
	TAILQ_HEAD(, encoded_header)
				 transit;
	struct net2_evbase	*evbase;
	size_t			 old_sz;

	/* If nothing to send, return without data. */
	if (TAILQ_EMPTY(&cn->sendq))
		return 0;

	/* Initialize locals. */
	evbase = net2_acceptor_socket_evbase(&CNEG_CONN(cn)->n2c_socket);
	*bufptr = NULL;
	TAILQ_INIT(&transit);

	/* Create buffer. */
	if ((buf = net2_buffer_new()) == NULL)
		return ENOMEM;

	for (eh = TAILQ_FIRST(&cn->sendq); eh != NULL; eh = eh_next) {
		eh_next = TAILQ_NEXT(eh, entry);	/* Next header. */

		/* Cache encoded header. */
		if (eh->buf == NULL) {
			if ((eh->buf = net2_buffer_new()) == NULL)
				break;

			error = encode_header(eh->buf, &eh->data.header);
			if (error != 0) {
				net2_buffer_free(eh->buf);
				if (error == ENOMEM)
					break;
				else
					goto fail;
			}
		}

		/*
		 * Store old size, so we can undo the addition of this
		 * buffer on failure.
		 */
		old_sz = net2_buffer_length(buf);

		/* Test if the header will fit in available space. */
		if (old_sz + net2_buffer_length(eh->buf) + FINI_LEN > maxlen)
			continue;

		/* Append this eh. */
		if (net2_buffer_append(buf, eh->buf))
			break;

		/* Register callback. */
		if ((error = net2_connwindow_txcb_register(tx, evbase,
		    NULL, &ack_cb, &nack_cb, &destroy_cb, eh, cn)) != 0) {
			net2_buffer_truncate(buf, old_sz);	/* Undo. */
			break;
		}

		/* Move to transit queue. */
		TAILQ_REMOVE(&cn->sendq, eh, entry);
		TAILQ_INSERT_TAIL(&transit, eh, entry);
	}

	/*
	 * Add poetry.
	 *
	 * We don't add poetry while under stealth.
	 * Also, we don't add poetry once we allow payload to happen.
	 */
	if (net2_cneg_allow_payload(cn, ph->seq))
		assert(!stealth);
	if (!stealth && !net2_cneg_allow_payload(cn, ph->seq) &&
	    net2_buffer_length(buf) + FINI_LEN <= maxlen) {
		/*
		 * Only add poetry on:
		 * - packets with negotiation data, or
		 * - keepalive packets
		 */
		if (!(want_payload && TAILQ_EMPTY(&transit))) {
			/* Ignore failure: this is optional and ignored. */
			net2_add_poetry(buf, maxlen - FINI_LEN -
			    net2_buffer_length(buf));
		}
	}

	if (TAILQ_EMPTY(&transit)) {
		net2_buffer_free(buf);
		return 0;
	}

	/* Append closing tag. */
	if ((error = encode_header(buf, &header_fini)) != 0)
		goto fail;

	/* Commit transit queue. */
	while ((eh = TAILQ_FIRST(&transit)) != NULL) {
		TAILQ_REMOVE(&transit, eh, entry);
		TAILQ_INSERT_TAIL(&cn->waitq, eh, entry);
	}
	ph->flags |= PH_HANDSHAKE;

	*bufptr = buf;
	return 0;

fail:
	net2_buffer_free(buf);
	/* Undo putting transit packets on queue. */
	while ((eh = TAILQ_FIRST(&transit)) != NULL)
		TAILQ_INSERT_TAIL(&cn->sendq, eh, entry);
	return error;
}

/*
 * Handle stage 2 decoding and application.
 */
static int
cneg_stage2_accept(struct net2_conn_negotiator *cn, struct packet_header *ph,
    struct net2_buffer *buf)
{
	int			 error;
	struct exchange_msg	 msg;
	struct net2_encdec_ctx	 ctx;
	struct net2_cneg_exchange
				*exchange;
	int			 local;
	int			 result_alg, xchange_alg;
	size_t			 keysize;
	int			 signature_idx;

	if ((error = net2_encdec_ctx_newaccsocket(&ctx, &CNEG_CONN(cn)->n2c_socket)) != 0)
		return error;

	for (;;) {
		if ((error = net2_cp_init(&ctx, &cp_exchange_msg, &msg, NULL)) != 0)
			goto out;
		if ((error = net2_cp_decode(&ctx, &cp_exchange_msg, &msg, buf, NULL)) != 0)
			goto out_with_msg;
		if (msg.slot == SLOT_FIN)
			break;		/* GUARD */

		local = 0;	/* Not local exchange. */
		switch (msg.slot) {
		default:
			/* Unrecognized slot. */
			error = EINVAL;
			goto out_with_msg;
		case NET2_CNEG_S2_HASH | NET2_CNEG_S2_LOCAL:
		case NET2_CNEG_S2_ENC | NET2_CNEG_S2_LOCAL:
			local = 1;
			/* FALLTHROUGH */
		case NET2_CNEG_S2_HASH | NET2_CNEG_S2_REMOTE:
		case NET2_CNEG_S2_ENC | NET2_CNEG_S2_REMOTE:
			exchange = &cn->stage2.xchanges[msg.slot];
			break;

			switch (msg.msg_id) {
			default:
				error = EINVAL;
				goto out_with_msg;

			case XMSG_SETUP:
				/*
				 * Setup can only be called for remotely
				 * initialized exchanges.
				 */
				if (local) {
					error = EINVAL;
					goto out_with_msg;
				}

				/* Look up algorithm IDs. */
				switch (msg.slot) {
				case NET2_CNEG_S2_HASH | NET2_CNEG_S2_REMOTE:
					result_alg = net2_hash_findname(msg.payload.result_alg);
					keysize = net2_hash_getkeylen(result_alg);
					break;
				case NET2_CNEG_S2_ENC | NET2_CNEG_S2_REMOTE:
					result_alg = net2_enc_findname(msg.payload.result_alg);
					keysize = net2_enc_getkeylen(result_alg);
					break;
				default:
					error = EINVAL;
					goto out_with_msg;
				}
				xchange_alg = net2_xchange_findname(msg.payload.exchange_alg);

				/* Check that we found a matching algorithm. */
				if (xchange_alg == -1 || result_alg == -1) {
					error = EINVAL;	/* Not found. */
					goto out_with_msg;
				}

				/* Apply or cross-reference with previously
				 * published values. */
				if (exchange->state & S2_SETUP_KNOWN) {
					/* Check that new data does not
					 * contradict old data. */
					if (xchange_alg != exchange->xchange_alg ||
					    result_alg != exchange->alg) {
						error = EINVAL;
						goto out_with_msg;
					}
				} else {
					exchange->xchange_alg = xchange_alg;
					exchange->alg = result_alg;
					exchange->keysize = keysize;
					exchange->state |= S2_SETUP_KNOWN;
					if (keysize == 0)
						exchange->state |= S2_INITBUF_KNOWN | S2_RESPONSE_RECEIVED;
				}
				break;

			case XMSG_INITBUF:
				/*
				 * Handle initbuf input.
				 */
				if (local) {
					/* Initbuf can only be transmitted by
					 * remote initializer. */
					error = EINVAL;
					goto out_with_msg;
				}

				assert(0); /* TODO: push into INITBUF keyex_ctx. */
				break;

			case XMSG_RESPONSE:
				assert(0); /* TODO: push into IMPORT keyex_ctx. */
				break;

			case XMSG_INITBUF | XMSG_SIGNATURE:
				if (local) {
					/* Initbuf can only be transmitted by
					 * remote initializer. */
					error = EINVAL;
					goto out_with_msg;
				}

				signature_idx = msg.payload.signature_idx;
				assert(0); /* TODO: push into INITBUF signature[signature_idx] keyex_ctx. */
				break;

			case XMSG_RESPONSE | XMSG_SIGNATURE:
				signature_idx = msg.payload.signature_idx;
				assert(0); /* TODO: push into IMPORT signature[signature_idx] keyex_ctx. */
				break;
			}
		}
		/* TODO: implement */

		net2_cp_destroy(&ctx, &cp_exchange_msg, &msg, NULL);
	}

	error = 0;
out_with_msg:
	net2_cp_destroy(&ctx, &cp_exchange_msg, &msg, NULL);
out:
	net2_encdec_ctx_deinit(&ctx);
	return error;
}

/*
 * Generate stage 2 buffer contents.
 */
static int
cneg_stage2_get_transmit(struct net2_conn_negotiator *cn,
    struct packet_header* ph,
    struct net2_buffer **bufptr, struct net2_cw_tx *tx, size_t maxlen,
    int stealth, int want_payload)
{
	struct net2_buffer	 *payload, *fin, *buf;
	int			 error;
	struct exchange_msg	 msg;
	struct net2_encdec_ctx	 ctx;
	size_t			 i;
	struct net2_evbase	*evbase;

	/* Setup buffers, context. */
	payload = fin = NULL;
	if ((error = net2_encdec_ctx_newaccsocket(&ctx, &CNEG_CONN(cn)->n2c_socket)) != 0)
		return error;
	if ((buf = net2_buffer_new()) == NULL)
		goto out;

	/* Lookup evbase. */
	evbase = net2_acceptor_socket_evbase(&CNEG_CONN(cn)->n2c_socket);

	/* Encode the fini header. */
	if ((fin = net2_buffer_new()) == NULL)
		goto out;
	if ((error = mk_exchange_msg_fin(&msg)) != 0)
		goto out;
	error = net2_cp_encode(&ctx, &cp_exchange_msg, fin, &msg, NULL);
	net2_cp_destroy(&ctx, &cp_exchange_msg, &msg, NULL);
	if (error != 0)
		goto out;
	/* Insufficient space for meaningful data. */
	if (net2_buffer_length(fin) >= maxlen)
		goto out;
	maxlen -= net2_buffer_length(fin);

	for (i = 0; i < NET2_CNEG_S2_MAX; i++) {
		error = net2_cneg_exchange_get_transmit(&payload,
		    &cn->stage2.xchanges[i], &ctx, evbase, tx, i,
		    maxlen - net2_buffer_length(buf));
		if (error != 0)
			goto out;

		/* Append payload to buf. */
		if (payload != NULL) {
			if (net2_buffer_append(buf, payload)) {
				error = ENOMEM;
				goto out;
			}
			net2_buffer_free(payload);
		}
		payload = NULL;
	}

	/* Append fin data to buffer, since it is not empty. */
	if (!net2_buffer_empty(buf)) {
		if ((net2_buffer_append(buf, fin)) != 0) {
			error = ENOMEM;
			goto out;
		}
	}

	/* Done. */
	if (!net2_buffer_empty(buf))
		ph->flags |= PH_HANDSHAKE_S2;
	error = 0;
	*bufptr = buf;
	buf = NULL;

out:
	net2_encdec_ctx_deinit(&ctx);
	if (buf != NULL)
		net2_buffer_free(buf);
	if (payload != NULL)
		net2_buffer_free(payload);
	if (fin != NULL)
		net2_buffer_free(fin);
	assert(error == 0 || *bufptr == NULL);
	return error;
}


/*
 * True iff the connection is ready and sufficiently secure
 * to allow payload to cross.
 */
ILIAS_NET2_LOCAL int
net2_cneg_allow_payload(struct net2_conn_negotiator *cn, uint32_t seq)
{
	int	require = (cn->flags & REQUIRE);

	/* Check that stage is sufficient to transmit. */
	switch (cn->stage) {
	case NET2_CNEG_STAGE_PRISTINE:
		return 0;
	}

	/* XXX for now, allow progress anyway */
	return 1;

	/* Check that all required options are enabled. */
	if ((cn->flags_have & require) != require)
		return 0;

	return 1;
}

/* Initialize connection negotiator. */
ILIAS_NET2_LOCAL int
net2_cneg_init(struct net2_conn_negotiator *cn, struct net2_ctx *context)
{
	int		 error;
	struct net2_connection
			*s = CNEG_CONN(cn);
	struct encoded_header
			*h;
	size_t		 i;

	assert(s != NULL);

	cn->context = context;
	cn->stage = NET2_CNEG_STAGE_PRISTINE;
	cn->flags = cn->flags_have = 0;
	cn->pver_acknowledged = 0;
	if (!(s->n2c_socket.fn->flags & NET2_SOCKET_SECURE)) {
		cn->flags |= NET2_CNEG_REQUIRE_ENCRYPTION |
		    NET2_CNEG_REQUIRE_SIGNING;
	}

	cn->signature_list.signatures = NULL;
	cn->signature_list.size = 0;
	cn->negotiated.sets = NULL;
	cn->negotiated.sets_count = 0;
	net2_bitset_init(&cn->negotiated.received);
	cn->negotiated.rcv_expected = UNKNOWN_SIZE;

	TAILQ_INIT(&cn->sendq);
	TAILQ_INIT(&cn->waitq);

	if ((error = create_headers(cn)) != 0)
		goto fail_0;

	if ((error = net2_pvlist_init(&cn->negotiated.proto)) != 0)
		goto fail_0;

	cn->hash.supported = NULL;
	cn->hash.num_supported = 0;
	cn->enc.supported = NULL;
	cn->enc.num_supported = 0;
	cn->xchange.supported = NULL;
	cn->xchange.num_supported = 0;
	cn->sign.supported = NULL;
	cn->sign.num_supported = 0;
	if ((error = net2_signset_init(&cn->remote_signs)) != 0)
		goto fail_1;

	/* Create stage 2 data. */
	if ((cn->stage2.xchanges = net2_calloc(NET2_CNEG_S2_MAX,
	    sizeof(*cn->stage2.xchanges))) == NULL)
		goto fail_2;
	for (i = 0; i < NET2_CNEG_S2_MAX; i++) {
		if ((error = net2_cneg_exchange_init(cn,
		    &cn->stage2.xchanges[i])) != 0)
			goto fail_4_partial;
	}

	return 0;


fail_4:
	i = NET2_CNEG_S2_MAX;
fail_4_partial:
	while (i > 0)
		net2_cneg_exchange_deinit(&cn->stage2.xchanges[--i]);
fail_3:
	net2_free(cn->stage2.xchanges);
fail_2:
	net2_signset_deinit(&cn->remote_signs);
fail_1:
	net2_bitset_deinit(&cn->negotiated.received);
	net2_pvlist_deinit(&cn->negotiated.proto);
fail_0:
	/* Mark as dead, all headers on the waitq; callback will deal with
	 * cleanup. */
	while ((h = TAILQ_FIRST(&cn->waitq)) != NULL) {
		h->flags |= EHF_NEGOTIATOR_DIED;
		TAILQ_REMOVE(&cn->waitq, h, entry);
	}
	/* Destroy all headers on the sendq. */
	while ((h = TAILQ_FIRST(&cn->sendq)) != NULL) {
		TAILQ_REMOVE(&cn->sendq, h, entry);
		free_encoded_header(h);
	}
	return error;
}

/* Destroy connection negotiator. */
ILIAS_NET2_LOCAL void
net2_cneg_deinit(struct net2_conn_negotiator *cn)
{
	struct encoded_header	*h;
	size_t			 i;
	struct event		*ev;

	/* Mark as dead, all headers on the waitq; callback will deal with
	 * cleanup. */
	while ((h = TAILQ_FIRST(&cn->waitq)) != NULL) {
		h->flags |= EHF_NEGOTIATOR_DIED;
		TAILQ_REMOVE(&cn->waitq, h, entry);
	}
	/* Destroy all headers on the sendq. */
	while ((h = TAILQ_FIRST(&cn->sendq)) != NULL) {
		TAILQ_REMOVE(&cn->sendq, h, entry);
		free_encoded_header(h);
	}

	/* Free negotiation sets. */
	if (cn->negotiated.sets != NULL) {
		while (cn->negotiated.sets_count > 0) {
			net2_bitset_deinit(&cn->negotiated.sets[
			    --cn->negotiated.sets_count].data);
		}
		net2_free(cn->negotiated.sets);
	}

	/* Free signatures used to identify this host. */
	if (cn->signature_list.signatures != NULL) {
		for (i = 0; i < cn->signature_list.size; i++) {
			if (cn->signature_list.signatures[i] == NULL)
				continue;
			net2_signctx_free(cn->signature_list.signatures[i]);
		}

		net2_free(cn->signature_list.signatures);
		cn->signature_list.signatures = NULL;
		cn->signature_list.size = 0;
	}

	/* Release stage2 data. */
	if (cn->stage2.xchanges != NULL) {
		for (i = 0; i < NET2_CNEG_S2_MAX; i++)
			net2_cneg_exchange_deinit(&cn->stage2.xchanges[i]);
		net2_free(cn->stage2.xchanges);
	}

	net2_pvlist_deinit(&cn->negotiated.proto);
	net2_bitset_deinit(&cn->negotiated.received);
	net2_signset_deinit(&cn->remote_signs);
	net2_free(cn->hash.supported);
	net2_free(cn->enc.supported);
	net2_free(cn->xchange.supported);
	net2_free(cn->sign.supported);
	return;
}

/* Get connection negotiator transmission. */
ILIAS_NET2_LOCAL int
net2_cneg_get_transmit(struct net2_conn_negotiator *cn,
    struct packet_header* ph,
    struct net2_buffer **bufptr, struct net2_cw_tx *tx, size_t maxlen,
    int stealth, int want_payload)
{
	/* Fill stage 1 transmission data. */
	if (cn->stage == NET2_CNEG_STAGE_PRISTINE) {
		return cneg_stage1_get_transmit(cn, ph, bufptr, tx, maxlen,
		    stealth, want_payload);
	}

	/* Fill stage 2 transmission data. */
	if (cn->stage == NET2_CNEG_STAGE_KEY_EXCHANGE) {
		return cneg_stage2_get_transmit(cn, ph, bufptr, tx, maxlen,
		    stealth, want_payload);
	}

	return 0;
}

/*
 * Accept packets.
 */
ILIAS_NET2_LOCAL int
net2_cneg_accept(struct net2_conn_negotiator *cn, struct packet_header *ph,
    struct net2_buffer *buf)
{
	int			 error;

	/* Handle stage 1 decoding. */
	if ((ph->flags & PH_HANDSHAKE) &&
	    (error = cneg_stage1_accept(cn, ph, buf)) != 0)
		goto fail;

	/*
	 * Handle conclusion of pristine (stage 1) stage.
	 */
	if (cn->stage == NET2_CNEG_STAGE_PRISTINE && all_done(cn)) {
		if ((error = cneg_conclude_pristine(cn)) != 0)
			goto fail;

		/*
		 * Disengage stealth (TODO: move down once more states
		 * are added.
		 */
		CNEG_CONN(cn)->n2c_stealth |= NET2_CONN_STEALTH_UNSTEALTH;
	}

	/* Handle stage 2 decoding. */
	if ((ph->flags & PH_HANDSHAKE_S2) &&
	    (error = cneg_stage2_accept(cn, ph, buf)) != 0)
		goto fail;

	/*
	 * Handle conclusion of KEY_EXCHANGE (stage 2) stage.
	 */
	if (cn->stage == NET2_CNEG_STAGE_KEY_EXCHANGE) {
		/* TODO: conclude stage 2. */
	}

	return 0;

fail:
	return error;
}

ILIAS_NET2_LOCAL int
net2_cneg_pvlist(struct net2_conn_negotiator *cn, struct net2_pvlist *pv)
{
	return net2_pvlist_merge(pv, &cn->negotiated.proto);
}
