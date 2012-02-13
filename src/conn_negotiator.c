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
#include <ilias/net2/bitset.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/cp.h>
#include <ilias/net2/packet.h>
#include <stdlib.h>
#include <assert.h>
#include <bsd_compat/minmax.h>

#include <ilias/net2/enc.h>
#include <ilias/net2/hash.h>
#include <ilias/net2/xchange.h>

#include "handshake.h"
#include "signature.h"

#include <stdio.h>	/* DEBUG */

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
};


static __inline int
encode_header(const struct header *h, struct net2_buffer *out)
{
	return net2_cp_encode(NULL, &cp_header, out, h, NULL);
}
static __inline int
decode_header(struct header *h, struct net2_buffer *in)
{
	return net2_cp_decode(NULL, &cp_header, h, in, NULL);
}


/* Queue encoded headers. */
struct encoded_header {
	TAILQ_ENTRY(encoded_header)
				 entry;

	int			 flags;
#define EHF_NEGOTIATOR_DIED	0x00000001
	struct header		 header;
};
/* Create a new encoded header from a buffer. */
static struct encoded_header*
mk_encoded_header()
{
	struct encoded_header	*eh;

	if ((eh = malloc(sizeof(*eh))) == NULL)
		return NULL;
	if (net2_cp_init(NULL, &cp_header, &eh->header, NULL)) {
		free(eh);
		return NULL;
	}
	eh->flags = 0;
	return eh;
}
/* Free an encoded header. */
static void
free_encoded_header(struct encoded_header *eh)
{
	net2_cp_destroy(NULL, &cp_header, &eh->header, NULL);
	free(eh);
}
/* Notify connection that we want to send data. */
static void
cneg_ready_to_send(struct net2_conn_negotiator *cn)
{
	net2_acceptor_socket_ready_to_send(&CNEG_CONN(cn)->n2c_socket);
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
	if ((list = calloc(MAX(end, 1), sizeof(*list))) == NULL)
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

		if ((error = init_header_stringset(&h->header, i, list[i],
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

		if ((error = init_header_empty_set(&h->header, type)) != 0) {
			free_encoded_header(h);
			goto fail;
		}
		TAILQ_INSERT_TAIL(&cn->sendq, h, entry);
	}

	free(list);
	return 0;

fail:
	free(list);
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

	if ((h = mk_encoded_header()) == NULL)
		return ENOMEM;
	/* Generate protocol header. */
	if ((error = init_header_protocol(&h->header, cn->flags)) != 0) {
		free_encoded_header(h);
		return error;
	}
	TAILQ_INSERT_TAIL(&cn->sendq, h, entry);

	/* Gather all exchange methods into set. */
	if ((error = create_xhc_headers(cn,
	    &net2_xchange_getname, net2_xchangemax, F_TYPE_XCHANGE)) != 0)
		return error;

	/* Gather all hash methods into set. */
	if ((error = create_xhc_headers(cn,
	    &net2_hash_getname, net2_hashmax, F_TYPE_HASH)) != 0)
		return error;

	/* Gather all crypt methods into set. */
	if ((error = create_xhc_headers(cn,
	    &net2_enc_getname, net2_encmax, F_TYPE_CRYPT)) != 0)
		return error;

	/* Gather all signature methods into set. */
	if ((error = create_xhc_headers(cn,
	    &net2_sign_getname, net2_signmax, F_TYPE_SIGN)) != 0)
		return error;

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
		list = realloc(list, (which_set + 1) * sizeof(*list));
		if (list == NULL)
			return ENOMEM;
		cn->negotiated.sets = list;

		while (cn->negotiated.sets_count <= which_set) {
			list[cn->negotiated.sets_count].flags = 0;
			list[cn->negotiated.sets_count].expected_size =
			    UNKNOWN_SIZE;
			net2_bitset_init(&list[cn->negotiated.sets_count].data);
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
		if (list->expected_size == UNKNOWN_SIZE)
			return 0;
		if (list->expected_size != net2_bitset_size(&list->data))
			return 0;
	}

	/*
	 * Now, check that each set has their bits set.
	 */
	for (list = cn->negotiated.sets; list != last; list++) {
		/* Already checked. */
		if (list->flags & SET_F_ALLDONE)
			continue;

		if (!net2_bitset_allset(&list->data))
			return 0;

		/* This set passed, exclude it from future checks. */
		list->flags |= SET_F_ALLDONE;
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
	nl = realloc(*list, newsz * sizeof(int));
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
	int		error;
	int		idx;

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
		idx = net2_xchange_findname(h->payload.string);
		if (idx == -1)
			break;

		/* Store this idx. */
		if ((error = intlist_add(&cn->xchange.supported,
		    &cn->xchange.num_supported, idx)) != 0)
			return error;

		break;

	case F_TYPE_HASH:
		idx = net2_hash_findname(h->payload.string);
		if (idx == -1)
			break;

		/* Store this idx. */
		if ((error = intlist_add(&cn->hash.supported,
		    &cn->hash.num_supported, idx)) != 0)
			return error;

		break;

	case F_TYPE_CRYPT:
		idx = net2_enc_findname(h->payload.string);
		if (idx == -1)
			break;

		/* Store this idx. */
		if ((error = intlist_add(&cn->enc.supported,
		    &cn->enc.num_supported, idx)) != 0)
			return error;

		break;

	case F_TYPE_SIGN:
		idx = net2_sign_findname(h->payload.string);
		if (idx == -1)
			break;

		/* Store this idx. */
		if ((error = intlist_add(&cn->sign.supported,
		    &cn->sign.num_supported, idx)) != 0)
			return error;

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
	cn->tx_xchange =
	    cn->xchange.supported[cn->xchange.num_supported - 1];

	/* Select encryption algorithm. */
	if (!(cn->flags & NET2_CNEG_REQUIRE_ENCRYPTION)) {
		/*
		 * Select the weakest encryption algorithm.
		 * This usually is enc[0]: nil.
		 */
		cn->tx_enc = cn->enc.supported[0];
	} else {
		/*
		 * Select the best encryption algorithm.
		 */
		cn->tx_enc =
		    cn->enc.supported[cn->enc.num_supported - 1];
	}

	/* Select hashing algorithm. */
	if (!(cn->flags & NET2_CNEG_REQUIRE_SIGNING)) {
		/*
		 * Select the weakest signing algorithm.
		 * This usually is hash[0]: nil.
		 */
		cn->tx_hash = cn->enc.supported[0];
	} else {
		/*
		 * Select the best signing algorithm.
		 */
		cn->tx_hash =
		    cn->hash.supported[cn->hash.num_supported - 1];
	}

	/*
	 * If we require signing, ensure we don't select
	 * the nil algorithm.
	 */
	if (cn->tx_hash == 0 &&
	    (cn->flags & NET2_CNEG_REQUIRE_SIGNING)) {
		error = ENODEV;
		goto fail;
	}
	/*
	 * If we require encryption, ensure we don't select
	 * the nil algorithm.
	 */
	if (cn->tx_enc == 0 &&
	    (cn->flags & NET2_CNEG_REQUIRE_ENCRYPTION)) {
		error = ENODEV;
		goto fail;
	}

	/* Go to next stage. */
	cn->stage = NET2_CNEG_STAGE_KEY_EXCHANGE;
	cneg_ready_to_send(cn);

fail:
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
net2_cneg_init(struct net2_conn_negotiator *cn)
{
	int		 error;
	struct net2_connection
			*s = CNEG_CONN(cn);
	struct encoded_header
			*h;

	assert(s != NULL);

	cn->stage = NET2_CNEG_STAGE_PRISTINE;
	cn->flags = cn->flags_have = 0;
	if (!(s->n2c_socket.fn->flags & NET2_SOCKET_SECURE)) {
		cn->flags |= NET2_CNEG_REQUIRE_ENCRYPTION |
		    NET2_CNEG_REQUIRE_SIGNING;
	}

	TAILQ_INIT(&cn->sendq);
	TAILQ_INIT(&cn->waitq);

	if ((error = create_headers(cn)) != 0)
		goto fail_0;

	if ((error = net2_pvlist_init(&cn->negotiated.proto)) != 0)
		goto fail_0;

	cn->negotiated.sets = NULL;
	cn->negotiated.sets_count = 0;
	net2_bitset_init(&cn->negotiated.received);
	cn->negotiated.rcv_expected = UNKNOWN_SIZE;

	cn->hash.supported = NULL;
	cn->hash.num_supported = 0;
	cn->enc.supported = NULL;
	cn->enc.num_supported = 0;
	cn->xchange.supported = NULL;
	cn->xchange.num_supported = 0;
	cn->sign.supported = NULL;
	cn->sign.num_supported = 0;

	return 0;

fail_1:
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
		free(cn->negotiated.sets);
	}

	net2_pvlist_deinit(&cn->negotiated.proto);
	net2_bitset_deinit(&cn->negotiated.received);
	free(cn->hash.supported);
	free(cn->enc.supported);
	free(cn->xchange.supported);
	free(cn->sign.supported);
	return;
}

/* Get connection negotiator transmission. */
ILIAS_NET2_LOCAL int
net2_cneg_get_transmit(struct net2_conn_negotiator *cn,
    struct packet_header* ph,
    struct net2_buffer **bufptr, struct net2_cw_tx *tx, size_t maxlen)
{
	struct encoded_header	*eh;
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

	while ((eh = TAILQ_FIRST(&cn->sendq)) != NULL && maxlen > FINI_LEN) {
		/*
		 * Store old size, so we can undo the addition of this
		 * buffer on failure.
		 */
		old_sz = net2_buffer_length(buf);

		/* Append this eh. */
		error = encode_header(&eh->header, buf);
		if (error == ENOMEM)
			break;
		if (error != 0)
			goto fail;
		/* Check that the buffer doesn't exceed the maxlen. */
		if (net2_buffer_length(buf) + FINI_LEN > maxlen) {
			net2_buffer_truncate(buf, old_sz);
			break;
		}

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
	if (TAILQ_EMPTY(&transit))
		return 0;

	/* Append closing tag. */
	if ((error = encode_header(&header_fini, buf)) != 0)
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
 * Accept packets.
 */
ILIAS_NET2_LOCAL int
net2_cneg_accept(struct net2_conn_negotiator *cn, struct packet_header *ph,
    struct net2_buffer *buf)
{
	struct header		 h;
	int			 skip;
	int			 error;
	size_t			 i;

	/* Only decode if negotiation data is present. */
	if (!(ph->flags & PH_HANDSHAKE))
		return 0;

	for (;;) {
		/* Decode header. */
		if ((error = decode_header(&h, buf)) != 0)
			goto fail;
		/* GUARD: Stop after decoding the last header. */
		if (h.flags == F_LAST_HEADER) {
			deinit_header(&h);
			break;
		}

		skip = 0;
		if (h.flags & F_SET_ELEMENT) {
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
		}


skip:
		/* Free header. */
		deinit_header(&h);
	}

	/*
	 * Handle conclusion of pristine (exchange) stage.
	 */
	if (cn->stage == NET2_CNEG_STAGE_PRISTINE && all_done(cn)) {
		if ((error = cneg_conclude_pristine(cn)) != 0)
			goto fail;

		/* Disengage stealth (TODO: move down once more states are added. */
		CNEG_CONN(cn)->n2c_stealth |= NET2_CONN_STEALTH_UNSTEALTH;
	}

	return 0;

fail_wh:
	deinit_header(&h);
fail:
	return error;
}

ILIAS_NET2_LOCAL int
net2_cneg_pvlist(struct net2_conn_negotiator *cn, struct net2_pvlist *pv)
{
	return net2_pvlist_merge(pv, &cn->negotiated.proto);
}
