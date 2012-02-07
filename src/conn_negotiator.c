#include <ilias/net2/conn_negotiator.h>
#include <ilias/net2/connection.h>
#include <ilias/net2/bitset.h>
#include <ilias/net2/buffer.h>
#include <stdlib.h>
#include <assert.h>
#include <bsd_compat/minmax.h>

#include <ilias/net2/enc.h>
#include <ilias/net2/hash.h>
#include <ilias/net2/xchange.h>

#include "handshake.h"

#define REQUIRE			(REQUIRE_ENCRYPTION | REQUIRE_SIGNING)

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
	struct net2_buffer	*buf;
};
/* Create a new encoded header from a buffer. */
static struct encoded_header*
mk_encoded_header(struct net2_buffer *buf)
{
	struct encoded_header	*eh;

	assert(buf != NULL);
	if ((eh = malloc(sizeof(*eh))) == NULL)
		return NULL;
	eh->buf = buf;
	eh->flags = 0;
	return eh;
}
/* Free an encoded header. */
static void
free_encoded_header(struct encoded_header *eh)
{
	net2_buffer_free(eh->buf);
	free(eh);
}
/* Notify connection that we want to send data. */
static void
cneg_ready_to_send(struct net2_conn_negotiator *cn)
{
	net2_acceptor_socket_ready_to_send(&cn->conn->n2c_socket);
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
create_xhc_headers(struct net2_buffer **set, size_t *setsz_ptr, const char *(*name_fn)(int), int end, uint32_t type)
{
	struct header		 h;
	int			 i, e;
	const char		**list;
	int			 error;
	size_t			 list_alloc_sz;

	/* Allocate the name list. */
	if ((list = calloc(MIN(end, 1), sizeof(*list))) == NULL)
		return ENOMEM;

	/* Gather all names, skipping nulls. */
	for (i = e = 0; i < end; i++) {
		if ((list[e] = (*name_fn)(i)) != NULL)
			e++;
	}

	/* Transform names into buffers. */
	for (i = 0; i < e; i++) {
		if ((set[i] = net2_buffer_new()) == NULL) {
			i--;	/* Decrement i, since set[i] does not contain a buffer. */
			goto fail_nh;
		}

		if ((error = init_header_stringset(&h, i, list[i], e - 1, type)) != 0)
			goto fail_nh;
		if ((error = encode_header(&h, set[i])) != 0)
			goto fail;
		deinit_header(&h);
	}

	/* Handle empty set. */
	if (e == 0) {
		if ((set[0] = net2_buffer_new()) == NULL)
			goto fail_nh;
		i = e = 1;
		if ((error = init_header_empty_set(&h, type)) != 0)
			goto fail_nh;
		if ((error = encode_header(&h, set[0])) != 0)
			goto fail;
		deinit_header(&h);
	}

	*setsz_ptr = e;
	free(list);
	return 0;

fail:
	deinit_header(&h);
fail_nh:
	free(list);
	while (i >= 0)
		net2_buffer_free(set[i--]);
	return error;
}

/*
 * Create buffers with all headers.
 */
static int
create_headers(struct net2_buffer ***set_ptr, size_t *setsz_ptr,
    struct net2_conn_negotiator *cn)
{
	struct header		 h;
	struct net2_buffer	**set;
	size_t			 setsz, addsz;
	int			 error;
	size_t			 num_bufs;

	*set_ptr = NULL;
	*setsz_ptr = 0;

	/* Require at least 1 xchange method, 1 hash method and
	 * 1 crypt method. */
	assert(net2_xchangemax > 0 && net2_hashmax > 0 && net2_encmax > 0);

	/*
	 * We will now generate up to:
	 * 1		protocol header
	 * xchangemax	xchange headers
	 * hashmax	hash headers
	 * encmax	crypt headers
	 */
	num_bufs = 1 + net2_xchangemax + net2_hashmax + net2_encmax;
	set = calloc(num_bufs, sizeof(*set));
	setsz = 0;

	/* Generate protocol header. */
	if ((error = init_header_protocol(&h, cn->flags)) != 0)
		goto fail_nh;
	if ((set[setsz] = net2_buffer_new()) == NULL) {
		error = ENOMEM;
		goto fail;
	}
	setsz++;
	if ((error = encode_header(&h, (set)[setsz - 1])) != 0)
		goto fail;
	deinit_header(&h);

	/* Gather all exchange methods into set. */
	if ((error = create_xhc_headers(set + setsz, &addsz,
	    &net2_xchange_getname, net2_xchangemax, F_TYPE_XCHANGE)) != 0)
		goto fail_nh;
	setsz += addsz;
	assert(addsz > 0);

	/* Gather all hash methods into set. */
	if ((error = create_xhc_headers(set + setsz, &addsz,
	    &net2_hash_getname, net2_hashmax, F_TYPE_HASH)) != 0)
		goto fail_nh;
	setsz += addsz;
	assert(addsz > 0);

	/* Gather all crypt methods into set. */
	if ((error = create_xhc_headers(set + setsz, &addsz,
	    &net2_enc_getname, net2_encmax, F_TYPE_CRYPT)) != 0)
		goto fail_nh;
	setsz += addsz;
	assert(addsz > 0);

	*set_ptr = set;
	*setsz_ptr = setsz;

	return 0;

fail:
	deinit_header(&h);
fail_nh:	/* Fail, without initialized header. */
	while (setsz > 0)
		net2_buffer_free(set[--setsz]);
	free(set);
	return error;
}


#define UNKNOWN_SIZE	((size_t)-1)
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
#undef UNKNOWN_SIZE


/*
 * True iff the connection is ready and sufficiently secure
 * to allow payload to cross.
 */
ILIAS_NET2_LOCAL int
net2_cneg_allow_payload(struct net2_conn_negotiator *cn, uint32_t seq)
{
	int	require = (cn->flags & REQUIRE);

	/* Check that all required options are enabled. */
	if ((cn->flags_have & require) != require)
		return 0;

	return 1;
}

/* Initialize connection negotiator. */
ILIAS_NET2_LOCAL int
net2_cneg_init(struct net2_conn_negotiator *cn, struct net2_connection *s)
{
	int		 error;

	assert(s != NULL);
	cn->conn = s;

	cn->flags = 0;
	if (!(s->n2c_socket.fn->flags & NET2_SOCKET_SECURE))
		cn->flags |= REQUIRE_ENCRYPTION | REQUIRE_SIGNING;

	TAILQ_INIT(&cn->sendq);
	TAILQ_INIT(&cn->waitq);

	cn->headers.set = NULL;
	cn->headers.fini = NULL;
	cn->headers.setsz = 0;
	if ((error = create_headers(&cn->headers.set, &cn->headers.setsz, cn)) != 0)
		goto fail_1;

	if ((error = net2_pvlist_init(&cn->negotiated.proto)) != 0)
		goto fail_2;

	cn->negotiated.sets = NULL;
	cn->negotiated.sets_count = 0;
	net2_bitset_init(&cn->negotiated.received);

	return 0;

fail_3:
	net2_pvlist_deinit(&cn->negotiated.proto);
fail_2:
	if (cn->headers.set) {
		while (cn->headers.setsz > 0)
			net2_buffer_free(cn->headers.set[--cn->headers.setsz]);
		free(cn->headers.set);
	}
	if (cn->headers.fini)
		net2_buffer_free(cn->headers.fini);
fail_1:
fail_0:
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

	/* Free negotiation headers. */
	if (cn->headers.set) {
		while (cn->headers.setsz > 0)
			net2_buffer_free(cn->headers.set[--cn->headers.setsz]);
		free(cn->headers.set);
	}
	if (cn->headers.fini)
		net2_buffer_free(cn->headers.fini);

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
	return;
}

/* Get connection negotiator transmission. */
ILIAS_NET2_LOCAL int
net2_cneg_get_transmit(struct net2_conn_negotiator *cn,
    struct net2_buffer **bufptr, struct net2_cw_tx *tx, size_t maxlen)
{
	struct encoded_header	*eh;
	struct net2_buffer	*buf;
	int			 error;
	size_t			 fini_len;
	TAILQ_HEAD(, encoded_header)
				 transit;
	struct net2_evbase	*evbase;
	size_t			 old_sz;

	/* If nothing to send, return without data. */
	if (TAILQ_EMPTY(&cn->sendq))
		return 0;

	/* Initialize locals. */
	evbase = net2_acceptor_socket_evbase(&cn->conn->n2c_socket);
	fini_len = net2_buffer_length(cn->headers.fini);
	*bufptr = NULL;
	TAILQ_INIT(&transit);

	/* Create buffer. */
	if ((buf = net2_buffer_new()) == NULL)
		return ENOMEM;

	while ((eh = TAILQ_FIRST(&cn->sendq)) != NULL &&
	    maxlen > net2_buffer_length(eh->buf) + FINI_LEN) {
		/*
		 * Store old size, so we can undo the addition of this
		 * buffer on failure.
		 */
		old_sz = net2_buffer_length(buf);

		/* Append this eh. */
		error = net2_buffer_append(buf, eh->buf);
		if (error == ENOMEM)
			break;
		if (error != 0)
			goto fail;

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
		return ENOMEM;

	/* Append closing tag. */
	if ((error = net2_buffer_append(buf, cn->headers.fini)) != 0)
		goto fail;

	/* Commit transit queue. */
	while ((eh = TAILQ_FIRST(&transit)) != NULL) {
		TAILQ_REMOVE(&transit, eh, entry);
		TAILQ_INSERT_TAIL(&cn->waitq, eh, entry);
	}

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
net2_cneg_accept(struct net2_conn_negotiator *cn, struct net2_buffer *buf)
{
	struct header		 h;
	int			 skip;
	int			 error;
	size_t			 i;

	for (;;) {
		/* Decode header. */
		if ((error = decode_header(&h, buf)) != 0)
			goto fail;
		/* Stop after decoding the last header. */
		if (h.flags == F_LAST_HEADER) {
			deinit_header(&h);
			return 0;
		}

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
			if (i >= net2_bitset_size(&cn->negotiated.received)) {
				if ((error = net2_bitset_resize(
				    &cn->negotiated.received, i + 1, 0)) != 0)
					goto fail_wh;
			}

			if ((error = net2_bitset_set(&cn->negotiated.received,
			    i, 1, &skip)) != 0)
				goto fail_wh;
		}

		if (skip)
			goto skip;

		switch (h.flags & F_TYPEMASK) {
		case F_TYPE_PVER:
			if ((error = net2_pvlist_add(&cn->negotiated.proto,
			    &net2_proto, MIN(h.payload.version,
			    net2_proto.version))) != 0)
				goto fail_wh;
			/* TODO: store number of settypes, store number of types. */

			break;
		case F_TYPE_XCHANGE:
		case F_TYPE_HASH:
		case F_TYPE_CRYPT:
			break;
		default:
			/* Decoding error. */
			return EINVAL;
		}

skip:
		/* Free header. */
		deinit_header(&h);
	}

fail_wh:
	deinit_header(&h);
fail:
	return error;
}
