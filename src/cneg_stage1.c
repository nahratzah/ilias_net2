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
#include <ilias/net2/cneg_stage1.h>
#include <ilias/net2/config.h>
#include <ilias/net2/bitset.h>
#include <ilias/net2/cp.h>
#include <ilias/net2/context.h>
#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/packet.h>
#include <ilias/net2/promise.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>

#include "handshake.h"
#include "exchange.h"

#include <ilias/net2/enc.h>
#include <ilias/net2/hash.h>
#include <ilias/net2/sign.h>
#include <ilias/net2/xchange.h>

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <ilias/net2/bsd_compat/queue.h>
#endif


/* Define the unknown length. */
#define LEN_UNKNOWN		((uint32_t)-1)

/* Single value management. */
struct value {
	/* Fired when every element has been received and was processed. */
	struct net2_promise	*complete;

	/*
	 * Processing logic.
	 * The processing logic consists of a data pointer, which is passed
	 * as the first element of the process() callback.
	 */
	void			*data;	/* Data, will be given to set. */
	int			(*process)(void**, struct header*);
	/* Release function for data. */
	struct {
		void		(*fn)(void*, void*);
		void		*fn_arg;
	}			 free;
};

/* All data that is delivered in sets. */
struct sets {
	struct sets_elem	*rcv;	/* Per-set receive data. */
	size_t			 len;	/* # rcv. */
	size_t			 expected_len; /* Expected # recv. */
	struct net2_bitset	 completion_bits; /* Indicates completion. */

	/* Promise, fired when all sets have been received. */
	struct net2_promise	*complete;
};
/* All data that is delivered in a specific set. */
struct sets_elem {
	uint32_t		 len;	/* # elements per set. */
	struct net2_bitset	 rcv;	/* Indicates receival. */

	struct value		 val;	/* Value logic. */
};

/* List of to-be-transmitted headers. */
struct txh {
	struct net2_workq_job	 dummy;		/* Detect workq destruction. */
	TAILQ_ENTRY(txh)	 q;		/* Link into queue. */
	struct header		 header;	/* Header contents. */
	struct net2_buffer	*buf;		/* Encoded header (lazy). */
};
/* All to-be-transmitted headers. */
TAILQ_HEAD(txh_head, txh);

/* Stage 1 negotiation data. */
struct net2_cneg_stage1 {
	/* Single-value property receival state. */
	struct net2_bitset	 received;	/* Received marks. */
	struct value		*sv;		/* Single values. */
	uint32_t		 sv_len;	/* # sv. */
	uint32_t		 sv_expected;	/* Expected rcv_len. */
	struct net2_promise	*sv_complete;	/* All sv completed. */

	uint32_t		 cn_flags;	/* Required flags. */

	/* Sets receival state. */
	struct sets		 sets;

	struct txh_head		 tx,		/* To-be-transmitted. */
				 wait;		/* To-be-acked. */
};


static void	 free2(void*, void*);
static int	 sv_get(struct net2_cneg_stage1*, uint32_t, struct value**);
static int	 sv_process(struct net2_cneg_stage1*, struct header*, uint32_t);
static int	 sv_expected(struct net2_cneg_stage1*, uint32_t);

static int	 val_errfin(struct value*, int);
static int	 val_setfin(struct value*);
static int	 val_setcancel(struct value*);
static int	 val_init(struct value*);
static void	 val_deinit(struct value*);
static int	 val_process(struct value*, struct header*);

static int	 sets_setfin(struct sets*, uint32_t);
static int	 sets_setcancel(struct sets*, uint32_t);
static int	 sets_elem_init(struct sets_elem*);
static void	 sets_elem_deinit(struct sets_elem*);
static int	 sets_elem_errfin(struct sets*, uint32_t, int);
static int	 sets_elem_testfin(struct sets*, uint32_t);
static int	 sets_get(struct sets*, uint32_t, struct sets_elem**);
static int	 sets_setsize(struct sets*, uint32_t, uint32_t);
static int	 sets_recv(struct sets*, struct header*, uint32_t, uint32_t);
static int	 sets_init(struct sets*);
static void	 sets_deinit(struct sets*);

static struct txh
		*txh_new();
static void
		 txh_destroy(struct txh*);


struct name_set;	/* Used in creation of headers
			 * (txh_init, txh_init_name_set). */
static int	 xchange_names(char***, size_t*);
static int	 hash_names(char***, size_t*);
static int	 crypt_names(char***, size_t*);
static int	 sign_names(char***, size_t*);
static int	 txh_init_name_set(struct txh_head*, const struct name_set*);
static int	 txh_init_fingerprints(struct txh_head*, struct net2_signset*);
static int	 txh_init(struct txh_head*, uint32_t, struct net2_ctx*);


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


/* Promise helper around free. */
static void
free2(void *p, void * ILIAS_NET2__unused unused)
{
	net2_free(p);
}


/* Request a specific single-value. */
static int
sv_get(struct net2_cneg_stage1 *s, uint32_t idx, struct value **v)
{
	struct value		*list;
	int			 error;

	*v = NULL;
	if (s->sv_expected != LEN_UNKNOWN && idx >= s->sv_expected)
		return EINVAL;

	list = s->sv;
	if (s->sv_len <= idx) {
		if (idx + 1 == 0)
			return ENOMEM;
		list = net2_recalloc(list, idx + 1, sizeof(*list));
		if (list == NULL)
			return ENOMEM;
		s->sv = list;
		if ((error = net2_bitset_resize(&s->received, idx + 1,
		    0)) != 0)
			return error;

		while (s->sv_len < idx + 1) {
			if ((error = val_init(&list[s->sv_len])) != 0) {
				net2_bitset_resize(&s->received, s->sv_len, 0);
				return error;
			}

			s->sv_len++;
		}
	}

	*v = &list[idx];
	return 0;
}

/* Process a specific single-value. */
static int
sv_process(struct net2_cneg_stage1 *s, struct header *h, uint32_t idx)
{
	int			 error;
	int			 old;
	struct value		*v;

	if ((error = sv_get(s, idx, &v)) != 0)
		return error;
	if ((error = net2_bitset_set(&s->received, idx, 1, &old)) != 0)
		return error;

	if (old)
		return 0;

	if ((error = val_process(v, h)) != 0)
		return error;
	if ((error = val_setfin(v)) != 0)
		return error;

	/* Fire sv_complete if all single-values have completed. */
	if (s->sv_expected != LEN_UNKNOWN && s->sv_complete != NULL &&
	    net2_bitset_allset(&s->received)) {
		if ((error = net2_promise_set_finok(s->sv_complete, NULL,
		    NULL, NULL, NET2_PROMFLAG_RELEASE)) != 0)
			return error;
		s->sv_complete = NULL;
	}
	return 0;
}

/* Set number of expected sv. */
static int
sv_expected(struct net2_cneg_stage1 *s, uint32_t len)
{
	int			 error;
	int			 b;
	uint32_t		 i;

	if (s->sv_expected != LEN_UNKNOWN) {
		if (s->sv_expected != len)
			return EINVAL;
		return 0;
	}

	/* Test that the value has never been received. */
	for (i = len; i < s->sv_len; i++) {
		if ((error = net2_bitset_get(&s->received, i, &b)) != 0)
			return error;
		if (b)
			return EINVAL;
	}
	for (i = len; i < s->sv_len; i++)
		val_deinit(&s->sv[i]);

	s->sv_expected = len;
	if (s->sv_len > len)
		s->sv_len = len;

	/* Resize received bits. */
	if ((error = net2_bitset_resize(&s->received, len, 0)) != 0)
		return error;

	/* Test if we completed. */
	if (net2_bitset_allset(&s->received) && s->sv_complete != NULL) {
		if ((error = net2_promise_set_finok(s->sv_complete, NULL,
		    NULL, NULL, NET2_PROMFLAG_RELEASE)) != 0)
			return error;
		s->sv_complete = NULL;
	}
	return 0;
}


/* Complete value with error. */
static int
val_errfin(struct value *v, int err)
{
	int			 error;

	if (v->complete != NULL) {
		if ((error = net2_promise_set_error(v->complete, err,
		    NET2_PROMFLAG_RELEASE)) != 0)
			return error;
		v->complete = NULL;
	}

	if (v->data != NULL && v->free.fn != NULL)
		(*v->free.fn)(v->data, v->free.fn_arg);

	/* Block further processing. */
	v->data = NULL;
	v->complete = NULL;
	v->process = NULL;
	v->free.fn = NULL;

	return 0;
}

/* Mark value as complete. */
static int
val_setfin(struct value *v)
{
	int			 error;

	if (v->complete != NULL) {
		/* Fill in promise. */
		if ((error = net2_promise_set_finok(v->complete,
		    v->data, v->free.fn, v->free.fn_arg,
		    NET2_PROMFLAG_RELEASE)) != 0)
			return error;

		/* Block further processing. */
		v->data = NULL;
		v->complete = NULL;
		v->process = NULL;
		v->free.fn = NULL;

		return 0;
	}

	if (v->data != NULL && v->free.fn != NULL)
		(*v->free.fn)(v->data, v->free.fn_arg);

	/* Block further processing. */
	v->data = NULL;
	v->complete = NULL;
	v->process = NULL;
	v->free.fn = NULL;

	return 0;
}

/* Mark value as canceled. */
static int
val_setcancel(struct value *v)
{
	int			 error;

	if (v->complete != NULL) {
		/* Fill in promise. */
		if ((error = net2_promise_set_cancel(v->complete,
		    NET2_PROMFLAG_RELEASE)) != 0)
			return error;
	}

	/* Free data. */
	if (v->data != NULL && v->free.fn != NULL)
		(*v->free.fn)(v->data, v->free.fn_arg);

	/* Block further processing. */
	v->data = NULL;
	v->complete = NULL;
	v->process = NULL;
	v->free.fn = NULL;

	return 0;
}

/* Initialize value. */
static int
val_init(struct value *v)
{
	v->complete = NULL;
	v->process = NULL;
	v->data = NULL;
	v->free.fn = NULL;
	v->free.fn_arg = NULL;
	return 0;
}

/* Deinitialize value. */
static void
val_deinit(struct value *v)
{
	if (v->complete != NULL) {
		net2_promise_set_cancel(v->complete, 0);
		net2_promise_release(v->complete);
		v->complete = NULL;
	}

	if (v->data != NULL && v->free.fn != NULL)
		(*v->free.fn)(v->data, v->free.fn_arg);
}

/* Process data for value. */
static int
val_process(struct value *v, struct header *h)
{
	int		 error;

	if (v->process == NULL)
		return 0;

	error = (*v->process)(&v->data, h);
	if (error == ENOMEM)
		return ENOMEM;
	return val_errfin(v, error);
}


/*
 * Mark specific set as complete.
 * Fires sets completion if all sets have completed.
 */
static int
sets_setfin(struct sets *s, uint32_t idx)
{
	int			 old;
	int			 error;

	assert(idx < s->len);
	assert(idx < net2_bitset_size(&s->completion_bits));

	if ((error = net2_bitset_set(&s->completion_bits, idx, 1, &old)) != 0)
		return error;

	/* Set was already complete, nothing to do. */
	if (old)
		return 0;

	/* Test if every set_elem has completed. */
	if (s->complete != NULL && s->expected_len != LEN_UNKNOWN &&
	    net2_bitset_allset(&s->completion_bits)) {
		if ((error = net2_promise_set_finok(s->complete, NULL, NULL,
		    NULL, NET2_PROMFLAG_RELEASE)) != 0)
			return error;
		s->complete = NULL;
	}

	return 0;
}

/*
 * Complete the sets completion with cancelation.
 * Fires the cancel event.
 */
static int
sets_setcancel(struct sets *s, uint32_t ILIAS_NET2__unused idx)
{
	int			 error;

	if (s->complete != NULL) {
		if ((error = net2_promise_set_cancel(s->complete, NET2_PROMFLAG_RELEASE)) != 0)
			return error;
		s->complete = NULL;
	}
	return 0;
}

/* Initialize sets element. */
static int
sets_elem_init(struct sets_elem *se)
{
	int			 error;

	if ((error = val_init(&se->val)) != 0)
		return error;
	se->len = LEN_UNKNOWN;
	net2_bitset_init(&se->rcv);

	return 0;
}

/* Deinitialize sets element. */
static void
sets_elem_deinit(struct sets_elem *se)
{
	net2_bitset_deinit(&se->rcv);
	val_deinit(&se->val);
}

/* Mark sets element as completed with error. */
static int
sets_elem_errfin(struct sets *s, uint32_t idx, int err)
{
	struct sets_elem	*se;
	int			 error;

	assert(err > 0);
	assert(idx < s->len);
	se = &s->rcv[idx];

	if ((error = val_errfin(&se->val, err)) != 0)
		return error;
	return sets_setfin(s, idx);
}

/*
 * Test if the sets element has completed.
 * If it is complete, sets_setfin() will be called to mark it properly.
 *
 * If the set was canceled, completes with cancellation of the set element and
 * cancels the entire sets.
 */
static int
sets_elem_testfin(struct sets *s, uint32_t idx)
{
	struct sets_elem	*se;
	int			 error;

	assert(idx < s->len);
	se = &s->rcv[idx];

	if (net2_bitset_allset(&se->rcv)) {
		if ((error = val_setfin(&se->val)) != 0)
			return error;
		if ((error = sets_setfin(s, idx)) != 0)
			return error;
	} else if (se->val.complete != NULL &&
	    net2_promise_is_cancelreq(se->val.complete)) {
		if ((error = val_setcancel(&se->val)) != 0)
			return 0;
		if ((error = sets_setcancel(s, idx)) != 0)
			return error;
	}
	return 0;
}

/*
 * Retrieve a specific sets element.
 * Sets element will be created if required.
 */
static int
sets_get(struct sets *s, uint32_t idx, struct sets_elem **result)
{
	struct sets_elem	*list;
	int			 error;

	*result = NULL;
	if ((idx & F_TYPEMASK) != idx || !(idx & F_SET_ELEMENT))
		return EINVAL;
	idx &= ~F_SET_ELEMENT;
	list = s->rcv;

	if (s->expected_len != LEN_UNKNOWN && idx >= s->expected_len)
		return EINVAL;

	if (idx >= s->len) {
		/* Detect overflow. */
		if (idx + 1 == 0)
			return ENOMEM;

		list = net2_recalloc(list, idx + 1, sizeof(*list));
		if (list == NULL)
			return ENOMEM;
		s->rcv = list;

		if ((error = net2_bitset_resize(&s->completion_bits, idx + 1,
		    0)) != 0)
			return error;

		while (s->len <= idx) {
			if ((error = sets_elem_init(&list[s->len])) != 0) {
				net2_bitset_resize(&s->completion_bits, s->len,
				    0);
				return error;
			}

			s->len++;
		}
	}

	*result = &list[idx];
	return 0;
}

/* Set # sets to be expected. */
static int
sets_expected(struct sets *s, uint32_t len)
{
	uint32_t		 i;
	int			 error;

	if (s->expected_len != LEN_UNKNOWN) {
		if (s->expected_len != len)
			return EINVAL;
		return 0;
	}

	for (i = len; i < s->len; i++) {
		/*
		 * If this set has received data,
		 * the sender sent something invalid.
		 */
		if (!net2_bitset_allclear(&s->rcv[i].rcv))
			return EINVAL;
	}
	for (i = len; i < s->len; i++) {
		/* Deinit the sets_elem (will cancel any promises). */
		sets_elem_deinit(&s->rcv[i]);
	}
	s->expected_len = len;
	if (s->len > len)
		s->len = len;

	/* Resize the bitset to the number of required bits. */
	if ((error = net2_bitset_resize(&s->completion_bits, len, 0)) != 0)
		return error;

	if (s->complete != NULL && net2_bitset_allset(&s->completion_bits)) {
		if ((error = net2_promise_set_finok(s->complete, NULL,
		    NULL, NULL, NET2_PROMFLAG_RELEASE)) != 0)
			return error;
		s->complete = NULL;
	}

	return 0;
}

/* Set the size of a specific sets element. */
static int
sets_setsize(struct sets *s, uint32_t idx, uint32_t len)
{
	struct sets_elem	*se;
	int			 error;

	if ((error = sets_get(s, idx, &se)) != 0)
		return error;

	if (se->len != LEN_UNKNOWN && se->len != len) {
		sets_elem_errfin(s, idx, EINVAL);
		return 0;
	}
	if (net2_bitset_size(&se->rcv) > len) {
		sets_elem_errfin(s, idx, EINVAL);
		return 0;
	}
	if ((error = net2_bitset_resize(&se->rcv, len, 0)) != 0) {
		sets_elem_errfin(s, idx, error);
		return error;
	}
	se->len = len;

	return sets_elem_testfin(s, idx);
}

/* Handles incoming data for a set. */
static int
sets_recv(struct sets *s, struct header *h, uint32_t idx, uint32_t len)
{
	struct sets_elem	*se;
	int			 error;
	int			 old;

	if ((error = sets_get(s, idx, &se)) != 0)
		return error;
	if (se->len != LEN_UNKNOWN && se->len <= len) {
		sets_elem_errfin(s, idx, EINVAL);
		return 0;
	}
	if (net2_bitset_size(&se->rcv) <= len) {
		if ((error = net2_bitset_resize(&se->rcv, len, 0)) != 0)
			return error;
	}

	if ((error = net2_bitset_set(&se->rcv, len, 1, &old)) != 0) {
		sets_elem_errfin(s, idx, error);
		return 0;
	}
	/* Already received -> skip. */
	if (old)
		return 0;

	/* Process message. */
	if ((error = val_process(&se->val, h)) != 0)
		return error;

	/* Test if the sets_elem has completed. */
	return sets_elem_testfin(s, idx);
}

/* Initialize sets. */
static int
sets_init(struct sets *s)
{
	s->rcv = NULL;
	s->len = 0;
	s->expected_len = LEN_UNKNOWN;
	net2_bitset_init(&s->completion_bits);
	if ((s->complete = net2_promise_new()) == NULL)
		return ENOMEM;
	net2_promise_set_running(s->complete);
	return 0;
}

/* Deinitialize sets. */
static void
sets_deinit(struct sets *s)
{
	/*
	 * First, cancel the promise,
	 * to reduce overhead from sets_elem destruction.
	 */
	if (s->complete != NULL) {
		net2_promise_set_cancel(s->complete, NET2_PROMFLAG_RELEASE);
		s->complete = NULL; /* Prevent sets_elem from touching it. */
	}

	/*
	 * Cancel all sets_elem.
	 */
	while (s->len-- > 0)
		sets_elem_deinit(&s->rcv[s->len]);
	net2_free(s->rcv);

	/*
	 * Release the bitset.  Note that sets_elem_deinit may have touched
	 * this, so it must be destroyed _after_ sets_elem_deinit has run.
	 */
	net2_bitset_deinit(&s->completion_bits);
}


/* Create a new (barely initialized) stage 1 transmit header. */
static struct txh*
txh_new()
{
	struct txh		*out;

	if ((out = net2_malloc(sizeof(*out))) == NULL)
		goto fail_0;
	if (net2_cp_init(NULL, &cp_header, &out->header, NULL))
		goto fail_1;
	out->buf = NULL;
	return out;


fail_2:
	net2_cp_destroy(NULL, &cp_header, &out->header, NULL);
fail_1:
	net2_free(out);
fail_0:
	return NULL;
}

/* Destroy a stage 1 transmit header. */
static void
txh_destroy(struct txh *txh)
{
	if (txh->buf != NULL)
		net2_buffer_free(txh->buf);
	net2_cp_destroy(NULL, &cp_header, &txh->header, NULL);
	net2_free(txh);
}


/* Create a new stage1 negotiator. */
ILIAS_NET2_LOCAL struct net2_cneg_stage1*
cneg_stage1_new(uint32_t cn_flags, struct net2_ctx *nctx)
{
	struct net2_cneg_stage1	*s;

	if ((s = net2_malloc(sizeof(*s))) == NULL)
		goto fail_0;
	if (sets_init(&s->sets) != 0)
		goto fail_1;

	net2_bitset_init(&s->received);
	s->sv = NULL;
	s->sv_len = 0;
	s->sv_expected = LEN_UNKNOWN;
	s->cn_flags = cn_flags;
	if ((s->sv_complete = net2_promise_new()) == NULL)
		goto fail_2;

	TAILQ_INIT(&s->tx);
	TAILQ_INIT(&s->wait);
	txh_init(&s->tx, cn_flags, nctx);

	return s;

fail_3:
	if (s->sv_complete != NULL)
		net2_promise_release(s->sv_complete);
fail_2:
	net2_bitset_deinit(&s->received);
	sets_deinit(&s->sets);
fail_1:
	net2_free(s);
fail_0:
	return NULL;
}

/* Destroy a stage1 negotiator. */
ILIAS_NET2_LOCAL void
cneg_stage1_free(struct net2_cneg_stage1 *s)
{
	struct txh		*txh;

	/* Break the single-value promise. */
	if (s->sv_complete != NULL) {
		net2_promise_set_cancel(s->sv_complete, 0);
		net2_promise_release(s->sv_complete);
		s->sv_complete = NULL;
	}

	/* Destroy the single values. */
	while (s->sv_len-- > 0)
		val_deinit(&s->sv[s->sv_len]);
	/* Clear the single-values received bits. */
	net2_bitset_deinit(&s->received);

	/* De-init all sets. */
	sets_deinit(&s->sets);

	/* Destroy all tx headers. */
	while ((txh = TAILQ_FIRST(&s->tx)) != NULL) {
		TAILQ_REMOVE(&s->tx, txh, q);
		txh_destroy(txh);
	}
	while ((txh = TAILQ_FIRST(&s->wait)) != NULL) {
		TAILQ_REMOVE(&s->wait, txh, q);
		txh_destroy(txh);
	}

	/* Free stage1. */
	net2_free(s);
}

/* Stage1 network acceptor. */
ILIAS_NET2_LOCAL int
cneg_stage1_accept(struct net2_cneg_stage1 *s,
    struct packet_header * ILIAS_NET2__unused ph,
    struct net2_buffer *buf)
{
	struct header		 h;
	int			 error;

	for (;;) {
		if ((error = decode_header(&h, buf)) != 0)
			goto fail_0;
		/* GUARD: stop after decoding the last header. */
		if (h.flags == F_LAST_HEADER) {
			deinit_header(&net2_encdec_proto0, &h);
			break;
		}

		if (h.flags == F_POETRY) {
			/* Do nothing. */
		} else if (h.flags & F_SET_EMPTY) {
			if ((sets_setsize(&s->sets, h.flags & F_TYPEMASK,
			    0)) != 0)
				goto fail_1;
		} else if (h.flags & F_SET_ELEMENT) {
			if (h.flags & F_SET_LASTELEM) {
				if ((sets_setsize(&s->sets,
				    h.flags & F_TYPEMASK,
				    (uint32_t)h.seq + 1)) != 0)
					goto fail_1;
			}

			if ((error = sets_recv(&s->sets, &h,
			    h.flags & F_TYPEMASK, h.seq)) != 0)
				goto fail_1;
		} else {
			/* Read expected {sets, sv} from main header. */
			if ((h.flags & F_TYPEMASK) == F_TYPE_PVER) {
				sets_expected(&s->sets, h.payload.num_settypes);
				sv_expected(s, h.payload.num_types);
			}

			if ((error = sv_process(s, &h,
			    h.flags & F_TYPEMASK)) != 0)
				goto fail_1;
		}

		/* Release resources in header. */
		deinit_header(&net2_encdec_proto0, &h);
	}

	return 0;


fail_1:
	deinit_header(&net2_encdec_proto0, &h);
fail_0:
	assert(error != 0);
	return error;
}



/* Create protocol version header. */
static int
txh_init_pver(struct txh_head *list, uint32_t cn_flags)
{
	struct txh		*h;
	int			 error;

	if ((h = txh_new()) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	if ((error = init_header_protocol(&h->header, cn_flags)) != 0)
		goto fail_1;

	TAILQ_INSERT_TAIL(list, h, q);
	return 0;


fail_1:
	txh_destroy(h);
fail_0:
	assert(error != 0);
	return error;
}


/* Describe named sets. */
struct name_set {
	uint32_t which;
	int	(*names)(char ***names, size_t *count);
	int	 free_names;	/* If true, names are allocated. */
};
/* All name sets. */
static const struct name_set name_sets[] = {
	{ F_TYPE_XCHANGE,	&xchange_names,	0 },
	{ F_TYPE_HASH,		&hash_names,	0 },
	{ F_TYPE_CRYPT,		&crypt_names,	0 },
	{ F_TYPE_SIGN,		&sign_names,	0 },
};

/* Create name method headers. */
static int
txh_init_name_set(struct txh_head *list, const struct name_set *set)
{
	struct txh		*h;
	char			**names;
	size_t			 count, i;
	int			 error;

	/* Gather all names. */
	names = NULL;
	if ((error = (*set->names)(&names, &count)) != 0)
		goto fail_0;

	/* Push each name on the list. */
	for (i = 0; i < count; i++) {
		if ((h = txh_new()) == NULL) {
			error = ENOMEM;
			goto fail_1;
		}
		if ((error = init_header_stringset(&h->header, i, names[i],
		    count - 1, set->which)) != 0)
			goto fail_2;

		TAILQ_INSERT_TAIL(list, h, q);
	}

	/* Handle the case of the empty list. */
	if (count == 0) {
		if ((h = txh_new()) == NULL) {
			error = ENOMEM;
			goto fail_1;
		}
		if ((error = init_header_empty_set(&h->header,
		    set->which)) != 0)
			goto fail_2;

		TAILQ_INSERT_TAIL(list, h, q);
	}

	/* Succes. */
	error = 0;
	/* Use fail_1 path to clean up. */
	goto fail_1;


fail_2:
	txh_destroy(h);
fail_1:
	if (names != NULL) {
		if (set->free_names) {
			for (i = 0; i < count; i++)
				net2_free(names[i]);
		}
		net2_free(names);
	}
fail_0:
	return error;
}

/* Create fingerprint headers. */
static int
txh_init_fingerprints(struct txh_head *list, struct net2_signset *set)
{
	struct net2_buffer	**fps;
	size_t			 count, i;
	int			 error;
	struct txh		*h;

	/* Gather fingerprints. */
	fps = NULL;
	count = 0;
	if (set != NULL) {
		if ((error = net2_signset_all_fingerprints(set, &fps, &count)) != 0)
			goto fail_0;
	}

	/* Add all fingerprints. */
	for (i = 0; i < count; i++) {
		if ((h = txh_new()) == NULL) {
			error = ENOMEM;
			goto fail_1;
		}
		if ((error = init_header_bufset(&h->header, i, fps[i],
		    count - 1, F_TYPE_SIGNATURE)) != 0)
			goto fail_2;

		TAILQ_INSERT_TAIL(list, h, q);
	}

	/* Handle empty set. */
	if (count == 0) {
		if ((h = txh_new()) == NULL) {
			error = ENOMEM;
			goto fail_1;
		}
		if ((error = init_header_empty_set(&h->header, F_TYPE_SIGNATURE)) != 0)
			goto fail_2;

		TAILQ_INSERT_TAIL(list, h, q);
	}

	/* Done. */
	error = 0;
	/* Use fail_1 to do cleanup. */
	goto fail_1;


fail_2:
	txh_destroy(h);
fail_1:
	if (fps != NULL) {
		for (i = 0; i < count; i++)
			net2_buffer_free(fps[i]);
		net2_free(fps);
	}
fail_0:
	return error;
}

/*
 * Create headers.
 * Note: the last set of headers (set 6: requested fingerprints)
 * is not created here.
 */
static int
txh_init(struct txh_head *list, uint32_t cn_flags, struct net2_ctx *nctx)
{
	int			 error;
	size_t			 i;
	struct txh		*h;

	assert(TAILQ_EMPTY(list));

	/* Value 0: protocol version, flags, stage1 metadata. */
	if ((error = txh_init_pver(list, cn_flags)) != 0)
		goto fail;

	/*
	 * All non-set types have been added.
	 *
	 * Time to add set data.
	 */

	/* Set 0, 1, 2, 3: exchange, hash, crypt, sign methods. */
	for (i = 0; i < sizeof(name_sets) / sizeof(name_sets[0]); i++) {
		if ((error = txh_init_name_set(list, &name_sets[i])) != 0)
			goto fail;
	}

	/* Set 5: signature fingerprints. */
	if ((error = txh_init_fingerprints(list,
	    (nctx == NULL ? NULL : &nctx->local_signs))) != 0)
		goto fail;

	/* Done. */
	return 0;


fail:
	while ((h = TAILQ_FIRST(list)) != NULL) {
		TAILQ_REMOVE(list, h, q);
		txh_destroy(h);
	}

	assert(error != 0);
	return error;
}

/* Gather all xchange methods. */
static int
xchange_names(char ***names_ptr, size_t *count_ptr)
{
	char			**names;
	size_t			 count;
	int			 i;

	if (net2_xchangemax == 0) {
		*names_ptr = NULL;
		*count_ptr = 0;
		return 0;
	}

	/* Allocate names. */
	names = net2_calloc(net2_xchangemax, sizeof(*names));
	if (names == NULL)
		return ENOMEM;

	/* Collect all names. */
	for (count = 0, i = 0; i < net2_xchangemax; i++) {
		if ((names[count] = (char*)net2_xchange_getname(i)) != NULL)
			count++;
	}

	*names_ptr = names;
	*count_ptr = count;
	return 0;
}
/* Gather all hash methods. */
static int
hash_names(char ***names_ptr, size_t *count_ptr)
{
	char			**names;
	size_t			 count;
	int			 i;

	if (net2_hashmax == 0) {
		*names_ptr = NULL;
		*count_ptr = 0;
		return 0;
	}

	/* Allocate names. */
	names = net2_calloc(net2_hashmax, sizeof(*names));
	if (names == NULL)
		return ENOMEM;

	/* Collect all names. */
	for (count = 0, i = 0; i < net2_hashmax; i++) {
		if ((names[count] = (char*)net2_hash_getname(i)) != NULL)
			count++;
	}

	*names_ptr = names;
	*count_ptr = count;
	return 0;
}
/* Gather all crypt methods. */
static int
crypt_names(char ***names_ptr, size_t *count_ptr)
{
	char			**names;
	size_t			 count;
	int			 i;

	if (net2_encmax == 0) {
		*names_ptr = NULL;
		*count_ptr = 0;
		return 0;
	}

	/* Allocate names. */
	names = net2_calloc(net2_encmax, sizeof(*names));
	if (names == NULL)
		return ENOMEM;

	/* Collect all names. */
	for (count = 0, i = 0; i < net2_encmax; i++) {
		if ((names[count] = (char*)net2_enc_getname(i)) != NULL)
			count++;
	}

	*names_ptr = names;
	*count_ptr = count;
	return 0;
}
/* Gather all sign methods. */
static int
sign_names(char ***names_ptr, size_t *count_ptr)
{
	char			**names;
	size_t			 count;
	int			 i;

	if (net2_signmax == 0) {
		*names_ptr = NULL;
		*count_ptr = 0;
		return 0;
	}

	/* Allocate names. */
	names = net2_calloc(net2_signmax, sizeof(*names));
	if (names == NULL)
		return ENOMEM;

	/* Collect all names. */
	for (count = 0, i = 0; i < net2_signmax; i++) {
		if ((names[count] = (char*)net2_sign_getname(i)) != NULL)
			count++;
	}

	*names_ptr = names;
	*count_ptr = count;
	return 0;
}
