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
#include <ilias/net2/cp.h>
#include <ilias/net2/bitset.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/packet.h>
#include <ilias/net2/promise.h>
#include <ilias/net2/encdec_ctx.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>

#include "handshake.h"
#include "exchange.h"


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

/* Stage 1 negotiation data. */
struct net2_cneg_stage1 {
	/* Single-value property receival state. */
	struct net2_bitset	 received;	/* Received marks. */
	struct value		*sv;		/* Single values. */
	uint32_t		 sv_len;	/* # sv. */
	uint32_t		 sv_expected;	/* Expected rcv_len. */
	struct net2_promise	*sv_complete;	/* All sv completed. */

	/* Sets receival state. */
	struct sets		 sets;
};


static int	sv_get(struct net2_cneg_stage1*, uint32_t, struct value**);
static int	sv_process(struct net2_cneg_stage1*, struct header*, uint32_t);
static int	sv_expected(struct net2_cneg_stage1*, uint32_t);

static int	val_errfin(struct value*, int);
static int	val_setfin(struct value*);
static int	val_setcancel(struct value*);
static int	val_init(struct value*);
static void	val_deinit(struct value*);
static int	val_process(struct value*, struct header*);

static int	sets_setfin(struct sets*, uint32_t);
static int	sets_setcancel(struct sets*, uint32_t);
static int	sets_elem_init(struct sets_elem*);
static void	sets_elem_deinit(struct sets_elem*);
static int	sets_elem_errfin(struct sets*, uint32_t, int);
static int	sets_elem_testfin(struct sets*, uint32_t);
static int	sets_get(struct sets*, uint32_t, struct sets_elem**);
static int	sets_setsize(struct sets*, uint32_t, uint32_t);
static int	sets_recv(struct sets*, struct header*, uint32_t, uint32_t);
static int	sets_init(struct sets*);
static void	sets_deinit(struct sets*);


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
sets_setcancel(struct sets *s, uint32_t idx)
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

	assert(error > 0);
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


/* Create a new stage1 negotiator. */
ILIAS_NET2_LOCAL struct net2_cneg_stage1*
cneg_stage1_new()
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
	if ((s->sv_complete = net2_promise_new()) == NULL)
		goto fail_2;

	return s;

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

	/* Free stage1. */
	net2_free(s);
}

/* Stage1 network acceptor. */
ILIAS_NET2_LOCAL int
cneg_stage1_accept(struct net2_cneg_stage1 *s, struct packet_header *ph,
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
