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
#include <ilias/net2/poetry.h>
#include <ilias/net2/promise.h>
#include <ilias/net2/signset.h>
#include <ilias/net2/tx_callback.h>
#include <ilias/net2/workq.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>

#include "handshake.h"
#include "exchange.h"
#include "packet.h"

#include <ilias/net2/enc.h>
#include <ilias/net2/hash.h>
#include <ilias/net2/sign.h>
#include <ilias/net2/xchange.h>
#include <ilias/net2/bsd_compat/minmax.h>
#include <ilias/net2/bsd_compat/secure_random.h>

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
	int			(*process)(struct net2_cneg_stage1*, void**,
				    struct header*);
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
	struct net2_txcb_entryq	 txcbq;		/* TX callbacks for this. */

	int			 whichq;	/* On which queue is this. */
#define TXH_WQ_WAIT		 0
#define TXH_WQ_TX		 1
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
	struct net2_promise	*rsin;		/* Required signatures that
						 * remote must send crypto
						 * negotiation with. */
	struct net2_promise	*tx_complete;	/* TX completed. */
	struct net2_promise	*rx_complete;	/* RX completed. */
	struct net2_promise	*complete;	/* Everything completed. */
	struct net2_workq_job	 rts;		/* Ready to send event. */

	uint32_t		 cn_flags;	/* Required flags. */

	/* Sets receival state. */
	struct sets		 sets;

	struct txh_head		 tx,		/* To-be-transmitted. */
				 wait;		/* To-be-acked. */

	struct net2_ctx		*nctx;		/* Network context. */

	struct net2_promise_event txh_accsign;	/* Remote end must provide
						 * these signatures. */
	int			 txh_error;	/* Delayed txh error. */

	int			 txh_delayed;	/* Bitset describing delayed
						 * which txh generators
						 * completed. */
#define TXH_DELAYED_ACCSIGN	0x00000001	/* Accept signs. complete. */
#define TXH_DELAYED_ALL		0x00000001	/* All txh completed. */
};


static void	 free2(void*, void*);
static int	 sv_get(struct net2_cneg_stage1*, uint32_t, struct value**);
static int	 sv_process(struct net2_cneg_stage1*, struct header*, uint32_t);
static int	 sv_expected(struct net2_cneg_stage1*, uint32_t);

static int	 val_errfin(struct value*, int);
static int	 val_setfin(struct value*);
static int	 val_setcancel(struct value*);
static int	 val_init(struct value*);
static int	 val_init_handler(struct value*,
		    int (*)(struct net2_cneg_stage1*, void**, struct header*),
		    void (*)(void*, void*), void*);
static void	 val_deinit(struct value*);
static int	 val_process(struct net2_cneg_stage1*, struct value*,
		    struct header*);

static int	 sets_setfin(struct sets*, uint32_t);
static int	 sets_setcancel(struct sets*, uint32_t);
static int	 sets_elem_init(struct sets_elem*);
static int	 sets_elem_init_handler(struct sets_elem*,
		    int (*)(struct net2_cneg_stage1*, void**, struct header*),
		    void (*)(void*, void*), void*);
static void	 sets_elem_deinit(struct sets_elem*);
static int	 sets_elem_errfin(struct sets*, uint32_t, int);
static int	 sets_elem_testfin(struct sets*, uint32_t);
static int	 sets_get(struct sets*, uint32_t, struct sets_elem**);
static int	 sets_setsize(struct sets*, uint32_t, uint32_t);
static int	 sets_recv(struct net2_cneg_stage1*, struct sets*,
		    struct header*, uint32_t, uint32_t);
static int	 sets_init(struct sets*);
static void	 sets_deinit(struct sets*);

static struct txh
		*txh_new();
static void	 txh_destroy(struct txh*);
static int	 txh_buffer(struct txh*, struct net2_buffer**);


struct name_set;	/* Used in creation of headers
			 * (txh_init, txh_init_name_set). */
static int	 xchange_names(char***, size_t*);
static int	 hash_names(char***, size_t*);
static int	 crypt_names(char***, size_t*);
static int	 sign_names(char***, size_t*);
static int	 txh_init_pver(struct txh_head*, uint32_t,
		    struct txh **made);
static int	 txh_init_name_set(struct txh_head*, const struct name_set*);
static int	 txh_init_fingerprints(struct txh_head*, struct net2_signset*,
		    struct txh**);
static int	 txh_init(struct txh_head*, uint32_t, struct net2_ctx*);


static int	 process_sv_pver(struct net2_cneg_stage1*, void**,
		    struct header*);
static int	 init_sv(struct net2_cneg_stage1*);


static int	 process_set_signature(struct net2_cneg_stage1*, void**,
		    struct header*);
static void	 signature_free2(void*, void*);
static int	 process_set_req_signature(struct net2_cneg_stage1*, void**,
		    struct header*);
static void	 req_signature_free2(void*, void*);
static void	 signset_to_s1ss(struct net2_promise*, struct net2_promise**,
		    size_t, void*);
static void	 txh_acceptable_signatures(void*, void*);
int		 sets_val_init(struct sets*);

static void	 txh_ack(void*, void*);
static void	 txh_nack(void*, void*);
static void	 txh_timeout(void*, void*);
static struct net2_buffer
		*mk_poetry();

static void	 process_all_completions(struct net2_promise*,
		    struct net2_promise**, size_t, void*);


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
free2(void *p, void *unused ILIAS_NET2__unused)
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

	if ((error = val_process(s, v, h)) != 0)
		return error;
	if ((error = val_setfin(v)) != 0)
		return error;

	/* Fire sv_complete if all single-values have completed. */
	if (s->sv_expected != LEN_UNKNOWN &&
	    net2_promise_is_finished(s->sv_complete) ==
	      NET2_PROM_FIN_UNFINISHED &&
	    net2_bitset_allset(&s->received)) {
		if ((error = net2_promise_set_finok(s->sv_complete, NULL,
		    NULL, NULL, 0)) != 0)
			return error;
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
	if (net2_bitset_allset(&s->received) &&
	    net2_promise_is_finished(s->sv_complete) ==
	      NET2_PROM_FIN_UNFINISHED) {
		if ((error = net2_promise_set_finok(s->sv_complete, NULL,
		    NULL, NULL, 0)) != 0)
			return error;
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

/* Initialize value with handler. */
static int
val_init_handler(struct value *v,
    int (*process_fn)(struct net2_cneg_stage1*, void**, struct header*),
    void (*free_fn)(void*, void*), void *free_arg)
{
	val_init(v);

	if ((v->complete = net2_promise_new()) == NULL) {
		val_deinit(v);
		return ENOMEM;
	}

	v->process = process_fn;
	v->free.fn = free_fn;
	v->free.fn_arg = free_arg;
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
val_process(struct net2_cneg_stage1 *s, struct value *v, struct header *h)
{
	int		 error;

	if (v->process == NULL)
		return 0;

	error = (*v->process)(s, &v->data, h);
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

/* Initialize sets element with handler. */
static int
sets_elem_init_handler(struct sets_elem *se,
    int (*process_fn)(struct net2_cneg_stage1*, void**, struct header*),
    void (*free_fn)(void*, void*), void *free_arg)
{
	int			 error;

	if ((error = val_init_handler(&se->val,
	    process_fn, free_fn, free_arg)) != 0)
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
sets_recv(struct net2_cneg_stage1 *s1, struct sets *s, struct header *h,
    uint32_t idx, uint32_t len)
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
	if ((error = val_process(s1, &se->val, h)) != 0)
		return error;

	/* Test if the sets_elem has completed. */
	return sets_elem_testfin(s, idx);
}

/* Initialize sets. */
static int
sets_init(struct sets *s)
{
	int			 error;

	s->rcv = NULL;
	s->len = 0;
	s->expected_len = LEN_UNKNOWN;
	net2_bitset_init(&s->completion_bits);
	if ((s->complete = net2_promise_new()) == NULL)
		return ENOMEM;
	net2_promise_set_running(s->complete);

	if ((error = sets_val_init(s)) != 0) {
		sets_deinit(s);
		return error;
	}

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
	if (net2_cp_init(&cp_header, &out->header, NULL))
		goto fail_1;
	if (net2_txcb_entryq_init(&out->txcbq) != 0)
		goto fail_2;
	out->buf = NULL;
	out->whichq = TXH_WQ_WAIT;
	return out;


fail_3:
	net2_txcb_entryq_deinit(&out->txcbq);
fail_2:
	net2_cp_destroy(&cp_header, &out->header, NULL);
fail_1:
	net2_free(out);
fail_0:
	return NULL;
}

/* Destroy a stage 1 transmit header. */
static void
txh_destroy(struct txh *txh)
{
	net2_txcb_entryq_deinit(&txh->txcbq);
	if (txh->buf != NULL)
		net2_buffer_free(txh->buf);
	net2_cp_destroy(&cp_header, &txh->header, NULL);
	net2_free(txh);
}

/* Retrieve the buffer from a txh. */
static int
txh_buffer(struct txh *txh, struct net2_buffer **payload)
{
	struct net2_buffer	*buf;
	int			 error;

	assert(payload != NULL);

	/* Return cached buffer. */
	if (txh->buf != NULL) {
		*payload = txh->buf;
		return 0;
	}

	/* Create cached buffer. */
	if ((buf = net2_buffer_new()) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	if ((error = encode_header(buf, &txh->header)) != 0)
		goto fail_1;
	*payload = txh->buf = buf;
	return 0;


fail_1:
	net2_buffer_free(buf);
fail_0:
	*payload = NULL;
	assert(error != 0);
	return error;
}


/* Create a new stage1 negotiator. */
ILIAS_NET2_LOCAL struct net2_cneg_stage1*
cneg_stage1_new(uint32_t cn_flags, struct net2_ctx *nctx,
    struct net2_workq *wq)
{
	struct net2_cneg_stage1	*s;
	struct txh		*txh;
	const size_t		 prom_signature_idx =
				    (F_TYPE_SIGNATURE & ~F_SET_ELEMENT);
	struct net2_promise	*prom2[2];

	if ((s = net2_malloc(sizeof(*s))) == NULL)
		goto fail_0;
	if (sets_init(&s->sets) != 0)
		goto fail_1;

	net2_bitset_init(&s->received);
	net2_workq_init_work_null(&s->rts);
	s->sv = NULL;
	s->sv_len = 0;
	s->sv_expected = LEN_UNKNOWN;
	s->cn_flags = cn_flags;
	s->nctx = nctx;
	s->txh_error = 0;
	s->txh_delayed = 0;

	if ((s->sv_complete = net2_promise_new()) == NULL)
		goto fail_2;
	if ((s->tx_complete = net2_promise_new()) == NULL)
		goto fail_3;

	/* Initialize receive handlers. */
	if (init_sv(s) != 0)
		goto fail_4;

	/* Initialize transmit sets. */
	TAILQ_INIT(&s->tx);
	TAILQ_INIT(&s->wait);
	if (txh_init(&s->tx, cn_flags, nctx) != 0)
		goto fail_5;

	/* Create signature list that remote will use to sign messages. */
	if (nctx == NULL || nctx->remote_min == 0) {
		/* Trivial case: no acceptable signatures required. */
		if ((s->rsin = net2_promise_new()) == NULL)
			goto fail_6;
		if (net2_promise_set_finok(s->rsin, NULL,
		    NULL, NULL, 0) != 0) {
			net2_promise_release(s->rsin);
			goto fail_6;
		}
	} else {
		size_t		*count;

		/*
		 * Add count argument: the number of signctx to be used
		 * by the remote endpoint.
		 */
		if ((count = net2_malloc(sizeof(*count))) == NULL)
			goto fail_6;
		*count = (nctx == NULL ? 0 : nctx->remote_min);

		/* Create conversion from F_TYPE_SIGNATURE to rsin. */
		s->rsin = net2_promise_combine(wq, &signset_to_s1ss, count,
		    &s->sets.rcv[prom_signature_idx].val.complete, 1);
		if (s->rsin == NULL) {
			net2_free(count);
			goto fail_6;
		}

		/* Ensure count is freed when rsin is destroyed. */
		net2_promise_destroy_cb(s->rsin, &free2, count, NULL);
	}

	/*
	 * Attach event to signatures receival
	 * which will generate the list of acceptable signatures.
	 */
	if (net2_promise_event_init(&s->txh_accsign, s->rsin,
	    NET2_PROM_ON_FINISH, wq, &txh_acceptable_signatures, s,
	    s->rsin) != 0)
		goto fail_7;

	/*
	 * Create combined rx-completion and all-encompassing completion
	 * promises.
	 */
	prom2[0] = s->sv_complete;
	prom2[1] = s->sets.complete;
	s->rx_complete = net2_promise_combine(wq, &process_all_completions,
	    NULL, prom2, 2);
	if (s->rx_complete == NULL)
		goto fail_8;
	prom2[0] = s->tx_complete;
	prom2[1] = s->rx_complete;
	s->complete = net2_promise_combine(wq, &process_all_completions,
	    NULL, prom2, 2);
	if (s->complete == NULL)
		goto fail_9;

	return s;


fail_10:
	net2_promise_cancel(s->complete);
	net2_promise_release(s->complete);
fail_9:
	net2_promise_cancel(s->rx_complete);
	net2_promise_release(s->rx_complete);
fail_8:
	net2_promise_event_deinit(&s->txh_accsign);
fail_7:
	net2_promise_cancel(s->rsin);
	net2_promise_release(s->rsin);
fail_6:
	while ((txh = TAILQ_FIRST(&s->tx)) != NULL) {
		TAILQ_REMOVE(&s->tx, txh, q);
		txh_destroy(txh);
	}
fail_5:
	/* Destroy the single values. */
	while (s->sv_len-- > 0)
		val_deinit(&s->sv[s->sv_len]);
fail_4:
	net2_promise_release(s->tx_complete);
fail_3:
	net2_promise_release(s->sv_complete);
fail_2:
	net2_bitset_deinit(&s->received);
	net2_workq_deinit_work(&s->rts);
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

	/* Remove acceptable signature txh generator. */
	net2_promise_event_deinit(&s->txh_accsign);
	net2_workq_deinit_work(&s->rts);

	/* Release signature selection promise. */
	net2_promise_cancel(s->rsin);
	net2_promise_release(s->rsin);

	/* Release total completion promise. */
	net2_promise_cancel(s->complete);
	net2_promise_release(s->complete);

	/* Release rx completion promise. */
	net2_promise_cancel(s->rx_complete);
	net2_promise_release(s->rx_complete);

	/* Break the single-value promise. */
	net2_promise_set_cancel(s->sv_complete, 0);
	net2_promise_release(s->sv_complete);

	/* Break the tx completion promise. */
	net2_promise_set_cancel(s->tx_complete, 0);
	net2_promise_release(s->tx_complete);

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
    struct packet_header *ph ILIAS_NET2__unused,
    struct net2_buffer *buf)
{
	struct header		 h;
	int			 error;

	for (;;) {
		if ((error = decode_header(&h, buf)) != 0)
			goto fail_0;
		/* GUARD: stop after decoding the last header. */
		if (h.flags == F_LAST_HEADER) {
			deinit_header(&h);
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

			if ((error = sets_recv(s, &s->sets, &h,
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
		deinit_header(&h);
	}

	return 0;


fail_1:
	deinit_header(&h);
fail_0:
	assert(error != 0);
	return error;
}

/* Stage1 network get_transmit. */
ILIAS_NET2_LOCAL int
cneg_stage1_get_transmit(struct net2_cneg_stage1 *s, struct net2_workq *wq,
    struct net2_buffer *out, struct net2_tx_callback *txcb, size_t maxsz,
    int add_poetry, int empty_poetry)
{
	struct net2_tx_callback	 txcb_tmp;
	struct net2_txcb_entryq	 txcbq_tmp;
	struct net2_buffer	*buf, *fin, *poetry;
	struct txh		*txh;
	int			 error;

	assert(net2_buffer_empty(out));

	/* Insufficient space to transmit anything. */
	if (maxsz <= FINI_LEN)
		return 0;
	if ((error = net2_txcb_init(&txcb_tmp)) != 0)
		return error;
	if ((error = net2_txcb_entryq_init(&txcbq_tmp)) != 0) {
		net2_txcb_deinit(&txcb_tmp);
		return error;
	}

	/* Prepare fin, poetry headers. */
	fin = net2_buffer_new();
	if (add_poetry) {
		if ((poetry = mk_poetry()) == NULL) {
			error = ENOMEM;
			goto fail_0;
		}
	} else
		poetry = NULL;
	if (fin == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	if ((error = encode_header(fin, &header_fini)) != 0)
		goto fail_0;


	/* Append messages. */
	for (;;) {
		txh = TAILQ_FIRST(&s->tx);
		if (txh == NULL)
			break;				/* GUARD */
		assert(txh->whichq == TXH_WQ_TX);

		/*
		 * Acquire txh buffer.
		 * This buffer is owned by the txh and may not be freed.
		 */
		if ((error = txh_buffer(txh, &buf)) != 0)
			goto fail_1;
		assert(buf != NULL);
		if (net2_buffer_length(buf) > maxsz - FINI_LEN)
			break;				/* GUARD */

		/* Create txh callbacks. */
		if ((error = net2_txcb_add(&txcb_tmp, wq, &txcbq_tmp,
		    &txh_timeout, &txh_ack, &txh_nack, &txh_nack,
		    s, txh)) != 0)
			goto fail_1;

		/* Add output. */
		if (net2_buffer_append(out, buf)) {
			error = ENOMEM;
			goto fail_1;
		}

		/* Move txh to wait queue. */
		TAILQ_REMOVE(&s->tx, txh, q);
		TAILQ_INSERT_TAIL(&s->wait, txh, q);
		txh->whichq = TXH_WQ_WAIT;

		/* Merge callbacks. */
		net2_txcb_merge(txcb, &txcb_tmp);
		net2_txcb_entryq_merge(&txh->txcbq, &txcbq_tmp);

		/* Append poetry after first appended packet. */
		if (poetry != NULL) {
			if (net2_buffer_length(poetry) > maxsz - FINI_LEN)
				break;			/* GUARD */
			net2_buffer_append(out, poetry);
			net2_buffer_free(poetry);
			poetry = NULL;
		}
	}

	/* Add poetry to empty message. */
	if (empty_poetry && poetry != NULL &&
	    net2_buffer_length(poetry) > maxsz - FINI_LEN)
		net2_buffer_append(out, poetry); /* Failure is fine. */

finish_out:
	/* Append fin header. */
	if (!net2_buffer_empty(out)) {
		if (net2_buffer_append(out, fin) != 0) {
			error = ENOMEM;
			goto fail_0;
		}
	}

	/* Cleanup. */
	if (poetry != NULL)
		net2_buffer_free(poetry);
	net2_buffer_free(fin);
	net2_txcb_deinit(&txcb_tmp);
	net2_txcb_entryq_deinit(&txcbq_tmp);
	return 0;


fail_1:
	assert(error != 0);
	if (error == ENOMEM && !net2_buffer_empty(out)) {
		/* Attempt recovery. */
		net2_txcb_entryq_clear(&txcbq_tmp, NET2_TXCB_EQ_ALL);
		goto finish_out;
	}
fail_0:
	if (poetry != NULL)
		net2_buffer_free(poetry);
	if (fin != NULL)
		net2_buffer_free(fin);
	net2_txcb_deinit(&txcb_tmp);
	net2_txcb_entryq_deinit(&txcbq_tmp);
	return error;
}


/*
 * Transmit message generation.
 */


/* Create protocol version header. */
static int
txh_init_pver(struct txh_head *list, uint32_t cn_flags,
    struct txh **made)
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
	if (made != NULL)
		*made = h;
	return 0;


fail_1:
	txh_destroy(h);
fail_0:
	if (made != NULL)
		*made = NULL;
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
txh_init_fingerprints(struct txh_head *list, struct net2_signset *set,
    struct txh **after)
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

		if (after != NULL && *after != NULL)
			TAILQ_INSERT_AFTER(list, *after, h, q);
		else
			TAILQ_INSERT_TAIL(list, h, q);
		if (after != NULL)
			*after = h;
	}

	/* Handle empty set. */
	if (count == 0) {
		if ((h = txh_new()) == NULL) {
			error = ENOMEM;
			goto fail_1;
		}
		if ((error = init_header_empty_set(&h->header, F_TYPE_SIGNATURE)) != 0)
			goto fail_2;

		if (after != NULL && *after != NULL)
			TAILQ_INSERT_AFTER(list, *after, h, q);
		else
			TAILQ_INSERT_TAIL(list, h, q);
		if (after != NULL)
			*after = h;
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
	struct txh		*h, *iafter = NULL;

	assert(TAILQ_EMPTY(list));

	/* Value 0: protocol version, flags, stage1 metadata. */
	if ((error = txh_init_pver(list, cn_flags, &iafter)) != 0)
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

	/*
	 * Set 5: signature fingerprints.
	 *
	 * These are put right after pver, so the remote end can quickly
	 * filter them and send back the signatures it wants.
	 */
	if ((error = txh_init_fingerprints(list,
	    (nctx == NULL ? NULL : &nctx->local_signs), &iafter)) != 0)
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


/*
 * Processing of completed values.
 */


/* Receive handler for protocol version. */
static int
process_sv_pver(struct net2_cneg_stage1 *s, void **vptr, struct header *h)
{
	struct net2_cneg_stage1_pver
				*pv;

	/* Allocate storage. */
	if ((pv = net2_malloc(sizeof(*pv))) == NULL)
		return ENOMEM;

	/* Calculate protocol version and options. */
	pv->proto0 = MIN(net2_proto.version, h->payload.version);
	pv->flags = mask_option(pv->proto0, s->cn_flags | h->payload.options);

	/* Assign result. */
	*vptr = pv;
	return 0;
}

/* Single value receive handlers. */
static int
init_sv(struct net2_cneg_stage1 *s)
{
	int			 error;

	/* Allocate. */
	s->sv_len = 1;
	if ((s->sv = net2_calloc(s->sv_len, sizeof(*s->sv))) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}

	/* Initialize pver handling. */
	if ((error = val_init_handler(&s->sv[F_TYPE_PVER],
	    &process_sv_pver, &free2, NULL)) != 0)
		goto fail_1;

	return 0;


fail_2:
	val_deinit(&s->sv[F_TYPE_PVER]);
fail_1:
	net2_free(s->sv);
fail_0:
	s->sv_len = 0;
	assert(error != 0);
	return error;
}


/*
 * Algorithm add function.
 * Silently ignores duplicates.
 */
static int
algorithms_add(struct net2_cneg_stage1_algorithms **algs_ptr, int alg_idx)
{
	struct net2_cneg_stage1_algorithms
				*algs = *algs_ptr;
	int			*arr;
	size_t			 i;

	assert(algs_ptr != NULL);
	assert(alg_idx != -1);

	/* Create empty set. */
	if (algs == NULL) {
		if ((algs = net2_malloc(sizeof(*algs))) == NULL)
			return ENOMEM;
		algs->sz = 0;
		algs->algs = NULL;
		*algs_ptr = algs;
	} else {
		/* Prevent duplicates. */
		for (i = 0; i < algs->sz; i++) {
			if (algs->algs[i] == alg_idx)
				return 0;
		}
	}

	/* Append alg_idx. */
	arr = net2_recalloc(algs->algs, algs->sz + 1, sizeof(algs->algs));
	if (arr == NULL)
		return ENOMEM;
	arr[algs->sz++] = alg_idx;
	algs->algs = arr;
	return 0;
}
/* Algorithms free method. */
static void
algorithms_free2(void *algs_ptr, void *unused ILIAS_NET2__unused)
{
	struct net2_cneg_stage1_algorithms
				*algs = algs_ptr;

	if (algs != NULL) {
		if (algs->algs != NULL)
			net2_free(algs->algs);
		net2_free(algs);
	}
}

/* Process hash set element. */
static int
process_set_hash(struct net2_cneg_stage1 *s ILIAS_NET2__unused,
    void **vptr, struct header *h)
{
	int			 alg_idx;

	/* Find algorithm name. */
	alg_idx = net2_hash_findname(h->payload.string);
	if (alg_idx == -1)
		return 0;
	return algorithms_add((struct net2_cneg_stage1_algorithms**)vptr,
	    alg_idx);
}
/* Process enc set element. */
static int
process_set_crypt(struct net2_cneg_stage1 *s ILIAS_NET2__unused,
    void **vptr, struct header *h)
{
	int			 alg_idx;

	/* Find algorithm name. */
	alg_idx = net2_enc_findname(h->payload.string);
	if (alg_idx == -1)
		return 0;
	return algorithms_add((struct net2_cneg_stage1_algorithms**)vptr,
	    alg_idx);
}
/* Process sign set element. */
static int
process_set_sign(struct net2_cneg_stage1 *s ILIAS_NET2__unused,
    void **vptr, struct header *h)
{
	int			 alg_idx;

	/* Find algorithm name. */
	alg_idx = net2_sign_findname(h->payload.string);
	if (alg_idx == -1)
		return 0;
	return algorithms_add((struct net2_cneg_stage1_algorithms**)vptr,
	    alg_idx);
}
/* Process xchange set element. */
static int
process_set_xchange(struct net2_cneg_stage1 *s ILIAS_NET2__unused,
    void **vptr, struct header *h)
{
	int			 alg_idx;

	/* Find algorithm name. */
	alg_idx = net2_xchange_findname(h->payload.string);
	if (alg_idx == -1)
		return 0;
	return algorithms_add((struct net2_cneg_stage1_algorithms**)vptr,
	    alg_idx);
}
/* Process fingerprint set element. */
static int
process_set_signature(struct net2_cneg_stage1 *s, void **vptr,
    struct header *h)
{
	struct net2_signset	*ss = *vptr;
	struct net2_sign_ctx	*sctx;
	int			 error;

	/* Allocate signset. */
	if (ss == NULL) {
		if ((ss = net2_malloc(sizeof(*ss))) == NULL)
			return ENOMEM;
		if ((error = net2_signset_init(ss)) != 0) {
			net2_free(ss);
			return error;
		}
		*vptr = ss;
	}

	/* Without context, we cannot handle any signatures. */
	if (s->nctx == NULL)
		return 0;

	/* Find known signature context. */
	sctx = net2_signset_find(&s->nctx->remote_signs, h->payload.buf);
	if (sctx == NULL)
		return 0; /* Signature not recognized: ignore. */

	/* Convert reference to ownership. */
	if ((sctx = net2_signctx_clone(sctx)) == NULL)
		return ENOMEM;

	/* Add signature to set. */
	error = net2_signset_insert(ss, sctx);
	if (error != 0)
		net2_signctx_free(sctx);

	/* Ignore duplicates. */
	if (error == EEXIST)
		error = 0;
	return error;
}
/* Fingerprint free helper. */
static void
signature_free2(void *ss, void *unused ILIAS_NET2__unused)
{
	if (ss != NULL) {
		net2_signset_deinit(ss);
		net2_free(ss);
	}
}
/* Process acceptable signatures set. */
static int
process_set_req_signature(struct net2_cneg_stage1 *s, void **vptr,
    struct header *h)
{
	struct net2_sign_ctx	*sctx;
	struct net2_cneg_stage1_req_signs
				*rs = *vptr;
	struct net2_sign_ctx	**arr;

	/* Allocate storage. */
	if (rs == NULL) {
		if ((rs = net2_malloc(sizeof(*rs))) == NULL)
			return ENOMEM;
		rs->sz = 0;
		rs->sctx = NULL;
		*vptr = rs;
	}

	/*
	 * If we have no nctx, we cannot have sent any signatures.
	 * Therefor any signature received is indicative of something
	 * about to go horribly wrong.
	 */
	if (s->nctx == NULL)
		return EINVAL;

	/* Lookup signature. */
	sctx = net2_signset_find(&s->nctx->local_signs, h->payload.buf);
	if (sctx == NULL) {
		/*
		 * Received acceptable signature we don't have.
		 * This should not happen in normal operation.
		 */
		return EINVAL;
	}

	/* Grow storage. */
	if (rs->sz <= h->seq) {
		arr = net2_recalloc(rs->sctx, h->seq + 1, sizeof(*rs->sctx));
		if (arr == NULL)
			return ENOMEM;
		rs->sctx = arr;

		/*
		 * Initalize new elements to NULL.
		 *
		 * Note that we stop short of zeroing index h->seq.
		 * That element will be assigned either a context or NULL
		 * below, by virtue of the net2_signctx_clone() call.
		 */
		while (rs->sz < (size_t)h->seq)
			rs->sctx[rs->sz++] = NULL;
	}

	/* Assign clone of sctx to list. */
	if ((rs->sctx[h->seq] = net2_signctx_clone(sctx)) == NULL)
		return ENOMEM;
	return 0;
}
/* Require signature free function. */
static void
req_signature_free2(void *rs_ptr, void *unused ILIAS_NET2__unused)
{
	struct net2_cneg_stage1_req_signs
				*rs = rs_ptr;

	if (rs != NULL) {
		while (rs->sz-- > 0)
			net2_signctx_free(rs->sctx[rs->sz]);
		net2_free(rs->sctx);
		net2_free(rs);
	}
}

/* Convert received signset to net2_cneg_stage1_req_signs. */
static void
signset_to_s1ss(struct net2_promise *out, struct net2_promise **in,
    size_t insz, void *count_ptr)
{
	size_t			*count = count_ptr;
	struct net2_signset	*ss;
	struct net2_cneg_stage1_req_signs
				*rs;
	uint32_t		 err;
	int			 fin;
	struct net2_signset_entry *sse;

	assert(insz == 1);

	/* Handle promise cancelation. */
	if (net2_promise_is_cancelreq(out)) {
		net2_promise_set_cancel(out, 0);
		return;
	}

	/* Get result. */
	fin = net2_promise_get_result(in[0], (void**)&ss, &err);
	switch (fin) {
	case NET2_PROM_FIN_OK:
		/* Handled outside switch. */
		break;

	default:
		err = EIO;
		/* FALLTHROUGH */
	case NET2_PROM_FIN_ERROR:
		/* Cascade error. */
		net2_promise_set_error(out, err, 0);
		return;
	}

	/* Empty result requested? */
	if (*count == 0) {
		/* Null result. */
		net2_promise_set_finok(out, NULL, NULL, NULL, 0);
		return;
	}
	/* Insufficient? */
	if (ss == NULL || net2_signset_size(ss) < *count) {
		err = EIO;
		goto fail_0;
	}

	/* Allocate result. */
	if ((rs = net2_malloc(sizeof(*rs))) == NULL) {
		err = ENOMEM;
		goto fail_0;
	}
	rs->sz = 0;
	if ((rs->sctx = net2_calloc(*count, sizeof(*rs->sctx))) == NULL) {
		err = ENOMEM;
		goto fail_1;
	}

	/* Add up-to count sign ctx to rs. */
	net2_signset_foreach(sse, ss) {
		if (rs->sz == *count)
			break;
		if ((rs->sctx[rs->sz] = net2_signctx_clone(sse->key)) == NULL)
			goto fail_3;
		rs->sz++;
	}
	assert(rs->sz == *count);

	/* Apply result. */
	net2_promise_set_finok(out, rs, &req_signature_free2, NULL, 0);
	return;


fail_3:
	while (rs->sz-- > 0)
		net2_signctx_free(rs->sctx[rs->sz]);
fail_2:
	net2_free(rs->sctx);
fail_1:
	net2_free(rs);
fail_0:
	assert(err != 0);
	net2_promise_set_error(out, err, 0);
}
/* Create txh for acceptable signatures. */
static void
txh_acceptable_signatures(void *s_ptr, void *prom_ptr)
{
	struct net2_cneg_stage1	*s = s_ptr;
	struct net2_promise	*prom = prom_ptr;
	struct net2_cneg_stage1_req_signs
				*rs;
	uint32_t		 err;
	int			 fin;
	struct txh		*h;
	struct net2_buffer	*fp;
	size_t			 i;
	int			 error;

	/* Acquire result. */
	fin = net2_promise_get_result(prom, (void**)&rs, &err);
	switch (fin) {
	case NET2_PROM_FIN_OK:
		/* Handled below. */
		break;

	default:
		err = EIO;
		/* FALLTHROUGH */
	case NET2_PROM_FIN_ERROR:
		error = err;
		goto fail_0;
	}

	/*
	 * Handle empty set.
	 */
	if (rs == NULL || rs->sz == 0) {
		if ((h = txh_new()) == NULL) {
			error = ENOMEM;
			goto fail_0;
		}

		if ((error = init_header_empty_set(&h->header,
		    F_TYPE_SIGNATURE_ACCEPT)) != 0)
			goto fail_1;
		TAILQ_INSERT_TAIL(&s->tx, h, q);
	} else {
		/* Create txh for each required signature. */
		for (i = 0; i < rs->sz; i++) {
			if ((h = txh_new()) == NULL) {
				error = ENOMEM;
				goto fail_0;
			}

			if ((fp = net2_signctx_fingerprint(rs->sctx[i])) ==
			    NULL) {
				error = ENOMEM;
				goto fail_1;
			}
			error = init_header_bufset(&h->header, i, fp,
			    rs->sz - 1, F_TYPE_SIGNATURE_ACCEPT);
			net2_buffer_free(fp);
			if (error != 0)
				goto fail_1;

			TAILQ_INSERT_TAIL(&s->tx, h, q);
		}
	}

	/* Done. */
	s->txh_delayed |= TXH_DELAYED_ACCSIGN;
	return;


fail_1:
	txh_destroy(h);
fail_0:
	assert(error != 0);
	if (s->txh_error == 0)
		s->txh_error = error;
}

/* Set value receive handlers. */
int
sets_val_init(struct sets *s)
{
#define IDX(_v)	((_v) & ~F_SET_ELEMENT)
	int			 error;

	/* Allocate storage. */
	s->len = 6;
	if ((s->rcv = net2_calloc(s->len, sizeof(*s->rcv))) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}

	/* Create hash algorithm acceptor. */
	if ((error = sets_elem_init_handler(&s->rcv[IDX(F_TYPE_HASH)],
	    &process_set_hash,
	    &algorithms_free2, NULL)) != 0)
		goto fail_1;

	/* Create crypt (enc) algorithm acceptor. */
	if ((error = sets_elem_init_handler(&s->rcv[IDX(F_TYPE_CRYPT)],
	    &process_set_crypt,
	    &algorithms_free2, NULL)) != 0)
		goto fail_2;

	/* Create sign algorithm acceptor. */
	if ((error = sets_elem_init_handler(&s->rcv[IDX(F_TYPE_SIGN)],
	    &process_set_sign,
	    &algorithms_free2, NULL)) != 0)
		goto fail_3;

	/* Create xchange algorithm acceptor. */
	if ((error = sets_elem_init_handler(&s->rcv[IDX(F_TYPE_XCHANGE)],
	    &process_set_xchange,
	    &algorithms_free2, NULL)) != 0)
		goto fail_4;

	/* Create signature (fingerprints) algorithm acceptor. */
	if ((error = sets_elem_init_handler(&s->rcv[IDX(F_TYPE_SIGNATURE)],
	    &process_set_signature,
	    &signature_free2, NULL)) != 0)
		goto fail_5;

	/* Create signature accept (required signatures) algorithm acceptor. */
	if ((error = sets_elem_init_handler(
	    &s->rcv[IDX(F_TYPE_SIGNATURE_ACCEPT)],
	    &process_set_req_signature,
	    &req_signature_free2, NULL)) != 0)
		goto fail_6;

	return 0;


fail_7:
	sets_elem_deinit(&s->rcv[IDX(F_TYPE_SIGNATURE_ACCEPT)]);
fail_6:
	sets_elem_deinit(&s->rcv[IDX(F_TYPE_SIGNATURE)]);
fail_5:
	sets_elem_deinit(&s->rcv[IDX(F_TYPE_XCHANGE)]);
fail_4:
	sets_elem_deinit(&s->rcv[IDX(F_TYPE_SIGN)]);
fail_3:
	sets_elem_deinit(&s->rcv[IDX(F_TYPE_CRYPT)]);
fail_2:
	sets_elem_deinit(&s->rcv[IDX(F_TYPE_HASH)]);
fail_1:
	net2_free(s->rcv);
fail_0:
	s->len = 0;
	assert(error != 0);
	return error;
#undef IDX
}


/* txh acknowledged handler. */
static void
txh_ack(void *s_ptr, void *txh_ptr)
{
	struct net2_cneg_stage1	*s = s_ptr;
	struct txh		*txh = txh_ptr;

	assert(txh->whichq == TXH_WQ_TX || txh->whichq == TXH_WQ_WAIT);
	switch (txh->whichq) {
	case TXH_WQ_TX:
		TAILQ_REMOVE(&s->tx, txh, q);
		break;
	case TXH_WQ_WAIT:
		TAILQ_REMOVE(&s->wait, txh, q);
		break;
	}

	/* Destroy txh. */
	txh_destroy(txh);

	/* Mark tx complete. */
	if (TAILQ_EMPTY(&s->tx) && TAILQ_EMPTY(&s->wait) &&
	    s->txh_delayed == TXH_DELAYED_ALL)
		net2_promise_set_finok(s->tx_complete, NULL, NULL, NULL, 0);
}
/* txh nack handler. */
static void
txh_nack(void *s_ptr, void *txh_ptr)
{
	struct net2_cneg_stage1	*s = s_ptr;
	struct txh		*txh = txh_ptr;

	assert(txh->whichq == TXH_WQ_TX || txh->whichq == TXH_WQ_WAIT);

	switch (txh->whichq) {
	case TXH_WQ_WAIT:
		TAILQ_REMOVE(&s->wait, txh, q);
		TAILQ_INSERT_TAIL(&s->tx, txh, q);
		txh->whichq = TXH_WQ_TX;

		/* There is work to do. */
		net2_workq_activate(&s->rts, 0);
		break;
	}

	/* Moved to wait, clear anything that will move from tx to wait. */
	net2_txcb_entryq_clear(&txh->txcbq,
	    NET2_TXCB_EQ_TIMEOUT | NET2_TXCB_EQ_NACK);
}
/* txh timeout handler. */
static void
txh_timeout(void *s_ptr, void *txh_ptr)
{
	struct net2_cneg_stage1	*s = s_ptr;
	struct txh		*txh = txh_ptr;

	assert(txh->whichq == TXH_WQ_TX || txh->whichq == TXH_WQ_WAIT);

	/* Don't requeue this is there are more timeouts pending. */
	if (!net2_txcb_entryq_empty(&txh->txcbq, NET2_TXCB_EQ_TIMEOUT))
		return;

	switch (txh->whichq) {
	case TXH_WQ_WAIT:
		TAILQ_REMOVE(&s->wait, txh, q);
		TAILQ_INSERT_TAIL(&s->tx, txh, q);
		txh->whichq = TXH_WQ_TX;

		/* There is work to do. */
		net2_workq_activate(&s->rts, 0);
		break;
	}
}

/* Create poetry handshake message. */
static struct net2_buffer*
mk_poetry()
{
	struct net2_buffer	*out;
	struct header		 h;

	/* Cannot generate poetry without data. */
	if (poetry_sz == 0)
		return NULL;

	/* Allocate storage. */
	if ((out = net2_buffer_new()) == NULL)
		goto fail_0;

	/* Initialize poetry header. */
	memset(&h, 0, sizeof(h));
	h.flags = F_POETRY | FT_STRING;
	h.payload.string =
	    (char*)poetry_txts[secure_random_uniform(poetry_sz)];

	/* Encode header into storage. */
	if (encode_header(out, &h) != 0)
		goto fail_1;
	return out;


fail_1:
	net2_buffer_free(out);
fail_0:
	return NULL;
}


/*
 * Process all completions.
 *
 * Puts succes in out if all in completed succesful.
 * EIO error otherwise.
 * Does not copy any results over.
 */
static void
process_all_completions(struct net2_promise *out, struct net2_promise **in,
    size_t insz, void *unused ILIAS_NET2__unused)
{
	size_t			 i;
	int			 fin;

	/* Accept cancelation request. */
	if (net2_promise_is_cancelreq(out)) {
		net2_promise_set_cancel(out, 0);
		return;
	}

	/* Test that each input completed succesful. */
	for (i = 0; i < insz; i++) {
		fin = net2_promise_is_finished(in[i]);
		assert(fin != NET2_PROM_FIN_UNFINISHED);

		if (fin != NET2_PROM_FIN_OK) {
			/* Propagate failure. */
			net2_promise_set_error(out, EIO, 0);
			return;
		}
	}

	/* Propagate succes. */
	net2_promise_set_finok(out, NULL, NULL, NULL, 0);
}


/* Single value receive handlers. */
static __inline struct net2_promise*
get_promise(struct net2_cneg_stage1 *s, unsigned int which)
{
	struct net2_promise	*p;

	if (which & F_SET_ELEMENT) {
		/* Return set element. */
		which &= ~F_SET_ELEMENT;

		if (which >= s->sets.len)
			p = NULL;
		else
			p = s->sets.rcv[which].val.complete;
	} else {
		/* Return single value element. */
		if (which >= s->sv_len)
			p = NULL; /* Element not present. */
		else
			p = s->sv[which].complete;
	}

	if (p != NULL)
		net2_promise_ref(p);
	return p;
}
/* Return promise for pver. */
ILIAS_NET2_LOCAL struct net2_promise*
cneg_stage1_get_pver(struct net2_cneg_stage1 *s)
{
	return get_promise(s, F_TYPE_PVER);
}
/* Return promise for xchange. */
ILIAS_NET2_LOCAL struct net2_promise*
cneg_stage1_get_xchange(struct net2_cneg_stage1 *s)
{
	return get_promise(s, F_TYPE_XCHANGE);
}
/* Return promise for hash. */
ILIAS_NET2_LOCAL struct net2_promise*
cneg_stage1_get_hash(struct net2_cneg_stage1 *s)
{
	return get_promise(s, F_TYPE_HASH);
}
/* Return promise for crypt (enc). */
ILIAS_NET2_LOCAL struct net2_promise*
cneg_stage1_get_crypt(struct net2_cneg_stage1 *s)
{
	return get_promise(s, F_TYPE_CRYPT);
}
/* Return promise for sign. */
ILIAS_NET2_LOCAL struct net2_promise*
cneg_stage1_get_sign(struct net2_cneg_stage1 *s)
{
	return get_promise(s, F_TYPE_SIGN);
}
/* Return promise for remote advertised signatures. */
ILIAS_NET2_LOCAL struct net2_promise*
cneg_stage1_get_advertised_signatures(struct net2_cneg_stage1 *s)
{
	return get_promise(s, F_TYPE_SIGNATURE);
}
/* Return promise for signatures remote is to send us. */
ILIAS_NET2_LOCAL struct net2_promise*
cneg_stage1_get_accepted_signatures(struct net2_cneg_stage1 *s)
{
	struct net2_promise	*p;

	p = s->rsin;
	if (p != NULL)
		net2_promise_ref(p);
	return p;
}
/* Return promise for signatures remote requires us to send. */
ILIAS_NET2_LOCAL struct net2_promise*
cneg_stage1_get_transmit_signatures(struct net2_cneg_stage1 *s)
{
	return get_promise(s, F_TYPE_SIGNATURE_ACCEPT);
}
/* Return promise fired when everything has been succesfully sent. */
ILIAS_NET2_LOCAL struct net2_promise*
cneg_stage1_tx_complete(struct net2_cneg_stage1 *s)
{
	struct net2_promise	*p;

	p = s->tx_complete;
	if (p != NULL)
		net2_promise_ref(p);
	return p;
}
/* Return promise fired when everything has been succesfully received. */
ILIAS_NET2_LOCAL struct net2_promise*
cneg_stage1_rx_complete(struct net2_cneg_stage1 *s)
{
	struct net2_promise	*p;

	p = s->rx_complete;
	if (p != NULL)
		net2_promise_ref(p);
	return p;
}
/* Return promise fired when everything completes. */
ILIAS_NET2_LOCAL struct net2_promise*
cneg_stage1_complete(struct net2_cneg_stage1 *s)
{
	struct net2_promise	*p;

	p = s->complete;
	if (p != NULL)
		net2_promise_ref(p);
	return p;
}
