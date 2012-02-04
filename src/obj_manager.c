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
#include <ilias/net2/obj_manager.h>
#include <ilias/net2/obj_window.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/evbase.h>
#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/mutex.h>
#include <ilias/net2/cp.h>
#include <bsd_compat/error.h>
#include <bsd_compat/sysexits.h>
#include <event2/event.h>
#include "obj_manager_proto.h"
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#define OM_ATTACHED	0x80000000	/* Objman has been attached. */

/*
 * Window group.
 */
struct net2_objman_group {
	uint32_t		 id;

	RB_ENTRY(net2_objman_group)
				 tree;

	/* TODO: implement group moving. */
	/* TODO: implement forwarding when group moves. */

	struct net2_objwin	 scheduler;	/* Request scheduler. */
	struct net2_objwin_stub	*transmittor;	/* Request transmittor. */

	/* TODO: implement object set. */
	/* TODO: add list of command invocations. */
};

/*
 * Remote method invocation ticket (transmittor endpoint).
 */
struct net2_objman_tx_ticket {
	uint32_t		 seq;		/* Ticket sequence. */
	uint32_t		 group;		/* Remote group ID. */
	struct net2_objmanager	*objman;	/* Object manager. */
	int			 finish_how;	/* Finish how. */

	RB_ENTRY(net2_objman_tx_ticket)
				 id_tree;	/* ID set. */

	const struct command_param
				*result_type;	/* Type of result. */
	void			*result;	/* Result of command. */
	struct net2_objwin_tx	*objwin_tx;	/* Objwin data. */

	struct {
		net2_objman_return_cb	 fn;	/* Result callback. */
		void			*arg;	/* Result callback arg. */
		struct net2_evbase	*ev;	/* Callback evbase. */
	}			 cb;		/* Callback spec. */

	size_t			 refcnt;	/* Reference counter. */
	struct net2_mutex	*mtx;		/* Guard. */
};


/* Compare two groups on ID. */
static __inline int
group_cmp(struct net2_objman_group *g1, struct net2_objman_group *g2)
{
	return (g1->id < g2->id ? -1 : g1->id > g2->id);
}

/* Compare tx ticket on ID. */
static __inline int
ttx_cmp(struct net2_objman_tx_ticket *t1, struct net2_objman_tx_ticket *t2)
{
	int			cmp;

	cmp = (t1->group < t2->group ? -1 : t1->group > t2->group);
	if (cmp == 0)
		cmp = (t1->seq < t2->seq ? -1 : t1->seq > t2->seq);
	return cmp;
}

RB_PROTOTYPE_STATIC(net2_objman_groups, net2_objman_group, tree, group_cmp);
RB_GENERATE_STATIC(net2_objman_groups, net2_objman_group, tree, group_cmp);

RB_PROTOTYPE_STATIC(net2_objman_ttx, net2_objman_tx_ticket, id_tree, ttx_cmp);
RB_GENERATE_STATIC(net2_objman_ttx, net2_objman_tx_ticket, id_tree, ttx_cmp);


static int	 net2_objmanager_attach(struct net2_acceptor_socket*,
		    struct net2_acceptor *self);
static void	 net2_objmanager_detach(struct net2_acceptor_socket*,
		    struct net2_acceptor *self);
static void	 net2_objmanager_accept(struct net2_acceptor*,
		    struct net2_buffer*);

static void	 kill_group(struct net2_objman_group*);
static void	 rm_group(struct net2_objmanager*, struct net2_objman_group*);
static void	 kill_tx_ticket(struct net2_objman_tx_ticket*);
static struct net2_objman_group
		*create_group(struct net2_objmanager*, uint32_t);
static struct net2_objman_group
		*get_group(struct net2_objmanager*, uint32_t, int, int*);
static void	 unused_group_id(struct net2_objmanager*);

/*
 * Functions handling different categories of received information.
 */
static int	 accept_request(struct net2_objmanager*,
		    struct net2_encdec_ctx*, struct net2_objman_packet*);
static int	 accept_supersede(struct net2_objmanager*,
		    struct net2_encdec_ctx*, struct net2_objman_packet*);
static int	 accept_response(struct net2_objmanager*,
		    struct net2_encdec_ctx*, struct net2_objman_packet*);
static int	 accept_objman(struct net2_objmanager*,
		    struct net2_encdec_ctx*, struct net2_objman_packet*);


/* Run group event info. */
struct run_group_ev {
	struct net2_objwin_recv		*recv;
	struct event			*self;
	struct net2_objmanager		*m;
	struct net2_objman_group	*g;
};

static struct event	*run_group_ev_new(struct net2_objmanager*,
			    struct net2_objman_group*,
			    struct net2_objwin_recv*);
static void		 run_group_ev_free(struct run_group_ev*);


static const struct net2_acceptor_fn net2_objmanager_cafn = {
	net2_objmanager_detach,
	net2_objmanager_attach,
	net2_objmanager_accept,
	NULL /* get_transmit */
};


/*
 * Initialize object manager.
 */
static int
net2_objmanager_init(struct net2_objmanager *m)
{
	if (net2_acceptor_init(&m->base, &net2_objmanager_cafn))
		goto fail_0;
	m->evbase = NULL;
	RB_INIT(&m->groups);
	RB_INIT(&m->tx_tickets);
	if (net2_pvlist_init(&m->pvlist))
		goto fail_1;
	m->refcnt = 1;
	if ((m->mtx = net2_mutex_alloc()) == NULL)
		goto fail_2;
	return 0;

fail_2:
	net2_pvlist_deinit(&m->pvlist);
fail_1:
	net2_acceptor_deinit(&m->base);
fail_0:
	return -1;
}

/* Destroy object manager. */
static void
net2_objmanager_deinit(struct net2_objmanager *m)
{
	struct net2_objman_group	*g;
	struct net2_objman_tx_ticket	*ttx;

	while ((g = RB_ROOT(&m->groups)) != NULL)
		kill_group(g);
	while ((ttx = RB_ROOT(&m->tx_tickets)) != NULL)
		kill_tx_ticket(ttx);
	if (m->evbase)
		net2_evbase_release(m->evbase);
	net2_pvlist_deinit(&m->pvlist);
}

/* Attach objmanager to connection. */
static int
net2_objmanager_attach(struct net2_acceptor_socket *sock,
    struct net2_acceptor *self)
{
	struct net2_objmanager	*m;

	m = (struct net2_objmanager*)self;
	net2_mutex_lock(m->mtx);

	if (m->flags & OM_ATTACHED)
		goto fail;
	m->flags |= OM_ATTACHED;

	if (net2_acceptor_socket_pvlist(sock, &m->pvlist))
		goto fail;

	m->evbase = net2_acceptor_socket_evbase(sock);
	net2_evbase_ref(m->evbase);

	m->refcnt++;
	net2_mutex_unlock(m->mtx);
	return 0;

fail:
	net2_mutex_unlock(m->mtx);
	return -1;
}

/* Detach objmanager from connection. */
static void
net2_objmanager_detach(struct net2_acceptor_socket *sock,
    struct net2_acceptor *self)
{
	struct net2_objmanager	*m;

	m = (struct net2_objmanager*)self;
	net2_objmanager_release(m);
}

/* Accept incoming data from connection. */
static void
net2_objmanager_accept(struct net2_acceptor *self,
    struct net2_buffer *buf)
{
	struct net2_objmanager		*m;
	struct net2_objman_packet	 packet;
	struct net2_encdec_ctx		*ctx;

	m = (struct net2_objmanager*)self;
	/* Prepare decoding context. */
	if ((ctx = net2_encdec_ctx_newobjman(m)) != NULL)
		goto fail_0;

	/* Decode all messages. */
	while (!net2_buffer_empty(buf)) {
		if (n2omp_decode(ctx, &packet, buf))
			goto fail_1;
		switch ((packet.mh.flags & OBJMAN_PH_IS_MASK) >>
		    OBJMAN_PH_IS_MASK_SHIFT) {

		case OBJMAN_PH_IS_REQUEST >> OBJMAN_PH_IS_MASK_SHIFT:
			if (accept_request(m, ctx, &packet))
				goto fail_1;
			break;

		case OBJMAN_PH_IS_SUPERSEDE >> OBJMAN_PH_IS_MASK_SHIFT:
			if (accept_supersede(m, ctx, &packet))
				goto fail_1;
			break;

		case OBJMAN_PH_IS_RESPONSE >> OBJMAN_PH_IS_MASK_SHIFT:
			if (accept_response(m, ctx, &packet))
				goto fail_1;
			break;

		case OBJMAN_PH_IS_OBJMAN >> OBJMAN_PH_IS_MASK_SHIFT:
			if (accept_objman(m, ctx, &packet))
				goto fail_1;
			break;

		default:
			goto fail_1;
		}
	}

	/* Release encoding context. */
	net2_encdec_ctx_release(ctx);
	return;

fail_1:
	net2_encdec_ctx_rollback(ctx);
	net2_encdec_ctx_release(ctx);
fail_0:
	/* TODO: kill connection since delivery failed. */
	return;
}

/* Create a new obj manager. */
ILIAS_NET2_EXPORT struct net2_objmanager*
net2_objmanager_new()
{
	struct net2_objmanager	*m;

	if ((m = malloc(sizeof(*m))) == NULL)
		goto fail_0;
	if (net2_objmanager_init(m))
		goto fail_1;
	return m;

fail_1:
	free(m);
fail_0:
	return NULL;
}

/* Reference an objmanager. */
ILIAS_NET2_EXPORT void
net2_objmanager_ref(struct net2_objmanager *m)
{
	net2_mutex_lock(m->mtx);
	m->refcnt++;
	assert(m->refcnt > 0);
	net2_mutex_unlock(m->mtx);
}

/* Release an objmanager. */
ILIAS_NET2_EXPORT void
net2_objmanager_release(struct net2_objmanager *m)
{
	int		do_free;

	net2_mutex_lock(m->mtx);
	assert(m->refcnt > 0);
	do_free = (--m->refcnt == 0);
	net2_mutex_unlock(m->mtx);

	if (do_free) {
		net2_objmanager_deinit(m);
		free(m);
	}
}

/* Release window group. */
static void
kill_group(struct net2_objman_group *g)
{
	n2ow_deinit(&g->scheduler);
	n2ow_release_stub(g->transmittor);
	free(g);
}

/* Release tx ticket. */
static void
kill_tx_ticket(struct net2_objman_tx_ticket *ttx)
{
	struct net2_encdec_ctx	*c;
	int			 error;

	if (ttx->cb.fn != NULL)
		assert(0); /* TODO: invoke callback with "destroyed" error. */

	if (ttx->cb.ev != NULL)
		net2_evbase_release(ttx->cb.ev);
	if (ttx->result) {
		c = net2_encdec_ctx_newobjman(ttx->objman);
		if (c == NULL)
			assert(0);	/* TODO: handle failure? */
		error = net2_cp_destroy_alloc(c, ttx->result_type,
		    ttx->result, NULL);
		if (error)
			net2_encdec_ctx_rollback(c);
		net2_encdec_ctx_release(c);
		assert(error == 0);	/* TODO: handle error */
	}
	free(ttx);
}

/* Release structs held in group-scheduler. */
static void
scheduler_release(void *p)
{
	net2_invocation_ctx_free((struct net2_invocation_ctx*)p);
}

/* Create a new group in the object manager. */
static struct net2_objman_group*
create_group(struct net2_objmanager *m, uint32_t id)
{
	struct net2_objman_group	*g;

	if ((g = malloc(sizeof(*g))) == NULL)
		goto fail_0;
	g->id = id;
	if (n2ow_init(&g->scheduler, &scheduler_release))
		goto fail_1;
	if ((g->transmittor = n2ow_new_stub()) == NULL)
		goto fail_2;

	if (RB_INSERT(net2_objman_groups, &m->groups, g) != NULL)
		goto fail_3;

	return g;

fail_3:
	n2ow_release_stub(g->transmittor);
fail_2:
	n2ow_deinit(&g->scheduler);
fail_1:
	free(g);
fail_0:
	return NULL;
}

/* Remove group from manager. */
static void
rm_group(struct net2_objmanager *m, struct net2_objman_group *g)
{
	RB_REMOVE(net2_objman_groups, &m->groups, g);
	kill_group(g);
}

/* Get a group from the object manager. */
static struct net2_objman_group*
get_group(struct net2_objmanager *m, uint32_t id, int create, int *created)
{
	struct net2_objman_group	*g, search;

	/* Didn't create a group. */
	if (created != NULL)
		*created = 0;

	search.id = id;
	g = RB_FIND(net2_objman_groups, &m->groups, &search);
	if (g == NULL && create) {
		g = create_group(m, id);
		/* Mark created bit. */
		if (created != NULL && g != NULL)
			*created = 1;
	}
	return g;
}


static void
run_group_fin(int fd, short what, void *cbarg)
{
	struct run_group_ev		*arg;
	struct net2_invocation_ctx	*ctx;
	int				 error;
	int				 fin;

	arg = cbarg;
	ctx = n2ow_data_ptr(arg->recv);
	assert(ctx != NULL);

	/* Find out how it finished. */
	fin = net2_invocation_ctx_finished(ctx);
	switch (fin) {
	case NET2_IVCTX_FIN_UNFINISHED:
		abort();	/* Programmer error. */
		break;
	case NET2_IVCTX_FIN_OK:
		assert(0);	/* TODO: implement */
		break;
	case NET2_IVCTX_FIN_CANCEL:
		assert(0);	/* TODO: implement */
		break;
	case NET2_IVCTX_FIN_ERROR:
		assert(0);	/* TODO: implement */
		break;
	case NET2_IVCTX_FIN_FAIL:
		assert(0);	/* TODO: implement */
		break;
	default:
		errx(EX_SOFTWARE, "%s: "
		    "unrecognized net2_invocation_ctx fin state: %d",
		    __FUNCTION__, fin);
		assert(0);	/* TODO: kill connection. */
	}

	/* Inform group scheduler of command finish. */
	n2ow_finished(arg->recv);
	/* Release callback data. */
	run_group_ev_free(arg);
}

/* Run all runnable invocations in the given group. */
static int
run_group(struct net2_objmanager *m, struct net2_objman_group *g)
{
	struct net2_objwin_recv		*recv;
	struct net2_invocation_ctx	*invocation;
	int				 error;
	struct event			*finish_cb;

	/* Unable to run: invalid state. */
	if (m->evbase == NULL)
		return EINVAL;

	while ((recv = n2ow_get_pending(&g->scheduler)) != NULL) {
		finish_cb = run_group_ev_new(m, g, recv);
		if (finish_cb == NULL) {
			n2ow_finished(recv); /* TODO: should undo pending change. */
			return ENOMEM;
		}

		invocation = n2ow_data_ptr(recv);
		assert(invocation != NULL);

		error = net2_invocation_ctx_run(invocation);
		if (error != 0) {
			n2ow_finished(recv);
			run_group_ev_free(event_get_callback_arg(finish_cb));
			return error;
		}
	}

	return 0;
}

/* Create a new run group event info. */
static struct event*
run_group_ev_new(struct net2_objmanager *m, struct net2_objman_group *g,
    struct net2_objwin_recv *recv)
{
	struct run_group_ev		*ev;

	if (m->evbase == NULL)
		return NULL;
	if ((ev = malloc(sizeof(*ev))) == NULL)
		return NULL;
	ev->recv = recv;
	ev->m = m;
	ev->g = g;
	ev->self = event_new(m->evbase->evbase, -1, EV_TIMEOUT,
	    &run_group_fin, recv);
	return ev->self;
}

/* Free a run group event info. */
static void
run_group_ev_free(struct run_group_ev *ev)
{
	if (ev == NULL)
		return;

	event_free(ev->self);
	free(ev);
}


/*
 * Accept command invocation request (OBJMAN_PH_IS_REQUEST).
 *
 * Will claim all resources held by packet regardless of succes or failure.
 */
static int
accept_request(struct net2_objmanager *m, struct net2_encdec_ctx *c,
    struct net2_objman_packet *packet)
{
	struct net2_objman_group	*g;
	uint32_t			 seq, barrier;
	int				 accept;
	struct net2_invocation_ctx	*invocation;
	int				 error = -1;	/* Default: fail. */
	int				 g_is_new;

	/* Lookup group, sequence and barrier. */
	if ((g = get_group(m, packet->request.invocation.group, 1,
	    &g_is_new)) == NULL)
		goto fail_0;
	seq = packet->request.invocation.seq;
	barrier = packet->request.invocation.barrier;

	/* Create invocation context for this request. */
	if ((invocation = net2_invocation_ctx_new(m, packet->request.method,
	    packet->request.in_param)) == NULL)
		goto fail_1;
	packet->request.in_param = NULL;	/* Now owned by invocation. */

	/* Ask the scheduler to accept this message. */
	if (n2ow_receive(&g->scheduler, barrier, seq, &accept, invocation))
		goto fail_2;
	if (!accept) {
		/*
		 * The packet was not accepted.
		 *
		 * This may happen because the packet was already superseded,
		 * was received twice or has already been processed.
		 * Therefore this is not an error condition.
		 *
		 * Failure path will release unused invocation.
		 */
		error = 0;
		goto fail_2;
	} else
		invocation = NULL;	/* Now owned by scheduler. */

	run_group(m, g);
	error = 0;

fail_2:
	if (invocation)
		net2_invocation_ctx_free(invocation);
fail_1:
	if (error) {
		/* kill group iff it was created */
		if (g_is_new)
			rm_group(m, g);
	}
fail_0:
	if (packet->request.in_param) {
		net2_cp_destroy_alloc(c, packet->request.method->cm_in,
		    &packet->request.in_param, NULL);
	}
	return error;
}
/*
 * Accept command invocation supersede (OBJMAN_PH_IS_SUPERSEDE).
 *
 * Will claim all resources held by packet regardless of succes or failure.
 */
static int
accept_supersede(struct net2_objmanager *m, struct net2_encdec_ctx *c,
    struct net2_objman_packet *packet)
{
	struct net2_objman_group	*g;
	uint32_t			 seq, barrier;
	int				 accept;
	int				 error = -1;	/* Default: fail. */
	int				 g_is_new;
	int				 ow_err;
	struct net2_invocation_ctx	*invocation;

	/* Lookup group, sequence and barrier. */
	if ((g = get_group(m, packet->request.invocation.group, 1,
	    &g_is_new)) == NULL)
		goto fail_0;
	seq = packet->request.invocation.seq;
	barrier = packet->request.invocation.barrier;

	/* Supersede the message. */
	ow_err = n2ow_supersede(&g->scheduler, barrier, seq, &accept,
	    (void**)&invocation);
	switch (ow_err) {
	case 0:
		if (!accept) {
			error = 0;
			goto fail_1; /* Unaccepted -> rollback. */
		}
		break;
	case EBUSY:
		/*
		 * Inform the invocation that was cancelled.
		 * Implementation defined if this has any effect.
		 */
		if (invocation != NULL)
			net2_invocation_ctx_cancel(invocation);
		break;
	default:
		goto fail_1;
	}

	run_group(m, g);
	return 0;

fail_1:
	if (error) {
		/* kill group iff it was created */
		if (g_is_new)
			rm_group(m, g);
	}
fail_0:
	return error;
}
/*
 * Accept command invocation response (OBJMAN_PH_IS_RESPONSE).
 *
 * Will claim all resources held by packet regardless of succes or failure.
 */
static int
accept_response(struct net2_objmanager *m, struct net2_encdec_ctx *c,
    struct net2_objman_packet *packet)
{
	struct net2_objman_response	*resp;
	struct net2_objman_tx_ticket	*tx;
	int				 error = -1;	/* Default: fail. */

	tx = packet->response.tx;	/* Looked up by decoder. */
	assert(tx != NULL);

	/* Prevent duplicate delivery. */
	if (tx->finish_how != 0) {
		error = 0;
		goto fail_0;
	}

	/* Claim result, unless a previous result was claimed. */
	tx->finish_how = packet->response.finish_how;
	tx->result = packet->response.result;
	packet->response.result = NULL;

	assert(0); /* TODO: future is done */

	error = 0;

fail_0:
	if (packet->response.result) {
		net2_cp_destroy_alloc(c, packet->response.result_type,
		    &packet->response.result, NULL);
	}
	return error;
}
/*
 * Accept objman management message (OBJMAN_PH_IS_OBJMAN).
 *
 * Will claim all resources held by packet regardless of succes or failure.
 */
static int
accept_objman(struct net2_objmanager *m, struct net2_encdec_ctx *c,
    struct net2_objman_packet *packet)
{
	assert(0);	/* TODO: implement */
	return 0;
}


/* Locate tx ticket based on group and sequence. */
ILIAS_NET2_LOCAL struct net2_objman_tx_ticket*
net2_objmanager_find_tx_ticket(struct net2_objmanager *m,
    uint32_t seq, uint32_t group)
{
	struct net2_objman_tx_ticket	*result, search;

	search.seq = seq;
	search.group = group;

	net2_mutex_lock(m->mtx);
	result = RB_FIND(net2_objman_ttx, &m->tx_tickets, &search);
	net2_mutex_unlock(m->mtx);
	return result;
}

/* Return the type of a tx ticket. */
ILIAS_NET2_LOCAL const struct command_param*
net2_objman_ttx_type(struct net2_objman_tx_ticket *tx)
{
	return tx->result_type;
}


static int
n2om_input_to_buffer(struct net2_buffer **buf, struct net2_objmanager *m,
    const struct command_method *cm, const void *input)
{
	int				 error;
	struct net2_encdec_ctx		*c;

	/* Allocate destination buffer. */
	if ((*buf = net2_buffer_new()) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	/* Allocate encoding context. */
	if ((c = net2_encdec_ctx_newobjman(m)) == NULL) {
		error = ENOMEM;
		goto fail_1;
	}

	/* Encode argument. */
	if ((error = net2_cp_encode(c, cm->cm_in, *buf, input, NULL)) != 0)
		goto fail_2;

	/* Release encoding context. */
	net2_encdec_ctx_release(c);

	return 0;

fail_2:
	net2_encdec_ctx_rollback(c);
	net2_encdec_ctx_release(c);
fail_1:
	net2_buffer_free(*buf);
fail_0:
	*buf = NULL;
	return error;
}

/* Invoke remote method. */
ILIAS_NET2_EXPORT int
net2_objman_rmi(struct net2_objmanager *m, struct net2_objman_group *g,
    const struct command_method *cm, const void *in_params,
    net2_objman_return_cb cb, void *cb_arg, struct net2_evbase *evbase,
    struct net2_objman_tx_ticket **txptr)
{
	int				 error;
	struct net2_buffer		*input;
	struct net2_objman_tx_ticket	*tx;
	int				 tx_flags;

	/* Calculate objwin_stub flags. */
	tx_flags = 0;
	if (cm->cm_flags & CM_BARRIER_PRE)
		tx_flags |= N2OW_TXADD_BARRIER_PRE;
	if (cm->cm_flags & CM_BARRIER_POST)
		tx_flags |= N2OW_TXADD_BARRIER_POST;

	/*
	 * Create a ticket.
	 */
	if ((tx = malloc(sizeof(*tx))) == NULL)
		return ENOMEM;
	/* tx->seq is undefined (chosen by transmittor */
	tx->group = g->id;
	tx->objman = m;
	tx->finish_how = NET2_IVCTX_FIN_UNFINISHED;
	tx->result_type = cm->cm_out;
	tx->result = NULL;
	tx->objwin_tx = NULL;	/* tx->objwin_tx is set below. */
	tx->cb.fn = cb;
	tx->cb.arg = cb_arg;
	tx->cb.ev = evbase;
	tx->refcnt = 1;
	if ((tx->mtx = net2_mutex_alloc()) == NULL) {
		free(tx);
		return ENOMEM;
	}

	/* Calculate input. */
	if (cm->cm_in == NULL)
		input = NULL;
	else if ((error = n2om_input_to_buffer(&input, m, cm, in_params)) != 0)
		goto fail_0;

	/* Expose ticket to caller. */
	if (txptr != NULL) {
		*txptr = tx;
		tx->refcnt++;	/* No locking: not yet shared. */
	}

	/* Push ticket into transmittor. */
	net2_mutex_lock(m->mtx);
	if ((tx->objwin_tx = n2ow_tx_add(g->transmittor, input,
	    tx_flags)) == NULL) {
		net2_mutex_unlock(m->mtx);
		error = ENOMEM;
		goto fail_1;
	}
	net2_mutex_unlock(m->mtx);

	return 0;

fail_1:
	net2_buffer_free(input);
fail_0:
	net2_mutex_free(tx->mtx);
	free(tx);
	if (txptr != NULL)
		*txptr = NULL;
	return error;
}

/* Release reference to tx ticket. */
ILIAS_NET2_EXPORT void
net2_objman_rmi_release(struct net2_objman_tx_ticket *tx)
{
	int		 do_free;

	net2_mutex_lock(tx->mtx);
	assert(tx->refcnt > 0);
	do_free = (--tx->refcnt == 0);
	net2_mutex_unlock(tx->mtx);

	if (do_free)
		kill_tx_ticket(tx);
}
