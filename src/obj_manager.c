#include <ilias/net2/obj_manager.h>
#include <ilias/net2/obj_window.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/evbase.h>
#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/mutex.h>
#include <ilias/net2/cp.h>
#include "obj_manager_proto.h"
#include <stdlib.h>
#include <assert.h>

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
	uint32_t		 id;		/* Ticket ID. */
	int			 flags;		/* Flags. */

	RB_ENTRY(net2_objman_tx_ticket)
				 id_tree;	/* ID set. */

	const struct command_invocation
				*invocation;	/* Invoked command. */

	struct net2_buffer	*in_params;	/* Encoded input. */

	struct {
		net2_objman_return_cb	 fn;	/* Result callback. */
		void			*arg;	/* Result callback arg. */
		struct net2_evbase	*ev;	/* Callback evbase. */
	}			 cb;		/* Callback spec. */
};

/*
 * Remote method invocation ticket (receiver endpoint).
 */
struct net2_objman_rx_ticket {
	uint32_t		 id;		/* Ticket ID. */
	int			 flags;		/* Flags. */

	RB_ENTRY(net2_objman_rx_ticket)
				 id_tree;	/* ID set. */

	const struct command_invocation
				*invocation;	/* Invoked command. */

	void			*in_params;	/* Decoded input. */
	struct net2_buffer	*out_params;	/* Encoded output. */
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
	return (t1->id < t2->id ? -1 : t1->id > t2->id);
}
/* Compare rx ticket on ID. */
static __inline int
trx_cmp(struct net2_objman_rx_ticket *t1, struct net2_objman_rx_ticket *t2)
{
	return (t1->id < t2->id ? -1 : t1->id > t2->id);
}

RB_PROTOTYPE_STATIC(net2_objman_groups, net2_objman_group, tree, group_cmp);
RB_GENERATE_STATIC(net2_objman_groups, net2_objman_group, tree, group_cmp);

RB_PROTOTYPE_STATIC(net2_objman_ttx, net2_objman_tx_ticket, id_tree, ttx_cmp);
RB_GENERATE_STATIC(net2_objman_ttx, net2_objman_tx_ticket, id_tree, ttx_cmp);
RB_PROTOTYPE_STATIC(net2_objman_trx, net2_objman_rx_ticket, id_tree, trx_cmp);
RB_GENERATE_STATIC(net2_objman_trx, net2_objman_rx_ticket, id_tree, trx_cmp);


static int	 net2_objmanager_attach(struct net2_connection*,
		    struct net2_conn_acceptor *self);
static void	 net2_objmanager_detach(struct net2_connection*,
		    struct net2_conn_acceptor *self);
static void	 net2_objmanager_accept(struct net2_conn_acceptor*,
		    struct packet_header*, struct net2_buffer**);

static void	 kill_group(struct net2_objman_group*);
static void	 rm_group(struct net2_objmanager*, struct net2_objman_group*);
static void	 kill_tx_ticket(struct net2_objman_tx_ticket*);
static void	 kill_rx_ticket(struct net2_objman_rx_ticket*);
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


static const struct net2_conn_acceptor_fn net2_objmanager_cafn = {
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
	m->base.ca_conn = NULL;
	m->base.ca_fn = &net2_objmanager_cafn;
	RB_INIT(&m->groups);
	RB_INIT(&m->tx_tickets);
	RB_INIT(&m->rx_tickets);
	if (net2_pvlist_init(&m->pvlist))
		goto fail_0;
	m->refcnt = 1;
	if ((m->mtx = net2_mutex_alloc()) == NULL)
		goto fail_1;
	return 0;

fail_1:
	net2_pvlist_deinit(&m->pvlist);
fail_0:
	return -1;
}

/* Destroy object manager. */
static void
net2_objmanager_deinit(struct net2_objmanager *m)
{
	struct net2_objman_group	*g;
	struct net2_objman_tx_ticket	*ttx;
	struct net2_objman_rx_ticket	*trx;

	while ((g = RB_ROOT(&m->groups)) != NULL)
		kill_group(g);
	while ((ttx = RB_ROOT(&m->tx_tickets)) != NULL)
		kill_tx_ticket(ttx);
	while ((trx = RB_ROOT(&m->rx_tickets)) != NULL)
		kill_rx_ticket(trx);
	net2_pvlist_deinit(&m->pvlist);
}

/* Attach objmanager to connection. */
static int
net2_objmanager_attach(struct net2_connection *conn,
    struct net2_conn_acceptor *self)
{
	struct net2_objmanager	*m;

	m = (struct net2_objmanager*)self;
	net2_mutex_lock(m->mtx);

	if (m->flags & OM_ATTACHED)
		goto fail;
	m->flags |= OM_ATTACHED;

	if (net2_pvlist_add(&m->pvlist, &net2_proto, conn->n2c_version))
		goto fail;

	m->refcnt++;
	net2_mutex_unlock(m->mtx);
	return 0;

fail:
	net2_mutex_unlock(m->mtx);
	return -1;
}

/* Detach objmanager from connection. */
static void
net2_objmanager_detach(struct net2_connection *conn,
    struct net2_conn_acceptor *self)
{
	struct net2_objmanager	*m;

	m = (struct net2_objmanager*)self;
	net2_objmanager_release(m);
}

/* Accept incoming data from connection. */
static void
net2_objmanager_accept(struct net2_conn_acceptor *self,
    struct packet_header *ph, struct net2_buffer **bufptr)
{
	struct net2_objmanager		*m;
	struct net2_objman_packet	 packet;
	struct net2_encdec_ctx		*ctx;

	m = (struct net2_objmanager*)self;
	/* Prepare decoding context. */
	if ((ctx = net2_encdec_ctx_newobjman(m)) != NULL)
		goto fail_0;

	/* Decode all messages. */
	while (!net2_buffer_empty(*bufptr)) {
		if (n2omp_decode_header(ctx, &packet, *bufptr))
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

	assert(m->base.ca_conn == NULL);
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
	if (ttx->cb.fn != NULL)
		assert(0); /* TODO: invoke callback with "destroyed" error. */

	if (ttx->cb.ev != NULL)
		net2_evbase_release(ttx->cb.ev);
	net2_buffer_free(ttx->in_params);
	free(ttx);
}

/* Release rx ticket. */
static void
kill_rx_ticket(struct net2_objman_rx_ticket *trx)
{
	assert(0);	/* TODO: implement this. */
}

/* Create a new group in the object manager. */
static struct net2_objman_group*
create_group(struct net2_objmanager *m, uint32_t id)
{
	struct net2_objman_group	*g;

	if ((g = malloc(sizeof(*g))) == NULL)
		goto fail_0;
	g->id = id;
	if (n2ow_init(&g->scheduler))
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
	/* TODO: have the scheduler own the invocation, so it can hand it back to us when the message is to be executed. */
	if (n2ow_receive(&g->scheduler, barrier, seq, &accept))
		goto fail_2;
	if (!accept) {
		/*
		 * The packet was not accepted.
		 *
		 * This may happen because the packet was already superseded,
		 * was received twice or has already been processed.
		 * Therefore this is not an error condition.
		 */
		error = 0;
		goto fail_2;
	}

	assert(0);	/* TODO: implement */
	return 0;

fail_2:
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

	/* Lookup group, sequence and barrier. */
	if ((g = get_group(m, packet->request.invocation.group, 1,
	    &g_is_new)) == NULL)
		goto fail_0;
	seq = packet->request.invocation.seq;
	barrier = packet->request.invocation.barrier;

	/* Supersede the message. */
	if (n2ow_supersede(&g->scheduler, barrier, seq, &accept))
		goto fail_1;

	if (!accept) {
		/*
		 * TODO: check if the command is running and mark it as
		 * cancelled, so the executing function can cease doing
		 * work that is no longer relevant.
		 */
	}

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
	assert(0);	/* TODO: implement */
	return 0;
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
