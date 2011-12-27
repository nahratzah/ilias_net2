#include <ilias/net2/obj_manager.h>
#include <ilias/net2/obj_window.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/evbase.h>
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
static void	 kill_group(struct net2_objman_group*);
static void	 kill_tx_ticket(struct net2_objman_tx_ticket*);
static void	 kill_rx_ticket(struct net2_objman_rx_ticket*);
static struct net2_objman_group
		*create_group(struct net2_objmanager*, uint32_t);
static struct net2_objman_group
		*get_group(struct net2_objmanager*, uint32_t, int);
static void	 unused_group_id(struct net2_objmanager*);

/*
 * Functions handling different categories of received information.
 */
static void	 objman_handle_request();
static void	 objman_handle_completion();
static void	 objman_handle_objman();


static const struct net2_conn_acceptor_fn net2_objmanager_cafn = {
	net2_objmanager_detach,
	net2_objmanager_attach,
	NULL, /* accept */
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
		return -1;
	return 0;
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

	if (m->flags & OM_ATTACHED)
		return -1;
	m->flags |= OM_ATTACHED;

	if (net2_pvlist_add(&m->pvlist, &net2_proto, conn->n2c_version))
		return -1;
	return 0;
}

/* Detach objmanager from connection. */
void
net2_objmanager_detach(struct net2_connection *conn,
    struct net2_conn_acceptor *self)
{
	struct net2_objmanager	*m;

	m = (struct net2_objmanager*)self;
	assert(0); /* TODO: implement */
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

/* Release an objmanager. */
ILIAS_NET2_EXPORT void
net2_objmanager_release(struct net2_objmanager *m)
{
	net2_objmanager_deinit(m);
	free(m);
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

/* Get a group from the object manager. */
static struct net2_objman_group*
get_group(struct net2_objmanager *m, uint32_t id, int create)
{
	struct net2_objman_group	*g, search;

	search.id = id;
	g = RB_FIND(net2_objman_groups, &m->groups, &search);
	if (g == NULL && create)
		g = create_group(m, id);
	return g;
}
