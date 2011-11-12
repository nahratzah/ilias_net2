#include <ilias/net2/connwindow.h>
#include <ilias/net2/connection.h>
#include <ilias/net2/connstats.h>
#include <ilias/net2/evbase.h>
#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/packet.h>
#include <ilias/net2/cp.h>
#include <bsd_compat/secure_random.h>
#include <bsd_compat/clock.h>
#include <bsd_compat/error.h>
#include <bsd_compat/sysexits.h>
#include <bsd_compat/minmax.h>
#include <event2/event.h>
#include <stdlib.h>
#include <assert.h>
#include "connwindow_cp.h"

#ifdef WIN32
#include <WinSock2.h>
#else
#include <sys/time.h>
#endif


/* State transitions per packet:
 *
 * When a packet is sent, a new net2_cw_tx struct is created.
 * When the ack timeout expires, WANTBAD is set and timeout cbs are invoked.
 * When an acknowledgement is received, the state is removed and the ack/nack
 * cbs are invoked.
 *
 * Every time a SENTBAD packet is sent, the timeout will restart, setting
 * WANTBAD after timeout.
 *
 *
 * Each received packet is added to the rx set.
 * If the rx was of type LOST, a timer will start, which after expiry will
 * transmit the bad ack.
 * If the rx was of type RECVOK, if the LOST ack has not yet been transmitted,
 * the packet will be changed into RECVOK and an ack will be sent.
 * Once the first ACK (wether bad or ok) is sent, the ACKED flag will be set,
 * locking the received packet.
 *
 * Also, when a packet with seq S is received, every unreceived packet before
 * S will be created and treated as LOST. The timer delay before acknowledging
 * loss will allow for packets to receive out-of-order.
 *
 *
 * The timeouts at the sending side will be chosen such that in most cases,
 * the receiving side will be able to figure out loss on its own.
 *
 *
 * After the last send, keepalives will be sent every interval.
 * These keepalives don't use the standard timeout, but a much larger one:
 * keepalive-timeout = 2 * interval + round-trip-time.
 * Keepalive packets are not used in the determining of the bandwidth.
 * When a non-keepalive packet is sent, all keepalives are marked as BAD
 * and transmission is done accordingly.
 */

/*
 * All timeouts are defined as 2 integers, separated by a comma.
 * The first is the multiplier, the second is the standard deviation multiplier.
 *
 * TX_ACK is the time before an acknowledgement is expected.
 * TX_BAD is the time between TX_ACK expiry and BAD transmission.
 */
#define TIMEOUT_TX_ACK		2, 2	/* Expect ack for sent packet. */
#define TIMEOUT_RX_LOST		2, 3	/* Treat missed packet as lost. */
#define TIMEOUT_RX_ACK		3, 2	/* Retransmit ack. */
#define TIMEOUT_TX_BAD		8, 4	/* Expect nack for sent packet. */


/*
 * Transmission callback queue.
 *
 * Once the window receives confirmation of the remote end if the data
 * was received or lost, cb_ack or cb_nack will be invoked.
 * When confirmation is expected, but hasn't arrived yet, the timeout
 * callback will be invoked.
 *
 * The ack and nack callbacks will always be the last callback that is
 * invoked.
 * The timeout callback may or may not be invoked prior to calling the
 * nack and ack callbacks.
 *
 * If the connection is destroyed, the callback may arrive _after_ the
 * connection and connwindow are destroyed. In the case of cb_destroy,
 * this is guaranteed to happen.
 */
struct net2_cw_transmit_cb {
	net2_connwindow_cb	 cb_ack;	/* ACK callback. */
	net2_connwindow_cb	 cb_nack;	/* NACK callback. */
	net2_connwindow_cb	 cb_timeout;	/* Timed out cb. */
	net2_connwindow_cb	 cb_cdestroy;	/* Conn destroy. */
	void			*cb_arg0;	/* First argument. */
	void			*cb_arg1;	/* Second argument. */

	int			 state;		/* ACK/NACK state. */
#define NET2_CWTXCB_NONE	 0		/* State: nothing to do. */
#define NET2_CWTXCB_ACK		 2		/* State: ack received. */
#define NET2_CWTXCB_NACK	 3		/* State: nack received. */
#define NET2_CWTXCB_CDESTROY	 4		/* State: conn destroyed. */
	struct event		*ev;		/* Event delivery. */
	struct event		*ev_timeout;	/* Timeout event delivery. */

	TAILQ_ENTRY(net2_cw_transmit_cb)
				 entry;		/* Link into transmit. */
};

/*
 * Transmitted packet data.
 * Note that the packet itself is not stored:
 * when a transmission times out, a nack version of the same window is sent.
 * The remote end will respond with a window update, where it will indicate
 * wether the original or the nacked version of the window was received.
 */
struct net2_cw_tx {
	struct net2_connwindow
			*cwt_owner;		/* Owning window. */
	uint32_t	 cwt_seq;		/* Window sequence. */
	size_t		 cwt_wire_sz;		/* Wire size. */

	TAILQ_HEAD(, net2_cw_transmit_cb)
			 cwt_cbq;		/* Callback queue. */
	struct event	*cwt_timeout;		/* Nack timer. */

	RB_ENTRY(net2_cw_tx)
			 cwt_entry_id;		/* Allow lookup by ID. */
	TAILQ_ENTRY(net2_cw_tx)
			 cwt_entry_txbad;	/* Pos in WANTBAD transmitq. */

	struct timeval	 cwt_timestamp;		/* When transmit happened. */
	int		 cwt_flags;		/* State flags. */
#define NET2_CWTX_F_WANTBAD	0x00000001	/* Want loss transmission. */
#define NET2_CWTX_F_SENTBAD	0x00000002	/* Sent loss transmission. */
#define NET2_CWTX_F_TIMEDOUT	0x00000004	/* Timeout cb invoked. */
	int		 cwt_stalled;		/* No payload, no callbacks. */
};

/*
 * Received packet data.
 *
 * Note that a LOST state can be changed into a RECVOK state, unless we
 * already commited to the LOST state by having ACKED the loss.
 * The WANTACK state indicates that the ACKED state needs to be
 * (re)transmitted.
 */
struct net2_cw_rx {
	struct net2_connwindow
			*cwr_owner;		/* Owning window. */
	uint32_t	 cwr_seq;		/* Window sequence. */
	size_t		 cwr_wire_sz;		/* Wire size. */

	struct event	*cwr_timeout;		/* Nack timer. */

	RB_ENTRY(net2_cw_rx)
			 cwr_entry_id;		/* Allow lookup by ID. */
	TAILQ_ENTRY(net2_cw_rx)
			 cwr_entry_rx;		/* Position in recvq. */

	int		 cwr_flags;		/* State flags. */
#define NET2_CWRX_F_RECVOK	0x00000001	/* Packet was received ok. */
#define NET2_CWRX_F_LOST	0x00000002	/* Packet loss was received. */
#define NET2_CWRX_F_ACKED	0x00000010	/* Packet ack/nack sent. */
#define NET2_CWRX_F_WANTACK	0x00000020	/* Packet ack/nack wanted. */

#define NET2_CWRX_RCVMASK	(NET2_CWRX_F_RECVOK|NET2_CWRX_F_LOST)
};


#define INITIAL_RX_WINDOW_SIZE	4096	/* TODO: make dynamic. */
#define INITIAL_WINDOW_SIZE	8	/* Dynamically incremented each ack. */
#define INITIAL_TX_SSTHRESH	0	/* Slow start initially to here. */

/*
 * We want at least 128 bytes, to be able to comfortably put the window in.
 *
 * Provide more and we'll happily eat it though.
 */
ILIAS_NET2_LOCAL const size_t net2_connwindow_overhead = 128;

static __inline int
tx_cmp(struct net2_cw_tx *tx1, struct net2_cw_tx *tx2)
{
	return (tx1->cwt_seq < tx2->cwt_seq ? -1 : tx1->cwt_seq > tx2->cwt_seq);
}
static __inline int
rx_cmp(struct net2_cw_rx *rx1, struct net2_cw_rx *rx2)
{
	return (rx1->cwr_seq < rx2->cwr_seq ? -1 : rx1->cwr_seq > rx2->cwr_seq);
}
RB_PROTOTYPE_STATIC(net2_cw_transmits, net2_cw_tx, cwt_entry_id, tx_cmp);
RB_PROTOTYPE_STATIC(net2_cw_recvs, net2_cw_rx, cwr_entry_id, rx_cmp);
RB_GENERATE_STATIC(net2_cw_transmits, net2_cw_tx, cwt_entry_id, tx_cmp);
RB_GENERATE_STATIC(net2_cw_recvs, net2_cw_rx, cwr_entry_id, rx_cmp);

/* Set the stalled flag, depending on the transmission window. */
static __inline void
update_stalled(struct net2_connwindow *w)
{
	if (w->cw_tx_nextseq - w->cw_tx_start < w->cw_tx_windowsz)
		w->cw_flags &= ~NET2_CW_F_STALLED;
	else
		w->cw_flags |= NET2_CW_F_STALLED;
}


static void	tx_cb_timeout(struct net2_cw_transmit_cb*);
static void	tx_cb_ack(struct net2_cw_transmit_cb*);
static void	tx_cb_nack(struct net2_cw_transmit_cb*);
static void	add_statistic(struct net2_connwindow*,
		    struct timeval*, struct timeval*, size_t, int);
static void	dup_ack(struct net2_connwindow*);

/*
 * Handle tx timeout.
 *
 * - The first timeout is when the ack was expected; invoke timeout and start
 *   timer for bad request.
 * - Any next timeout activates the WANTBAD state.
 */
static void
tx_timeout(int fd, short what, void *txptr)
{
	struct net2_cw_tx		*tx = txptr;
	struct net2_connwindow		*w = tx->cwt_owner;
	struct timeval			 next_timeout;
	struct net2_cw_transmit_cb	*cb;

	if ((tx->cwt_flags & NET2_CWTX_F_TIMEDOUT) == 0) {
		tx->cwt_flags |= NET2_CWTX_F_TIMEDOUT;
		TAILQ_FOREACH(cb, &tx->cwt_cbq, entry)
			tx_cb_timeout(cb);

		/* Add wantbad event. */
		net2_connstats_timeout(&w->cw_conn->n2c_stats, &next_timeout,
		    TIMEOUT_TX_BAD);
		event_add(tx->cwt_timeout, &next_timeout);
	} else if (!(tx->cwt_flags & NET2_CWTX_F_WANTBAD)) {
		tx->cwt_flags |= NET2_CWTX_F_WANTBAD;
		TAILQ_INSERT_TAIL(&w->cw_tx_bad, tx, cwt_entry_txbad);
		net2_conn_ready_to_send(w->cw_conn);
	}
}
/*
 * Handle rx timeout.
 *
 * - The packet is marked as lost if it wasn't marked before.
 * - A request for ack transmission is put forth.
 */
static void
rx_timeout(int fd, short what, void *rxptr)
{
	struct net2_cw_rx		*rx = rxptr;
	struct net2_connwindow		*w = rx->cwr_owner;

	/* Mark rx as lost. */
	if ((rx->cwr_flags & NET2_CWRX_RCVMASK) == 0)
		rx->cwr_flags |= NET2_CWRX_F_LOST;
	/* Request ack transmission. */
	if ((rx->cwr_flags & NET2_CWRX_F_WANTACK) == 0) {
		rx->cwr_flags |= NET2_CWRX_F_WANTACK;
		TAILQ_INSERT_TAIL(&w->cw_rx_wantack, rx, cwr_entry_rx);
	}
}

static struct net2_cw_tx*
tx_new(uint32_t seq, struct net2_connwindow *w)
{
	struct net2_cw_tx		*tx;
	struct net2_connection		*c;
	struct net2_evbase		*evbase;

	c = w->cw_conn;
	evbase = c->n2c_evbase;

	if ((tx = malloc(sizeof(*tx))) == NULL)
		goto fail_0;
	tx->cwt_owner = w;
	tx->cwt_seq = seq;
	tx->cwt_wire_sz = 0;	/* No idea how large yet. */
	TAILQ_INIT(&tx->cwt_cbq);
	if ((tx->cwt_timeout = evtimer_new(evbase->evbase, tx_timeout, tx)) ==
	    NULL)
		goto fail_1;

	return tx;

fail_1:
	free(tx);
fail_0:
	return NULL;
}

/*
 * Execute the final event in a transmission callback.
 */
static void
tx_cb_execute(int fd, short what, void *cbptr)
{
	struct net2_cw_transmit_cb	*cb = cbptr;

	switch (cb->state) {
	case NET2_CWTXCB_ACK:
		if (cb->cb_ack)
			(*cb->cb_ack)(cb->cb_arg0, cb->cb_arg1);
		break;
	case NET2_CWTXCB_NACK:
		if (cb->cb_nack)
			(*cb->cb_nack)(cb->cb_arg0, cb->cb_arg1);
		break;
	case NET2_CWTXCB_CDESTROY:
		if (cb->cb_cdestroy)
			(*cb->cb_cdestroy)(cb->cb_arg0, cb->cb_arg1);
		break;
	case NET2_CWTXCB_NONE:
	default:
		errx(EX_SOFTWARE, "invalid transmit callback invocation %d",
		    cb->state);
		/* UNREACHABLE */
	}

	/* Destroy callback. */
	event_free(cb->ev);
	free(cb);
}
/*
 * Execute the timeout event in a transmission callback.
 */
static void
tx_cb_exectimeout(int fd, short what, void *cbptr)
{
	struct net2_cw_transmit_cb	*cb = cbptr;

	if (cb->cb_timeout)
		(*cb->cb_timeout)(cb->cb_arg0, cb->cb_arg1);
	return;
}

static void
tx_cb_timeout(struct net2_cw_transmit_cb *cb)
{
	const struct timeval	now = { 0, 0 };

	assert(cb->state == NET2_CWTXCB_NONE);

	if (cb->cb_timeout != NULL)
		event_add(cb->ev_timeout, &now);
}

static void
tx_cb_ack(struct net2_cw_transmit_cb *cb)
{
	const struct timeval	now = { 0, 0 };

	assert(cb->state == NET2_CWTXCB_NONE);

	if (cb->ev_timeout)
		event_del(cb->ev_timeout);
	cb->state = NET2_CWTXCB_ACK;
	if (cb->cb_ack != NULL)
		event_add(cb->ev, &now);
	else {
		if (cb->ev_timeout)
			event_free(cb->ev_timeout);
		if (cb->ev)
			event_free(cb->ev);
		free(cb);
	}
}

static void
tx_cb_nack(struct net2_cw_transmit_cb *cb)
{
	const struct timeval	now = { 0, 0 };

	assert(cb->state == NET2_CWTXCB_NONE);

	if (cb->ev_timeout)
		event_del(cb->ev_timeout);
	cb->state = NET2_CWTXCB_NACK;
	if (cb->cb_nack != NULL)
		event_add(cb->ev, &now);
	else {
		if (cb->ev_timeout)
			event_free(cb->ev_timeout);
		if (cb->ev)
			event_free(cb->ev);
		free(cb);
	}
}

static void
tx_cb_cdestroy(struct net2_cw_transmit_cb *cb)
{
	const struct timeval	now = { 0, 0 };

	assert(cb->state == NET2_CWTXCB_NONE);

	if (cb->ev_timeout)
		event_del(cb->ev_timeout);
	cb->state = NET2_CWTXCB_CDESTROY;
	if (cb->cb_cdestroy != NULL)
		event_add(cb->ev, &now);
	else {
		if (cb->ev_timeout)
			event_free(cb->ev_timeout);
		if (cb->ev)
			event_free(cb->ev);
		free(cb);
	}
}

static void
tx_free(struct net2_cw_tx *tx)
{
	struct net2_cw_transmit_cb	*cb;

	event_free(tx->cwt_timeout);
	while ((cb = TAILQ_FIRST(&tx->cwt_cbq)) != NULL) {
		TAILQ_REMOVE(&tx->cwt_cbq, cb, entry);
		tx_cb_cdestroy(cb);
	}
	free(tx);
}

static struct net2_cw_rx*
rx_new(uint32_t seq, struct net2_connwindow *w)
{
	struct net2_cw_rx		*rx;
	struct net2_connection		*c;
	struct net2_evbase		*evbase;

	c = w->cw_conn;
	evbase = c->n2c_evbase;

	if ((rx = malloc(sizeof(*rx))) == NULL)
		goto fail_0;
	rx->cwr_owner = w;
	rx->cwr_seq = seq;
	rx->cwr_wire_sz = 0;	/* No idea. */
	rx->cwr_flags = 0;
	if ((rx->cwr_timeout = evtimer_new(evbase->evbase, rx_timeout, rx)) ==
	    NULL)
		goto fail_1;

	return rx;

fail_1:
	free(rx);
fail_0:
	return NULL;
}

static void
rx_free(struct net2_cw_rx *rx)
{
	event_free(rx->cwr_timeout);
	free(rx);
}


/*
 * Get the receive for the given sequence.
 * If the recv does not exist, it will be created.
 * All receives prior are also created and marked to timeout.
 *
 * Naturally, all created recvs are pushed in the cw_rx_id set.
 *
 * If stalled is set, no datagram for seq is added.
 */
static struct net2_cw_rx*
get_recv(struct net2_connwindow *w, uint32_t seq, int stalled)
{
	struct net2_cw_rx		*found, search, *collide;
	uint32_t			 first_seq;
	struct timeval			 timeout;

	/* Initialize timeout to missed recv timeout. */
	net2_connstats_timeout(&w->cw_conn->n2c_stats, &timeout,
	    TIMEOUT_RX_LOST);

	search.cwr_seq = seq;
	found = RB_FIND(net2_cw_recvs, &w->cw_rx_id, &search);
	if (found != NULL)
		return found;

	/* Find the first entry in the set. */
	if (w->cw_flags & NET2_CW_F_WANTRECV) {
		first_seq = w->cw_rx_start = seq;
		w->cw_flags &= ~NET2_CW_F_WANTRECV;
	} else
		first_seq = w->cw_rx_nextrecv;

	while (first_seq - w->cw_rx_start <= seq - w->cw_rx_start) {
		if (stalled && first_seq == seq) {
			found = NULL;
			break;
		}

		/* Create new recv. */
		if ((found = rx_new(first_seq, w)) == NULL)
			goto fail_1;
		/* Mark it for timeout, unless its the requested ID. */
		if (first_seq != seq) {
			if (evtimer_add(found->cwr_timeout, &timeout)) {
				rx_free(found);
				goto fail_1;
			}
		}
		/* Push into the recv set. */
		collide = RB_INSERT(net2_cw_recvs, &w->cw_rx_id, found);
		assert(collide == NULL);

		/* Proceed to next sequence. */
		first_seq++;
	}

	/* Update next recv. */
	w->cw_rx_nextrecv = seq + (stalled ? 0 : 1);
	return found;

fail_1:
	/* Remove all created entries. */
	while (first_seq-- != w->cw_rx_nextrecv) {
		search.cwr_seq = first_seq;
		found = RB_FIND(net2_cw_recvs, &w->cw_rx_id, &search);
		if (found) {
			RB_REMOVE(net2_cw_recvs, &w->cw_rx_id, found);
			rx_free(found);
		}
	}
	return NULL;
}

/* Handle RECV and LOST acks for transmitted packets. */
static int
do_transmit_ack(struct net2_connwindow *w, uint32_t first, uint32_t last,
    int ok)
{
	uint32_t			 seq;
	struct net2_cw_tx		*tx, tx_search;
	struct net2_cw_transmit_cb	*cb;
	struct timeval			 now;
	int				 did_nothing = 1;

	/* now is only used with affirmitive acknowledgement. */
	if (ok && tv_clock_gettime(CLOCK_MONOTONIC, &now))
		err(EX_OSERR, "clock_gettime fail");

	for (seq = 0; seq <= last - first; seq++) {
		/* Lookup entry. */
		tx_search.cwt_seq = seq + first;
		tx = RB_REMOVE(net2_cw_transmits, &w->cw_tx_id, &tx_search);
		/* Skip already acked entries. */
		if (tx == NULL)
			continue;
		/* We're performing work. */
		did_nothing = 0;

		/* Packet ack implies no longer wanting BAD transmit */
		if (tx->cwt_flags & NET2_CWTX_F_WANTBAD) {
			tx->cwt_flags &= ~NET2_CWTX_F_WANTBAD;
			TAILQ_REMOVE(&w->cw_tx_bad, tx,
			    cwt_entry_txbad);
		}

		/* Update statistics. */
		add_statistic(w, &tx->cwt_timestamp,
		    (ok ? &now : NULL), tx->cwt_wire_sz, ok);

		/*
		 * Invoke ack/nack callbacks.
		 * Those callbacks will ensure the cb gets freed.
		 */
		while ((cb = TAILQ_FIRST(&tx->cwt_cbq)) != NULL) {
			TAILQ_REMOVE(&tx->cwt_cbq, cb, entry);
			if (ok)
				tx_cb_ack(cb);
			else
				tx_cb_nack(cb);
		}

		tx_free(tx);
	}

	/*
	 * If we didn't remove anything in this ack, the ack is definately
	 * a duplicate ack.
	 */
	if (ok && did_nothing)
		dup_ack(w);

	return 0;
}

/*
 * Move the start of the window forward.
 * If the window is moved forward, the connection becomes unstalled.
 */
static int
fix_txstart(struct net2_connwindow *w)
{
	struct net2_cw_tx		*tx, tx_search;

	/* Find the first unconfirmed datagram at or after cw_tx_start. */
	tx_search.cwt_seq = w->cw_tx_start;
	tx = RB_NFIND(net2_cw_transmits, &w->cw_tx_id, &tx_search);
	if (tx == NULL)
		tx = RB_MIN(net2_cw_transmits, &w->cw_tx_id);

	/* If the found datagram has the same ID, no window update is needed. */
	if (tx != NULL && tx->cwt_seq == w->cw_tx_start)
		return 0;

	if (tx == NULL)	/* Empty window? */
		w->cw_tx_start = w->cw_tx_nextseq;
	else		/* Start window at first unconfirmed datagram. */
		w->cw_tx_start = tx->cwt_seq;

	/* Window was moved, unstall connection. */
	update_stalled(w);
	return 0;
}

/*
 * Find the datagram with the rx_start ID.
 *
 * Put this ID on the WANTBAD queue immediately and mark the connection
 * ready-to-send.
 */
static void
do_stalled(struct net2_connwindow *w)
{
	struct net2_cw_rx		*rx, search;

	search.cwr_seq = w->cw_rx_start;
	if ((rx = RB_FIND(net2_cw_recvs, &w->cw_rx_id, &search)) == NULL)
		return;

	/*
	 * If the found packet is already on the wantack queue, we need to
	 * move it to the front.
	 */
	if (rx->cwr_flags & NET2_CWRX_F_WANTACK)
		TAILQ_REMOVE(&w->cw_rx_wantack, rx, cwr_entry_rx);
	else if ((rx->cwr_flags & NET2_CWRX_RCVMASK) == 0) {
		/* Mark as lost if it hadn't been marked already. */
		rx->cwr_flags |= (NET2_CWRX_F_LOST | NET2_CWRX_F_WANTACK);
	}

	/* Put on the front of the WANTACK queue. */
	TAILQ_INSERT_HEAD(&w->cw_rx_wantack, rx, cwr_entry_rx);

	/* Ensure connection will send immediately. */
	net2_conn_ready_to_send(w->cw_conn);
}

/* Perform window update. */
static int
do_window_update(struct net2_connwindow *w, struct windowheader *wh,
    int ph_flags)
{
	size_t				 i;
	struct net2_cw_rx		*rx, rx_search;

	/*
	 * Handle all items written as BAD in the window.
	 * All these items are considered by the sender to be acked/nacked
	 * immediately.
	 */
	for (i = 0; i < wh->num_bad; i++) {
		rx_search.cwr_seq = wh->bad[i];
		rx = RB_FIND(net2_cw_recvs, &w->cw_rx_id, &rx_search);

		/*
		 * If packet doesn't exist, it means it was succesfully
		 * acked earlier -> ignore.
		 */
		if (rx == NULL)
			continue;

		/* If packet has not been received, mark it as lost. */
		if (!(rx->cwr_flags & NET2_CWRX_RCVMASK))
			rx->cwr_flags |= NET2_CWRX_F_LOST;
		/* Enqueue the packet for acknowledgement. */
		if (!(rx->cwr_flags & NET2_CWRX_F_WANTACK)) {
			rx->cwr_flags |= NET2_CWRX_F_WANTACK;
			TAILQ_INSERT_TAIL(&w->cw_rx_wantack, rx, cwr_entry_rx);
		}
		/* No need for timing out on not receiving this. */
		event_del(rx->cwr_timeout);

		/*
		 * If this is a bad transmit for a succesfully received packet,
		 * mark the connection as ready-to-send so the remote end
		 * will receive its long awaited ack.
		 */
		if (rx->cwr_flags & NET2_CWRX_F_RECVOK)
			net2_conn_ready_to_send(w->cw_conn);
	}

	/* Move the rx window up to the new starting point. */
	for (; w->cw_rx_start != wh->tx_start; w->cw_rx_start++) {
		/* Skip elements outside window. */
		if (wh->tx_start - w->cw_rx_start >= w->cw_rx_windowsz)
			continue;

		/* Remove rx that is no longer in the window. */
		rx_search.cwr_seq = w->cw_rx_start;
		rx = RB_REMOVE(net2_cw_recvs, &w->cw_rx_id, &rx_search);

		/*
		 * rx must exist: window cannot continue unless all packets
		 * were received.
		 */
		if (rx == NULL) {
			warnx("illegal window state: "
			    "never received %u sliding out of window",
			    rx_search.cwr_seq);
			goto fail;
		}

		/* Remove from WANTACK queue. */
		if (rx->cwr_flags & NET2_CWRX_F_WANTACK)
			TAILQ_REMOVE(&w->cw_rx_wantack, rx, cwr_entry_rx);

		rx_free(rx);
	}

	/*
	 * Handle all succesfully received packets.
	 */
	for (i = 0; i < wh->num_recv; i++) {
		if (do_transmit_ack(w, wh->recv[i].first, wh->recv[i].last, 1))
			goto fail;
	}

	/*
	 * Handle all lost packets.
	 */
	for (i = 0; i < wh->num_lost; i++) {
		if (do_transmit_ack(w, wh->lost[i].first, wh->lost[i].last, 0))
			goto fail;
	}

	/* Update cw_tx_start and maybe remove F_STALLED from cw_flags. */
	if (ph_flags & PH_STALLED)
		do_stalled(w);

	return 0;

fail:
	return -1;
}


/* Initialize a new connection window. */
ILIAS_NET2_LOCAL int
net2_connwindow_init(struct net2_connwindow *w, struct net2_connection *c)
{
	w->cw_conn = c;
	w->cw_tx_start = w->cw_tx_nextseq = secure_random();
	w->cw_rx_windowsz = INITIAL_RX_WINDOW_SIZE;
	w->cw_tx_windowsz = INITIAL_WINDOW_SIZE;
	w->cw_tx_ssthresh = INITIAL_TX_SSTHRESH;
	w->cw_tx_count = 0;
	TAILQ_INIT(&w->cw_tx_bad);
	RB_INIT(&w->cw_tx_id);
	TAILQ_INIT(&w->cw_rx_wantack);
	RB_INIT(&w->cw_rx_id);
	w->cw_flags = NET2_CW_F_WANTRECV;

	return 0;
}

/* Destroy a connection window. */
ILIAS_NET2_LOCAL void
net2_connwindow_deinit(struct net2_connwindow *w)
{
	struct net2_cw_rx		*rx;
	struct net2_cw_tx		*tx;

	while ((rx = RB_ROOT(&w->cw_rx_id)) != NULL) {
		RB_REMOVE(net2_cw_recvs, &w->cw_rx_id, rx);
		rx_free(rx);
	}
	while ((tx = RB_ROOT(&w->cw_tx_id)) != NULL) {
		RB_REMOVE(net2_cw_transmits, &w->cw_tx_id, tx);
		tx_free(tx);
	}
}

/*
 * Test if a packet is to be accepted.
 *
 * Packets are accepted if:
 * - they are within the window
 * - they have not been received before
 * - they were lost, but the loss has not yet been acknowledged
 *
 * Since each packet is only ever sent once, there is no worry that the packet
 * will have changed from earlier receivals.
 *
 * The window is not updated (this call is intended to be run before the
 * signature validation and decryption run).
 */
ILIAS_NET2_LOCAL int
net2_connwindow_accept(const struct net2_connwindow *w,
    struct packet_header *ph)
{
	struct net2_cw_rx		*found, search;
	uint32_t			 seq = ph->seq;

	/*
	 * First accepted transmission needs window state.
	 *
	 * - Always accept packet in the WANTRECV state.
	 * - Always accept stalled packets: they contain no payload,
	 *   need no ack, but do allow window updates to be transferred.
	 * - Accept any packet that falls within the receive window.
	 */
	if (w->cw_flags & NET2_CW_F_WANTRECV)
		return (ph->flags & PH_WINUPDATE);
	else if ((ph->flags & (PH_STALLED|PH_PAYLOAD)) == PH_STALLED)
		return 1;
	else if (seq - w->cw_rx_start >= w->cw_rx_windowsz)
		return 0;	/* Outside acceptance window. */

	/* Check if the packet within the window was not already received. */
	search.cwr_seq = seq;
	found = RB_FIND(net2_cw_recvs, &((struct net2_connwindow*)w)->cw_rx_id,
	    &search);
	if (found == NULL)
		return 1;	/* Hasn't been received yet. */
	if (!(found->cwr_flags & NET2_CWRX_RCVMASK))
		return 1;	/* Haven't received yet, lost considered. */
	if ((found->cwr_flags & (NET2_CWRX_F_LOST | NET2_CWRX_F_ACKED)) ==
	    NET2_CWRX_F_LOST)
		return 1;	/* Lost ack not yet sent, so able to change. */

	return 0;
}

/*
 * Update the connection window.
 * If the packet contains a window update, apply it.
 */
ILIAS_NET2_LOCAL int
net2_connwindow_update(struct net2_connwindow *w, struct packet_header *ph,
    struct net2_buffer *buf, size_t wire_sz)
{
	struct net2_cw_rx		*rx;
	struct net2_encdec_ctx		*ctx = NULL;
	struct windowheader		 wh;
	int				 ph_needdestroy = 0;
	int				 ack_count;

	assert(net2_connwindow_accept(w, ph));

	if ((ph->flags & PH_WINUPDATE) != 0) {
		if ((ctx = net2_encdec_ctx_new(w->cw_conn)) == NULL)
			goto fail_0;
		if (net2_cp_init(ctx, &cp_windowheader, &wh, NULL))
			goto fail_0;
		ph_needdestroy = 1;
		if (net2_cp_decode(ctx, &cp_windowheader, &wh, buf, NULL))
			goto fail_0;
	}

	if ((w->cw_flags & NET2_CW_F_WANTRECV) != 0 &&
	    (ph->flags & PH_WINUPDATE) != 0) {
		w->cw_rx_start = w->cw_rx_nextrecv = wh.tx_start;
		w->cw_flags &= ~NET2_CW_F_WANTRECV;
	}

	/*
	 * Stalled packets only get every window up to them added, but not
	 * themselves: stalled packets are not real packets in this sense.
	 */
	rx = get_recv(w, ph->seq, ph->flags & PH_STALLED);
	if (!(ph->flags & PH_STALLED)) {
		/*
		 * Mark packet as received ok and add it
		 * to the to-be-acked queue.
		 */
		rx->cwr_wire_sz = wire_sz;
		rx->cwr_flags |= (NET2_CWRX_F_RECVOK | NET2_CWRX_F_WANTACK);
		TAILQ_INSERT_TAIL(&w->cw_rx_wantack, rx, cwr_entry_rx);
	}

	if (ph->flags & PH_WINUPDATE) {
		if (do_window_update(w, &wh, ph->flags))
			goto fail_0;

		ph_needdestroy = 0;
		if (net2_cp_destroy(ctx, &cp_windowheader, &wh, NULL))
			goto fail_0;
		net2_encdec_ctx_release(ctx);
		ctx = NULL;

		/* Update start of tx window. */
		fix_txstart(w);
	}

	/* Force transmission if the number of acks grows large. */
	ack_count = w->cw_rx_windowsz / 4;
	TAILQ_FOREACH(rx, &w->cw_rx_wantack, cwr_entry_rx) {
		if (--ack_count == 0) {
			net2_conn_ready_to_send(w->cw_conn);
			break;
		}
	}

	return 0;

fail_0:
	if (ph_needdestroy)
		net2_cp_destroy(ctx, &cp_windowheader, &wh, NULL);
	if (ctx) {
		net2_encdec_ctx_rollback(ctx);
		net2_encdec_ctx_release(ctx);
	}
	return -1;
}

/*
 * Create a buffer containing a window update.
 * Resulting buffer will be no larger than avail.
 */
ILIAS_NET2_LOCAL struct net2_buffer*
net2_connwindow_writebuf(struct net2_connwindow *w, struct packet_header *ph,
    size_t avail)
{
	struct net2_buffer		*buf;
	struct windowheader		 wh;
	size_t				 reqsz;
	size_t				 maxbad, maxranges, i;
	struct net2_cw_tx		*tx, *tx_next;
	struct net2_cw_rx		*rx, *rx_next, *rxi;
	void				*tmp;
	struct winrange			*r, **range;
	uint8_t				*counter;
	struct net2_encdec_ctx		*ctx;
	TAILQ_HEAD(, net2_cw_tx)	 txq;
	TAILQ_HEAD(, net2_cw_rx)	 rxq;
	struct timeval			 rx_ack_timeout, tx_bad_timeout;

	assert(!(ph->flags & PH_WINUPDATE));
	if ((buf = net2_buffer_new()) == NULL)
		goto fail_0;

	/*
	 * No real information to transmit.
	 * - no bad packets
	 * - no acknowledgement required
	 * - we have received at least one packet that initiated the connection
	 */
	if (TAILQ_EMPTY(&w->cw_tx_bad) && TAILQ_EMPTY(&w->cw_rx_wantack) &&
	    (w->cw_flags & NET2_CW_F_WANTRECV) == 0)
		return buf;

	reqsz = WINDOWHEADER_MINSIZE;	/* Initial size. */
	if (avail < reqsz) {
		if ((w->cw_flags & NET2_CW_F_WANTRECV) == 0)
			return buf;
		net2_buffer_free(buf);
		goto fail_0;
	}

	wh.tx_start = w->cw_tx_start;
	wh.flags = 0;
	wh.num_recv = 0;
	wh.num_lost = 0;
	wh.num_bad = 0;
	wh.recv = NULL;
	wh.lost = NULL;
	wh.bad = NULL;

	TAILQ_INIT(&txq);
	TAILQ_INIT(&rxq);

	/* Initialize timeouts for retransmitting ack and bad. */
	net2_connstats_timeout(&w->cw_conn->n2c_stats, &rx_ack_timeout,
	    TIMEOUT_RX_ACK);
	net2_connstats_timeout(&w->cw_conn->n2c_stats, &tx_bad_timeout,
	    TIMEOUT_TX_BAD);

	/*
	 * Decide what the maximum number of bad packets will be.
	 *
	 * Divide space by 2: bad will use at most half the space.
	 *   Unless the wantack queue is empty.
	 * Divide space by 8: each line of bad will consume 8 bytes.
	 */
	maxbad = (avail - reqsz) / (TAILQ_EMPTY(&w->cw_rx_wantack) ? 1 : 2) /
	    WINDOWHEADER_RANGE_SIZE;
	/* Multiply by 2: each line of bad will hold 2 bad IDs. */
	maxbad *= WINDOWHEADER_BAD_PER_LINE;
	/* Prevent overflow of byte. */
	maxbad = MIN(maxbad, 255);

	/* Create wh.bad list. */
	for (tx = TAILQ_FIRST(&w->cw_tx_bad); tx != NULL; tx = tx_next) {
		/* Prepare next tx. */
		tx_next = TAILQ_NEXT(tx, cwt_entry_txbad);

		/* Don't use more that maxbad entries. */
		if (maxbad == 0)
			break;

		/*
		 * Allocation failure is not fatal: window has no requirement
		 * to be complete.
		 */
		if ((tmp = realloc(wh.bad,
		    ((size_t)wh.num_bad + 1) * sizeof(*wh.bad))) == NULL)
			break;
		wh.bad = tmp;

		wh.bad[wh.num_bad] = tx->cwt_seq;
		wh.num_bad++;
		maxbad--;

		TAILQ_REMOVE(&w->cw_tx_bad, tx, cwt_entry_txbad);
		TAILQ_INSERT_TAIL(&txq, tx, cwt_entry_txbad);
	}
	/* Update required space. */
	reqsz += WINDOWHEADER_RANGE_SIZE *
	    ((wh.num_bad + WINDOWHEADER_BAD_PER_LINE - 1) /
	     WINDOWHEADER_BAD_PER_LINE);

	/* Calculate number of lines available for LOST and RECV. */
	maxranges = (avail - reqsz) / WINDOWHEADER_RANGE_SIZE;
	/* Cap maxranges to 255 recv, 255 lost. */
	maxranges = MIN(maxranges, 2 * 255);

	for (rx = TAILQ_FIRST(&w->cw_rx_wantack); rx != NULL; rx = rx_next) {
		/* Prepare next rx. */
		rx_next = TAILQ_NEXT(rx, cwr_entry_rx);

		/* Stop when max ranges have been added. */
		if (maxranges == 0)
			break;

		/* Determine in which queue rx goes. */
		if (rx->cwr_flags & NET2_CWRX_F_RECVOK) {
			counter = &wh.num_recv;
			range = &wh.recv;
		} else if (rx->cwr_flags & NET2_CWRX_F_LOST) {
			counter = &wh.num_lost;
			range = &wh.lost;
		} else {
skip:			/* All goto skip continue here. */
			continue;
		}

		/*
		 * Ensure we don't overflow.
		 */
		if (*counter == 0xff)
			goto skip;

		/*
		 * Check if the sequence is already described in one of the
		 * ranges.
		 */
		for (i = 0; i < *counter; i++) {
			if (rx->cwr_seq - (*range)[i].first <= (*range)[i].last)
				goto skip;
		}

		/*
		 * Create a new range for this sequence.
		 */
		tmp = realloc(*range, (*counter + 1) * sizeof(**range));
		if (tmp == NULL)
			break;
		*range = tmp;
		/*
		 * Update counter.
		 * r will be the range we just added.
		 */
		r = &(*range)[*counter];
		(*counter)++;
		maxranges--;			/* We used another range. */

		/* Initially, both first and last are equal. */
		r->first = r->last = rx->cwr_seq;

		/* Extend range backwards. */
		for (rxi = RB_PREV(net2_cw_recvs, &w->cw_rx_id, rx);
		    rxi != NULL && rxi->cwr_seq == r->first - 1 &&
		    ((rxi->cwr_flags & NET2_CWRX_RCVMASK) ==
		     (rx ->cwr_flags & NET2_CWRX_RCVMASK));
		    rxi = RB_PREV(net2_cw_recvs, &w->cw_rx_id, rxi)) {
			r->first--;

			if (rxi->cwr_flags & NET2_CWRX_F_WANTACK) {
				TAILQ_REMOVE(&w->cw_rx_wantack, rxi,
				    cwr_entry_rx);
				TAILQ_INSERT_TAIL(&rxq, rxi, cwr_entry_rx);
			}
		}

		/* Extend range forwards. */
		for (rxi = RB_NEXT(net2_cw_recvs, &w->cw_rx_id, rx);
		    rxi != NULL && rxi->cwr_seq == r->last + 1 &&
		   ((rxi->cwr_flags & NET2_CWRX_RCVMASK) ==
		    (rx ->cwr_flags & NET2_CWRX_RCVMASK));
		    rxi = RB_NEXT(net2_cw_recvs, &w->cw_rx_id, rxi)) {
			r->last++;

			if (rxi->cwr_flags & NET2_CWRX_F_WANTACK) {
				TAILQ_REMOVE(&w->cw_rx_wantack, rxi,
				    cwr_entry_rx);
				TAILQ_INSERT_TAIL(&rxq, rxi, cwr_entry_rx);
			}
		}

		/*
		 * rx_next may have been removed from the queue.
		 * Update rx_next, prior to continueing the loop.
		 */
		rx_next = TAILQ_NEXT(rx, cwr_entry_rx);

		/* Now that rx_next is certain not to be changed, move it. */
		TAILQ_REMOVE(&w->cw_rx_wantack, rx, cwr_entry_rx);
		TAILQ_INSERT_TAIL(&rxq, rx, cwr_entry_rx);
	}

	/*
	 * We now have a valid window.
	 * Encode it into a buffer.
	 */
	if ((ctx = net2_encdec_ctx_new(w->cw_conn)) == NULL)
		goto fail_1;
	if (net2_cp_encode(ctx, &cp_windowheader, buf, &wh, NULL))
		goto fail_2;
	assert(net2_buffer_length(buf) <= avail);

	/* Release encoding context. */
	net2_encdec_ctx_release(ctx);

	/* Release resources in window. */
	if (wh.bad)
		free(wh.bad);
	if (wh.lost)
		free(wh.lost);
	if (wh.recv)
		free(wh.recv);

	/* Unwant all rx. */
	TAILQ_FOREACH(rx, &rxq, cwr_entry_rx) {
		rx->cwr_flags &= ~NET2_CWRX_F_WANTACK;
		rx->cwr_flags |= NET2_CWRX_F_ACKED;
		event_del(rx->cwr_timeout);
		if (event_add(rx->cwr_timeout, &rx_ack_timeout))
			warnx("event_add fail, window may misbehave...");
	}
	/* Unwant all tx. */
	TAILQ_FOREACH(tx, &txq, cwt_entry_txbad) {
		tx->cwt_flags &= ~NET2_CWTX_F_WANTBAD;
		tx->cwt_flags |= NET2_CWTX_F_SENTBAD;
		event_del(tx->cwt_timeout);
		if (event_add(rx->cwr_timeout, &tx_bad_timeout))
			warnx("event_add fail, window may misbehave...");
	}

	/* Result. */
	return buf;

fail_2:
	net2_encdec_ctx_rollback(ctx);
	net2_encdec_ctx_release(ctx);
fail_1:
	if (wh.bad)
		free(wh.bad);
	if (wh.lost)
		free(wh.lost);
	if (wh.recv)
		free(wh.recv);

	/* Move all tx and rx back into their queues; order will change. */
	while ((rx = TAILQ_FIRST(&rxq)) != NULL) {
		TAILQ_REMOVE(&rxq, rx, cwr_entry_rx);
		TAILQ_INSERT_HEAD(&w->cw_rx_wantack, rx, cwr_entry_rx);
	}
	while ((tx = TAILQ_FIRST(&txq)) != NULL) {
		TAILQ_REMOVE(&txq, tx, cwt_entry_txbad);
		TAILQ_INSERT_HEAD(&w->cw_tx_bad, tx, cwt_entry_txbad);
	}

fail_0:
	return NULL;
}

/*
 * Prepare a connwindow transmission.
 *
 * Fills in the sequence ID in the packet header.
 */
ILIAS_NET2_LOCAL struct net2_cw_tx*
net2_connwindow_tx_prepare(struct net2_connwindow *w,
    struct packet_header *ph)
{
	struct net2_cw_tx		*tx;

	update_stalled(w);

	ph->seq = w->cw_tx_nextseq;
	if ((tx = tx_new(w->cw_tx_nextseq, w)) == NULL)
		goto fail_0;

	if (w->cw_flags & NET2_CW_F_STALLED) {
		ph->flags |= PH_STALLED;
		tx->cwt_stalled = 1;
	} else {
		if (RB_INSERT(net2_cw_transmits, &w->cw_tx_id, tx) != NULL)
			goto fail_1;
		w->cw_tx_nextseq++;
	}
	return tx;

fail_1:
	tx_free(tx);
fail_0:
	return NULL;
}

/*
 * Commit a connwindow transmission.
 */
ILIAS_NET2_LOCAL void
net2_connwindow_tx_commit(struct net2_cw_tx *tx, size_t wire_sz)
{
	struct net2_connwindow		*w = tx->cwt_owner;
	struct timeval			 timeout;

	if (tx->cwt_stalled) {
		tx_free(tx);
		return;
	}

	net2_connstats_timeout(&w->cw_conn->n2c_stats, &timeout,
	    TIMEOUT_TX_ACK);

	if (tv_clock_gettime(CLOCK_MONOTONIC, &tx->cwt_timestamp))
		err(EX_OSERR, "clock_gettime fail");
	tx->cwt_wire_sz = wire_sz;
	event_add(tx->cwt_timeout, &timeout);
}

/*
 * Fail a connwindow transmission.
 *
 * The transmission will be considered unsent and the bad request will be
 * posted immediately.
 * Since the transmission will not take place, we can be sure that this is
 * a transmission failure and invoke the bad callbacks immediately.
 */
ILIAS_NET2_LOCAL void
net2_connwindow_tx_rollback(struct net2_cw_tx *tx)
{
	struct net2_connwindow		*w;
	struct net2_cw_transmit_cb	*cb;

	w = tx->cwt_owner;

	/* Invoke each callback for nack. */
	while ((cb = TAILQ_FIRST(&tx->cwt_cbq)) != NULL) {
		TAILQ_REMOVE(&tx->cwt_cbq, cb, entry);
		tx_cb_nack(cb);
	}

	/*
	 * If this is the most recently allocated sequence, we can undo the
	 * sequence update, thereby not requiring dead transmissions in the
	 * window.
	 *
	 * If the window is stalled, the sequence cannot increase.
	 */
	if (w->cw_flags & NET2_CW_F_STALLED) {
		tx_free(tx);
	} else if (w->cw_tx_nextseq - 1 == tx->cwt_seq) {
		w->cw_tx_nextseq--;
		tx_free(tx);
	} else {
		/*
		 * Cannot undo sequence update -> mark as bad.
		 * We also set the timeout flag, so the tx_timeout code
		 * skips its first timeout handling.
		 */
		tx->cwt_flags |= NET2_CWTX_F_WANTBAD | NET2_CWTX_F_TIMEDOUT;
		TAILQ_INSERT_TAIL(&w->cw_tx_bad, tx, cwt_entry_txbad);
	}
}

/*
 * Add a callback to the transmission.
 */
ILIAS_NET2_EXPORT int
net2_connwindow_txcb_register(struct net2_cw_tx *tx, struct net2_evbase *evbase,
    net2_connwindow_cb cb_timeout, net2_connwindow_cb cb_ack,
    net2_connwindow_cb cb_nack, net2_connwindow_cb cb_cdestroy,
    void *arg0, void *arg1)
{
	struct net2_cw_transmit_cb	*cb;

	/* Argument check. */
	if (tx == NULL || evbase == NULL)
		return -1;
	/* Cannot add callbacks to stalled packet: this will never be acked. */
	if (tx->cwt_stalled)
		return -1;
	/* Don't add empty events. */
	if (cb_timeout == NULL && cb_ack == NULL && cb_nack == NULL &&
	    cb_cdestroy == NULL)
		return 0;

	/* Create storage for new callback. */
	if ((cb = malloc(sizeof(*cb))) == NULL)
		goto fail_0;
	/* Apply parameters. */
	cb->cb_ack = cb_ack;
	cb->cb_nack = cb_nack;
	cb->cb_timeout = cb_timeout;
	cb->cb_cdestroy = cb_cdestroy;
	cb->cb_arg0 = arg0;
	cb->cb_arg1 = arg1;
	cb->state = NET2_CWTXCB_NONE;

	/* Allocate timeout event. */
	if (cb_timeout == NULL)
		cb->ev_timeout = NULL;		/* Not needed. */
	else if ((cb->ev_timeout = evtimer_new(evbase->evbase,
	    tx_cb_exectimeout, cb)) == NULL)
		goto fail_1;

	/* Allocate other callback event. */
	if (cb_ack == NULL && cb_nack == NULL && cb_cdestroy == NULL)
		cb->ev = NULL;			/* Not needed. */
	else if ((cb->ev = evtimer_new(evbase->evbase,
	    tx_cb_execute, cb)) == NULL)
		goto fail_2;

	/* Add callback to list. */
	TAILQ_INSERT_TAIL(&tx->cwt_cbq, cb, entry);
	return 0;

#if 0	/* Only needed if more code is added. */
fail_3:
	if (cb->ev != NULL)
		event_free(cb->ev);
#endif
fail_2:
	if (cb->ev_timeout != NULL)
		event_free(cb->ev_timeout);
fail_1:
	free(cb);
fail_0:
	return -1;
}

/*
 * Add round-trip-time and throughput measurement to connection window state.
 */
static void
add_statistic(struct net2_connwindow *w, struct timeval *tx_ts,
    struct timeval *ack_ts, size_t winsz, int succes)
{
	net2_connstats_tx_datapoint(&w->cw_conn->n2c_stats, tx_ts, ack_ts,
	    winsz, succes);

	/*
	 * Perform window management based on ack/nack.
	 */

	if (succes) {
		/*
		 * Increment window size on ack.
		 *
		 * TODO: implement congestion avoidance logic
		 *   (but see the else part for that).
		 */
		if (w->cw_tx_windowsz < w->cw_tx_ssthresh) {
			/* Fast recovery. */
			w->cw_tx_windowsz = w->cw_tx_ssthresh;
		} else if (w->cw_tx_ssthresh == 0) {
			/* Slow start. */
			w->cw_tx_windowsz++;
		} else {
			/* Congestion avoidance (lineair growth). */
			if (!secure_random_uniform(w->cw_tx_windowsz))
				w->cw_tx_windowsz++;
		}
	} else if (w->cw_tx_windowsz > 1) {
		/*
		 * Decrement window size on nack.
		 *
		 * We don't allow the window size to drop below 1.
		 */
		w->cw_tx_windowsz--;

		/*
		 * Predict if we expected this packet to be lost.
		 * If not, start congestion avoidance.
		 */
		if ((int)secure_random_uniform(100) >
		    w->cw_conn->n2c_stats.arrival_chance) {
			w->cw_tx_ssthresh = w->cw_tx_windowsz =
			    MAX(1, w->cw_tx_windowsz / 2);
		}
	}

	update_stalled(w);
}

/* A duplicate ack was received. */
static void
dup_ack(struct net2_connwindow *w)
{
	w->cw_tx_windowsz++;
	update_stalled(w);
}
