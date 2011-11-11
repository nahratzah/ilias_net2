#ifndef ILIAS_NET2_WINDOW_H
#define ILIAS_NET2_WINDOW_H

#include <ilias/net2/types.h>
#include <ilias/net2/ilias_net2_export.h>
#include <sys/types.h>

#include <bsd_compat.h>
#ifdef HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include <bsd_compat/tree.h>
#endif
#ifdef WIN32
#include <WinSock2.h>
#endif

/*
 * Windows and barriers.
 *
 * Each message can be synced to one or more windows.
 * Messages can execute out-of-order within the same barrier.
 * A special raise message will advance the barrier to a new level.
 *
 * Each message has:
 * - a primary object on which it acts
 * - a window on which it acts (derived from the primary object)
 * - sequence and barrier information in that window
 * - payload
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Window tag, applied to datagrams on the wire.
 */
struct net2_window_tag {
	uint32_t		 seq;		/* Packet sequence. */
	uint32_t		 barrier;	/* Barrier sequence. */
};

/* Data for a single datagram. */
struct windata {
	struct net2_window_tag	 seq;		/* Window sequence. */
	struct evbuffer		*payload;	/* Payload. */
	RB_ENTRY(windata)	 entry;		/* Link into tx window. */
	struct timeval		 tx_time;	/* Transmission time. */
};
RB_HEAD(windata_head, windata);

/* Transmission window.
 *
 * All pending acknowledgements are put on the ackpending list.
 */
struct tx_window {
	struct net2_window_tag	 next;		/* Next unused sequence. */
	uint32_t		 winsize;	/* Size of window. */
	struct windata_head	 ackpending;	/* Acknowledgement pending. */
};
/* Receive window.
 *
 * Received datagrams are put in the pending list.
 * If they are processed immediately, the windata is marked as done.
 * Otherwise, the windata is marked as to-be-processed.
 */
struct rx_window {
	struct net2_window_tag	 cur;		/* First missing datagram. */
	struct windata_head	 pending;	/* Received data. */
};

/* Network window. */
struct net2_window {
	struct net2_connection	*n2w_conn;	/* Conn for this window. */
	uint32_t		 n2w_winid;	/* Window ID. */
#define NET2_WIN_IDREMOTE	 0x80000000	/* ID mask for remote. */

	struct net2_mutex	*n2w_mtx;	/* Protect window. */
	size_t			 n2w_refcnt;	/* Extern reference count. */
	size_t			 n2w_objrefcnt;	/* Objects using the window. */

	struct net2_window_tag	*n2w_init;	/* Window tx/rx state at
						 * creation. */
#define NET2_WINDOW_TAG_TX	0		/* TX index. */
#define NET2_WINDOW_TAG_RX	1		/* RX index. */

	RB_ENTRY(net2_window)	 n2w_manq;	/* Link in window manager. */

	struct tx_window	 n2w_tx;	/* Transmit window. */
	struct rx_window	 n2w_rx;	/* Receive window. */
};

/* Manage all windows on a single connection. */
struct net2_winmanager {
	struct net2_mutex	*mtx;

	RB_HEAD(net2_window_head, net2_window)
				 winhead;
};

ILIAS_NET2_EXPORT
void			 net2_window_reference(struct net2_window*);
ILIAS_NET2_EXPORT
void			 net2_window_release(struct net2_window*);
ILIAS_NET2_EXPORT
struct net2_window	*net2_window_new(struct net2_connection*);
ILIAS_NET2_EXPORT
struct net2_window	*net2_window_from_obj(struct net2_obj*);

#ifdef ilias_net2_EXPORTS
ILIAS_NET2_LOCAL
void			 net2_window_link(struct net2_window*,
			    struct net2_obj*);
ILIAS_NET2_LOCAL
void			 net2_window_unlink(struct net2_obj*);
ILIAS_NET2_LOCAL
int			 net2_winmanager_init(struct net2_connection*);
ILIAS_NET2_LOCAL
void			 net2_winmanager_destroy(struct net2_connection*);
ILIAS_NET2_LOCAL
struct net2_window	*net2_win_by_id(struct net2_connection*, uint32_t);
ILIAS_NET2_LOCAL
struct net2_window	*net2_window_stub(struct net2_connection*, uint32_t);
ILIAS_NET2_LOCAL
int			 net2_window_activate(struct net2_connection*,
			    struct net2_window*);
#endif /* ilias_net2_EXPORTS */

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_WINDOW_H */
