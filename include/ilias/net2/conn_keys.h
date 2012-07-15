#ifndef ILIAS_NET2_CONN_KEYS_H
#define ILIAS_NET2_CONN_KEYS_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/cneg_key_xchange.h>
#include <sys/types.h>
#include <stdint.h>

ILIAS_NET2__begin_cdecl


struct net2_buffer;		/* From ilias/net2/buffer.h */
struct net2_connwindow;		/* From ilias/net2/connwindow.h */
struct net2_workq;		/* From ilias/net2/workq.h */
struct packet_header;		/* From packet.h */

/* Connection keys. */
struct net2_ck_keys {
	int			 alg[NET2_CNEG_S2_MAX];
	struct net2_buffer	*key[NET2_CNEG_S2_MAX];
};

/*
 * Connection keys.
 *
 * TX keys are simply activated at some point, which sets the ALTKEY
 * flag on the packets.  Once a packet with ALTKEY has been acked, the flag
 * is dropped.  Once the bottom of the window (i.e. the first unacknowledged
 * transmission) slides past the ALTKEY cut off point, the old key is dropped
 * and new negotiation is possible.
 *
 * RX keys are in two stages.  The altkey is prepared once new keys are
 * negotiated.  The first receival of a data packet with ALTKEY set is then
 * used to describe the bottom of the RX window.  If a later packet with a
 * lower offset in the window is received, this number is reduced to the
 * newly received window ID.  Packets without ALTKEY set are given either
 * the old key (if they are prior to the first ALTKEY receival) or the new
 * key (if they are after the ALTKEY receival).  Once the window slides out
 * the ALTKEY receival window ID, the old key is dropped and the new key
 * becomes the ALTKEY.  At this point, new renegotiation is possible.
 */
struct net2_conn_keys {
	/* Active and alt rx/tx keys. */
	struct net2_ck_keys	 keys[4];
#define NET2_CK_RX_ACTIVE	 0
#define NET2_CK_RX_ALT		 1
#define NET2_CK_TX_ACTIVE	 2
#define NET2_CK_TX_ALT		 3

	/*
	 * Cutoff points.  Valid if the corresponding alt key exists
	 * and NET2_CK_F_NO_[TR]X_CUTOFF is clear.
	 */
	uint32_t		 rx_alt_cutoff;
	uint32_t		 tx_alt_cutoff;

	/* State flags. */
	int			 flags;
#define NET2_CK_F_NO_RX_CUTOFF	0x00000001
#define NET2_CK_F_NO_TX_CUTOFF	0x00000002

	/* Cutoff events. */
	struct net2_promise_event
				*rx_alt_cutoff_expire,
				*tx_alt_cutoff_expire;
};

ILIAS_NET2_LOCAL
struct net2_ck_keys	*net2_ck_rx_key(struct net2_conn_keys*,
			    struct net2_connwindow*,
			    const struct packet_header*);
ILIAS_NET2_LOCAL
int			 net2_ck_rx_key_commit(struct net2_conn_keys*,
			    struct net2_workq*, struct net2_connwindow*,
			    const struct packet_header*);
ILIAS_NET2_LOCAL
struct net2_ck_keys	*net2_ck_tx_key(struct net2_conn_keys*,
			    struct net2_workq*, struct net2_connwindow*,
			    struct packet_header*);
ILIAS_NET2_LOCAL
int			 net2_ck_rx_key_inject(struct net2_conn_keys*,
			    const struct net2_ck_keys*);
ILIAS_NET2_LOCAL
int			 net2_ck_tx_key_inject(struct net2_conn_keys*,
			    const struct net2_ck_keys*);

ILIAS_NET2_LOCAL
int			 net2_ck_init(struct net2_conn_keys*);
ILIAS_NET2_LOCAL
void			 net2_ck_deinit(struct net2_conn_keys*);


ILIAS_NET2__end_cdecl
#endif /* ILIAS_NET2_CONN_KEYS_H */
