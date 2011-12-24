/*
 *   +------------+
 *  / obj acceptor \
 * +----------------+-----------------------------------------+
 * | negotiated protocols                                     |
 * |                                                          |
 * |    +----------+                                          |
 * |   / oa element \                                         |
 * |  +--------------+-------------------------------------+  |
 * |  | evbase                                             |  |
 * |  | cluster synchronization                            |  |
 * |  | client/server synchronization                      |  |
 * |  |                                                    |  |
 * |  |    +------+                     +-----------+      |  |
 * |  |   / window \                   / obj manager \     |  |
 * |  |  +----------+--------+        +---------------+-+  |  |
 * |  |  | queue of requests | <====> | objects         |  |  |
 * |  |  | seq, barrier      |        | active requests |  |  |
 * |  |  +-------------------+        +-----------------+  |  |
 * |  |                                                    |  |
 * |  +----------------------------------------------------+  |
 * |                                                          |
 * +----------------------------------------------------------+
 *
 * The obj acceptor decodes requests and pushes them on the window that is to manage
 * them. The window dequeues requests into the obj manager, where a request becomes
 * active. Once the request is completed, the result is given to the obj acceptor,
 * which will return them to the remote node.
 *
 * If the command has a barrier-after, the window barrier will be increased after
 * the command completes. A command may however opt to manually cause the barrier
 * increment, for example if the request will take a long time, but the required
 * state has been read or updated at the start of the command.
 * A barrier-after will only be incremented once, no matter how often the barrier
 * increment function is called.
 *
 * Each command consists of a set of windows, with a cmd ID.
 * The window ID contains a barrier and a sequence:
 * - the barrier prevents the command from executing until all commands before the
 *   barrier have been processed,
 * - the sequence prevents duplicate reception.
 * Commands within the same barrier execute out of order, in parallel.
 * The command ID is used to decode and invoke the request and encode the result.
 *
 * Each object may have serialization or synchronization code.
 * Serialization and synchronization are used within a cluster to create backup state,
 * allowing another node to take over when a node fails.
 * Serialzation between nodes in a cluster, allows the cluster to distribute its state
 * to another node. Synchronization does the same, but instead of serializing the
 * entire object, it provides deltas, which are applied on the remote node.
 * Synchronization may also include activating distributed locks, to ensure atomicity
 * among multiple nodes.
 *
 * An object may also provide cached data to a client (regardless of wether that
 * client is part of the cluster). Whenever the client requests cached data, if the
 * client has this data locally, it will not invoke a request.
 * Cached data may be invalidated in two ways:
 * - a request may specify that the data will be modified during the request, in which
 *   case the client will immediately invalidate the cache,
 *   Instead of invalidating the cache immediately, a request may, as part of its
 *   response, contain a delta or new cache state, which will be applied to the
 *   client. In this case, the client will delay any requests for new cache state
 *   until the request result has been received.
 * - the remote node may specify that the cache is to be invalidated, which will be
 *   processed as soon as possible.
 *   Optionally, the server can send a new cache state with the invalidation.
 */

struct net2_oa_command {
	void				*data;		/* Decoded data. */
	const struct command_param	*cp_in;		/* How to encode input. */
	const struct command_param	*cp_out;	/* How to encode result. */
	struct net2_buffer		*outbuf;	/* Encoded result. */

	int				 flags;
#define NET2_OACMD_F_BARRIER_BEFORE	0x00000001	/* Raise barrier before exec. */
#define NET2_OACMD_F_BARRIER_AFTER	0x00000002	/* Raise barrier after exec. */
#define NET2_OACMD_F_ATOMIC		(NET2_OACMD_F_BARRIER_BEFORE | \
					 NET2_OACMD_F_BARRIER_AFTER)
#define NET2_OACMD_F_RESULT_READY	0x00000010	/* Ready to send result. */
#define NET2_OACMD_F_BARRIER_DONE	0x00000020	/* Barrier was incremented. */

	uint32_t			 w_seq;		/* Window sequence. */
	uint32_t			 w_barrier;	/* Window barrier. */

	struct net2_obj_acceptor	*acceptor;	/* Acceptor. */
	uint32_t			 cmd_id;	/* Command ID. */
	uint32_t			 request_id;	/* Remote request ID. */
};

struct net2_oa_element {
	RB_ENTRY(net2_oa_element)	 oae_elemt;
	TAILQ_ENTRY(net2_oa_element)	 oae_transmitq;

	struct net2_window		 oae_window;
	struct net2_obj_group		 oae_objs;
	struct net2_evbase		*oae_evbase;
};

struct net2_oa_proto {
	const struct net2_protocol	*oap_proto;
	net2_protocol_t			 oap_version;
};

struct net2_obj_acceptor {
	struct net2_conn_acceptor	base;

	struct net2_oa_proto		*protocols;	/* Negotiated protocols. */
	size_t				 num_protocols;	/* Number of protocols. */

	RB_TREE(net2_oae_tree, net2_oa_element)
					oa_elems;
	TAILQ_ENTRY(, net2_oa_element)	oa_transmit;
};
