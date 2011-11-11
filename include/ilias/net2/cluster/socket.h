#ifndef ILIAS_NET2_CLUSTER_SOCKET_H
#define ILIAS_NET2_CLUSTER_SOCKET_H

#include <event2/buffer.h>
#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/evbase.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Remote access implementation.
 *
 * This contains the functions used by a specific implementation of
 * communication.
 */
struct ra_functions {
	const char	*name;		/* Name of this implementation. */

	void		(*destroy)	(void*);
	void		(*transmit)	(void*, struct evbuffer*);
};

/*
 * Remote access structure.
 *
 * Each implementation is capable of transmitting data and having it be
 * received by each of its targets.
 */
struct remote_access {
	void		*state;		/* State of the access method. */
	const struct ra_functions
			*impl;		/* Implementation functions. */
};


ILIAS_NET2_EXPORT
struct remote_access	*n2ra_init_mcast(struct net2_evbase*, int,
			    const char*, const char*, const char*,
			    const char*);

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_CLUSTER_SOCKET_H */
