#ifndef TEST_TESTCONN_H
#define TEST_TESTCONN_H

#include <ilias/net2/connection.h>
#include <ilias/net2/evbase.h>

struct testconn {
	struct net2_connection	 base_conn;
	struct testconn		*other;

	void			*in;
	size_t			 inlen;
	int			 wantsend;
};

extern struct net2_evbase	*global_evbase;
int	testconn(struct net2_connection**, struct net2_connection**);

#endif /* TEST_TESTCONN_H */
