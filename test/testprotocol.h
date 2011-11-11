#ifndef TEST_PROTOCOL_H
#define TEST_PROTOCOL_H

#include <ilias/net2/protocol.h>

extern const struct net2_protocol test_protocol;

struct net2_ctx	*test_ctx();
void		 test_ctx_free(struct net2_ctx*);

#endif /* TEST_PROTOCOL_H */
