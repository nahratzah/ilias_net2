#include <ilias/net2/protocol.h>
#include <stdlib.h>

ILIAS_NET2_EXPORT const struct net2_objtype *
net2_protocol_type(const struct net2_protocol *p, uint32_t tid)
{
	if (tid >= p->numtypes)
		return NULL;
	return p->types[tid];
}
