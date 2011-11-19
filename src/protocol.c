#include <ilias/net2/protocol.h>
#include <ilias/net2/cp.h>
#include <ilias/net2/ctypes.h>
#include <ilias/net2/packet.h>
#include "connwindow_cp.h"
#include "stream_packet.h"
#include <stdlib.h>

ILIAS_NET2_EXPORT const struct net2_objtype *
net2_protocol_type(const struct net2_protocol *p, uint32_t tid)
{
	if (tid >= p->numtypes)
		return NULL;
	return p->types[tid];
}

static const struct command_param *net2_cp_array[] = {
	&cp_uint8,
	&cp_uint16,
	&cp_uint32,
	&cp_uint64,
	&cp_int8,
	&cp_int16,
	&cp_int32,
	&cp_int64,
	&cp_string,
	&cp_net2_buffer,
	&cp_short_net2_buffer,
	&cp_null_stringlist,
	&cp_packet_header,
	&cp_windowheader,
	&cp_winrange,
	&cp_stream_packet
};

/*
 * Specification of the base net2 protocol.
 */
ILIAS_NET2_EXPORT
const struct net2_protocol net2_proto = {
	"net2",
	/* version */ 0,

	net2_cp_array,
	sizeof(net2_cp_array) / sizeof(net2_cp_array[0]),

#if 0	/* not yet */
	net2_proto_types,
	sizeof(net2_proto_types) / sizeof(net2_proto_types[0]),
#else
	NULL, 0,
#endif

	/* flags */ 0
};
