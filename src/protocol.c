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


/* Protocol comparator. Compares based on pointer to protocol. */
static int
net2_pvlist_cmp(const void *a1, const void *a2)
{
	const struct net2_proto_version	*p1, *p2;

	p1 = a1;
	p2 = a2;
	return (p1->pv_protocol < p2->pv_protocol ? -1 :
	    p1->pv_protocol > p2->pv_protocol);
}

/* Initialize set. */
ILIAS_NET2_EXPORT int
net2_pvlist_init(struct net2_pvlist *pv)
{
	pv->list = NULL;
	pv->listsz = 0;
	return 0;
}

/* Release resource. */
ILIAS_NET2_EXPORT void
net2_pvlist_deinit(struct net2_pvlist *pv)
{
	free(pv->list);
	pv->list = NULL;
	pv->listsz = 0;
}

/* Add a protocol with version. */
ILIAS_NET2_EXPORT int
net2_pvlist_add(struct net2_pvlist *pv, const struct net2_protocol *p,
    net2_protocol_t v)
{
	struct net2_proto_version	key, *list, *elem;

	list = pv->list;
	key.pv_protocol = p;
	if (list != NULL && bsearch(&key, list, pv->listsz,
	    sizeof(pv->list[0]), &net2_pvlist_cmp) != NULL)
		return -1;

	if ((list = realloc(list, (pv->listsz + 1) * sizeof(*list))) == NULL)
		return -1;
	pv->list = list;
	elem = &list[pv->listsz];
	elem->pv_protocol = p;
	elem->pv_version = v;
	qsort(list, pv->listsz + 1, sizeof(*list), &net2_pvlist_cmp);

	pv->listsz++;
	return 0;
}

/* Find the version for the given protocol. */
ILIAS_NET2_EXPORT int
net2_pvlist_get(const struct net2_pvlist *pv, const struct net2_protocol *p,
    net2_protocol_t *v)
{
	struct net2_proto_version	key, *f;

	if (pv->listsz == 0)
		return -1;

	key.pv_protocol = p;
	f = bsearch(&key, pv->list, pv->listsz, sizeof(pv->list[0]), &net2_pvlist_cmp);
	if (f == NULL)
		return -1;
	*v = f->pv_version;
	return 0;
}

/*
 * Merge another list into this list.
 *
 * If a protocol occurs in both lists, the one in dst will stay.
 */
ILIAS_NET2_EXPORT int
net2_pvlist_merge(struct net2_pvlist *dst, const struct net2_pvlist *src)
{
	size_t				 listlen, i, insert_idx;
	struct net2_proto_version	*list, *collide;

	if (src->listsz == 0)
		return 0;

	list = dst->list;
	listlen = dst->listsz + src->listsz;
	if ((list = realloc(list, listlen * sizeof(*list))) == NULL)
		return -1;
	dst->list = list;

	insert_idx = dst->listsz;
	for (i = 0; i < src->listsz; i++) {
		collide = bsearch(&src->list[i], list, dst->listsz,
		    sizeof(dst->list[0]), &net2_pvlist_cmp);
		if (collide != NULL) {
			/* Collision. */
			continue;
		}

		list[insert_idx++] = src->list[i];
	}

	/* Ensure everything is sorted. */
	qsort(list, insert_idx, sizeof(*list), &net2_pvlist_cmp);
	/* Update dst listsz. */
	dst->listsz = insert_idx;
	return 0;
}
