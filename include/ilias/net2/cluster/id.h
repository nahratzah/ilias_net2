#ifndef ILIAS_NET2_CLUSTER_ID_H
#define ILIAS_NET2_CLUSTER_ID_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Site identifier. */
struct site_id {
	uint32_t	 site_id;
};

/* Node identifier. */
struct node_id {
	struct site_id	 site;
	uint32_t	 node_id;
};

/* Object identifier. */
struct obj_id {
	struct node_id	 node;
	uint32_t	 obj_id;
};

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_CLUSTER_ID_H */
