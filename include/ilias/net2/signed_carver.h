#ifndef ILIAS_NET2_SIGNED_CARVER_H
#define ILIAS_NET2_SIGNED_CARVER_H

#include <ilias/net2/ilias_net2_export.h>
#include <sys/types.h>
#include <stdint.h>

struct net2_signed_carver;
struct net2_signed_combiner;

struct net2_workq;	/* from ilias/net2/workq.h */
struct net2_encdec_ctx;	/* from ilias/net2/encdec_ctx.h */
struct net2_buffer;	/* from ilias/net2/buffer.h */
struct net2_sign_ctx;	/* from ilias/net2/sign.h */
struct net2_promise;	/* from ilias/net2/promise.h */
struct net2_tx_callback;/* from ilias/net2/tx_callback.h */


ILIAS_NET2_EXPORT
struct net2_signed_carver
		*net2_signed_carver_new(struct net2_workq*,
		    struct net2_encdec_ctx*,
		    struct net2_buffer*, int, uint32_t, struct net2_sign_ctx**);
ILIAS_NET2_EXPORT
void		 net2_signed_carver_destroy(struct net2_signed_carver*);

ILIAS_NET2_EXPORT
struct net2_signed_combiner
		*net2_signed_combiner_new(struct net2_workq*,
		    struct net2_encdec_ctx*, uint32_t, struct net2_sign_ctx**);
ILIAS_NET2_EXPORT
void		 net2_signed_combiner_destroy(struct net2_signed_combiner*);

ILIAS_NET2_EXPORT
int		 net2_signed_carver_get_transmit(struct net2_signed_carver*,
		    struct net2_encdec_ctx*,
		    struct net2_workq*, struct net2_buffer*,
		    struct net2_tx_callback*, size_t);
ILIAS_NET2_EXPORT
int		 net2_signed_combiner_accept(struct net2_signed_combiner*,
		    struct net2_encdec_ctx*, struct net2_buffer*);

ILIAS_NET2_EXPORT
struct net2_promise
		*net2_signed_carver_complete(struct net2_signed_carver*);
ILIAS_NET2_EXPORT
struct net2_promise
		*net2_signed_carver_payload(struct net2_signed_carver*);

ILIAS_NET2_EXPORT
struct net2_promise
		*net2_signed_combiner_complete(struct net2_signed_combiner*);
ILIAS_NET2_EXPORT
struct net2_promise
		*net2_signed_combiner_payload(struct net2_signed_combiner*);

ILIAS_NET2_EXPORT
void		 net2_signed_carver_set_rts(struct net2_signed_carver*,
		    void (*)(void*, void*), void*, void*);


#endif /* ILIAS_NET2_SIGNED_CARVER_H */
