#ifndef ILIAS_NET2_ENCDEC_CTX_H
#define ILIAS_NET2_ENCDEC_CTX_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Encoding/decoding context.
 *
 * Contains parameters required to perform the encoding/decoding and
 * allows for rollback of failed operations.
 *
 * Whenever a message is prepared for transmission, a net2_encdec_ctx
 * is allocated to keep track of connection state modifications.
 * If for any reason, the transmission is cancelled or fails, the
 * net2_encdec_ctx is rolled back.
 */
struct net2_encdec_ctx {
	struct net2_objmanager	*ed_objman;	/* Object manager. */
};

#ifdef ilias_net2_EXPORTS
ILIAS_NET2_LOCAL
struct net2_encdec_ctx	*net2_encdec_ctx_new(struct net2_objmanager*);
ILIAS_NET2_LOCAL
void			 net2_encdec_ctx_rollback(struct net2_encdec_ctx*);
ILIAS_NET2_LOCAL
void			 net2_encdec_ctx_release(struct net2_encdec_ctx*);
#endif /* ilias_net2_EXPORTS */

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_ENCDEC_CTX_H */
