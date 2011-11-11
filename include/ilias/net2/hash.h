#ifndef ILIAS_NET2_HASH_H
#define ILIAS_NET2_HASH_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/buffer.h>
#include <sys/types.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct net2_hash_ctx;

extern ILIAS_NET2_EXPORT const int net2_hashmax;

ILIAS_NET2_EXPORT
size_t			 net2_hash_gethashlen(int);
ILIAS_NET2_EXPORT
size_t			 net2_hash_getkeylen(int);
ILIAS_NET2_EXPORT
const char		*net2_hash_getname(int);
ILIAS_NET2_EXPORT
int			 net2_hash_findname(const char *);

ILIAS_NET2_EXPORT
struct net2_hash_ctx	*net2_hashctx_new(int, const void*, size_t);
ILIAS_NET2_EXPORT
void			 net2_hashctx_free(struct net2_hash_ctx*);
ILIAS_NET2_EXPORT
int			 net2_hashctx_update(struct net2_hash_ctx*,
			    const void*, size_t);
ILIAS_NET2_EXPORT
struct net2_buffer	*net2_hashctx_final(struct net2_hash_ctx*);
ILIAS_NET2_EXPORT
struct net2_buffer	*net2_hashctx_finalfree(struct net2_hash_ctx*);

ILIAS_NET2_EXPORT
struct net2_buffer	*net2_hashctx_hashbuf(int, const void*, size_t,
			    struct net2_buffer*);

#ifdef __cplusplus
}
#endif

#endif /* ILIAS_NET2_HASH_H */
