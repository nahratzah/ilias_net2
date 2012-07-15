#ifndef ILIAS_NET2_CONTEXT_XCHANGE_H
#define ILIAS_NET2_CONTEXT_XCHANGE_H

#include <ilias/net2/ilias_net2_export.h>
#include <sys/types.h>
#include <stdint.h>

ILIAS_NET2__begin_cdecl


ILIAS_NET2_EXPORT
struct net2_promise	*net2_ctx_xchange_factory_bg(int, size_t, void*);
ILIAS_NET2_EXPORT
void			*net2_ctx_xchange_factory_bg_new();
ILIAS_NET2_EXPORT
void			 net2_ctx_xchange_factory_bg_destroy(void*);


ILIAS_NET2__end_cdecl
#endif /* ILIAS_NET2_CONTEXT_XCHANGE_H */
