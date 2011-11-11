#ifndef ILIAS_NET2_TYPES_H
#define ILIAS_NET2_TYPES_H

#include <ilias/net2/ilias_net2_export.h>
#include <sys/types.h>
#include <stdint.h>

typedef uint32_t	net2_command_t;
typedef uint32_t	net2_protocol_t;
struct			net2_connection;
struct			net2_encdec_ctx;
struct			net2_evbase;
struct			net2_obj;
struct			net2_objtype;
struct			net2_window;

#ifdef ilias_net2_EXPORTS
/* Not a type, but it needs to be defined somewhere... */
ILIAS_NET2_LOCAL
void			net2_secure_zero(void*, size_t);
#endif /* ilias_net2_EXPORTS */

#endif /* ILIAS_NET2_TYPES_H */
