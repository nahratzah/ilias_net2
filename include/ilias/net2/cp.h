#ifndef ILIAS_NET2_CP_H
#define ILIAS_NET2_CP_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/types.h>
#include <ilias/net2/buffer.h>

typedef int (*net2_cp_encfun) (struct net2_encdec_ctx*,
    struct net2_buffer*, const void*, const void*);
typedef int (*net2_cp_decfun) (struct net2_encdec_ctx*,
    void*, struct net2_buffer*, const void*);
typedef int (*net2_cp_initfun) (struct net2_encdec_ctx*, void*, const void*);
typedef int (*net2_cp_delfun) (struct net2_encdec_ctx*, void*, const void*);

struct command_param {
	int		 cp_flags;
#define CPT_NONE	 (0)
	size_t		 cp_size;
	const char	*cp_name;
	net2_cp_encfun	 cp_encode;
	net2_cp_decfun	 cp_decode;
	net2_cp_initfun	 cp_init;
	net2_cp_delfun	 cp_delete;
};

ILIAS_NET2_EXPORT
int net2_cp_encode(struct net2_encdec_ctx*, const struct command_param*,
    struct net2_buffer*, const void*, const void*);
ILIAS_NET2_EXPORT
int net2_cp_decode(struct net2_encdec_ctx*, const struct command_param*,
    void*, struct net2_buffer*, const void*);
ILIAS_NET2_EXPORT
int net2_cp_init(struct net2_encdec_ctx*, const struct command_param*,
    void*, const void*);
ILIAS_NET2_EXPORT
int net2_cp_destroy(struct net2_encdec_ctx*, const struct command_param*,
    void*, const void*);


struct net2_invocation_ctx;
typedef int (*net2_cm_invocation) (const struct net2_invocation_ctx*,
    void*, void*);

struct command_method {
	const struct command_param
			*cm_in;
	const struct command_param
			*cm_out;
	net2_cm_invocation
			 cm_method;
};

#endif /* ILIAS_NET2_CP_H */
