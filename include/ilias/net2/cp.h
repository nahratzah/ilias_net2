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
ILIAS_NET2_EXPORT
int net2_cp_init_alloc(struct net2_encdec_ctx*, const struct command_param*,
    void**, const void*);
ILIAS_NET2_EXPORT
int net2_cp_destroy_alloc(struct net2_encdec_ctx*, const struct command_param*,
    void**, const void*);


struct net2_invocation_ctx;
struct net2_objmanager;
struct event;	/* from event2/event.h */
typedef int (*net2_cm_invocation) (const struct net2_invocation_ctx*,
    void*, void*);

struct command_method {
	const struct command_param
			*cm_in;
	const struct command_param
			*cm_out;
	int		 cm_flags;
#define CM_ASYNC	0x00000001	/* Asynchronous method. */
	net2_cm_invocation
			 cm_method;
};

ILIAS_NET2_EXPORT
struct net2_invocation_ctx
		*net2_invocation_ctx_new(struct net2_objmanager*,
		    const struct command_method*, void*);
ILIAS_NET2_EXPORT
void		 net2_invocation_ctx_free(struct net2_invocation_ctx*);
ILIAS_NET2_EXPORT
void		 net2_invocation_ctx_cancel(struct net2_invocation_ctx*);
ILIAS_NET2_EXPORT
int		 net2_invocation_ctx_is_cancelled(struct net2_invocation_ctx*);

ILIAS_NET2_EXPORT
int		 net2_invocation_ctx_run(struct net2_invocation_ctx*);
ILIAS_NET2_EXPORT
int		 net2_invocation_ctx_fin(struct net2_invocation_ctx*, int);
ILIAS_NET2_EXPORT
int		 net2_invocation_ctx_is_running(struct net2_invocation_ctx*);
ILIAS_NET2_EXPORT
int		 net2_invocation_ctx_finished(struct net2_invocation_ctx*);
ILIAS_NET2_EXPORT
struct event	*net2_invocation_ctx_get_event(struct net2_invocation_ctx*,
		    int);
ILIAS_NET2_EXPORT
int		 net2_invocation_ctx_set_event(struct net2_invocation_ctx*,
		    int, struct event*, struct event**);

#define NET2_IVCTX_FIN_UNFINISHED	0	/* Invoc hasn't finished. */
#define NET2_IVCTX_FIN_OK		1	/* Executed succesful. */
#define NET2_IVCTX_FIN_CANCEL		2	/* Execution cancelled. */
#define NET2_IVCTX_FIN_ERROR		3	/* Execution failed. */
#define NET2_IVCTX_FIN_FAIL		0xf	/* Failed to run. */

#define NET2_IVCTX_ON_FINISH		0	/* Finish event. */
#define NET2_IVCTX__NUM_EVENTS		1	/* Number of events. */

#endif /* ILIAS_NET2_CP_H */
