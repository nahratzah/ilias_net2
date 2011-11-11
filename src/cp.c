#include <ilias/net2/cp.h>
#include <stdlib.h>
#include <assert.h>

ILIAS_NET2_EXPORT int
net2_cp_encode(struct net2_encdec_ctx *c, const struct command_param *cp,
    struct net2_buffer *out, const void *val, const void *arg)
{
	assert(cp->cp_encode != NULL);
	return (*cp->cp_encode)(c, out, val, arg);
}

ILIAS_NET2_EXPORT int
net2_cp_decode(struct net2_encdec_ctx *c, const struct command_param *cp,
    void *val, struct net2_buffer *in, const void *arg)
{
	assert(cp->cp_decode != NULL);
	return (*cp->cp_decode)(c, val, in, arg);
}

ILIAS_NET2_EXPORT int
net2_cp_init(struct net2_encdec_ctx *c, const struct command_param *cp,
    void *val, const void *arg)
{
	if (!cp->cp_init)
		return 0;
	return (*cp->cp_init)(c, val, arg);
}

ILIAS_NET2_EXPORT int
net2_cp_destroy(struct net2_encdec_ctx *c, const struct command_param *cp,
    void *val, const void *arg)
{
	if (!cp->cp_delete)
		return 0;
	return (*cp->cp_delete)(c, val, arg);
}
