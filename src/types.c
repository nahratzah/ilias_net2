#include <ilias/net2/types.h>
#include <string.h>

/* Declared over here, to avoid compiler from optimizing it out. */
ILIAS_NET2_LOCAL void
net2_secure_zero(void *addr, size_t len)
{
	memset(addr, 0, len);
}
