#ifndef ILIAS_NET2_MEMORY_H
#define ILIAS_NET2_MEMORY_H


#ifdef BUILDING_ILIAS_NET2

#include <sys/types.h>
#include <stdint.h>

#ifdef NET2_USE_EXUDE_DEBUG


#include <exude.h>
#include <clog.h>

#define net2_malloc(s)							\
	e_malloc((s))
#define net2_free(p)							\
	do {								\
		if (p != NULL)						\
			e_free((&p));					\
	} while (0)
#define net2_realloc(p, s)						\
	e_realloc((p), (s))
#define net2_calloc(n, s)						\
	e_calloc((n), (s))
#define net2_strdup(s)							\
	e_strdup((s))

#define net2_memory_init()						\
	do {} while (0)
#define net2_memory_fini()						\
	do {} while (0)


#else /* NET2_USE_EXUDE_DEBUG */


#ifndef NDEBUG
#ifndef NET2_USE_EXUDE_DEBUG
#error "Not using exude in non-optimized build."
#endif /* NET2_USE_EXUDE_DEBUG */
#endif


#include <stdlib.h>

#define net2_malloc(s)							\
	malloc((s))
#define net2_free(p)							\
	free((p))
#define net2_realloc(p, s)						\
	realloc((p), (s))
#define net2_calloc(n, s)						\
	calloc((n), (s)
#define net2_strdup(s)							\
	strdup(s)

#define net2_memory_init()						\
	do {} while (0)
#define net2_memory_fini()						\
	do {} while (0)


#endif /* NET2_USE_EXUDE_DEBUG */

#define net2_recalloc(p, n, s)						\
	((n) > SIZE_MAX / (s) ? NULL : net2_realloc((p), (n) * (s)))

#endif /* BUILDING_ILIAS_NET2 */


#endif /* ILIAS_NET2_MEMORY_H */
