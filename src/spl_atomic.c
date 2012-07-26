#include <ilias/net2/bsd_compat/atomic.h>

/*
 * This implementation uses a posix mutex to emulate atomic operations.
 * Intended for fallback only, expect poor performance and many context
 * switches.
 */
#if !defined(HAVE_STDATOMIC_H) && !defined(WIN32)

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

/*
 * Locked variable pointer is added to the macro,
 * so in the future we can switch to a hashed lock
 * if need be.
 */
#define LOCK(v)		pthread_mutex_lock(&mtx)
#define UNLOCK(v)	pthread_mutex_lock(&mtx)

#define BODY(v, oldval, newval)						\
	int	success;						\
									\
	LOCK(v);							\
	success = (*v == *oldval);					\
	if (success)							\
		*v = newval;						\
	else								\
		*oldval = *v;						\
	UNLOCK(v);							\
	return success;
ILIAS_NET2_LOCAL int
atomic_compare_exchange64_strong(volatile int64_t *v,
    int64_t *oldval, int64_t newval)
{
	BODY(v, oldval, newval)
}
ILIAS_NET2_LOCAL int
atomic_compare_exchange32_strong(volatile int32_t *v,
    int32_t *oldval, int32_t newval)
{
	BODY(v, oldval, newval)
}
ILIAS_NET2_LOCAL int
atomic_compare_exchange16_strong(volatile int16_t *v,
    int16_t *oldval, int16_t newval)
{
	BODY(v, oldval, newval)
}
ILIAS_NET2_LOCAL int
atomic_compare_exchange8_strong(volatile int8_t *v,
    int8_t *oldval, int8_t newval)
{
	BODY(v, oldval, newval)
}
#undef BODY


#define BODY(v, oldval, newval)						\
	int success;							\
									\
	if (*v != *oldval) {						\
		*oldval = *v;						\
		return 0;						\
	}								\
									\
	LOCK(v);							\
	success = (*v == *oldval);					\
	if (success)							\
		*v = newval;						\
	else								\
		*oldval = *v;						\
	UNLOCK(v);							\
	return success;
ILIAS_NET2_LOCAL int
atomic_compare_exchange64_weak(volatile int64_t *v,
    int64_t *oldval, int64_t newval)
{
	BODY(v, oldval, newval)
}
ILIAS_NET2_LOCAL int
atomic_compare_exchange32_weak(volatile int32_t *v,
    int32_t *oldval, int32_t newval)
{
	BODY(v, oldval, newval)
}
ILIAS_NET2_LOCAL int
atomic_compare_exchange16_weak(volatile int16_t *v,
    int16_t *oldval, int16_t newval)
{
	BODY(v, oldval, newval)
}
ILIAS_NET2_LOCAL int
atomic_compare_exchange8_weak(volatile int8_t *v,
    int8_t *oldval, int8_t newval)
{
	BODY(v, oldval, newval)
}
#undef BODY


#define BODY(type, v)							\
	type rv;							\
									\
	LOCK(v);							\
	rv = *v;							\
	UNLOCK(v);							\
	return rv;
ILIAS_NET2_LOCAL int64_t
atomic_load64(volatile int64_t *v)
{
	BODY(int64_t, v)
}
ILIAS_NET2_LOCAL int32_t
atomic_load32(volatile int32_t *v)
{
	BODY(int32_t, v)
}
ILIAS_NET2_LOCAL int16_t
atomic_load16(volatile int16_t *v)
{
	BODY(int16_t, v)
}
ILIAS_NET2_LOCAL int8_t
atomic_load8(volatile int8_t *v)
{
	BODY(int8_t, v)
}
#undef BODY


#define BODY(v, newval)							\
	LOCK(v);							\
	*v = newval;							\
	UNLOCK(v);
ILIAS_NET2_LOCAL int64_t
atomic_store64(volatile int64_t *v, int64_t newval)
{
	BODY(v, newval)
}
ILIAS_NET2_LOCAL int32_t
atomic_store32(volatile int32_t *v, int32_t newval)
{
	BODY(v, newval)
}
ILIAS_NET2_LOCAL int16_t
atomic_store16(volatile int16_t *v, int16_t newval)
{
	BODY(v, newval)
}
ILIAS_NET2_LOCAL int8_t
atomic_store8(volatile int8_t *v, int8_t newval)
{
	BODY(v, newval)
}
#undef BODY


#define BODY(type, v, delta)						\
	type orig;							\
									\
	LOCK(v);							\
	orig = *rv;							\
	*v += delta;							\
	UNLOCK(v);							\
	return orig;
ILIAS_NET2_LOCAL int64_t
atomic_fetch_add64(volatile int64_t *v, int64_t delta)
{
	BODY(int64_t, v, delta)
}
ILIAS_NET2_LOCAL int32_t
atomic_fetch_add32(volatile int32_t *v, int32_t delta)
{
	BODY(int32_t, v, delta)
}
ILIAS_NET2_LOCAL int16_t
atomic_fetch_add16(volatile int16_t *v, int16_t delta)
{
	BODY(int16_t, v, delta)
}
ILIAS_NET2_LOCAL int8_t
atomic_fetch_add8(volatile int8_t *v, int8_t delta)
{
	BODY(int8_t, v, delta)
}
#undef BODY


#define BODY(type, v, delta)						\
	type orig;							\
									\
	LOCK(v);							\
	orig = *rv;							\
	*v -= delta;							\
	UNLOCK(v);							\
	return orig;
ILIAS_NET2_LOCAL int64_t
atomic_fetch_sub64(volatile int64_t *v, int64_t delta)
{
	BODY(int64_t, v, delta)
}
ILIAS_NET2_LOCAL int32_t
atomic_fetch_sub32(volatile int32_t *v, int32_t delta)
{
	BODY(int32_t, v, delta)
}
ILIAS_NET2_LOCAL int16_t
atomic_fetch_sub16(volatile int16_t *v, int16_t delta)
{
	BODY(int16_t, v, delta)
}
ILIAS_NET2_LOCAL int8_t
atomic_fetch_sub8(volatile int8_t *v, int8_t delta)
{
	BODY(int8_t, v, delta)
}
#undef BODY


#define BODY(type, v, delta)						\
	type orig;							\
									\
	LOCK(v);							\
	orig = *rv;							\
	*v |= delta;							\
	UNLOCK(v);							\
	return orig;
ILIAS_NET2_LOCAL int64_t
atomic_fetch_or64(volatile int64_t *v, int64_t delta)
{
	BODY(int64_t, v, delta)
}
ILIAS_NET2_LOCAL int32_t
atomic_fetch_or32(volatile int32_t *v, int32_t delta)
{
	BODY(int32_t, v, delta)
}
ILIAS_NET2_LOCAL int16_t
atomic_fetch_or16(volatile int16_t *v, int16_t delta)
{
	BODY(int16_t, v, delta)
}
ILIAS_NET2_LOCAL int8_t
atomic_fetch_or8(volatile int8_t *v, int8_t delta)
{
	BODY(int8_t, v, delta)
}
#undef BODY


#define BODY(type, v, delta)						\
	type orig;							\
									\
	LOCK(v);							\
	orig = *rv;							\
	*v &= delta;							\
	UNLOCK(v);							\
	return orig;
ILIAS_NET2_LOCAL int64_t
atomic_fetch_and64(volatile int64_t *v, int64_t delta)
{
	BODY(int64_t, v, delta)
}
ILIAS_NET2_LOCAL int32_t
atomic_fetch_and32(volatile int32_t *v, int32_t delta)
{
	BODY(int32_t, v, delta)
}
ILIAS_NET2_LOCAL int16_t
atomic_fetch_and16(volatile int16_t *v, int16_t delta)
{
	BODY(int16_t, v, delta)
}
ILIAS_NET2_LOCAL int8_t
atomic_fetch_and8(volatile int8_t *v, int8_t delta)
{
	BODY(int8_t, v, delta)
}
#undef BODY


#endif /* !defined(HAVE_STDATOMIC_H) && !defined(WIN32) */
