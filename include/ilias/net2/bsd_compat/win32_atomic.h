#ifndef ILIAS_NET2_BSD_COMPAT_WIN32_ATOMIC_H
#define ILIAS_NET2_BSD_COMPAT_WIN32_ATOMIC_H

#ifndef _MSC_VER
#error MS Interlocked code requires MSC.
#endif

#include <intrin.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#define _Atomic(type)	struct { type volatile __val; }
typedef _Atomic(char)			atomic_char;
typedef _Atomic(signed char)		atomic_schar;
typedef _Atomic(unsigned char)		atomic_uchar;
typedef _Atomic(signed short)		atomic_short;
typedef _Atomic(unsigned short)		atomic_ushort;
typedef _Atomic(signed int)		atomic_int;
typedef _Atomic(unsigned int)		atomic_uint;
typedef _Atomic(signed long)		atomic_long;
typedef _Atomic(unsigned long)		atomic_ulong;
typedef _Atomic(signed long long)	atomic_llong;
typedef _Atomic(unsigned long long)	atomic_ullong;
typedef _Atomic(wchar_t)		atomic_wchar_t;

typedef _Atomic(size_t)			atomic_size_t;
typedef _Atomic(ptrdiff_t)		atomic_ptrdiff_t;
typedef _Atomic(intptr_t)		atomic_intptr_t;
typedef _Atomic(uintptr_t)		atomic_uintptr_t;

/*
 * Choose a statement based on the number of bits in variable.
 */
#define select_8_16_32_64(variable, stmt8, stmt16, stmt32, stmt64)	\
	(								\
		(sizeof (variable) == 1 ? (stmt8) :			\
		(sizeof (variable) == 2 ? (stmt16) :			\
		(sizeof (variable) == 4 ? (stmt32) :			\
		(sizeof (variable) == 8 ? (stmt64) :			\
		    (assert(0), 0)					\
		))))							\
	)

/*
 * Atomic compare/exchange.
 */
static __inline int
atomic_compare_exchange64_strong(volatile int64_t *v,
    int64_t *oldval, int64_t newval)
{
	int64_t expect;

	assert(sizeof(int64_t) == sizeof(long long));
	_ReadWriteBarrier();
	expect = *oldval;
	*oldval = _InterlockedCompareExchange64(v, newval, *oldval);
	_ReadWriteBarrier();
	return (*oldval == expect);
}
static __inline int
atomic_compare_exchange32_strong(volatile int32_t *v,
    int32_t *oldval, int32_t newval)
{
	int32_t expect;

	assert(sizeof(int32_t) == sizeof(long));
	_ReadWriteBarrier();
	expect = *oldval;
	*oldval = _InterlockedCompareExchange((volatile long*)v,
	    newval, *oldval);
	_ReadWriteBarrier();
	return (*oldval == expect);
}
static __inline int
atomic_compare_exchange16_strong(volatile int16_t *v,
    int16_t *oldval, int16_t newval)
{
	int16_t expect;

	assert(sizeof(int16_t) == sizeof(short));
	_ReadWriteBarrier();
	expect = *oldval;
	*oldval = _InterlockedCompareExchange16((volatile short*)v,
	    newval, *oldval);
	_ReadWriteBarrier();
	return (*oldval == expect);
}
static __inline int
atomic_compare_exchange8_strong(volatile int8_t *v,
    int8_t *oldval, int8_t newval)
{
	int8_t expect;

	assert(sizeof(int8_t) == sizeof(char));
	_ReadWriteBarrier();
	expect = *oldval;
	*oldval = _InterlockedCompareExchange8((volatile char*)v,
	    newval, *oldval);
	_ReadWriteBarrier();
	return (*oldval == expect);
}
#define atomic_compare_exchange_strong(v, oldval, newval)		\
	select_8_16_32_64(*(v),						\
	    atomic_compare_exchange8_strong(				\
	      (volatile int8_t*)&(v)->__val,				\
	      (int8_t*)(oldval), (newval)),				\
	    atomic_compare_exchange16_strong(				\
	      (volatile int16_t*)&(v)->__val,				\
	      (int16_t*)(oldval), (newval)),				\
	    atomic_compare_exchange32_strong(				\
	      (volatile int32_t*)&(v)->__val,				\
	      (int32_t*)(oldval), (newval)),				\
	    atomic_compare_exchange64_strong(				\
	      (volatile int64_t*)&(v)->__val,				\
	      (int64_t*)(oldval), (newval)))
#define atomic_compare_exchange_strong_explicit(v, o, n, succes, fail)	\
	atomic_compare_exchange_strong((v), (o), (n))

static __inline int
atomic_compare_exchange64_weak(volatile int64_t *v,
    int64_t *oldval, int64_t newval)
{
	assert(sizeof(int64_t) == sizeof(long long));

	if (*v != *oldval) {
		*oldval = *v;
		_ReadWriteBarrier();
		return 0;
	}

	return atomic_compare_exchange64_strong(v, oldval, newval);
}
static __inline int
atomic_compare_exchange32_weak(volatile int32_t *v,
    int32_t *oldval, int32_t newval)
{
	assert(sizeof(int32_t) == sizeof(long));

	if (*v != *oldval) {
		*oldval = *v;
		_ReadWriteBarrier();
		return 0;
	}

	return atomic_compare_exchange32_strong(v, oldval, newval);
}
static __inline int
atomic_compare_exchange16_weak(volatile int16_t *v,
    int16_t *oldval, int16_t newval)
{
	assert(sizeof(int16_t) == sizeof(short));

	if (*v != *oldval) {
		*oldval = *v;
		_ReadWriteBarrier();
		return 0;
	}

	return atomic_compare_exchange16_strong(v, oldval, newval);
}
static __inline int
atomic_compare_exchange8_weak(volatile int8_t *v,
    int8_t *oldval, int8_t newval)
{
	assert(sizeof(int8_t) == sizeof(char));

	if (*v != *oldval) {
		*oldval = *v;
		_ReadWriteBarrier();
		return 0;
	}

	return atomic_compare_exchange8_strong(v, oldval, newval);
}
#define atomic_compare_exchange_weak(v, oldval, newval)			\
	select_8_16_32_64(*(v),						\
	    atomic_compare_exchange8_weak(				\
	      (volatile int8_t*)&(v)->__val,				\
	      (int8_t*)(oldval), (newval)),				\
	    atomic_compare_exchange16_weak(				\
	      (volatile int16_t*)&(v)->__val,				\
	      (int16_t*)(oldval), (newval)),				\
	    atomic_compare_exchange32_weak(				\
	      (volatile int32_t*)&(v)->__val,				\
	      (int32_t*)(oldval), (newval)),				\
	    atomic_compare_exchange64_weak(				\
	      (volatile int64_t*)&(v)->__val,				\
	      (int64_t*)(oldval), (newval)))
#define atomic_compare_exchange_weak_explicit(v, o, n, succes, fail)	\
	atomic_compare_exchange_weak((v), (o), (n))

static __inline int64_t
atomic_load64(volatile int64_t *v)
{
#ifdef _WIN64
	int64_t rv;

	_ReadWriteBarrier();
	rv = *v;
	_ReadWriteBarrier();
	return rv;
#else
	abort();	/* Not atomic mov. */
	for (;;);
#endif
}
static __inline int32_t
atomic_load32(volatile int32_t *v)
{
	int32_t rv;

	_ReadWriteBarrier();
	rv = *v;
	_ReadWriteBarrier();
	return rv;
}
static __inline int16_t
atomic_load16(volatile int16_t *v)
{
	int16_t rv;

	_ReadWriteBarrier();
	rv = *v;
	_ReadWriteBarrier();
	return rv;
}
static __inline int8_t
atomic_load8(volatile int8_t *v)
{
	int8_t rv;

	_ReadWriteBarrier();
	rv = *v;
	_ReadWriteBarrier();
	return rv;
}
#define atomic_load(v)							\
	select_8_16_32_64(*(v),						\
	    atomic_load8((volatile int8_t*)&(v)->__val),		\
	    atomic_load16((volatile int16_t*)&(v)->__val),		\
	    atomic_load32((volatile int32_t*)&(v)->__val),		\
	    atomic_load64((volatile int64_t*)&(v)->__val))
#define atomic_load_explicit(v, memory)					\
	atomic_load((v))

static __inline void
atomic_store64(volatile int64_t *v, int64_t val)
{
#ifdef _WIN64
	_ReadWriteBarrier();
	*v = val;
	_ReadWriteBarrier();
#else
	abort();	/* Not atomic mov. */
#endif
}
static __inline void
atomic_store32(volatile int32_t *v, int32_t val)
{
	_ReadWriteBarrier();
	*v = val;
	_ReadWriteBarrier();
}
static __inline void
atomic_store16(volatile int16_t *v, int16_t val)
{
	_ReadWriteBarrier();
	*v = val;
	_ReadWriteBarrier();
}
static __inline void
atomic_store8(volatile int8_t *v, int8_t val)
{
	_ReadWriteBarrier();
	*v = val;
	_ReadWriteBarrier();
}
#define atomic_store(v, val)						\
	select_8_16_32_64(*(v),						\
	    atomic_store8((volatile int8_t*)&(v)->__val, (val)),	\
	    atomic_store16((volatile int16_t*)&(v)->__val, (val)),	\
	    atomic_store32((volatile int32_t*)&(v)->__val, (val)),	\
	    atomic_store64((volatile int64_t*)&(v)->__val, (val)))
#define atomic_store_explicit(v, val, memory)				\
	atomic_store((v), (val))

static __inline int64_t
atomic_fetch_add64(volatile int64_t *v, uint64_t add)
{
#ifdef _WIN64
	return _InterlockedExchangeAdd64(v, add);
#else
	abort();	/* Unsupported. */
#endif
}
static __inline int32_t
atomic_fetch_add32(volatile int32_t *v, uint32_t add)
{
	assert(sizeof(int32_t) == sizeof(long));
	return _InterlockedExchangeAdd((volatile long*)v, add);
}
static __inline int16_t
atomic_fetch_add16(volatile int16_t *v, uint16_t add)
{
	assert(sizeof(int16_t) == sizeof(short));
	return _InterlockedExchangeAdd16((volatile short*)v, add);
}
static __inline int8_t
atomic_fetch_add8(volatile int8_t *v, uint8_t add)
{
	assert(sizeof(int8_t) == sizeof(char));
	return _InterlockedExchangeAdd8((volatile char*)v, add);
}
#define atomic_fetch_add(v, val)					\
	select_8_16_32_64(*(v),						\
	    atomic_fetch_add8((volatile int8_t*)&(v)->__val, (val)),	\
	    atomic_fetch_add16((volatile int16_t*)&(v)->__val, (val)),	\
	    atomic_fetch_add32((volatile int32_t*)&(v)->__val, (val)),	\
	    atomic_fetch_add64((volatile int64_t*)&(v)->__val, (val)))
#define atomic_fetch_add_explicit(v, val, memory)			\
	atomic_fetch_add((v), (val))

static __inline int64_t
atomic_fetch_sub64(volatile int64_t *v, uint64_t add)
{
#ifdef _WIN64
	return _InterlockedExchangeAdd64(v, ~add);
#else
	abort();	/* Unsupported. */
#endif
}
static __inline int32_t
atomic_fetch_sub32(volatile int32_t *v, uint32_t add)
{
	assert(sizeof(int32_t) == sizeof(long));
	return _InterlockedExchangeAdd((volatile long*)v, -(int32_t)add);
}
static __inline int16_t
atomic_fetch_sub16(volatile int16_t *v, uint16_t add)
{
	assert(sizeof(int16_t) == sizeof(short));
	return _InterlockedExchangeAdd16((volatile short*)v, -(int16_t)add);
}
static __inline int8_t
atomic_fetch_sub8(volatile int8_t *v, uint8_t add)
{
	assert(sizeof(int8_t) == sizeof(char));
	return _InterlockedExchangeAdd8((volatile char*)v, -(int8_t)add);
}
#define atomic_fetch_sub(v, val)					\
	select_8_16_32_64(*(v),						\
	    atomic_fetch_sub8((volatile int8_t*)&(v)->__val, (val)),	\
	    atomic_fetch_sub16((volatile int16_t*)&(v)->__val, (val)),	\
	    atomic_fetch_sub32((volatile int32_t*)&(v)->__val, (val)),	\
	    atomic_fetch_sub64((volatile int64_t*)&(v)->__val, (val)))
#define atomic_fetch_sub_explicit(v, val, memory)			\
	atomic_fetch_sub((v), (val))

static __inline int64_t
atomic_fetch_or64(volatile int64_t *v, int64_t f)
{
#ifdef _WIN64
	return _InterlockedOr64(v, f);
#else
	abort();	/* Unsupported. */
#endif
}
static __inline int32_t
atomic_fetch_or32(volatile int32_t *v, int32_t f)
{
	assert(sizeof(int32_t) == sizeof(long));
	return _InterlockedOr((volatile long*)v, f);
}
static __inline int16_t
atomic_fetch_or16(volatile int16_t *v, int16_t f)
{
	assert(sizeof(int16_t) == sizeof(short));
	return _InterlockedOr16((volatile short*)v, f);
}
static __inline int8_t
atomic_fetch_or8(volatile int8_t *v, int8_t f)
{
	assert(sizeof(int8_t) == sizeof(char));
	return _InterlockedOr8((volatile char*)v, f);
}
#define atomic_fetch_or(v, val)						\
	select_8_16_32_64(*(v),						\
	    atomic_fetch_or8((volatile int8_t*)&(v)->__val, (val)),	\
	    atomic_fetch_or16((volatile int16_t*)&(v)->__val, (val)),	\
	    atomic_fetch_or32((volatile int32_t*)&(v)->__val, (val)),	\
	    atomic_fetch_or64((volatile int64_t*)&(v)->__val, (val)))
#define atomic_fetch_or_explicit(v, val, memory)			\
	atomic_fetch_or((v), (val))

static __inline int64_t
atomic_fetch_and64(volatile int64_t *v, int64_t f)
{
#ifdef _WIN64
	return _InterlockedAnd64(v, f);
#else
	abort();	/* Unsupported. */
#endif
}
static __inline int32_t
atomic_fetch_and32(volatile int32_t *v, int32_t f)
{
	assert(sizeof(int32_t) == sizeof(long));
	return _InterlockedAnd((volatile long*)v, f);
}
static __inline int16_t
atomic_fetch_and16(volatile int16_t *v, int16_t f)
{
	assert(sizeof(int16_t) == sizeof(short));
	return _InterlockedAnd16((volatile short*)v, f);
}
static __inline int8_t
atomic_fetch_and8(volatile int8_t *v, int8_t f)
{
	assert(sizeof(int8_t) == sizeof(char));
	return _InterlockedAnd8((volatile char*)v, f);
}
#define atomic_fetch_and(v, val)					\
	select_8_16_32_64(*(v),						\
	    atomic_fetch_and8((volatile int8_t*)&(v)->__val, (val)),	\
	    atomic_fetch_and16((volatile int16_t*)&(v)->__val, (val)),	\
	    atomic_fetch_and32((volatile int32_t*)&(v)->__val, (val)),	\
	    atomic_fetch_and64((volatile int64_t*)&(v)->__val, (val)))
#define atomic_fetch_and_explicit(v, val, memory)			\
	atomic_fetch_and((v), (val))

#define atomic_init(v, val)						\
	do { *v = val; } while (0)

/* Spinwait assembly for ms compiler. */
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
#define SPINWAIT()							\
	do {								\
		__asm {							\
			__asm pause					\
		};							\
	} while (0)
#endif

#endif /* ILIAS_NET2_BSD_COMPAT_WIN32_ATOMIC_H */
