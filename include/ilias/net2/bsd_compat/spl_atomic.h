#ifndef ILIAS_NET2_BSD_COMPAT_SPL_ATOMIC_H
#define ILIAS_NET2_BSD_COMPAT_SPL_ATOMIC_H

#include <sys/types.h>
#include <stdint.h>
#include <assert.h>

#define _Atomic(type)	struct { volatile type __val; }
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

typedef _Atomic(size_t)			atomic_size_t;
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
 * Atomic exchange.
 */
ILIAS_NET2_LOCAL
void	atomic_exchange64(volatile int64_t*, int64_t*, int64_t);
ILIAS_NET2_LOCAL
void	atomic_exchange32(volatile int32_t*, int32_t*, int32_t);
ILIAS_NET2_LOCAL
void	atomic_exchange16(volatile int16_t*, int16_t*, int16_t);
ILIAS_NET2_LOCAL
void	atomic_exchange8(volatile int8_t*, int8_t*, int8_t);
#define atomic_exchange(v, newval)					\
	({								\
		__typeof__((v)->__val) oldval;				\
									\
		select_8_16_32_64(*v,					\
		    atomic_exchange8(					\
			(volatile int8_t*)&(v)->__val,			\
			(int8_t*)&(oldval), (newval)),			\
		    atomic_exchange16(					\
			(volatile int16_t*)&(v)->__val,			\
			(int16_t*)&(oldval), (newval)),			\
		    atomic_exchange32(					\
			(volatile int32_t*)&(v)->__val,			\
			(int32_t*)&(oldval), (newval)),			\
		    atomic_exchange64(					\
			(volatile int64_t*)&(v)->__val,			\
			(int64_t*)&(oldval), (newval)));		\
									\
		oldval;							\
	})
#define atomic_exchange_explicit(v, newval, order)			\
	atomic_exchange(v, newval)

/*
 * Atomic compare/exchange.
 */
ILIAS_NET2_LOCAL
int	atomic_compare_exchange64_strong(volatile int64_t*, int64_t*, int64_t);
ILIAS_NET2_LOCAL
int	atomic_compare_exchange32_strong(volatile int32_t*, int32_t*, int32_t);
ILIAS_NET2_LOCAL
int	atomic_compare_exchange16_strong(volatile int16_t*, int16_t*, int16_t);
ILIAS_NET2_LOCAL
int	atomic_compare_exchange8_strong(volatile int8_t*, int8_t*, int8_t);
#define atomic_compare_exchange_strong(v, oldval, newval)		\
	select_8_16_32_64(*v,						\
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

ILIAS_NET2_LOCAL
int	atomic_compare_exchange64_weak(volatile int64_t*, int64_t*, int64_t);
ILIAS_NET2_LOCAL
int	atomic_compare_exchange32_weak(volatile int32_t*, int32_t*, int32_t);
ILIAS_NET2_LOCAL
int	atomic_compare_exchange16_weak(volatile int16_t*, int16_t*, int16_t);
ILIAS_NET2_LOCAL
int	atomic_compare_exchange8_weak(volatile int8_t*, int8_t*, int8_t);
#define atomic_compare_exchange_weak(v, oldval, newval)			\
	select_8_16_32_64(*v,						\
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

ILIAS_NET2_LOCAL
int64_t	atomic_load64(volatile int64_t*);
ILIAS_NET2_LOCAL
int32_t	atomic_load32(volatile int32_t*);
ILIAS_NET2_LOCAL
int16_t	atomic_load16(volatile int16_t*);
ILIAS_NET2_LOCAL
int8_t	atomic_load8(volatile int8_t*);
#define atomic_load(v)							\
	select_8_16_32_64(*v,						\
	    atomic_load8((volatile int8_t*)&(v)->__val),		\
	    atomic_load16((volatile int16_t*)&(v)->__val),		\
	    atomic_load32((volatile int32_t*)&(v)->__val),		\
	    atomic_load64((volatile int64_t*)&(v)->__val))
#define atomic_load_explicit(v, memory)					\
	atomic_load((v))

ILIAS_NET2_LOCAL
void	atomic_store64(volatile int64_t*, int64_t);
ILIAS_NET2_LOCAL
void	atomic_store32(volatile int32_t*, int32_t);
ILIAS_NET2_LOCAL
void	atomic_store16(volatile int16_t*, int16_t);
ILIAS_NET2_LOCAL
void	atomic_store8(volatile int8_t*, int8_t);
#define atomic_store(v, val)						\
	select_8_16_32_64(*v,						\
	    atomic_store8((volatile int8_t*)&(v)->__val, (val)),	\
	    atomic_store16((volatile int16_t*)&(v)->__val, (val)),	\
	    atomic_store32((volatile int32_t*)&(v)->__val, (val)),	\
	    atomic_store64((volatile int64_t*)&(v)->__val, (val)))
#define atomic_store_explicit(v, val, memory)				\
	atomic_store((v), (val))

ILIAS_NET2_LOCAL
int64_t	atomic_fetch_add64(volatile int64_t*, uint64_t);
ILIAS_NET2_LOCAL
int32_t	atomic_fetch_add32(volatile int32_t*, uint32_t);
ILIAS_NET2_LOCAL
int16_t	atomic_fetch_add16(volatile int16_t*, uint16_t);
ILIAS_NET2_LOCAL
int8_t	atomic_fetch_add8(volatile int8_t*, uint8_t);
#define atomic_fetch_add(v, val)					\
	select_8_16_32_64(*v,						\
	    atomic_fetch_add8((volatile int8_t*)&(v)->__val, (val)),	\
	    atomic_fetch_add16((volatile int16_t*)&(v)->__val, (val)),	\
	    atomic_fetch_add32((volatile int32_t*)&(v)->__val, (val)),	\
	    atomic_fetch_add64((volatile int64_t*)&(v)->__val, (val)))
#define atomic_fetch_add_explicit(v, val, memory)			\
	atomic_fetch_add((v), (val))

ILIAS_NET2_LOCAL
int64_t	atomic_fetch_sub64(volatile int64_t*, uint64_t);
ILIAS_NET2_LOCAL
int32_t	atomic_fetch_sub32(volatile int32_t*, uint32_t);
ILIAS_NET2_LOCAL
int16_t	atomic_fetch_sub16(volatile int16_t*, uint16_t);
ILIAS_NET2_LOCAL
int8_t	atomic_fetch_sub8(volatile int8_t*, uint8_t);
#define atomic_fetch_sub(v, val)					\
	select_8_16_32_64(*v,						\
	    atomic_fetch_sub8((volatile int8_t*)&(v)->__val, (val)),	\
	    atomic_fetch_sub16((volatile int16_t*)&(v)->__val, (val)),	\
	    atomic_fetch_sub32((volatile int32_t*)&(v)->__val, (val)),	\
	    atomic_fetch_sub64((volatile int64_t*)&(v)->__val, (val)))
#define atomic_fetch_sub_explicit(v, val, memory)			\
	atomic_fetch_sub((v), (val))

ILIAS_NET2_LOCAL
int64_t	atomic_fetch_or64(volatile int64_t*, int64_t);
ILIAS_NET2_LOCAL
int32_t	atomic_fetch_or32(volatile int32_t*, int32_t);
ILIAS_NET2_LOCAL
int16_t	atomic_fetch_or16(volatile int16_t*, int16_t);
ILIAS_NET2_LOCAL
int8_t	atomic_fetch_or8(volatile int8_t*, int8_t);
#define atomic_fetch_or(v, val)						\
	select_8_16_32_64(*v,						\
	    atomic_fetch_or8((volatile int8_t*)&(v)->__val, (val)),	\
	    atomic_fetch_or16((volatile int16_t*)&(v)->__val, (val)),	\
	    atomic_fetch_or32((volatile int32_t*)&(v)->__val, (val)),	\
	    atomic_fetch_or64((volatile int64_t*)&(v)->__val, (val)))
#define atomic_fetch_or_explicit(v, val, memory)			\
	atomic_fetch_or((v), (val))

ILIAS_NET2_LOCAL
int64_t	atomic_fetch_and64(volatile int64_t*, int64_t);
ILIAS_NET2_LOCAL
int32_t	atomic_fetch_and32(volatile int32_t*, int32_t);
ILIAS_NET2_LOCAL
int16_t	atomic_fetch_and16(volatile int16_t*, int16_t);
ILIAS_NET2_LOCAL
int8_t	atomic_fetch_and8(volatile int8_t*, int8_t);
#define atomic_fetch_and(v, val)					\
	select_8_16_32_64(*v,						\
	    atomic_fetch_and8((volatile int8_t*)&(v)->__val, (val)),	\
	    atomic_fetch_and16((volatile int16_t*)&(v)->__val, (val)),	\
	    atomic_fetch_and32((volatile int32_t*)&(v)->__val, (val)),	\
	    atomic_fetch_and64((volatile int64_t*)&(v)->__val, (val)))
#define atomic_fetch_and_explicit(v, val, memory)			\
	atomic_fetch_and((v), (val))

#define atomic_init(v, val)						\
	do { (v)->__val = (val); } while (0)

#define atomic_thread_fence(order)					\
	__sync_synchronize()
#define atomic_signal_fence(order)					\
	__asm __volatile("":::"memory");

#endif /* ILIAS_NET2_BSD_COMPAT_SPL_ATOMIC_H */
