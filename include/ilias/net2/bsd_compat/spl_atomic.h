#ifndef ILIAS_NET2_BSD_COMPAT_SPL_ATOMIC_H
#define ILIAS_NET2_BSD_COMPAT_SPL_ATOMIC_H

#include <sys/types.h>
#include <stdint.h>
#include <assert.h>

typedef volatile char			atomic_char;
typedef volatile signed char		atomic_schar;
typedef volatile unsigned char		atomic_uchar;
typedef volatile signed short		atomic_short;
typedef volatile unsigned short		atomic_ushort;
typedef volatile signed int		atomic_int;
typedef volatile unsigned int		atomic_uint;
typedef volatile signed long		atomic_long;
typedef volatile unsigned long		atomic_ulong;
typedef volatile signed long long	atomic_llong;
typedef volatile unsigned long long	atomic_ullong;

typedef volatile size_t			atomic_size_t;
typedef volatile intptr_t		atomic_intptr_t;
typedef volatile uintptr_t		atomic_uintptr_t;

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
	    atomic_compare_exchange8_strong((volatile int8_t*)(v),	\
	      (int8_t*)(oldval), (newval)),				\
	    atomic_compare_exchange16_strong((volatile int16_t*)(v),	\
	      (int16_t*)(oldval), (newval)),				\
	    atomic_compare_exchange32_strong((volatile int32_t*)(v),	\
	      (int32_t*)(oldval), (newval)),				\
	    atomic_compare_exchange64_strong((volatile int64_t*)(v),	\
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
	    atomic_compare_exchange8_weak((volatile int8_t*)(v),	\
	      (int8_t*)(oldval), (newval)),				\
	    atomic_compare_exchange16_weak((volatile int16_t*)(v),	\
	      (int16_t*)(oldval), (newval)),				\
	    atomic_compare_exchange32_weak((volatile int32_t*)(v),	\
	      (int32_t*)(oldval), (newval)),				\
	    atomic_compare_exchange64_weak((volatile int64_t*)(v),	\
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
	    atomic_load8((volatile int8_t*)(v)),			\
	    atomic_load16((volatile int16_t*)(v)),			\
	    atomic_load32((volatile int32_t*)(v)),			\
	    atomic_load64((volatile int64_t*)(v)))
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
	    atomic_store8((volatile int8_t*)(v), (val)),		\
	    atomic_store16((volatile int16_t*)(v), (val)),		\
	    atomic_store32((volatile int32_t*)(v), (val)),		\
	    atomic_store64((volatile int64_t*)(v), (val)))
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
	    atomic_fetch_add8((volatile int8_t*)(v), (val)),		\
	    atomic_fetch_add16((volatile int16_t*)(v), (val)),		\
	    atomic_fetch_add32((volatile int32_t*)(v), (val)),		\
	    atomic_fetch_add64((volatile int64_t*)(v), (val)))
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
	    atomic_fetch_sub8((volatile int8_t*)(v), (val)),		\
	    atomic_fetch_sub16((volatile int16_t*)(v), (val)),		\
	    atomic_fetch_sub32((volatile int32_t*)(v), (val)),		\
	    atomic_fetch_sub64((volatile int64_t*)(v), (val)))
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
	    atomic_fetch_or8((volatile int8_t*)(v), (val)),		\
	    atomic_fetch_or16((volatile int16_t*)(v), (val)),		\
	    atomic_fetch_or32((volatile int32_t*)(v), (val)),		\
	    atomic_fetch_or64((volatile int64_t*)(v), (val)))
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
	    atomic_fetch_and8((volatile int8_t*)(v), (val)),		\
	    atomic_fetch_and16((volatile int16_t*)(v), (val)),		\
	    atomic_fetch_and32((volatile int32_t*)(v), (val)),		\
	    atomic_fetch_and64((volatile int64_t*)(v), (val)))
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

#endif /* ILIAS_NET2_BSD_COMPAT_SPL_ATOMIC_H */
