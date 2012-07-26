#ifndef ILIAS_NET2_BSD_COMPAT_STDATOMIC_H
#define ILIAS_NET2_BSD_COMPAT_STDATOMIC_H

#include <ilias/net2/config.h>
#include <ilias/net2/ilias_net2_export.h>

#ifdef HAVE_STDATOMIC_H
#include <stdatomic.h>
#elif WIN32
#include <ilias/net2/bsd_compat/win32_atomic.h>
#else
#include <ilias/net2/bsd_compat/spl_atomic.h>
#endif /* !HAVE_STDATOMIC_H */

/* ASM pause instruction for clang/gcc on intel 32/64 bit. */
#if (defined(__GNUC__) || defined(__clang__)) &&			\
    (defined(__amd64__) || defined(__x86_64__) || defined(__i386__))
#define SPINWAIT()	do { __asm __volatile("pause":::"memory"); } while (0)
#endif

/* Fallback implementation for spinwait. */
#ifndef SPINWAIT
#define SPINWAIT	do {} while (0)
#endif

#endif /* ILIAS_NET2_BSD_COMPAT_STDATOMIC_H */
