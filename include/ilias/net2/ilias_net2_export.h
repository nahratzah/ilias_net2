/*
 * Copyright (c) 2012 Ariane van der Steldt <ariane@stack.nl>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef ILIAS_ILIAS_NET2_EXPORT_H
#define ILIAS_ILIAS_NET2_EXPORT_H


/* Include ilias config here, so I won't keep tripping over missing include. */
#include <ilias/net2/config.h>


#if defined(WIN32)
#ifdef ilias_net2_EXPORTS
#define ILIAS_NET2_EXPORT	__declspec(dllexport)
#define ILIAS_NET2_LOCAL	/* nothing */
#else
#define ILIAS_NET2_EXPORT	__declspec(dllimport)
#define ILIAS_NET2_LOCAL	/* nothing */
#endif /* ilias_net2_EXPORTS */
#elif defined(__GNUC__) || defined(__clang__)
#define ILIAS_NET2_EXPORT	__attribute__ ((visibility ("default")))
#define ILIAS_NET2_LOCAL	__attribute__ ((visibility ("hidden")))
#else
#define ILIAS_NET2_EXPORT	/* nothing */
#define ILIAS_NET2_LOCAL	/* nothing */
#endif

#if defined(__GNUC__) || defined(__clang__)
#define ILIAS_NET2__dead	__attribute__ ((__noreturn__))
#define ILIAS_NET2__unused	__attribute__ ((__unused__))
#else
#define ILIAS_NET2__dead	/* nothing */
#define ILIAS_NET2__unused	/* nothing */
#endif

#ifdef __cplusplus
#define ILIAS_NET2__begin_cdecl	extern "C" {
#define ILIAS_NET2__end_cdecl	}
#else
#define ILIAS_NET2__begin_cdecl	/* This is C */
#define ILIAS_NET2__end_cdecl	/* This is C */
#endif


#endif /* ILIAS_ILIAS_NET2_EXPORT_H */
