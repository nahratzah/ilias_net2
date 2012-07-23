/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
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


#include <ilias/net2/bsd_compat/secure_random.h>

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ilias/net2/bsd_compat/error.h>
#include <ilias/net2/bsd_compat/sysexits.h>

ILIAS_NET2_EXPORT uint32_t
win32_secure_random()
{
	uint32_t result;

	win32_secure_random_buf(&result, sizeof(result));
	return result;
}

ILIAS_NET2_EXPORT void
win32_secure_random_buf(void *ptr, size_t len)
{
	BOOLEAN (APIENTRY *pfn)(void*, ULONG);
	HMODULE hLib;
	
	hLib = LoadLibrary("ADVAPI32.DLL");
	if (!hLib)
		err(EX_OSERR, "LoadLibrary ADVAPI32.DLL: error code %d", (int32_t)GetLastError());
	pfn = (BOOLEAN (APIENTRY *)(void*, ULONG))GetProcAddress(hLib, "SystemFunction036");
	if (!pfn) {
		const int32_t last_error = GetLastError();
		FreeLibrary(hLib);
		err(EX_OSERR, "GetProcAddress(%s \"%s\") not found: error code %d", "RtlGenRandom", "SystemFunction036", last_error);
	}

	if (!pfn(ptr, len)) {
		FreeLibrary(hLib);
		err(EX_OSERR, "RtlGenRandom");
	}
	FreeLibrary(hLib);
}

ILIAS_NET2_EXPORT uint32_t
win32_secure_random_uniform(uint32_t upper_bound)
{
	/*
	 * Lifted from OpenBSD.
	 */
	uint32_t r, min;

	if (upper_bound < 2)
		return 0;

#if (ULONG_MAX > 0xffffffffUL)
	min = 0x100000000UL % upper_bound;
#else
	/* Calculate (2**32 % upper_bound) avoiding 64-bit math */
	if (upper_bound > 0x80000000)
		min = 1 + ~upper_bound;		/* 2**32 - upper_bound */
	else {
		/* (2**32 - (x * 2)) % x == 2**32 % x when x <= 2**31 */
		min = ((0xffffffff - (upper_bound * 2)) + 1) % upper_bound;
	}
#endif

	/*
	 * This could theoretically loop forever but each retry has
	 * p > 0.5 (worst case, usually far better) of selecting a
	 * number inside the range we need, so it should rarely need
	 * to re-roll.
	 */
	for (;;) {
		r = secure_random();
		if (r >= min)
			break;
	}

	return r % upper_bound;
}

#else
#error "No implementation of secure random present."
#endif
