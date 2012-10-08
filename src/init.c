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
#include <ilias/net2/memory.h>
#include <ilias/net2/thread.h>
#include <ilias/net2/workq.h>
#include <ilias/net2/bsd_compat/error.h>
#include <ilias/net2/bsd_compat/sysexits.h>
#include <ilias/net2/bsd_compat/secure_random.h>
#include <assert.h>
#include <errno.h>

#ifdef WIN32
#include <Winsock2.h>
#endif

#include "handshake.h"

#if !defined(WIN32) && (defined(__GNUC__) || defined(__clang__))
#define constructor	__attribute__((constructor))
#define destructor	__attribute__((destructor))
#elif defined(WIN32)
#define constructor	/* Using dllmain instead. */
#define destructor	/* Using dllmain instead. */
#else
#error Need some way to define constructor/destructor.
#endif


static int
constructor
net2_init()
{
#ifdef WIN32
	WSADATA	wsa_data;
	int	minor, major;
#endif
	int	rv;

	if ((rv = net2_memory_init()) != 0)
		goto fail_0;
	if ((rv = secure_random_init()) != 0)
		goto fail_1;

#ifdef WIN32
	if ((rv = WSAStartup(MAKEWORD(2, 2), &wsa_data)) != 0) {
		warnx("WSAStartup fail: %d", rv);
		goto fail_2;
	}
	major = LOBYTE(wsa_data.wVersion);
	minor = HIBYTE(wsa_data.wVersion);
	if (minor != 2 && major != 2) {
		warnx("Winsock %d.%d is too old, "
		    "upgrade your windows.", major, minor);
		rv = EINVAL;
		goto fail_3;
	}
#endif
	if ((rv = net2_workq_init()) != 0)
		goto fail_3;

	/* No errors. */
	return 0;


fail_4:
	net2_workq_fini();
fail_3:
#ifdef WIN32
	WSACleanup();
#endif
fail_2:
	secure_random_deinit();
fail_1:
	net2_memory_fini();
fail_0:
	assert(rv != 0);
	return rv;
}

static void
destructor
net2_cleanup()
{
	net2_workq_fini();
#ifdef WIN32
	WSACleanup();
#endif
	secure_random_deinit();
	net2_memory_fini();
}

#ifdef WIN32
/* Runtime linker will call this function. */
BOOL
WINAPI DllMain(HINSTANCE hinstDll, DWORD fdwReason, LPVOID reserved)
{
	static int init = 0;

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		if (net2_init() != 0)
			return FALSE;
		init = 1;
		break;
	case DLL_PROCESS_DETACH:
		if (init)
			net2_cleanup();
		break;
	}
	return TRUE;
}
#endif /* WIN32 */
