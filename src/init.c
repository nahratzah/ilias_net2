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
#include <ilias/net2/init.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/thread.h>
#include <ilias/net2/bsd_compat/error.h>
#include <ilias/net2/bsd_compat/sysexits.h>
#include <ilias/net2/bsd_compat/secure_random.h>
#include <assert.h>
#include <errno.h>

#ifdef WIN32
#include <Winsock2.h>
#endif

#include "handshake.h"

ILIAS_NET2_EXPORT int
net2_init()
{
#ifdef WIN32
	WSADATA	wsa_data;
	int	minor, major;
#endif
	int	rv;

	if ((rv = net2_memory_init()) != 0)
		goto fail_0;
	if ((rv = net2_thread_init()) != 0)
		goto fail_1;
	if ((rv = secure_random_init()) != 0)
		goto fail_2;

#ifdef WIN32
	if ((rv = WSAStartup(MAKEWORD(2, 2), &wsa_data)) != 0) {
		warnx(EX_OSERR, "WSAStartup fail: %d", rv);
		goto fail_3;
	}
	major = LOBYTE(wsa_data.wVersion);
	minor = HIBYTE(wsa_data.wVersion);
	if (minor != 2 && major != 2) {
		warnx(EX_OSERR, "Winsock %d.%d is too old, "
		    "upgrade your windows.", major, minor);
		rv = EINVAL;
		goto fail_4;
	}
#endif

	/* No errors. */
	return 0;


fail_4:
#ifdef WIN32
	WSACleanup();
#endif
fail_3:
	secure_random_deinit();
fail_2:
	net2_thread_fini();
fail_1:
	net2_memory_fini();
fail_0:
	assert(rv != 0);
	return rv;
}

ILIAS_NET2_EXPORT void
net2_cleanup()
{
#ifdef WIN32
	WSACleanup();
#endif
	secure_random_deinit();
	net2_thread_fini();
	net2_memory_fini();
}
