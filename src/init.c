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
#include <ilias/net2/bsd_compat/error.h>
#include <ilias/net2/bsd_compat/sysexits.h>

#ifdef WIN32
#include <Winsock2.h>
#endif

#include "handshake.h"

ILIAS_NET2_EXPORT void
net2_init()
{
	net2_memory_init();

#ifdef WIN32
	WSADATA	wsa_data;
	int	rv;
	int	minor, major;

	if ((rv = WSAStartup(MAKEWORD(2, 2), &wsa_data)) != 0)
		errx(EX_OSERR, "WSAStartup fail: %d", rv);
	major = LOBYTE(wsa_data.wVersion);
	minor = HIBYTE(wsa_data.wVersion);
	if (minor != 2 && major != 2) {
		WSACleanup();
		errx(EX_OSERR, "Winsock %d.%d is too old, "
		    "upgrade your windows.", major, minor);
	}
#endif

	net2_init_poetry();
}

ILIAS_NET2_EXPORT void
net2_cleanup()
{
	net2_destroy_poetry();

#ifdef WIN32
	WSACleanup();
#endif

	net2_memory_fini();
}
