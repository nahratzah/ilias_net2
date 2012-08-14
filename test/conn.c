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
#include "testconn.h"
#include "test.h"
#include <ilias/net2/init.h>
#include <ilias/net2/connection.h>
#include <ilias/net2/buffer.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

int fail = 0;
#define DOODLE	"Yankee Doodle sing a song\ndoodaa, doodaa"
#define PH_LEN	net2_ph_overhead

int	cb_done_called;
int	cb_fail_called;



int
test_conn_create_destroy()
{
	struct net2_connection	*c1, *c2;

	printf("test 1: testing connection destroy invocation\n");
	if (testconn(&c1, &c2)) {
		printf("  failed to create connections\n");
		return -1;
	}

	net2_connection_destroy(c1);
	net2_connection_destroy(c2);
	return 0;
}

int
main()
{
	test_start();
	net2_init();

	if (test_conn_create_destroy())
		return -1;

	testconn_cleanup();

	net2_cleanup();
	test_fini();
	return fail;
}
