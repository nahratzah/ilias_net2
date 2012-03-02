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
#include "test.h"
#include <ilias/net2/init.h>
#include <ilias/net2/carver.h>
#include <ilias/net2/buffer.h>
#include <bsd_compat/secure_random.h>
#include <bsd_compat/minmax.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int fail = 0;

struct net2_buffer*
mk_buffer(size_t sz)
{
	uint8_t		 tmp[1024];
	size_t		 reduce;
	struct net2_buffer
			*out;

	if ((out = net2_buffer_new()) == NULL) {
		fprintf(stderr, "Could not allocate buffer.\n");
		abort();
	}

	while (sz > 0) {
		reduce = MIN(sizeof(tmp), sz);

		secure_random_buf(tmp, reduce);
		if (net2_buffer_add(out, tmp, reduce)) {
			fprintf(stderr, "Could not add to buffer.\n");
			abort();
		}
		sz -= reduce;
	}
	return out;
}

int
test_run(size_t packet_sz)
{
	struct net2_buffer
			*original;
	struct net2_carver
			 carver;
	struct net2_combiner
			 combiner;

	original = mk_buffer(0xfffe);

	if (net2_carver_init(&carver, NET2_CARVER_16BIT, original)) {
		fprintf(stderr, "Failed to init carver.");
		return 1;
	}
	if (net2_combiner_init(&combiner, NET2_CARVER_16BIT)) {
		fprintf(stderr, "Failed to init combiner.");
		return 1;
	}

	net2_carver_deinit(&carver);
	net2_combiner_deinit(&combiner);
	net2_buffer_free(original);
	return 0;
}

int
main()
{
	test_start();
	net2_init();

	if (test_run(17))
		fail++;
	if (test_run(32))
		fail++;
	if (test_run(1000000))
		fail++;

	net2_cleanup();
	test_fini();

	return fail;
}
