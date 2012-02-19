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
#include <ilias/net2/hash.h>
#include <event2/buffer.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int fail = 0;
const char	*father = "Luke, I am your father.";

const uint8_t	 father_sha256[] = {
	0x5d, 0x80, 0x82, 0xc2,  0xea, 0xbf, 0xe3, 0x6a,
	0x51, 0x3a, 0x64, 0x47,  0x00, 0x15, 0x5b, 0xc4,
	0x79, 0xce, 0xee, 0x85,  0x33, 0x45, 0x9e, 0x71,
	0x67, 0x8b, 0x68, 0x9b,  0xea, 0xbd, 0xd7, 0xd6
};

const uint8_t	 father_sha384[] = {
	0xec, 0x2c, 0x17, 0xed,  0x88, 0x6a, 0xa2, 0x9b,
	0x30, 0x67, 0x69, 0x0d,  0xe3, 0x19, 0xcf, 0xdc,
	0xad, 0x69, 0x31, 0x3e,  0x00, 0x39, 0x03, 0x39,
	0xd5, 0x6d, 0xfe, 0xc1,  0x3d, 0xde, 0x38, 0x4b,
	0xf0, 0x63, 0x42, 0xcd,  0xf9, 0xf5, 0x8f, 0xfb,
	0x5a, 0x9f, 0xcd, 0xfc,  0xc9, 0xdb, 0x3c, 0x93
};

const uint8_t	 father_sha512[] = {
	0x97, 0x59, 0xa1, 0x85,  0x65, 0xf8, 0x17, 0x20,
	0xc1, 0x12, 0xd8, 0x40,  0x41, 0xec, 0x1a, 0xa2,
	0x31, 0x96, 0x37, 0x8d,  0x27, 0xcf, 0xe0, 0xf4,
	0x7a, 0xd3, 0x5d, 0x0a,  0xfa, 0xd5, 0x84, 0x21,
	0x38, 0x46, 0xf4, 0x6f,  0x50, 0x99, 0x41, 0x68,
	0xed, 0x09, 0x93, 0xbe,  0x11, 0x93, 0xdc, 0x59,
	0x2b, 0x1a, 0x04, 0xf0,  0x40, 0x4b, 0x9d, 0xf5,
	0x87, 0x17, 0x59, 0x74,  0xc9, 0x7a, 0x1f, 0xfe
};

int
test_hash(const char *name, const void *in, size_t inlen,
    const void *expect, size_t expectlen)
{
	struct net2_buffer	*buf;
	int			 alg;
	struct net2_hash_ctx	*ctx;
	void			*result;

	alg = net2_hash_findname(name);
	if (alg == -1) {
		printf("  failed to find algorithm %s\n", name);
		return 0;
	}
	if (strcmp(net2_hash_getname(alg), name) != 0) {
		printf("  found algorithm \"%s\" by name, "
		    "but result has name \"%s\"\n",
		    name, net2_hash_getname(alg));
		fail++;
	}

	ctx = net2_hashctx_new(alg, NULL, 0);
	if (ctx == NULL) {
		printf("  net2_hashctx_new(%d) failed\n", alg);
		fail++;
		return 0;
	}

	net2_hashctx_update(ctx, in, inlen);
	buf = net2_hashctx_finalfree(ctx);
	if (buf == NULL) {
		printf("  net2_hashctx_finalfree returned NULL buffer\n");
		fail++;
	}

	if (net2_buffer_length(buf) != expectlen) {
		printf("  returned hash has length %lu, expected %lu\n",
		    (unsigned long)net2_buffer_length(buf),
		    (unsigned long)expectlen);
		fail++;
	} else {
		result = net2_buffer_pullup(buf, -1);
		if (memcmp(result, expect, expectlen) != 0) {
			printf("  returned hash differs from expected hash\n");
			fail++;
		}
	}

	net2_buffer_free(buf);
	return 0;
}


int
main()
{
	const char	*nilname;
	int		 alg;

	test_start();
	net2_init();

	printf("test 1: nil checksum name\n");
	alg = net2_hash_findname("nil");
	if (alg != 0) {
		printf("  expected nil as algorithm 0, got %d\n", alg);
		fail++;
	}
	nilname = net2_hash_getname(0);
	if (nilname == NULL) {
		printf("  expected algorithm 0 to have a name, "
		    "got NULL for a name\n");
		fail++;
	} else if (strcmp(nilname, "nil") != 0) {
		printf("  expected algorithm 0 to have name \"nil\", "
		    "got \"%s\" for name\n", nilname);
		fail++;
	}

	printf("test 2: nil checksum\n");
	if (test_hash("nil", father, strlen(father), NULL, 0))
		return -1;

	printf("test 3: sha256 checksum\n");
	if (test_hash("sha256", father, strlen(father),
	    father_sha256, sizeof(father_sha256)))
		return -1;

	printf("test 4: sha384 checksum\n");
	if (test_hash("sha384", father, strlen(father),
	    father_sha384, sizeof(father_sha384)))
		return -1;

	printf("test 5: sha512 checksum\n");
	if (test_hash("sha512", father, strlen(father),
	    father_sha512, sizeof(father_sha512)))
		return -1;

	net2_cleanup();
	test_fini();

	return fail;
}
