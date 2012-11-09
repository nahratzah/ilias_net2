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
#include <ilias/net2/buffer.h>
#include <ilias/net2/hash.h>
#include <cstring>
#include "test.h"

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

void
test_hash(const ilias::hash_ctx_factory& hctx,
    const ilias::buffer& in_buf,
    const void *expectptr, size_t expectlen)
{
	printf("Test algorithm: %s\n", hctx.name.c_str());
	const ilias::buffer expect(expectptr, expectlen);

	printf("- automatic hash_ctx_factory run...\n");
	const ilias::buffer result_run = hctx.run(ilias::buffer(), in_buf);
	TEST(result_run == expect);

	printf("- manual hash_ctx_factory run...\n");
	const ilias::hash_ctx_ptr hp = hctx.instantiate(ilias::buffer());
	hp->update(in_buf);
	const ilias::buffer result_manual = hp->final();
	TEST(result_manual == expect);
}


int
main()
{
	const ilias::buffer in_buf(father, std::strlen(father));

	test_hash(ilias::hash::sha256(), in_buf, father_sha256, sizeof(father_sha256));
	test_hash(ilias::hash::sha384(), in_buf, father_sha384, sizeof(father_sha384));
	test_hash(ilias::hash::sha512(), in_buf, father_sha512, sizeof(father_sha512));

	return 0;
}
