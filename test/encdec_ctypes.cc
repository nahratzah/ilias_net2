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
#include <ilias/net2/cp.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/encdec_ctx.h>
#include <stdio.h>

template<typename Type>
void
test_cp(const Type& in)
{
	typedef ilias::cp_encdec<Type> cp;
	ilias::encdec_ctx ectx;

	ilias::buffer buf;
	cp::encode(ectx, buf, in);
	const Type out = cp::decode(ectx, buf);

	TEST(buf.empty());
	TEST(in == out);
}

int
main()
{
	uint8_t		u8   = 0xf1;
	uint16_t	u16  = 0xf1e2;
	uint32_t	u32  = 0xf1e2d3c4;
	uint64_t	u64  = 0xf1e2d3c4b5a69788ULL;
	int8_t		s8   = -17;
	int16_t		s16  = -17017;
	int32_t		s32  = -1701701701;
	int64_t		s64  = -1701701701701701701LL;
	std::string	s    = "Lah lah lah chocoladevla";
	std::string	sl[] = {
		"Three rings for the elven kings under the sky",
		"seven for the dwarf lords in their halls of stone",
		"nine for mortal men doomed to die",
		"one for the dark lord on his dark throne",
		"in the land of Mordor where the shadows lie",
		"",
		"One Ring to rule them all",
		"One Ring to find them",
		"One Ring to bring them all",
		"and in the darkness bind them",
	};

	printf("test  1: unsigned int8\n");
	test_cp(u8);
	printf("test  2: unsigned int16\n");
	test_cp(u16);
	printf("test  3: unsigned int32\n");
	test_cp(u32);
	printf("test  4: unsigned int64\n");
	test_cp(u64);

	printf("test  5: signed int8\n");
	test_cp(s8);
	printf("test  6: signed int16\n");
	test_cp(s16);
	printf("test  7: signed int32\n");
	test_cp(s32);
	printf("test  8: signed int64\n");
	test_cp(s64);

	printf("test  9: string\n");
	test_cp(s);

	//printf("test 10: NULL-terminated string list\n");
	//test_cp(&sl[0], sl_out, &cp_null_stringlist);

	return 0;
}
