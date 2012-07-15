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
#include <ilias/net2/ctypes.h>
#include <ilias/net2/cp.h>
#include <stdio.h>
#include <string.h>

int fail = 0;

int
test_cp(const void *in, void *out, size_t datalen,
    const struct command_param *cp)
{
	struct net2_buffer	*buf;
	struct net2_encdec_ctx	*ctx = NULL;	/* Not required for ctypes. */
	int			 err = -1;

	buf = net2_buffer_new();
	if (net2_cp_encode(ctx, cp, buf, in, NULL)) {
		printf("  encoding failure\n");
		goto cleanup;
	}
	if (net2_cp_decode(ctx, cp, out, buf, NULL)) {
		printf("  decoding failure\n");
		goto cleanup;
	}
	if (net2_buffer_length(buf) > 0) {
		printf("  buffer not drained on decoding: "
		    "%lu bytes remaining\n",
		    (unsigned long)net2_buffer_length(buf));
		goto cleanup;
	}

	if (memcmp(in, out, datalen) != 0) {
		printf("  input and output mismatch");
		goto cleanup;
	}

	err = 0;

cleanup:
	net2_buffer_free(buf);
	if (err == 0)
		printf("  SUCCESS\n");
	else {
		fail++;
		printf("  FAIL\n");
	}
	return err;
}

int
test_string_cp(char **in, char **out,
    const struct command_param *cp)
{
	struct net2_buffer	*buf;
	struct net2_encdec_ctx	*ctx = NULL;	/* Not required for ctypes. */
	int			 err = -1;

	buf = net2_buffer_new();
	if (net2_cp_encode(ctx, cp, buf, in, NULL)) {
		printf("  encoding failure\n");
		goto cleanup;
	}
	*out = NULL;
	if (net2_cp_init(cp, out, NULL)) {
		printf("  pre-decode initialization failure\n");
		goto cleanup;
	}
	if (net2_cp_decode(ctx, cp, out, buf, NULL)) {
		printf("  decoding failure\n");
		goto cleanup;
	}
	if (net2_buffer_length(buf) > 0) {
		printf("  buffer not drained on decoding: "
		    "%lu bytes remaining\n",
		    (unsigned long)net2_buffer_length(buf));
		goto cleanup;
	}

	if (strcmp(*in, *out) != 0) {
		printf("  input and output mismatch\n"
		    "\texpected: %s\n"
		    "\tgot     : %s\n",
		    *in, *out);
		goto cleanup;
	}

	if (net2_cp_destroy(cp, out, NULL)) {
		printf("  post-decode destruction failure\n");
		goto cleanup;
	}

	err = 0;

cleanup:
	net2_buffer_free(buf);
	if (err == 0)
		printf("  SUCCESS\n");
	else {
		fail++;
		printf("  FAIL\n");
	}
	return err;
}

int
test_stringlist_cp(char **in, char **out,
    const struct command_param *cp)
{
	struct net2_buffer	*buf;
	struct net2_encdec_ctx	*ctx = NULL;	/* Not required for ctypes. */
	int			 err = -1;
	char			**ii, **io;

	buf = net2_buffer_new();
	if (net2_cp_encode(ctx, cp, buf, &in, NULL)) {
		printf("  encoding failure\n");
		goto cleanup;
	}
	printf("  encoded buffer is %lu bytes\n",
	    (unsigned long)net2_buffer_length(buf));
	out = NULL;
	if (net2_cp_init(cp, &out, NULL)) {
		printf("  pre-decode initialization failure\n");
		goto cleanup;
	}
	if (net2_cp_decode(ctx, cp, &out, buf, NULL)) {
		printf("  decoding failure\n");
		goto cleanup;
	}
	if (net2_buffer_length(buf) > 0) {
		printf("  buffer not drained on decoding: "
		    "%lu bytes remaining\n",
		    (unsigned long)net2_buffer_length(buf));
		goto cleanup;
	}

	for (ii = in, io = out; *ii != NULL && io != NULL && *io != NULL;
	    ii++, io++) {
		if (strcmp(*ii, *io) != 0) {
			printf("  input and output mismatch\n"
			    "expected %s\n"
			    "got      %s\n",
			    *ii, *io);
			goto cleanup;
		}
	}
	if (*ii != NULL || *io != NULL) {
		printf("  input and output list size mismatch");
		goto cleanup;
	}

	if (net2_cp_destroy(cp, &out, NULL)) {
		printf("  post-decode destruction failure\n");
		goto cleanup;
	}

	err = 0;

cleanup:
	net2_buffer_free(buf);
	if (err == 0)
		printf("  SUCCESS\n");
	else {
		fail++;
		printf("  FAIL\n");
	}
	return err;
}

int
main()
{
	uint8_t		 u8_out,  u8  = 0xf1;
	uint16_t	 u16_out, u16 = 0xf1e2;
	uint32_t	 u32_out, u32 = 0xf1e2d3c4;
	uint64_t	 u64_out, u64 = 0xf1e2d3c4b5a69788ULL;
	int8_t		 s8_out,  s8  = -17;
	int16_t		 s16_out, s16 = -17017;
	int32_t		 s32_out, s32 = -1701701701;
	int64_t		 s64_out, s64 = -1701701701701701701LL;
	char		*s_out,  *s   = "Lah lah lah chocoladevla";
	char		**sl_out = NULL, *sl[] = {
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
		NULL
	};

	test_start();
	net2_init();

	printf("test  1: unsigned int8\n");
	test_cp(&u8,  &u8_out,  sizeof(u8),  &cp_uint8);
	printf("test  2: unsigned int16\n");
	test_cp(&u16, &u16_out, sizeof(u16), &cp_uint16);
	printf("test  3: unsigned int32\n");
	test_cp(&u32, &u32_out, sizeof(u32), &cp_uint32);
	printf("test  4: unsigned int64\n");
	test_cp(&u64, &u64_out, sizeof(u64), &cp_uint64);

	printf("test  5: signed int8\n");
	test_cp(&s8,  &s8_out,  sizeof(s8),  &cp_int8);
	printf("test  6: signed int16\n");
	test_cp(&s16, &s16_out, sizeof(s16), &cp_int16);
	printf("test  7: signed int32\n");
	test_cp(&s32, &s32_out, sizeof(s32), &cp_int32);
	printf("test  8: signed int64\n");
	test_cp(&s64, &s64_out, sizeof(s64), &cp_int64);

	printf("test  9: string\n");
	test_string_cp(&s, &s_out, &cp_string);

	printf("test 10: NULL-terminated string list\n");
	test_stringlist_cp(&sl[0], sl_out, &cp_null_stringlist);

	net2_cleanup();
	test_fini();

	return fail;
}
