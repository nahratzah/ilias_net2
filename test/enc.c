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
#include <ilias/net2/enc.h>
#include <ilias/net2/buffer.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <bsd_compat/secure_random.h>

int		 fail = 0;
const char	*doctor = "Who are you ?\n"
	"I am the 'Doctor'.\n"
	"'Doctor' who ?\n"
	"Precisely!";


int
test_nil_at_zero()
{
	int	nil;

	nil = net2_enc_findname("nil");
	if (nil == -1) {
		printf("  nil encoding not found\n");
		return -1;
	}
	if (nil != 0) {
		printf("  nil encoding at position %d, expected %d\n",
		    nil, 0);
		fail++;
	}
	return 0;
}

int
test_nil_is_identity(int dir)
{
	struct net2_enc_ctx	*crypt;
	void			*result;
	struct net2_buffer	*buf;

	crypt = net2_encctx_new(0, NULL, 0, NULL, 0, dir);
	if (crypt == NULL) {
		printf("  failed to create crypt context for nil encoding\n");
		fail++;
		return 0;
	}

	if (net2_encctx_update(crypt, doctor, strlen(doctor))) {
		printf("  failed to update cryption\n");
		fail++;
	}

	if ((buf = net2_encctx_finalfree(crypt)) == NULL) {
		printf("  finalized to NULL buffer\n");
		fail++;
	}

	if (net2_buffer_length(buf) != strlen(doctor)) {
		printf("  identity encryption created output of length %lu, "
		    "expected %lu\n",
		    (unsigned long)net2_buffer_length(buf),
		    (unsigned long)strlen(doctor));
		fail++;
	} else {
		result = net2_buffer_pullup(buf, -1);
		if (memcmp(result, doctor, strlen(doctor)) != 0) {
			printf("  encrypted form differs from plaintext\n");
			fail++;
		}
	}

	net2_buffer_free(buf);
	return 0;
}

int
test_encdec(int alg)
{
	struct net2_enc_ctx	*crypt;
	void			*key, *iv;
	size_t			 keylen, ivlen;
	struct net2_buffer	*encrypted, *decrypted;
	void			*result;

	keylen = net2_enc_getkeylen(alg);
	ivlen = net2_enc_getivlen(alg);
	printf("  algorithm uses %lu keylen and %lu ivlen\n",
	    (unsigned long)keylen, (unsigned long)ivlen);
	key = malloc(keylen);
	iv = malloc(ivlen);
	if (key == NULL || iv == NULL) {
		printf("  failed to allocate key and/or iv\n");
		fail++;
		if (key)
			free(key);
		if (iv)
			free(iv);
		return 0;
	}
	secure_random_buf(key, keylen);
	secure_random_buf(iv, ivlen);

	crypt = net2_encctx_new(alg, key, keylen, iv, ivlen, NET2_ENC_ENCRYPT);
	if (crypt == NULL) {
		printf("  failed to create encryption context\n");
		fail++;
		return 0;
	}

	if (net2_encctx_update(crypt, doctor, strlen(doctor))) {
		printf("  failed to update encrypt context\n");
		fail++;
		return 0;
	}

	if ((encrypted = net2_encctx_finalfree(crypt)) == NULL) {
		printf("  encrypt finalization failed to yield a buffer\n");
		fail++;
		return 0;
	}
	printf("  encrypted form is %lu bytes\n",
	    (unsigned long)net2_buffer_length(encrypted));


	crypt = net2_encctx_new(alg, key, keylen, iv, ivlen, NET2_ENC_DECRYPT);
	if (crypt == NULL) {
		printf("  failed to create decryption context\n");
		fail++;
		return 0;
	}

	if (net2_encctx_update(crypt, net2_buffer_pullup(encrypted, -1),
	    net2_buffer_length(encrypted))) {
		printf("  failed to update decrypt context\n");
		fail++;
		return 0;
	}

	if ((decrypted = net2_encctx_finalfree(crypt)) == NULL) {
		printf("  decrypt finalization failed to yield a buffer\n");
		fail++;
		return 0;
	}
	printf("  decrypted form is %lu bytes\n",
	    (unsigned long)net2_buffer_length(decrypted));


	if (net2_buffer_length(decrypted) != strlen(doctor)) {
		printf("  plaintext before and after differ in length: "
		    "before %lu bytes, after %lu bytes\n",
		    (unsigned long)strlen(doctor),
		    (unsigned long)net2_buffer_length(decrypted));
		fail++;
	} else {
		result = net2_buffer_pullup(decrypted, -1);
		if (memcmp(result, doctor, strlen(doctor)) != 0) {
			printf("  before and after differ,\n"
			    "\texpected: %s\n"
			    "\tgot:      %*s\n",
			    doctor, (int)strlen(doctor), (char*)result);
			fail++;
		}
	}

	net2_buffer_free(encrypted);
	net2_buffer_free(decrypted);
	return 0;
}

int
main()
{
	int		 i;
	const char	*name;

	test_start();
	net2_init();

	printf("test 1: check that the nil encryption has ID 0\n");
	if (test_nil_at_zero())
		return -1;

	printf("test 2: check that the nil encryption "
	    "is an identity operation\n");
	if (test_nil_is_identity(NET2_ENC_ENCRYPT))
		return -1;

	printf("test 3: check that the nil decryption "
	    "is an identity operation\n");
	if (test_nil_is_identity(NET2_ENC_DECRYPT))
		return -1;

	printf("test 4: check each encryption to be reversible\n");
	for (i = 0; i < net2_encmax; i++) {
		name = net2_enc_getname(i);
		if (name == NULL)
			continue;

		printf("test 4.%d: checking encryption/decryption %d \"%s\"\n",
		    i, i, name);
		test_encdec(i);
	}

	net2_cleanup();
	test_fini();

	return fail;
}
