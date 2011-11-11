#include <ilias/net2/xchange.h>
#include <ilias/net2/buffer.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define KEYLEN	(256 / 8)	/* 256 bit key */

int fail = 0;

int
test(int alg)
{
	struct net2_xchange_ctx	*alice, *bob;
	struct net2_buffer	*wire, *alice_exp, *bob_exp;
	struct net2_buffer	*alice_key, *bob_key;
	char			*alice_hex, *bob_hex;

	if (net2_xchange_getname(alg) == NULL) {
		printf("SKIP %d: no name\n", alg);
		return 0;
	} else if (alg == 0) {
		printf("SKIP %d: implementation is fail only\n", alg);
		return 0;
	} else
		printf("TEST %d: %s\n", alg, net2_xchange_getname(alg));


	if ((wire = net2_buffer_new()) == NULL) {
		printf("net2_buffer_new fail\n");
		return -1;
	}

	alice = net2_xchangectx_prepare(alg, KEYLEN, NET2_XCHANGE_F_INITIATOR,
	    wire);
	if (alice == NULL) {
		printf("failed to create Alice\n");
		return -1;
	}

	bob = net2_xchangectx_prepare(alg, KEYLEN, 0,
	    wire);
	if (bob == NULL) {
		printf("failed to create Bob\n");
		return -1;
	}

	if ((alice_exp = net2_xchangectx_export(alice)) == NULL) {
		printf("failed to export pubkey of Alice\n");
		return -1;
	}
	if ((bob_exp = net2_xchangectx_export(bob)) == NULL) {
		printf("failed to export pubkey of Bob\n");
		return -1;
	}

	if (net2_xchangectx_import(alice, bob_exp)) {
		printf("Alice failed to import pubkey from Bob\n");
		return -1;
	}
	if (net2_xchangectx_import(bob, alice_exp)) {
		printf("Bob failed to import pubkey from Alice\n");
		return -1;
	}

	if ((alice_key = net2_xchangectx_finalfree(alice)) == NULL) {
		printf("Alice failed to generate a key\n");
		return -1;
	}
	if ((bob_key = net2_xchangectx_finalfree(bob)) == NULL) {
		printf("Bob failed to generate a key\n");
		return -1;
	}

	if (net2_buffer_length(alice_key) != KEYLEN) {
		printf("Alice' key is %lu bytes, expected %lu bytes\n",
		    (unsigned long)net2_buffer_length(alice_key),
		    (unsigned long)KEYLEN);
		fail++;
	}
	if (net2_buffer_length(bob_key) != KEYLEN) {
		printf("Bob's key is %lu bytes, expected %lu bytes\n",
		    (unsigned long)net2_buffer_length(bob_key),
		    (unsigned long)KEYLEN);
		fail++;
	}

	alice_hex = net2_buffer_hex(alice_key);
	bob_hex = net2_buffer_hex(bob_key);
	if (net2_buffer_cmp(alice_key, bob_key) != 0) {
		printf("Bob and Alice don't have the same key\n"
		    "Alice: %s\n"
		    "Bob  : %s\n",
		    alice_hex, bob_hex);
		fail++;
	} else
		printf("Negotiated key: %s\n", alice_hex);

	/* Release all resources for this test. */
	net2_buffer_free(wire);
	net2_buffer_free(alice_exp);
	net2_buffer_free(bob_exp);
	net2_buffer_free(alice_key);
	net2_buffer_free(bob_key);
	free(alice_hex);
	free(bob_hex);

	return 0;
}

int
main()
{
	int i;

	for (i = 0; i < net2_xchangemax; i++) {
		if (test(i))
			return -1;
	}

	return fail;
}
