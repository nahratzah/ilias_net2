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
#include <ilias/net2/buffer.h>
#include <ilias/net2/sign.h>
#include <ilias/net2/bsd_compat/error.h>
#include <ilias/net2/bsd_compat/secure_random.h>
#include <ilias/net2/bsd_compat/minmax.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>

const char *ecdsa_privkey =
	"-----BEGIN EC PARAMETERS-----\n"
	"BgUrgQQAIw==\n"
	"-----END EC PARAMETERS-----\n"
	"-----BEGIN EC PRIVATE KEY-----\n"
	"MIHcAgEBBEIBDCcCFNIxvyATLBgqCQ0MxfShTO36vc2KBdveh4O8BjEb3A1+pXPQ\n"
	"y/p9DqMdTPClHxmbsm11pN3clpm1uCMAzQGgBwYFK4EEACOhgYkDgYYABAFow7KD\n"
	"BSN+q3OOBmQ+Eb3iExf/Nq4FvOmgA7Ru2IUQxyf2Z8M8JQl4+6YG/ctfiel6zjwZ\n"
	"VFO19O0y89M9EdDi0wGbOf4C7/ip53UyoKpNbMiblDCBrWHqX3dGAEddulypMpOf\n"
	"4+GczYlYAHBqs1U9qp3G9FNzhmZk1bwmmm5vkZGyXg==\n"
	"-----END EC PRIVATE KEY-----\n";

const char *ecdsa_pubkey =
	"-----BEGIN PUBLIC KEY-----\n"
	"MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBaMOygwUjfqtzjgZkPhG94hMX/zau\n"
	"BbzpoAO0btiFEMcn9mfDPCUJePumBv3LX4npes48GVRTtfTtMvPTPRHQ4tMBmzn+\n"
	"Au/4qed1MqCqTWzIm5Qwga1h6l93RgBHXbpcqTKTn+PhnM2JWABwarNVPaqdxvRT\n"
	"c4ZmZNW8Jppub5GRsl4=\n"
	"-----END PUBLIC KEY-----\n";

int
main()
{
	struct net2_sign_ctx	*priv, *pub;
	struct net2_buffer	*msg, *badmsg, *sig, *sig2;
	uint32_t		 v;
	int			 error;
	int			 fail = 0;

	test_start();

	/* Initialize SSL. */
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	/* Load keys. */
	fprintf(stderr, "Loading private key...\n");
	priv = net2_signctx_privnew(net2_sign_ecdsa, ecdsa_privkey, strlen(ecdsa_privkey));
	fprintf(stderr, "Private key loaded...\n");
	fprintf(stderr, "Loading public key...\n");
	pub =  net2_signctx_pubnew( net2_sign_ecdsa, ecdsa_pubkey,  strlen(ecdsa_pubkey));
	fprintf(stderr, "Public key loaded...\n");
	if (priv == NULL || pub == NULL)
		errx(1, "Failed to create public/private ecdsa signature context: pub=%p, priv=%p.", pub, priv);

	/* Allocate buffers. */
	if ((msg = net2_buffer_new()) == NULL)
		errx(1, "Failed to allocate message buffer.");
	if ((sig = net2_buffer_new()) == NULL)
		errx(1, "Failed to allocate signature buffer.");
	if ((sig2 = net2_buffer_new()) == NULL)
		errx(1, "Failed to allocate signature 2 buffer.");
	if ((badmsg = net2_buffer_new()) == NULL)
		errx(1, "Failed to allocate bad message buffer.");

	/* Create message. */
	while (net2_buffer_length(msg) < net2_signctx_maxmsglen(priv)) {
		v = secure_random();
		if (net2_buffer_add(msg, &v, MIN(sizeof(v),
		    net2_signctx_maxmsglen(priv) - net2_buffer_length(msg))))
			errx(1, "Failed to allocate message buffer.");
	}

	/* Generate signature. */
	if ((error = net2_signctx_sign(priv, msg, sig)) != 0)
		errx(2, "Sign operation failed, error %d", error);

	/* Validate signature. */
	error = net2_signctx_validate(pub, sig, msg);
	if (error)
		printf("Signature is valid\n");
	else {
		fail++;
		warnx("Signature is invalid (expected: valid)");
	}

	/* Generate signature again (to see if it's different). */
	if ((error = net2_signctx_sign(priv, msg, sig2)) != 0)
		errx(2, "Sign operation failed, error %d", error);
	/* Validate signature again. */
	error = net2_signctx_validate(pub, sig2, msg);
	if (error)
		printf("Signature 2 is valid\n");
	else {
		fail++;
		warnx("Signature 2 is invalid (expected: valid)");
	}
	/* Ensure it is different. */
	if (net2_buffer_cmp(sig, sig2) == 0) {
		fail++;
		warnx("Signature 2 is the same as first signature "
		    "(this may happen only rarely, but is probably a bug!)");
	}

	/*
	 * Create tampered buffer.
	 *
	 * Note: this test is leaking buffers here. Don't use this as an
	 * example of proper coding!
	 */
	net2_buffer_copyout(msg, &v, sizeof(v));
	v = ~v;
	net2_buffer_add(badmsg, &v, sizeof(v));
	{
		struct net2_buffer	*tmp;

		net2_buffer_append(badmsg,
		    tmp = net2_buffer_subrange(msg, sizeof(v),
		    net2_buffer_length(msg) - sizeof(v)));
		net2_buffer_free(tmp);
	}

	/* Test tampered buffer. */
	error = net2_signctx_validate(pub, sig, badmsg);
	if (!error)
		printf("Signature is invalid\n");
	else {
		fail++;
		warnx("Signature is valid (expected: invalid)");
	}

	/* Test public key extraction. */
	{
		struct net2_buffer	*priv_pk, *pub_pk;

		priv_pk = net2_signctx_pubkey(priv);
		pub_pk = net2_signctx_pubkey(pub);
		if (priv_pk == NULL || pub_pk == NULL) {
			fail++;
			warnx("Public key extraction failed "
			    "(priv_pk=%p, pub_pk=%p).", priv_pk, pub_pk);
			goto skip_pubkey;
		}

		if (net2_buffer_length(priv_pk) == 0 ||
		    net2_buffer_length(pub_pk) == 0) {
			fail++;
			warnx("Public key length 0: "
			    "(priv_pk: %llu bytes, pub_pk: %llu bytes).",
			    (unsigned long long)net2_buffer_length(priv_pk),
			    (unsigned long long)net2_buffer_length(pub_pk));
		}

		if (net2_buffer_cmp(priv_pk, pub_pk) != 0) {
			fail++;
			warnx("Public key for priv and pub mismatch");
		}

		net2_buffer_free(priv_pk);
		net2_buffer_free(pub_pk);

	}

	net2_buffer_free(msg);
	net2_buffer_free(badmsg);
	net2_buffer_free(sig);
	net2_buffer_free(sig2);
	net2_signctx_free(priv);
	net2_signctx_free(pub);

skip_pubkey:

	test_fini();
	/* Done. */
	return fail;
}
