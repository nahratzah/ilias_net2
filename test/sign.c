#include <ilias/net2/buffer.h>
#include <ilias/net2/sign.h>
#include <bsd_compat/error.h>
#include <bsd_compat/secure_random.h>
#include <bsd_compat/minmax.h>
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
	char			*hex;
	int			 fail = 0;

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
	printf("Signature (hex): %s\n", hex = net2_buffer_hex(sig));
	free(hex);

	/* Validate signature. */
	error = net2_signctx_validate(priv, sig, msg);
	if (error)
		printf("Signature is valid\n");
	else {
		fail++;
		warnx("Signature is invalid (expected: valid)");
	}

	/* Generate signature again (to see if it's different). */
	if ((error = net2_signctx_sign(priv, msg, sig2)) != 0)
		errx(2, "Sign operation failed, error %d", error);
	printf("Signature (hex): %s\n", hex = net2_buffer_hex(sig2));
	free(hex);
	/* Validate signature again. */
	error = net2_signctx_validate(priv, sig2, msg);
	if (error)
		printf("Signature 2 is valid\n");
	else {
		fail++;
		warnx("Signature 2 is invalid (expected: valid)");
	}
	/* Ensure it is different. */
	if (net2_buffer_cmp(sig, sig2) == 0) {
		fail++;
		warnx("Signature 2 is the same as first signature (this may happen only rarely, but is probably a bug!)");
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
	net2_buffer_append(badmsg,
	    net2_buffer_subrange(msg, sizeof(v),
	    net2_buffer_length(msg) - sizeof(v)));

	/* Test tampered buffer. */
	error = net2_signctx_validate(priv, sig, badmsg);
	if (!error)
		printf("Signature is invalid\n");
	else {
		fail++;
		warnx("Signature is valid (expected: invalid)");
	}

	/* Done. */
	return fail;
}
