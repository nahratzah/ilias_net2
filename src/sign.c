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
#include <ilias/net2/sign.h>
#include <ilias/net2/memory.h>
#include <errno.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <assert.h>
#include <stdlib.h>

#ifdef _WIN32
#include <malloc.h>
#endif

#include <ilias/net2/config.h>
#ifdef HAS_SHA2
#include <sha2.h>
#else
#include <ilias/net2/bsd_compat/sha2.h>
#endif


/* ECDSA algorithm. */
static int	 ecdsa_initpub_fn(struct net2_sign_ctx*, const void*, size_t);
static int	 ecdsa_initpriv_fn(struct net2_sign_ctx*, const void*, size_t);
static size_t	 ecdsa_maxmsglen_fn(struct net2_sign_ctx*);
static int	 ecdsa_sign_fn(struct net2_sign_ctx*,
		    const struct net2_buffer*, struct net2_buffer*);
static int	 ecdsa_validate_fn(struct net2_sign_ctx*,
		    const struct net2_buffer*, const struct net2_buffer*);
#define		 ecdsa_destroy_fn	eckey_destroy_fn
#define		 ecdsa_pubkey_fn	eckey_pubkey_fn
#define		 ecdsa_clone_fn		eckey_clone_fn

static int	 eckey_clone_fn(struct net2_sign_ctx*, struct net2_sign_ctx*);
static struct net2_buffer
		*eckey_pubkey_fn(struct net2_sign_ctx*);
static void	 eckey_destroy_fn(struct net2_sign_ctx*);

/* Function table. */
struct sign_fn {
	const char		*name;
	int	(*initpub_fn)(struct net2_sign_ctx*, const void*, size_t);
	int	(*initpriv_fn)(struct net2_sign_ctx*, const void*, size_t);
	void	(*destroy_fn)(struct net2_sign_ctx*);
	size_t	(*maxmsglen_fn)(struct net2_sign_ctx*);
	int	(*sign_fn)(struct net2_sign_ctx*, const struct net2_buffer*,
		    struct net2_buffer*);
	int	(*validate_fn)(struct net2_sign_ctx*,
		    const struct net2_buffer*, const struct net2_buffer*);
	int	(*clone_fn)(struct net2_sign_ctx*, struct net2_sign_ctx*);
	struct net2_buffer*
		(*pubkey_fn)(struct net2_sign_ctx*);
};

#define SIGN_FN(_namestr, _name)					\
	{								\
		_namestr,						\
		_name##_initpub_fn,					\
		_name##_initpriv_fn,					\
		_name##_destroy_fn,					\
		_name##_maxmsglen_fn,					\
		_name##_sign_fn,					\
		_name##_validate_fn,					\
		_name##_clone_fn,					\
		_name##_pubkey_fn					\
	}

/* Signature definitions. */
static const struct sign_fn sign[] = {
	SIGN_FN("ecdsa", ecdsa),
};

/* Number of algorithms. */
ILIAS_NET2_EXPORT const int net2_signmax = sizeof(sign) / sizeof(sign[0]);


struct net2_sign_ctx {
	const struct sign_fn	*fn;

	union {
		struct {
			EC_KEY	*eckey;
			struct net2_buffer
				*eckey_pub;
		};
	}			 impl;

	struct net2_buffer	*fingerprint;
};


/* Retrieve the name of an algorithm. */
ILIAS_NET2_EXPORT const char*
net2_sign_getname(int alg)
{
	if (alg < 0 || alg >= net2_signmax)
		return NULL;
	return sign[alg].name;
}

/* Find signature algorithm by name. */
ILIAS_NET2_EXPORT int
net2_sign_findname(const char *name)
{
	int			 i;

	if (name == NULL)
		return -1;

	for (i = 0; i < net2_signmax; i++) {
		if (sign[i].name != NULL && strcmp(sign[i].name, name) == 0)
			return i;
	}

	return -1;
}

/* Create a new instance, based on a known public key. */
ILIAS_NET2_EXPORT struct net2_sign_ctx*
net2_signctx_pubnew(int alg, const void *key, size_t keylen)
{
	struct net2_sign_ctx	*s;

	if (alg < 0 || alg >= net2_signmax)
		return NULL;

	if ((s = net2_malloc(sizeof(*s))) == NULL)
		return NULL;
	s->fn = &sign[alg];
	s->fingerprint = NULL;
	if ((*s->fn->initpub_fn)(s, key, keylen) != 0) {
		net2_free(s);
		return NULL;
	}
	return s;
}

/* Create a new instance, based on a known private key. */
ILIAS_NET2_EXPORT struct net2_sign_ctx*
net2_signctx_privnew(int alg, const void *key, size_t keylen)
{
	struct net2_sign_ctx	*s;

	if (alg < 0 || alg >= net2_signmax)
		return NULL;

	if ((s = net2_malloc(sizeof(*s))) == NULL)
		return NULL;
	s->fn = &sign[alg];
	s->fingerprint = NULL;
	if ((*s->fn->initpriv_fn)(s, key, keylen) != 0) {
		net2_free(s);
		return NULL;
	}
	return s;
}

/* Free instance. */
ILIAS_NET2_EXPORT void
net2_signctx_free(struct net2_sign_ctx *s)
{
	if (s != NULL) {
		(*s->fn->destroy_fn)(s);
		if (s->fingerprint != NULL)
			net2_buffer_free(s->fingerprint);
		net2_free(s);
	}
}

/* Return the max message size that can be encoded. */
ILIAS_NET2_EXPORT size_t
net2_signctx_maxmsglen(struct net2_sign_ctx *s)
{
	return (*s->fn->maxmsglen_fn)(s);
}

/* Calculate signature. */
ILIAS_NET2_EXPORT int
net2_signctx_sign(struct net2_sign_ctx *s, const struct net2_buffer *in,
    struct net2_buffer *out)
{
	if (in == NULL || out == NULL)
		return EINVAL;

	return (*s->fn->sign_fn)(s, in, out);
}

/* Validate a signature. */
ILIAS_NET2_EXPORT int
net2_signctx_validate(struct net2_sign_ctx *s,
    const struct net2_buffer *sig, const struct net2_buffer *in)
{
	if (in == NULL)
		return 0;
	return (*s->fn->validate_fn)(s, sig, in);
}

/* Return the algorithm name. */
ILIAS_NET2_EXPORT const char*
net2_signctx_name(struct net2_sign_ctx *s)
{
	return s->fn->name;
}

/* Duplicate the key. */
ILIAS_NET2_EXPORT struct net2_sign_ctx*
net2_signctx_clone(struct net2_sign_ctx *orig)
{
	struct net2_sign_ctx	*dest;

	if ((dest = net2_malloc(sizeof(*dest))) == NULL)
		return NULL;
	dest->fn = orig->fn;

	if ((*dest->fn->clone_fn)(dest, orig) != 0) {
		net2_free(dest);
		return NULL;
	}

	/* Copy fingerprint cache. */
	if (orig->fingerprint != NULL)
		dest->fingerprint = net2_buffer_copy(orig->fingerprint);
	else
		dest->fingerprint = NULL;

	return dest;
}

/* Provide public key in binary encoding. */
ILIAS_NET2_EXPORT struct net2_buffer*
net2_signctx_pubkey(struct net2_sign_ctx *s)
{
	return (*s->fn->pubkey_fn)(s);
}

/*
 * Calculate the public key fingerprint.
 * This is the SHA256 hash of the public key.
 */
ILIAS_NET2_EXPORT struct net2_buffer*
net2_signctx_fingerprint(struct net2_sign_ctx *s)
{
	struct iovec	*iov, out;
	size_t		 iovcount, outcount;
	size_t		 pklen;
	SHA2_CTX	 sha2;
	struct net2_buffer
			*pk, *buf;

	/* Use cached value. */
	if (s->fingerprint != NULL)
		return net2_buffer_copy(s->fingerprint);

	/* Read public key. */
	if ((pk = net2_signctx_pubkey(s)) == NULL)
		return NULL;
	pklen = net2_buffer_length(pk);

	/* Prepare output space. */
	if ((buf = net2_buffer_new()) == NULL) {
		net2_buffer_free(pk);
		return NULL;
	}
	outcount = 1;
	if (net2_buffer_reserve_space(buf, SHA256_DIGEST_LENGTH,
	    &out, &outcount))
		goto fail;
	assert(outcount == 1 && out.iov_len >= SHA256_DIGEST_LENGTH);
	out.iov_len = SHA256_DIGEST_LENGTH;

	/* Load iovs. */
	iovcount = net2_buffer_peek(pk, pklen, NULL, 0);
	if (iovcount == 0 || iovcount > SIZE_MAX / sizeof(*iov))
		goto fail;
	iov = alloca(sizeof(*iov) * iovcount);
	if (net2_buffer_peek(pk, pklen, iov, iovcount) != iovcount)
		goto fail;

	/* Checksum calculation. */
	SHA256Init(&sha2);
	while (iovcount > 0) {
		SHA256Update(&sha2, iov->iov_base, iov->iov_len);

		iovcount--;
		iov++;
	}

	/* Store checksum result in allocated space. */
	SHA256Final(out.iov_base, &sha2);
	if (net2_buffer_commit_space(buf, &out, 1))
		goto fail;

	/* Cleanup and return. */
	net2_buffer_free(pk);
	s->fingerprint = net2_buffer_copy(buf);	/* Cache. */
	return buf;

fail:
	net2_buffer_free(buf);
	net2_buffer_free(pk);
	return NULL;
}


/*
 * Read PEM encoded private key.
 */
static int
read_privkey_PEM(EC_KEY **k, const void *key, size_t keylen,
    const char *passphrase)
{
	BIO		*bio;
	int		 error;
	EVP_PKEY	*pk;

	if (k == NULL)
		return EINVAL;
	*k = NULL;

	/* Create a BIO for the key. */
	if ((bio = BIO_new_mem_buf((void*)key, keylen)) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}

	/* Read the PEM file. */
	if ((pk = PEM_read_bio_PrivateKey(bio, NULL, NULL,
	    (void*)passphrase)) == NULL) {
		error = EIO;
		goto fail_1;
	}

	/* Ensure this really is a EC key. */
	if (pk->type != EVP_PKEY_EC) {
		error = EINVAL;
		goto fail_2;
	}

	/* Assign EC key. */
	*k = EVP_PKEY_get1_EC_KEY(pk);

	/* Key validation. */
	if (!EC_KEY_check_key(*k)) {
		error = EINVAL;
		goto fail_3;
	}

	/*
	 * Precompute multiples of the generator, to accelerate further EC_KEY
	 * operations.
	 * Failure is not an issue, since in that case, the operations will
	 * simply be slightly slower, but they won't fail.
	 *
	 * Hence: ignore success/error return.
	 */
	EC_KEY_precompute_mult(*k, NULL);

	/* Succes. */
	error = 0;

fail_3:
	if (error != 0) {
		EC_KEY_free(*k);
		*k = NULL;
	}
fail_2:
	EVP_PKEY_free(pk);
fail_1:
	BIO_free(bio);
fail_0:
	return error;
}

/*
 * Read PEM encoded public key.
 */
static int
read_pubkey_PEM(EC_KEY **k, const void *key, size_t keylen,
    const char *passphrase)
{
	BIO		*bio;
	int		 error;
	EVP_PKEY	*pk;

	if (k == NULL)
		return EINVAL;
	*k = NULL;

	/* Create a BIO for the key. */
	if ((bio = BIO_new_mem_buf((void*)key, keylen)) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}

	/* Read the PEM file. */
	if ((pk = PEM_read_bio_PUBKEY(bio, NULL, NULL,
	    (void*)passphrase)) == NULL) {
		error = EIO;
		goto fail_1;
	}

	/* Ensure this really is a EC key. */
	if (pk->type != EVP_PKEY_EC) {
		error = EINVAL;
		goto fail_2;
	}

	/* Assign EC key. */
	*k = EVP_PKEY_get1_EC_KEY(pk);

	/* Key validation. */
	if (!EC_KEY_check_key(*k)) {
		error = EINVAL;
		goto fail_3;
	}

	/* Succes. */
	error = 0;

fail_3:
	if (error != 0) {
		EC_KEY_free(*k);
		*k = NULL;
	}
fail_2:
	EVP_PKEY_free(pk);
fail_1:
	BIO_free(bio);
fail_0:
	return error;
}


/* Read public key. */
static int
ecdsa_initpub_fn(struct net2_sign_ctx *s, const void *key, size_t keylen)
{
	s->impl.eckey_pub = NULL;
	return read_pubkey_PEM(&s->impl.eckey, key, keylen, NULL);
}
/* Read private key. */
static int
ecdsa_initpriv_fn(struct net2_sign_ctx *s, const void *key, size_t keylen)
{
	s->impl.eckey_pub = NULL;
	return read_privkey_PEM(&s->impl.eckey, key, keylen, NULL);
}
/* The max message that can be signed using this algorithm. */
static size_t
ecdsa_maxmsglen_fn(struct net2_sign_ctx *s)
{
	/*
	 * TODO: this is not technically correct, since the value returned
	 * is the size of the signature, not the significant size of the
	 * input message.
	 */
	return ECDSA_size(s->impl.eckey);
}
/* Sign a piece of data with ECDSA in s. */
static int
ecdsa_sign_fn(struct net2_sign_ctx *s, const struct net2_buffer *in,
    struct net2_buffer *out)
{
	void		*inbuf;
	size_t		 insz;
	unsigned int	 outsz;
	struct iovec	 iov;
	size_t		 iovcount;

	/* Setup inbuf. Only copy if we have to. */
	insz = net2_buffer_length(in);
	if (insz == 0)
		inbuf = NULL;
	else if (net2_buffer_peek(in, insz, &iov, 1) == 1)
		inbuf = iov.iov_base;
	else {
		inbuf = alloca(insz);
		net2_buffer_copyout(in, inbuf, insz);
	}

	/* Prepare output buffer. */
	outsz = ECDSA_size(s->impl.eckey);
	iovcount = 1;
	if (net2_buffer_reserve_space(out, outsz, &iov, &iovcount))
		return ENOMEM;

	/* Compute signature. */
	if (!ECDSA_sign(0 /* ignored */, inbuf, insz, iov.iov_base, &outsz,
	    s->impl.eckey))
		return -1;	/* Failure. */
	iov.iov_len = outsz;

	/* Commit prepared space. */
	if (net2_buffer_commit_space(out, &iov, iovcount))
		return EINVAL;

	return 0;
}
/* Validate a piece of data with ECDSA in s. */
static int
ecdsa_validate_fn(struct net2_sign_ctx *s, const struct net2_buffer *sig,
    const struct net2_buffer *in)
{
	void		*inbuf, *sigbuf;
	size_t		 insz, sigsz;
	struct iovec	 iov;

	/* Check that the sig has the correct size. */
	sigsz = net2_buffer_length(sig);
	if (sigsz > (size_t)ECDSA_size(s->impl.eckey))
		return 0;

	/* Setup inbuf. Only copy if we have to. */
	insz = net2_buffer_length(in);
	if (insz == 0)
		inbuf = NULL;
	else if (net2_buffer_peek(in, insz, &iov, 1) == 1)
		inbuf = iov.iov_base;
	else {
		inbuf = alloca(insz);
		net2_buffer_copyout(in, inbuf, insz);
	}

	/* Setup sigbuf. Only copy if we have to. */
	if (sigsz == 0)
		sigbuf = NULL;
	else if (net2_buffer_peek(sig, sigsz, &iov, 1) == 1)
		sigbuf = iov.iov_base;
	else {
		sigbuf = alloca(sigsz);
		net2_buffer_copyout(sig, sigbuf, sigsz);
	}

	/* Verify sig. */
	switch (ECDSA_verify(0, inbuf, insz, sigbuf, sigsz,
	    s->impl.eckey)) {
	case 0:
		return 0;	/* Incorrect. */
	case 1:
		return 1;	/* Correct. */
	}

	/* Only reachable in case of error. */
	return 0;
}

/* Clone a ECDSA key. */
static int
eckey_clone_fn(struct net2_sign_ctx *dest, struct net2_sign_ctx *orig)
{
	if (!EC_KEY_up_ref(orig->impl.eckey))
		return -1;

	dest->impl.eckey = orig->impl.eckey;
	if (orig->impl.eckey_pub != NULL)
		dest->impl.eckey_pub = net2_buffer_copy(orig->impl.eckey_pub);
	else
		dest->impl.eckey_pub = NULL;
	return 0;
}
/* Encode a public key into a binary blob. */
static struct net2_buffer*
eckey_pubkey_fn(struct net2_sign_ctx *s)
{
	const EC_GROUP		*curve;
	const EC_POINT		*point;
	BN_CTX			*bnctx;
	struct net2_buffer	*buf;
	size_t			 len;
	struct iovec		 iov;
	size_t			 iovlen;

	/* Return cached copy. */
	if (s->impl.eckey_pub != NULL)
		return net2_buffer_copy(s->impl.eckey_pub);

	buf = NULL;
	bnctx = NULL;

	/* Fetch curve and public key point. */
	curve = EC_KEY_get0_group(s->impl.eckey);
	point = EC_KEY_get0_public_key(s->impl.eckey);
	if (curve == NULL || point == NULL)
		goto fail;

	/* Determine size. */
	if ((bnctx = BN_CTX_new()) == NULL)
		goto fail;
	len = EC_POINT_point2oct(curve, point, POINT_CONVERSION_UNCOMPRESSED,
	    NULL, 0, bnctx);
	/* 0-length public key, is that legal? */
	if (len == 0)
		goto fail;

	/* Allocate. */
	if ((buf = net2_buffer_new()) == NULL)
		goto fail;
	iovlen = 1;
	if (net2_buffer_reserve_space(buf, len, &iov, &iovlen))
		goto fail;
	assert(iovlen == 1 && iov.iov_len >= len);

	/* Convert. */
	if (EC_POINT_point2oct(curve, point, POINT_CONVERSION_UNCOMPRESSED,
	    iov.iov_base, len, bnctx) != len)
		goto fail;
	iov.iov_len = len;
	if (net2_buffer_commit_space(buf, &iov, 1))
		goto fail;

	BN_CTX_free(bnctx);
	s->impl.eckey_pub = net2_buffer_copy(buf);	/* Cache value. */
	return buf;

fail:
	if (bnctx != NULL)
		BN_CTX_free(bnctx);
	if (buf != NULL)
		net2_buffer_free(buf);
	return NULL;
}
/* Destroy key. */
static void
eckey_destroy_fn(struct net2_sign_ctx *s)
{
	if (s->impl.eckey_pub != NULL)
		net2_buffer_free(s->impl.eckey_pub);
	if (s->impl.eckey)
		EC_KEY_free(s->impl.eckey);
	s->impl.eckey = NULL;
	s->impl.eckey_pub = NULL;
}

/* Index of ECDSA algorithm. */
ILIAS_NET2_EXPORT const int net2_sign_ecdsa = 0;
