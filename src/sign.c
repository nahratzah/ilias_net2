#include <ilias/net2/sign.h>
#include <errno.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>


/* ECDSA algorithm. */
static int	ecdsa_initpub_fn(struct net2_sign_ctx*, const void*, size_t);
static int	ecdsa_initpriv_fn(struct net2_sign_ctx*, const void*, size_t);
static void	ecdsa_destroy_fn(struct net2_sign_ctx*);
static size_t	ecdsa_maxmsglen_fn(struct net2_sign_ctx*);
static int	ecdsa_sign_fn(struct net2_sign_ctx*,
		    const struct net2_buffer*, struct net2_buffer*);
static int	ecdsa_validate_fn(struct net2_sign_ctx*,
		    const struct net2_buffer*, const struct net2_buffer*);

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
};

#define SIGN_FN(_namestr, _name)					\
	{								\
		_namestr,						\
		_name##_initpub_fn,					\
		_name##_initpriv_fn,					\
		_name##_destroy_fn,					\
		_name##_maxmsglen_fn,					\
		_name##_sign_fn,					\
		_name##_validate_fn					\
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
		EC_KEY		*eckey;
	}			 impl;
};


/* Retrieve the name of an algorithm. */
ILIAS_NET2_EXPORT const char*
net2_sign_getname(int alg)
{
	if (alg < 0 || alg >= net2_signmax)
		return NULL;
	return sign[alg].name;
}

/* Create a new instance, based on a known public key. */
ILIAS_NET2_EXPORT struct net2_sign_ctx*
net2_signctx_pubnew(int alg, const void *key, size_t keylen)
{
	struct net2_sign_ctx	*s;

	if (alg < 0 || alg >= net2_signmax)
		return NULL;

	if ((s = malloc(sizeof(*s))) == NULL)
		return NULL;
	s->fn = &sign[alg];
	if ((*s->fn->initpub_fn)(s, key, keylen) != 0) {
		free(s);
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

	if ((s = malloc(sizeof(*s))) == NULL)
		return NULL;
	s->fn = &sign[alg];
	if ((*s->fn->initpriv_fn)(s, key, keylen) != 0) {
		free(s);
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
		free(s);
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


/* Read public key. */
static int
ecdsa_initpub_fn(struct net2_sign_ctx *s, const void *key, size_t keylen)
{
	const unsigned char	*openssl_key = key;

	if ((s->impl.eckey = d2i_ECParameters(NULL,
	    &openssl_key, keylen)) == NULL)
		return -1;	/* Failed to decode or allocate. */
	return 0;
}
/* Read private key. */
static int
ecdsa_initpriv_fn(struct net2_sign_ctx *s, const void *key, size_t keylen)
{
	const unsigned char	*openssl_key = key;

	if ((s->impl.eckey = d2i_ECPrivateKey(NULL,
	    &openssl_key, keylen)) == NULL)
		return -1;	/* Failed to decode or allocate. */
	return 0;
}
/* Destroy key. */
static void
ecdsa_destroy_fn(struct net2_sign_ctx *s)
{
	if (s->impl.eckey)
		EC_KEY_free(s->impl.eckey);
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
	int		 outsz;
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
