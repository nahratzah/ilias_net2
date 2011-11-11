#include <ilias/net2/xchange.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/types.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <bsd_compat/secure_random.h>
#include <bsd_compat/error.h>
#include <assert.h>
#include <string.h>

static int	NIL_init_fn(struct net2_xchange_ctx*, size_t,
		    struct net2_buffer*);
static int	DH_init_fn(struct net2_xchange_ctx*, size_t,
		    struct net2_buffer*);
static void	DH_destroy_fn(struct net2_xchange_ctx*);
static int	DH_export_fn(struct net2_xchange_ctx*, struct net2_buffer*);
static int	DH_import_fn(struct net2_xchange_ctx*, struct net2_buffer*);
static int	DH_final_fn(struct net2_xchange_ctx*, struct net2_buffer*);

struct net2_xchange_fn {
	const char	*name;
	int	(*init)(struct net2_xchange_ctx*, size_t, struct net2_buffer*);
	void	(*destroy)(struct net2_xchange_ctx*);
	int	(*export)(struct net2_xchange_ctx*, struct net2_buffer*);
	int	(*import)(struct net2_xchange_ctx*, struct net2_buffer*);
	int	(*final)(struct net2_xchange_ctx*, struct net2_buffer*);
};

#define XCHANGE_FN(_namestr, _name)					\
	{								\
		_namestr,						\
		_name##_init_fn,					\
		_name##_destroy_fn,					\
		_name##_export_fn,					\
		_name##_import_fn,					\
		_name##_final_fn					\
	}

static const struct net2_xchange_fn xchange[] = {
	{ "nil", NIL_init_fn, NULL, NULL, NULL, NULL },
	XCHANGE_FN("dh", DH)
};

/* Number of xchange algorithms. */
ILIAS_NET2_EXPORT const int net2_xchangemax =
    sizeof(xchange) / sizeof(xchange[0]);

struct net2_xchange_ctx {
	const struct net2_xchange_fn	*fn;
	int				 flags;
	void				*scratch;

	union {
		DH			*dh;
	}				 impl;
};


/* Returns the name of the xchange. */
ILIAS_NET2_EXPORT const char*
net2_xchange_getname(int alg)
{
	if (alg < 0 || alg >= net2_xchangemax)
		return NULL;
	return xchange[alg].name;
}

/* Find the algorithm ID with the given name. */
ILIAS_NET2_EXPORT int
net2_xchange_findname(const char *name)
{
	int			 i;

	if (name == NULL)
		return -1;

	for (i = 0; i >= 0 && i < net2_xchangemax; i++) {
		if (xchange[i].name != NULL &&
		    strcmp(xchange[i].name, name) == 0)
			return i;
	}
	return -1;
}


/* Create the xchange context for the given algorithm. */
ILIAS_NET2_EXPORT struct net2_xchange_ctx*
net2_xchangectx_prepare(int alg, size_t keylen, int flags,
    struct net2_buffer *initbuf)
{
	struct net2_xchange_ctx	*x;

	/*
	 * Fail if algorithm does not exist.
	 * Initbuf may never be NULL.
	 */
	if (alg < 0 || alg >= net2_xchangemax || initbuf == NULL)
		return NULL;

	/*
	 * Initiator will fill the buffer, not read it.
	 * Therefore, initbuf needs to be empty.
	 */
	if ((flags & NET2_XCHANGE_F_INITIATOR) && !net2_buffer_empty(initbuf))
		return NULL;

	if ((x = malloc(sizeof(*x))) == NULL)
		goto fail_0;
	x->fn = &xchange[alg];
	x->flags = flags;
	x->scratch = NULL;
	if ((*xchange[alg].init)(x, keylen, initbuf))
		goto fail_1;
	return x;

fail_1:
	free(x);
fail_0:
	return NULL;
}

/* Destroy xchange context. */
ILIAS_NET2_EXPORT void
net2_xchangectx_free(struct net2_xchange_ctx *x)
{
	if (x->fn->destroy != NULL)
		(*x->fn->destroy)(x);
	free(x);
}

/* Fill export buffer. */
ILIAS_NET2_EXPORT struct net2_buffer*
net2_xchangectx_export(struct net2_xchange_ctx *x)
{
	struct net2_buffer		*b;

	if ((b = net2_buffer_new()) == NULL)
		goto fail_0;
	if (x->fn->export(x, b))
		goto fail_1;
	return b;

fail_1:
	net2_buffer_free(b);
fail_0:
	return NULL;
}

/* Read import buffer. */
ILIAS_NET2_EXPORT int
net2_xchangectx_import(struct net2_xchange_ctx *x, struct net2_buffer *b)
{
	if (b == NULL)
		return -1;
	return x->fn->import(x, b);
}

/* Returns final key. */
ILIAS_NET2_EXPORT struct net2_buffer*
net2_xchangectx_final(struct net2_xchange_ctx *x)
{
	struct net2_buffer	*b;

	if ((b = net2_buffer_new()) == NULL)
		goto fail_0;
	if ((*x->fn->final)(x, b))
		goto fail_1;
	return b;

fail_1:
	net2_buffer_free(b);
fail_0:
	return NULL;
}

/* Return negotiated key and free xchange. */
ILIAS_NET2_EXPORT struct net2_buffer*
net2_xchangectx_finalfree(struct net2_xchange_ctx *x)
{
	struct net2_buffer	*b;

	b = net2_xchangectx_final(x);
	net2_xchangectx_free(x);
	return b;
}


/* Initialize NIL, nil key exchange always fails, for lack of implementation. */
static int
NIL_init_fn(struct net2_xchange_ctx *x, size_t keylen,
    struct net2_buffer *initbuf)
{
	return -1;
}

/* Clean all SSL errors. */
static void
eat_ssl_errors()
{
	while (ERR_get_error() != 0);
}
/* Print all SSL errors. */
static void
print_ssl_errors()
{
	char			buf[256];
	unsigned long		e;

	while ((e = ERR_get_error()) != 0) {
		ERR_error_string_n(e, buf, sizeof(buf));
		buf[sizeof(buf) - 1] = '\0';
		warnx("SSL %lu %s", e, &buf[0]);
	}
}

/* Initialize DH. */
static int
DH_init_fn(struct net2_xchange_ctx *x, size_t keylen,
    struct net2_buffer *initbuf)
{
	uint8_t			 rnd[1024]; /* Hopefully this is overkill. */
	int			 len;
	struct iovec		 iov;
	size_t			 iovlen = 1, initbuf_len;
	unsigned char		*p, *pp;
	int			 check_codes;

	eat_ssl_errors();

	/*
	 * Seed the openssl random generator with secure_buffer data
	 * prior to determining the parameters.
	 */
	secure_random_buf(&rnd[0], sizeof(rnd));
	RAND_seed(&rnd[0], sizeof(rnd));
	net2_secure_zero(&rnd[0], sizeof(rnd));
	print_ssl_errors();

	/*
	 * Generate or read parameters.
	 */
	if (x->flags & NET2_XCHANGE_F_INITIATOR) {
		/* Generate DH parameters. */
		if ((x->impl.dh = DH_generate_parameters(8 * keylen,
		    DH_GENERATOR_5, NULL, NULL)) == NULL)
			goto fail_0;

		/* Calculate the buffer size needed to encode this. */
		if ((len = i2d_DHparams(x->impl.dh, NULL)) == -1)
			goto fail;

		/* Allocate space for parameters. */
		iovlen = 1;
		if (net2_buffer_reserve_space(initbuf, len, &iov, &iovlen))
			goto fail;

		/* Store encoded parameters in buffer. */
		p = iov.iov_base;
		if ((len = i2d_DHparams(x->impl.dh, &p)) == -1)
			goto fail;
		assert(len >= 0 && iov.iov_len >= (size_t)len);
		iov.iov_len = len;
		if (net2_buffer_commit_space(initbuf, &iov, iovlen))
			goto fail;
	} else {
		initbuf_len = net2_buffer_length(initbuf);

		/* We need a contig buffer for reading. */
		if ((pp = p = net2_buffer_pullup(initbuf, -1)) == NULL)
			goto fail_0;

		/* Read DH parameters from buffer. */
		x->impl.dh = NULL;
		if (d2i_DHparams(&x->impl.dh, (const unsigned char**)&p,
		    initbuf_len) == NULL)
			goto fail_0;

		/*
		 * Check if the whole buffer was used.
		 * Left over space means that something went wrong.
		 */
		if (pp + initbuf_len != p)
			goto fail;
	}

	/*
	 * Check parameters.
	 * We do this with the locally generated params (INITIATOR case above)
	 * as well, to validate that the other end is able to succeed.
	 */
	check_codes = 0;
	if (!DH_check(x->impl.dh, &check_codes)) {
		if (check_codes & DH_UNABLE_TO_CHECK_GENERATOR)
			warnx("DH: unable to check generator");
		else
			warnx("DH: could not check parameters");
		goto fail;
	}
	if (check_codes & DH_UNABLE_TO_CHECK_GENERATOR)
		warnx("DH: unable to check generator");
	if (check_codes & DH_NOT_SUITABLE_GENERATOR)
		warnx("DH: not a suitable generator");
	if (check_codes & DH_CHECK_P_NOT_SAFE_PRIME)
		warnx("DH: p is not a safe prime");
	if (check_codes) {
		warnx("DH: failing due to DH_check failure");
		goto fail;
	}

	if ((size_t)DH_size(x->impl.dh) != keylen) {
		/* Yes, DH_size is in bytes, just like keylen. */
		warnx("DH: DH_size = %d, expecting %lu",
		    DH_size(x->impl.dh), (unsigned long)keylen);
		goto fail;
	}

	return 0;

fail:
	DH_free(x->impl.dh);
fail_0:
	print_ssl_errors();
	return -1;
}
/* DH destructor. */
static void
DH_destroy_fn(struct net2_xchange_ctx *x)
{
	eat_ssl_errors();

	/* scratch is actually a bignum public key */
	if (x->scratch != NULL) {
		BN_clear_free((BIGNUM*)x->scratch);
		x->scratch = NULL;
	}
	DH_free(x->impl.dh);

	print_ssl_errors();
}
/* Export public key. */
static int
DH_export_fn(struct net2_xchange_ctx *x, struct net2_buffer *b)
{
	struct iovec		iov;
	size_t			iovlen = 1;

	eat_ssl_errors();

	/* Generate key. */
	if (!DH_generate_key(x->impl.dh))
		goto fail;

	/* Write key to buffer. */
	if (net2_buffer_reserve_space(b, BN_num_bytes(x->impl.dh->pub_key),
	    &iov, &iovlen))
		goto fail;
	iov.iov_len = BN_bn2bin(x->impl.dh->pub_key, iov.iov_base);
	if (net2_buffer_commit_space(b, &iov, iovlen))
		goto fail;

	return 0;

fail:
	print_ssl_errors();
	return -1;
}
/* Import public key. */
static int
DH_import_fn(struct net2_xchange_ctx *x, struct net2_buffer *b)
{
	void			*p;
	size_t			 p_len;

	eat_ssl_errors();

	/* Get binary data. */
	p_len = net2_buffer_length(b);
	if ((p = net2_buffer_pullup(b, p_len)) == NULL)
		goto fail;

	/* Import binary data. */
	if ((x->scratch = BN_bin2bn(p, p_len, (BIGNUM*)x->scratch)) == NULL)
		goto fail;

	return 0;

fail:
	print_ssl_errors();
	return -1;
}
/* Calculate exchanged private key. */
static int
DH_final_fn(struct net2_xchange_ctx *x, struct net2_buffer *privkey)
{
	struct iovec		iov;
	size_t			iovlen = 1;
	int			rv;
	size_t			keylen, i;

	eat_ssl_errors();

	/* Check that we indeed have our partner's public key. */
	if (x->scratch == NULL)
		goto fail;

	keylen = DH_size(x->impl.dh);

	/* Prepare space in privkey. */
	if (net2_buffer_reserve_space(privkey, keylen, &iov, &iovlen))
		goto fail;
	/* Computation. */
	rv = DH_compute_key(iov.iov_base, (BIGNUM*)x->scratch, x->impl.dh);
	if (rv == -1)
		goto fail;

	/* Commit privkey. */
	iov.iov_len = keylen;

	/* DH removes leading zeroes from the key. */
	if ((size_t)rv < keylen) {
		/* Move data towards the end of the iov. */
		memmove((uint8_t*)iov.iov_base + (keylen - (size_t)rv),
		    iov.iov_base, rv);
		/* Reintroduce zeroes at the front. */
		memset(iov.iov_base, 0, keylen - (size_t)rv);
	}

	if (net2_buffer_commit_space(privkey, &iov, iovlen))
		goto fail;

	return 0;

fail:
	print_ssl_errors();
	return -1;
}
