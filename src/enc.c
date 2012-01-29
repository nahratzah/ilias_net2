#include <ilias/net2/enc.h>
#include <bsd_compat/bsd_compat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <bsd_compat/error.h>

#ifdef WIN32
#include <malloc.h>
#endif

#include <openssl/evp.h>
#include <openssl/aes.h>

/* NIL encoder (identity encoding) */
static int	NIL_init_fn(struct net2_enc_ctx*, const void*, size_t,
		    const void*, size_t, int);
static void	NIL_destroy_fn(struct net2_enc_ctx*);
static int	NIL_update_fn(struct net2_enc_ctx*, const void*, size_t);
static int	NIL_final_fn(struct net2_enc_ctx*);
/* AES256 encoder. */
static int	AES256_init_fn(struct net2_enc_ctx*, const void*, size_t,
		    const void*, size_t, int);
static void	AES256_destroy_fn(struct net2_enc_ctx*);
static int	AES256_update_fn(struct net2_enc_ctx*, const void*, size_t);
static int	AES256_final_fn(struct net2_enc_ctx*);

struct enc_fn {
	const char		*name;
	size_t			 keylen;
	size_t			 ivlen;
	int			(*init_fn)(struct net2_enc_ctx*,
				    const void*, size_t, const void*, size_t,
				    int);
	void			(*destroy_fn)(struct net2_enc_ctx*);
	int			(*update_fn)(struct net2_enc_ctx*,
				    const void*, size_t);
	int			(*final_fn)(struct net2_enc_ctx*);
	size_t			 overhead;
};

#define ENC_FN(_namestr, _keylen, _ivlen, _name, _overhead)		\
	{								\
		_namestr, (_keylen), (_ivlen),				\
		_name##_init_fn,					\
		_name##_destroy_fn,					\
		_name##_update_fn,					\
		_name##_final_fn,					\
		(_overhead)						\
	}

/* Encoder definition. */
static const struct enc_fn enc[] = {
	ENC_FN("nil", 0, 0, NIL, 0),
	ENC_FN("aes256", 256 / 8, AES_BLOCK_SIZE, AES256,
	    AES_BLOCK_SIZE),
};

/* Export number of possible algorithms. */
ILIAS_NET2_EXPORT const int net2_encmax = sizeof(enc) / sizeof(enc[0]);

struct net2_enc_ctx {
	struct net2_buffer	*out;
	const struct enc_fn	*fn;
	int			 direction;

	union {
		EVP_CIPHER_CTX	 cipher_ctx;
	}			 impl;
};


/* Lookup key length for algorithm. */
ILIAS_NET2_EXPORT size_t
net2_enc_getkeylen(int alg)
{
	if (alg < 0 || alg >= net2_encmax)
		return 0;
	return enc[alg].keylen;
}

/* Lookup iv length for algorithm. */
ILIAS_NET2_EXPORT size_t
net2_enc_getivlen(int alg)
{
	if (alg < 0 || alg >= net2_encmax)
		return 0;
	return enc[alg].ivlen;
}

/* Lookup name for algorithm. */
ILIAS_NET2_EXPORT const char*
net2_enc_getname(int alg)
{
	if (alg < 0 || alg >= net2_encmax)
		return NULL;
	return enc[alg].name;
}

/* Lookup max overhead for algorithm. */
ILIAS_NET2_EXPORT size_t
net2_enc_getoverhead(int alg)
{
	if (alg < 0 || alg >= net2_encmax)
		return 0;
	return enc[alg].overhead;
}

ILIAS_NET2_EXPORT int
net2_enc_findname(const char *name)
{
	int			i;

	if (name == NULL)
		return -1;

	for (i = 0; i < net2_encmax; i++) {
		if (enc[i].name != NULL && strcmp(enc[i].name, name) == 0)
			return i;
	}
	return -1;
}

/* Create new encoder context. */
ILIAS_NET2_EXPORT struct net2_enc_ctx*
net2_encctx_new(int alg, const void *key, size_t keylen,
    const void *iv, size_t ivlen, int direction)
{
	struct net2_enc_ctx	*ctx;
	const struct enc_fn	*fn;

	/* Check arguments. */
	if (alg < 0 || alg >= net2_encmax)
		return NULL;
	if (direction != NET2_ENC_ENCRYPT && direction != NET2_ENC_DECRYPT)
		return NULL;
	if ((key == NULL && keylen != 0) ||
	    (iv == NULL && ivlen != 0))
		return NULL;

	/* Lookup algorithm. */
	fn = &enc[alg];
	/* Check if algorithm has an init_fn. */
	if (fn->init_fn == NULL)
		return NULL;

	/* Check keylen and ivlen. */
	if (keylen != fn->keylen && ivlen != fn->ivlen)
		return NULL;

	/* Create context. */
	if ((ctx = malloc(sizeof(*ctx))) == NULL)
		return NULL;
	if ((ctx->out = net2_buffer_new()) == NULL) {
		free(ctx);
		return NULL;
	}
	ctx->fn = fn;
	ctx->direction = direction;
	/* Initialize algorithm. */
	if ((*fn->init_fn)(ctx, key, keylen, iv, ivlen, direction)) {
		net2_buffer_free(ctx->out);
		free(ctx);
		return NULL;
	}

	return ctx;
}

/* Free encoder context. */
ILIAS_NET2_EXPORT void
net2_encctx_free(struct net2_enc_ctx *ctx)
{
	const struct enc_fn	*fn = ctx->fn;

	if (fn->destroy_fn != NULL)
		(*fn->destroy_fn)(ctx);
	if (ctx->out)
		net2_buffer_free(ctx->out);
	free(ctx);
}

/* Add data to encoder context. */
ILIAS_NET2_EXPORT int
net2_encctx_update(struct net2_enc_ctx *ctx, const void *data, size_t len)
{
	return (*ctx->fn->update_fn)(ctx, data, len);
}

/* Finalize encryption context and retrieve the result. */
ILIAS_NET2_EXPORT struct net2_buffer*
net2_encctx_final(struct net2_enc_ctx *ctx)
{
	struct net2_buffer	*out;

	/* Small measure of protection against double invocation... */
	if (ctx->out == NULL)
		return NULL;

	if ((*ctx->fn->final_fn)(ctx))
		return NULL;
	out = ctx->out;
	ctx->out = NULL;
	return out;
}

/* Finalize and free encryption context. */
ILIAS_NET2_EXPORT struct net2_buffer*
net2_encctx_finalfree(struct net2_enc_ctx *ctx)
{
	struct net2_buffer	*buf;

	buf = net2_encctx_final(ctx);
	net2_encctx_free(ctx);
	return buf;
}

ILIAS_NET2_EXPORT struct net2_buffer*
net2_encctx_encbuf(int alg, const void *key, size_t keylen,
    const void *iv, size_t ivlen, int direction, struct net2_buffer *buf)
{
	struct net2_enc_ctx	*ctx;
	struct iovec		*iov;
	size_t			 buflen;
	int			 iovlen;

	/* Set up IO vectors. */
	if (buf == NULL)
		return NULL;
	buflen = net2_buffer_length(buf);
	iovlen = net2_buffer_peek(buf, buflen, NULL, 0);
	if (iovlen == -1)
		return NULL;
	iov = alloca(iovlen * sizeof(*iov));
	net2_buffer_peek(buf, buflen, iov, iovlen);

	/* Create enc context. */
	if ((ctx = net2_encctx_new(alg, key, keylen, iv, ivlen, direction)) ==
	    NULL)
		return NULL;
	/* Update enc context with buffer data. */
	for (; iovlen > 0; iovlen--, iov++) {
		if (net2_encctx_update(ctx, iov->iov_base, iov->iov_len))
			goto fail;
	}
	/* Return calculated enc. */
	return net2_encctx_finalfree(ctx);

fail:
	/* Handle update failure. */
	net2_encctx_free(ctx);
	return NULL;
}


static int
NIL_init_fn(struct net2_enc_ctx *ctx, const void *key, size_t keylen,
    const void *iv, size_t ivlen, int direction)
{
	return 0;
}
static void
NIL_destroy_fn(struct net2_enc_ctx *ctx)
{
	return;
}
static int
NIL_update_fn(struct net2_enc_ctx *ctx, const void *data, size_t len)
{
	return net2_buffer_add(ctx->out, data, len);
}
static int
NIL_final_fn(struct net2_enc_ctx *ctx)
{
	return 0;
}

static int
AES256_init_fn(struct net2_enc_ctx *ctx, const void *key, size_t keylen,
    const void *iv, size_t ivlen, int direction)
{
	EVP_CIPHER_CTX_init(&ctx->impl.cipher_ctx);
	switch (direction) {
	case NET2_ENC_ENCRYPT:
		if (!EVP_EncryptInit_ex(&ctx->impl.cipher_ctx,
		    EVP_aes_256_cbc(), NULL, key, iv))
			goto fail;
		break;
	case NET2_ENC_DECRYPT:
		if (!EVP_DecryptInit_ex(&ctx->impl.cipher_ctx,
		    EVP_aes_256_cbc(), NULL, key, iv))
			goto fail;
		break;
	}
	return 0;

fail:
	EVP_CIPHER_CTX_cleanup(&ctx->impl.cipher_ctx);
	return -1;
}
static void
AES256_destroy_fn(struct net2_enc_ctx *ctx)
{
	EVP_CIPHER_CTX_cleanup(&ctx->impl.cipher_ctx);
}
static int
AES256_update_fn(struct net2_enc_ctx *ctx, const void *data, size_t len)
{
	struct iovec		iov;
	int			cipherlen;
	size_t			iovlen;

	/* Prepare space. */
	iovlen = 1;
	if (net2_buffer_reserve_space(ctx->out, len + AES_BLOCK_SIZE,
	    &iov, &iovlen))
		return -1;
	cipherlen = iov.iov_len;

	/* Invoke encrypt or decrypt function. */
	switch (ctx->direction) {
	case NET2_ENC_ENCRYPT:
		if (!EVP_EncryptUpdate(&ctx->impl.cipher_ctx,
		    iov.iov_base, &cipherlen, data, len))
			return -1;
		break;
	case NET2_ENC_DECRYPT:
		if (!EVP_DecryptUpdate(&ctx->impl.cipher_ctx,
		    iov.iov_base, &cipherlen, data, len))
			return -1;
		break;
	}

	/* Commit prepared space. */
	iov.iov_len = cipherlen;
	if (net2_buffer_commit_space(ctx->out, &iov, iovlen) == -1)
		return -1;

	return 0;
}
static int
AES256_final_fn(struct net2_enc_ctx *ctx)
{
	struct iovec		iov;
	int			cipherlen;
	size_t			iovlen;

	/* Prepare space. */
	iovlen = 1;
	if (net2_buffer_reserve_space(ctx->out, AES_BLOCK_SIZE,
	    &iov, &iovlen))
		return -1;
	cipherlen = iov.iov_len;

	/* Invoke encrypt or decrypt function. */
	switch (ctx->direction) {
	case NET2_ENC_ENCRYPT:
		if (!EVP_EncryptFinal_ex(&ctx->impl.cipher_ctx,
		    iov.iov_base, &cipherlen))
			return -1;
		break;
	case NET2_ENC_DECRYPT:
		if (!EVP_DecryptFinal_ex(&ctx->impl.cipher_ctx,
		    iov.iov_base, &cipherlen))
			return -1;
		break;
	}

	/* Commit prepared space. */
	iov.iov_len = cipherlen;
	if (net2_buffer_commit_space(ctx->out, &iov, iovlen) == -1)
		return -1;

	return 0;
}
