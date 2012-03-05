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
#include <ilias/net2/hash.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/config.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <event2/buffer.h>
#include <ilias/net2/bsd_compat/error.h>
#include <ilias/net2/bsd_compat/sysexits.h>

#ifdef WIN32
#include <malloc.h>
#endif

#ifdef HAS_SHA2
#include <sha2.h>
#else
#include <ilias/net2/bsd_compat/sha2.h>
#endif

#include <openssl/evp.h>
#include <openssl/hmac.h>

/* SHA256 */
static int	SHA256_init_fn(struct net2_hash_ctx*, const void*, size_t);
static void	SHA256_destroy_fn(struct net2_hash_ctx*);
static int	SHA256_update_fn(struct net2_hash_ctx*, const void*, size_t);
static int	SHA256_final_fn(void*, struct net2_hash_ctx*);
/* SHA384 */
static int	SHA384_init_fn(struct net2_hash_ctx*, const void*, size_t);
static void	SHA384_destroy_fn(struct net2_hash_ctx*);
static int	SHA384_update_fn(struct net2_hash_ctx*, const void*, size_t);
static int	SHA384_final_fn(void*, struct net2_hash_ctx*);
/* SHA512 */
static int	SHA512_init_fn(struct net2_hash_ctx*, const void*, size_t);
static void	SHA512_destroy_fn(struct net2_hash_ctx*);
static int	SHA512_update_fn(struct net2_hash_ctx*, const void*, size_t);
static int	SHA512_final_fn(void*, struct net2_hash_ctx*);
/* HMAC-SHA256 */
static int	HMAC_SHA256_init_fn(struct net2_hash_ctx*,
		    const void*, size_t);
#define HMAC_SHA256_destroy_fn		HMAC_SHA2_destroy_fn
#define HMAC_SHA256_update_fn		HMAC_SHA2_update_fn
#define HMAC_SHA256_final_fn		HMAC_SHA2_final_fn
/* HMAC-SHA384 */
static int	HMAC_SHA384_init_fn(struct net2_hash_ctx*,
		    const void*, size_t);
#define HMAC_SHA384_destroy_fn		HMAC_SHA2_destroy_fn
#define HMAC_SHA384_update_fn		HMAC_SHA2_update_fn
#define HMAC_SHA384_final_fn		HMAC_SHA2_final_fn
/* HMAC-SHA512 */
static int	HMAC_SHA512_init_fn(struct net2_hash_ctx*,
		    const void*, size_t);
#define HMAC_SHA512_destroy_fn		HMAC_SHA2_destroy_fn
#define HMAC_SHA512_update_fn		HMAC_SHA2_update_fn
#define HMAC_SHA512_final_fn		HMAC_SHA2_final_fn

/* HMAC-SHA??? functions. */
static void	HMAC_SHA2_destroy_fn(struct net2_hash_ctx*);
static int	HMAC_SHA2_update_fn(struct net2_hash_ctx*,
		    const void*, size_t);
static int	HMAC_SHA2_final_fn(void*, struct net2_hash_ctx*);

/* Function table. */
struct hash_fn {
	const char		*name;
	size_t			 hashlen;
	size_t			 keylen;
	int	(*init_fn)(struct net2_hash_ctx*, const void*, size_t);
	void	(*destroy_fn)(struct net2_hash_ctx*);
	int	(*update_fn)(struct net2_hash_ctx*, const void*, size_t);
	int	(*final_fn)(void*, struct net2_hash_ctx*);
};

#define HASH_FN(_namestr, _hashlen, _keylen, _name)			\
	{								\
		_namestr, (_hashlen), (_keylen),			\
		_name##_init_fn,					\
		_name##_destroy_fn,					\
		_name##_update_fn,					\
		_name##_final_fn					\
	}

/* Hash definitions. */
static const struct hash_fn hash[] = {
	{ "nil", 0, 0, NULL, NULL, NULL, NULL },
	HASH_FN("sha256", SHA256_DIGEST_LENGTH, 0, SHA256),
	HASH_FN("sha384", SHA384_DIGEST_LENGTH, 0, SHA384),
	HASH_FN("sha512", SHA512_DIGEST_LENGTH, 0, SHA512),
	HASH_FN("hmac-sha256", SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH,
	    HMAC_SHA256),
	HASH_FN("hmac-sha384", SHA384_DIGEST_LENGTH, SHA384_DIGEST_LENGTH,
	    HMAC_SHA384),
	HASH_FN("hmac-sha512", SHA512_DIGEST_LENGTH, SHA512_DIGEST_LENGTH,
	    HMAC_SHA512),
};

/* Export number of possible hash algorithms. */
ILIAS_NET2_EXPORT const int net2_hashmax = sizeof(hash) / sizeof(hash[0]);


struct net2_hash_ctx {
	const struct hash_fn	*fn;	/* Hash algorithm. */

	union {
		SHA2_CTX	 sha2;
		HMAC_CTX	 hmac_ctx;
	}			 impl;	/* Context implementation. */
};


/* Retrieve the length of the hash. */
ILIAS_NET2_EXPORT size_t
net2_hash_gethashlen(int alg)
{
	if (alg < 0 || alg >= net2_hashmax)
		return 0;
	return hash[alg].hashlen;
}

/* Retrieve the required key size of the hash. */
ILIAS_NET2_EXPORT size_t
net2_hash_getkeylen(int alg)
{
	if (alg < 0 || alg >= net2_hashmax)
		return 0;
	return hash[alg].keylen;
}

/* Retrieve the name of the hash. */
ILIAS_NET2_EXPORT const char*
net2_hash_getname(int alg)
{
	if (alg < 0 || alg >= net2_hashmax)
		return NULL;
	return hash[alg].name;
}

/*
 * Find the hash with the given name.
 * Return -1 if no algorithm with the given name exists.
 */
ILIAS_NET2_EXPORT int
net2_hash_findname(const char *name)
{
	int			i;

	if (name == NULL)
		return -1;

	for (i = 0; i >= 0 && i < net2_hashmax; i++) {
		if (hash[i].name != NULL && strcmp(hash[i].name, name) == 0)
			return i;
	}
	return -1;
}

/* Create a new hash context for the given algorithm ID. */
ILIAS_NET2_EXPORT struct net2_hash_ctx*
net2_hashctx_new(int alg, const void *key, size_t keylen)
{
	const struct hash_fn	*fn;
	struct net2_hash_ctx	*ctx;

	/* Check arguments. */
	if (alg < 0 || alg >= net2_hashmax)
		return NULL;
	if (key == NULL && keylen != 0)
		return NULL;

	/* Find algorithm. */
	fn = &hash[alg];
	if (keylen != fn->keylen)
		return NULL;

	/* Allocate context. */
	if ((ctx = net2_malloc(sizeof(*ctx))) == NULL)
		return NULL;

	/* Store algorithm and initialize state. */
	ctx->fn = fn;
	if (fn->init_fn != NULL &&
	    (*fn->init_fn)(ctx, key, keylen)) {
		net2_free(ctx);
		return NULL;
	}

	return ctx;
}

/* Free hash context. */
ILIAS_NET2_EXPORT void
net2_hashctx_free(struct net2_hash_ctx *ctx)
{
	const struct hash_fn	*fn = ctx->fn;

	if (fn->destroy_fn != NULL)
		(*fn->destroy_fn)(ctx);
	net2_free(ctx);
}

/* Add data to be hashed. */
ILIAS_NET2_EXPORT int
net2_hashctx_update(struct net2_hash_ctx *ctx, const void *data, size_t len)
{
	const struct hash_fn	*fn = ctx->fn;

	if (fn->update_fn != NULL)
		return (*fn->update_fn)(ctx, data, len);
	return 0;
}

/* Add data that is to be hashed, from the specified buffer. */
ILIAS_NET2_EXPORT int
net2_hashctx_updatebuf(struct net2_hash_ctx *ctx,
    const struct net2_buffer *buf)
{
	struct iovec		*iov;
	size_t			 iovcount;
	size_t			 buflen;
	int			 error;

	if ((buflen = net2_buffer_length(buf)) == 0)
		return 0;

	iovcount = net2_buffer_peek(buf, buflen, NULL, 0);
	iov = alloca(iovcount * sizeof(*iov));
	if (net2_buffer_peek(buf, buflen, iov, iovcount) != iovcount) {
		errx(EX_SOFTWARE, "net2_hashctx_updatebuf: "
		    "iovcount changed between calls");
	}

	while (iovcount > 0) {
		error = net2_hashctx_update(ctx, iov->iov_base, iov->iov_len);
		if (error != 0)
			return error;

		/* Next. */
		iov++;
		iovcount--;
	}

	return 0;
}

/* Retrieve result of hash operation. */
ILIAS_NET2_EXPORT struct net2_buffer*
net2_hashctx_final(struct net2_hash_ctx *ctx)
{
	const struct hash_fn	*fn = ctx->fn;
	struct net2_buffer	*buf;
	struct iovec		 iov;
	size_t			 iovlen;

	if ((buf = net2_buffer_new()) == NULL)
		return NULL;
	if (fn->final_fn == NULL)
		return buf;
	iovlen = 1;
	if (net2_buffer_reserve_space(buf, fn->hashlen,
	    &iov, &iovlen)) {
		net2_buffer_free(buf);
		return NULL;
	}
	if (iovlen == 0)
		iov.iov_len = 0;
	else
		iov.iov_len = fn->hashlen;

	if ((*fn->final_fn)(iov.iov_base, ctx)) {
		net2_buffer_free(buf);
		return NULL;
	}
	if (net2_buffer_commit_space(buf, &iov, iovlen)) {
		net2_buffer_free(buf);
		return NULL;
	}
	return buf;
}

/* Execute call to final and free in a single operation. */
ILIAS_NET2_EXPORT struct net2_buffer*
net2_hashctx_finalfree(struct net2_hash_ctx *ctx)
{
	struct net2_buffer	*buf;

	buf = net2_hashctx_final(ctx);
	net2_hashctx_free(ctx);
	return buf;
}

/* Calculate the hash of a single buffer. */
ILIAS_NET2_EXPORT struct net2_buffer*
net2_hashctx_hashbuf(int alg, const void *key, size_t keylen,
    const struct net2_buffer *buf)
{
	struct net2_hash_ctx	*ctx;

	/* Create hash context. */
	if ((ctx = net2_hashctx_new(alg, key, keylen)) == NULL)
		return NULL;
	/* Update hash context with buffer data. */
	if (net2_hashctx_updatebuf(ctx, buf))
		goto fail;
	/* Return calculated hash. */
	return net2_hashctx_finalfree(ctx);

fail:
	/* Handle update failure. */
	net2_hashctx_free(ctx);
	return NULL;
}


static int
SHA256_init_fn(struct net2_hash_ctx *c, const void *key, size_t keylen)
{
	SHA256Init(&c->impl.sha2);
	return 0;
}
static void
SHA256_destroy_fn(struct net2_hash_ctx *c)
{
	return;
}
static int
SHA256_update_fn(struct net2_hash_ctx *c, const void *buf, size_t len)
{
	SHA256Update(&c->impl.sha2, buf, len);
	return 0;
}
static int
SHA256_final_fn(void *out, struct net2_hash_ctx *c)
{
	SHA256Final(out, &c->impl.sha2);
	return 0;
}

static int
SHA384_init_fn(struct net2_hash_ctx *c, const void *key, size_t keylen)
{
	SHA384Init(&c->impl.sha2);
	return 0;
}
static void
SHA384_destroy_fn(struct net2_hash_ctx *c)
{
	return;
}
static int
SHA384_update_fn(struct net2_hash_ctx *c, const void *buf, size_t len)
{
	SHA384Update(&c->impl.sha2, buf, len);
	return 0;
}
static int
SHA384_final_fn(void *out, struct net2_hash_ctx *c)
{
	SHA384Final(out, &c->impl.sha2);
	return 0;
}

static int
SHA512_init_fn(struct net2_hash_ctx *c, const void *key, size_t keylen)
{
	SHA512Init(&c->impl.sha2);
	return 0;
}
static void
SHA512_destroy_fn(struct net2_hash_ctx *c)
{
	return;
}
static int
SHA512_update_fn(struct net2_hash_ctx *c, const void *buf, size_t len)
{
	SHA512Update(&c->impl.sha2, buf, len);
	return 0;
}
static int
SHA512_final_fn(void *out, struct net2_hash_ctx *c)
{
	SHA512Final(out, &c->impl.sha2);
	return 0;
}

static int
HMAC_SHA256_init_fn(struct net2_hash_ctx *ctx, const void *key, size_t keylen)
{
	HMAC_CTX_init(&ctx->impl.hmac_ctx);
	if (!HMAC_Init_ex(&ctx->impl.hmac_ctx, key, keylen, EVP_sha256(),
	    NULL)) {
		HMAC_CTX_cleanup(&ctx->impl.hmac_ctx);
		return -1;
	}
	return 0;
}
static int
HMAC_SHA384_init_fn(struct net2_hash_ctx *ctx, const void *key, size_t keylen)
{
	HMAC_CTX_init(&ctx->impl.hmac_ctx);
	if (!HMAC_Init_ex(&ctx->impl.hmac_ctx, key, keylen, EVP_sha384(),
	    NULL)) {
		HMAC_CTX_cleanup(&ctx->impl.hmac_ctx);
		return -1;
	}
	return 0;
}
static int
HMAC_SHA512_init_fn(struct net2_hash_ctx *ctx, const void *key, size_t keylen)
{
	HMAC_CTX_init(&ctx->impl.hmac_ctx);
	if (!HMAC_Init_ex(&ctx->impl.hmac_ctx, key, keylen, EVP_sha512(),
	    NULL)) {
		HMAC_CTX_cleanup(&ctx->impl.hmac_ctx);
		return -1;
	}
	return 0;
}
static void
HMAC_SHA2_destroy_fn(struct net2_hash_ctx *ctx)
{
	HMAC_CTX_cleanup(&ctx->impl.hmac_ctx);
}
static int
HMAC_SHA2_update_fn(struct net2_hash_ctx *ctx, const void *data, size_t len)
{
	if (!HMAC_Update(&ctx->impl.hmac_ctx, data, len))
		return -1;
	return 0;
}
static int
HMAC_SHA2_final_fn(void *out, struct net2_hash_ctx *ctx)
{
	unsigned int		result_len;

	result_len = ctx->fn->hashlen;
	if (!HMAC_Final(&ctx->impl.hmac_ctx, out, &result_len))
		return -1;
	if (ctx->fn->hashlen != result_len) {
		warnx("%s: hash output has length %u, expected %u",
		    ctx->fn->name,
		    result_len, (unsigned int)ctx->fn->hashlen);
		return -1;
	}
	return 0;
}
