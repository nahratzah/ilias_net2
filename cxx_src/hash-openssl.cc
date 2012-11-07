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
#include <ilias/net2/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>


namespace ilias {


hash_ctx::~hash_ctx() ILIAS_NET2_NOTHROW
{
	return;
}

buffer
hash_ctx_factory::run(const buffer& key, const buffer& data) const
{
	std::unique_ptr<hash_ctx> instance = this->instantiate(key);
	instance->update(data);
	return MOVE(instance->final());
}


hash_ctx_factory::~hash_ctx_factory() ILIAS_NET2_NOTHROW
{
	return;
}


class ILIAS_NET2_LOCAL hash_sha256 :
	public hash_ctx
{
private:
	SHA256_CTX ctx;

public:
	hash_sha256() :
		hash_ctx("SHA256", SHA256_DIGEST_LENGTH, 0)
	{
		SHA256_Init(&ctx);
	}

	virtual void update(const buffer&);
	virtual buffer final();
};

class ILIAS_NET2_LOCAL hash_sha384 :
	public hash_ctx
{
private:
	SHA512_CTX ctx;

public:
	hash_sha384() :
		hash_ctx("SHA384", SHA384_DIGEST_LENGTH, 0)
	{
		SHA384_Init(&ctx);
	}

	virtual void update(const buffer&);
	virtual buffer final();
};

class ILIAS_NET2_LOCAL hash_sha512 :
	public hash_ctx
{
private:
	SHA512_CTX ctx;

public:
	hash_sha512() :
		hash_ctx("SHA512", SHA512_DIGEST_LENGTH, 0)
	{
		SHA512_Init(&ctx);
	}

	virtual void update(const buffer&);
	virtual buffer final();
};


void
hash_sha256::update(const buffer& b)
{
	b.visit([this](const void* p, buffer::size_type l) {
		SHA256_Update(&ctx, reinterpret_cast<const uint8_t*>(p), l);
	});
}

void
hash_sha384::update(const buffer& b)
{
	b.visit([this](const void* p, buffer::size_type l) {
		SHA384_Update(&ctx, reinterpret_cast<const uint8_t*>(p), l);
	});
}

void
hash_sha512::update(const buffer& b)
{
	b.visit([this](const void* p, buffer::size_type l) {
		SHA512_Update(&ctx, reinterpret_cast<const uint8_t*>(p), l);
	});
}


buffer
hash_sha256::final()
{
	buffer rv;
	buffer::prepare prep(rv, SHA256_DIGEST_LENGTH);
	SHA256_Final(reinterpret_cast<uint8_t*>(prep.data()), &ctx);
	prep.commit();
	return MOVE(rv);
}

buffer
hash_sha384::final()
{
	buffer rv;
	buffer::prepare prep(rv, SHA384_DIGEST_LENGTH);
	SHA384_Final(reinterpret_cast<uint8_t*>(prep.data()), &ctx);
	prep.commit();
	return MOVE(rv);
}

buffer
hash_sha512::final()
{
	buffer rv;
	buffer::prepare prep(rv, SHA512_DIGEST_LENGTH);
	SHA512_Final(reinterpret_cast<uint8_t*>(prep.data()), &ctx);
	prep.commit();
	return MOVE(rv);
}


class ILIAS_NET2_LOCAL hash_sha256_factory :
	public hash_ctx_factory
{
public:
	hash_sha256_factory() :
		hash_ctx_factory("SHA256", SHA256_DIGEST_LENGTH, 0)
	{
		/* Empty body. */
	}

	virtual ~hash_sha256_factory() ILIAS_NET2_NOTHROW;
	virtual std::unique_ptr<hash_ctx> instantiate(const buffer&) const;
	virtual buffer run(const buffer&, const buffer&) const;
};

class ILIAS_NET2_LOCAL hash_sha384_factory :
	public hash_ctx_factory
{
public:
	hash_sha384_factory() :
		hash_ctx_factory("SHA384", SHA384_DIGEST_LENGTH, 0)
	{
		/* Empty body. */
	}

	virtual ~hash_sha384_factory() ILIAS_NET2_NOTHROW;
	virtual std::unique_ptr<hash_ctx> instantiate(const buffer&) const;
	virtual buffer run(const buffer&, const buffer&) const;
};

class ILIAS_NET2_LOCAL hash_sha512_factory :
	public hash_ctx_factory
{
public:
	hash_sha512_factory() :
		hash_ctx_factory("SHA512", SHA512_DIGEST_LENGTH, 0)
	{
		/* Empty body. */
	}

	virtual ~hash_sha512_factory() ILIAS_NET2_NOTHROW;
	virtual std::unique_ptr<hash_ctx> instantiate(const buffer&) const;
	virtual buffer run(const buffer&, const buffer&) const;
};


hash_sha256_factory::~hash_sha256_factory() ILIAS_NET2_NOTHROW
{
	return;
}

hash_sha384_factory::~hash_sha384_factory() ILIAS_NET2_NOTHROW
{
	return;
}

hash_sha512_factory::~hash_sha512_factory() ILIAS_NET2_NOTHROW
{
	return;
}


std::unique_ptr<hash_ctx>
hash_sha256_factory::instantiate(const buffer& key) const
{
	if (!key.empty())
		throw std::invalid_argument("expected empty key buffer for un-keyed hash");

	return std::unique_ptr<hash_ctx>(new hash_sha256());
}

std::unique_ptr<hash_ctx>
hash_sha384_factory::instantiate(const buffer& key) const
{
	if (!key.empty())
		throw std::invalid_argument("expected empty key buffer for un-keyed hash");

	return std::unique_ptr<hash_ctx>(new hash_sha384());
}

std::unique_ptr<hash_ctx>
hash_sha512_factory::instantiate(const buffer& key) const
{
	if (!key.empty())
		throw std::invalid_argument("expected empty key buffer for un-keyed hash");

	return std::unique_ptr<hash_ctx>(new hash_sha512());
}


buffer
hash_sha256_factory::run(const buffer& key, const buffer& b) const
{
	if (!key.empty())
		throw std::invalid_argument("expected empty key buffer for un-keyed hash");

	buffer rv;
	buffer::prepare prep(rv, SHA256_DIGEST_LENGTH);
	SHA256_CTX ctx;

	SHA256_Init(&ctx);
	b.visit([&ctx](const void* p, buffer::size_type l) {
		SHA256_Update(&ctx, reinterpret_cast<const uint8_t*>(p), l);
	});
	SHA256_Final(reinterpret_cast<uint8_t*>(prep.data()), &ctx);

	prep.commit();
	return MOVE(rv);
}

buffer
hash_sha384_factory::run(const buffer& key, const buffer& b) const
{
	if (!key.empty())
		throw std::invalid_argument("expected empty key buffer for un-keyed hash");

	buffer rv;
	buffer::prepare prep(rv, SHA384_DIGEST_LENGTH);
	SHA512_CTX ctx;

	SHA384_Init(&ctx);
	b.visit([&ctx](const void* p, buffer::size_type l) {
		SHA384_Update(&ctx, reinterpret_cast<const uint8_t*>(p), l);
	});
	SHA384_Final(reinterpret_cast<uint8_t*>(prep.data()), &ctx);

	prep.commit();
	return MOVE(rv);
}

buffer
hash_sha512_factory::run(const buffer& key, const buffer& b) const
{
	if (!key.empty())
		throw std::invalid_argument("expected empty key buffer for un-keyed hash");

	buffer rv;
	buffer::prepare prep(rv, SHA512_DIGEST_LENGTH);
	SHA512_CTX ctx;

	SHA512_Init(&ctx);
	b.visit([&ctx](const void* p, buffer::size_type l) {
		SHA512_Update(&ctx, reinterpret_cast<const uint8_t*>(p), l);
	});
	SHA512_Final(reinterpret_cast<uint8_t*>(prep.data()), &ctx);

	prep.commit();
	return MOVE(rv);
}


class ILIAS_NET2_LOCAL hash_openssl_evp :
	public hash_ctx
{
private:
	HMAC_CTX ctx;

public:
	hash_openssl_evp(const EVP_MD* evp, const std::string& name, size_type hashlen, size_type keylen, const void* key);

	virtual ~hash_openssl_evp() ILIAS_NET2_NOTHROW;
	virtual void update(const buffer&);
	virtual buffer final();
};


hash_openssl_evp::hash_openssl_evp(const EVP_MD* evp, const std::string& name, size_type hashlen, size_type keylen, const void* key) :
	hash_ctx(name, hashlen, keylen)
{
	HMAC_CTX_init(&ctx);

#if (OPENSSL_VERSION_NUMBER < 0x01000000)
	/* Prior to openssl 1.0.0, the HMAC_{Init_ex,Update,Final} returned void. */
	HMAC_Init_ex(&this->ctx, key, keylen, evp, NULL);
#else
	if (!HMAC_Init_ex(&this->ctx, key, keylen, evp, NULL)) {
		HMAC_CTX_cleanup(&this->ctx);
		throw std::exception();
	}
#endif
}

hash_openssl_evp::~hash_openssl_evp() ILIAS_NET2_NOTHROW
{
	HMAC_CTX_cleanup(&this->ctx);
}

void
hash_openssl_evp::update(const buffer& b)
{
	b.visit([this](const void* p, buffer::size_type l) {
#if (OPENSSL_VERSION_NUMBER < 0x01000000)
		/* Prior to openssl 1.0.0, the HMAC_{Init_ex,Update,Final} returned void. */
		HMAC_Update(&this->ctx, reinterpret_cast<const uint8_t*>(p), l);
#else
		if (!HMAC_Update(&this->ctx, reinterpret_cast<const uint8_t*>(p), l))
			throw std::exception();
#endif
	});
}

buffer
hash_openssl_evp::final()
{
	unsigned int result_len = this->hashlen;
	buffer rv;
	buffer::prepare prep(rv, result_len);
	uint8_t* out = reinterpret_cast<uint8_t*>(prep.data());

#if (OPENSSL_VERSION_NUMBER < 0x01000000)
	/* Prior to openssl 1.0.0, the HMAC_{Init_ex,Update,Final} returned void. */
	HMAC_Final(&this->ctx, out, &result_len);
#else
	if (!HMAC_Final(&this->ctx, out, &result_len))
		throw std::exception();
#endif

	if (result_len != this->hashlen)
		throw std::runtime_error("result hashlen differs from expected hashlen");

	prep.commit();
	return MOVE(rv);
}


class ILIAS_NET2_LOCAL hash_evp_factory :
	public hash_ctx_factory
{
private:
	const EVP_MD* (*const evp_fn)();

public:
	hash_evp_factory(const EVP_MD*(*evp_fn)(), const std::string& name, size_type hashlen, size_type keylen) ILIAS_NET2_NOTHROW :
		hash_ctx_factory(name, hashlen, keylen),
		evp_fn(evp_fn)
	{
		/* Empty body. */
	}

	virtual std::unique_ptr<hash_ctx> instantiate(const buffer&) const;
};

std::unique_ptr<hash_ctx>
hash_evp_factory::instantiate(const buffer& key) const
{
	const EVP_MD* evp = (*this->evp_fn)();
	if (!evp)
		throw std::bad_alloc();

	if (key.empty())
		throw std::invalid_argument("key required");
	if (key.size() != this->keylen)
		throw std::invalid_argument("invalid key length");

	void* keybuf = alloca(this->keylen);
	key.copyout(keybuf, this->keylen);

	return MOVE(std::unique_ptr<hash_ctx>(new hash_openssl_evp(evp, this->name, this->hashlen, this->keylen, keybuf)));
}


namespace hash {


ILIAS_NET2_LOCAL hash_sha256_factory sha256;
ILIAS_NET2_LOCAL hash_sha384_factory sha384;
ILIAS_NET2_LOCAL hash_sha512_factory sha512;

ILIAS_NET2_LOCAL hash_evp_factory hmac_sha256(EVP_sha256, "HMAC-SHA256", SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH);
ILIAS_NET2_LOCAL hash_evp_factory hmac_sha384(EVP_sha384, "HMAC-SHA384", SHA384_DIGEST_LENGTH, SHA384_DIGEST_LENGTH);
ILIAS_NET2_LOCAL hash_evp_factory hmac_sha512(EVP_sha512, "HMAC-SHA512", SHA512_DIGEST_LENGTH, SHA512_DIGEST_LENGTH);


} /* namespace hash */


} /* namespace ilias */
