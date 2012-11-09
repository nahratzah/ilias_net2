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
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>


namespace ilias {



class ILIAS_NET2_LOCAL hash_sha256 :
	public hash_ctx
{
private:
	CC_SHA256_CTX ctx;

public:
	hash_sha256() :
		hash_ctx("SHA256", CC_SHA256_DIGEST_LENGTH, 0)
	{
		CC_SHA256_Init(&ctx);
	}

	virtual void update(const buffer&);
	virtual buffer final();
};

class ILIAS_NET2_LOCAL hash_sha384 :
	public hash_ctx
{
private:
	CC_SHA512_CTX ctx;

public:
	hash_sha384() :
		hash_ctx("SHA384", CC_SHA384_DIGEST_LENGTH, 0)
	{
		CC_SHA384_Init(&ctx);
	}

	virtual void update(const buffer&);
	virtual buffer final();
};

class ILIAS_NET2_LOCAL hash_sha512 :
	public hash_ctx
{
private:
	CC_SHA512_CTX ctx;

public:
	hash_sha512() :
		hash_ctx("SHA512", CC_SHA512_DIGEST_LENGTH, 0)
	{
		CC_SHA512_Init(&ctx);
	}

	virtual void update(const buffer&);
	virtual buffer final();
};


void
hash_sha256::update(const buffer& b)
{
	b.visit([this](const void* p, buffer::size_type l) {
		CC_SHA256_Update(&ctx, reinterpret_cast<const uint8_t*>(p), l);
	});
}

void
hash_sha384::update(const buffer& b)
{
	b.visit([this](const void* p, buffer::size_type l) {
		CC_SHA384_Update(&ctx, reinterpret_cast<const uint8_t*>(p), l);
	});
}

void
hash_sha512::update(const buffer& b)
{
	b.visit([this](const void* p, buffer::size_type l) {
		CC_SHA512_Update(&ctx, reinterpret_cast<const uint8_t*>(p), l);
	});
}


buffer
hash_sha256::final()
{
	buffer rv;
	buffer::prepare prep(rv, CC_SHA256_DIGEST_LENGTH);
	uint8_t* data = reinterpret_cast<uint8_t*>(prep.data());

	CC_SHA256_Final(data, &ctx);

	prep.commit();
	return rv;
}

buffer
hash_sha384::final()
{
	buffer rv;
	buffer::prepare prep(rv, CC_SHA384_DIGEST_LENGTH);
	uint8_t* data = reinterpret_cast<uint8_t*>(prep.data());

	CC_SHA384_Final(data, &ctx);

	prep.commit();
	return rv;
}

buffer
hash_sha512::final()
{
	buffer rv;
	buffer::prepare prep(rv, CC_SHA512_DIGEST_LENGTH);
	uint8_t* data = reinterpret_cast<uint8_t*>(prep.data());

	CC_SHA512_Final(data, &ctx);

	prep.commit();
	return rv;
}


class ILIAS_NET2_LOCAL hash_sha256_factory :
	public hash_ctx_factory
{
public:
	hash_sha256_factory() :
		hash_ctx_factory("SHA256", CC_SHA256_DIGEST_LENGTH, 0)
	{
		/* Empty body. */
	}

	virtual ~hash_sha256_factory() ILIAS_NET2_NOTHROW;
	virtual std::unique_ptr<hash_ctx> instantiate(buffer) const;
	virtual buffer run(buffer, const buffer&) const;
};

class ILIAS_NET2_LOCAL hash_sha384_factory :
	public hash_ctx_factory
{
public:
	hash_sha384_factory() :
		hash_ctx_factory("SHA384", CC_SHA384_DIGEST_LENGTH, 0)
	{
		/* Empty body. */
	}

	virtual ~hash_sha384_factory() ILIAS_NET2_NOTHROW;
	virtual std::unique_ptr<hash_ctx> instantiate(buffer) const;
	virtual buffer run(buffer, const buffer&) const;
};

class ILIAS_NET2_LOCAL hash_sha512_factory :
	public hash_ctx_factory
{
public:
	hash_sha512_factory() :
		hash_ctx_factory("SHA512", CC_SHA512_DIGEST_LENGTH, 0)
	{
		/* Empty body. */
	}

	virtual ~hash_sha512_factory() ILIAS_NET2_NOTHROW;
	virtual std::unique_ptr<hash_ctx> instantiate(buffer) const;
	virtual buffer run(buffer, const buffer&) const;
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
hash_sha256_factory::instantiate(buffer key) const
{
	if (!key.empty())
		throw std::invalid_argument("expected empty key buffer for un-keyed hash");

	return std::unique_ptr<hash_ctx>(new hash_sha256());
}

std::unique_ptr<hash_ctx>
hash_sha384_factory::instantiate(buffer key) const
{
	if (!key.empty())
		throw std::invalid_argument("expected empty key buffer for un-keyed hash");

	return std::unique_ptr<hash_ctx>(new hash_sha384());
}

std::unique_ptr<hash_ctx>
hash_sha512_factory::instantiate(buffer key) const
{
	if (!key.empty())
		throw std::invalid_argument("expected empty key buffer for un-keyed hash");

	return std::unique_ptr<hash_ctx>(new hash_sha512());
}


buffer
hash_sha256_factory::run(buffer key, const buffer& b) const
{
	if (!key.empty())
		throw std::invalid_argument("expected empty key buffer for un-keyed hash");

	CC_SHA256_CTX ctx;
	buffer rv;
	buffer::prepare prep(rv, CC_SHA256_DIGEST_LENGTH);

	CC_SHA256_Init(&ctx);
	b.visit([&ctx](const void* p, buffer::size_type l) {
		CC_SHA256_Update(&ctx, reinterpret_cast<const uint8_t*>(p), l);
	});
	CC_SHA256_Final(reinterpret_cast<uint8_t*>(prep.data()), &ctx);
	prep.commit();
	return rv;
}

buffer
hash_sha384_factory::run(buffer key, const buffer& b) const
{
	if (!key.empty())
		throw std::invalid_argument("expected empty key buffer for un-keyed hash");

	CC_SHA512_CTX ctx;
	buffer rv;
	buffer::prepare prep(rv, CC_SHA384_DIGEST_LENGTH);

	CC_SHA384_Init(&ctx);
	b.visit([&ctx](const void* p, buffer::size_type l) {
		CC_SHA384_Update(&ctx, reinterpret_cast<const uint8_t*>(p), l);
	});
	CC_SHA384_Final(reinterpret_cast<uint8_t*>(prep.data()), &ctx);
	prep.commit();
	return rv;
}

buffer
hash_sha512_factory::run(buffer key, const buffer& b) const
{
	if (!key.empty())
		throw std::invalid_argument("expected empty key buffer for un-keyed hash");

	CC_SHA512_CTX ctx;
	buffer rv;
	buffer::prepare prep(rv, CC_SHA512_DIGEST_LENGTH);

	CC_SHA512_Init(&ctx);
	b.visit([&ctx](const void* p, buffer::size_type l) {
		CC_SHA512_Update(&ctx, reinterpret_cast<const uint8_t*>(p), l);
	});
	CC_SHA512_Final(reinterpret_cast<uint8_t*>(prep.data()), &ctx);
	prep.commit();
	return rv;
}


class ILIAS_NET2_LOCAL hash_cc_hmac :
	public hash_ctx
{
private:
	CCHmacContext ctx;

public:
	hash_cc_hmac(CCHmacAlgorithm alg, const std::string& name, size_type hashlen, size_type keylen, const void* key);

	virtual void update(const buffer&);
	virtual buffer final();
};


hash_cc_hmac::hash_cc_hmac(CCHmacAlgorithm alg, const std::string& name, size_type hashlen, size_type keylen, const void* key) :
	hash_ctx(name, hashlen, keylen)
{
	CCHmacInit(&ctx, alg, key, keylen);
}

void
hash_cc_hmac::update(const buffer& b)
{
	b.visit([this](const void* p, buffer::size_type l) {
		CCHmacUpdate(&this->ctx, reinterpret_cast<const uint8_t*>(p), l);
	});
}

buffer
hash_cc_hmac::final()
{
	buffer rv;
	buffer::prepare prep(rv, this->hashlen, true);
	CCHmacFinal(&this->ctx, prep.data());
	prep.commit();
	return rv;
}


class ILIAS_NET2_LOCAL hash_cc_hmac_factory :
	public hash_ctx_factory
{
private:
	const CCHmacAlgorithm alg;

public:
	hash_cc_hmac_factory(CCHmacAlgorithm alg, const std::string& name, size_type hashlen, size_type keylen) ILIAS_NET2_NOTHROW :
		hash_ctx_factory(name, hashlen, keylen),
		alg(alg)
	{
		/* Empty body. */
	}

	virtual std::unique_ptr<hash_ctx> instantiate(buffer) const;
};

std::unique_ptr<hash_ctx>
hash_cc_hmac_factory::instantiate(buffer key) const
{
	if (key.empty())
		throw std::invalid_argument("key required");
	if (key.size() != this->keylen)
		throw std::invalid_argument("invalid key length");

	return std::unique_ptr<hash_ctx>(new hash_cc_hmac(this->alg, this->name, this->hashlen, this->keylen, key.pullup()));
}


namespace hash {


ILIAS_NET2_EXPORT const hash_ctx_factory&
sha256()
{
	static const hash_sha256_factory impl;
	return impl;
}
ILIAS_NET2_EXPORT const hash_ctx_factory&
sha384()
{
	static const hash_sha384_factory impl;
	return impl;
}
ILIAS_NET2_EXPORT const hash_ctx_factory&
sha512()
{
	static const hash_sha512_factory impl;
	return impl;
}

ILIAS_NET2_EXPORT const hash_ctx_factory&
hmac_sha256()
{
	static const hash_cc_hmac_factory impl(kCCHmacAlgSHA256, "HMAC-SHA256", CC_SHA256_DIGEST_LENGTH, CC_SHA256_DIGEST_LENGTH);
	return impl;
}
ILIAS_NET2_EXPORT const hash_ctx_factory&
hmac_sha384()
{
	static const hash_cc_hmac_factory impl(kCCHmacAlgSHA384, "HMAC-SHA384", CC_SHA384_DIGEST_LENGTH, CC_SHA384_DIGEST_LENGTH);
	return impl;
}
ILIAS_NET2_EXPORT const hash_ctx_factory&
hmac_sha512()
{
	static const hash_cc_hmac_factory impl(kCCHmacAlgSHA512, "HMAC-SHA512", CC_SHA512_DIGEST_LENGTH, CC_SHA512_DIGEST_LENGTH);
	return impl;
}


}} /* namespace ilias::hash */
