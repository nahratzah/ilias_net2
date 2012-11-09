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
#define WIN32_NO_STATUS
#include <ilias/net2/hash.h>
#include <ilias/net2/buffer.h>
#undef WIN32_NO_STATUS

#include <ntstatus.h>
#include <bcrypt.h>
#include <array>
#include <atomic>
#include <limits>


namespace ilias {


/*
 * Since the documentation already warns that BCryptOpenAlgorithmProvider()
 * is expensive and slow and recommends caching its values, this is a simple,
 * lock-free cache.
 *
 * While the cache can be changed in size, it is recommended not to make it
 * very large, since the cache lookup is O(n) (where 'n' is the size of the
 * cache).
 *
 * XXX implement a real cache?  This is simply something I came up with in 5 minutes.
 */
class bcrypt_algorithm_cache
{
private:
	static const unsigned long
	m_flag_mask()
	{
		return ~BCRYPT_HASH_REUSABLE_FLAG;
	}

	struct bcrypt_hash_delete {
		void
		operator()(void* algorithm) ILIAS_NET2_NOTHROW
		{
			NTSTATUS rv = BCryptCloseAlgorithmProvider(algorithm, 0);
			assert(rv == STATUS_SUCCESS);
		}
	};

	static const int NEED_INIT = 29;
	static const int ACCEPT_REUSE = 31;
	static const int NO_REUSE = 37;
	static std::atomic<int> accept_reuse;

public:
	typedef std::unique_ptr<void, bcrypt_hash_delete> algorithm;

private:
	typedef std::array<std::atomic<BCRYPT_ALG_HANDLE>, 256> cache_list;

	cache_list m_cache;
	const wchar_t*const m_algorithm;
	const unsigned long m_flags;

	algorithm
	create_new()
	{
		unsigned long fl = this->m_flags;
		bool record = false;
		switch (this->accept_reuse.load(std::memory_order_relaxed)) {
		case ACCEPT_REUSE:
			break;
		case NO_REUSE:
			fl &= ~BCRYPT_HASH_REUSABLE_FLAG;
			break;
		default:
			record = true;
		}

		BCRYPT_ALG_HANDLE handle;
		NTSTATUS open_rv = BCryptOpenAlgorithmProvider(&handle, this->m_algorithm, NULL, fl);
		switch (open_rv) {
		case STATUS_SUCCESS:
			/* Record that reuse is allowed. */
			if (record)
				this->accept_reuse.store(ACCEPT_REUSE, std::memory_order_relaxed);
			break;
		case STATUS_NOT_FOUND:
			throw std::runtime_error("could not find implementation");
		case STATUS_INVALID_PARAMETER:
			if (record) {
				fl &= ~BCRYPT_HASH_REUSABLE_FLAG;
				open_rv = BCryptOpenAlgorithmProvider(&handle, this->m_algorithm, NULL, fl);
				if (open_rv == STATUS_SUCCESS) {
					this->accept_reuse.store(NO_REUSE, std::memory_order_relaxed);
					break;
				}
			}
			throw std::invalid_argument("invalid argument supplied to BCryptOpenAlgorithmProvider function");
		case STATUS_NO_MEMORY:
			throw std::bad_alloc();
		default:
			throw std::runtime_error("failed to initialize algorithm");
		}
		return algorithm(handle);
	}

public:
	bcrypt_algorithm_cache(const wchar_t* alg_name, unsigned long flags) :
		m_algorithm(alg_name),
		m_flags(flags | BCRYPT_HASH_REUSABLE_FLAG)
	{
		/* Initialize cache to empty state. */
		for (cache_list::iterator i = this->m_cache.begin(); i != this->m_cache.end(); ++i)
			i->store(nullptr, std::memory_order_relaxed);
	}

	~bcrypt_algorithm_cache() ILIAS_NET2_NOTHROW
	{
		for (cache_list::iterator i = this->m_cache.begin(); i != this->m_cache.end(); ++i)
			algorithm tmp(i->exchange(nullptr, std::memory_order_consume));
	}

	algorithm
	allocate()
	{
		for (cache_list::iterator i = this->m_cache.begin(); i != this->m_cache.end(); ++i) {
			BCRYPT_ALG_HANDLE rv = i->exchange(nullptr, std::memory_order_consume);
			if (rv != nullptr)
				return std::move(algorithm(rv));
		}
		return create_new();
	}

	void
	deallocate(algorithm&& v)
	{
		if (this->accept_reuse.load(std::memory_order_relaxed) == ACCEPT_REUSE) {
			for (cache_list::iterator i = this->m_cache.begin(); i != this->m_cache.end(); ++i) {
				BCRYPT_ALG_HANDLE expect = nullptr;
				if (i->compare_exchange_strong(expect, v.get(), std::memory_order_release, std::memory_order_relaxed)) {
					v.release();
					return;
				}
			}
		}
		v.reset();
	}


#if HAS_DELETED_FN
	bcrypt_algorithm_cache(const bcrypt_algorithm_cache&) = delete;
	bcrypt_algorithm_cache& operator=(const bcrypt_algorithm_cache&) = delete;
#else
private:
	bcrypt_algorithm_cache(const bcrypt_algorithm_cache&);
	bcrypt_algorithm_cache& operator=(const bcrypt_algorithm_cache&);
#endif
};

std::atomic<int> bcrypt_algorithm_cache::accept_reuse = bcrypt_algorithm_cache::NEED_INIT;


class ILIAS_NET2_LOCAL bcrypt_hash :
	public hash_ctx
{
private:
	struct hash_destructor
	{
		void
		operator()(void* hash) const ILIAS_NET2_NOTHROW
		{
			NTSTATUS rv = BCryptDestroyHash(hash);
			assert(rv == STATUS_SUCCESS);
		}
	};

	typedef std::unique_ptr<void, hash_destructor> hash_handle;	/* BCRYPT_HANDLE_{HASH,HMAC} etc */
	typedef std::pair<std::unique_ptr<uint8_t[]>, unsigned long> hash_storage;

	static hash_handle
	create_hash_handle(const bcrypt_algorithm_cache::algorithm& alg, const hash_storage& store, const void* key, size_type keylen)
	{
		BCRYPT_HASH_HANDLE handle;
		switch (BCryptCreateHash(alg.get(), &handle, store.first.get(), store.second, const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(key)), keylen, 0)) {
		case STATUS_SUCCESS:
			break;
		case STATUS_BUFFER_TOO_SMALL:
			throw std::logic_error("BCryptCreateHash returned STATUS_BUFFER_TOO_SMALL");
		case STATUS_INVALID_HANDLE:
			throw std::logic_error("BCryptCreateHash returned STATUS_INVALID_HANDLE");
		case STATUS_INVALID_PARAMETER:
			throw std::invalid_argument("BCryptCreateHash returned STATUS_INVALID_PARAMETER");
		case STATUS_NOT_SUPPORTED:
			throw std::logic_error("BCryptCreateHash provider does not do hashes...");
		default:
			throw std::runtime_error("BCryptCreateHash returned undocumented error");
		}
		return hash_handle(handle);
	}

	static hash_storage
	create_hash_storage(const bcrypt_algorithm_cache::algorithm& alg)
	{
		ULONG sz;
		ULONG bytesCopied;

		switch (BCryptGetProperty(alg.get(), BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&sz), sizeof(sz), &bytesCopied, 0)) {
		case STATUS_SUCCESS:
			break;
		case STATUS_INVALID_HANDLE:
			throw std::logic_error("BCryptGetProperty returned STATUS_INVALID_HANDLE");
		case STATUS_INVALID_PARAMETER:
			throw std::invalid_argument("BCryptGetProperty returned STATUS_INVALID_PARAMETER");
		case STATUS_NOT_SUPPORTED:
			throw std::logic_error("BCryptGetProperty provider does not do object length...");
		case STATUS_BUFFER_TOO_SMALL:
			throw std::invalid_argument("BCryptGetProperty(BCRYPT_OBJECT_LENGTH) used different length than expected");
		default:
			throw std::runtime_error("BCryptGetProperty returned undocumented error");
		}
		if (bytesCopied != sizeof(sz))
			throw std::invalid_argument("BCryptGetProperty(BCRYPT_OBJECT_LENGTH) used different length than expected");

		std::unique_ptr<uint8_t[]> buffer((sz == 0 ? nullptr : new uint8_t[sz]));
		return hash_storage(std::move(buffer), sz);
	}

	bcrypt_algorithm_cache& m_cache;	/* Algorithm cache, to where succesfully expired hash algorithms go. */
	bcrypt_algorithm_cache::algorithm m_alg; /* Hash algorithm handle. */
	hash_storage m_hash_storage;		/* Storage for hash algorithm. */
	hash_handle m_hash;			/* Handle to hash state. */

public:
	bcrypt_hash(bcrypt_algorithm_cache& cache, const std::string& name, size_type hashlen, const void* key, size_type keylen) :
		hash_ctx(name, hashlen, keylen),
		m_cache(cache)
	{
		this->m_alg = this->m_cache.allocate();
		this->m_hash_storage = create_hash_storage(this->m_alg);
		this->m_hash = create_hash_handle(this->m_alg, this->m_hash_storage, key, keylen);
	}

	virtual ~bcrypt_hash() ILIAS_NET2_NOTHROW;

	virtual void update(const buffer&);
	virtual buffer final();
};


void
bcrypt_hash::update(const buffer& b)
{
	b.visit([this](const void* p, buffer::size_type l) {
		do {
			/*
			 * Probably exagerated: ensure that the actual length inserted in the crypto loop is not truncated.
			 */
#ifdef _MSC_VER
#pragma warning( push )
#pragma warning( disable: 4244 )
#endif
			const unsigned long crypt_len = std::min(l,
			    buffer::size_type(1UL << (std::numeric_limits<unsigned long>::digits - 1)));
#ifdef _MSC_VER
#pragma warning( pop )
#endif

			switch (BCryptHashData(this->m_hash.get(), const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(p)), crypt_len, 0)) {
			case STATUS_SUCCESS:
				break;
			case STATUS_INVALID_PARAMETER:
				throw std::invalid_argument("BCryptHashData didn't like our arguments");
			case STATUS_INVALID_HANDLE:
				throw std::logic_error("BCrypt hash handle appears to be invalid");
			default:
				throw std::runtime_error("BCryptHashData returned undocumented status");
			}

			p = reinterpret_cast<const void*>(reinterpret_cast<uintptr_t>(p) + crypt_len);
			l -= crypt_len;
		} while (l > 0);
	});
}

buffer
bcrypt_hash::final()
{
	buffer rv;
	buffer::prepare prep(rv, this->hashlen, (this->keylen != 0));
	switch (BCryptFinishHash(this->m_hash.get(), reinterpret_cast<uint8_t*>(prep.data()), this->hashlen, 0)) {
	case STATUS_SUCCESS:
		break;
	case STATUS_INVALID_PARAMETER:
		throw std::invalid_argument("BCryptHashData didn't like our arguments");
	case STATUS_INVALID_HANDLE:
		throw std::logic_error("BCrypt hash handle appears to be invalid");
	default:
		throw std::runtime_error("BCryptHashData returned undocumented status");
	}
	prep.commit();

	this->m_hash.reset();
	this->m_cache.deallocate(std::move(this->m_alg));

	return rv;
}

bcrypt_hash::~bcrypt_hash() ILIAS_NET2_NOTHROW
{
	return;
}


class ILIAS_NET2_LOCAL bcrypt_hash_factory :
	public hash_ctx_factory
{
private:
	mutable bcrypt_algorithm_cache m_cache;

public:
	bcrypt_hash_factory(const std::string& alg_name, size_type hashlen, size_type keylen, const wchar_t* bcrypt_alg, unsigned long bcrypt_flags) :
		hash_ctx_factory(alg_name, hashlen, keylen),
		m_cache(bcrypt_alg, bcrypt_flags)
	{
		/* Empty body. */
	}

	virtual ~bcrypt_hash_factory() ILIAS_NET2_NOTHROW;
	virtual std::unique_ptr<hash_ctx> instantiate(const buffer&) const;
};


bcrypt_hash_factory::~bcrypt_hash_factory() ILIAS_NET2_NOTHROW
{
	return;
}

std::unique_ptr<hash_ctx>
bcrypt_hash_factory::instantiate(const buffer& key) const
{
	if (key.size() != this->keylen)
		throw std::invalid_argument(this->name + ": invalid key for hash");
	void* k = alloca(key.size());
	key.copyout(k, key.size());

	return std::unique_ptr<hash_ctx>(new bcrypt_hash(this->m_cache, this->name, this->hashlen, (key.empty() ? nullptr : k), this->keylen));
}


namespace hash {


ILIAS_NET2_EXPORT const hash_ctx_factory&
sha256()
{
	static const bcrypt_hash_factory impl("SHA256", 256 / 8, 0,
	    BCRYPT_SHA256_ALGORITHM, 0);
	return impl;
}
ILIAS_NET2_EXPORT const hash_ctx_factory&
sha384()
{
	static const bcrypt_hash_factory impl("SHA384", 384 / 8, 0,
	    BCRYPT_SHA384_ALGORITHM, 0);
	return impl;
}
ILIAS_NET2_EXPORT const hash_ctx_factory&
sha512()
{
	static const bcrypt_hash_factory impl("SHA512", 512 / 8, 0,
	    BCRYPT_SHA512_ALGORITHM, 0);
	return impl;
}

ILIAS_NET2_EXPORT const hash_ctx_factory&
hmac_sha256()
{
	static const bcrypt_hash_factory impl("HMAC-SHA256", 256 / 8, 256 / 8,
	    BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	return impl;
}
ILIAS_NET2_EXPORT const hash_ctx_factory&
hmac_sha384()
{
	static const bcrypt_hash_factory impl("HMAC-SHA384", 384 / 8, 384 / 8,
	    BCRYPT_SHA384_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	return impl;
}
ILIAS_NET2_EXPORT const hash_ctx_factory&
hmac_sha512()
{
	static const bcrypt_hash_factory impl("HMAC-SHA512", 512 / 8, 512 / 8,
	    BCRYPT_SHA512_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	return impl;
}


}} /* namespace ilias::hash */
