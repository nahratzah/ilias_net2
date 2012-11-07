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
#ifndef ILIAS_NET2_HASH_H
#define ILIAS_NET2_HASH_H

#include <ilias/net2/ilias_net2_export.h>
#include <cstdint>
#include <string>
#include <memory>


#ifdef _MSC_VER
#pragma warning( push )
#pragma warning( disable: 4251 )
#endif


namespace ilias {


class buffer; /* From ilias/net2/buffer.h */

/* Interface to hash functions. */
class ILIAS_NET2_EXPORT hash_ctx
{
public:
	typedef std::size_t size_type;

	const size_type hashlen;
	const size_type keylen;
	const std::string name;

	hash_ctx(const std::string& name, size_type hashlen, size_type keylen) :
		hashlen(hashlen),
		keylen(keylen),
		name(name)
	{
		/* Empty body. */
	}

	virtual ~hash_ctx() ILIAS_NET2_NOTHROW;

	virtual void update(const buffer&) = 0;
	virtual RVALUE(buffer) final() = 0;
};

class ILIAS_NET2_EXPORT hash_ctx_factory
{
public:
	typedef hash_ctx::size_type size_type;

	const size_type hashlen;
	const size_type keylen;
	const std::string name;

	hash_ctx_factory(const std::string& name, size_type hashlen, size_type keylen) :
		hashlen(hashlen),
		keylen(keylen),
		name(name)
	{
		/* Empty body. */
	}

	virtual ~hash_ctx_factory() ILIAS_NET2_NOTHROW;
	virtual std::unique_ptr<hash_ctx> instantiate(const buffer&) const = 0;

	/*
	 * Short-cut for full hash context handling.
	 * Called with key, data.
	 */
	virtual RVALUE(buffer) run(const buffer&, const buffer&) const;
};


} /* namespace ilias */


#ifdef _MSC_VER
#pragma warning( pop )
#endif


#endif /* ILIAS_NET2_HASH_H */
