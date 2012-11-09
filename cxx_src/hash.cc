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


namespace ilias {


#ifdef _MSC_VER
#pragma warning( push )
#pragma warning( disable: 4251 )
#endif


hash_ctx::hash_ctx(std::string name, size_type hashlen, size_type keylen) :
	hashlen(hashlen),
	keylen(keylen),
	name(std::move(name))
{
	/* Empty body. */
}

hash_ctx::~hash_ctx() ILIAS_NET2_NOTHROW
{
	return;
}

buffer
hash_ctx_factory::run(buffer key, const buffer& data) const
{
	std::unique_ptr<hash_ctx> instance = this->instantiate(key);
	instance->update(data);
	return instance->final();
}


hash_ctx_factory::hash_ctx_factory(std::string name, size_type hashlen, size_type keylen) :
	hashlen(hashlen),
	keylen(keylen),
	name(std::move(name))
{
	/* Empty body. */
}

hash_ctx_factory::~hash_ctx_factory() ILIAS_NET2_NOTHROW
{
	return;
}


} /* namespace ilias */
