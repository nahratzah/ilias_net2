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

#include <ilias/net2/cp.h>


namespace ilias {
namespace buf_encode {

static CONSTEXPR_VALUE std::size_t buf_padding = 8;	/* ABI: Ensure strings and bufs always use a multiple of 8 bytes of space. */
typedef std::uint32_t buf_len_indicator;	/* ABI: Type used to indicate buf/string length. */

/* Calculate how much padding is required. */
inline CONSTEXPR buf_len_indicator
buf_padding_length(buf_len_indicator len)
{
	/*
	 * (x - 1) % y + 1  makes the modulo round up to y instead of down to 0.
	 * Which makes  y - ((x - 1) % y + 1)  able to reach 0 instead of y.
	 *
	 * Below is what happens if you optimize it for constant folding.
	 */
	return (buf_padding - 1) - (sizeof(buf_len_indicator) - 1 + len) % buf_padding;
}

} /* namespace ilias::buf_encode */

template<>
void
cp_encdec<std::string>::encode(encdec_ctx& ectx, buffer& out, const std::string& value)
{
	using namespace buf_encode;

	if (value.length() > std::numeric_limits<buf_len_indicator>::max())
		throw std::length_error("string is too large to be encoded");
	const buf_len_indicator len = buf_len_indicator(value.length());

	char pad[buf_padding];
	std::for_each(&pad[0], &pad[buf_padding], [](char& v) { v = '\0'; });

	/* Encode string length. */
	cp_encdec<buf_len_indicator>::encode(ectx, out, len);
	/* Encode string payload. */
	out.append(reinterpret_cast<const void*>(value.data()), len);
	/* Pad until the combination is a multiple of buf_padding. */
	out.append(reinterpret_cast<const void*>(&pad[0]), buf_padding_length(len));
}
template<>
std::string
cp_encdec<std::string>::decode(encdec_ctx& ectx, buffer& in)
{
	using namespace buf_encode;

	const buf_len_indicator len = cp_encdec<buf_len_indicator>::decode(ectx, in);
	const buf_len_indicator padding = buf_padding_length(len);

	/* Read string from buffer, using the visitor pattern. */
	std::string rv;
	in.visit([&rv](const void* p, buffer::size_type l) {
		const char* b = reinterpret_cast<const char*>(p);
		rv.append(b, l);
	});

	/* Visitor doesn't drain, so we must do so here. */
	in.drain(len + padding);

	return rv;
}

template<>
void
cp_encdec<buffer>::encode(encdec_ctx& ectx, buffer& out, const buffer& value)
{
	using namespace buf_encode;

	/* Ensure this will fit. */
	if (value.size() > std::numeric_limits<buf_len_indicator>::max())
		throw std::length_error("buffer is too large to be encoded");
	const buf_len_indicator len = buf_len_indicator(value.size());

	char pad[buf_padding];
	std::for_each(&pad[0], &pad[buf_padding], [](char& v) { v = '\0'; });

	/* Encode buffer length. */
	cp_encdec<buf_len_indicator>::encode(ectx, out, len);
	/* Encode buffer payload. */
	out += value;
	/* Pad until the combination is a multiple of buf_padding. */
	out.append(reinterpret_cast<const void*>(&pad[0]), buf_padding_length(len));
}
template<>
buffer
cp_encdec<buffer>::decode(encdec_ctx& ectx, buffer& in)
{
	using namespace buf_encode;

	const buf_len_indicator len = cp_encdec<buf_len_indicator>::decode(ectx, in);
	const buf_len_indicator padding = buf_padding_length(len);

	/* Read string from buffer, using the visitor pattern. */
	buffer rv = in.subrange(0, len);
	/* buffer::subrange doesn't drain, so we must do so here. */
	in.drain(len + padding);

	return rv;
}

template struct cp_encdec<std::string>;
template struct cp_encdec<buffer>;


} /* namespace ilias */
