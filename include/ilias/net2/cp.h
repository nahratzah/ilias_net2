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
#ifndef ILIAS_NET2_CP_H
#define ILIAS_NET2_CP_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/types.h>
#include <ilias/net2/buffer.h>
#include <cstdint>
#include <string>
#ifdef HAVE_TYPE_TRAITS
#include <type_traits>
#endif


namespace ilias {


class encdec_ctx;


/*
 * Interface for encoding/decoding.
 *
 * Can be specialized and/or implemented by types.
 */
template<typename T>
struct cp_encdec
{
	typedef T value_type;
	typedef value_type& reference;
	typedef const value_type& const_reference;
	typedef value_type* pointer;
	typedef const value_type* const_pointer;
	typedef RVALUE(value_type) result_type;

	static void encode(encdec_ctx&, buffer&, const_reference);
	static result_type decode(encdec_ctx&, buffer&);
};


namespace endian_detail {


#ifdef BIG_ENDIAN
template<typename T>
T
big_endian(const T& v) ILIAS_NET2_NOTHROW
{
	return v;
}
template<typename T>
T
host_endian(const T& v) ILIAS_NET2_NOTHROW
{
	return v;
}
#else
/* Assuming little endian. */

template<typename T, int B = 0, bool Stop = 2 * B + 1 >= sizeof(T)>
struct endian_helper
{
private:
	static constexpr unsigned int byte_digits = std::numeric_limits<uint8_t>::digits;
	static constexpr unsigned int t_digits = std::numeric_limits<T>::digits;
	/* Mask the lowest byte in T. */
	static constexpr T mask_byte = ((T(1) << byte_digits) - 1);

	/* Mask the low byte we want to swap. */
	static constexpr T low_mask = (mask_byte << (B * byte_digits));
	/* Mask the high byte we want to swap. */
	static constexpr T high_mask = (mask_byte << (t_digits - byte_digits - B * byte_digits));
	/* Mask for the bits we do nothing with. */
	static constexpr T not_mask = ~(low_mask | high_mask);

	/* Calculate how far both parts need to be shifted. */
	static constexpr unsigned int distance = t_digits - byte_digits - 2 * byte_digits * B;

	/* Flip the byte B in T from byte order. */
	static constexpr T
	flip(T v) ILIAS_NET2_NOTHROW
	{
		return ((v & low_mask) << distance) | ((v & high_mask) >> distance) | (v & not_mask);
	}

public:
	/* Recursively flip the byte order in T. */
	static constexpr T
	flip_endian(T v) ILIAS_NET2_NOTHROW
	{
		return endian_helper<T, B + 1>::flip_endian(flip(v));
	}
};

template<typename T, int B>
struct endian_helper<T, B, true>
{
public:
	/* Byte B cannot be flipped, therefore this is the identity operation. */
	static constexpr T
	flip_endian(T v) ILIAS_NET2_NOTHROW
	{
		return v;
	}
};

template<typename T>
T
big_endian(const T& v)
{
	return endian_helper<T>::flip_endian(v);
}
template<typename T>
T
host_endian(const T& v)
{
	return endian_helper<T>::flip_endian(v);
}
#endif


/*
 * Wrt two's complement, we assume your platform uses it.
 * The functions in this namespace will allow for abstraction should a platform be found that doesn't do this.
 */

/* Encode signed value v as two's complement value. */
template<typename T>
typename std::make_unsigned<T>::type
net_two_compl(const typename std::make_signed<T>::type& v)
{
	return reinterpret_cast<const typename std::make_unsigned<T>::type&>(v);
}
template<typename T>
typename std::make_signed<T>::type
host_two_compl(const typename std::make_unsigned<T>::type& v)
{
	return reinterpret_cast<const typename std::make_signed<T>::type&>(v);
}


} /* namespace ilias::endian_detail */


template<>
inline void
cp_encdec<std::uint8_t>::encode(encdec_ctx& ectx, buffer& out, const std::uint8_t& value)
{
	using namespace endian_detail;

	out.append_literal(value);
}
template<>
inline RVALUE(std::uint8_t)
cp_encdec<std::uint8_t>::decode(encdec_ctx& ectx, buffer& in)
{
	using namespace endian_detail;

	return MOVE(in.drain_literal<uint8_t>());
}

template<>
inline void
cp_encdec<std::uint16_t>::encode(encdec_ctx& ectx, buffer& out, const std::uint16_t& value)
{
	using namespace endian_detail;

	out.append_literal(big_endian(value));
}
template<>
inline RVALUE(std::uint16_t)
cp_encdec<std::uint16_t>::decode(encdec_ctx& ectx, buffer& in)
{
	using namespace endian_detail;

	return MOVE(host_endian(in.drain_literal<std::uint16_t>()));
}

template<>
inline void
cp_encdec<std::uint32_t>::encode(encdec_ctx& ectx, buffer& out, const std::uint32_t& value)
{
	using namespace endian_detail;

	out.append_literal(big_endian(value));
}
template<>
inline RVALUE(std::uint32_t)
cp_encdec<std::uint32_t>::decode(encdec_ctx& ectx, buffer& in)
{
	using namespace endian_detail;

	return MOVE(host_endian(in.drain_literal<std::uint32_t>()));
}

template<>
inline void
cp_encdec<std::uint64_t>::encode(encdec_ctx& ectx, buffer& out, const std::uint64_t& value)
{
	using namespace endian_detail;

	out.append_literal(big_endian(value));
}
template<>
inline RVALUE(std::uint64_t)
cp_encdec<std::uint64_t>::decode(encdec_ctx& ectx, buffer& in)
{
	using namespace endian_detail;

	return MOVE(host_endian(in.drain_literal<std::uint64_t>()));
}


template<>
inline void
cp_encdec<std::int8_t>::encode(encdec_ctx& ectx, buffer& out, const std::int8_t& value)
{
	using namespace endian_detail;

	cp_encdec<std::uint8_t>::encode(ectx, out, net_two_compl<std::uint8_t>(value));
}
template<>
inline RVALUE(std::int8_t)
cp_encdec<std::int8_t>::decode(encdec_ctx& ectx, buffer& in)
{
	using namespace endian_detail;

	return MOVE(host_two_compl<std::uint8_t>(cp_encdec<std::uint8_t>::decode(ectx, in)));
}

template<>
inline void
cp_encdec<std::int16_t>::encode(encdec_ctx& ectx, buffer& out, const std::int16_t& value)
{
	using namespace endian_detail;

	cp_encdec<std::uint16_t>::encode(ectx, out, net_two_compl<std::uint16_t>(value));
}
template<>
inline RVALUE(std::int16_t)
cp_encdec<std::int16_t>::decode(encdec_ctx& ectx, buffer& in)
{
	using namespace endian_detail;

	return MOVE(host_two_compl<std::uint16_t>(cp_encdec<std::uint16_t>::decode(ectx, in)));
}

template<>
inline void
cp_encdec<std::int32_t>::encode(encdec_ctx& ectx, buffer& out, const std::int32_t& value)
{
	using namespace endian_detail;

	cp_encdec<std::uint32_t>::encode(ectx, out, net_two_compl<std::uint32_t>(value));
}
template<>
inline RVALUE(std::int32_t)
cp_encdec<std::int32_t>::decode(encdec_ctx& ectx, buffer& in)
{
	using namespace endian_detail;

	return MOVE(host_two_compl<std::uint32_t>(cp_encdec<std::uint32_t>::decode(ectx, in)));
}

template<>
inline void
cp_encdec<std::int64_t>::encode(encdec_ctx& ectx, buffer& out, const std::int64_t& value)
{
	using namespace endian_detail;

	cp_encdec<std::uint64_t>::encode(ectx, out, net_two_compl<std::uint64_t>(value));
}
template<>
inline RVALUE(std::int64_t)
cp_encdec<std::int64_t>::decode(encdec_ctx& ectx, buffer& in)
{
	using namespace endian_detail;

	return MOVE(host_two_compl<std::uint64_t>(cp_encdec<std::uint64_t>::decode(ectx, in)));
}

template<>
ILIAS_NET2_EXPORT void
cp_encdec<std::string>::encode(encdec_ctx& ectx, buffer& out, const std::string& value);
template<>
ILIAS_NET2_EXPORT RVALUE(std::string)
cp_encdec<std::string>::decode(encdec_ctx& ectx, buffer& in);

template<>
ILIAS_NET2_EXPORT void
cp_encdec<buffer>::encode(encdec_ctx& ectx, buffer& out, const buffer& value);
template<>
ILIAS_NET2_EXPORT RVALUE(buffer)
cp_encdec<buffer>::decode(encdec_ctx& ectx, buffer& in);

extern template void cp_encdec<std::string>::encode(encdec_ctx& ectx, buffer& out, const std::string& value);
extern template RVALUE(std::string) cp_encdec<std::string>::decode(encdec_ctx& ectx, buffer& in);

extern template void cp_encdec<buffer>::encode(encdec_ctx& ectx, buffer& out, const buffer& value);
extern template RVALUE(buffer) cp_encdec<buffer>::decode(encdec_ctx& ectx, buffer& in);


} /* namespace ilias */

#endif /* ILIAS_NET2_CP_H */
