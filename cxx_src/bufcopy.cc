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
#include <ilias/net2/buffer.h>
#include <cstring>
#include <limits>


namespace ilias {
namespace {


using std::uintptr_t;
using std::size_t;
using std::uint8_t;
using std::memcmp;

#if defined(__GNUC__) || defined(__clang__)
typedef uintptr_t __attribute__((aligned(sizeof(uintptr_t)))) word_t;
#else
typedef uintptr_t word_t;
#endif

constexpr_value size_t BYTES = sizeof(word_t);
constexpr_value size_t BPP = std::numeric_limits<word_t>::digits / BYTES;
constexpr_value size_t BITS = BYTES * BPP;
constexpr_value uintptr_t ADDR_MASK = (BYTES - 1);
constexpr_value uintptr_t PREFETCH = 8 * BYTES;

inline constexpr word_t
mask(size_t high, size_t low = 0) ILIAS_NET2_NOTHROW
{
	return (high == BITS ? ~mask(low) : ((word_t(1) << high) - (word_t(1) << low)));
}

inline word_t
fifo_merge(word_t& in, word_t& next, const word_t& merge, size_t bytes)
{
	const uintptr_t bits = BPP * bytes;

	const word_t out = in;
	in = next;
	if (bytes == 0) {
		next = merge;
		return out;
	}
	next = 0;

#ifdef IS_BIG_ENDIAN
	assert((in & mask(BITS, bits)) == in);
	in |= merge >> (BITS - bits);
	next = merge << bits;
#else /* Little endian. */
	assert((in & mask(BITS - bits)) == in);
	in |= merge << (BITS - bits);
	next = merge >> bits;
#endif

	return out;
}

inline word_t
fifo_bytes(word_t& in, word_t& next, size_t bytes) ILIAS_NET2_NOTHROW
{
	if (bytes == 0)
		return 0;

	const uintptr_t bits = BPP * bytes;
#if IS_BIG_ENDIAN
	const word_t out = in & mask(BITS, bits);
	in <<= bits;
	in |= next >> (BITS - bits);
	next <<= bits;
#else /* Little endian. */
	const word_t out = in & mask(bits);
	in >>= bits;
	in |= next << (BITS - bits);
	next >>= bits;
#endif

	return out;
}

inline uint8_t
fifo_byte(word_t& in, word_t& next) ILIAS_NET2_NOTHROW
{
#ifndef NDEBUG
	const uint8_t expect = *reinterpret_cast<const uint8_t*>(&in);
#endif

	const word_t tmp = fifo_bytes(in, next, 1);
#if IS_BIG_ENDIAN
	const word_t out = tmp >> (BITS - BPP);
#else
	const word_t out = tmp & mask(BPP);
#endif

	assert(out == expect);
	return out;
}

template<typename T>
inline uintptr_t
int_addr(const T* ptr) ILIAS_NET2_NOTHROW
{
	return reinterpret_cast<uintptr_t>(ptr);
}

inline constexpr uintptr_t
apply_addr_mask(uintptr_t addr) ILIAS_NET2_NOTHROW
{
	return addr & ~ADDR_MASK;
}

inline uintptr_t
apply_addr_mask(const void* addr) ILIAS_NET2_NOTHROW
{
	return apply_addr_mask(reinterpret_cast<uintptr_t>(addr));
}

/*
 * Prefetch for read, minimum locality (so the cache will evict it in favour
 * of other data).
 */
template<typename T>
inline void
prefetch_r(const T* addr)
{
#if defined(__GNUC__) || defined(__clang__)
	__builtin_prefetch(addr, 0, 0);
#elif defined(_MSC_VER)
	_mm_prefetch(addr, _MM_HINT_NTA);
#else
	/* No prefetching. */
#endif
}

/*
 * Prefetch for write, minimum locality (so the cache will evict it in favour
 * of other data).
 */
template<typename T>
inline void
prefetch_w(T* addr)
{
#if defined(__GNUC__) || defined(__clang__)
	__builtin_prefetch(addr, 1, 0);
#elif defined(_MSC_VER)
	_mm_prefetch(addr, _MM_HINT_NTA);
#else
	/* No prefetching. */
#endif
}

inline void
cp(void*const dst0, const void*const src0, const size_t len0) ILIAS_NET2_NOTHROW
{
	/* First unread byte. */
	const word_t	*src = reinterpret_cast<word_t*>(apply_addr_mask(src0));
	/* First unwritten byte. */
	uint8_t		*dst = reinterpret_cast<uint8_t*>(dst0);

	const size_t outshift = (BYTES - int_addr(dst)) & ADDR_MASK;
	size_t shift = outshift + (int_addr(src) & ADDR_MASK);

	/*
	 * For input, we use an aligned pointer and
	 * shift away the bits we don't want to copy.
	 * This is technically breaking the C/C++ standard,
	 * since we're reading outside the supplied memory.
	 * In practise this is safe on all architectures,
	 * since we stay within the same memory page.
	 */

	/* First word in input buffer. */
	word_t in = src[0];
	/* Second word in input buffer. */
	word_t next = src[1];
	/* Shift bytes we are not to copy out of input buffer. */
	fifo_bytes(in, next, int_addr(src0) & ADDR_MASK);

	/* Algorithm verification. */
	assert(memcmp(&in, src0, BYTES) == 0);

	/* Align dst, by copying out single bytes. */
	size_t out_len = len0;
	for (size_t i = outshift; i > 0; --i) {
		if (out_len == 0) {
			/* Reached the end of the copy... */
			assert(int_addr(dst) == int_addr(dst0) + len0);
			assert(memcmp(src0, dst0, len0) == 0);
			return;
		}
		--out_len;
		*dst++ = fifo_byte(in, next);
	}

	/* If shift is too large, now we can fix it. */
	if (shift >= BYTES) {
		in = src[0];
		next = src[1];
		src++;
		shift -= BYTES;
		fifo_bytes(in, next, shift);
		fifo_merge(in, next, src[1], shift);
	}

	/* Validate algorithm so far... */
	assert((int_addr(src) & ADDR_MASK) == 0);
	assert((int_addr(dst) & ADDR_MASK) == 0);
	assert(memcmp(dst0, src0, outshift) == 0);

	/* Copy from in to out. */
	for (size_t j = out_len / BYTES; j > 0; --j) {
		/* Assert loop invariant. */
		assert(memcmp(dst0, src0, len0 - j * BYTES - out_len % BYTES) == 0);

		src++;
		assert(int_addr(src) < int_addr(src0) + len0);

		/*
		 * Prefetch a few bytes ahead of our position, so the
		 * cache can fill while we work.
		 */
		if (j > PREFETCH / BYTES) {
			assert(int_addr(src) + PREFETCH < int_addr(src0) + len0);
			prefetch_r(src + PREFETCH / BYTES);
			assert(int_addr(dst) + PREFETCH < int_addr(dst0) + len0);
			prefetch_w(dst + PREFETCH);
		}

		*reinterpret_cast<word_t*>(dst) = fifo_merge(in, next, src[1], shift);
		dst += BYTES;
	}
	assert(out_len &= ADDR_MASK);
	assert(memcmp(dst0, src0, len0 - out_len) == 0);

	/* Copy remaining (unaligned length) bytes to dst. */
	while (out_len > 0) {
		*dst++ = fifo_byte(in, next);
		--out_len;
	}

	/* Complete, validate result. */
	assert(int_addr(dst) == int_addr(dst0) + len0);
	assert(memcmp(dst0, src0, len0) == 0);
}


} /* namespace ilias::[unnamed namespace] */


void
buffer::copy_memory(void* dst, const void* src, size_type len) ILIAS_NET2_NOTHROW
{
	cp(dst, src, len);
}


void
buffer::zero_memory(void* dst, size_type len0) ILIAS_NET2_NOTHROW
{
	std::uintptr_t addr = int_addr(dst);
	size_type len = len0;

	/* Zero non-aligned memory per byte, until we reach alignment. */
	if (addr & ADDR_MASK) {
		prefetch_w(reinterpret_cast<void*>(apply_addr_mask(dst)));

		/* Byte pointer at which we are zeroing. */
		std::uint8_t* byte = reinterpret_cast<std::uint8_t*>(addr);
		/* Length of bytes to be zeroed. */
		size_type i = std::min(len, ADDR_MASK - (addr & ADDR_MASK));
		len -= i;

		while (i-- > 0)
			*byte++ = 0;
		addr = int_addr(byte);
	}

	/* Invariant check. */
	assert(addr + len == int_addr(dst) + len0);
	assert((addr & ADDR_MASK) == 0 || len == 0);

	/* Zero aligned memory per word. */
	if (len >= BYTES) {
		/* Word pointer at which we are zeroing. */
		word_t* word = reinterpret_cast<word_t*>(addr);
		/* # of words to be zeroed. */
		size_type i = len / BYTES;
		len %= BYTES;

		while (i-- > 0) {
			prefetch_w(word);
			*word++ = 0;
		}
		addr = int_addr(word);
	}

	/* Invariant check. */
	assert(addr + len == int_addr(dst) + len0);
	assert((addr & ADDR_MASK) == 0 || len == 0);
	assert(len < BYTES);

	/* Zero any remaining bytes. */
	if (len > 0) {
		std::uint8_t* byte = reinterpret_cast<std::uint8_t*>(addr);
		prefetch_w(byte);

		size_type i = len;
		while (i-- > 0)
			*byte++ = 0;
		addr = int_addr(byte);
	}

	/* Invariant check. */
	assert(addr + len == int_addr(dst) + len0);
	assert(len == 0);

	/* Post-condition check. */
#ifndef NDEBUG
	for (std::uint8_t* p = reinterpret_cast<std::uint8_t*>(dst);
	    p != reinterpret_cast<uint8_t*>(dst) + len0;
	    ++p)
		assert(*p == 0);
#endif
}


} /* namespace ilias */
