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
#ifndef ILIAS_NET2_BOOLTEST_H
#define ILIAS_NET2_BOOLTEST_H

#include <ilias/net2/ilias_net2_export.h>

#if !HAS_EXPL_OP_BOOL
class bool_test_base
{
protected:
	typedef void (bool_test_base::*bool_type)() const;
	void this_type_does_not_support_comparisons() const {};
	bool_type msvc_compiler_is_annoying_the_heck_out_of_me() const ILIAS_NET2_NOTHROW { return &bool_test_base::this_type_does_not_support_comparisons; }

	bool_test_base() ILIAS_NET2_NOTHROW {}
	bool_test_base(const bool_test_base&) ILIAS_NET2_NOTHROW {}
	bool_test_base& operator=(const bool_test_base&) ILIAS_NET2_NOTHROW { return *this; }
	~bool_test_base() ILIAS_NET2_NOTHROW {}
};
#endif

template<typename Derived = void>
class bool_test
#if !HAS_EXPL_OP_BOOL
:	public bool_test_base
#endif
{
public:
#if HAS_EXPL_OP_BOOL
	explicit operator bool() const ILIAS_NET2_NOTHROW
	{
		return static_cast<const Derived&>(*this).booltest();
	}
#else
	operator bool_type() const ILIAS_NET2_NOTHROW
	{
		return (static_cast<const Derived&>(*this).booltest() ?
		    this->msvc_compiler_is_annoying_the_heck_out_of_me() :
		    nullptr);
	}
#endif

protected:
	~bool_test() ILIAS_NET2_NOTHROW {}
};

template<>
class bool_test<void>
#if !HAS_EXPL_OP_BOOL
:	public bool_test_base
#endif
{
private:
	virtual bool booltest() const ILIAS_NET2_NOTHROW = 0;

public:
#if HAS_EXPL_OP_BOOL
	explicit operator bool() const ILIAS_NET2_NOTHROW
	{
		return this->booltest();
	}
#else
	operator bool_type() const ILIAS_NET2_NOTHROW
	{
		return (this->booltest() ?
		    this->msvc_compiler_is_annoying_the_heck_out_of_me() :
		    nullptr);
	}
#endif

protected:
	~bool_test() ILIAS_NET2_NOTHROW {}
};

#endif /* ILIAS_NET2_BOOLTEST_H */
