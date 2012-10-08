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
#include <ilias/net2/promise.h>
#include <cassert>
#include <cerrno>

namespace ilias {


void
do_promise_deref_exception(struct net2_promise *p, int fin, uint32_t err)
    throw (promise_deref_error)
{
	if (p == NULL)
		throw promise_deref_noinit_error();

	switch (fin) {
	case NET2_PROM_FIN_UNFINISHED:
		throw promise_unfinished();
	case NET2_PROM_FIN_OK:
		return;
	case NET2_PROM_FIN_CANCEL:
		throw promise_canceled();
	case NET2_PROM_FIN_ERROR:
		throw promise_finerr_error(err);
	case NET2_PROM_FIN_UNREF:
		throw promise_unref_error();
	case NET2_PROM_FIN_FAIL:
		throw promise_fail_error();
	default:
		throw promise_deref_error();	/* Don't have anything more specific. */
	}

	/* UNREACHABLE */
	assert(0);
}

void
do_promise_fin_exception(struct net2_promise *p, int err)
    throw (std::bad_alloc, std::invalid_argument, promise_fin_error)
{
	if (p == NULL)
		throw promise_fin_noinit_error();

	switch (err) {
	case EINVAL:
		if (!net2_promise_is_finished(p))
			throw std::invalid_argument("promise finalization");
		throw promise_fin_twice_error();
	case ENOMEM:
		throw std::bad_alloc();
	}
}


promise_error::~promise_error() throw ()
{
	return;
}
const char*
promise_error::what() const throw ()
{
	return "ilias::promise error";
}

promise_noinit_error::~promise_noinit_error() throw ()
{
	return;
}
const char*
promise_noinit_error::what() const throw ()
{
	return "ilias::promise uninitalized";
}

promise_deref_error::~promise_deref_error() throw ()
{
	return;
}
const char*
promise_deref_error::what() const throw ()
{
	return "ilias::promise null dereference";
}

promise_deref_noinit_error::~promise_deref_noinit_error() throw ()
{
	return;
}
const char*
promise_deref_noinit_error::what() const throw ()
{
	return "ilias::promise unreferenced without initialization";
}

promise_canceled::~promise_canceled() throw ()
{
	return;
}
const char*
promise_canceled::what() const throw ()
{
	return "ilias::promise canceled";
}

promise_unfinished::~promise_unfinished() throw ()
{
	return;
}
const char*
promise_unfinished::what() const throw ()
{
	return "ilias::promise unfinished";
}

promise_finerr_error::~promise_finerr_error() throw ()
{
	return;
}
const char*
promise_finerr_error::what() const throw ()
{
	return "ilias::promise completed with error";
}

promise_unref_error::~promise_unref_error() throw ()
{
	return;
}
const char*
promise_unref_error::what() const throw ()
{
	return "ilias::promise unreferenced before completion";
}

promise_fail_error::~promise_fail_error() throw ()
{
	return;
}
const char*
promise_fail_error::what() const throw ()
{
	return "ilias::promise failed to execute";
}

promise_fin_error::~promise_fin_error() throw ()
{
	return;
}
const char*
promise_fin_error::what() const throw ()
{
	return "ilias::promise assign finish error";
}

promise_fin_twice_error::~promise_fin_twice_error() throw ()
{
	return;
}
const char*
promise_fin_twice_error::what() const throw ()
{
	return "ilias::promise already finished";
}

promise_fin_noinit_error::~promise_fin_noinit_error() throw ()
{
	return;
}
const char*
promise_fin_noinit_error::what() const throw ()
{
	return "ilias::promise uninitialized while setting final state";
}


} /* namespace ilias */
