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


bool
basic_future::ready() const ILIAS_NET2_NOTHROW
{
	basic_state*const s = this->get_state();
	return (s && s->ready());
}

bool
basic_future::has_exception() const ILIAS_NET2_NOTHROW
{
	basic_state*const s = this->get_state();
	return (s && s->has_exception());
}


basic_promise::~basic_promise() ILIAS_NET2_NOTHROW
{
	return;
}


basic_promise::basic_state::basic_state() ILIAS_NET2_NOTHROW :
	m_ready(NIL),
	m_prom_refcnt(0)
{
	/* Empty body. */
}

basic_promise::basic_state::~basic_state() ILIAS_NET2_NOTHROW
{
	return;
}

/*
 * Mark the promise as to-be-executing.
 * Returns true if the state changed from not-started to started.
 */
bool
basic_promise::basic_state::start(bool) ILIAS_NET2_NOTHROW
{
	return !this->m_start.exchange(true, std::memory_order_relaxed);
}

/*
 * Mark promise as completed and notify anything waiting for it.
 */
void
basic_promise::basic_state::on_assign() ILIAS_NET2_NOTHROW
{
	return;
}

bool
basic_promise::basic_state::has_lazy() const ILIAS_NET2_NOTHROW
{
	return false;
}


namespace {

/*
 * Pre-allocated broken promise, so we can destroy without throwing an exception.
 */
const std::exception_ptr unref = std::make_exception_ptr(broken_promise());

} /* namespace ilias::<unnamed> */

void
basic_promise::mark_unreferenced::unreferenced(basic_state& s) const ILIAS_NET2_NOTHROW
{
	assert(s.m_prom_refcnt.load(std::memory_order_acquire) == 0);

	s.set_exception(unref);
	refcnt_release(s);
}


broken_promise::broken_promise() :
	std::runtime_error("broken promise: destroyed without setting a value")
{
	return;
}

broken_promise::~broken_promise() ILIAS_NET2_NOTHROW
{
	return;
}


void
uninitialized_promise::throw_me()
{
	throw uninitialized_promise();
}

uninitialized_promise::uninitialized_promise() :
	std::logic_error("uninitialized promise")
{
	return;
}

uninitialized_promise::~uninitialized_promise() ILIAS_NET2_NOTHROW
{
	return;
}


} /* namespace ilias */
