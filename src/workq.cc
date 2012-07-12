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
#include <ilias/net2/workq.h>


namespace ilias {


void
workq_sync::do_error(int error) throw (std::bad_alloc, workq_sync_error)
{
	switch (error) {
	case 0:
		/* No error. */
		break;
	default:
		throw std::exception();
	case EINVAL:
		throw std::invalid_argument("workq");
	case EINTR:
		throw workq_sync_tryfail();
	case EDEADLK:
		throw workq_sync_self();
	case ENOMEM:
		throw std::bad_alloc();
	}
}


workq_sync_error::~workq_sync_error() throw ()
{
	return;
}
const char*
workq_sync_error::what() const throw ()
{
	return "workq_sync failed";
}

workq_sync_self::~workq_sync_self() throw ()
{
	return;
}
const char*
workq_sync_self::what() const throw ()
{
	return "workq_sync failed: code is executed inside workq";
}

workq_sync_tryfail::~workq_sync_tryfail() throw ()
{
	return;
}
const char*
workq_sync_tryfail::what() const throw ()
{
	return "workq_sync failed: busy trylock";
}


} /* namespace ilias */
