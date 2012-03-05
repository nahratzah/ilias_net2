/*
 * Copyright (c) 2011, 2012 Ariane van der Steldt <ariane@stack.nl>
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
#include <ilias/net2/bsd_compat/error.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifdef WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

/* Use a buffer on the stack for creating msg strings. */
#define ERROR_BUFFER	1024

/*
 * What good are standards if you can't violate them.
 * Some window malarky below.
 */
#ifdef WIN32
#define snprintf	_snprintf
#define strdup		_strdup
#define write		_write
#endif /* WIN32 */

static char*
make_message(const char *fmt, int use_errno, va_list ap)
{
	char	 fmt_msg[ERROR_BUFFER];
	char	 msg[ERROR_BUFFER];

	if (vsnprintf(fmt_msg, sizeof(fmt_msg), fmt, ap) == -1)
		return NULL;
	if (use_errno == 0)
		return strdup(fmt_msg);

	if (snprintf(msg, sizeof(msg), "%s: %s", fmt_msg, strerror(errno)) ==
	    -1)
		return NULL;
	return strdup(msg);
}


static error_handler_t	error_handler = 0;
static warn_handler_t	warn_handler = 0;
static info_handler_t	info_handler = 0;
static debug_handler_t	debug_handler = 0;

ILIAS_NET2_EXPORT error_handler_t
set_error_handler(error_handler_t new_handler)
{
	error_handler_t old = error_handler;
	error_handler = new_handler;
	return old;
}

ILIAS_NET2_EXPORT warn_handler_t
set_warn_handler(warn_handler_t new_handler)
{
	warn_handler_t old = warn_handler;
	warn_handler = new_handler;
	return old;
}

ILIAS_NET2_EXPORT info_handler_t
set_info_handler(info_handler_t new_handler)
{
	info_handler_t old = info_handler;
	info_handler = new_handler;
	return old;
}

ILIAS_NET2_EXPORT debug_handler_t
set_debug_handler(debug_handler_t new_handler)
{
	debug_handler_t old = debug_handler;
	debug_handler = new_handler;
	return old;
}


ILIAS_NET2_EXPORT void
ILIAS_NET2__dead
verr(int eval, const char *fmt, va_list ap)
{
	char	*msg;

	if ((msg = make_message(fmt, errno, ap)) == NULL)
		abort();
	if (error_handler)
		(*error_handler)(eval, msg);
	else {
		write(2, msg, strlen(msg));
		write(2, "\n", 1);
	}
	free(msg);

	/* Don't return. */
	exit(eval);
}

ILIAS_NET2_EXPORT void
ILIAS_NET2__dead
verrx(int eval, const char *fmt, va_list ap)
{
	char	*msg;

	if ((msg = make_message(fmt, errno, ap)) == NULL)
		abort();
	if (error_handler)
		(*error_handler)(eval, msg);
	else {
		write(2, msg, strlen(msg));
		write(2, "\n", 1);
	}
	free(msg);

	/* Don't return. */
	exit(eval);
}

ILIAS_NET2_EXPORT void
ILIAS_NET2__dead
err(int eval, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	verr(eval, fmt, ap);
	va_end(ap);
}

ILIAS_NET2_EXPORT void
ILIAS_NET2__dead
errx(int eval, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	verrx(eval, fmt, ap);
	va_end(ap);
}


ILIAS_NET2_EXPORT void
vwarn(const char *fmt, va_list ap)
{
	char	*msg;

	if ((msg = make_message(fmt, errno, ap)) == NULL)
		abort();
	if (error_handler)
		(*warn_handler)(msg);
	else {
		write(2, msg, strlen(msg));
		write(2, "\n", 1);
	}
	free(msg);
}

ILIAS_NET2_EXPORT void
vwarnx(const char *fmt, va_list ap)
{
	char	*msg;

	if ((msg = make_message(fmt, errno, ap)) == NULL)
		abort();
	if (error_handler)
		(*warn_handler)(msg);
	else {
		write(2, msg, strlen(msg));
		write(2, "\n", 1);
	}
	free(msg);
}

ILIAS_NET2_EXPORT void
warn(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vwarn(fmt, ap);
	va_end(ap);
}

ILIAS_NET2_EXPORT void
warnx(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vwarnx(fmt, ap);
	va_end(ap);
}

ILIAS_NET2_EXPORT void
vinfo(const char *fmt, va_list ap)
{
	char	*msg;

	if ((msg = make_message(fmt, 0, ap)) == NULL)
		abort();
	if (info_handler)
		(*info_handler)(msg);
	else {
		write(2, msg, strlen(msg));
		write(2, "\n", 1);
	}
	free(msg);
}

ILIAS_NET2_EXPORT void
info(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vinfo(fmt, ap);
	va_end(ap);
}

ILIAS_NET2_EXPORT void
vdebug(const char *fmt, va_list ap)
{
	char	*msg;

	/* Short cut: if no info handler is present, there's no work. */
	if (!debug_handler)
		return;

	if ((msg = make_message(fmt, 0, ap)) == NULL)
		abort();
	if (debug_handler)
		(*debug_handler)(msg);
	free(msg);
}

ILIAS_NET2_EXPORT void
debug(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vdebug(fmt, ap);
	va_end(ap);
}
