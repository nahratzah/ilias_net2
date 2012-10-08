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
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "compat.h"

#ifdef WIN32
#define _CRT_SECURE_NO_WARNINGS /* Silence MS compiler. */
#endif


#ifndef HAS_VASPRINTF
/*
 * This implementation is rather inefficient.
 * You'll need 2 passes through the string, in most cases.
 *
 * XXX provide faster implementation if speed is an issue.
 */
int
vasprintf(char **ret, const char *format, va_list ap)
{
	char	*buf;
	size_t	 buflen;
	int	 rv;
	int	 realloc_on_return = 0;

	buflen = 64;
	for (;;) {
		if ((buf = (char*)malloc(buflen)) == NULL) {
			rv = -1;
			break;
		}
		rv = vsnprintf(buf, buflen, format, ap);
		if (rv == -1) {
			if (errno == ERANGE) {
				/*
				 * Motherfuckers don't give the required length back.
				 * The stupidity is astounding.
				 */
				realloc_on_return = 1;
				buflen *= 2;
				free(buf);
				continue;
			}
			fprintf(stderr, "vsnprintf returned -1, errno = %d\n", errno);
			free(buf);
			break;
		}

		if ((size_t)rv < buflen) {
			*ret = buf;
			break;
		}
		buflen = rv + 1;
		free(buf);
	}

	if (rv >= 0 && realloc_on_return) {
		char *tmp = (char*)realloc(buf, rv + 1);
		if (tmp)
			*ret = tmp;
	}

	return rv;
}
#endif /* HAS_VASPRINTF */

#ifndef HAS_ASPRINTF
/*
 * asprintf implemented in terms of vasprintf
 */
int
asprintf(char **ret, const char *format, ...)
{
	va_list	 ap;
	int	 err;

	va_start(ap, format);
	err = vasprintf(ret, format, ap);
	va_end(ap);
	return err;
}
#endif /* HAS_ASPRINTF */

#ifndef HAS_VSNPRINTF
/*
 * An inefficient implementation of vsnprintf, based on vasprintf.
 */
int
vsnprintf(char *ret, size_t len, const char *format, va_list ap)
{
	va_list	 ap;
	char	*tmp;
	int	 err;

	va_start(ap, format);
	err = vasprintf(&tmp, format, ap);
	if (err >= 0) {
		strlcpy(ret, tmp, len);
		free(tmp);
	}
	va_end(ap);

	return err;
}
#endif /* HAS_VSNPRINTF */

#ifndef HAS_SNPRINTF
/*
 * snprintf forwards to vsnprintf
 */
int
snprintf(char *ret, size_t len, const char *format, ...)
{
	va_list	 ap;
	int	 err;

	va_start(ap, format);
	err = vsnprintf(ret, len, format, ap);
	va_end(ap);
	return err;
}
#endif /* HAS_SNPRINTF */


/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
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

#ifndef HAS_STRLCPY
size_t
strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0) {
		while (--n != 0) {
			if ((*d++ = *s++) == '\0')
				break;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';		/* NUL-terminate dst */
		while (*s++)
			;
	}

	return(s - src - 1);	/* count does not include NUL */
}
#endif /* !HAS_STRLCPY */

#ifndef HAS_STRLCAT
size_t
strlcat(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return(dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return(dlen + (s - src));	/* count does not include NUL */
}
#endif /* !HAS_STRLCAT */
