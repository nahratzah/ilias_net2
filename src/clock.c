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
#include <ilias/net2/bsd_compat/clock.h>
#include <stdint.h>
#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif


/* Export monotonic clock as struct timeval. */
ILIAS_NET2_EXPORT int
tv_clock_gettime(clockid_t clock, struct timeval *tv)
{
#ifdef WIN32
	LARGE_INTEGER		counter, freq;
	uint64_t		t;
#else
	struct timespec		ts;
#endif
	int err;


#ifdef WIN32
	if (clock != CLOCK_MONOTONIC)
		err = -1;
	else if (!QueryPerformanceCounter(&counter) ||
	    !QueryPerformanceFrequency(&freq))
		err = -1;
	else if (freq.QuadPart == 0)
		err = -1;
	else {
		t = (1000000 * counter.QuadPart) / freq.QuadPart;
		tv->tv_sec  = t / 1000000;
		tv->tv_usec = t % 1000000;
		err = 0;
	}
#else
	err = clock_gettime(clock, &ts);
	TIMESPEC_TO_TIMEVAL(tv, &ts);
#endif
	return err;
}

/* Export monotonic clock resolution as struct timeval. */
ILIAS_NET2_EXPORT int
tv_clock_getres(clockid_t clock, struct timeval *tv)
{
#ifdef WIN32
	LARGE_INTEGER		freq;
	uint64_t		t;
#else
	struct timespec		ts;
#endif
	int err;


#ifdef WIN32
	if (clock != CLOCK_MONOTONIC)
		err = -1;
	else if (QueryPerformanceFrequency(&freq))
		err = -1;
	else if (freq.QuadPart == 0)
		err = -1;
	else {
		t = 1000000 / freq.QuadPart;
		tv->tv_sec  = t / 1000000;
		tv->tv_usec = t % 1000000;
		err = 0;
	}
#else
	err = clock_getres(clock, &ts);
	TIMESPEC_TO_TIMEVAL(tv, &ts);
#endif
	return err;
}
