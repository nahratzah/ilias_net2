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
#include <ilias/net2/event.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>


/* Create new event. */
ILIAS_NET2_LOCAL struct net2_event*
net2_event_alloc()
{
	HANDLE		*ev;

	ev = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (ev == NULL)
		return NULL;
	return (struct net2_event*)ev;
}

/* Free event. */
ILIAS_NET2_LOCAL void
net2_event_free(struct net2_event *ev)
{
	CloseHandle((HANDLE)ev);
}

/* Wait for event to become active. */
ILIAS_NET2_LOCAL void
net2_event_wait(struct net2_event *ev)
{
	switch (WaitForSingleObject((HANDLE)ev, INFINITE)) {
	case WAIT_OBJECT_0:	/* Succes. */
		break;
	case WAIT_TIMEOUT:	/* Failure to lock. */
	case WAIT_ABANDONED:	/* Not a mutex. */
	case WAIT_FAILED:	/* Wait function failed to run. */
	default:
		abort();
	}
}

/* Change the event to active state. */
ILIAS_NET2_LOCAL void
net2_event_signal(struct net2_event *ev)
{
	if (!SetEvent((HANDLE)ev))
		abort();
}

/* Test if the event is active. */
ILIAS_NET2_LOCAL int
net2_event_test(struct net2_event *ev)
{
	int rv;

	switch (WaitForSingleObject((HANDLE)ev, 0)) {
	case WAIT_OBJECT_0:	/* Succes. */
		rv = 1;
		break;
	case WAIT_TIMEOUT:	/* Failure to lock. */
		rv = 0;
		break;
	case WAIT_ABANDONED:	/* Not a mutex. */
	case WAIT_FAILED:	/* Wait function failed to run. */
	default:
		abort();
	}

	return rv;
}
