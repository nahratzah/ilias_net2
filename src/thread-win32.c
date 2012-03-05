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
#include <ilias/net2/ilias_net2_export.h>
#include <stdlib.h>
#include <ilias/net2/bsd_compat/error.h>
#include <Windows.h>

struct net2_thread {
	HANDLE		 handle;
	void		*result;
	void		*(*fn)(void*);
	void		*arg;
};

static DWORD WINAPI
thread_wrapper(void *tptr)
{
	struct net2_thread *t = tptr;

	t->result = t->fn(t->arg);
	return 0;
}

/* Start a new thread. */
ILIAS_NET2_LOCAL struct net2_thread*
net2_thread_new(void *(*fn)(void*), void *arg, const char *name)
{
	struct net2_thread	*t;

	if ((t = net2_malloc(sizeof(*t))) == NULL)
		return NULL;
	t->handle = CreateThread(NULL, 0, &thread_wrapper, t, 0, NULL);
	if (t->handle == NULL) {
		net2_free(t);
		return NULL;
	}
	t->fn = fn;
	t->arg = arg;
	t->result = NULL;
	return t;
}

/* Join a thread. */
ILIAS_NET2_LOCAL int
net2_thread_join(struct net2_thread *t, void **out)
{
	if (WaitForSingleObject(t->handle, INFINITE) != WAIT_OBJECT_0)
		return -1;
	if (out != NULL)
		*out = t->result;
	return 0;
}

/* Free a thread. */
ILIAS_NET2_LOCAL void
net2_thread_free(struct net2_thread *t)
{
	net2_free(t);
}
