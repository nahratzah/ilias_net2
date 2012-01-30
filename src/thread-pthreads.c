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
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <bsd_compat/error.h>
#include "config.h"

#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif /* HAVE_PTHREAD_NP_H */

struct net2_thread {
	pthread_t		 n2t_impl;
	void			*(*fn)(void*);
	void			*arg;
};

static void*
thread_wrapper(void *argptr)
{
	struct net2_thread	*t = argptr;
	sigset_t		 sigset;

	/* Block all signals to this thread. */
	sigfillset(&sigset);
	pthread_sigmask(SIG_BLOCK, &sigset, NULL);

	/* Run callback. */
	return (*t->fn)(t->arg);
}

/* Start a new thread. */
ILIAS_NET2_LOCAL struct net2_thread*
net2_thread_new(void *(*fn)(void*), void *arg, const char *name)
{
	struct net2_thread	*t;

	if ((t = malloc(sizeof(*t))) == NULL)
		return NULL;
	t->fn = fn;
	t->arg = arg;
	if (pthread_create(&t->n2t_impl, NULL, &thread_wrapper, t)) {
		warn("pthread_create");
		free(t);
		return NULL;
	}

#ifdef HAS_PTHREAD_SET_NAME_NP
	if (name != NULL)
		pthread_set_name_np(t->n2t_impl, name);
#endif /* HAS_PTHREAD_SET_NAME_NP */
	return t;
}

/* Join a thread. */
ILIAS_NET2_LOCAL int
net2_thread_join(struct net2_thread *t, void **out)
{
	return pthread_join(t->n2t_impl, out);
}

/* Free a thread. */
ILIAS_NET2_LOCAL void
net2_thread_free(struct net2_thread *t)
{
	free(t);
}
