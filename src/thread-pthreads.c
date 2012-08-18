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
#include <ilias/net2/memory.h>
#include <ilias/net2/config.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <ilias/net2/bsd_compat/error.h>

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
#if 0
	sigset_t		 sigset;

	/* Block all signals to this thread. */
	sigfillset(&sigset);
	pthread_sigmask(SIG_BLOCK, &sigset, NULL);
#endif

	/* Run callback. */
	return (*t->fn)(t->arg);
}

/* Start a new thread. */
ILIAS_NET2_LOCAL struct net2_thread*
net2_thread_new(void *(*fn)(void*), void *arg, const char *name)
{
	struct net2_thread	*t;

	if ((t = net2_malloc(sizeof(*t))) == NULL)
		return NULL;
	t->fn = fn;
	t->arg = arg;
	if (pthread_create(&t->n2t_impl, NULL, &thread_wrapper, t)) {
		warn("pthread_create");
		net2_free(t);
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
	net2_free(t);
}

/* Test if the given thread is the current thread. */
ILIAS_NET2_LOCAL int
net2_thread_is_self(struct net2_thread *t)
{
	return pthread_equal(t->n2t_impl, pthread_self());
}

/* Compare 2 threads for equality. */
ILIAS_NET2_LOCAL int
net2_thread_eq(struct net2_thread *t1, struct net2_thread *t2)
{
	return pthread_equal(t1->n2t_impl, t2->n2t_impl);
}

/* Returns this thread. */
ILIAS_NET2_LOCAL struct net2_thread*
net2_thread_self()
{
	struct net2_thread	*t;

	if ((t = net2_malloc(sizeof(*t))) == NULL)
		return NULL;
	t->n2t_impl = pthread_self();
	return t;
}

/* Detach current thread. */
ILIAS_NET2_LOCAL void
net2_thread_detach_self()
{
	pthread_detach(pthread_self());
}
