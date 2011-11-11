#include <ilias/net2/ilias_net2_export.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <bsd_compat/error.h>

struct net2_thread {
	pthread_t		 n2t_impl;
	void			*(*fn)(void*);
	void			*arg;
};

static void*
thread_wrapper(void *argptr)
{
	struct net2_thread	*t;
	sigset_t		 sigset;

	/* Block all signals to this thread. */
	sigfillset(&sigset);
	pthread_sigmask(SIG_BLOCK, &sigset, NULL);

	/* Run callback. */
	return (*t->fn)(t->arg);
}

/* Start a new thread. */
ILIAS_NET2_LOCAL struct net2_thread*
net2_thread_new(void *(*fn)(void*), void *arg)
{
	struct net2_thread	*t;

	if ((t = malloc(sizeof(*t))) == NULL)
		return NULL;
	if (pthread_create(&t->n2t_impl, NULL, fn, arg)) {
		warn("pthread_create");
		free(t);
		return NULL;
	}
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
