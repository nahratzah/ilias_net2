#include <ilias/net2/ilias_net2_export.h>
#include <stdlib.h>
#include <bsd_compat/error.h>
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
net2_thread_new(void *(*fn)(void*), void *arg)
{
	struct net2_thread	*t;

	if ((t = malloc(sizeof(*t))) == NULL)
		return NULL;
	t->handle = CreateThread(NULL, 0, &thread_wrapper, t, 0, NULL);
	if (t->handle == NULL) {
		free(t);
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
	free(t);
}
