#include <ilias/net2/mutex.h>
#include <bsd_compat/error.h>
#include <bsd_compat/sysexits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct net2_mutex {
	pthread_mutex_t n2m_impl;
};

/*
 * Allocate a mutex.
 */
ILIAS_NET2_LOCAL struct net2_mutex*
net2_mutex_alloc()
{
	struct net2_mutex	*m;
	int			 rv;

	if ((m = malloc(sizeof(*m))) == NULL)
		return m;
	if ((rv = pthread_mutex_init(&m->n2m_impl, NULL)) != 0) {
		warn("%s: %s", "pthread_mutex_destroy", strerror(rv));
		free(m);
		return NULL;
	}
	return m;
}

/*
 * Free a mutex.
 */
ILIAS_NET2_LOCAL void
net2_mutex_free(struct net2_mutex *m)
{
	int rv;

	if (m == NULL)
		return;
	if ((rv = pthread_mutex_destroy(&m->n2m_impl)) != 0) {
		errx(EX_OSERR, "%s: %s",
		    "pthread_mutex_destroy", strerror(rv));
	}
	free(m);
}

/*
 * Lock a mutex.
 */
ILIAS_NET2_LOCAL void
net2_mutex_lock(struct net2_mutex *m)
{
	int rv;

	if ((rv = pthread_mutex_lock(&m->n2m_impl)) != 0)
		errx(EX_OSERR, "%s: %s", "pthread_mutex_lock", strerror(rv));
}

/*
 * Unlock a mutex.
 */
ILIAS_NET2_LOCAL void
net2_mutex_unlock(struct net2_mutex *m)
{
	int rv;

	if ((rv = pthread_mutex_unlock(&m->n2m_impl)) != 0)
		errx(EX_OSERR, "%s: %s", "pthread_mutex_lock", strerror(rv));
}
