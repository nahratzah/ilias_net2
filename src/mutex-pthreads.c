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
#include <ilias/net2/mutex.h>
#include <ilias/net2/memory.h>
#include <bsd_compat/error.h>
#include <bsd_compat/sysexits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct net2_mutex {
	pthread_mutex_t	n2m_impl;
};

struct net2_condition {
	pthread_cond_t	n2c_impl;
};

/*
 * Allocate a mutex.
 */
ILIAS_NET2_LOCAL struct net2_mutex*
net2_mutex_alloc()
{
	struct net2_mutex	*m;
	int			 rv;

	if ((m = net2_malloc(sizeof(*m))) == NULL)
		return m;
	if ((rv = pthread_mutex_init(&m->n2m_impl, NULL)) != 0) {
		warnx("%s: %s", "pthread_mutex_init", strerror(rv));
		net2_free(m);
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
	net2_free(m);
}

/*
 * Lock a mutex.
 */
ILIAS_NET2_LOCAL void
net2_mutex_lock(struct net2_mutex *m)
{
	int rv;

	while ((rv = pthread_mutex_lock(&m->n2m_impl)) != 0) {
		switch (rv) {
		case EINTR:
			break;
		case EDEADLK:
			warnx("%s: %s", "pthread_mutex_lock", strerror(rv));
			abort();
		default:
			errx(EX_OSERR, "%s: %s", "pthread_mutex_lock",
			    strerror(rv));
		}
	}
}

/*
 * Unlock a mutex.
 */
ILIAS_NET2_LOCAL void
net2_mutex_unlock(struct net2_mutex *m)
{
	int rv;

	while ((rv = pthread_mutex_unlock(&m->n2m_impl)) != 0) {
		switch (rv) {
		case EINTR:
			break;
		default:
			errx(EX_OSERR, "%s: %s", "pthread_mutex_unlock",
			    strerror(rv));
		}
	}
}



/*
 * Allocate a condition variable.
 */
ILIAS_NET2_LOCAL struct net2_condition*
net2_cond_alloc()
{
	struct net2_condition	*c;
	int			 rv;

	if ((c = net2_malloc(sizeof(c))) == NULL)
		return c;

	if ((rv = pthread_cond_init(&c->n2c_impl, NULL)) != 0) {
		warnx("%s: %s", "pthread_cond_init", strerror(rv));
		net2_free(c);
		return NULL;
	}
	return c;
}

/*
 * Free a condition variable.
 */
ILIAS_NET2_LOCAL void
net2_cond_free(struct net2_condition *c)
{
	int rv;

	if (c == NULL)
		return;
	if ((rv = pthread_cond_destroy(&c->n2c_impl)) != 0) {
		errx(EX_OSERR, "%s: %s",
		    "pthread_cond_destroy", strerror(rv));
	}
	net2_free(c);
}

/*
 * Signal a condition variable, waking up a single waiting thread.
 */
ILIAS_NET2_LOCAL void
net2_cond_signal(struct net2_condition *c)
{
	int rv;

	if ((rv = pthread_cond_signal(&c->n2c_impl)) != 0)
		warnx("%s: %s", "pthread_cond_signal", strerror(rv));
}

/*
 * Wakeup all threads waiting for a condition.
 */
ILIAS_NET2_LOCAL void
net2_cond_broadcast(struct net2_condition *c)
{
	int rv;

	if ((rv = pthread_cond_broadcast(&c->n2c_impl)) != 0)
		warnx("%s: %s", "pthread_cond_signal", strerror(rv));
}

/*
 * Wait for condition to fire.
 */
ILIAS_NET2_LOCAL void
net2_cond_wait(struct net2_condition *c, struct net2_mutex *m)
{
	int rv;

	if ((rv = pthread_cond_wait(&c->n2c_impl, &m->n2m_impl)) != 0)
		warnx("%s: %s", "pthread_cond_wait", strerror(rv));
}
