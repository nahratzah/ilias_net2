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
#include <ilias/net2/semaphore.h>

#ifdef ILIAS_NET2_SEMAPHORE_EXTERN
#include <ilias/net2/mutex.h>
#include <stdlib.h>


ILIAS_NET2_LOCAL int
net2_semaphore_initval(struct net2_semaphore *s, unsigned int initial)
{
	if ((s->mtx = net2_mutex_alloc()) == NULL)
		goto fail_0;
	if ((s->cnd = net2_cond_alloc()) == NULL)
		goto fail_1;
	s->v = initial;
	return 0;


fail_2:
	net2_cond_free(s->cnd);
fail_1:
	net2_mutex_free(s->mtx);
fail_0:
	return ENOMEM;
}

ILIAS_NET2_LOCAL void
net2_semaphore_deinit(struct net2_semaphore *s)
{
	net2_cond_free(s->cnd);
	net2_mutex_free(s->mtx);
}

ILIAS_NET2_LOCAL void
net2_semaphore_up(struct net2_semaphore *s, unsigned int count)
{
	net2_mutex_lock(s->mtx);
	s->v += count;
	while (count-- > 0)
		net2_cond_signal(s->cnd);
	net2_mutex_unlock(s->mtx);
}

ILIAS_NET2_LOCAL void
net2_semaphore_down(struct net2_semaphore *s)
{
	net2_mutex_lock(s->mtx);
	while (s->v == 0)
		net2_cond_wait(s->cnd, s->mtx);
	s->v--;
	net2_mutex_unlock(s->mtx);
}

ILIAS_NET2_LOCAL int
net2_semaphore_trydown(struct net2_semaphore *s)
{
	int	succeeded;

	net2_mutex_lock(s->mtx);
	if (s->v == 0)
		succeeded = 0;
	else {
		s->v--;
		succeeded = 1;
	}
	net2_mutex_unlock(s->mtx);
	return succeeded;
}
#endif /* HAVE_STDATOMIC_H */
