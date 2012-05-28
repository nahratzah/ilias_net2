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
#ifndef ILIAS_NET2_PROMISE_H
#define ILIAS_NET2_PROMISE_H

#include <ilias/net2/ilias_net2_export.h>
#include <ilias/net2/workq.h>
#include <sys/types.h>
#include <stdint.h>

struct net2_promise;
/* Combined promise callback. */
typedef void (*net2_promise_ccb)(struct net2_promise*, struct net2_promise**,
    size_t, void*);

/* An event associated with promise. */
struct net2_promise_event {
	struct net2_promise	*owner;
	net2_workq_cb		 fn;
	TAILQ_ENTRY(net2_promise_event)
				 promq;
	struct net2_workq_job	 job;
	int			 evno;
	void			*arg0;
};


#define NET2_PROM_FIN_UNFINISHED	0	/* Promise hasn't completed. */
#define NET2_PROM_FIN_OK		1	/* Executed succesful. */
#define NET2_PROM_FIN_CANCEL		2	/* Execution cancelled. */
#define NET2_PROM_FIN_ERROR		3	/* Execution failed. */
#define NET2_PROM_FIN_UNREF		4	/* Unreferenced at run. */
#define NET2_PROM_FIN_FAIL		0xf	/* Failed to run. */

#define NET2_PROMFLAG_RELEASE		0x00000001	/* In-call release. */

#define NET2_PROM_ON_FINISH		0	/* On-finish event. */
#define NET2_PROM_ON_RUN		1	/* On-run event: fired when a
						 * thread asks for the result
						 * and the running state hasn't
						 * been set. */
#define NET2_PROM__NUM_EVENTS		2


ILIAS_NET2_EXPORT
struct net2_promise	*net2_promise_new();
ILIAS_NET2_EXPORT
void			 net2_promise_destroy_cb(struct net2_promise*,
			    void (*fn)(void*, void*), void*, void*);
ILIAS_NET2_EXPORT
void			 net2_promise_release(struct net2_promise*);
ILIAS_NET2_EXPORT
void			 net2_promise_ref(struct net2_promise*);
ILIAS_NET2_EXPORT
int			 net2_promise_set_error(struct net2_promise*,
			    uint32_t errcode, int flags);
ILIAS_NET2_EXPORT
int			 net2_promise_is_cancelreq(struct net2_promise*);
ILIAS_NET2_EXPORT
void			 net2_promise_cancel(struct net2_promise*);
ILIAS_NET2_EXPORT
int			 net2_promise_set_cancel(struct net2_promise*, int);
ILIAS_NET2_EXPORT
int			 net2_promise_set_running(struct net2_promise*);
ILIAS_NET2_EXPORT
int			 net2_promise_is_running(struct net2_promise*);
ILIAS_NET2_EXPORT
int			 net2_promise_set_finok(struct net2_promise*, void*,
			    void (*)(void*, void*), void *, int);
ILIAS_NET2_EXPORT
int			 net2_promise_dontfree(struct net2_promise*);
ILIAS_NET2_EXPORT
int			 net2_promise_is_finished(struct net2_promise*);
ILIAS_NET2_EXPORT
int			 net2_promise_get_result(struct net2_promise*,
			    void**, uint32_t*);
ILIAS_NET2_EXPORT
void			 net2_promise_wait(struct net2_promise*);
ILIAS_NET2_EXPORT
void			 net2_promise_start(struct net2_promise*);

ILIAS_NET2_EXPORT
int			 net2_promise_event_init(struct net2_promise_event*,
			    struct net2_promise*, int, struct net2_workq*,
			    net2_workq_cb, void*, void*);

ILIAS_NET2_EXPORT
struct net2_promise	*net2_promise_combine(struct net2_workq*,
			    net2_promise_ccb, void*,
			    struct net2_promise**, size_t);

/* Convert promise event to workq job. */
static __inline struct net2_workq_job*
net2_promise_event_wqjob(struct net2_promise_event *ev)
{
	return &ev->job;
}

/* Deinit promise event. */
static __inline void
net2_promise_event_deinit(struct net2_promise_event *ev)
{
	net2_workq_deinit_work(net2_promise_event_wqjob((ev)));
}

#endif /* ILIAS_NET2_PROMISE_H */
