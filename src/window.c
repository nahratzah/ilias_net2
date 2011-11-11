#include <ilias/net2/window.h>
#include <ilias/net2/connection.h>
#include <ilias/net2/remote.h>
#include <ilias/net2/mutex.h>
#include <bsd_compat/secure_random.h>
#include <bsd_compat/error.h>
#include <stdlib.h>
#include <assert.h>


#define WINSIZE_DFL	4096

/* Window tree. */
static __inline int
winidcmp(struct net2_window *l, struct net2_window *r)
{
	return (l->n2w_winid < r->n2w_winid ? -1 : l->n2w_winid > r->n2w_winid);
}
RB_PROTOTYPE_STATIC(net2_window_head, net2_window, n2w_manq, winidcmp);

/* Test if the window should be freed. */
static int
net2_window_testfree(struct net2_window *w)
{
	return w->n2w_objrefcnt == 0 && w->n2w_refcnt == 0 &&
	    w->n2w_winid == 0;
}

/* Free the window. */
static void
net2_window_free(struct net2_window *w)
{
	assert(net2_window_testfree(w));
	if (w->n2w_init)
		free(w->n2w_init);
	net2_mutex_free(w->n2w_mtx);
	free(w);
}

static void
net2_window_init_txrx_1(struct net2_window_tag *init_ptr)
{
	init_ptr->seq = secure_random();
	init_ptr->barrier = secure_random();
}
/* Initialize window receive/transmit. Window must be locked. */
static int
net2_window_init_txrx(struct net2_window *w)
{
	assert(!(w->n2w_winid & NET2_WIN_IDREMOTE));

	if ((w->n2w_init = calloc(2, sizeof(*w->n2w_init))) == NULL)
		return -1;
	net2_window_init_txrx_1(&w->n2w_init[NET2_WINDOW_TAG_TX]);
	net2_window_init_txrx_1(&w->n2w_init[NET2_WINDOW_TAG_RX]);

	w->n2w_tx.next = w->n2w_init[NET2_WINDOW_TAG_TX];
	w->n2w_rx.cur = w->n2w_init[NET2_WINDOW_TAG_RX];
	return 0;
}

/* Acquire reference to window. */
ILIAS_NET2_EXPORT void
net2_window_reference(struct net2_window *w)
{
	if (w != NULL) {
		net2_mutex_lock(w->n2w_mtx);
		w->n2w_refcnt++;
		assert(w->n2w_refcnt > 0);
		net2_mutex_unlock(w->n2w_mtx);
	}
}
/* Release reference to window. */
ILIAS_NET2_EXPORT void
net2_window_release(struct net2_window *w)
{
	int		do_free;

	if (w != NULL) {
		net2_mutex_lock(w->n2w_mtx);
		assert(w->n2w_refcnt > 0);
		w->n2w_refcnt--;
		do_free = net2_window_testfree(w);
		net2_mutex_unlock(w->n2w_mtx);

		if (do_free)
			net2_window_free(w);
	}
}

/* Allocate a new window for the given object (called on object creation). */
ILIAS_NET2_EXPORT struct net2_window*
net2_window_new(struct net2_connection *conn)
{
	struct net2_window	*w;

	w = malloc(sizeof(*w));
	w->n2w_conn = conn;
	w->n2w_winid = 0;	/* Not in manager. */

	if ((w->n2w_mtx = net2_mutex_alloc()) == NULL) {
		free(w);
		return NULL;
	}
	w->n2w_refcnt = 1;
	w->n2w_objrefcnt = 0;
	w->n2w_init = NULL;

	w->n2w_tx.winsize = WINSIZE_DFL;
	RB_INIT(&w->n2w_tx.ackpending);
	RB_INIT(&w->n2w_rx.pending);
	return w;
}

ILIAS_NET2_EXPORT struct net2_window*
net2_window_from_obj(struct net2_obj *o)
{
	struct net2_window	*w;

	w = o->n2o_window;
	net2_window_reference(w);
	return w;
}

/* Link an object to an existing window (called on object initialization). */
ILIAS_NET2_LOCAL void
net2_window_link(struct net2_window *w, struct net2_obj *o)
{
	net2_mutex_lock(w->n2w_mtx);
	assert(o->n2o_window == NULL);
	o->n2o_window = w;
	w->n2w_objrefcnt++;
	net2_mutex_unlock(w->n2w_mtx);
}

/* Unlink an object from a window (called on object destruction). */
ILIAS_NET2_LOCAL void
net2_window_unlink(struct net2_obj *o)
{
	struct net2_window	*w;
	int			 do_free;

	w = o->n2o_window;
	assert(o->n2o_window != NULL);

	net2_mutex_lock(w->n2w_mtx);
	o->n2o_window = NULL;
	w->n2w_objrefcnt--;

	do_free = net2_window_testfree(w);
	net2_mutex_unlock(w->n2w_mtx);

	if (do_free)
		net2_window_free(w);
}

/* Initialize the window manager. */
ILIAS_NET2_LOCAL int
net2_winmanager_init(struct net2_connection *c)
{
	struct net2_winmanager	*w = &c->n2c_winmanager;

	if ((w->mtx = net2_mutex_alloc()) == NULL)
		return -1;
	RB_INIT(&w->winhead);
	return 0;
}

/* Destroy the window manager. */
ILIAS_NET2_LOCAL void
net2_winmanager_destroy(struct net2_connection *c)
{
	struct net2_winmanager	*w = &c->n2c_winmanager;
	struct net2_window	*win, *rm;
	int			 do_free;

	net2_mutex_lock(w->mtx);
	while ((win = RB_ROOT(&w->winhead)) != NULL) {
		rm = RB_REMOVE(net2_window_head, &w->winhead, win);
		assert(rm == win);
		win->n2w_winid = 0;

		net2_mutex_lock(win->n2w_mtx);
		do_free = net2_window_testfree(win);
		net2_mutex_unlock(win->n2w_mtx);
		if (do_free)
			net2_window_free(win);
	}
	net2_mutex_unlock(w->mtx);
	net2_mutex_free(w->mtx);
	w->mtx = NULL;
}

/* Find a window with the given ID. */
ILIAS_NET2_LOCAL struct net2_window*
net2_win_by_id(struct net2_connection *c, uint32_t id)
{
	struct net2_winmanager	*w = &c->n2c_winmanager;
	struct net2_window	*win, search;

	net2_mutex_lock(w->mtx);
	search.n2w_winid = id;
	win = RB_FIND(net2_window_head, &w->winhead, &search);
	net2_window_reference(win);
	net2_mutex_unlock(w->mtx);
	return win;
}

/* Create a stub for a remotely initiated window. */
ILIAS_NET2_LOCAL struct net2_window*
net2_window_stub(struct net2_connection *c, uint32_t id)
{
	struct net2_winmanager	*w = &c->n2c_winmanager;
	struct net2_window	*win, search;

	if (!(id & NET2_WIN_IDREMOTE)) {
		warnx("attempt to create local stub window %u", id);
		return NULL;
	}

	net2_mutex_lock(w->mtx);
	search.n2w_winid = id;
	win = RB_FIND(net2_window_head, &w->winhead, &search);
	net2_window_reference(win);

	/* Create new window, since it doesn't exist yet. */
	if (win == NULL) {
		win = net2_window_new(c);
		win->n2w_winid = id;
		RB_INSERT(net2_window_head, &w->winhead, win);
	}

	net2_mutex_unlock(w->mtx);
	return win;
}

/* Activate a window on a local object. */
ILIAS_NET2_LOCAL int
net2_window_activate(struct net2_connection *c, struct net2_window *win)
{
	struct net2_winmanager	*w = &c->n2c_winmanager;
	uint32_t		 id;
	struct net2_window	*i;

	net2_mutex_lock(w->mtx);
	net2_mutex_lock(win->n2w_mtx);

	if (win->n2w_winid != 0)
		goto out;

	id = 1;
	RB_FOREACH(i, net2_window_head, &w->winhead) {
		if (i->n2w_winid != id)
			break;
		if (++id & NET2_WIN_IDREMOTE)
			goto fail;
	}
	win->n2w_winid = id;
	RB_INSERT(net2_window_head, &w->winhead, win);

	if (net2_window_init_txrx(win)) {
		RB_REMOVE(net2_window_head, &w->winhead, win);
		win->n2w_winid = 0;
		goto fail;
	}

out:
	net2_mutex_unlock(win->n2w_mtx);
	net2_mutex_unlock(w->mtx);
	return 0;

fail:
	net2_mutex_unlock(win->n2w_mtx);
	net2_mutex_unlock(w->mtx);
	return -1;
}

RB_GENERATE_STATIC(net2_window_head, net2_window, n2w_manq, winidcmp);
