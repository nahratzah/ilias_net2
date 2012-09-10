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
#ifndef ILIAS_NET2_LL_H
#define ILIAS_NET2_LL_H

#include <ilias/net2/bsd_compat/atomic.h>
#include <stddef.h>

typedef atomic_uintptr_t elem_ptr_t;
struct elem {
	elem_ptr_t	succ, pred;
	atomic_size_t	refcnt;
};


struct elem	*ll_unlink(struct elem*, struct elem*, int);
void		 ll_unlink_release(struct elem*);
struct elem	*ll_succ(struct elem*, struct elem*);
struct elem	*ll_pred(struct elem*, struct elem*);
void		 ll_ref(struct elem*, struct elem*);
void		 ll_release(struct elem*, struct elem*);
int		 ll_empty(struct elem*);
void		 ll_insert_before(struct elem*, struct elem*, struct elem*);
void		 ll_insert_after(struct elem*, struct elem*, struct elem*);
void		 ll_insert_head(struct elem*, struct elem*);
void		 ll_insert_tail(struct elem*, struct elem*);
struct elem	*ll_pop_front(struct elem*);
struct elem	*ll_pop_back(struct elem*);


#define LL_HEAD(name)							\
	struct name {							\
		struct elem	ll_head;				\
	}
#define LL_ENTRY(type)							\
	struct elem

#define LL_HEAD_INITIALIZER(head)					\
{									\
	{								\
		ATOMIC_VAR_INIT(&head.ll_head),				\
		ATOMIC_VAR_INIT(&head.ll_head),				\
		ATOMIC_VAR_INIT(0)					\
	}								\
}

#define LL_INIT(head)							\
do {									\
	atomic_init(&head->ll_head.succ, &head->ll_head);		\
	atomic_init(&head->ll_head.pred, &head->ll_head);		\
	atomic_init(&head->ll_head.refcnt, 0);				\
} while (0)

#define LL_NEXT(name, head, node)	ll_pred_##name(head, node)
#define LL_PREV(name, head, node)	ll_succ_##name(head, node)
#define LL_FIRST(name, head)		ll_first_##name(head)
#define LL_LAST(name, head)		ll_last_##name(head)
#define LL_EMPTY(name, head)		ll_empty_##name(head)
#define LL_REF(name, head, node)	ll_ref_##name(head, node)
#define LL_RELEASE(name, head, node)	ll_release_##name(head, node)

#define LL_INSERT_AFTER(name, head, node, rel)				\
	ll_insert_after_##name(head, node, rel)
#define LL_INSERT_BEFORE(name, head, node, rel)				\
	ll_insert_before_##name(head, node, rel)
#define LL_INSERT_HEAD(name, head, node)				\
	ll_insert_head_##name(head, node)
#define LL_INSERT_TAIL(name, head, node)				\
	ll_insert_tail_##name(head, node)
#define LL_UNLINK(name, head, node)					\
	ll_unlink_##name(head, node)
#define LL_UNLINK_NOWAIT(name, head, node)				\
	ll_unlink_nowait_##name(head, node)
#define LL_UNLINK_WAIT(name, node)					\
	ll_unlink_wait_##name(node)
#define LL_POP_FRONT(name, head)					\
	ll_pop_front_##name(head)
#define LL_POP_BACK(name, head)						\
	ll_pop_back_##name(head)

#define LL_FOREACH(var, name, head)					\
	for (var = ll_first_##name(head);				\
	    var != NULL;						\
	    var = ll_foreach_succ_##name(var))
#define LL_FOREACH_REVERSE(var, name, head)				\
	for (var = ll_last_##name(head);				\
	    var != NULL;						\
	    var = ll_foreach_pred_##name(var))

#define LL_PUSH_FRONT(name, head, node)					\
	ll_insert_head_##name(head, node)
#define LL_PUSH_BACK(name, head, node)					\
	ll_insert_tail_##name(head, node)


#define LL_GENERATE(name, type, member)					\
static __inline struct type*						\
ll_elem_##name(struct elem *e)						\
{									\
	return (e == NULL ? NULL :					\
	    (struct type*)((uintptr_t)e - offsetof(type, member)));	\
}									\
static __inline struct type*						\
ll_pred_##name(struct name *q, struct type *n)				\
{									\
	return ll_elem_##name(ll_succ(&q->ll_head, &n->member));	\
}									\
static __inline struct type*						\
ll_succ_##name(struct name *q, struct type *n)				\
{									\
	return ll_elem_##name(ll_pred(&q->ll_head, &n->member));	\
}									\
static __inline struct type*						\
ll_first_##name(struct name *q)						\
{									\
	return ll_elem_##name(ll_succ(&q->ll_head, &q->ll_head));	\
}									\
static __inline struct type*						\
ll_last_##name(struct name *q)						\
{									\
	return ll_elem_##name(ll_pred(&q->ll_head, &q->ll_head));	\
}									\
static __inline void							\
ll_ref_##name(struct name *q, struct type *n)				\
{									\
	ll_ref(&q->ll_head, &n->member);				\
}									\
static __inline void							\
ll_release_##name(struct name *q, struct type *n)			\
{									\
	ll_release(&q->ll_head, &n->member);				\
}									\
static __inline int							\
ll_empty_##name(struct name *q)						\
{									\
	ll_empty(&q->ll_head);						\
}									\
static __inline struct type*						\
ll_foreach_succ_##name(struct name *q, struct type *n)			\
{									\
	struct type	*s;						\
									\
	/* Lookup successor. */						\
	s = ll_succ_##name(q, n);					\
	/* Release n. */						\
	ll_release_##name(q, n);					\
	/* Return successor. */						\
	return s;							\
}									\
static __inline struct type*						\
ll_foreach_pred_##name(struct name *q, struct type *n)			\
{									\
	struct type	*p;						\
									\
	/* Lookup predecessor. */					\
	p = ll_pred_##name(q, n);					\
	/* Release n. */						\
	ll_release_##name(q, n);					\
	/* Return successor. */						\
	return p;							\
}									\
static __inline void							\
ll_insert_after_##name(struct name *q, struct type *n,			\
    struct type *rel)							\
{									\
	ll_insert_after(&q->ll_head, &n->member, &rel->member);		\
}									\
static __inline void							\
ll_insert_before_##name(struct name *q, struct type *n,			\
    struct type *rel)							\
{									\
	ll_insert_before(&q->ll_head, &n->member, &rel->member);	\
}									\
static __inline void							\
ll_insert_head_##name(struct name *q, struct type *n)			\
{									\
	ll_insert_head(&q->ll_head, &n->member);			\
}									\
static __inline void							\
ll_insert_tail_##name(struct name *q, struct type *n)			\
{									\
	ll_insert_tail(&q->ll_head, &n->member);			\
}									\
static __inline struct type*						\
ll_unlink_##name(struct name *q, struct type *n)			\
{									\
	return ll_elem_##name(ll_unlink(&q->ll_head, &n->member, 1));	\
}									\
static __inline struct type*						\
ll_unlink_nowait_##name(struct name *q, struct type *n)			\
{									\
	return ll_elem_##name(ll_unlink(&q->ll_head, &n->member, 0));	\
}									\
static __inline struct type*						\
ll_unlink_wait_##name(struct type *n)					\
{									\
	ll_unlink_release(&n->member);					\
}									\
static __inline struct type*						\
ll_pop_front_##name(struct name *q)					\
{									\
	return ll_elem_##name(ll_pop_front(&q->ll_head));		\
}									\
static __inline struct type*						\
ll_pop_back_##name(struct name *q)					\
{									\
	return ll_elem_##name(ll_pop_back(&q->ll_head));		\
}
/* End of LL_GENERATE macro. */

#endif /* ILIAS_NET2_LL_H */
