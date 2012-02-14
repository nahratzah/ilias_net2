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
#include <ilias/net2/signset.h>
#include <ilias/net2/sign.h>
#include <ilias/net2/buffer.h>
#include <bsd_compat/error.h>
#include <bsd_compat/sysexits.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>


/* Comparator for signset tree. */
static __inline int
signset_cmp(struct net2_signset_entry *e1, struct net2_signset_entry *e2)
{
	int			 cmp;
	struct net2_buffer	*b1, *b2;

	/* Compare using mini hash. */
	cmp = (e1->mini_hash < e2->mini_hash ? -1 :
	    e1->mini_hash > e2->mini_hash);

	/* Disambiguation needed. */
	if (cmp == 0) {
		b1 = net2_signctx_fingerprint(e1->key);
		b2 = net2_signctx_fingerprint(e2->key);
		if (b1 == NULL && b2 == NULL) {
			/* Unrecoverable error. */
			err(EX_UNAVAILABLE, "Unable to read fingerprints.");
		}

		cmp = net2_buffer_cmp(b1, b2);
		net2_buffer_free(b1);
		net2_buffer_free(b2);
	}

	return cmp;
}

RB_PROTOTYPE_STATIC(net2_signset_tree, net2_signset_entry, tree, signset_cmp);
RB_GENERATE_STATIC(net2_signset_tree, net2_signset_entry, tree, signset_cmp);


/* Initialize set. */
ILIAS_NET2_EXPORT int
net2_signset_init(struct net2_signset *s)
{
	RB_INIT(&s->data);
	return 0;
}

/* Destroy set. */
ILIAS_NET2_EXPORT void
net2_signset_deinit(struct net2_signset *s)
{
	struct net2_signset_entry
				*e;

	while ((e = RB_ROOT(&s->data)) != NULL) {
		RB_REMOVE(net2_signset_tree, &s->data, e);

		net2_signctx_free(e->key);
		free(e);
	}
}

/* Find a key by its fingerprint. */
ILIAS_NET2_EXPORT struct net2_sign_ctx*
net2_signset_find(const struct net2_signset *s,
    const struct net2_buffer *fingerprint)
{
	uint_fast32_t		 mini_hash;
	struct net2_buffer	*tmp;
	struct net2_signset_entry
				*e;
	int			 cmp;

	/* Generate the mini hash. */
	if (net2_buffer_copyout(fingerprint, &mini_hash, sizeof(mini_hash)) !=
	    sizeof(mini_hash))
		return NULL;	/* Can't return error. */

	/* Binary search using the tree. */
	e = RB_ROOT(&s->data);
	while (e != NULL) {
		cmp = (mini_hash < e->mini_hash ? -1 :
		    mini_hash > e->mini_hash);
		if (cmp == 0) {
			/* Disambiguation needed. */
			if ((tmp = net2_signctx_fingerprint(e->key)) == NULL)
				return NULL;	/* Can't return error. */
			cmp = net2_buffer_cmp(fingerprint, tmp);
			net2_buffer_free(tmp);
		}

		if (cmp < 0)
			e = RB_LEFT(e, tree);
		else if (cmp > 0)
			e = RB_RIGHT(e, tree);
		else
			return e->key;
	}

	return NULL;
}

/* Insert a key into the set. */
ILIAS_NET2_EXPORT int
net2_signset_insert(struct net2_signset *s, struct net2_sign_ctx *key)
{
	struct net2_signset_entry
				*e;
	struct net2_buffer	*fp;

	/* Allocate storage. */
	if ((e = malloc(sizeof(*e))) == NULL)
		return ENOMEM;
	e->key = key;

	/* Calculate the mini_hash fingerprint. */
	if ((fp = net2_signctx_fingerprint(key)) == NULL) {
		free(e);
		return EINVAL;	/* Key invalid? Could be ENOMEM... */
	}
	if (net2_buffer_copyout(fp, &e->mini_hash, sizeof(e->mini_hash)) !=
	    sizeof(e->mini_hash)) {
		/* The fingerprint is not large enough. */
		net2_buffer_free(fp);
		free(e);
		return EINVAL;
	}
	net2_buffer_free(fp);

	/* Insert into set. */
	if (RB_INSERT(net2_signset_tree, &s->data, e) != NULL) {
		free(e);
		return EEXIST;
	}

	return 0;
}
