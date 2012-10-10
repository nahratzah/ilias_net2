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
#include <ilias/net2/bitset.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>


/* # bits in uintptr_t. */
#define BITS			(8 * sizeof(uintptr_t))
/* Calculate space in bytes to store up to _sz bits. */
#define SIZE_TO_BYTES(_sz)	(((_sz) + BITS - 1) / BITS)
/* Calculate element index for bit at _idx. */
#define INDEX(_idx)		((_idx) / BITS)
/* Calculate offset withing element for bit _idx. */
#define OFFSET(_idx)		((_idx) % BITS)
/* Return the pointer to element for index idx. */
#define ptr(s_, idx)							\
	(((s_)->size <= BITS ? &(s_)->immed : (s_)->indir) + INDEX(idx))


/* Initialize bitset. */
ILIAS_NET2_EXPORT void
net2_bitset_init(struct net2_bitset *s)
{
	s->size = 0;
	s->indir = NULL;
}

/* Initialize bitset as copy of another bitset. */
ILIAS_NET2_EXPORT int
net2_bitset_init_copy(struct net2_bitset *s, const struct net2_bitset *src)
{
	if (src->size > BITS) {
		if ((s->indir = malloc(SIZE_TO_BYTES(src->size))) == NULL)
			return ENOMEM;
		memcpy(s->indir, src->indir, SIZE_TO_BYTES(src->size));
		s->size = src->size;
	} else
		*s = *src;	/* Struct copy. */
	return 0;
}

/* Initialize bitset, moving data from other bitset into this. */
ILIAS_NET2_EXPORT void
net2_bitset_init_move(struct net2_bitset *s, struct net2_bitset *src)
{
	*s = *src;		/* Struct copy. */
	src->size = 0;
	src->indir = NULL;
}

/* Deinitialize bitset. */
ILIAS_NET2_EXPORT void
net2_bitset_deinit(struct net2_bitset *s)
{
	if (s->size > BITS)
		free(s->indir);
}

/* Read a value from the bitset. */
ILIAS_NET2_EXPORT int
net2_bitset_get(const struct net2_bitset *s, size_t idx, int *val)
{
	const uintptr_t	*i;
	uintptr_t	 mask;

	if (idx >= s->size)
		return EINVAL;
	i = ptr(s, idx);
	mask = 1 << OFFSET(idx);

	if (val)
		*val = ((*i & mask) != 0);
	return 0;
}

/* Set a value in the bitset. */
ILIAS_NET2_EXPORT int
net2_bitset_set(struct net2_bitset *s, size_t idx, int newval, int *oldval)
{
	uintptr_t	*i;
	uintptr_t	 mask;

	if (idx >= s->size)
		return EINVAL;
	i = ptr(s, idx);
	mask = 1 << OFFSET(idx);

	if (oldval != NULL)
		*oldval = (*i) & mask;

	if (newval)
		*i |= mask;
	else
		*i &= ~mask;
	return 0;
}

/* Change the size of the bitset. */
ILIAS_NET2_EXPORT int
net2_bitset_resize(struct net2_bitset *s, size_t newsz, int new_is_set)
{
	size_t		 need, have, i;
	uintptr_t	*list;

	if (newsz <= BITS) {
		if (s->size > BITS) {
			list = s->indir;
			s->immed = list[0];
			free(s->indir);
		}

		goto init_data;
	}

	if (s->size > BITS)
		list = s->indir;
	else
		list = NULL;
	need = SIZE_TO_BYTES(newsz);
	have = SIZE_TO_BYTES(s->size);
	if (newsz > SIZE_MAX / sizeof(*list))
		return ENOMEM;	/* size_t overflow detected. */

	if (need != have) {
		if (list == NULL) {
			if ((list = malloc(need)) == NULL)
				return ENOMEM;
			list[0] = s->immed;
		} else if ((list = realloc(list, need)) == NULL)
			return ENOMEM;
		s->indir = list;
	}

init_data:
	if (s->size >= newsz) {
		/* Truncated list. */
		s->size = newsz;
	} else {
		/* Grown list. */
		i = s->size;
		s->size = newsz;
		while (i < newsz) {
			net2_bitset_set(s, i, new_is_set, NULL);
			i++;
		}
	}
	return 0;
}

/* Test if all bits have the pattern in test. */
static int
net2_bitset_all_value(const struct net2_bitset *s, uintptr_t test)
{
	uintptr_t		 mask;
	size_t			 i, index, offset;

	/* Test all complete ints. */
	index = INDEX(s->size);
	offset = OFFSET(s->size);
	for (i = 0; i + 1 < index; i++) {
		if (ptr(s, 0)[i] != test)
			return 0;
	}

	/* Test last, incomplete int. */
	if (offset != 0) {
		mask = (1 << offset) - 1;
		if ((ptr(s, 0)[index] & mask) != (test & mask))
			return 0;
	}

	return 1;
}
/* Test if all bits are set. */
ILIAS_NET2_EXPORT int
net2_bitset_allset(const struct net2_bitset *s)
{
	return net2_bitset_all_value(s, ~(uintptr_t)0);
}
/* Test if all bits are clear. */
ILIAS_NET2_EXPORT int
net2_bitset_allclear(const struct net2_bitset *s)
{
	return net2_bitset_all_value(s, (uintptr_t)0);
}
