#include <ilias/net2/bitset.h>
#include <stdlib.h>
#include <errno.h>


#define SIZE_TO_BYTES(_sz)						\
	(((_sz) + (8 * sizeof(int)) - 1) / (8 * sizeof(int)))

#define INDEX(_idx)		((_idx) / (8 * sizeof(int)))
#define OFFSET(_idx)		((_idx) % (8 * sizeof(int)))


/* Initialize bitset. */
ILIAS_NET2_LOCAL void
net2_bitset_init(struct net2_bitset *s)
{
	s->size = 0;
	s->data = NULL;
}

/* Deinitialize bitset. */
ILIAS_NET2_LOCAL void
net2_bitset_deinit(struct net2_bitset *s)
{
	if (s->data)
		free(s->data);
}

/* Read a value from the bitset. */
ILIAS_NET2_LOCAL int
net2_bitset_get(const struct net2_bitset *s, size_t idx, int *val)
{
	const int	*i;
	int		 mask;

	if (idx >= s->size)
		return EINVAL;
	i = s->data + INDEX(idx);
	mask = 1 << OFFSET(idx);

	if (val)
		*val = *i & mask;
	return 0;
}

/* Set a value in the bitset. */
ILIAS_NET2_LOCAL int
net2_bitset_set(struct net2_bitset *s, size_t idx, int newval, int *oldval)
{
	int		*i;
	int		 mask;

	if (idx >= s->size)
		return EINVAL;
	i = s->data + INDEX(idx);
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
ILIAS_NET2_LOCAL int
net2_bitset_resize(struct net2_bitset *s, size_t newsz, int new_is_set)
{
	size_t		 need, have;
	int		*list;

	if (newsz == 0) {
		free(s->data);
		s->data = NULL;
		s->size = 0;
		return 0;
	}

	list = s->data;
	need = SIZE_TO_BYTES(newsz);
	have = SIZE_TO_BYTES(s->size);
	if (newsz > SIZE_MAX / sizeof(*list))
		return ENOMEM;	/* size_t overflow detected. */

	if (need != have) {
		if ((list = realloc(list, need)) == NULL)
			return ENOMEM;
		s->data = list;
	}

	if (s->size >= newsz) {
		/* Truncated list. */
		s->size = newsz;
	} else {
		/* Grown list. */
		while (s->size < newsz) {
			s->size++;
			net2_bitset_set(s, s->size - 1, new_is_set, NULL);
		}
	}
	return 0;
}

/* Test if all bits are set. */
ILIAS_NET2_LOCAL int
net2_bitset_allset(const struct net2_bitset *s)
{
	int			 mask, test;
	size_t			 i, index, offset;

	test = ~(int)0;

	/* Test all complete ints. */
	index = INDEX(s->size);
	offset = OFFSET(s->size);
	for (i = 0; i + 1 < index; i++) {
		if (s->data[i] != test)
			return 0;
	}

	/* Test last, incomplete int. */
	if (offset != 0) {
		mask = (1 << offset) - 1;
		if ((s->data[index] & mask) != (test & mask))
			return 0;
	}

	return 1;
}
/* Test if all bits are clear. */
ILIAS_NET2_LOCAL int
net2_bitset_allclear(const struct net2_bitset *s)
{
	int			 mask, test;
	size_t			 i, index, offset;

	test = 0;

	/* Test all complete ints. */
	index = INDEX(s->size);
	offset = OFFSET(s->size);
	for (i = 0; i + 1 < index; i++) {
		if (s->data[i] != test)
			return 0;
	}

	/* Test last, incomplete int. */
	if (offset != 0) {
		mask = (1 << offset) - 1;
		if ((s->data[index] & mask) != (test & mask))
			return 0;
	}

	return 1;
}
