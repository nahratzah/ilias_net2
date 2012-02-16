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
#include <ilias/net2/buffer.h>
#include <ilias/net2/mutex.h>
#include <bsd_compat/minmax.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <bsd_compat/error.h>
#include <bsd_compat/sysexits.h>

#include <stdio.h>	/* DEBUG */


#ifndef NDEBUG
/* Invariant check. */
static void	buffer_is_valid(struct net2_buffer*,
		    const char*, int, const char*);

#define ASSERTBUFFER(_var)						\
	buffer_is_valid((_var), __FUNCTION__, __LINE__, #_var)
#else
#define ASSERTBUFFER(_var)	do { /* NOTHING */ } while (0)
#endif /* NDEBUG */

/* Special constant, that points at offset 0 within a buffer. */
ILIAS_NET2_EXPORT const struct net2_buffer_ptr
net2_buffer_ptr0 = { 0, 0, 0 };

/*
 * A buffer segment.
 *
 * Each buffer segment contains some space that is used to contain data.
 * Not all of its data may be in use.
 *
 * Segment impl are threadsafe.
 * Segment impl may be shared and are reference counted.
 */
struct net2_buffer_segment_impl {
	struct net2_mutex		*mtx;
	size_t				 refcnt;
	size_t				 len;
	size_t				 use;

	int				 flags;
#define BUF_STD				0x00000001	/* Standard buffer style. */
#define BUF_REFERENCE			0x00000002	/* Reference data. */
	/* Data after segment. */
};

/* Data alignment of net2_buffer_segment_impl. */
#define DATA_ALIGN			 				\
	(MAX(MAX(sizeof(void*), sizeof(unsigned long long)), 8))
/*
 * sizeof(struct net2_buffer_segment_impl)
 *
 * This value is chosen in such a way that the DATA_ALIGN constraint is met.
 */
#define NET2_BUFSEGMENT_IMPL_SZ						\
	((sizeof(struct net2_buffer_segment_impl) + DATA_ALIGN - 1) &	\
	 ~((size_t)DATA_ALIGN - 1))

/* Memory reference data. */
struct reference {
	void				*release_arg;
	void				(*release)(void*);
	void				*data;
};

/* Extract reference info from buffer segment impl. */
static __inline struct reference*
get_reference(struct net2_buffer_segment_impl *s)
{
	void				*p;

	assert(s->flags & BUF_REFERENCE);
	p = (uint8_t*)s + NET2_BUFSEGMENT_IMPL_SZ;
	return p;
}

#define SEGMENT_SZ(datasz)						\
	(NET2_BUFSEGMENT_IMPL_SZ + (datasz))

/*
 * Allocate multiples of 32 byte, to reduce the number of required
 * reallocations.
 */
#define NET2_BUFFER_ALIGN	((size_t)64)
#define NET2_BUFFER_FRAGMENT	((size_t)1024*1024)

/* Allocate a new segment impl with the given length. */
static struct net2_buffer_segment_impl*
segment_impl_new(const void *data, size_t datlen, size_t len)
{
	struct net2_buffer_segment_impl	*s;
	size_t				 require, want, have;

	/* Ensure that net2_buffer_segment_impl is a multiple of 8 bytes. */
	fprintf(stderr, "net2_buffer_segment_impl size = %zu bytes; define size = %zu bytes\n", sizeof(*s), NET2_BUFSEGMENT_IMPL_SZ);
	assert((NET2_BUFSEGMENT_IMPL_SZ & ((size_t)DATA_ALIGN - 1)) == 0);

	if (len < datlen)
		goto fail_0;

	require = SEGMENT_SZ(len);
	want = ((require + NET2_BUFFER_ALIGN - 1) & ~(NET2_BUFFER_ALIGN - 1));

	if ((s = malloc(want)) == NULL) {
		if ((s = malloc(require)) == NULL)
			goto fail_0;
		else
			have = require;
	} else
		have = want;
	if ((s->mtx = net2_mutex_alloc()) == NULL)
		goto fail_1;
	s->refcnt = 1;
	s->len = have - NET2_BUFSEGMENT_IMPL_SZ;
	s->use = datlen;
	s->flags = BUF_STD;
	if (data)
		memcpy((uint8_t*)s + NET2_BUFSEGMENT_IMPL_SZ, data, datlen);
	return s;

fail_1:
	free(s);
fail_0:
	return NULL;
}

/* Allocate a new segment impl, referencing the given data. */
static struct net2_buffer_segment_impl*
segment_impl_newref(void *data, size_t len, void (*release)(void*), void *release_arg)
{
	struct net2_buffer_segment_impl	*s;
	struct reference		*r;

	if (len == 0)
		goto fail_0;

	if ((s = malloc(NET2_BUFSEGMENT_IMPL_SZ + sizeof(*r))) == NULL)
		goto fail_0;
	if ((s->mtx = net2_mutex_alloc()) == NULL)
		goto fail_1;
	s->refcnt = 1;
	s->len = len;
	s->use = len;
	s->flags = BUF_REFERENCE;

	r = get_reference(s);
	r->data = data;
	r->release = release;
	r->release_arg = release_arg;

	return s;

fail_1:
	free(s);
fail_0:
	return NULL;
}

/* Release a segment impl. */
static void
segment_impl_release(struct net2_buffer_segment_impl *s)
{
	struct reference		*r;

	net2_mutex_lock(s->mtx);

	assert(s->refcnt > 0);
	if (--s->refcnt == 0) {
		net2_mutex_unlock(s->mtx);
		net2_mutex_free(s->mtx);

		if (s->flags & BUF_REFERENCE) {
			r = get_reference(s);
			if (r->release != NULL)
				(*r->release)(r->release_arg);
		}

		free(s);
		return;
	}
	net2_mutex_unlock(s->mtx);
}

/* Reference a segment impl. */
static void
segment_impl_reference(struct net2_buffer_segment_impl *s)
{
	net2_mutex_lock(s->mtx);
	s->refcnt++;
	assert(s->refcnt != 0);
	net2_mutex_unlock(s->mtx);
}

/*
 * Attempt to grow a segment impl.
 * May move the pointer.
 */
static int
segment_impl_grow(struct net2_buffer_segment_impl **sptr,
    size_t off, size_t add, int do_realloc)
{
	struct net2_buffer_segment_impl	*s = *sptr, *tmp;
	int				 rv = -1;
	size_t				 require, want, have;

	assert(s->use >= off);
	if ((s->flags & BUF_STD) && s->use == off) {
		if (s->len - s->use >= add) {
			s->use += add;
			rv = 0;
		} else if (s->refcnt == 1 && do_realloc) {
			require = SEGMENT_SZ(off + add);
			want = ((require + NET2_BUFFER_ALIGN - 1) &
			    ~(NET2_BUFFER_ALIGN - 1));
			if ((tmp = realloc(s, want)) == NULL) {
				if ((tmp = realloc(s, require)) == NULL)
					goto fail_0;
				else
					have = require;
			} else
				have = want;
			*sptr = s = tmp;
			s->len = have - NET2_BUFSEGMENT_IMPL_SZ;
			s->use += add;
			rv = 0;
		}
	}

fail_0:
	return rv;
}

/*
 * Append data to segment impl at given offset.
 */
static int
segment_impl_append(struct net2_buffer_segment_impl **sptr,
    size_t off, const void *data, size_t len, int do_realloc)
{
	int				 rv;
	struct net2_buffer_segment_impl *s;

	net2_mutex_lock((*sptr)->mtx);
	rv = segment_impl_grow(sptr, off, len, 1);
	s = *sptr;
	if (rv != 0) {
		net2_mutex_unlock(s->mtx);
		return rv;
	}

	memcpy((uint8_t*)s + NET2_BUFSEGMENT_IMPL_SZ + off, data, len);
	net2_mutex_unlock(s->mtx);
	return 0;
}

/*
 * Reserve space in a segment.
 *
 * If do_realloc, the segment may be reallocated to reserve all this space.
 * If all, all data must fit or the reserve will fail.
 */
static int
segment_impl_reserve(struct net2_buffer_segment_impl **sptr,
    size_t off, size_t len, int do_realloc, int all,
    struct iovec *iov)
{
	struct net2_buffer_segment_impl	*s;
	int				 rv = -1;
	size_t				 grow;

	s = *sptr;
	net2_mutex_lock(s->mtx);
	if (s->use != off)
		goto fail_0;

	grow = len;
	rv = segment_impl_grow(sptr, off, grow, do_realloc);
	if (rv != 0 && !all) {
		grow = s->len - s->use;
		if (grow > 0 && grow < len)
			rv = segment_impl_grow(sptr, off, grow, do_realloc);
	}
	if (rv != 0)
		goto fail_0;
	s = *sptr;

	iov->iov_base = (uint8_t*)s + NET2_BUFSEGMENT_IMPL_SZ + off;
	iov->iov_len = grow;
	rv = 0;

fail_0:
	net2_mutex_unlock(s->mtx);
	return rv;
}


/*
 * A segment description.
 *
 * Points at a segment impl and maintains information about the offset and
 * length of the data that is actually used within the segment impl.
 */
struct net2_buffer_segment {
	size_t				 off;
	size_t				 len;
	struct net2_buffer_segment_impl	*data;
};

/* Initialize a new segment. */
static int
segment_init_data(struct net2_buffer_segment *s, const void *data, size_t len)
{
	s->off = 0;
	s->len = len;
	if ((s->data = segment_impl_new(data, len, len)) == NULL)
		return -1;
	return 0;
}

/* Initialize a new segment, referencing data. */
static int
segment_init_ref(struct net2_buffer_segment *s, void *data, size_t len,
    void (*release)(void*), void *release_arg)
{
	s->off = 0;
	s->len = len;
	if ((s->data = segment_impl_newref(data, len, release, release_arg)) == NULL)
		return -1;
	return 0;
}

/* Copy a segment. */
static void
segment_init_copy(struct net2_buffer_segment *dst,
    struct net2_buffer_segment *src)
{
	segment_impl_reference(src->data);
	dst->off = src->off;
	dst->len = src->len;
	dst->data = src->data;
}

/* Release a segment. */
static void
segment_deinit(struct net2_buffer_segment *s)
{
	segment_impl_release(s->data);
	s->data = NULL;
}

/* Return the pointer to the beginning of the data in this segment. */
static void*
segment_getptr(struct net2_buffer_segment *s)
{
	uint8_t				*p;
	struct reference		*r;

	if (s->data->flags & BUF_REFERENCE) {
		r = get_reference(s->data);
		p = r->data;
	} else if (s->data->flags & BUF_STD)
		p = (uint8_t*)s->data + NET2_BUFSEGMENT_IMPL_SZ;
	else {
		errx(EX_SOFTWARE, "unrecognized buffer segment: flags=0x%x",
		    s->data->flags);
	}

	return p + s->off;
}

/*
 * Attempt to add data to a segment.
 */
static int
segment_append(struct net2_buffer_segment *s, const void *data, size_t datlen)
{
	int				 rv;

	rv = segment_impl_append(&s->data, s->off + s->len, data, datlen, 1);
	if (rv == 0)
		s->len += datlen;
	return rv;
}

/* Truncate a segment. */
static void
segment_trunc(struct net2_buffer_segment *s, size_t newlen)
{
	assert(s->len >= newlen);
	s->len = newlen;
}

/* Remove the front of a segment. */
static void
segment_drain(struct net2_buffer_segment *s, size_t off)
{
	assert(s->len >= off);
	s->off += off;
	s->len -= off;
}

/*
 * Reserve space at the end of orig.
 * s will be initialized with the space thus reserved.
 */
static int
segment_reserve(struct net2_buffer_segment *s,
    struct net2_buffer_segment *orig, size_t len, int do_realloc, int all,
    struct iovec *iov)
{
	int				 rv;

	rv = segment_impl_reserve(&orig->data, orig->off + orig->len, len,
	    do_realloc, all, iov);
	if (rv == 0) {
		segment_impl_reference(s->data);
		s->data = orig->data;
		s->off = orig->off + orig->len;
		s->len = iov->iov_len;
	}
	return rv;
}


/*
 * A network buffer.
 *
 * Data is managed in copy-on-write fashion.
 */
struct net2_buffer {
	struct net2_buffer_segment	*list;
	size_t				 listlen;
	struct net2_buffer_segment	*reserve;
	size_t				 reservelen;
};

/* Kill reserved segments in buffer. */
static void
kill_reserve(struct net2_buffer *b)
{
	while (b->reservelen > 0)
		segment_deinit(&b->reserve[--b->reservelen]);
	free(b->reserve);
	b->reserve = NULL;
}

/* Create a new empty buffer. */
ILIAS_NET2_EXPORT struct net2_buffer*
net2_buffer_new()
{
	struct net2_buffer		*result;

	result = malloc(sizeof(*result));
	if (result) {
		result->list = NULL;
		result->listlen = 0;
		result->reserve = NULL;
		result->reservelen = 0;
		ASSERTBUFFER(result);
	}
	return result;
}

/* Free a buffer. */
ILIAS_NET2_EXPORT void
net2_buffer_free(struct net2_buffer *buf)
{
	size_t				 i;

	if (buf == NULL)
		return;

	kill_reserve(buf);
	if (buf->list != NULL) {
		for (i = 0; i < buf->listlen; i++)
			segment_deinit(&buf->list[i]);
		free(buf->list);
	}
	free(buf);
}

/* Copy a buffer. */
ILIAS_NET2_EXPORT struct net2_buffer*
net2_buffer_copy(const struct net2_buffer *src)
{
	struct net2_buffer		*dst;
	size_t				 i;

	if ((dst = net2_buffer_new()) == NULL)
		goto fail_0;
	if ((dst->list = malloc(src->listlen * sizeof(*dst->list))) == NULL)
		goto fail_1;
	dst->listlen = src->listlen;

	for (i = 0; i < dst->listlen; i++)
		segment_init_copy(&dst->list[i], &src->list[i]);
	ASSERTBUFFER(dst);
	return dst;

fail_1:
	net2_buffer_free(dst);
fail_0:
	return NULL;
}

/*
 * Append data to a buffer.
 *
 * When appending to a buffer, we try to avoid a situation where the buffer
 * grows forever, because the buffer is used as a drain and sink at the
 * same time: we start a new segment if the last one exceeds
 * NET2_BUFFER_FRAGMENT bytes.
 *
 * If we wouldn't split, a buffer on which net2_buffer_add and
 * net2_buffer_drain is called repeatedly, without the buffer ever draining
 * to 0 bytes, would cause the drained memory to never be released.
 */
ILIAS_NET2_EXPORT int
net2_buffer_add(struct net2_buffer *b, const void *data, size_t len)
{
	struct net2_buffer_segment	*last;
	struct net2_buffer_segment	*list;

	kill_reserve(b);
	/* Trivial case. */
	if (len == 0)
		return 0;
	if (data == NULL)
		return -1;	/* Cannot add null data. */

	list = b->list;
	if (b->listlen > 0 &&
	    list[b->listlen - 1].off + list[b->listlen - 1].len <=
	    NET2_BUFFER_FRAGMENT) {
		last = &list[b->listlen - 1];
		if (segment_append(last, data, len) == 0)
			return 0;
	}

	if ((list = realloc(list, (b->listlen + 1) * sizeof(*list))) == NULL)
		goto fail_0;
	b->list = list;
	if (segment_init_data(&list[b->listlen], data, len))
		goto fail_0;
	b->listlen++;
	ASSERTBUFFER(b);
	return 0;

fail_0:
	ASSERTBUFFER(b);
	return -1;
}

/*
 * Append referenced data to a buffer.
 *
 * The data must remain valid until the release function has been called.
 *
 * The release function will be called with the release_arg parameter, once the
 * last reference to this data is removed.
 */
ILIAS_NET2_EXPORT int
net2_buffer_add_reference(struct net2_buffer *b, void *data, size_t len,
    void (*release)(void*), void *release_arg)
{
	struct net2_buffer_segment	*last;
	struct net2_buffer_segment	*list;

	kill_reserve(b);
	/* Trivial case. */
	if (len == 0)
		return -1;	/* Cannot reference no data. */
	if (data == NULL)
		return -1;	/* Cannot reference null data. */

	list = b->list;

	if ((list = realloc(list, (b->listlen + 1) * sizeof(*list))) == NULL)
		goto fail_0;
	b->list = list;
	if (segment_init_ref(&list[b->listlen], data, len, release, release_arg))
		goto fail_0;
	b->listlen++;
	ASSERTBUFFER(b);
	return 0;

fail_0:
	ASSERTBUFFER(b);
	return -1;
}

/* Append a buffer. */
ILIAS_NET2_EXPORT int
net2_buffer_append(struct net2_buffer *dst, const struct net2_buffer *src)
{
	size_t				 newlen, i, listoff;
	struct net2_buffer_segment	*list;

	kill_reserve(dst);
	/* Trivial case. */
	if (src->listlen == 0)
		return 0;

	/* Create enough space in list. */
	newlen = dst->listlen + src->listlen;
	list = dst->list;
	if ((list = realloc(list, newlen * sizeof(*list))) == NULL)
		goto fail_0;
	dst->list = list;

	/* Copy list entries from src to the added space in dst. */
	listoff = dst->listlen;
	for (i = 0; i < src->listlen; i++)
		segment_init_copy(&list[listoff + i], &src->list[i]);

	dst->listlen = newlen;
	ASSERTBUFFER(dst);
	return 0;

fail_0:
	ASSERTBUFFER(dst);
	return -1;
}

/* Prepend a buffer. */
ILIAS_NET2_EXPORT int
net2_buffer_prepend(struct net2_buffer *dst, const struct net2_buffer *src)
{
	size_t				 newlen, i, listoff;
	struct net2_buffer_segment	*list;

	kill_reserve(dst);
	/* Trivial case. */
	if (src->listlen == 0)
		return 0;

	/* Create enough space in list. */
	newlen = dst->listlen + src->listlen;
	list = dst->list;
	if ((list = realloc(list, newlen * sizeof(*list))) == NULL)
		goto fail_0;
	dst->list = list;

	/* Move entries in list to the end. */
	listoff = src->listlen;
	memmove(&list[listoff], list, dst->listlen * sizeof(*list));

	/* Copy list entries from src to the added space in dst. */
	for (i = 0; i < listoff; i++)
		segment_init_copy(&list[i], &src->list[i]);

	dst->listlen = newlen;
	ASSERTBUFFER(dst);
	return 0;

fail_0:
	ASSERTBUFFER(dst);
	return -1;
}

/*
 * Ensure the first len bytes of the buffer are contiguous and return
 * a pointer to this data.
 *
 * If len is larger than the length of the buffer, all data will be made
 * contiguous, but the pointer return will indicate failure.
 */
ILIAS_NET2_EXPORT void*
net2_buffer_pullup(struct net2_buffer *b, size_t len)
{
	struct net2_buffer_segment	*list, new0;
	size_t				 next;
	int				 fail = 0;

	kill_reserve(b);
	/* Cannot pullup on empty buffer. */
	if (b->listlen == 0)
		return NULL;

	list = b->list;
	next = 1;
	while (list[0].len < len && next < b->listlen) {
		/* Attempt to simply append the data to list[0]. */
		if (segment_append(&list[0], segment_getptr(&list[next]),
		    list[next].len) == 0) {
			segment_deinit(&list[next]);
			next++;
			continue;
		}

		/* Attempt to create an unshared copy of list[0]. */
		if (segment_init_data(&new0,
		    segment_getptr(&list[0]), list[0].len)) {
			fail = 1;
			break;
		}
		segment_deinit(&list[0]);
		list[0] = new0;

		/*
		 * No next++: we didn't actually merge the next entry.
		 * The next iteration of the loop will do that for us.
		 */
	}

	/* Move elements in the list, covering the deinitialized segments. */
	b->listlen -= (next - 1);
	memmove(&list[1], &list[next], b->listlen - 1);

	/* Attempt to release memory (not an error if this fails). */
	if ((list = realloc(list, b->listlen * sizeof(*list))) != NULL)
		b->list = list;

	/*
	 * Return pointer to list[0], unless we failed (by triggering the break
	 * in the above loop.
	 */
	ASSERTBUFFER(b);
	return (fail ? NULL : segment_getptr(&list[0]));
}

/*
 * Return the length of the buffer.
 */
ILIAS_NET2_EXPORT size_t
net2_buffer_length(const struct net2_buffer *b)
{
	struct net2_buffer_segment	*list;
	size_t				 i, sz;

	list = b->list;
	sz = 0;
	for (i = 0; i < b->listlen; i++)
		sz += list[i].len;

	return sz;
}

/*
 * Returns true if the buffer is empty.
 */
ILIAS_NET2_EXPORT int
net2_buffer_empty(const struct net2_buffer *b)
{
	struct net2_buffer_segment	*list;
	size_t				 i;

	if (b->listlen == 0)
		return 1;

	list = b->list;
	for (i = 0; i < b->listlen; i++) {
		if (list[i].len > 0)
			return 0;
	}
	return 1;
}

/*
 * Fill iovecs to describe the first len bytes in the buffer.
 *
 * Don't write in the returned memory unless you are sure the buffer data
 * is not shared!
 * If the buffer contains less than len bytes,
 * the whole buffer will be returned.
 *
 * Returns the number of iovec that would be required for the operation to
 * succeed.
 */
ILIAS_NET2_EXPORT size_t
net2_buffer_peek(const struct net2_buffer *b, size_t len,
    struct iovec *iov, size_t iovlen)
{
	struct net2_buffer_segment	*list, *list_end;
	size_t				 count;

	list = b->list;
	list_end = list + b->listlen;
	for (count = 0; len > 0 && list != list_end; count++, list++) {
		if (iovlen > 0) {
			iov->iov_base = segment_getptr(list);
			iov->iov_len = MIN(len, list->len);
			iov++;
			iovlen--;
		}
		len -= MIN(len, list->len);
	}

	return count;
}

/*
 * Read data from the beginning of the buffer.
 *
 * If the buffer has less than len bytes, the whole buffer will be copied.
 * Returns the number of bytes thus copied.
 */
ILIAS_NET2_EXPORT size_t
net2_buffer_copyout(const struct net2_buffer *b, void *datptr, size_t len)
{
	struct net2_buffer_segment	*list;
	size_t				 drained, drain, i;
	uint8_t				*data;

	/* Update all segments at the beginning until len is 0. */
	data = datptr;
	drained = 0;
	list = b->list;
	for (i = 0; i < b->listlen && len > 0; i++) {
		/* Calculate how much data we can fetch from this segment. */
		drain = MIN(list[i].len, len);

		/* Copy data if so requested. */
		if (data) {
			memcpy(data, segment_getptr(&list[i]), drain);
			data += drain;
		}

		/* Reduce segment by drained amount. */
		len -= drain;
		drained += drain;
	}

	return drained;
}

/*
 * Read data from the beginning of the buffer.
 *
 * If the buffer has less than len bytes, the whole buffer will be drained.
 * Returns the number of bytes thus drained.
 */
ILIAS_NET2_EXPORT size_t
net2_buffer_remove(struct net2_buffer *b, void *datptr, size_t len)
{
	struct net2_buffer_segment	*list;
	size_t				 drained, drain, i;
	uint8_t				*data;

	kill_reserve(b);
	/* Update all segments at the beginning until len is 0. */
	data = datptr;
	drained = 0;
	list = b->list;
	for (i = 0; i < b->listlen && len > 0; i++) {
		/* Calculate how much data we can fetch from this segment. */
		drain = MIN(list[i].len, len);

		/* Copy data if so requested. */
		if (data) {
			memcpy(data, segment_getptr(&list[i]), drain);
			data += drain;
		}

		/* Reduce segment by drained amount. */
		segment_drain(&list[i], drain);
		len -= drain;
		drained += drain;

		/*
		 * If the segment is empty, drain it and ensure i++
		 * (at the for-loop declaration) is executed to update
		 * the number of released segments.
		 *
		 * Otherwise, skip this.
		 */
		if (list[i].len == 0)
			segment_deinit(&list[i]);
		else if (len == 0)
			break;
	}

	/* Move segments to cover drained and released elements. */
	b->listlen -= i;
	memmove(&list[0], &list[i], b->listlen * sizeof(*list));

	ASSERTBUFFER(b);

	return drained;
}

/*
 * Advance the pointer N steps.
 * Fails if the pointer is already at the end or would fall over the end.
 */
ILIAS_NET2_EXPORT int
net2_buffer_ptr_advance(const struct net2_buffer *b, struct net2_buffer_ptr *p,
    size_t delta)
{
	struct net2_buffer_segment	*list;
	size_t				 max_delta;

	list = b->list;
	if (p->segment >= b->listlen || p->off >= list[p->segment].len)
		return -1;

	/* We search until delta becomes 0. */
	while (delta > 0) {
		max_delta = list[p->segment].len - p->off;
		p->off += MIN(max_delta, delta);
		p->pos += MIN(max_delta, delta);
		delta -= MIN(max_delta, delta);

		/*
		 * When running into the end of the segment, step to the next
		 * segment.
		 * Do this until the next non-empty segment is reached.
		 */
		while (p->off == list[p->segment].len) {
			if (++p->segment == b->listlen && delta != 0)
				return -1;
			p->off = 0;
		}
	}

	return 0;
}

/*
 * Test if the text between start and end matches that of needle.
 * Return true on match, 0 if they don't match.
 */
static int
buffer_match(const struct net2_buffer *b, struct net2_buffer_ptr *start,
    struct net2_buffer_ptr *pend, const void *needle, size_t needle_len)
{
	struct net2_buffer_segment	*list, *list_seg;
	size_t				 seg, off, len, end;
	uint8_t				*p;

	assert(start->pos + needle_len == pend->pos);
	assert(start->segment <= pend->segment);
	assert(start->segment != pend->segment || start->off <= pend->off);
	assert(pend->segment <= b->listlen);
	list = b->list;

	for (seg = start->segment;
	    seg < pend->segment || (seg == pend->segment && pend->off > 0);
	    seg++) {
		list_seg = &list[seg];

		off = (seg == start->segment ? start->off : 0);
		end = (seg == pend->segment ? pend->off : list_seg->len);
		p = segment_getptr(list_seg);
		p += off;
		len = end - off;
		if (memcmp(p, needle, len) != 0)
			return 0;
		needle = (uint8_t*)needle + len;
		needle_len -= len;
	}
	assert(needle_len == 0);

	return 1;
}

/*
 * Search for a byte string in buffer.
 */
ILIAS_NET2_EXPORT int
net2_buffer_search(const struct net2_buffer *b, struct net2_buffer_ptr *found,
    const void *needle, size_t needle_len, struct net2_buffer_ptr *start)
{
	struct net2_buffer_ptr		 pos, pos_end;
	struct net2_buffer_segment	*list, *list_seg;
	size_t				 histogram[0x100];
	const uint8_t			*ptr, *ptr_end, *p;
	size_t				 i;
	size_t				 h_zeroes; /* #non-zero in histogram */
	size_t				 seg, off;

	/* Initialize: pos must be either *start or the null position. */
	list = b->list;
	if (start == NULL) {
		pos.pos = 0;
		pos.segment = 0;
		pos.off = 0;
		while (pos.off == list[pos.segment].len) {
			if (++pos.segment == b->listlen)
				return -1;
		}
	} else
		pos = *start;

	/* Derive at pos_end from pos and needle_len. */
	pos_end = pos;
	if (net2_buffer_ptr_advance(b, &pos_end, needle_len))
		return -1;

	/* Initialize histogram. */
	for (i = 0; i < sizeof(histogram) / sizeof(histogram[0]); i++)
		histogram[i] = 0;
	h_zeroes = 0;
	for (i = 0; i < needle_len; i++) {
		if (histogram[((uint8_t*)needle)[i]]-- == 0)
			h_zeroes--;
	}

	/* Create pointer corresponding to start position. */
	ptr = segment_getptr(&list[pos.segment]);
	ptr += pos.off;
	ptr_end = segment_getptr(&list[pos_end.segment]);
	ptr_end += pos_end.off;

	/* Update histogram with text between (pos, pos_end). */
	for (seg = pos.segment; seg <= pos_end.segment; seg++) {
		list_seg = &list[seg];
		p = segment_getptr(list_seg);

		off = (seg == pos.segment ? pos.off : 0);
		p += off;
		for (;
		    (!(seg <  pos_end.segment) || off < list_seg->len) &&
		    (!(seg == pos_end.segment) || off < pos_end.off);
		    off++, p++) {
			if (histogram[*p] == 0)
				h_zeroes--;
			histogram[*p]++;
			if (histogram[*p] == 0)
				h_zeroes++;
		}
	}

	/*
	 * We are now set up to start the actual search.
	 *
	 * When h_zeroes == 0, we have balance in the number of characters
	 * and needle, and we only need to check if they match.
	 * If the text indeed matches, *found will acquire the value of pos.
	 *
	 * When pos_end.segment == b->listlen, we bounce into the end of the
	 * list and the search fails.
	 *
	 * ptr and ptr_end need to be reset when pos and pos_end traverse a
	 * segment (off == 0).
	 */
	for (;;) {
		/*
		 * If h_zeroes is 0, possible match in the area between
		 * ptr, ptr_end.
		 * Do actual check.
		 */
		if (h_zeroes == 0 &&
		    buffer_match(b, &pos, &pos_end, needle, needle_len)) {
			*found = pos;
			return 0;
		}

		if (pos_end.segment == b->listlen)
			return -1;	/* Hitting the end. */

		/* Update zero counter for to-be-removed ptr. */
		if (histogram[*ptr] == 0)
			h_zeroes--;
		histogram[*ptr]--;
		if (histogram[*ptr] == 0)
			h_zeroes++;

		/* Update zero counter for to-be-added ptr_end. */
		if (histogram[*ptr_end] == 0)
			h_zeroes--;
		histogram[*ptr_end]++;
		if (histogram[*ptr_end] == 0)
			h_zeroes++;

		/* Step to next element. */
		pos.pos++;
		pos_end.pos++;
		pos.off++;
		pos_end.off++;
		ptr++;
		ptr_end++;
		while (pos_end.segment < b->listlen &&
		    pos_end.off == list[pos_end.segment].len) {
			pos_end.segment++;
			pos_end.off = 0;
			/*
			 * pos_end may be at the first segment after the end,
			 * in which case we cannot dereference into ptr_end.
			 */
			if (pos_end.segment != b->listlen) {
				ptr_end =
				    segment_getptr(&list[pos_end.segment]);
			} else
				ptr_end = NULL;
		}
		while (pos.off == list[pos.segment].len) {
			pos.segment++;
			pos.off = 0;
			ptr = segment_getptr(&list[pos.segment]);
		}
	}

	/* UNREACHABLE */
}

/*
 * Drain the first len bytes from src into dst.
 */
ILIAS_NET2_EXPORT size_t
net2_buffer_remove_buffer(struct net2_buffer *src, struct net2_buffer *dst,
    size_t len)
{
	struct net2_buffer_segment	*dst_list, *src_list;
	size_t				 listlen, sz;
	struct net2_buffer_ptr		 src_ptr;
	size_t				 dst_add, mv;
	size_t				 i;

#ifndef NDEBUG
	size_t				 srclen_expect, dstlen_expect;
#endif

	kill_reserve(src);
	kill_reserve(dst);
	dst_list = dst->list;
	src_list = src->list;

	/* Always succeeds. */
	if (len == 0)
		return 0;

#ifndef NDEBUG
	srclen_expect = net2_buffer_length(src);
	dstlen_expect = net2_buffer_length(dst);
	if (len > srclen_expect) {
		dstlen_expect += srclen_expect;
		srclen_expect = 0;
	} else {
		dstlen_expect += len;
		srclen_expect -= len;
	}
#endif

	src_ptr = net2_buffer_ptr0;
	if (net2_buffer_ptr_advance(src, &src_ptr, len - 1)) {
remove_everything:
		/*
		 * Source has insufficient entries -> add all.
		 */
		listlen = src->listlen + dst->listlen;
		dst_list = realloc(dst_list, listlen * sizeof(*dst_list));
		if (dst_list == NULL)
			return 0;
		dst->list = dst_list;
		sz = 0;
		for (i = 0; i < src->listlen; i++) {
			sz += src_list[i].len;
			dst_list[dst->listlen + i] = src_list[i];
		}
		dst->listlen = listlen;
		free(src->list);
		src->list = NULL;
		src->listlen = 0;
		ASSERTBUFFER(src);
		ASSERTBUFFER(dst);
		return sz;
	}
	/* Manually adjust the pointer to one-past-the-end. */
	src_ptr.pos++;
	src_ptr.off++;
	if (src_ptr.segment + 1 == src->listlen && src_ptr.off == src_list[src_ptr.segment].len)
		goto remove_everything;

	assert(src_ptr.pos == len);

	/*
	 * dst_add: number of additional segments in dst.
	 * mv: number of segments that is moved entirely from src to dst.
	 */
	dst_add = src_ptr.segment + 1;
	mv = src_ptr.segment +
	    (src_ptr.off == src_list[src_ptr.segment].len ? 1 : 0);
	listlen = dst->listlen + dst_add;

	assert(dst_add <= src->listlen);
	assert(mv <= src->listlen);

	/* Prepare space in dst. */
	dst_list = realloc(dst_list, listlen * sizeof(*dst_list));
	if (dst_list == NULL)
		return 0;
	dst->list = dst_list;

	/* Move entries from src into dst. */
	memcpy(&dst_list[dst->listlen], &src_list[0], mv * sizeof(*dst_list));
	dst->listlen += mv;

	/* Move entries that remain in src to the bottom of src. */
	memmove(&src_list[0], &src_list[mv],
	    (src->listlen - mv) * sizeof(*src_list));
	src->listlen -= mv;

	/*
	 * Share the first entry in src with the last in dst,
	 * as it is split through the middle.
	 */
	if (dst_add != mv) {
		segment_init_copy(&dst_list[dst->listlen], &src_list[0]);
		segment_trunc(&dst_list[dst->listlen], src_ptr.off);
		segment_drain(&src_list[0], src_ptr.off);
		dst->listlen++;
	}

	/* Validation. */
#ifndef NDEBUG
	assert(net2_buffer_length(src) == srclen_expect);
	assert(net2_buffer_length(dst) == dstlen_expect);
#endif
	if (src->listlen == 0) {
		free(src->list);
		src->list = NULL;
	} else {
		/* Reduce memory usage. */
		src_list = realloc(src_list,
		    src->listlen * sizeof(*src_list));
		if (src_list != NULL)
			src->list = src_list;
	}

	ASSERTBUFFER(src);
	ASSERTBUFFER(dst);

	return src_ptr.pos;
}

/*
 * Lexicographical comparison of two buffers.
 *
 * Returns  0 if they are equal.
 * Returns -1 if b1 comes before b2.
 * Returns  1 if b1 comes after  b2.
 */
ILIAS_NET2_EXPORT int
net2_buffer_cmp(const struct net2_buffer *b1, const struct net2_buffer *b2)
{
	struct net2_buffer_segment	*list1, *list2;
	size_t				 i1, i2;
	size_t				 off1, off2, len;
	const uint8_t			*p1, *p2;
	int				 cmp;

	list1 = b1->list;
	list2 = b2->list;
	i1 = i2 = 0;
	off1 = off2 = 0;

	for (;;) {
		/*
		 * Skip empty segments.
		 */
		while (i1 != b1->listlen && off1 == list1[i1].len) {
			off1 = 0;
			if (++i1 == b1->listlen)
				break;
		}
		while (i2 != b2->listlen && off2 == list2[i2].len) {
			off2 = 0;
			if (++i2 == b2->listlen)
				break;
		}

		/*
		 * Don't break earlier: the must both be able to reach the
		 * end of the list to be able to compare equal.
		 */
		if (i1 == b1->listlen || i2 == b2->listlen)
			break;

		/*
		 * Compare as many bytes as possible in one operation.
		 */
		len = MIN(list1[i1].len - off1, list2[i2].len - off2);
		p1 = segment_getptr(&list1[i1]);
		p1 += off1;
		p2 = segment_getptr(&list2[i2]);
		p2 += off2;

		/* If they are not equal, abort with failure. */
		if ((cmp = memcmp(p1, p2, len)) != 0)
			return cmp;

		/* Next comparison position. */
		off1 += len;
		off2 += len;
	}

	/*
	 * Both buffers contained the same data,
	 * but maybe one of them hasn't reached the end yet?
	 *
	 * We know at least one of them is at the end of its data.
	 */
	if (i1 == b1->listlen && i2 == b2->listlen)
		return 0;	/* Equal data, equal length. */
	return (i1 == b1->listlen ? -1 : 1);
}


/*
 * Reserve a chunk of memory in a buffer.
 *
 * This memory can be changed, but will not be visible in the buffer until
 * commit is called.
 */
ILIAS_NET2_EXPORT int
net2_buffer_reserve_space(struct net2_buffer *b, size_t len, struct iovec *iov,
    size_t *iovlen)
{
	struct net2_buffer_segment	*list, *reserve;
	size_t				 spent, grow;

	if (iovlen == NULL || iov == NULL)
		return -1;
	kill_reserve(b);

	/* Trivial case: reserve no memory. */
	if (len == 0) {
		*iovlen = 0;
		return 0;
	} else if (*iovlen == 0)
		return -1;

	/* Initialization. */
	list = b->list;
	reserve = b->reserve;

	/* Reserve enough space for the worst case scenario. */
	reserve = realloc(reserve,
	    (b->reservelen + *iovlen) * sizeof(*reserve));
	if (reserve == NULL)
		return -1;
	b->reserve = reserve;

	spent = 0;	/* 0 iovs in use so far. */

	/*
	 * Attempt to share the first entry in reserve with the last buffer
	 * in list.
	 * *iovlen is at least 1 at this point.
	 */
	if (b->listlen >= 1) {
		if (segment_reserve(&reserve[spent], &list[b->listlen - 1], len,
		    1, *iovlen == 1, iov) == 0) {
			len -= iov->iov_len;
			spent++;
			iov++;
		}
	}

	/*
	 * Create new segments.
	 */
	while (len > 0 && spent < *iovlen) {
		/*
		 * Allocate a new segment.
		 * We don't let a small problem like memory fragmentation or
		 * allocation failure stop us without a fight.
		 *
		 * New segment is allocated with NULL data, causing the
		 * memory to be uninitialized.
		 */
		if (spent + 1 < *iovlen) {
			grow = MIN(len, NET2_BUFFER_FRAGMENT);
		} else
			grow = len;
		for (; grow > 0; grow /= 2) {
			if (segment_init_data(&reserve[spent],
			    NULL, grow) == 0)
				break;
		}
		if (grow == 0)
			goto fail;

		iov->iov_base = segment_getptr(&reserve[spent]);
		iov->iov_len = reserve[spent].len;
		len -= iov->iov_len;
		spent++;
		iov++;
	}
	if (len > 0)
		goto fail;

	b->reservelen += spent;
	*iovlen = spent;
	return 0;

fail:
	while (spent-- > b->reservelen)
		segment_deinit(&reserve[spent]);
	if (b->reservelen == 0) {
		free(reserve);
		b->reserve = NULL;
	}
	return -1;
}

/* Find the element that describes the first byte of this iov. */
static struct net2_buffer_segment*
find_reserved(struct net2_buffer_segment *reserve, size_t reservelen,
    void *base)
{
	void				*seg_base, *seg_end;
	size_t				 i;

	for (i = 0; i < reservelen; i++) {
		seg_base = segment_getptr(&reserve[i]);
		seg_end = (uint8_t*)seg_base + reserve[i].len;

		if (seg_base <= base && seg_end > base)
			return &reserve[i];
	}
	return NULL;
}

/*
 * Commit previously reserved space.
 */
ILIAS_NET2_EXPORT int
net2_buffer_commit_space(struct net2_buffer *b, struct iovec *iov,
    size_t iovlen)
{
	struct net2_buffer_segment	*list, *reserve, *seg;
	size_t				 i, spent, seg_off, seg_len;
	void				*iov_base;
	size_t				 iov_len;
	size_t				 old_list_lastlen;

	/* Initialize. */
	list = b->list;
	reserve = b->reserve;
	spent = b->listlen;

	/*
	 * Save old length of last element in list, in case we fail after
	 * adding data to it.
	 */
	if (b->listlen > 0)
		old_list_lastlen = list[b->listlen - 1].len;
	else
		old_list_lastlen = 0;

	/*
	 * Add each iov to the list.
	 */
	for (i = 0; i < iovlen; i++) {
		/*
		 * We operate on a copy of the iov data,
		 * since we need to modify it in the loop below.
		 */
		iov_base = iov[i].iov_base;
		iov_len = iov[i].iov_len;

		while (iov_len > 0) {
			/*
			 * Get which reserved segment describes which part
			 * of this data.
			 */
			seg = find_reserved(reserve, b->reservelen, iov_base);
			if (seg == NULL)
				goto fail;
			seg_off = (uint8_t*)iov_base -
			    (uint8_t*)segment_getptr(seg);
			seg_len = MIN(seg->len - seg_off, iov_len);
			assert(seg_off + seg_len <= seg->len);

			/*
			 * Commit the space to the end of list if possible.
			 */
			if (spent > 0  && seg_off == 0 &&
			    list[spent - 1].data == seg->data &&
			    (list[spent - 1].off + list[spent - 1].len ==
			     seg->off)) {
				list[spent - 1].len += seg_len;
			} else {
				/*
				 * Cannot merge with last entry in list.
				 * Grow the list and create a copy.
				 */
				list = realloc(list,
				    (spent + 1) * sizeof(*list));
				if (list == NULL)
					goto fail;
				b->list = list;
				segment_init_copy(&list[spent], seg);
				segment_drain(&list[spent], seg_off);
				segment_trunc(&list[spent], seg_len);
				spent++;
			}

			iov_base = (uint8_t*)iov_base + seg_len;
			iov_len -= seg_len;
		}
	}

	/*
	 * Succes, throw away the reserved segments.
	 */
	kill_reserve(b);
	b->listlen = spent;

	ASSERTBUFFER(b);
	return 0;

fail:
	/*
	 * Undo addition to b->list.
	 */
	while (spent-- > b->listlen)
		segment_deinit(&b->list[spent]);
	if (b->listlen == 0) {
		free(b->list);
		b->list = NULL;
	} else
		segment_trunc(&b->list[b->listlen - 1], old_list_lastlen);

	/*
	 * Throw away reserved segments.
	 */
	kill_reserve(b);
	ASSERTBUFFER(b);

	return -1;
}

/*
 * Return the hexadecimal encoded content of the buffer.
 * String will be NULL terminated.
 */
ILIAS_NET2_EXPORT char*
net2_buffer_hex(const struct net2_buffer *b)
{
	struct net2_buffer_segment	*list;
	char				*s, *result;
	size_t				 i, p_len;
	uint8_t				*p;
	uint8_t				 hi, lo;

	/* Hex lookup table used in conversion. */
	static const char		 hex[] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
	};

	list = b->list;
	if ((result = s = malloc(2 * net2_buffer_length(b) + 1)) == NULL)
		return NULL;
	for (i = 0; i < b->listlen; i++) {
		p = segment_getptr(&list[i]);
		for (p_len = list[i].len; p_len > 0; p_len--, p++) {
			hi = (*p & 0xf0) >> 4;
			lo = (*p & 0x0f);

			*s++ = hex[hi];
			*s++ = hex[lo];
		}
	}

	*s = '\0';
	return result;
}

/*
 * Returns a buffer containing a subrange of the buffer.
 *
 * Returns NULL if insufficient memory or off+len exceeds the source buffer.
 */
ILIAS_NET2_EXPORT struct net2_buffer*
net2_buffer_subrange(const struct net2_buffer *b, size_t off, size_t len)
{
	struct net2_buffer		*dst;
	struct net2_buffer_segment	*list;
	struct net2_buffer_ptr		 start, end;
	size_t				 listlen;

	/* Create a new buffer. */
	if ((dst = net2_buffer_new()) == NULL)
		goto fail_0;
	list = dst->list;

	/*
	 * If the length is 0, ensure no failure even if off points to the
	 * end of b.
	 */
	start = net2_buffer_ptr0;
	if (len == 0) {
		/* Check that off doesn't point past the end. */
		if (off != 0 && net2_buffer_ptr_advance(b, &start, off - 1))
			goto fail_1;
		return dst;
	}

	/* Calculate which segments need copying and start/end offsets. */
	if (net2_buffer_ptr_advance(b, &start, off))
		goto fail_1;
	end = start;
	if (net2_buffer_ptr_advance(b, &end, len - 1))
		goto fail_1;
	/* Manually adjust end to one-past-the-end (array semantics). */
	end.pos++;
	end.off++;

	/* Calculate destination listlen. */
	listlen = end.segment - start.segment + 1;
	/* Allocate storage. */
	if ((list = realloc(list, listlen * sizeof(*list))) == NULL)
		goto fail_1;
	dst->list = list;

	/* Validate algorithm. */
	assert(end.segment < b->listlen);
	assert(start.segment + listlen <= b->listlen);
	assert(listlen > 0);

	/* Copy segments. */
	assert(dst->listlen == 0);
	for (dst->listlen = 0; dst->listlen < listlen; dst->listlen++) {
		assert(start.segment + dst->listlen < b->listlen);
		segment_init_copy(&list[dst->listlen],
		    &b->list[start.segment + dst->listlen]);
	}

	/*
	 * Drain the first and truncate the last segment to match.
	 *
	 * We truncate before draining, since the result may be only a
	 * single segment. In which case truncating won't affect the drain,
	 * but the drain would affect the truncation.
	 */
	segment_trunc(&list[dst->listlen - 1], end.off);
	segment_drain(&list[0], start.off);

	ASSERTBUFFER(dst);
	return dst;

fail_1:
	net2_buffer_free(dst);
fail_0:
	return NULL;
}

/*
 * Truncate a buffer to maxlen.
 *
 * If the buffer is shorter than maxlen, no action takes place.
 */
ILIAS_NET2_EXPORT void
net2_buffer_truncate(struct net2_buffer *b, size_t maxlen)
{
	struct net2_buffer_segment	*list;
	size_t				 listlen, avail, lastlen, i;

	list = b->list;
	avail = maxlen;
	lastlen = 0;
	for (listlen = 0; avail > 0 && listlen < b->listlen; listlen++) {
		if (avail <= list[listlen].len) {
			lastlen = avail;
			avail = 0;
		} else
			avail -= list[listlen].len;
	}

	/* Buffer is already shorter than maxlen. */
	if (avail > 0)
		return;

	/* Truncate partial segment. */
	if (listlen > 0)
		segment_trunc(&list[listlen - 1], lastlen);

	/* Throw away segments that are no longer used. */
	while (b->listlen > listlen)
		segment_deinit(&list[--b->listlen]);

	/* Attempt to conserve memory. */
	if ((list = realloc(list, listlen * sizeof(*list))) != NULL)
		b->list = list;

	ASSERTBUFFER(b);
}


#ifndef NDEBUG
static void
buffer_is_valid(struct net2_buffer *b, const char *fun, int line,
    const char *var)
{
	size_t				 i;
	int				 fail = 0;

	/* Segments may not be empty. */
	for (i = 0; i < b->listlen; i++) {
		if (b->list[i].len <= 0) {
			fail++;
			warnx("  %s() at %d -- %s: list[%lu].len = %lu\n",
			    fun, line, var, (unsigned long)i,
			    (unsigned long)b->list[i].len);
		}
	}

	if (fail)
		abort();
}
#endif /* NDEBUG */
