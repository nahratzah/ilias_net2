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
#ifndef ILIAS_NET2_BUFFER_H
#define ILIAS_NET2_BUFFER_H
/*
 * Additional support functions for libevents buffers.
 */

#include <ilias/net2/ilias_net2_export.h>
#include <sys/types.h>
#include <stdint.h>

#ifdef WIN32
struct iovec {
	void	*iov_base;
	size_t	 iov_len;
};
#else
#include <sys/uio.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

ILIAS_NET2_EXPORT struct evbuffer	*net2_copybuffer(struct evbuffer*);


#ifdef __cplusplus
}
#endif


struct net2_buffer;

/*
 * A pointer in a buffer.
 *
 * Safe to copy via simple struct assignment.
 * May be invalidated on operations that modify the buffer.
 */
struct net2_buffer_ptr {
	size_t		 pos;
	size_t		 segment;
	size_t		 off;
};

/* A buffer pointer that points at position 0. */
extern ILIAS_NET2_EXPORT const struct net2_buffer_ptr
			 net2_buffer_ptr0;

ILIAS_NET2_EXPORT
struct net2_buffer	*net2_buffer_new();
ILIAS_NET2_EXPORT
void			 net2_buffer_free(struct net2_buffer*);
ILIAS_NET2_EXPORT
struct net2_buffer	*net2_buffer_copy(const struct net2_buffer*);
ILIAS_NET2_EXPORT
int			 net2_buffer_add(struct net2_buffer*,
			    const void*, size_t);
ILIAS_NET2_EXPORT
int			 net2_buffer_add_reference(struct net2_buffer*, void*, size_t,
			    void (*)(void*), void*);
ILIAS_NET2_EXPORT
int			 net2_buffer_append(struct net2_buffer*,
			    const struct net2_buffer*);
ILIAS_NET2_EXPORT
int			 net2_buffer_prepend(struct net2_buffer*,
			    const struct net2_buffer*);
ILIAS_NET2_EXPORT
void			*net2_buffer_pullup(struct net2_buffer*, size_t);
ILIAS_NET2_EXPORT
size_t			 net2_buffer_length(const struct net2_buffer*);
ILIAS_NET2_EXPORT
int			 net2_buffer_empty(const struct net2_buffer*);

ILIAS_NET2_EXPORT
size_t			 net2_buffer_peek(const struct net2_buffer*, size_t,
			    struct iovec*, size_t);

ILIAS_NET2_EXPORT
size_t			 net2_buffer_copyout(const struct net2_buffer*,
			    void*, size_t);
ILIAS_NET2_EXPORT
size_t			 net2_buffer_remove(struct net2_buffer*,
			    void*, size_t);
#define net2_buffer_drain(buf, len)					\
			 net2_buffer_remove((buf), (void*)0, (len))
ILIAS_NET2_EXPORT
void			 net2_buffer_truncate(struct net2_buffer*, size_t);
ILIAS_NET2_EXPORT
size_t			 net2_buffer_remove_buffer(struct net2_buffer*,
			    struct net2_buffer*, size_t);

ILIAS_NET2_EXPORT
int			 net2_buffer_ptr_advance(const struct net2_buffer*,
			    struct net2_buffer_ptr*, size_t);
ILIAS_NET2_EXPORT
int			 net2_buffer_search(const struct net2_buffer*,
			    struct net2_buffer_ptr*,
			    const void*, size_t, struct net2_buffer_ptr*);

ILIAS_NET2_EXPORT
int			 net2_buffer_cmp(const struct net2_buffer*,
			    const struct net2_buffer*);

ILIAS_NET2_EXPORT
int			 net2_buffer_reserve_space(struct net2_buffer*,
			    size_t, struct iovec*, size_t*);
ILIAS_NET2_EXPORT
int			 net2_buffer_commit_space(struct net2_buffer*,
			    struct iovec*, size_t);

ILIAS_NET2_EXPORT
char			*net2_buffer_hex(const struct net2_buffer*,
			    void *(*)(size_t));

ILIAS_NET2_EXPORT
struct net2_buffer	*net2_buffer_subrange(const struct net2_buffer*,
			    size_t, size_t);

ILIAS_NET2_EXPORT
int			 net2_buffer_sensitive(struct net2_buffer*);

#endif /* ILIAS_NET2_BUFFER_H */
