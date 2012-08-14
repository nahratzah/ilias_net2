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
#include <ilias/net2/memory.h>

#ifdef MEMDEBUG

#include <ilias/net2/config.h>
#ifdef HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include <ilias/net2/bsd_compat/tree.h>
#endif
#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include <ilias/net2/bsd_compat/queue.h>
#endif
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/siginfo.h>
#include <signal.h>
#include <stdarg.h>

struct malloc_data {
	RB_ENTRY(malloc_data)	 tree;
	TAILQ_ENTRY(malloc_data) lru;

	/* Last allocation when? */
	struct {
		const char	*file;
		const char	*func;
		int		 line;
	}			 when,
				 when_free;

	void			*addr;
	size_t			 size,
				 szpg;
	int			 free;

	/* Memory was realloced into new d. */
	struct malloc_data	*realloc,
				*realloc_from;
};

static __inline int
malloc_data_cmp(struct malloc_data *l, struct malloc_data *r)
{
	return (l->addr < r->addr ? -1 : l->addr > r->addr);
}

static RB_HEAD(mdata_tree, malloc_data)	 data;
static TAILQ_HEAD(, malloc_data)	 lru;
static size_t				 lru_size;
static pthread_mutex_t			 mtx;
static uintptr_t			 page_size;
static int				 unused_mem_fd;

static int init_fault();
static void deinit_fault();

RB_PROTOTYPE_STATIC(mdata_tree, malloc_data, tree, malloc_data_cmp)

#define TEMPLATE		"/tmp/ilias_net2_mem.XXXXXX"

static void
print_malloc_data(const struct malloc_data *d)
{
	const struct malloc_data	*past;
	char				*alloc_str;

	if (d == NULL) {
		fprintf(stderr,
		    "No memory range describes the error point.\n");
		return;
	}

	/* Note that we are starting to print memory log. */
	fprintf(stderr, "Printing memory tracking log...\n");

	/* Find the first place where this range was allocated. */
	past = d;
	while (past->realloc_from != NULL)
		past = past->realloc_from;

	/* Print allocations in chronological order. */
	for (; past != NULL; past = past->realloc) {
		alloc_str = (past->realloc_from == NULL ?
		    "malloc" : "realloc");

		fprintf(stderr, "\t%s(%lu bytes) at %s:%d %s()\t->%p\n",
		    alloc_str, (unsigned long)past->size,
		    past->when.file, past->when.line, past->when.func, past->addr);
		if (past == d)
			fprintf(stderr, "\t\t*** This was the failing range "
			    "of memory ***\n");
		if (past->free) {
			fprintf(stderr, "\t\tfreed at %s:%d %s()\n",
			    past->when_free.file, past->when_free.line, past->when_free.func);
		} else
			fprintf(stderr, "\t\tnever freed\n");
	}

	fprintf(stderr, "End of memory tracking log.\n");
}

/* Print where an error occured. */
static void
fatal(const struct malloc_data *d,
    const char *file, const char *func, int line, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	fprintf(stderr, "\n\nMemory error at %s:%d %s()\t", file, line, func);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	print_malloc_data(d);

	abort();
}
/* Print where an errno occured. */
static void
fatal_errno(const struct malloc_data *d,
    const char *file, const char *func, int line, const char *fmt, ...)
{
	va_list	ap;
	int	error = errno;
	char	buf[128];

	strerror_r(error, buf, sizeof(buf));

	va_start(ap, fmt);
	fprintf(stderr, "\n\nMemory error at %s:%d %s()\t%s\n\t", file, line, func, buf);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	print_malloc_data(d);

	abort();
}

/*
 * Allocate memory mutex.
 *
 * Note: this is before ilias_net2 uses any threads.
 */
ILIAS_NET2_LOCAL int
net2_memory_init()
{
	int		 sc_pagesize;
	int		 saved_errno;
	char		*template;

	if ((sc_pagesize = sysconf(_SC_PAGESIZE)) == -1) {
		saved_errno = errno;
		perror("failed to figure out page size");
		return saved_errno;
	}

	page_size = sc_pagesize;

	/* Copy template name. */
	if ((template = strdup(TEMPLATE)) == NULL)
		return ENOMEM;
	/* Create temporary file. */
	unused_mem_fd = mkstemp(template);
	if (unused_mem_fd == -1) {
		saved_errno = errno;
		free(template);
		perror("failed to create temporary file for allocator");
		return saved_errno;
	}
	unlink(template);
	free(template);

	/* Write pagesize bytes to the temporary file. */
	if (pwrite(unused_mem_fd, "", 1, page_size - 1) == -1) {
		saved_errno = errno;
		perror("growing unused memory file to span a page failed");
		return saved_errno;
	}

	RB_INIT(&data);
	TAILQ_INIT(&lru);
	lru_size = 0;
	if ((saved_errno = pthread_mutex_init(&mtx, NULL)) != 0) {
		errno = saved_errno;
		perror("failed to init mutex");
		close(unused_mem_fd);
		return saved_errno;
	}

	fprintf(stderr, "ilias_net: use after free memory debugger ready\n");

	return init_fault();
}

/*
 * Free memory mutex.
 *
 * Note: this is after ilias_net2 uses any threads.
 */
ILIAS_NET2_LOCAL void
net2_memory_fini()
{
	struct malloc_data	*d, *d_next;

	pthread_mutex_lock(&mtx);
	deinit_fault();

	fprintf(stderr, "ilias_net: use after free memory debugger shutting down\n");
	close(unused_mem_fd);
	unused_mem_fd = -1;

	/* Expire left over freed memory. */
	while ((d = RB_ROOT(&data)) != NULL) {
		/* Find the last point in allocation. */
		while (d->realloc != NULL)
			d = d->realloc;
		/* Inform memory leak detection. */
		if (!d->free) {
			fprintf(stderr, "Memory leak detected!\n");
			print_malloc_data(d);
		}

		/* Remove chain from sets. */
		while (d != NULL) {
			d_next = d->realloc_from;
			if (d->free)
				TAILQ_REMOVE(&lru, d, lru);
			RB_REMOVE(mdata_tree, &data, d);
			d = d_next;
		}
	}
	pthread_mutex_unlock(&mtx);

	pthread_mutex_destroy(&mtx);
	fprintf(stderr, "ilias_net: use after free memory debugger closed\n");
}


/* Internal allocator. Memory is zeroed if zero is set. */
static struct malloc_data*
i_malloc(size_t sz, int zero, const char *file, const char *func, int line)
{
	size_t			 szpg;
	struct malloc_data	*d;

	if ((d = calloc(1, sizeof(*d))) == NULL)
		return NULL;

	/* szpg is sz, rounded up to whole pages. */
	assert(page_size > 0);
	if (sz == 0)
		szpg = page_size;
	else
		szpg = (sz + (page_size - 1)) & ~(page_size - 1);

	d->addr = mmap(NULL, szpg, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
	if (d->addr == MAP_FAILED) {
		free(d);
		return NULL;
	}
	d->size = sz;
	d->szpg = szpg;

	memset(d->addr, 0x17, szpg);
	if (zero)
		memset(d->addr, 0, sz);
	if (sz == 0)
		mprotect(d->addr, page_size, PROT_NONE);

	d->when.file = file;
	d->when.func = func;
	d->when.line = line;

	RB_INSERT(mdata_tree, &data, d);
	return d;
}
/* Find description of memory at addr. */
static struct malloc_data*
i_lookup(void *addr, const char *file, const char *func, int line)
{
	struct malloc_data	*d, search;

	/* szpg is sz, rounded up to whole pages. */
	search.addr = addr;

	/* Look up description for memory at addr. */
	d = RB_FIND(mdata_tree, &data, &search);
	if (d == NULL)
		fatal(d, file, func, line, "Attempt to free memory at %p, "
		    "that was never allocated.", addr);
	/* Test if the memory is not freed. */
	if (d->free)
		fatal(d, file, func, line, "Duplicate free of %p.", addr);

	return d;
}
/* Free memory at addr. */
static void
i_free(struct malloc_data *d, const char *file, const char *func, int line)
{
	size_t			 szpg;

	assert(d != NULL && !d->free);

	/*
	 * Map unused_mem_fd into the area
	 * described by the original allocation.
	 */
	for (szpg = 0; szpg < d->szpg; szpg += page_size) {
		if (mmap((char*)d->addr + szpg, page_size, PROT_NONE,
		    MAP_FILE | MAP_SHARED | MAP_FIXED, unused_mem_fd, 0) ==
		    MAP_FAILED) {
			fatal_errno(d, file, func, line,
			    "mmap unused mem file into free space");
		}
	}

	/* Mark d as freed. */
	TAILQ_INSERT_TAIL(&lru, d, lru);
	d->free = 1;
	d->when_free.file = file;
	d->when_free.func = func;
	d->when_free.line = line;
}
/* Realloc memory at addr. */
struct malloc_data*
i_realloc(void *addr, size_t sz, const char *file, const char *func, int line)
{
	struct malloc_data	*d, *repl;

	/* Find original entry and create replacement memory. */
	d = i_lookup(addr, file, func, line);
	repl = i_malloc(sz, 0, file, func, line);
	if (repl == NULL)
		return NULL;

	/* Copy data. */
	if (d->size > 0)
		memcpy(repl->addr, d->addr, d->size);

	/* Mark old memory as free. */
	i_free(d, file, func, line);

	/* Mark operation as reallocation. */
	d->realloc = repl;
	repl->realloc_from = d;
	return repl;
}

/*
 * Print info about memory involved in a fault.
 */
static void
i_fault(uintptr_t addr, const char *fault_descr)
{
	const struct malloc_data	*mem, *best;
	uintptr_t	best_dst;

	/* Inform user that fault handler has been invoked. */
	fprintf(stderr, "\n\nMemory error accessing %p: %s\n",
	    (void*)addr, fault_descr);

	/* Find the memory access describing the fault memory. */
	best_dst = (uintptr_t)-1;
	best = NULL;
	mem = RB_ROOT(&data);
	while (mem != NULL) {
		if (addr < (uintptr_t)mem->addr) {
			if ((uintptr_t)mem->addr - addr < best_dst) {
				best_dst = (uintptr_t)mem->addr - addr;
				best = mem;
			}
			mem = RB_LEFT(mem, tree);
		} else if (addr >= (uintptr_t)mem->addr + mem->size) {
			if (addr - ((uintptr_t)mem->addr + mem->size) < best_dst) {
				best_dst = addr - ((uintptr_t)mem->addr + mem->size);
				best = mem;
			}
			mem = RB_LEFT(mem, tree);
		} else
			break;
	}
	if (mem == NULL) {
		if (best == NULL) {
			fprintf(stderr, "No memory debug data available.\n");
			return;
		}

		fprintf(stderr, "No memory debug data tracks this address, "
		    "closest match:\n\t%p (%llu bytes away)\n",
		    best->addr, (unsigned long long)best_dst);
		mem = best;
	}

	print_malloc_data(mem);
}


#define LOCK()		pthread_mutex_lock(&mtx)
#define UNLOCK()	pthread_mutex_unlock(&mtx)

/*
 * Wrappers around exude allocators.
 *
 * These provide exclusion using exude_mtx as declared and initialized above.
 */

ILIAS_NET2_LOCAL void*
net2_malloc_(size_t s, const char *file, const char *function, int line)
{
	struct malloc_data	*d;
	void			*p;

	LOCK();
	d = i_malloc(s, 0, file, function, line);
	p = (d == NULL ? NULL : d->addr);
	UNLOCK();
	return p;
}

ILIAS_NET2_LOCAL void*
net2_realloc_(void *p, size_t s, const char *file, const char *function, int line)
{
	struct malloc_data	*d;

	LOCK();
	if (p == NULL) {
		if (s == 0)
			d = NULL;
		else
			d = i_malloc(s, 0, file, function, line);
	} else if (s == 0) {
		i_free(i_lookup(p, file, function, line), file, function, line);
		d = NULL;
	} else
		d = i_realloc(p, s, file, function, line);
	p = (d == NULL ? NULL : d->addr);
	UNLOCK();
	return p;
}

ILIAS_NET2_LOCAL void*
net2_calloc_(size_t n, size_t es, const char *file, const char *function, int line)
{
	void			*p;
	size_t			 s;
	struct malloc_data	*d;

	if (SIZE_MAX / es < n)
		return NULL;
	s = n * es;

	LOCK();
	d = i_malloc(s, 1, file, function, line);
	p = (d == NULL ? NULL : d->addr);
	UNLOCK();
	return p;
}

ILIAS_NET2_LOCAL char*
net2_strdup_(const char *s, const char *file, const char *function, int line)
{
	char			*p;

	assert(s != NULL);
	if ((p = net2_malloc_(strlen(s) + 1, file, function, line)) == NULL)
		return NULL;
	strcpy(p, s);
	return p;
}

ILIAS_NET2_LOCAL void
net2_free_(void *p, const char *file, const char *function, int line)
{
	if (p == NULL)
		return;

	LOCK();
	i_free(i_lookup(p, file, function, line), file, function, line);
	UNLOCK();
}


/*
 * Signal handler for fault.
 */
void
i_fault_handler(int sig ILIAS_NET2__unused, siginfo_t *sip,
    void *scp ILIAS_NET2__unused)
{
	static char	 buf[64];
	char		*descr;
	uintptr_t	 addr;
	int		 saved_errno;

	saved_errno = errno;

	/* Decode error type. */
	switch (sip->si_code) {
	case SEGV_MAPERR:
		descr = "Access to unmapped memory.";
		break;
	case SEGV_ACCERR:
		descr = "Access permission error.";
		break;
	default:
		descr = buf;
		snprintf(buf, sizeof(buf), "Unrecognized si_code %d",
		    sip->si_code);
	}

	/* Decode address. */
	addr = (uintptr_t)sip->si_addr;

	LOCK();

	/* Print data about error. */
	i_fault(addr, descr);

	UNLOCK();

	/* Restore errno (may aid in coredump analysis). */
	errno = saved_errno;

	/* Abort. */
	abort();
}

/* Set up fault handler. */
static int
init_fault()
{
	struct sigaction sa;
	int	saved_errno;

	bzero(&sa, sizeof(sa));
	sa.sa_sigaction = &i_fault_handler;
	sa.sa_mask = 0;
	sa.sa_flags = SA_NODEFER | SA_RESETHAND | SA_SIGINFO;
	if (sigaction(SIGSEGV, &sa, NULL) == 0)
		return 0;

	saved_errno = errno;
	perror("sigaction(SIGSEGV)");
	return saved_errno;
}
/* Clear the fault handler. */
static void
deinit_fault()
{
	struct sigaction sa;

	bzero(&sa, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	sigaction(SIGSEGV, &sa, NULL);
}

RB_GENERATE_STATIC(mdata_tree, malloc_data, tree, malloc_data_cmp)

#endif /* NET2_MEMDEBUG */
