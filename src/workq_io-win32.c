#include <ilias/net2/workq_io.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/datapipe.h>
#include <ilias/net2/ll.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/promise.h>
#include <ilias/net2/semaphore.h>
#include <ilias/net2/bsd_compat/minmax.h>
#include <ilias/net2/connection.h> // XXX error should be in different header.
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#include <process.h>
#include <errno.h>
#include <stdio.h>/* DEBUG */


/* Type of IOCP. */
enum iocp_kind {
	IOCP_INVALID,
	IOCP_RX,	/* RX iocp. */
	IOCP_TX		/* TX iocp. */
};
/* Basic iocp used by workq_io. */
struct iocp {
	enum iocp_kind		 kind;		/* IOCP type. */
	struct net2_workq_io	*io;		/* IO. */
	OVERLAPPED		 overlapped;	/* Overlapped struct. */
};

/* Receive iocp. */
struct iocp_rx {
	struct iovec		 buf_iovec[64];	/* Buffer iovec. */
	struct net2_datapipe_in_prepare
				 prep;		/* Prepared input. */
	struct iocp		 base;		/* Shared data. */
	struct net2_dgram_rx	*rx;		/* Receive buffer. */
	size_t			 iovec_cnt;	/* # iovec in use. */
	LL_ENTRY(iocp_rx)	 q;
};
/* Transmit iocp. */
struct iocp_tx {
	struct net2_datapipe_out_prepare
				 prep;		/* Prepared output. */
	struct iocp		 base;		/* Shared data. */
	struct net2_promise	*completed_prom; /* TX done promise. */
	struct net2_promise	*prom;		/* Promise from prep. */
	LL_ENTRY(iocp_tx)	 q;
};

/* Translate from WSAOVERLAPPED to iocp. */
static __inline struct iocp*
overlapped2iocp(OVERLAPPED *overlapped)
{
#define OFFSET	((size_t)(&((struct iocp*)0)->overlapped))
	struct iocp		*iocp;

	iocp = (struct iocp*)((uintptr_t)overlapped - OFFSET);
	assert(&iocp->overlapped == overlapped);
	return iocp;
#undef OFFSET
}
/* Convert base iocp to iocp_rx. */
static __inline struct iocp_rx*
iocp2rx(struct iocp *iocp)
{
#define OFFSET	((size_t)(&((struct iocp_rx*)0)->base))
	assert(iocp->kind == IOCP_RX);
	return (struct iocp_rx*)((uintptr_t)iocp - OFFSET);
#undef OFFSET
}
/* Convert base iocp to iocp_tx. */
static __inline struct iocp_tx*
iocp2tx(struct iocp *iocp)
{
#define OFFSET	((size_t)(&((struct iocp_tx*)0)->base))
	assert(iocp->kind == IOCP_TX);
	return (struct iocp_tx*)((uintptr_t)iocp - OFFSET);
#undef OFFSET
}

/* Thread name exception (MSVC debugger listens to this). */
static const DWORD MS_VC_EXCEPTION = 0x406D1388;

#pragma pack(push,8)
typedef struct tagTHREADNAME_INFO
{
	DWORD dwType; // Must be 0x1000.
	LPCSTR szName; // Pointer to name (in user addr space).
	DWORD dwThreadID; // Thread ID (-1=caller thread).
	DWORD dwFlags; // Reserved for future use, must be zero.
} THREADNAME_INFO;
#pragma pack(pop)

static __inline void
SetThreadName(DWORD dwThreadID, char *threadName)
{
	THREADNAME_INFO info;
	info.dwType = 0x1000;
	info.szName = threadName;
	info.dwThreadID = dwThreadID;
	info.dwFlags = 0;

	__try
	{
		RaiseException(MS_VC_EXCEPTION, 0,
		    sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
}

LL_HEAD(iocp_rx_list, iocp_rx);
LL_HEAD(iocp_tx_list, iocp_tx);
LL_GENERATE(iocp_rx_list, iocp_rx, q);
LL_GENERATE(iocp_tx_list, iocp_tx, q);

struct net2_workq_io {
	/* TX datapipe, accepts promise of net2_dgram_tx_promdata. */
	struct net2_datapipe_in	*tx;
	/* RX datapipe, generates net2_dgram_rx. */
	struct net2_datapipe_out*rx;
	/* Internal half of the TX datapipe. */
	struct net2_datapipe_out*tx_internal;
	/* Internal half of the RX datapipe. */
	struct net2_datapipe_in	*rx_internal;

	struct net2_workq_io_container
				*container;	/* Associated io container. */
	SOCKET			 socket;	/* Operational socket. */

	struct iocp_rx_list	 rx_act;	/* Active RX iocps. */
	struct iocp_tx_list	 tx_act;	/* Active TX iocps. */

	struct net2_datapipe_event
				 rx_avail_ev,	/* Datapipe wakeup. */
				 tx_avail_ev;	/* Datapipe wakeup. */

	LL_ENTRY(net2_workq_io)	 redo;

	atomic_int		 dying;		/* Set by destructor. */
	atomic_size_t		 refcnt;	/* Reference counter. */

	struct net2_workq_evbase*wqev;		/* Event base owner. */
};

/*
 * Because iocp are aborted (failed) when the thread creating them exits,
 * only the dedicated thread in this function may start new iocps.
 * To that end, the redo_list on container will contain every net2_workq_io
 * that needs tx/rx iocps started.
 *
 * The thread-local thr_container is used to detect if the current thread
 * is the appropriate worker thread for a given container.
 */
LL_HEAD(redo_list, net2_workq_io);
LL_GENERATE(redo_list, net2_workq_io, redo);
static __declspec(thread) struct net2_workq_io_container *thr_container;

struct net2_workq_io_container {
	HANDLE			 iocp;		/* IO completion port. */
	HANDLE			 iocp_event;	/* IOCP ready. */
	HANDLE			 destroy_wait;	/* Destructor event. */
	HANDLE			 thread;	/* Worker thread. */
	HANDLE			 redo_event;	/* Redo queue avail. */
	struct redo_list	 redo;		/* IOCP creation queue. */
};


static int	start_rx(struct net2_workq_io*, struct iocp_rx*);
static void	do_rx(struct iocp_rx*, unsigned long);
static void	dp_rx_ev(void*, void*);
static void	do_tx(struct iocp_tx*, unsigned long);
static void	dp_tx_ev(void*, void*);
static int	do_iocp(struct net2_workq_io_container*, HANDLE, unsigned int);
static void	rxfree(void*, void*);
static void	handle_iocp_wait(struct net2_workq_io_container*, unsigned int,
		    unsigned int);
static unsigned int __stdcall
		worker(void*);
static void	link_redo_io(struct net2_workq_io_container*,
		    struct net2_workq_io*);


/*
 * Test if the current thread may start iocp for this io.
 *
 * If false, the io is added to the redo list in the container.
 */
static __inline BOOL
start_io(struct net2_workq_io *io)
{
	struct net2_workq_io_container	*c;

	c = io->container;

	/* Abort early if the io is dying. */
	if (atomic_load_explicit(&io->dying, memory_order_acquire))
		return FALSE;

	/*
	 * Allow progress if this is the worker thread calling.
	 * In windows, each IOCP is bound to the lifetime of the thread
	 * that initiates it.
	 * For this reason, only the worker thread of the container may start
	 * new IOCP (since it is the only thread that will live at least as
	 * long as the container.
	 */
	if (thr_container == c)
		return TRUE;

	/*
	 * If the operation may not continue, link the io into the REDO list.
	 * The worker thread will pick it up and re-issue any tx/rx iocp calls.
	 * Note that this call has special handling against redoing a dying io.
	 */
	link_redo_io(c, io);
	return FALSE;
}


/* Create a new io container. */
ILIAS_NET2_LOCAL struct net2_workq_io_container*
net2_workq_io_container_new()
{
	struct net2_workq_io_container
				*c;
	unsigned int		 tid;

	if ((c = net2_malloc(sizeof(*c))) == NULL)
		goto fail_0;
	if ((c->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL,
	    0, 0)) == NULL)
		goto fail_1;
	if ((c->iocp_event = CreateEvent(NULL, FALSE, FALSE, NULL)) == NULL)
		goto fail_2;
	if ((c->destroy_wait = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL)
		goto fail_3;
	if ((c->redo_event = CreateEvent(NULL, FALSE, FALSE, NULL)) == NULL)
		goto fail_4;

	LL_INIT(&c->redo);

	if ((c->thread = (HANDLE)_beginthreadex(NULL, 0, &worker, c,
	    0, &tid)) == (HANDLE)-1)
		goto fail_5;

	SetThreadName(tid, "io worker thread");

	return c;


fail_5:
	CloseHandle(c->redo_event);
fail_4:
	CloseHandle(c->destroy_wait);
fail_3:
	CloseHandle(c->iocp_event);
fail_2:
	CloseHandle(c->iocp);
fail_1:
	net2_free(c);
fail_0:
	return NULL;
}
/* Destroy an io container. */
ILIAS_NET2_LOCAL void
net2_workq_io_container_destroy(struct net2_workq_io_container *c)
{
	/* Stop worker before closing handle. */
	int error = SignalObjectAndWait(c->destroy_wait, c->thread,
	    INFINITE, FALSE);
	while (error != WAIT_OBJECT_0) {
		switch (error) {
		default:
		case WAIT_ABANDONED:
		case WAIT_FAILED:
			abort();
			break;
		case WAIT_TIMEOUT:
		case WAIT_IO_COMPLETION:
			error = WaitForSingleObject(c->thread, INFINITE);
			break;
		}
	}

	CloseHandle(c->redo_event);
	CloseHandle(c->iocp);
	CloseHandle(c->iocp_event);
	CloseHandle(c->destroy_wait);
	CloseHandle(c->thread);
	net2_free(c);
}

/*
 * Start an iocp rx.
 * All allocations are done in advance.
 * Newly created iocp_rx is placed on io->rx_act.
 *
 * If rx is not null, it is pre-allocated but uninitialized.
 * This function will take ownership of rx, regardless of succes
 * or failure.
 *
 * Errors:
 * EINTR	-- completion is queued on worker thread.
 * ENOMEM	-- insufficient memory to start iocp.
 * EINVAL	-- socket is invalid.
 * EAGAIN	-- rx queue is full.
 */
static int
start_rx(struct net2_workq_io *io, struct iocp_rx *rx)
{
	int			 error, wsa_error, commited = 0;

	/* Argument check. */
	assert(io != NULL);

	/* Test if we are allowed to start iocp in this thread. */
	if (!start_io(io)) {
		if (rx != NULL)
			net2_free(rx);
		return EINTR;
	}

	/* Acquire a reference to io. */
	atomic_fetch_add_explicit(&io->refcnt, 1, memory_order_acquire);

	/* Allocate rx. */
	if (rx == NULL && (rx = net2_malloc(sizeof(*rx))) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	rx->base.io = io;
	rx->base.kind = IOCP_RX;
	SecureZeroMemory(&rx->base.overlapped,
	    sizeof(rx->base.overlapped));
	rx->base.overlapped.hEvent = io->container->iocp_event;

	/* Prepare an insert on the datapipe. */
	if ((error = net2_dp_push_prepare(&rx->prep, io->rx_internal)) != 0) {
		assert(error != EINVAL);
		goto fail_1;
	}

	/* Prepare net2_dgram_rx result. */
	if ((rx->rx = net2_malloc(sizeof(*rx->rx))) == NULL) {
		error = ENOMEM;
		goto fail_2;
	}
	memset(&rx->rx->addr, 0, sizeof(rx->rx->addr));
	rx->rx->addrlen = sizeof(rx->rx->addr);
	rx->rx->error = 0;
	if ((rx->rx->data = net2_buffer_new()) == NULL) {
		error = ENOMEM;
		goto fail_3;
	}

	/* Prepare space in the buffer. */
	rx->iovec_cnt = sizeof(rx->buf_iovec) / sizeof(rx->buf_iovec[0]);
	if (net2_buffer_reserve_space(rx->rx->data, NET2_WORKQ_IO_MAXLEN,
	    rx->buf_iovec, &rx->iovec_cnt) != 0) {
		error = ENOMEM;
		goto fail_4;
	}
	assert(rx->iovec_cnt > 0);

	/* Create IOCP call. */
	LL_REF(iocp_rx_list, &io->rx_act, rx);
	LL_INSERT_TAIL(iocp_rx_list, &io->rx_act, rx);
	error = WSARecvFrom(io->socket, rx->buf_iovec, rx->iovec_cnt, NULL, NULL,
	    (struct sockaddr*)&rx->rx->addr, &rx->rx->addrlen,
	    &rx->base.overlapped, NULL);
	if (error == SOCKET_ERROR)
		wsa_error = WSAGetLastError();
	assert(error == 0 || error == SOCKET_ERROR);
	/* Change WSA_IO_PENDING to no-error, since this is what we want. */
	if (error == SOCKET_ERROR && wsa_error == WSA_IO_PENDING)
		error = 0;
	/* Add to activity list iff succesful. */
	if (error == 0)
		LL_RELEASE(iocp_rx_list, &io->rx_act, rx);
	else
		LL_UNLINK(iocp_rx_list, &io->rx_act, rx);

	/* Handle WSA error. */
	if (error == SOCKET_ERROR) {
		error = EAGAIN;

		switch (wsa_error) {
		case WSA_IO_PENDING:
			/* Not an error:
			 * this means the RecvFrom is pending.
			 *
			 * Note that we excluded this above. */
			assert(0);
			break;
		case WSAENOTCONN:	/* Socket is not connected. */
		case WSANOTINITIALISED:	/* Winsock uninitialized. */
		case WSAEFAULT:		/* Address error. */
			assert(0);
			/* FALLTHROUGH */
		case WSA_OPERATION_ABORTED: /* Socket is closing. */
		case WSAEWOULDBLOCK:	/* Too many iocps. */
		case WSAEINPROGRESS:
		case WSAEINTR:
		default:		/* Undocumented. */
			/* Someone is mucking about on our socket. */
			break;
		case WSAEINVAL:		/* Socket in invalid state. */
		case WSAECONNRESET:	/* Connection lost. */
		case WSAEMSGSIZE:	/* XXX Packet too large? */
		case WSAENETDOWN:	/* RIP network layer. */
		case WSAENETRESET:	/* TTL expiry (huh?) */
			/* Assign error code and deliver error. */
			net2_buffer_free(rx->rx->data);
			rx->rx->data = NULL;
			rx->rx->error = NET2_CONNRECV_REJECT;
			net2_dp_push_commit(&rx->prep, rx->rx);
			rx->rx = NULL;
			commited = 1;
			break;
		}

		goto fail_4;
	}

	return 0;


fail_4:
	if (rx->rx != NULL)
		net2_buffer_free(rx->rx->data);
fail_3:
	if (rx->rx != NULL)
		net2_free(rx->rx);
fail_2:
	if (!commited)
		net2_dp_push_rollback(&rx->prep);
fail_1:
	net2_free(rx);
fail_0:
	assert(error != 0);
	/* Release our reference to io. */
	atomic_fetch_sub_explicit(&io->refcnt, 1, memory_order_acquire);
	return error;
}
/* Handle rx completion. */
static void
do_rx(struct iocp_rx *rx, unsigned long bytes)
{
	size_t			 i;
	int			 error;
	struct net2_workq_io	*io;

	assert(rx->base.kind == IOCP_RX);
	io = rx->base.io;

	/* Unlink rx. This may never fail. */
	{
		struct iocp_rx *unlinked;

		LL_REF(iocp_rx_list, &io->rx_act, rx);
		unlinked = LL_UNLINK(iocp_rx_list, &io->rx_act, rx);
		assert(unlinked == rx);
	}

	/*
	 * Figure out the number of iovec that needs to be commited
	 * to the buffer.  Also truncate the iov_len properly.
	 */
	for (i = 0; bytes > 0 && i < rx->iovec_cnt; i++) {
		if (rx->buf_iovec[i].iov_len > bytes)
			rx->buf_iovec[i].iov_len = bytes;
		bytes -= rx->buf_iovec[i].iov_len;
	}
	assert(bytes == 0);

	/* Commit reserved space. */
	if (net2_buffer_commit_space(rx->rx->data, rx->buf_iovec, i) != 0) {
		/* Eep, commit failure! */
		abort();	/* XXX think of a way to avoid this. */
	}

	/* Push received data into the datapipe. */
	error = net2_dp_push_commit(&rx->prep, rx->rx);	/* Never fails. */
	assert(error == 0);
	rx->rx = NULL;

	/*
	 * rx holds no more relevant data,
	 * try to start a new rx iocp using it.
	 * (This will free rx if that didn't work out.)
	 */
	start_rx(rx->base.io, rx);

	/* Release our reference to io. */
	atomic_fetch_sub_explicit(&io->refcnt, 1, memory_order_release);
}
/* RX datapipe input event. */
static void
dp_rx_ev(void *io_ptr, void *unused ILIAS_NET2__unused)
{
	struct net2_workq_io *io = (struct net2_workq_io*)io_ptr;

	/* Add as many rx as possible. */
	while (start_rx(io, NULL) == 0);
}

/*
 * Start a tx iocp.
 * If tx is not null, it will be claimed by this function.
 *
 * Errors:
 * EINTR	-- completion is queued on worker thread.
 * ENOMEM	-- insufficient memory to start iocp.
 * EINVAL	-- socket is invalid.
 * EAGAIN	-- tx queue is empty.
 */
static int
start_tx(struct net2_workq_io *io, struct iocp_tx *tx)
{
	int			 fin, error, wsa_error;
	uint32_t		 p_err;
	struct net2_dgram_tx_promdata
				*p_result;
	struct sockaddr		*addr;
	int			 addrlen;
	size_t			 iov_cnt;
	struct iovec		*iov;

	/* Argument check. */
	assert(io != NULL);

	/* Test if we are allowed to start iocp in this thread. */
	if (!start_io(io)) {
		if (tx != NULL)
			net2_free(tx);
		return EINTR;
	}

	/* Acquire a reference to io. */
	atomic_fetch_add_explicit(&io->refcnt, 1, memory_order_acquire);

	/* Allocate tx. */
	if (tx == NULL && (tx = net2_malloc(sizeof(*tx))) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	tx->base.io = io;
	tx->base.kind = IOCP_TX;
	SecureZeroMemory(&tx->base.overlapped,
	    sizeof(tx->base.overlapped));
	tx->base.overlapped.hEvent = io->container->iocp_event;

	/*
	 * Load a succesful promise.
	 * Canceled and failed promises are ignored
	 * (promise generator callback is to handle that).
	 */
	do {
		if ((tx->prom = net2_dp_pop_prepare(&tx->prep,
		    io->tx_internal)) == NULL) {
			error = EAGAIN;
			goto fail_1;
		}
		fin = net2_promise_get_result(tx->prom,
		    (void**)&p_result, &p_err);
		if (fin != NET2_PROM_FIN_OK)
			net2_dp_pop_commit(&tx->prep);
	} while (fin != NET2_PROM_FIN_OK);
	assert(p_result != NULL && p_result->data != NULL);

	/* Load promdata info. */
	addr = (struct sockaddr*)&p_result->addr;
	addrlen = p_result->addrlen;
	if (addrlen == 0)
		addr = NULL;
	tx->completed_prom = p_result->tx_done;
	if (tx->completed_prom != NULL)
		net2_promise_ref(tx->completed_prom);	/* fail_3 */

	/* Prepare IO vectors. */
	iov_cnt = net2_buffer_peek(p_result->data, -1, NULL, 0);
	if ((iov = net2_calloc(iov_cnt, sizeof(*iov))) == NULL) {
		error = ENOMEM;
		goto fail_3;
	}

	/* Send buffer. */
	LL_REF(iocp_tx_list, &io->tx_act, tx);
	LL_INSERT_TAIL(iocp_tx_list, &io->tx_act, tx);
	error = WSASendTo(io->socket, iov, iov_cnt, NULL, 0, addr, addrlen,
	    &tx->base.overlapped, NULL);
	if (error == SOCKET_ERROR)
		wsa_error = WSAGetLastError();
	assert(error == 0 || error == SOCKET_ERROR);
	/* Change WSA_IO_PENDING to no-error, since this is what we want. */
	if (error == SOCKET_ERROR && wsa_error == WSA_IO_PENDING)
		error = 0;
	/* Add to activity list iff succesful. */
	if (error == 0)
		LL_RELEASE(iocp_tx_list, &io->tx_act, tx);
	else {
		struct iocp_tx *unlinked;

		/* May never fail. */
		unlinked = LL_UNLINK(iocp_tx_list, &io->tx_act, tx);
		assert(unlinked == tx);
	}

	/* Check completion. */
	if (error != 0) {
		error = EAGAIN;

		switch (wsa_error) {
		case WSA_IO_PENDING:
			/*
			 * IO in progress.
			 * Note that this should not trigger, since above
			 * will clear the error for this case.
			 */
			assert(0);
			break;
		case WSAEFAULT:		/* Memory fault. */
		case WSANOTINITIALISED:	/* Winsock needs init. */
		case WSA_OPERATION_ABORTED: /* XXX */
			abort();
			/* FALLTHROUGH */
		case WSAEACCES:		/* Broadcast not supported. */
		case WSAEADDRNOTAVAIL:	/* Invalid address. */
		case WSAECONNRESET:	/* ICMP unreachable. */
		case WSAEHOSTUNREACH:	/* Host unreachable. */
		case WSAEMSGSIZE:	/* Message too large. */
		case WSAENETDOWN:	/* RIP network layer. */
		case WSAENETRESET:	/* TTL expiry (huh?) */
		case WSAENETUNREACH:	/* Net unreachable (routing issue?) */
		case WSAESHUTDOWN:	/* Socket is shutting down. */
			error = EIO;
			goto fail_2;
			break;
		case WSAEAFNOSUPPORT:	/* Socket/pd address fam. mismatch. */
		case WSAEDESTADDRREQ:	/* Need address on socket. */
		case WSAEINPROGRESS:
		case WSAEINTR:
		case WSAENOTCONN:	/* Socket needs connect(). */
		case WSAENOTSOCK:	/* Socket is not a socket. */
		default:		/* Undocumented. */
			break;
		case WSAENOBUFS:	/* Kernel ran out of buffers. */
		case WSAEWOULDBLOCK:	/* Too many iocp active. */
			/*
			 * Ran out of buffers.
			 * Report out-of-memory, to allow caller to recover.
			 */
			break;
		}
		goto fail_4;
	}

	if (tx->completed_prom != NULL)
		net2_promise_set_running(tx->completed_prom);

	/* Free iovectors. */
	net2_free(iov);
	return 0;


fail_4:
	net2_free(iov);
fail_3:
	if (tx->completed_prom != NULL)
		net2_promise_release(tx->completed_prom);
fail_2:
	net2_dp_pop_rollback(&tx->prep);
fail_1:
	net2_free(tx);
fail_0:
	assert(error != 0);
	/* Release our reference to io. */
	atomic_fetch_sub_explicit(&io->refcnt, 1, memory_order_relaxed);
	return error;
}
/* TX iocp completion routine. */
static void
do_tx(struct iocp_tx *tx, unsigned long bytes)
{
	int	 error;

	assert(tx->base.kind == IOCP_TX);

	/* Unlink tx, which may never fail. */
	{
		struct iocp_tx *unlinked;

		LL_REF(iocp_tx_list, &tx->base.io->tx_act, tx);
		unlinked = LL_UNLINK(iocp_tx_list, &tx->base.io->tx_act, tx);
		assert(unlinked == tx);
	}

	/*
	 * Commit prepared removal,
	 * allowing new tx to be scheduled.
	 *
	 * Note that even on failure, the tx will be removed,
	 * since the completed_prom will be used to signify succes or failure.
	 */
	error = net2_dp_pop_commit(&tx->prep);
	assert(error == 0);	/* May not fail. */

	/* Mark delivery as succesful. */
	if (tx->completed_prom != NULL) {
		if (bytes == 0) {
			if (net2_promise_set_error(tx->completed_prom, EIO, 1))
				net2_promise_release(tx->completed_prom);
		} else if (net2_promise_set_finok(tx->completed_prom,
		    NULL, NULL, NULL, 1))
			net2_promise_release(tx->completed_prom);
	}

	/* Release promise we received from dataqueue. */
	net2_promise_release(tx->prom);

	/* Release reference to io. */
	atomic_fetch_sub_explicit(&tx->base.io->refcnt, 1, memory_order_release);

	net2_free(tx);
}
/*
 * Add a tx iocp.
 * This is a datapipe event.
 */
static void
dp_tx_ev(void *io_ptr, void *unused ILIAS_NET2__unused)
{
	struct net2_workq_io *io = (struct net2_workq_io*)io_ptr;

	/* Add as many tx as possible. */
	while (start_tx(io, NULL) == 0);
}

/*
 * Handle up to count iocp completions.
 */
static void
handle_iocp_wait(struct net2_workq_io_container *c, unsigned int count,
    unsigned int delay)
{
	OVERLAPPED_ENTRY	*entry;
	struct iocp		*iocp;
	unsigned long		 entry_count;

	/* Allocate storage for entries on the stack. */
	assert(count > 0);
	count = MIN(count, 8192 / sizeof(*entry));
	entry = alloca(count * sizeof(*entry));

	/* Acquire up to count completions. */
	if (!GetQueuedCompletionStatusEx(c->iocp,
	    entry, count, &entry_count, delay, FALSE))
		return;

	/* Signal event,
	 * so another thread will attempt to read iocp as well. */
	SetEvent(c->iocp_event);

	/* Process all received completion entries. */
	for (; entry_count > 0; entry++, entry_count--) {
		fprintf(stderr, "%s wait for IOCP completed\n", __FUNCTION__);

		iocp = overlapped2iocp(entry->lpOverlapped);

		switch (iocp->kind) {
		default:
			abort();
			break;
		case IOCP_RX:
			assert(iocp2rx(iocp)->base.io->container == c);
			do_rx(iocp2rx(iocp),
			    entry->dwNumberOfBytesTransferred);
			break;
		case IOCP_TX:
			assert(iocp2tx(iocp)->base.io->container == c);
			do_tx(iocp2tx(iocp),
			    entry->dwNumberOfBytesTransferred);
			break;
		}
	}
}
/*
 * Handle a single iocp.
 *
 * The function will return if:
 * - delay expires (if it wasn't INFINITE), returning ETIMEDOUT
 * - intr becomes set (if it wasn't NULL), returning EINTR
 * - an iocp completes (tested via c->iocp_event), returning 0
 * - the container is being destroyed (tested via c->destroy_wait), returning EBADF
 *
 * If the wait routine fails, EIO is returned.
 */
static int
do_iocp(struct net2_workq_io_container *c, HANDLE intr, unsigned int delay)
{
	HANDLE			 wait[] = {
				    c->destroy_wait,
				    c->iocp_event,
				    intr
				};
	int			 wait_count = (intr == NULL ? 2 : 3);
	int			 wait_result, rv;

	fprintf(stderr, "%s waiting for IOCP\n", __FUNCTION__);
	wait_result = WaitForMultipleObjectsEx(wait_count, wait, FALSE, delay,
	    FALSE);
	switch (wait_result) {
	case WAIT_OBJECT_0 + 0:
		/* c->destroy_wait is set. */
		rv = EBADF;
		break;
	case WAIT_IO_COMPLETION:
	case WAIT_OBJECT_0 + 1:
		/* iocp is ready. */
		handle_iocp_wait(c, 256, 0);
		rv = 0;
		break;
	case WAIT_OBJECT_0 + 2:
		/* Interrupted call. */
		rv = EINTR;
		break;
	case WAIT_TIMEOUT:
		fprintf(stderr, "%s wait timed out\n", __FUNCTION__);
		rv = ETIMEDOUT;
		break;
	case WAIT_FAILED:
		/* Failed to wait. */
		fprintf(stderr, "%s wait failed\n", __FUNCTION__);
		rv = EIO;
		break;
	default:
		abort();
		rv = 0;
	}

	return rv;
}

/* Free rx data. */
static void
rxfree(void *rx_ptr, void *unused ILIAS_NET2__unused)
{
	struct net2_dgram_rx *rx = rx_ptr;

	if (rx != NULL) {
		net2_buffer_free(rx->data);
		net2_free(rx);
	}
}

/*
 * Create the TX datapipe.
 * The TX datapipe consumes promises and will always keep a few of them ready.
 */
static __inline int
create_tx_pipe(struct net2_datapipe_in **in, struct net2_datapipe_out **out,
    struct net2_workq_evbase *wqev)
{
	int	 error;

	error = net2_dp_prom_new(in, out, wqev);
	if (error == 0)
		net2_dpout_set_maxlen(*out, MAX_TX);
	return error;
}
/*
 * Create the RX datapipe.
 * The RX datapipe is filled from the socket.
 */
static __inline int
create_rx_pipe(struct net2_datapipe_in **in, struct net2_datapipe_out **out,
    struct net2_workq_evbase *wqev)
{
	int	 error;

	error = net2_dp_new(in, out, wqev, &rxfree, NULL);
	if (error == 0)
		net2_dpin_set_maxlen(*in, MAX_RX);
	return 0;
}
/*
 * Create a new workq_io object.
 * Claims the socket for itself.
 */
ILIAS_NET2_EXPORT struct net2_workq_io*
net2_workq_io_new(struct net2_workq *wq, net2_socket_t socket)
{
	struct net2_workq_io	*io;
	struct net2_workq_evbase*wqev;

	/* Argument check. */
	if (wq == NULL || socket == (SOCKET)NULL)
		return NULL;
	wqev = net2_workq_evbase(wq);
	net2_workq_evbase_ref(wqev);

	/* Allocate io object. */
	if ((io = net2_malloc(sizeof(*io))) == NULL)
		goto fail_0;
	if ((io->container = net2_workq_get_io(wq)) == NULL)
		goto fail_0;

	/* On success, steals reference from local variable wqev. */
	io->wqev = wqev;

	io->socket = socket;
	LL_INIT(&io->rx_act);
	LL_INIT(&io->tx_act);
	atomic_init(&io->dying, 0);
	atomic_init(&io->refcnt, 1);

	/* Create datapipes. */
	if (create_tx_pipe(&io->tx, &io->tx_internal, wqev) != 0)
		goto fail_1;
	if (create_rx_pipe(&io->rx_internal, &io->rx, wqev) != 0)
		goto fail_2;

	/* Initialize datapipe events.
	 * These events enable the watchers, which will ultimately pull/push
	 * data from/to the datapipe. */
	if (net2_datapipe_event_init_out(&io->tx_avail_ev, io->tx_internal,
	    NET2_DP_EVTYPE_AVAIL, wq,
	    &dp_tx_ev, io, NULL) != 0)
		goto fail_3;
	if (net2_datapipe_event_init_in(&io->rx_avail_ev, io->rx_internal,
	    NET2_DP_EVTYPE_AVAIL, wq,
	    &dp_rx_ev, io, NULL) != 0)
		goto fail_4;

	return io;

fail_5:
	net2_datapipe_event_deinit(&io->rx_avail_ev);
fail_4:
	net2_datapipe_event_deinit(&io->tx_avail_ev);
fail_3:
	net2_dpout_release(io->rx);
	net2_dpin_release(io->rx_internal);
fail_2:
	net2_dpout_release(io->tx_internal);
	net2_dpin_release(io->tx);
fail_1:
	net2_free(io);
fail_0:
	net2_workq_evbase_release(wqev);
	return NULL;
}
/* Destroy IO. */
ILIAS_NET2_EXPORT void
net2_workq_io_destroy(struct net2_workq_io *io)
{
	int			 dying;
	size_t			 refcnt;
	struct net2_workq_io_container
				*c;
	struct net2_workq_evbase*wqev;

	/* Free semantics: null destruction is safe. */
	if (io == NULL)
		return;

	c = io->container;
	wqev = io->wqev;
	assert(c != NULL && wqev != NULL);

	/* Set dying marker. */
	dying = atomic_exchange_explicit(&io->dying, 1, memory_order_acq_rel);
	assert(dying == 0);	/* Duplicate call to destructor. */

	/* Destroy events. */
	net2_datapipe_event_deinit(&io->tx_avail_ev);
	net2_datapipe_event_deinit(&io->rx_avail_ev);
	/* Release public side of data pipes. */
	net2_dpin_release(io->tx);
	net2_dpout_release(io->rx);
	io->tx = NULL;
	io->rx = NULL;

	/*
	 * Remove this workq_io from the redo list.
	 */
	LL_REF(redo_list, &c->redo, io);
	if (LL_UNLINK(redo_list, &c->redo, io)) {
		atomic_fetch_sub_explicit(&io->refcnt, 1,
		    memory_order_relaxed);
	} else
		LL_RELEASE(redo_list, &c->redo, io);

	/*
	 * Cancel all outstanding IOCP.
	 *
	 * This function is not available from Windows Vista and
	 * Windows Server 2008 (_WIN32_WINNT >= 0x600 aka WINVER >= 0x600).
	 */
#if WINVER >= 0x600
	CancelIoEx((HANDLE)io->socket, NULL);
#endif

	/*
	 * Wait until refcnt falls to 1.
	 * While waiting, we help out with IO completion ports (hoping our
	 * iocp will get handled by us as well).
	 */
	while (atomic_load_explicit(&io->refcnt, memory_order_acquire) > 1)
		handle_iocp_wait(io->container, 0xffff, 100);

	/* Release our reference. */
	refcnt = atomic_fetch_sub_explicit(&io->refcnt, 1,
	    memory_order_acquire);
	assert(refcnt == 1);

	/* Release internal data pipes. */
	net2_dpin_release(io->rx_internal);
	net2_dpout_release(io->tx_internal);
	io->rx_internal = NULL;
	io->tx_internal = NULL;

	/* Ensure there really aren't any in-progress iocp. */
	assert(LL_EMPTY(iocp_rx_list, &io->rx_act));
	assert(LL_EMPTY(iocp_tx_list, &io->tx_act));

	/* Close socket. */
	closesocket(io->socket);
	net2_free(io);

	/* Release wqev, this may potentially release the io container. */
	net2_workq_evbase_release(wqev);
}

/* Worker thread. */
static unsigned int __stdcall
worker(void *c_ptr)
{
	struct net2_workq_io_container
				*c = c_ptr;
	struct net2_workq_io	*io;
	int			 rv;

	/*
	 * Mark this thread as the one allowed to initiate iocp calls.
	 * Tested for by start_io().
	 *
	 * Rationale: windows API documents specify that all iocp created by
	 * a thread X will be canceled when that thread X exits.  Since the
	 * workq threads and external threads can be stopped prior to iocp
	 * completion, this behaviour would cause packets to get dropped.
	 * By using a single creator thread that stays alive until the
	 * io container dies, we allow an iocp to complete regardless of the
	 * lifetime of the original thread.
	 *
	 * XXX some articles suggest this is no longer the case since
	 * Windows Server 2008 and Windows Vista.  However the online
	 * documentation for WSARecv still mentions this trait, so better to
	 * be safe than sorry here.
	 */
	thr_container = c;

	for (;;) {
		rv = do_iocp(c, c->redo_event, INFINITE);
		if (rv == EBADF)
			_endthreadex(0);
		else if (rv == EINTR) {
			while ((io = LL_POP_FRONT(redo_list, &c->redo)) !=
			    NULL) {
				do {
					rv = start_rx(io, NULL);
				} while (rv == 0);
				assert(rv != EINTR);
				do {
					rv = start_tx(io, NULL);
				} while (rv == 0);
				assert(rv != EINTR);
			}
		}
	}
}

/* Link io into the redo list. */
static void
link_redo_io(struct net2_workq_io_container *c, struct net2_workq_io *io)
{
	assert(c == io->container);

	atomic_fetch_add_explicit(&io->refcnt, 1, memory_order_acquire);
	LL_REF(redo_list, &c->redo, io);
	if (!LL_PUSH_BACK(redo_list, &c->redo, io))
		goto already_inserted;
	atomic_thread_fence(memory_order_release);

	if (atomic_load_explicit(&io->dying, memory_order_acquire))
		goto rollback;

	/* Release our hold on io. */
	LL_RELEASE(redo_list, &c->redo, io);

	/* Signal that the redo list is no longer empty. */
	SetEvent(c->redo_event);
	return;

already_inserted:
	/* Error path if the io is already on the redo list. */
	LL_RELEASE(redo_list, &c->redo, io);
	atomic_fetch_sub_explicit(&io->refcnt, 1, memory_order_release);
	return;

rollback:
	/* Error path when the io is dying. */
	if (LL_UNLINK(redo_list, &c->redo, io)) {
		atomic_fetch_sub_explicit(&io->refcnt, 1,
		    memory_order_release);
	} else
		LL_RELEASE(redo_list, &c->redo, io);
	return;
}

/* Free tx promise data. */
ILIAS_NET2_EXPORT void
net2_workq_io_tx_pdata_free(void *pd_ptr, void * ILIAS_NET2__unused unused)
{
	struct net2_dgram_tx_promdata
				*pd = pd_ptr;

	if (pd->data != NULL)
		net2_buffer_free(pd->data);
	if (pd->tx_done != NULL) {
		net2_promise_set_cancel(pd->tx_done, 0);
		net2_promise_release(pd->tx_done);
	}
	net2_free(pd);
}

ILIAS_NET2_EXPORT struct net2_datapipe_in*
net2_workq_io_txpipe(struct net2_workq_io *io)
{
	net2_dpin_ref(io->tx);
	return io->tx;
}

ILIAS_NET2_EXPORT struct net2_datapipe_out*
net2_workq_io_rxpipe(struct net2_workq_io *io)
{
	net2_dpout_ref(io->rx);
	return io->rx;
}
