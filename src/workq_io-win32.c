#include <ilias/net2/workq_io.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/memory.h>
#include <ilias/net2/promise.h>
#include <ilias/net2/semaphore.h>
#include <ilias/net2/connection.h>	/* For NET2_CONNRECV_*. */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#include <process.h>
#include <errno.h>
#include <stdio.h>/* DEBUG */

#define MAX_RX_WAIT	8192	/* Max active RX iocps. */


/* Type of IOCP. */
enum iocp_kind {
	IOCP_INVALID,
	IOCP_RX,	/* RX iocp. */
	IOCP_TX		/* TX iocp. */
};
/* Basic iocp used by workq_io. */
struct iocp {
	enum iocp_kind		 kind;		/* IOCP type. */
	OVERLAPPED		 overlapped;	/* Overlapped struct. */
};
#define IOCP_OVERLAPPED_OFFSET						\
	((size_t)(&((struct iocp*)0)->overlapped))
/* Translate from WSAOVERLAPPED to iocp. */
static __inline struct iocp*
overlapped2iocp(OVERLAPPED *overlapped)
{
	struct iocp		*iocp;

	iocp = (struct iocp*)((uintptr_t)overlapped - IOCP_OVERLAPPED_OFFSET);
	assert(&iocp->overlapped == overlapped);
	return iocp;
}

/* Receive iocp. */
struct iocp_rx {
	struct iocp		 base;		/* Shared data. */
	struct net2_dgram_rx	 rx;		/* Receive buffer. */
	struct iovec		 buf_iovec;	/* Buffer iovec. */
	TAILQ_ENTRY(iocp_rx)	 q;
};
/* Transmit iocp. */
struct iocp_tx {
	struct iocp		 base;		/* Shared data. */
	struct net2_buffer	*buf;		/* Transmit buffer. */
	struct net2_promise	*completed_prom; /* TX done promise. */
	TAILQ_ENTRY(iocp_tx)	 q;
};

/* TX promises. */
struct tx_prom {
	TAILQ_ENTRY(tx_prom)	 q;		/* Link to queue. */
	struct net2_promise	*prom;		/* TX promise. */
	struct net2_promise_event promcb;	/* Completion event. */
	struct net2_dgram_tx_promdata
				*pd;		/* Promise result. */
};

struct net2_workq_io_container {
	HANDLE			 iocp;		/* IO completion port. */
	HANDLE			 iocp_event;	/* IOCP ready. */
	struct net2_semaphore	*wqev_idle,	/* Idle wqev semaphore. */
				*wqev_active;	/* Active wqev semaphore. */
	HANDLE			 thread;	/* Worker thread. */
};

struct net2_workq_io {
	struct net2_workq_io_container
				*container;	/* Associated io container. */
	struct net2_workq	*wq;		/* Associated workq. */
	SOCKET			 socket;	/* Operational socket. */
	net2_workq_io_recv	 rxfn;		/* Receive function. */
	void			*cbarg;		/* Argument to rxfn/txfn. */
	atomic_size_t		 rx_wait,	/* # outstanding rx iocps. */
				 tx_wait;	/* # outstanding tx iocps. */
	atomic_size_t		 tx_target;	/* Target for tx_wait. */
	CRITICAL_SECTION	 lock;
	TAILQ_HEAD(, iocp_rx)	 rxq;		/* RX ready for delivery. */
	struct net2_workq_job	 rx_delivery;	/* RX delivery job. */
	int			 rx_is_active;	/* RX may run. */

	TAILQ_HEAD(, tx_prom)	 tx_prom_inact;	/* Inactive tx promises. */
	TAILQ_HEAD(, tx_prom)	 tx_prom_act;	/* Active tx promises. */
	atomic_size_t		 tx_prom_actcnt; /* #tx_prom_act. */
	TAILQ_HEAD(, tx_prom)	 tx_prom_rts;	/* Ready to send. */
};


static int	start_rx(struct net2_workq_io*, struct iocp_rx*);
static int	new_rx(struct net2_workq_io*);
static void	do_rx_delivery(void*, void*);
static void	do_rx(struct net2_workq_io*, struct iocp_rx*,
		    unsigned long, int);
static void	do_tx(struct net2_workq_io*, struct iocp_tx*,
		    unsigned long, int);
static unsigned int __stdcall
		worker(void*);
static void	do_iocp(struct net2_workq_io_container*, unsigned int);
static int	pd_tx(struct net2_workq_io*, struct net2_dgram_tx_promdata*,
		    int*);
static void	activate_txpromises(struct net2_workq_io*);
static void	iocp_tx_rts(void*, void*);
static void	kill_iocp(struct net2_workq_io*, struct iocp*);
static void	kill_wqio(struct net2_workq_io*);



/* Thread name exception (MSVC debugger listens to this). */
static const DWORD MS_VC_EXCEPTION=0x406D1388;

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

/* Create a new io container. */
ILIAS_NET2_LOCAL struct net2_workq_io_container*
net2_workq_io_container_new(struct net2_semaphore *idle,
    struct net2_semaphore *active)
{
	struct net2_workq_io_container
				*c;
	unsigned int		 tid;

	/* DEBUG */
	idle = active = NULL;

	if ((c = net2_malloc(sizeof(*c))) == NULL)
		goto fail_0;
	if ((c->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL,
	    0, 0)) == NULL)
		goto fail_1;
	if ((c->iocp_event = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL)
		goto fail_2;
	c->wqev_idle = idle;
	c->wqev_active = active;
	if ((c->thread = (HANDLE)_beginthreadex(NULL, 0, &worker, c,
	    0, &tid)) == (HANDLE)-1)
		goto fail_3;

	SetThreadName(tid, "io worker thread");

	return c;


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
	CloseHandle(c->iocp);
	CloseHandle(c->iocp_event);
	/* XXX stop worker before closing handle. */
	CloseHandle(c->thread);
}

/* Create an io workq job. */
ILIAS_NET2_EXPORT struct net2_workq_io*
net2_workq_io_new(struct net2_workq *wq, net2_socket_t socket,
    net2_workq_io_recv rxfn, void *cbarg)
{
	struct net2_workq_io_container
				*c;
	struct net2_workq_io	*io;

	/* Argument check. */
	if (wq == NULL || socket == (SOCKET)NULL)
		return NULL;
	/* Acquire IO queue. */
	if ((c = net2_workq_get_io(wq)) == NULL)
		return NULL;

	/* Allocate and initialize io. */
	if ((io = net2_malloc(sizeof(*io))) == NULL)
		goto fail_0;
	io->container = c;
	io->socket = socket;
	io->cbarg = cbarg;
	io->rxfn = rxfn;
	TAILQ_INIT(&io->rxq);
	io->rx_is_active = 0;
	atomic_init(&io->rx_wait, 0);
	atomic_init(&io->tx_wait, 0);
	atomic_init(&io->tx_target, 1);
	io->wq = wq;
	TAILQ_INIT(&io->tx_prom_inact);
	TAILQ_INIT(&io->tx_prom_act);
	atomic_init(&io->tx_prom_actcnt, 0);
	TAILQ_INIT(&io->tx_prom_rts);

	if (!InitializeCriticalSectionAndSpinCount(&io->lock, 128))
		goto fail_1;
	if (rxfn == NULL)
		net2_workq_init_work_null(&io->rx_delivery);
	else if (net2_workq_init_work(&io->rx_delivery, wq,
	    &do_rx_delivery, io, NULL, NET2_WORKQ_PERSIST))
		goto fail_2;

	assert(io->container->iocp != NULL &&
	    io->container->iocp != INVALID_HANDLE_VALUE);
	if (CreateIoCompletionPort((HANDLE)socket, io->container->iocp,
	    (uintptr_t)io, 0) == NULL)
		goto fail_3;
	/* No failures past this point. */
	net2_workq_ref(wq);
	return io;


fail_3:
	net2_workq_deinit_work(&io->rx_delivery);
fail_2:
	DeleteCriticalSection(&io->lock);
fail_1:
	free(io);
fail_0:
	return NULL;
}
ILIAS_NET2_EXPORT void
net2_workq_io_destroy(struct net2_workq_io *io)
{
	int			 do_kill;

	net2_workq_deinit_work(&io->rx_delivery);
	io->rx_is_active = 0;

	EnterCriticalSection(&io->lock);
	net2_workq_release(io->wq);
	io->wq = NULL;

	if (atomic_load_explicit(&io->rx_wait, memory_order_relaxed) == 0 &&
	    atomic_load_explicit(&io->tx_wait, memory_order_relaxed) == 0) {
		do_kill = 1;
	} else
		do_kill = 0;
	LeaveCriticalSection(&io->lock);

	if (do_kill)
		kill_wqio(io);
}

/* Start a iocp rx. */
static int
start_rx(struct net2_workq_io *io, struct iocp_rx *iocp)
{
	int		 error;
	size_t		 niovec;
	int		 rv;
	size_t		 rx_wait;
	unsigned long	 flags;

	/* Make sure we start with a new buffer. */
	if (iocp->rx.data != NULL) {
		net2_buffer_free(iocp->rx.data);
		iocp->rx.data = NULL;
	}
	if ((iocp->rx.data = net2_buffer_new()) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	/* Reserve space in buffer. */
	niovec = 1;
	if (net2_buffer_reserve_space(iocp->rx.data, NET2_WORKQ_IO_MAXLEN,
	    &iocp->buf_iovec, &niovec) != 0) {
		error = ENOMEM;
		goto fail_1;
	}

	/* Prepare overlapped, addr. */
	SecureZeroMemory(&iocp->base.overlapped,
	    sizeof(iocp->base.overlapped));
	iocp->base.overlapped.hEvent = io->container->iocp_event;
	iocp->rx.addrlen = sizeof(iocp->rx.addr);
	iocp->rx.error = 0;

	/* Post new recvfrom operation. */
	iocp->rx.addrlen = sizeof(iocp->rx.addr);
	flags = 0;
	rv = WSARecvFrom(io->socket, &iocp->buf_iovec, 1, NULL,
	    &flags, (struct sockaddr*)&iocp->rx.addr, &iocp->rx.addrlen,
	    &iocp->base.overlapped, NULL);
	if (rv == SOCKET_ERROR) {
		int	wsa_error = WSAGetLastError();
		switch (wsa_error) {
		case WSA_IO_PENDING:
			/* Not an error:
			 * this means the RecvFrom is pending. */
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
			error = EINVAL;
			goto fail_1;
			break;
		case WSAEINVAL:		/* Socket in invalid state. */
		case WSAECONNRESET:	/* Connection lost. */
		case WSAEMSGSIZE:	/* XXX Packet too large? */
		case WSAENETDOWN:	/* RIP network layer. */
		case WSAENETRESET:	/* TTL expiry (huh?) */
			/* Assign error code and deliver error asap. */
			net2_buffer_free(iocp->rx.data);
			iocp->rx.data = NULL;
			iocp->rx.error = NET2_CONNRECV_REJECT;
			io->rxfn(io->cbarg, &iocp->rx);
			error = EIO;
			goto fail_0;
			break;
		}
	}

	/*
	 * Create a new IOCP and add it to the socket immediately,
	 * since the currently created invocation
	 * completed immediately.
	 */
	if (rv == 0 &&
	    (rx_wait = atomic_load_explicit(&io->rx_wait,
	    memory_order_relaxed)) < MAX_RX_WAIT) {
		/* Increment rx_wait. */
		while (atomic_compare_exchange_weak_explicit(&io->rx_wait,
		    &rx_wait, rx_wait + 1,
		    memory_order_relaxed, memory_order_relaxed)) {
			if (rx_wait >= MAX_RX_WAIT)
				goto skip_rxwait_incr;
		}

		/* Start new rx, undoing the increment if it fails. */
		if (new_rx(io) != 0) {
			atomic_fetch_sub_explicit(&io->rx_wait, 1,
			    memory_order_relaxed);
		}
	}
skip_rxwait_incr:

	return 0;


fail_1:
	net2_buffer_free(iocp->rx.data);
	iocp->rx.data = NULL;
fail_0:
	assert(error != 0);
	return error;
}
/* Create and start a new iocp rx for this io. */
static int
new_rx(struct net2_workq_io *io)
{
	struct iocp_rx		*iocp;
	int			 error;

	if (!io->rx_is_active)
		return EAGAIN;

	if ((iocp = net2_malloc(sizeof(*iocp))) == NULL)
		goto fail_0;
	iocp->base.kind = IOCP_RX;
	iocp->rx.data = NULL;
	if ((error = start_rx(io, iocp)) != 0)
		goto fail_1;
	return 0;


fail_1:
	net2_buffer_free(iocp->rx.data);
	net2_free(iocp);
fail_0:
	/* XXX mark io as needing new_rx invocation. */
	assert(error != 0);
	return error;
}
/*
 * Deliver received data.
 *
 * This runs from the io->rx_delivery event, which is persistent.
 * When the rx queue is empty, the function will cancel the
 * io->rx_delivery event.
 */
static void
do_rx_delivery(void *io_ptr, void *unused ILIAS_NET2__unused)
{
	struct net2_workq_io	*io = io_ptr;
	struct iocp_rx		*iocp;

	/* Pop iocp_rx from queue. */
	EnterCriticalSection(&io->lock);
	iocp = TAILQ_FIRST(&io->rxq);
	if (iocp != NULL)
		TAILQ_REMOVE(&io->rxq, iocp, q);
	else
		net2_workq_deactivate(&io->rx_delivery);
	LeaveCriticalSection(&io->lock);
	if (iocp == NULL)
		return;

	/* Invoke actual callback. */
	assert(iocp->base.kind == IOCP_RX);
	io->rxfn(io->cbarg, &iocp->rx);
	/* Release buffer, if callback hasn't done so yet. */
	if (iocp->rx.data != NULL) {
		net2_buffer_free(iocp->rx.data);
		iocp->rx.data = NULL;
	}

	if (start_rx(io, iocp) != 0) {
		net2_buffer_free(iocp->rx.data);
		net2_free(iocp);
		if (atomic_fetch_sub_explicit(&io->rx_wait, 1,
		    memory_order_relaxed) == 0) {
			/* XXX do something to recover. */
		}
	}
}

/* Queue data receival. */
static void
do_rx(struct net2_workq_io *io, struct iocp_rx *iocp, unsigned long bytes,
    int wqact_flags)
{
	int		 bufrv;

	assert(iocp->base.kind == IOCP_RX);
	assert(iocp->buf_iovec.iov_base != NULL &&
	    iocp->buf_iovec.iov_len >= bytes);
	iocp->buf_iovec.iov_len = bytes;
	bufrv = net2_buffer_commit_space(iocp->rx.data, &iocp->buf_iovec, 1);
	assert(bufrv == 0);

	iocp->buf_iovec.iov_base = NULL;
	iocp->buf_iovec.iov_len = 0;

	EnterCriticalSection(&io->lock);
	TAILQ_INSERT_TAIL(&io->rxq, iocp, q);
	LeaveCriticalSection(&io->lock);
	net2_workq_activate(&io->rx_delivery, wqact_flags);
}
/* Handle sent data completion on socket. */
static void
do_tx(struct net2_workq_io *io, struct iocp_tx *iocp, unsigned long bytes,
    int wqact_flags)
{
	/* Validate result. */
	assert(iocp->base.kind == IOCP_TX);
	assert(bytes >= net2_buffer_length(iocp->buf));
	/* Mark optional transmission promise as completed. */
	if (iocp->completed_prom != NULL) {
		assert(!net2_promise_is_finished(iocp->completed_prom));
		if (bytes == 0) {
			if (net2_promise_set_error(iocp->completed_prom,
			    EIO, NET2_PROMFLAG_RELEASE) == 0)
				iocp->completed_prom = NULL;
		} else if (net2_promise_set_finok(iocp->completed_prom,
		    NULL, NULL, NULL, NET2_PROMFLAG_RELEASE) == 0)
			iocp->completed_prom = NULL;
	}
	/* Release the buffer. */
	net2_buffer_free(iocp->buf);
	iocp->buf = NULL;
	/* Decrement count of outstanding tx. */
	atomic_fetch_sub_explicit(&io->tx_wait, 1, memory_order_relaxed);

	/* XXX try to schedule a new tx. */

	net2_buffer_free(iocp->buf);
	if (iocp->completed_prom != NULL) {
		net2_promise_set_cancel(iocp->completed_prom, 0);
		net2_promise_release(iocp->completed_prom);
	}
	net2_free(iocp);
}

/* Loop waiting for iocp activations. */
static unsigned int __stdcall
worker(void *c_ptr)
{
	struct net2_workq_io_container *c = c_ptr;

	fprintf(stderr, "%s started\n", __FUNCTION__);
	for (;;)
		do_iocp(c, INFINITE);
	fprintf(stderr, "%s stopped\n", __FUNCTION__);
}
static void
do_iocp(struct net2_workq_io_container *c, unsigned int delay)
{
	OVERLAPPED_ENTRY	 entry;
	unsigned long		 count;
	struct net2_workq_io	*io;
	struct iocp		*iocp;
	int			 wqact_flags;

	fprintf(stderr, "%s waiting for IOCP\n", __FUNCTION__);
	GetQueuedCompletionStatus(c->iocp,
	    &entry.dwNumberOfBytesTransferred,
	    &entry.lpCompletionKey,
	    &entry.lpOverlapped, INFINITE);
	fprintf(stderr, "%s wait for IOCP completed\n", __FUNCTION__);

	wqact_flags = 0;
	if (c->wqev_idle != NULL && c->wqev_active != NULL &&
	    net2_semaphore_trydown(c->wqev_idle))
		wqact_flags |= NET2_WQ_ACT_IMMED;

	io = (struct net2_workq_io*)entry.lpCompletionKey;
	iocp = overlapped2iocp(entry.lpOverlapped);

	/* Destruction in progrss. */
	if (io->wq == NULL) {
		kill_iocp(io, iocp);
		goto skip_iocp;
	}

	assert(io != NULL && iocp != NULL);
	switch (iocp->kind) {
	default:
		assert(0);
		break;
	case IOCP_RX:
		assert(io != NULL && io->container == c);
		do_rx(io, (struct iocp_rx*)iocp,
		    entry.dwNumberOfBytesTransferred,
		    wqact_flags);
		break;
	case IOCP_TX:
		assert(io != NULL && io->container == c);
		do_tx(io, (struct iocp_tx*)iocp,
		    entry.dwNumberOfBytesTransferred,
		    wqact_flags);
		break;
	}

skip_iocp:
	/*
	 * If we processed events inside the queue, we must activate
	 * the workq, since the workq may have failed to activate its
	 * own threads due to our claim of a thr_idle.
	 */
	if (wqact_flags & NET2_WQ_ACT_IMMED)
		net2_semaphore_up(c->wqev_active, 1);
}

/*
 * Change promdata into outstanding iocp.
 *
 * If the transmit succeeds, completed_immed (optional) will be set
 * if the operation returned immediate success, or cleared if the
 * operation will complete delayed.
 *
 * If the operation fails, an error will be returned and pd should be
 * destroyed.  If the operation fails due to resource shortage, ENOMEM
 * will be returned and the pd will not be touched (allowing the operation
 * to be retried at a later time, instead of destroying pd).
 *
 * If the operation succeeds, pd will have been altered and should be freed.
 */
static int
pd_tx(struct net2_workq_io *io, struct net2_dgram_tx_promdata *pd,
    int *completed_immed)
{
	struct iocp_tx	*iocp;
	struct iovec	*bufs;
	size_t		 nbufs;
	int		 error, rv;
	struct sockaddr	*addr;

	/* Check that the promdata has actual contents. */
	if (pd->data == NULL || net2_buffer_empty(pd->data))
		return EINVAL;

	if ((iocp = net2_malloc(sizeof(*iocp))) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	iocp->base.kind = IOCP_TX;
	SecureZeroMemory(&iocp->base.overlapped,
	    sizeof(iocp->base.overlapped));
	iocp->base.overlapped.hEvent = io->container->iocp_event;
	iocp->buf = pd->data;
	iocp->completed_prom = pd->tx_done;

	/* Create temporary iovec buf. */
	nbufs = net2_buffer_peek(iocp->buf, SIZE_MAX, NULL, 0);
	assert(nbufs > 0);
	if ((bufs = net2_calloc(nbufs, sizeof(*bufs))) == NULL) {
		error = ENOMEM;
		goto fail_1;
	}
	nbufs = net2_buffer_peek(iocp->buf, SIZE_MAX, bufs, nbufs);

	/* Claim ownership of completion promise, buffer. */
	pd->data = NULL;
	pd->tx_done = NULL;

	/* Start iocp. */
	if (pd->addrlen == 0) {
		rv = WSASend(io->socket, bufs, nbufs, NULL, 0,
		    &iocp->base.overlapped, NULL);
	} else {
		addr = (struct sockaddr*)&pd->addr;
		rv = WSASendTo(io->socket, bufs, nbufs, NULL, 0,
		    addr, pd->addrlen, &iocp->base.overlapped, NULL);
	}
	net2_free(bufs);

	/* Check completion. */
	if (rv != 0) {
		int	wsa_error = WSAGetLastError();
		switch (wsa_error) {
		case WSA_IO_PENDING:
			/* IO in progress. */
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
			error = EINVAL;
			goto fail_2;
			break;
		case WSAENOBUFS:	/* Kernel ran out of buffers. */
		case WSAEWOULDBLOCK:	/* Too many iocp active. */
			/*
			 * Ran out of buffers.
			 * Report out-of-memory, to allow caller to recover.
			 */
			pd->data = iocp->buf;
			pd->tx_done = iocp->completed_prom;
			error = ENOMEM;
			goto fail_1;
			break;
		}
	}

	/* Mark #tx_wait, publish immediate completion of tx. */
	atomic_fetch_add_explicit(&io->tx_wait, 1, memory_order_relaxed);
	if (completed_immed != NULL)
		*completed_immed = (rv == 0);

	return 0;


fail_2:
	assert(pd->data == NULL && pd->tx_done == NULL);
	net2_buffer_free(iocp->buf);
	net2_promise_set_error(iocp->completed_prom, error,
	    NET2_PROMFLAG_RELEASE);
	error = 0;
fail_1:
	net2_free(iocp);
fail_0:
	if (error == ENOMEM)
		assert(pd->data != NULL);
	return error;
}

/* Activate tx promises. */
static void
activate_txpromises(struct net2_workq_io *io)
{
	struct tx_prom		*txp;

	EnterCriticalSection(&io->lock);
	while (atomic_load_explicit(&io->tx_wait, memory_order_relaxed) +
	    atomic_load_explicit(&io->tx_prom_actcnt, memory_order_relaxed) <
	    atomic_load_explicit(&io->tx_target, memory_order_relaxed)) {
		txp = TAILQ_FIRST(&io->tx_prom_inact);
		if (txp == NULL)
			break;
		if (net2_promise_event_init(&txp->promcb, txp->prom,
		    NET2_PROM_ON_FINISH, io->wq, &iocp_tx_rts, io, txp) != 0)
			break;

		TAILQ_REMOVE(&io->tx_prom_inact, txp, q);
		TAILQ_INSERT_TAIL(&io->tx_prom_act, txp, q);
		atomic_fetch_add_explicit(&io->tx_prom_actcnt, 1,
		    memory_order_relaxed);
	}
	LeaveCriticalSection(&io->lock);
}
/* TX_prom event callback. */
static void
iocp_tx_rts(void *io_ptr, void *txp_ptr)
{
	struct net2_workq_io	*io = io_ptr;
	struct tx_prom		*txp = txp_ptr;
	int			 rv;
	int			 immed;

	/* If the promise fails, drop it. */
	if (net2_promise_get_result(txp->prom, (void**)&txp->pd, NULL) !=
	    NET2_PROM_FIN_OK || txp->pd == NULL) {
		EnterCriticalSection(&io->lock);
		TAILQ_REMOVE(&io->tx_prom_act, txp, q);
		LeaveCriticalSection(&io->lock);
		net2_promise_release(txp->prom);
		net2_promise_event_deinit(&txp->promcb);
		net2_free(txp);
		atomic_fetch_sub_explicit(&io->tx_prom_actcnt, 1,
		    memory_order_relaxed);
		activate_txpromises(io);
		return;
	}

	EnterCriticalSection(&io->lock);
	TAILQ_REMOVE(&io->tx_prom_act, txp, q);
	TAILQ_INSERT_TAIL(&io->tx_prom_rts, txp, q);

	immed = 0;
	while ((txp = TAILQ_FIRST(&io->tx_prom_rts)) != NULL) {
		int	immed_tmp = 0;

		rv = pd_tx(io, txp->pd, &immed_tmp);
		if (rv == ENOMEM)
			break;
		TAILQ_REMOVE(&io->tx_prom_act, txp, q);
		if (rv != 0 && txp->pd->tx_done != NULL)
			net2_promise_set_error(txp->pd->tx_done, rv, 0);
		net2_promise_release(txp->prom);
		net2_promise_event_deinit(&txp->promcb);
		free(txp);
		atomic_fetch_sub_explicit(&io->tx_prom_actcnt, 1,
		    memory_order_relaxed);
		if (rv != 0)
			break;
		immed = immed || immed_tmp;
	}
	LeaveCriticalSection(&io->lock);

	if (immed) {
		atomic_fetch_add_explicit(&io->tx_target, 1,
		    memory_order_relaxed);
	} else {
		size_t	target;
		
		target = atomic_load_explicit(&io->tx_target,
		    memory_order_relaxed);
		if (target > 1) {
			atomic_compare_exchange_weak_explicit(&io->tx_target,
			    &target, target - 1,
			    memory_order_relaxed, memory_order_relaxed);
		}
	}
	activate_txpromises(io);
}
/* Schedule a promise for transmission. */
ILIAS_NET2_EXPORT int
net2_workq_io_tx(struct net2_workq_io *io, struct net2_promise *tx_prom)
{
	struct tx_prom		*txp;
	int			 error;

	if ((txp = net2_malloc(sizeof(*txp))) == NULL) {
		error = ENOMEM;
		goto fail_0;
	}
	txp->prom = tx_prom;
	txp->pd = NULL;

	EnterCriticalSection(&io->lock);
	TAILQ_INSERT_TAIL(&io->tx_prom_inact, txp, q);
	activate_txpromises(io);
	LeaveCriticalSection(&io->lock);
	return 0;


fail_1:
	net2_free(txp);
fail_0:
	assert(error != 0);
	return error;
}

/* Activate rx. */
ILIAS_NET2_EXPORT void
net2_workq_io_activate_rx(struct net2_workq_io *io)
{
	if (io->rx_is_active || io->rxfn == NULL)
		return;

	io->rx_is_active = 1;
	new_rx(io);
}
/* Deactivate rx. */
ILIAS_NET2_EXPORT void
net2_workq_io_deactivate_rx(struct net2_workq_io *io)
{
	io->rx_is_active = 0;
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

/* IOCP completion callback for dying workq_io. */
static void
kill_iocp(struct net2_workq_io *io, struct iocp *iocp)
{
	struct iocp_rx		*rx;
	struct iocp_tx		*tx;
	int			 do_kill;

	EnterCriticalSection(&io->lock);
	switch (iocp->kind) {
	case IOCP_RX:
		rx = (struct iocp_rx*)iocp;
		net2_buffer_free(rx->rx.data);
		net2_free(rx);
		atomic_fetch_sub_explicit(&io->rx_wait, 1,
		    memory_order_release);
		break;
	case IOCP_TX:
		tx = (struct iocp_tx*)iocp;
		net2_buffer_free(tx->buf);
		if (tx->completed_prom != NULL) {
			net2_promise_set_cancel(tx->completed_prom,
			    NET2_PROMFLAG_RELEASE);
		}
		net2_free(tx);
		break;
	default:
		assert(0);
		break;
	}

	if (atomic_load_explicit(&io->rx_wait, memory_order_relaxed) == 0 &&
	    atomic_load_explicit(&io->tx_wait, memory_order_relaxed) == 0 &&
	    io->wq == NULL)
		do_kill = 1;
	else
		do_kill = 0;
	LeaveCriticalSection(&io->lock);

	if (do_kill)
		kill_wqio(io);
}
/* Remove the husk of workq_io after all outstanding iocp have completed. */
static void
kill_wqio(struct net2_workq_io *io)
{
	struct iocp_rx	*rx;
	struct tx_prom	*txp;

	assert(io->wq == NULL);

	DeleteCriticalSection(&io->lock);

	while ((rx = TAILQ_FIRST(&io->rxq)) != NULL) {
		TAILQ_REMOVE(&io->rxq, rx, q);
		net2_buffer_free(rx->rx.data);
		net2_free(rx);
	}
	while ((txp = TAILQ_FIRST(&io->tx_prom_inact)) != NULL) {
		TAILQ_REMOVE(&io->tx_prom_inact, txp, q);
		net2_promise_cancel(txp->prom);
		net2_promise_release(txp->prom);
		net2_promise_event_deinit(&txp->promcb);
		/* txp->prom frees txp->pd */
		net2_free(txp);
	}
	while ((txp = TAILQ_FIRST(&io->tx_prom_act)) != NULL) {
		TAILQ_REMOVE(&io->tx_prom_act, txp, q);
		net2_promise_cancel(txp->prom);
		net2_promise_release(txp->prom);
		net2_promise_event_deinit(&txp->promcb);
		/* txp->prom frees txp->pd */
		net2_free(txp);
	}
	while ((txp = TAILQ_FIRST(&io->tx_prom_rts)) != NULL) {
		TAILQ_REMOVE(&io->tx_prom_rts, txp, q);
		net2_promise_cancel(txp->prom);
		net2_promise_release(txp->prom);
		net2_promise_event_deinit(&txp->promcb);
		/* txp->prom frees txp->pd */
		net2_free(txp);
	}

	net2_free(io);
}
