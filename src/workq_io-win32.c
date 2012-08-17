#define N_IOCP		64

struct iocp {
	SOCKET			 socket;
	struct net2_buffer	*buf;
	struct sockaddr_storage	 addr;
	socklen_t		 addrlen;
	WSAOVERLAPPED		 overlapped;

	TAILQ_ENTRY(iocp)	 idleq;
};

struct net2_workq_io_container {
	iocp			 iocp[N_IOCP];
	TAILQ_HEAD(, iocp)	 idle;
};

struct net2_workq_io {
	struct net2_workq_job	 job;
};
