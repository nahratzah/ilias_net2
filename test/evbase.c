#include <ilias/net2/evbase.h>
#include <stdio.h>
#include <event2/event.h>
#ifdef WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

volatile int done_timedout = 0;

void
done(int fd, short what, void *arg)
{
	if (what == EV_TIMEOUT)
		done_timedout++;
	fprintf(stderr, "*ping* ");
}

int
main()
{
	struct net2_evbase	*b;
	struct event		*ev;
	struct timeval		 second = { 0, 0 };

	/* Initializing libevent. */
#ifdef WIN32
	if (evthread_use_windows_threads()) {
		fprintf(stderr, "unable to set up windows threading "
		    "in libevent");
		return -1;
	}
#else
	if (evthread_use_pthreads()) {
		fprintf(stderr, "unable to set up posix threading "
		    "in libevent");
		return -1;
	}
#endif


	fprintf(stderr, "creating evbase... ");
	if ((b = net2_evbase_new()) == NULL) {
		fprintf(stderr, "fail\n");
		return -1;
	}
	fprintf(stderr, "ok\n");

	fprintf(stderr, "starting evbase thread... ");
	if (net2_evbase_threadstart(b)) {
		fprintf(stderr, "fail\n");
		return -1;
	}
	fprintf(stderr, "ok\n");

	fprintf(stderr, "scheduling callback... ");
	if ((ev = event_new(b->evbase, -1, 0, &done, NULL)) == NULL) {
		fprintf(stderr, "event_new fail\n");
		return -1;
	}
	if (event_add(ev, &second)) {
		fprintf(stderr, "event_add fail\n");
		return -1;
	}
	fprintf(stderr, "ok\n");

	/* Sleep 2 seconds for done to time out. */
	fprintf(stderr, "sleeping 5 seconds for timeout... ");
#ifdef WIN32
	Sleep(2000); /* milli seconds */
#else
	sleep(2);
#endif
	if (done_timedout == 0) {
		fprintf(stderr, "time out never happened\n");
		return -1;
	} else if (done_timedout != 1) {
		fprintf(stderr, "time out happened wrong number of times: %d\n",
		    done_timedout);
		return -1;
	}
	fprintf(stderr, "ok\n");

	fprintf(stderr, "attempting to stop thread... ");
	if (net2_evbase_threadstop(b)) {
		fprintf(stderr, "fail\n");
		return -1;
	}
	fprintf(stderr, "ok\n");

	net2_evbase_release(b);
	return 0;
}
