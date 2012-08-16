#include "test.h"
#include <ilias/net2/init.h>
#include <ilias/net2/workq.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif


int
workq_evbase_create_destroy()
{
	struct net2_workq_evbase*wqev;

	fprintf(stderr, "\tcreating workq without threads\n");
	wqev = net2_workq_evbase_new(__FUNCTION__, 0, 0);
	if (wqev == NULL) {
		fprintf(stderr, "\tNULL returned\n");
		return -1;
	}
	fprintf(stderr, "\tdestroying workq\n");
	net2_workq_evbase_release(wqev);

	fprintf(stderr, "\tcreating workq with threads\n");
	wqev = net2_workq_evbase_new(__FUNCTION__, 10, 15);
	if (wqev == NULL) {
		fprintf(stderr, "\tNULL returned\n");
		return -1;
	}
	fprintf(stderr, "\tdestroying workq\n");
	net2_workq_evbase_release(wqev);

	return 0;
}


#define WORKQ_WANT_NONE	0
#define WORKQ_WANT_FAIL	1
#define WORKQ_WANT_OK	2
void
workq_want_job(void *wq_ptr, void *done_ptr)
{
	struct net2_workq	*wq = wq_ptr;
	int			*done = done_ptr;
	int			 error;
	int			 fail = 0;

	if ((error = net2_workq_want(wq, 0)) != EDEADLK) {
		fprintf(stderr, "%s:%d expected EDEADLK return, got %d (%s)\n",
		    __FUNCTION__, __LINE__, error, strerror(error));
		if (error == 0)
			net2_workq_unwant(wq);
		fail++;
	}

	if ((error = net2_workq_want(wq, 1)) != EDEADLK) {
		fprintf(stderr, "%s:%d expected EDEADLK return, got %d (%s)\n",
		    __FUNCTION__, __LINE__, error, strerror(error));
		if (error == 0)
			net2_workq_unwant(wq);
		fail++;
	}

	if (fail)
		*done = WORKQ_WANT_FAIL;
	else
		*done = WORKQ_WANT_OK;
}
int
workq_want()
{
	struct net2_workq_evbase	*wqev;
	struct net2_workq		*wq;
	struct net2_workq_job		 j;
	int				 done;

	done = 0;

	wqev = net2_workq_evbase_new(__FUNCTION__, 0, 0);
	wq = net2_workq_new(wqev);
	net2_workq_evbase_release(wqev);
	net2_workq_init_work(&j, wq, &workq_want_job, wq, &done, 0);
	net2_workq_activate(&j, 0);

	while (net2_workq_aid(wq, 1) == 0);

	net2_workq_deinit_work(&j);
	net2_workq_release(wq);

	switch (done) {
	case WORKQ_WANT_OK:
		return 0;
	case WORKQ_WANT_NONE:
		fprintf(stderr, "\tTest did not run\n");
		break;
	case WORKQ_WANT_FAIL:
		fprintf(stderr, "\tTest failed\n");
		break;
	default:
		fprintf(stderr, "\tUnrecognized completion: %d\n", done);
	}
	return -1;
}


#define COUNT	3
void
workq_persist_job(void *c_ptr, void *j_ptr)
{
	int	*c = c_ptr;

	if (++(*c) == COUNT)
		net2_workq_deactivate(j_ptr);
	fprintf(stderr, "%d, ", *c);
}
int
workq_persist()
{
	struct net2_workq_evbase*wqev;
	struct net2_workq	*wq;
	struct net2_workq_job	 j;
	int			 count = 0;

	wqev = net2_workq_evbase_new(__FUNCTION__, 0, 0);
	wq = net2_workq_new(wqev);
	net2_workq_evbase_release(wqev);

	net2_workq_init_work(&j, wq, &workq_persist_job, &count, &j,
	    NET2_WORKQ_PERSIST);
	net2_workq_activate(&j, 0);

	fprintf(stderr, "\t");
	while (net2_workq_aid(wq, 1) == 0);
	fprintf(stderr, "done\n");
	net2_workq_release(wq);

	if (count == COUNT)
		return 0;
	fprintf(stderr, "\tExpected %d invocations, got %d\n", COUNT, count);
	return -1;
}
#undef COUNT


void
workq_busy_destroy_job()
{
	return;
}
int
workq_busy_destroy()
{
#define COUNT	100
	struct net2_workq_evbase*wqev;
	struct net2_workq	*wq[COUNT];
	struct net2_workq_job	 j[COUNT];
	int			 i;

	wqev = net2_workq_evbase_new(__FUNCTION__, 10, 10);
	for (i = 0; i < COUNT; i++)
		wq[i] = net2_workq_new(wqev);
	net2_workq_evbase_release(wqev);

	for (i = 0; i < COUNT; i++) {
		net2_workq_init_work(&j[i], wq[i], &workq_busy_destroy_job,
		    NULL, NULL, NET2_WORKQ_PERSIST);
	}
	for (i = 0; i < COUNT; i++)
		net2_workq_activate(&j[i], 0);

	/* Give all threads a moment to wakeup. */
#ifdef WIN32
	Sleep(10000);
#else
	sleep(10);
#endif

	for (i = 0; i < COUNT; i++)
		net2_workq_release(wq[i]);

	for (i = 0; i < COUNT; i++)
		net2_workq_deinit_work(&j[i]);

	return 0;
#undef COUNT
}


#define TEST(name)							\
	do {								\
		fprintf(stderr, "TEST %d: %s\n", test++, #name);	\
		if (name()) {						\
			fail++;						\
			fprintf(stderr, "FAIL %d: %s\n",		\
			    test - 1, #name);				\
		}							\
	} while (0)

int
main()
{
	int	test = 0, fail = 0;

	test_start();
	net2_init();

	TEST(workq_evbase_create_destroy);
	TEST(workq_want);
	TEST(workq_persist);
	TEST(workq_busy_destroy);

	net2_cleanup();
	test_fini();

	return fail;
}
