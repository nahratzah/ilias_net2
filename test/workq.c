#include "test.h"
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
	int			 aid_result;

	wqev = net2_workq_evbase_new(__FUNCTION__, 0, 0);
	wq = net2_workq_new(wqev);
	net2_workq_evbase_release(wqev);

	net2_workq_init_work(&j, wq, &workq_persist_job, &count, &j,
	    NET2_WORKQ_PERSIST);
	net2_workq_activate(&j, 0);

	fprintf(stderr, "\t");
	do {
		aid_result = net2_workq_aid(wq, 1);
		fprintf(stderr, "[aid_result = %s] ",
		    (aid_result == 0 ? "0" : strerror(aid_result)));
	} while (aid_result == 0);
	fprintf(stderr, "done\n");
	net2_workq_release(wq);

	if (count == COUNT)
		return 0;
	fprintf(stderr, "\tExpected %d invocations, got %d\n", COUNT, count);
	return -1;
}
#undef COUNT


void
job_destroy_workq_job(void *wq_ptr, void *done_ptr)
{
	struct net2_workq	*wq = wq_ptr;
	int			*done = done_ptr;

	*done = 1;
	net2_workq_release(wq);
}
int
job_destroy_workq()
{
	struct net2_workq_evbase*wqev;
	struct net2_workq	*wq;
	struct net2_workq_job	 j;
	int			 done = 0;

	wqev = net2_workq_evbase_new(__FUNCTION__, 0, 0);
	wq = net2_workq_new(wqev);
	net2_workq_evbase_release(wqev);

	net2_workq_init_work(&j, wq, &job_destroy_workq_job, wq, &done, 0);
	net2_workq_activate(&j, NET2_WQ_ACT_IMMED);
	net2_workq_deinit_work(&j);

	if (!done)
		return -1;

	return 0;
}


void
workq_busy_destroy_job(void *unused0, void *unused1)
{
	return;
}
int
workq_busy_destroy()
{
#define COUNT	16
	struct net2_workq_evbase*wqev;
	struct net2_workq	**wq;
	struct net2_workq_job	*j;
	int			 i;

	wq = calloc(COUNT, sizeof(*wq));
	j = calloc(COUNT, sizeof(*j));
	if (wq == NULL || j == NULL) {
		fprintf(stderr, "\tFailed to start %s: malloc failed (%s)\n",
		    __FUNCTION__, strerror(errno));
		goto fail;
	}

	wqev = net2_workq_evbase_new(__FUNCTION__, 3, 4);
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
	Sleep(1000);
#else
	sleep(1);
#endif

	fprintf(stderr, "\tReleasing workq...");
	for (i = 0; i < COUNT; i++) {
		net2_workq_release(wq[i]);
		fprintf(stderr, " %d", i);
	}
	fprintf(stderr, "\n");

	fprintf(stderr, "\tDeinitializing jobs...");
	for (i = 0; i < COUNT; i++) {
		net2_workq_deinit_work(&j[i]);
		fprintf(stderr, " %d", i);
	}
	fprintf(stderr, "\n");

fail:
	free(wq);
	free(j);
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

	TEST(workq_evbase_create_destroy);
	TEST(workq_want);
	TEST(workq_persist);
	TEST(job_destroy_workq);
	TEST(workq_busy_destroy);

	test_fini();

	return fail;
}
