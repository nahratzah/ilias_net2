#include <ilias/net2/mutex.h>
#include <bsd_compat/sysexits.h>
#include <bsd_compat/error.h>
#include <windows.h>

/*
 * Note that struct net2_mutex is not defined: it is an implementation detail
 * hidden away by windows as well.
 */

/*
 * Allocate a new mutex.
 */
ILIAS_NET2_LOCAL struct net2_mutex*
net2_mutex_alloc()
{
	struct net2_mutex	*m;

	m = (struct net2_mutex*)CreateMutex(NULL, FALSE, NULL);
	if (m == NULL)
		warnx("CreateMutex error: %d\n", GetLastError());
	return m;
}

/*
 * Free a mutex.
 */
ILIAS_NET2_LOCAL void
net2_mutex_free(struct net2_mutex *m)
{
	if (m)
		CloseHandle((HANDLE)m);
}

/*
 * Lock a mutex.
 */
ILIAS_NET2_LOCAL void
net2_mutex_lock(struct net2_mutex *m)
{
	DWORD dwWaitResult;

	dwWaitResult = WaitForSingleObject((HANDLE)m, INFINITE);
	switch (dwWaitResult) {
	case WAIT_OBJECT_0:
		break;
	case WAIT_ABANDONED:
		/* Apparently someone died with the mutex locked. */
		errx(EX_OSERR, "someone died with mutex locked");
	default:
		errx(EX_OSERR, "unexpected result %u from WaitForSingleObject "
		    "waiting on mutex", (unsigned int)dwWaitResult);
	}
}

/*
 * Unlock a previously locked mutex.
 */
ILIAS_NET2_LOCAL void
net2_mutex_unlock(struct net2_mutex *m)
{
	DWORD rv;

	if (!(rv = ReleaseMutex((HANDLE)m)))
		errx(EX_OSERR, "error %u releasing mutex", (unsigned int)rv);
}
