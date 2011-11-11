#include <ilias/net2/init.h>
#include <bsd_compat/error.h>
#include <bsd_compat/sysexits.h>

#ifdef WIN32
#include <Winsock2.h>
#endif

ILIAS_NET2_EXPORT void
net2_init()
{
#ifdef WIN32
	WSADATA	wsa_data;
	int	rv;
	int	minor, major;

	if ((rv = WSAStartup(MAKEWORD(2, 2), &wsa_data)) != 0)
		errx(EX_OSERR, "WSAStartup fail: %d", rv);
	major = LOBYTE(wsa_data.wVersion);
	minor = HIBYTE(wsa_data.wVersion);
	if (minor != 2 && major != 2) {
		WSACleanup();
		errx(EX_OSERR, "Winsock %d.%d is too old, "
		    "upgrade your windows.", major, minor);
	}
#endif
}

ILIAS_NET2_EXPORT void
net2_cleanup()
{
#ifdef WIN32
	WSACleanup();
#endif
}
