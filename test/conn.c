#include "testconn.h"
#include <ilias/net2/init.h>
#include <ilias/net2/connection.h>
#include <ilias/net2/evbase.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/packet.h>
#include <stdio.h>
#include <string.h>
#include <event2/event.h>
#include <assert.h>

int fail = 0;
#define DOODLE	"Yankee Doodle sing a song\ndoodaa, doodaa"
#define PH_LEN	net2_ph_overhead

int	cb_done_called;
int	cb_fail_called;



int
test_conn_create_destroy()
{
	struct net2_connection	*c1, *c2;

	printf("test 1: testing connection destroy invocation\n");
	if (testconn(&c1, &c2)) {
		printf("  failed to create connections\n");
		return -1;
	}

	net2_connection_destroy(c1);
	net2_connection_destroy(c2);
	return 0;
}

int
main()
{
	net2_init();
 
	if (test_conn_create_destroy())
		return -1;

	net2_cleanup();
	return fail;
}
