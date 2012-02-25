#ifndef TEST__INIT_FINI
#define TEST__INIT_FINI

#include <stdio.h>

#ifdef NET2_USE_EXUDE_DEBUG
#include <clog.h>
#include <exude.h>
#endif /* NET2_USE_EXUDE_DEBUG */

static __inline void
test_start()
{
#ifdef NET2_USE_EXUDE_DEBUG
	fprintf(stderr, "Setting up exude...\n");
	clog_init(1);
	clog_set_mask((uint64_t)-1);
	clog_set_flags(CLOG_F_ENABLE | CLOG_F_STDERR | CLOG_F_FUNC | CLOG_F_LINE | CLOG_F_DTIME);
	exude_enable(EXUDE_DBG_ALWAYS);
#else
	fprintf(stderr, "Not using exude...\n");
#endif /* NET2_USE_EXUDE_DEBUG */
}

static __inline void
test_fini()
{
#ifdef NET2_USE_EXUDE_DEBUG
	e_check_memory();
#endif /* NET2_USE_EXUDE_DEBUG */
}

#endif /* TEST__INIT_FINI */
