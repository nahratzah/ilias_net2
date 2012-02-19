#ifndef TEST__INIT_FINI
#define TEST__INIT_FINI

#include <clog.h>
#include <exude.h>

static __inline void
test_start()
{
#ifdef NET2_USE_EXUDE_DEBUG
	clog_init(1);
	clog_set_flags(CLOG_F_ENABLE | CLOG_F_STDERR);
	exude_enable(EXUDE_DBG_ALWAYS);
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
