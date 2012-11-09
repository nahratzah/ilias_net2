#ifndef TEST__INIT_FINI
#define TEST__INIT_FINI

#include <cstdio>
#include <cstdlib>

#define TEST(x)								\
	do {								\
		if (!(x)) {						\
			fprintf(stderr, "Test at %s:%d failed: %s\n",	\
			    __FILE__, __LINE__, #x);			\
			exit(1);					\
		}							\
	} while (0)

#endif /* TEST__INIT_FINI */
