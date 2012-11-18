#ifndef TEST__INIT_FINI
#define TEST__INIT_FINI

#include <cstdio>
#include <cstdlib>

#define TEST(x)								\
	do {								\
		if (!(x)) {						\
			fprintf(stderr, "Test at %s:%d failed: %s\n",	\
			    __FILE__, __LINE__, #x);			\
			std::terminate();				\
		}							\
	} while (0)

int test_idx = 0;
#define do_test(fn)							\
	do {								\
		std::printf("%2d: %s\n", ++test_idx, #fn);		\
		fn();							\
	} while (0)

#define skip_test(fn)							\
	do {								\
		std::printf("%2d: SKIP: %s\n", ++test_idx, #fn);	\
	} while (0)

#endif /* TEST__INIT_FINI */
