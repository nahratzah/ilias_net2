#include <ilias/net2/promise.h>
#include "test.h"


void
test_set_read()
{
	auto p = ilias::new_promise<int>();
	auto f = p.get_future();

	TEST(p.valid());
	TEST(f.valid());
	TEST(!f.ready());
	TEST(!f.has_exception());

	p.set(42);

	TEST(p.valid());
	TEST(f.valid());
	TEST(f.ready());
	TEST(!f.has_exception());
	TEST(f.get() == 42);
}

void
test_set_destroy_read()
{
	ilias::future<int> f;
	{
		ilias::promise<int> p;

		TEST(p.valid());
		TEST(!f.valid());
		TEST(!f.ready());
		TEST(!f.has_exception());

		p.set(42);

		f = p.get_future();
	}

	TEST(f.valid());
	TEST(f.ready());
	TEST(!f.has_exception());
	TEST(f.get() == 42);
}


int test_idx = 0;
#define do_test(fn)							\
	do {								\
		printf("%2d: %s\n", ++test_idx, #fn);			\
		fn();							\
	} while (0)

int
main()
{
	do_test(test_set_read);
	do_test(test_set_destroy_read);

	return 0;
}
