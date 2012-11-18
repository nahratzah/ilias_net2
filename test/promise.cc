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

void
test_lazy_read()
{
	auto f = ilias::lazy_future([]() -> int { return 42; });

	TEST(f.valid());
	TEST(!f.ready());
	TEST(!f.has_exception());
	TEST(f.get() == 42);
}

void
test_wq_resolution()
{
	auto wqs = ilias::new_workq_service();
	auto f = ilias::lazy_future(wqs->new_workq(), 0, []() -> int { return 42; });

	TEST(f.valid());
	TEST(!f.ready());
	TEST(!f.has_exception());

	f.start();

	TEST(f.valid());
	TEST(!f.ready());
	TEST(!f.has_exception());

	wqs->aid(10);

	TEST(f.valid());
	TEST(f.ready());
	TEST(!f.has_exception());
	TEST(f.get() == 42);
}

void
SKIP()
{
	return;
}


int test_idx = 0;
#define do_test(fn)							\
	do {								\
		printf("%2d: %s\n", ++test_idx, #fn);			\
		fn();							\
	} while (0)

#define skip_test(fn)							\
	do {								\
		printf("%2d: SKIP: %s\n", ++test_idx, #fn);		\
	} while (0)

int
main()
{
	do_test(test_set_read);
	do_test(test_set_destroy_read);
	do_test(test_lazy_read);
	do_test(test_wq_resolution);

	return 0;
}