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
test_workq_resolution()
{
	auto wqs = ilias::new_workq_service(0);
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
test_broken_promise()
{
	auto f = ilias::new_promise<int>().get_future();
	bool broken_prom_caught = false;

	TEST(f.valid());
	TEST(f.ready());
	TEST(f.has_exception());

	try {
		f.get();
	} catch (const ilias::broken_promise&) {
		printf("\tbroken promise error, as expected\n");
		broken_prom_caught = true;
	} catch (...) {
		fprintf(stderr, "\texpected broken promise error, got something else...\n");
		std::unexpected();
	}
	TEST(broken_prom_caught);
}

void
test_set_exception()
{
	auto p = ilias::new_promise<int>();
	auto f = p.get_future();
	bool caught = false;

	p.emplace_exception<int>(42);

	TEST(f.valid());
	TEST(f.ready());
	TEST(f.has_exception());

	try {
		f.get();
	} catch (const int& except) {
		printf("\tcaught emplaced exception, as expected\n");
		TEST(except == 42);
		caught = true;
	} catch (...) {
		fprintf(stderr, "\texpected emplaced exception, got something else...\n");
		std::unexpected();
	}
	TEST(caught);
}

void
test_lazy_exception()
{
	auto f = ilias::lazy_future([]() -> int { throw int(42); });
	bool caught = false;

	TEST(f.valid());
	TEST(!f.ready());
	TEST(!f.has_exception());

	try {
		f.get();
	} catch (const int& except) {
		printf("\tcaught emplaced exception, as expected\n");
		TEST(except == 42);
		caught = true;
	} catch (...) {
		fprintf(stderr, "\texpected emplaced exception, got something else...\n");
		std::unexpected();
	}
	TEST(caught);

	TEST(f.ready());
	TEST(f.has_exception());
}

void
test_workq_exception()
{
	auto wqs = ilias::new_workq_service(0);
	auto f = ilias::lazy_future(wqs->new_workq(), 0, []() -> int { throw int(42); });
	bool caught = false;

	TEST(f.valid());
	TEST(!f.ready());
	TEST(!f.has_exception());

	f.start();
	wqs->aid(10);

	try {
		f.get();
	} catch (const int& except) {
		printf("\tcaught emplaced exception, as expected\n");
		TEST(except == 42);
		caught = true;
	} catch (...) {
		fprintf(stderr, "\texpected emplaced exception, got something else...\n");
		std::unexpected();
	}
	TEST(caught);

	TEST(f.ready());
	TEST(f.has_exception());
}

void
test_callbacks()
{
	static int sum;
	sum = 0;

	auto f = ilias::lazy_future([]() -> int { return 1; });
	for (int i = 0; i < 42; ++i)
		f.add_callback([](int v) { sum += v; });

	TEST(f.valid());
	TEST(!f.ready());
	TEST(sum == 0);

	/* Resolution. */
	TEST(f.get() == 1);
	TEST(sum == 42);
}


int
main()
{
	do_test(test_set_read);
	do_test(test_set_destroy_read);
	do_test(test_lazy_read);
	do_test(test_workq_resolution);
	do_test(test_broken_promise);
	do_test(test_set_exception);
	do_test(test_lazy_exception);
	do_test(test_workq_exception);
	do_test(test_callbacks);

	return 0;
}
