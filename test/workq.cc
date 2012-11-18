#include <ilias/net2/workq.h>
#include <vector>
#include "test.h"


void
test_workq_service_create()
{
	auto wqs = ilias::new_workq_service();
}

void
test_create_destroy()
{
	auto wqs = ilias::new_workq_service();
	auto wq = wqs->new_workq();
	wqs.reset();
	wq.reset();
}

void
test_job_immed()
{
	int i = 0;
	auto job = ilias::new_workq_service()->new_workq()->new_job([&i]() { ++i; });

	TEST(i == 0);
	job->activate(ilias::workq_job::ACT_IMMED);
	TEST(i == 1);
}

void
test_once()
{
	static int i;
	i = 0;
	auto wqs = ilias::new_workq_service();
	auto wq = wqs->new_workq();

	wq->once([]() { ++i; });
	wqs->aid(10);
	TEST(i == 1);
}

void
test_persist()
{
	static int i;
	i = 0;
	auto wqs = ilias::new_workq_service();
	auto wq = wqs->new_workq();
	ilias::workq_job_ptr job;

	job = wq->new_job(ilias::workq_job::TYPE_PERSIST, [&job]() {
		if (++i == 10)
			job->deactivate();
	    });

	while (wqs->aid());
	TEST(i ==10);
}

void
test_coroutine()
{
	typedef std::vector<unsigned long long> vec;

	vec v(1000);
	std::vector<std::function<void()> > fn;

	while (fn.size() < v.size()) {
		vec::size_type idx = fn.size();
		fn.push_back([&v, idx]() {
			vec::value_type v1 = 1, v2 = 1;
			for (vec::size_type i = 0; i < idx; ++i)
				std::tie(v1, v2) = std::make_tuple(v2, v1 + v2);
			v[idx] = v1;
		    });
	}

	{
		auto wqs = ilias::new_workq_service();
		wqs->new_workq()->once(std::move(fn));

		/* Wait until the job completes. */
		while (wqs->aid());
	}

	TEST(v[0] == 1);
	TEST(v[1] == 1);
	for (vec::size_type i = 2; i < v.size(); ++i)
		TEST(v[i] == v[i - 2] + v[i - 1]);
}


int
main()
{
	do_test(test_workq_service_create);
	do_test(test_create_destroy);
	do_test(test_job_immed);
	do_test(test_once);
	do_test(test_persist);
	do_test(test_coroutine);

	return 0;
}
