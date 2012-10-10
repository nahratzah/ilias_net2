#include <utility>

int
foo(int&& bar)
{
	return bar - 1;
}

int
main()
{
	int one = 1;

	return foo(std::move(one));
}
