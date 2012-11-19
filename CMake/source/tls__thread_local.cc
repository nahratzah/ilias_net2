#include <thread>

thread_local volatile int i;

int
main()
{
	i = 0;
	std::thread t([]() { i = 1; });
	t.join();
	return i;
}
