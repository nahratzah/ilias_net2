#include <type_traits>

class foo
{
	foo();
	foo(int);
};

int
main()
{
	/* Test if these templates instantiate correctly. */
	bool test =
	    std::is_nothrow_constructible<foo, int>::value &&
	    std::is_nothrow_destructable<foo>::value &&
	    std::is_nothrow_copy_constructable<foo>::value &&
	    std::is_nothrow_move_constructable<foo>::value;

	return 0;
}
