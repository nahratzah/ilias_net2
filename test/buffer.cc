/*
 * Copyright (c) 2012 Ariane van der Steldt <ariane@stack.nl>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <ilias/net2/buffer.h>
#include <array>
#include <memory>
#include <string>
#include <cstring>

void
force_buffer_fork(const ilias::buffer& origin)
{
	const char* fork_contents = "This buffer was forked.";
	ilias::buffer copy = origin;
	copy.append(fork_contents, std::strlen(fork_contents));
}

bool
buf_compare(const ilias::buffer& b, const std::string& s)
{
	if (b.size() != s.length())
		return false;

	std::unique_ptr<char[]> tmp(new char[b.size()]);
	b.copyout(tmp.get(), b.size());
	return (std::memcmp(tmp.get(), s.c_str(), b.size()) == 0);
}



void
test_new_free()
{
	const char* foo = "foo";
	std::unique_ptr<ilias::buffer> empty(new ilias::buffer());
	std::unique_ptr<ilias::buffer> wdata(new ilias::buffer());
	wdata->append(foo, std::strlen(foo));

	empty.reset();
	wdata.reset();
}

void
test_add()
{
	ilias::buffer buf;
	const char* voodoo = "voodoo";
	const char* doll = " doll";

	assert(buf.size() == 0);

	buf.append(voodoo, std::strlen(voodoo));
	assert(buf.size() == std::strlen(voodoo));

	buf.append(doll, std::strlen(doll));
	assert(buf.size() == std::strlen(voodoo) + std::strlen(doll));

	std::unique_ptr<char[]> tmp(new char[buf.size()]);
	buf.copyout(tmp.get(), buf.size());
	const std::string expect = std::string(voodoo) + std::string(doll);
	assert(memcmp(tmp.get(), expect.c_str(), expect.length()) == 0);
}

void
test_prepend()
{
	ilias::buffer pre, post;
	const char* pre_string = "Hello ";
	const char* post_string = "world!";

	pre.append(pre_string, std::strlen(pre_string));
	post.append(post_string, std::strlen(post_string));

	post.prepend(pre);
	assert(buf_compare(post, std::string(pre_string) + std::string(post_string)));
}

void
test_append()
{
	ilias::buffer pre, post;
	const char* pre_string = "Hello ";
	const char* post_string = "world!";

	pre.append(pre_string, std::strlen(pre_string));
	post.append(post_string, std::strlen(post_string));

	pre += post;
	assert(buf_compare(pre, std::string(pre_string) + std::string(post_string)));
}

void
test_copy()
{
	const char* voodoo = "voodoo";
	const char* doll = " doll";
	ilias::buffer copy;

	{
		ilias::buffer original;
		original.append(voodoo, strlen(voodoo));
		force_buffer_fork(original);
		original.append(doll, strlen(doll));

		copy = original;
	}

	assert(buf_compare(copy, std::string(voodoo) + std::string(doll)));
}

void
test_search()
{
	const char*const data = "abbZabababababaabbabaXCOMaababba";
	const char*const abba = std::strstr(data, "abba");
	const char*const xcom = std::strstr(data, "XCOM");
	/* abba2 is situated right at the end of the buffer. */
	const char*const abba2 = std::strstr(xcom, "abba");

	ilias::buffer buf(data, abba - data + 2);
	force_buffer_fork(buf);
	buf.append(abba + 2, strlen(abba + 2));

	ilias::buffer::size_type off = buf.find_string("abba", 4);
	assert(off == abba - data);

	off = buf.find_string("XCOM", 4, off);
	assert(off == xcom - data);

	off = buf.find_string("abba", 4, off);
	assert(off == abba2 - data);

	off = buf.find_string("ZZZ", 3);
	assert(off == ilias::buffer::npos);
}

void
test_remove()
{
	ilias::buffer orig("0123456789", 10);
	force_buffer_fork(orig);
	orig.append("0123456789", 10);

	std::array<ilias::buffer::size_type, 6> sizes = {{
		orig.size(),
		0,
		2,
		17,
		123456,
		-1
	}};

	std::for_each(sizes.begin(), sizes.end(), [&orig](ilias::buffer::size_type sz) {
		const ilias::buffer::size_type after_len = (sz > orig.size() ? orig.size() : orig.size() - sz);
		const bool expect_succes = (sz <= orig.size());
		ilias::buffer copy = orig;

		bool succes = true;
		try {
			copy.drain(sz);
		} catch (const std::out_of_range&) {
			succes = false;
		}

		assert(succes == expect_succes);
		assert(copy.size() == after_len);
	});
}

void
test_truncate()
{
	const std::string foobarbaz = "foobarbaz";
	ilias::buffer buf(foobarbaz.c_str(), 6);
	force_buffer_fork(buf);
	buf.append(foobarbaz.c_str() + 6, foobarbaz.length() - 6);
	assert(buf.size() == 9);

	{
		bool succes = true;
		try {
			buf.truncate(100);
		} catch (const std::out_of_range&) {
			succes = false;
		}
		assert(!succes);
	}

	buf.truncate(7);
	assert(buf_compare(buf, foobarbaz.substr(0, 7)));

	buf.truncate(6);
	assert(buf_compare(buf, foobarbaz.substr(0, 6)));

	buf.truncate(3);
	assert(buf_compare(buf, foobarbaz.substr(0, 3)));

	buf.truncate(0);
	assert(buf_compare(buf, foobarbaz.substr(0, 0)));
}

int
main()
{
	printf("test 1: buffer new, free\n");
	test_new_free();

	printf("test 2: buffer add\n");
	test_add();

	printf("test 3: buffer prepend\n");
	test_prepend();

	printf("test 4: buffer append\n");
	test_append();

	printf("test 5: copy\n");
	test_copy();

	printf("test 6: buffer remove buffer\n");
	test_remove();

	printf("test 7: search\n");
	test_search();

	printf("test 8: truncate\n");
	test_truncate();

	return 0;
}
