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
#include <stdio.h>
#include <string.h>

int fail = 0;

int
test_new_free()
{
	struct net2_buffer	*buf;

	if ((buf = net2_buffer_new()) == NULL) {
		printf("  net2_buffer_new failed\n");
		fail++;
		return -1;
	}

	net2_buffer_free(buf);
	return 0;
}

int
test_add()
{
	struct net2_buffer	*buf;
	void			*p;

	if ((buf = net2_buffer_new()) == NULL) {
		printf("  net2_buffer_new failed\n");
		fail++;
		return -1;
	}

	if (net2_buffer_length(buf) != 0) {
		printf("  empty buffer has length %lu\n",
		    (unsigned long)net2_buffer_length(buf));
		fail++;
	}

	if (net2_buffer_add(buf, "voodoo", strlen("voodoo"))) {
		printf("  net2_buffer_add fail\n");
		fail++;
	}

	if (net2_buffer_length(buf) != strlen("voodoo")) {
		printf("  expected buffer with length %lu, got %lu\n",
		    (unsigned long)strlen("voodoo"),
		    (unsigned long)net2_buffer_length(buf));
		fail++;
	}

	if (net2_buffer_add(buf, " doll", strlen(" doll"))) {
		printf("  net2_buffer_add fail\n");
		fail++;
	}

	if (net2_buffer_length(buf) != strlen("voodoo doll")) {
		printf("  expected buffer with length %lu, got %lu\n",
		    (unsigned long)strlen("voodoo doll"),
		    (unsigned long)net2_buffer_length(buf));
		fail++;
	}

	if (net2_buffer_pullup(buf, 3) == NULL) {
		printf("  pullup 3 bytes failed\n");
		fail++;
	}

	if ((p = net2_buffer_pullup(buf, strlen("voodoo doll"))) == NULL) {
		printf("  pullup %d bytes failed\n",
		    (int)strlen("voodoo doll"));
		fail++;
	} else if (strncmp(p, "voodoo doll", 11) != 0) {
		printf("  buffer contents invalid\n"
		     "\texpected: %s\n"
		     "\tgot     : %11s\n",
		    "voodoo",
		    (char*)p);
	}

	net2_buffer_free(buf);
	return 0;
}

int
test_prepend()
{
	struct net2_buffer	*pre, *post;
	const char		*p;

	pre = net2_buffer_new();
	post = net2_buffer_new();
	if (pre == NULL || post == NULL) {
		printf("  net2_buffer_new failed\n");
		fail++;
		return -1;
	}

	if (net2_buffer_add(pre, "Hel", strlen("Hel")) ||
	    net2_buffer_add(pre, "lo ", strlen("lo ")) ||
	    net2_buffer_add(post, "wor", strlen("wor")) ||
	    net2_buffer_add(post, "ld!", strlen("ld!"))) {
		printf("  net2_buffer_add failed\n");
		fail++;
		return -1;
	}

	if (net2_buffer_prepend(post, pre)) {
		printf("  net2_buffer_prepend failed\n");
		fail++;
		return -1;
	}

	if ((p = net2_buffer_pullup(post, net2_buffer_length(post))) == NULL) {
		printf("  net2_buffer_pullup of \"post\" failed\n");
		fail++;
		return -1;
	}
	if (strncmp("Hello world!", p, strlen("Hello world!")) != 0) {
		printf("  contents is wrong\n"
		    "\texpected: Hello world!\n"
		    "\tgot     : %*s\n",
		    (int)net2_buffer_length(post), p);
		fail++;
	}

	if ((p = net2_buffer_pullup(pre, net2_buffer_length(pre))) == NULL) {
		printf("  net2_buffer_pullup of \"pre\" failed\n");
		fail++;
		return -1;
	}
	if (strncmp("Hello ", p, strlen("Hello ")) != 0) {
		printf("  contents is wrong\n"
		    "\texpected: Hello \n"
		    "\tgot     : %*s\n",
		    (int)net2_buffer_length(pre), p);
		fail++;
	}

	net2_buffer_free(pre);
	net2_buffer_free(post);
	return 0;
}

int
test_append()
{
	struct net2_buffer	*pre, *post;
	const char		*p;

	pre = net2_buffer_new();
	post = net2_buffer_new();
	if (pre == NULL || post == NULL) {
		printf("  net2_buffer_new failed\n");
		fail++;
		return -1;
	}

	if (net2_buffer_add(pre, "Hel", strlen("Hel")) ||
	    net2_buffer_add(pre, "lo ", strlen("lo ")) ||
	    net2_buffer_add(post, "wor", strlen("wor")) ||
	    net2_buffer_add(post, "ld!", strlen("ld!"))) {
		printf("  net2_buffer_add failed\n");
		fail++;
		return -1;
	}

	if (net2_buffer_append(pre, post)) {
		printf("  net2_buffer_prepend failed\n");
		fail++;
		return -1;
	}

	if ((p = net2_buffer_pullup(pre, net2_buffer_length(pre))) == NULL) {
		printf("  net2_buffer_pullup of \"pre\" failed\n");
		fail++;
		return -1;
	}
	if (strncmp("Hello world!", p, strlen("Hello world!")) != 0) {
		printf("  contents is wrong\n"
		    "\texpected: Hello world!\n"
		    "\tgot     : %*s\n",
		    (int)net2_buffer_length(pre), p);
		fail++;
	}

	if ((p = net2_buffer_pullup(post, net2_buffer_length(post))) == NULL) {
		printf("  net2_buffer_pullup of \"post\" failed\n");
		fail++;
		return -1;
	}
	if (strncmp("world!", p, strlen("world!")) != 0) {
		printf("  contents is wrong\n"
		    "\texpected: world!\n"
		    "\tgot     : %*s\n",
		    (int)net2_buffer_length(pre), p);
		fail++;
	}

	net2_buffer_free(pre);
	net2_buffer_free(post);
	return 0;
}

int
test_copy()
{
	struct net2_buffer	*a, *b;
	const char		*p;

	if ((a = net2_buffer_new()) == NULL) {
		printf("  net2_buffer_new fail\n");
		fail++;
		return -1;
	}
	if (net2_buffer_add(a, "voodoo", strlen("voodoo"))) {
		printf("  net2_buffer_add fail\n");
		fail++;
		return -1;
	}

	if ((b = net2_buffer_copy(a)) == NULL) {
		printf("  net2_buffer_copy fail\n");
		fail++;
		return 0;	/* Can't complete test. */
	}

	if (net2_buffer_length(a) != net2_buffer_length(b)) {
		printf("  copied buffer has different length\n"
		    "\texpected: %lu (should be %lu)\n"
		    "\tgot     : %lu\n",
		    (unsigned long)net2_buffer_length(a),
		    (unsigned long)strlen("voodoo"),
		    (unsigned long)net2_buffer_length(b));
		fail++;
		return 0;	/* Can't complete test. */
	}

	if (net2_buffer_add(a, " doll", strlen(" doll"))) {
		printf("  net2_buffer_add \" doll\" fail\n");
		fail++;
		return -1;
	}

	if (net2_buffer_add(b, " magic", strlen(" magic"))) {
		printf("  net2_buffer_add \" magic\" fail\n");
		fail++;
		return -1;
	}

	if ((p = net2_buffer_pullup(a, net2_buffer_length(a))) == NULL) {
		printf("  net2_buffer_pullup of a fail\n");
		fail++;
		return -1;
	}
	if (net2_buffer_length(a) != strlen("voodoo doll") ||
	    strncmp(p, "voodoo doll", strlen("voodoo doll")) != 0) {
		printf("  a content mismatch\n"
		    "\texpected: %s\n"
		    "\tgot     : %*s\n",
		    "voodoo doll",
		    (int)net2_buffer_length(a), p);
		fail++;
	}

	if ((p = net2_buffer_pullup(b, net2_buffer_length(b))) == NULL) {
		printf("  net2_buffer_pullup of b fail\n");
		fail++;
		return -1;
	}
	if (net2_buffer_length(b) != strlen("voodoo magic") ||
	    strncmp(p, "voodoo magic", strlen("voodoo magic")) != 0) {
		printf("  b content mismatch\n"
		    "\texpected: %s\n"
		    "\tgot     : %*s\n",
		    "voodoo magic",
		    (int)net2_buffer_length(b), p);
		fail++;
	}

	net2_buffer_free(a);
	net2_buffer_free(b);
	return 0;
}

int
test_search()
{
	char			*data = "abbZabababababaabbabaXCOMaababba";
	char			*abba = strstr(data, "abba");
	char			*xcom = strstr(data, "XCOM");
	/* abba2 is situated right at the end of the buffer. */
	char			*abba2 = strstr(xcom, "abba");
	struct net2_buffer	*buf, *force_fork;
	struct net2_buffer_ptr	 ptr, ptr2;

	if ((buf = net2_buffer_new()) == NULL) {
		printf("  net2_buffer_new fail\n");
		fail++;
		return -1;
	}
	if (net2_buffer_add(buf, data, (size_t)(abba - data) + 2)) {
		printf("  net2_buffer_add fail\n");
		fail++;
		return -1;
	}
	if ((force_fork = net2_buffer_copy(buf)) == NULL) {
		printf("  net2_buffer_copy fail\n");
		fail++;
		return -1;
	}
	if (net2_buffer_add(force_fork, abba + 2, strlen(abba + 2))) {
		printf("  net2_buffer_copy forcefork fail\n");
		fail++;
		return -1;
	}
	if (net2_buffer_add(buf, abba + 2, strlen(abba + 2))) {
		printf("  net2_buffer_copy buf fail\n");
		fail++;
		return -1;
	}
	net2_buffer_free(force_fork);

	if (net2_buffer_search(buf, &ptr, "abba", 4, NULL)) {
		printf("  net2_buffer_search failed to find abba, "
		    "should have found it though...\n");
		fail++;
	} else if (ptr.pos != (size_t)(abba - data)) {
		printf("  net2_buffer_search found abba at %lu, expected %lu\n",
		    (unsigned long)ptr.pos,
		    (unsigned long)(abba - data));
		fail++;
	}

	if (net2_buffer_search(buf, &ptr2, "XCOM", 4, &ptr)) {
		printf("  net2_buffer_search failed to find XCOM, "
		    "should have found it though...\n");
		fail++;
	} else if (ptr2.pos != (size_t)(xcom - data)) {
		printf("  net2_Buffer_search found XCOM at %lu, expected %lu\n",
		    (unsigned long)ptr2.pos,
		    (unsigned long)(xcom - data));
		fail++;
	}

	if (net2_buffer_search(buf, &ptr, "abba", 4, &ptr2)) {
		printf("  net2_buffer_search failed to find abba again, "
		    "however abba is still present...");
		fail++;
	} else if (ptr.pos != (size_t)(abba2 - data)) {
		printf("  net2_buffer_search found second abba at %lu, "
		    "expected %lu\n",
		    (unsigned long)ptr.pos,
		    (unsigned long)(abba2 - data));
		fail++;
	}

	if (net2_buffer_search(buf, &ptr, "ZZZ", 3, &ptr) == 0) {
		printf("  net2_buffer_search found ZZZ at %lu, "
		    "while it is not present in data!\n",
		    (unsigned long)ptr.pos);
		fail++;
	}

	net2_buffer_free(buf);
	return 0;
}

int
test_remove()
{
	struct net2_buffer		*orig, *tmp, *drained, *out;
	size_t				 sizes[] = {
		0,	/* Filled in with buffer_length(orig) */
		0,
		2,
		17,
		123456,
		-1
	};
	size_t				 expect_out, expect_drain;
	size_t				 i, result;

	if ((orig = net2_buffer_new()) == NULL) {
		printf("  net2_buffer_new fail");
		fail++;
		return -1;
	}
	if (net2_buffer_add(orig, "0123456789", 10)) {
		printf("  net2_buffer_add fail");
		fail++;
		return -1;
	}

	/* Force the buffer to fork. */
	if ((tmp = net2_buffer_copy(orig)) == NULL)
		printf("  buffer failure; test may not be accurate");
	else {
		if (net2_buffer_add(tmp, "dummy", 5))
			printf("  buffer failure; test may not be accurate");
		if (net2_buffer_add(orig, "0123456789", 10))
			printf("  buffer failure; test may not be accurate");
		net2_buffer_free(tmp);
	}

	/* Fill in special sizes[0]. */
	sizes[0] = net2_buffer_length(orig);

	for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		/* Predict outcome. */
		if (sizes[i] > net2_buffer_length(orig)) {
			expect_out = net2_buffer_length(orig);
			expect_drain = 0;
		} else {
			expect_out = sizes[i];
			expect_drain = net2_buffer_length(orig) - sizes[i];
		}

		/* Print what we're doing. */
		printf("  %2lu: call net2_buffer_remove_buffer with sz=%lu,\n"
		    "      expect out %lu, expect drain %lu\n",
		    (unsigned long)i, (unsigned long)sizes[i],
		    (unsigned long)expect_out, (unsigned long)expect_drain);

		/* Copy original into drained. */
		if ((drained = net2_buffer_copy(orig)) == NULL) {
			printf("  net2_buffer_copy fail");
			fail++;
			return -1;
		}

		/* Initialize out. */
		if ((out = net2_buffer_new()) == NULL) {
			printf("  net2_buffer_new fail");
			fail++;
			return -1;
		}

		result = net2_buffer_remove_buffer(drained, out, sizes[i]);
		printf("      yielded %lu\n", (unsigned long)result);

		if (result != expect_out) {
			printf("  net2_buffer_remove_buffer returned %lu, "
			    "failing to remove "
			    "<=%lu bytes from buffer with length %lu\n",
			    (unsigned long)result,
			    (unsigned long)sizes[i],
			    (unsigned long)net2_buffer_length(orig));
			fail++;
		} else if (net2_buffer_length(out) != expect_out ||
		    net2_buffer_length(drained) != expect_drain) {
			printf("  net2_buffer_remove_buffer: out len = %lu, "
			    "expected %lu\n",
			    (unsigned long)net2_buffer_length(out),
			    (unsigned long)expect_out);
			printf("  net2_buffer_remove_buffer: drain len = %lu, "
			    "expected %lu\n",
			    (unsigned long)net2_buffer_length(drained),
			    (unsigned long)expect_drain);
			fail++;
		} else if (expect_drain == 0 &&
		    net2_buffer_cmp(out, orig) != 0) {
			printf("  net2_buffer_remove_buffer: "
			    "out and orig not equal\n");
			fail++;
		} else {
			if (net2_buffer_append(out, drained)) {
				printf("  net2_buffer_append fail");
				fail++;
				return -1;
			}
			if (net2_buffer_cmp(out, orig) != 0) {
				printf("  net2_buffer_remove_buffer: "
				    "out + drained != original buffer\n");
				fail++;
			}
		}

		net2_buffer_free(out);
		net2_buffer_free(drained);
	}

	return 0;
}

int
main()
{
	printf("test 1: buffer new, free\n");
	if (test_new_free())
		return -1;

	printf("test 2: buffer add\n");
	if (test_add())
		return -1;

	printf("test 3: buffer prepend\n");
	if (test_prepend())
		return -1;

	printf("test 4: buffer append\n");
	if (test_append())
		return -1;

	printf("test 5: copy\n");
	if (test_copy())
		return -1;

	printf("test 6: buffer remove buffer\n");
	if (test_remove())
		return -1;

	printf("test 7: search\n");
	if (test_search())
		return -1;

	return fail;
}
