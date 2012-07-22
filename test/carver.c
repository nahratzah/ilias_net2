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
#include "test.h"
#include <ilias/net2/init.h>
#include <ilias/net2/carver.h>
#include <ilias/net2/promise.h>
#include <ilias/net2/buffer.h>
#include <ilias/net2/tx_callback.h>
#include <ilias/net2/encdec_ctx.h>
#include <ilias/net2/bsd_compat/secure_random.h>
#include <ilias/net2/bsd_compat/minmax.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int fail = 0;

const char *buffer_data = "Op zekeren dag dat de opstandelingen op-nieuw "
    "waren geslagen, doolde hy rond in een dorp dat pas veroverd was door "
    "het Nederlandsche leger, en dus in brand stond. Saidjah wist dat de "
    "bende die daar vernietigd was geworden, grootendeels uit Bantammers "
    "had bestaan. Als een spook waarde hij rond in de huizen die nog niet "
    "geheel verbrand waren, en vond het lyk van Adinda's vader met een "
    "klewang-bajonetwonde in de borst. Naast hem zag Saidjah de drie "
    "vermoorde broeders van Adinda, jongelingen, byna kinderen nog, en een "
    "weinig verder lag het lyk van Adinda, naakt, afschuwelijk mishandeld.";

struct net2_buffer*
mk_buffer()
{
	struct net2_buffer
			*out;

	if ((out = net2_buffer_new()) == NULL) {
		fprintf(stderr, "Could not allocate buffer.\n");
		abort();
	}

	if ((net2_buffer_add_reference(out, (void*)buffer_data,
	    strlen(buffer_data) + 1, NULL, NULL)) != 0) {
		fprintf(stderr, "Could not reference buffer data.\n");
		abort();
	}

	return out;
}

void
mk_encdec_ctx(struct net2_encdec_ctx *ctx)
{
	struct net2_pvlist	 pvlist;

	if (net2_pvlist_init(&pvlist) ||
	    net2_pvlist_add(&pvlist, &net2_proto, net2_proto.version) ||
	    net2_encdec_ctx_init(ctx, &pvlist, NULL)) {
		fprintf(stderr, "Failed to create encoder context.\n");
		abort();
	}
	net2_pvlist_deinit(&pvlist);
}

void
transmit(struct net2_carver *carver, struct net2_combiner *combiner,
    struct net2_workq *wq, size_t packet_sz)
{
	struct net2_tx_callback	 callbacks;
	struct net2_buffer	*buf;
	int			 error;
	struct net2_encdec_ctx	 ctx;
	char			*hex;

	mk_encdec_ctx(&ctx);

	printf("Starting transmit with packet size %zu\n", packet_sz);

	while (!net2_carver_is_done(carver)) {
		if ((buf = net2_buffer_new()) == NULL) {
			fprintf(stderr, "Failed to allocate buffer.\n");
			abort();
		}
		if ((error = net2_txcb_init(&callbacks)) != 0) {
			fprintf(stderr, "Failed to init tx_callback: %d\n",
			    error);
			abort();
		}

		error = net2_carver_get_transmit(carver, &ctx,
		    wq, buf, &callbacks, packet_sz);
		if (error != 0) {
			fprintf(stderr, "carver_get_trnasmit: fatal error "
			    "%d: %s\n", error, strerror(error));
			abort();
		}
		if (net2_buffer_empty(buf))
			goto skip;

		hex = net2_buffer_hex(buf, &malloc);
		printf("Sent buffer: %s\n", hex);
		free(hex);

		error = net2_combiner_accept(combiner, &ctx,
		    buf);
		if (error != 0) {
			fprintf(stderr, "combiner_accept: fatal error "
			    "%d: %s\n", error, strerror(error));
			abort();
		}
		if (!net2_buffer_empty(buf)) {
			fprintf(stderr, "combiner_accept: "
			    "did not consume entire buffer\n");
			abort();
		}

		net2_txcb_ack(&callbacks);
skip:
		net2_txcb_nack(&callbacks);
		net2_txcb_deinit(&callbacks);
		net2_buffer_free(buf);
	}

	net2_encdec_ctx_deinit(&ctx);
	printf("Done transmitting\n");
	printf("Waiting for combiner to signal ready...");
	net2_promise_wait(net2_combiner_prom_ready(combiner));
	printf(" ready\n");
}

int
test_run(size_t packet_sz, enum net2_carver_type carver_type)
{
	struct net2_buffer	*original, *copy;
	struct net2_carver	 carver;
	struct net2_combiner	 combiner;
	struct net2_workq	*wq;
	struct net2_workq_evbase*wqev;

	if ((wqev = net2_workq_evbase_new("test_run", 1, 1)) == NULL) {
		fprintf(stderr, "Failed to init net2_workq_evbase.\n");
		abort();
	}
	if ((wq = net2_workq_new(wqev)) == NULL) {
		fprintf(stderr, "Failed to init net2_workq.\n");
		abort();
	}
	net2_workq_evbase_release(wqev);
	original = mk_buffer();

	if (net2_carver_init(&carver, carver_type, original)) {
		fprintf(stderr, "Failed to init carver.\n");
		return 1;
	}
	if (net2_combiner_init(&combiner, carver_type)) {
		fprintf(stderr, "Failed to init combiner.\n");
		return 1;
	}

	transmit(&carver, &combiner, wq, packet_sz);

	if (!net2_carver_is_done(&carver)) {
		fprintf(stderr, "Carver has not completed...\n");
		fail++;
	}
	if (!net2_combiner_is_done(&combiner)) {
		fprintf(stderr, "Combiner has not completed...\n");
		fail++;
	}

	copy = net2_combiner_data(&combiner);
	if (copy == NULL) {
		fprintf(stderr, "Combiner returned NULL result...\n");
		fail++;
	} else if (net2_buffer_cmp(original, copy) != 0) {
		fprintf(stderr, "Transmitted result differs from original...\n");
		fail++;
	}
	net2_buffer_free(copy);

	net2_carver_deinit(&carver);
	net2_combiner_deinit(&combiner);
	net2_buffer_free(original);

	net2_workq_release(wq);

	return 0;
}

int
main()
{
	test_start();
	net2_init();

	/* 16 BIT */
	if (test_run(17, NET2_CARVER_16BIT))
		fail++;
	fprintf(stderr, "\n\n");
	if (test_run(32, NET2_CARVER_16BIT))
		fail++;
	fprintf(stderr, "\n\n");
	if (test_run(1000000, NET2_CARVER_16BIT))
		fail++;

	/* 32 BIT */
	if (test_run(17, NET2_CARVER_32BIT))
		fail++;
	fprintf(stderr, "\n\n");
	if (test_run(32, NET2_CARVER_32BIT))
		fail++;
	fprintf(stderr, "\n\n");
	if (test_run(1000000, NET2_CARVER_32BIT))
		fail++;

	net2_cleanup();
	test_fini();

	return fail;
}
