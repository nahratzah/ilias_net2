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
#include <ilias/net2/connstats.h>
#include <string.h>
#include <stdio.h>
#include <ilias/net2/bsd_compat/clock.h>
#include <ilias/net2/bsd_compat/error.h>
#include <ilias/net2/bsd_compat/sysexits.h>
#ifdef WIN32
#include <Windows.h>
#endif

/* Define CONNSTATS_PRINTSTATS to periodically print statistics on the connection. */
/* #define CONNSTATS_PRINTSTATS */

#define MIN_WIRE_SZ	512 /* bytes */

/*
 * An algorithm to compute the square root of an int64, using only integer math.
 * Takes 32 steps.
 */
static uint64_t
isqrt64(uint64_t v)
{
	uint32_t		r = 0;
	int			i;

	for (i = 31; i >= 0; i--) {
		if (v >= ((uint64_t)1 << (2 * i))) {
			v -= ((uint64_t)1 << (2 * i));
			r |= ((uint32_t)1 << i);
		}
	}
	return r;
}

/* Rebase a set of summed squares for stddev to a new average. */
static int64_t
rebase_sumsq(int64_t sumsquare, int64_t sum, int64_t count, int64_t avg_inc)
{
	int64_t			rv;

	rv = sumsquare +
	    (2 * avg_inc * sum) +
	    count * avg_inc * avg_inc;
	/* Rounding errors? */
	if (rv < 0)
		rv = 0;
	return rv;
}

/*
 * Shift all segments to the left, losing the left-most (oldest) segment.
 * Creates a new zeroed youngest segment at the last position of the array.
 *
 * Update statistics based on the datapoints present prior to shifting.
 */
static void
segment_shift(struct net2_connstats *cs)
{
	int			i;
	uint32_t		sent, arrived, lost;
	int64_t			sum, count;

	/*
	 * First, use all segments to update statistics.
	 */

	/* Arrival change. */
	sent = arrived = 0;
	for (i = 0; i < NET2_STATS_LEN; i++) {
		sent += cs->segments[i].arrive.sent;
		arrived += cs->segments[i].arrive.arrived;
	}
	/* Don't update if nothing happened. */
	if (sent == 0)
		return;

	/* Calculate arrival chance. */
	cs->arrival_chance = 100 * arrived / sent;

	/* # packet retransmits for 97% reliability. */
	if (sent > 0) {
		uint64_t loss_accept = 3 * sent / 100;
		uint64_t lost_n = lost = sent - arrived;

		/* send_for_97 is arbitrarily capped at 32 packets. */
		cs->send_for_97 = 1;
		while (loss_accept < lost_n && cs->send_for_97 < 32) {
			loss_accept *= sent;
			lost_n *= lost;
			cs->send_for_97++;
		}
	}

	/* Used bandwidth. */
	cs->bandwidth = 0;
	for (i = 0; i < NET2_STATS_LEN; i++)
		cs->bandwidth += cs->segments[i].bytes_ok;

	/* Packets per second. */
	cs->packets_sec = arrived / NET2_STATS_LEN;

	/* Largest possible packet. */
	cs->wire_sz = MIN_WIRE_SZ;
	for (i = 0; i < NET2_STATS_LEN; i++) {
		if (cs->wire_sz < cs->segments[i].max_wire_sz)
			cs->wire_sz = cs->segments[i].max_wire_sz;
	}
	/* Smallest failed packet with size > wire_sz. */
	cs->over_sz = 0;
	for (i = 0; i < NET2_STATS_LEN; i++) {
		/*
		 * Skip if packets equal or larger were acked.
		 * 0 is skipped, since cs->wire_sz will always be at least
		 * 0 bytes.
		 */
		if (cs->segments[i].min_over_sz <= cs->wire_sz)
			continue;

		/* Search for smallest value. */
		if (cs->over_sz == 0 ||
		    cs->over_sz > cs->segments[i].min_over_sz)
			cs->over_sz = cs->segments[i].min_over_sz;
	}

	/*
	 * Latency average and standard deviation.
	 */
	sum = 0;
	count = 0;
	for (i = 0; i < NET2_STATS_LEN; i++) {
		sum += cs->segments[i].rtt.sum;
		count += cs->segments[i].rtt.count;
	}
	if (count != 0) {
		cs->latency_avg = sum / count;

		cs->latency_stddev = 0;
		for (i = 0; i < NET2_STATS_LEN; i++) {
			if (cs->segments[i].rtt.count == 0)
				continue;

			cs->latency_stddev += rebase_sumsq(
			    cs->segments[i].rtt.sumsquare,
			    cs->segments[i].rtt.sum,
			    cs->segments[i].rtt.count,
			    cs->latency_avg -
			      (cs->segments[i].rtt.sum /
			       cs->segments[i].rtt.count));
		}
		if (count > 0)
			cs->latency_stddev /= count;
		/*
		 * +1, since the isqrt returns the floor value, while
		 * we want the ceil.
		 */
		cs->latency_stddev = isqrt64(cs->latency_stddev) + 1;
	}

	/*
	 * Latency is currently actually round-trip-time.
	 */
	cs->latency_avg /= 2;
	cs->latency_stddev /= 4;


	/* Move all statistics one element to the left. */
	memmove(&cs->segments[0], &cs->segments[1],
	    (NET2_STATS_LEN - 1) * sizeof(cs->segments[0]));

	/* Reset last segment in the list. */
	memset(&cs->segments[NET2_STATS_LEN - 1], 0, sizeof(cs->segments[0]));

#ifdef CONNSTATS_PRINTSTATS
	/* Print statistics. */
	fprintf(stderr, "stats:\n"
	    "\t%-16s %8d%s\n"		/* arrival change */
	    "\t%-16s %8d%s\n"		/* send for 97% */
	    "\t%-16s %8ld%s\n"		/* bandwidth */
	    "\t%-16s %8ld%s\n"		/* bandwidth in packets */
	    "\t%-16s %8u%s\n"		/* packet size */
	    "\t%-16s %8llu%s\n"		/* latency avg */
	    "\t%-16s %8llu%s\n"		/* latency stddev */
	    "\t%-16s %8u%s\n"		/* sent */
	    "\t%-16s %8u%s\n",		/* arrived */

	    "arrival chance:", cs->arrival_chance, "%",
	    "send for 97%:", cs->send_for_97, " packets",
	    "bandwidth:", (unsigned long)cs->bandwidth, " bytes/sec",
	    "", (unsigned long)cs->packets_sec, " packets/sec",
	    "packet size:", (unsigned int)cs->wire_sz, " bytes",
	    "latency avg:", (unsigned long long)cs->latency_avg, " usec",
	    "latency stddev:", (unsigned long long)cs->latency_stddev, " usec",
	    "  sent:", (unsigned int)sent, " packets",
	    "  arrived:", (unsigned int)arrived, " packets");
#endif /* CONNSTATS_PRINTSTATS */
}

/* Update round trip time by adding new value. */
static void
rtt_update(struct net2_connstats_rtt *l, int64_t usec)
{
	int64_t			old_avg, new_avg, avg_inc;

	if (l->count == 0)
		old_avg = 0;
	else
		old_avg = l->sum / l->count;
	new_avg = (l->sum + usec) / (l->count + 1);
	avg_inc = new_avg - old_avg;

	/* Rebase sum of squares. */
	l->sumsquare = rebase_sumsq(l->sumsquare, l->sum, l->count, avg_inc);

	/* Add value. */
	l->sumsquare += (usec - new_avg) * (usec - new_avg);
	l->sum += usec;
	l->count++;
}

/*
 * Initialize connstats.
 */
ILIAS_NET2_LOCAL int
net2_connstats_init(struct net2_connstats *cs, struct net2_connection *conn)
{
	/* Zero all counters. */
	memset(&cs->segments[0], 0, sizeof(cs->segments));

	/* We initialize to dummy/sane values. */
	cs->arrival_chance = 100;
	cs->send_for_97 = 1;
	cs->bandwidth = 0;
	cs->packets_sec = 0;
	cs->wire_sz = MIN_WIRE_SZ;
	cs->latency_avg = 1000;
	cs->latency_stddev = 1000;

	cs->tx_packets = cs->rx_packets = 0;
	cs->tx_bytes = cs->rx_bytes = 0;

	tv_clock_gettime(CLOCK_MONOTONIC, &cs->last_update);

	return 0;
}

/* Deinitialize connstats. */
ILIAS_NET2_LOCAL void
net2_connstats_deinit(struct net2_connstats *cs)
{
	return;
}

/* Add transmission datapoint. */
ILIAS_NET2_LOCAL void
net2_connstats_tx_datapoint(struct net2_connstats *cs, struct timeval *sent_ts,
    struct timeval *ack_ts, size_t wire_sz, int ok)
{
	struct timeval		 rtt, now;
	struct net2_connstats_segment
				*segment;
	int64_t			 microsec;

	segment = &cs->segments[NET2_STATS_LEN - 1];
	tv_clock_gettime(CLOCK_MONOTONIC, &now);

	if (now.tv_sec != cs->last_update.tv_sec) {
		segment_shift(cs);
		cs->last_update = now;
	}

	/* Update largest wire_sz in this window. */
	if (segment->max_wire_sz < wire_sz) {
		if (ok) {
			segment->max_wire_sz = wire_sz;
			if (cs->wire_sz < wire_sz)
				cs->wire_sz = wire_sz;
		} else if (segment->min_over_sz == 0 ||
		    segment->min_over_sz > wire_sz)
			segment->min_over_sz = wire_sz;
	}

	/* Update round-trip-time. */
	if (ok) {
		/* Calculate round-trip-time. */
		timersub(ack_ts, sent_ts, &rtt);
		/* Make sure we don't clip. */
		if (rtt.tv_sec >= (INT64_MAX - rtt.tv_usec) / 1000000)
			microsec = INT64_MAX;
		else
			microsec = rtt.tv_sec * 1000000 + rtt.tv_usec;

		rtt_update(&segment->rtt, microsec);
	}

	/* Update arrival statistics. */
	segment->arrive.sent++;
	if (ok)
		segment->arrive.arrived++;

	/* Update bandwidth. */
	if (ok)
		segment->bytes_ok += wire_sz;
}

/*
 * Add timeout representing N times the latency in sigma(stddev)
 * of the arriving packets.
 *
 * Suppose N is 1 and D is 2, the chance that a datagram would travel
 * less than tv is 95%.
 */
ILIAS_NET2_LOCAL void
net2_connstats_timeout(struct net2_connstats *cs, struct timeval *tv,
    int n, int d)
{
	int64_t			v;
	int64_t			l_avg, l_stddev;

	l_avg = cs->latency_avg;
	l_stddev = cs->latency_stddev;

	/* If no measurements are available, use bad-case scenarios. */
	if (l_avg == 0)
		l_avg = 500000;
	if (l_stddev == 0)
		l_stddev = 500000;

	/* Is this correct? */
	v = (l_avg + (l_stddev * (int64_t)d)) * (int64_t)n;
	tv->tv_usec = v % 1000000;
	tv->tv_sec = v / 1000000;
}

/* Record that a packet with wire_sz bytes has been transmitted. */
ILIAS_NET2_LOCAL void
net2_connstats_record_transmit(struct net2_connstats *cs, size_t wire_sz)
{
	cs->tx_packets++;
	cs->tx_bytes += wire_sz;
}

/* Record that a packet with wire_sz bytes has been received. */
ILIAS_NET2_LOCAL void
net2_connstats_record_recv(struct net2_connstats *cs, size_t wire_sz)
{
	cs->rx_packets++;
	cs->rx_bytes += wire_sz;
}
