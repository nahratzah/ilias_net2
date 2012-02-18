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
#ifndef ILIAS_NET2_CONNSTATS_H
#define ILIAS_NET2_CONNSTATS_H

#include <ilias/net2/ilias_net2_export.h>
#include <sys/types.h>
#ifdef WIN32
#include <WinSock2.h>
#else
#include <sys/time.h>
#endif
#include <stdint.h>

/* Latency, measured in microseconds. */
struct net2_connstats_rtt {
	int64_t			 sumsquare;
	int64_t			 sum;
	int64_t			 count;
};

/* Packet arrival count. */
struct net2_connstats_arrive {
	uint32_t		 sent;		/* Packets sent. */
	uint32_t		 arrived;	/* Packets received. */
};

struct net2_connstats_segment {
	uint32_t		 max_wire_sz;	/* Largest acked packet. */
	uint32_t		 min_over_sz;	/* Smallest lost packet,
						 * that was larger than
						 * max_wire_sz. */
	struct net2_connstats_rtt
				 rtt;		/* Round trip time. */
	struct net2_connstats_arrive
				 arrive;	/* Reliability measurement. */
	uint64_t		 bytes_ok;	/* Acked bandwidth. */
};

/* Keep statistics over 4 segments of each 1 second. */
#define NET2_STATS_LEN		15

struct net2_connstats {
	/* Measurements. */
	struct net2_connstats_segment
				 segments[NET2_STATS_LEN];
						/* Segments with data. */
	struct timeval		 last_update;	/* Moment of last update. */

	/* Conclusions. */
	int			 arrival_chance; /* % arrives. */
	int			 send_for_97;	/* #packets to send for 97%. */
	int32_t			 bandwidth;	/* Bytes per second. */
	int32_t			 packets_sec;	/* Packets per second. */
	uint32_t		 wire_sz;	/* Bytes per packet. */
	uint32_t		 over_sz;	/* Too many bytes. */
	uint64_t		 latency_avg;	/* Average latency. */
	uint64_t		 latency_stddev; /* Latency std deviation. */

	uint64_t		 tx_packets;	/* # packets sent. */
	uint64_t		 tx_bytes;	/* # bytes sent. */
	uint64_t		 rx_packets;	/* # packets received. */
	uint64_t		 rx_bytes;	/* # bytes received. */
};


#ifdef BUILDING_ILIAS_NET2
struct net2_connection;

ILIAS_NET2_LOCAL
int	net2_connstats_init(struct net2_connstats*, struct net2_connection*);
ILIAS_NET2_LOCAL
void	net2_connstats_deinit(struct net2_connstats*);
ILIAS_NET2_LOCAL
void	net2_connstats_tx_datapoint(struct net2_connstats*, struct timeval*,
	    struct timeval*, size_t, int);
ILIAS_NET2_LOCAL
void	net2_connstats_timeout(struct net2_connstats*, struct timeval*,
	    int, int);
ILIAS_NET2_LOCAL
void	net2_connstats_record_transmit(struct net2_connstats*, size_t wire_sz);
ILIAS_NET2_LOCAL
void	net2_connstats_record_recv(struct net2_connstats*, size_t wire_sz);

#endif /* BUILDING_ILIAS_NET2 */

#endif /* ILIAS_NET2_CONNSTATS_H */
