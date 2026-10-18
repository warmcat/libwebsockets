/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * The DHT's vote on our external address, for one address family.
 *
 * Nodes we probed tell us what our address looks like from where they are.
 * Each witness (one host: see dht_source_key(), an IPv4 address or an IPv6
 * /64) holds one vote per family, its latest; votes older than
 * LWS_DHT_EXTVOTE_WINDOW_SECS no longer count.  An address is decided when it
 * has at least the quorum of current votes and strictly more than any other
 * address has: votes compete, so a minority of witnesses cannot move it
 * however long they keep voting.
 *
 * This only tallies.  Which witnesses may vote (nonce-bound probe replies),
 * what the quorum is and which reported addresses are acceptable at all are
 * the caller's business.  It only depends on the public api, so an api-test
 * can drive it directly.
 */

#if !defined(__LWS_DHT_EXTVOTE_H__)
#define __LWS_DHT_EXTVOTE_H__

#include <libwebsockets.h>
#include <time.h>

/* more than one probe round's worth of witnesses: 8 probes per family */
#define LWS_DHT_EXTVOTE_SLOTS		16
/* two probe rounds (one per 600s) and some slack */
#define LWS_DHT_EXTVOTE_WINDOW_SECS	1500
#define LWS_DHT_EXTVOTE_KEY_LEN		16

typedef struct lws_dht_extvote_vote {
	uint8_t			voter[LWS_DHT_EXTVOTE_KEY_LEN];
	lws_sockaddr46		voter_sa;	/* where the vote came from */
	lws_sockaddr46		reported;	/* what it says we are */
	time_t			when;		/* 0: slot unused */
} lws_dht_extvote_vote_t;

typedef struct lws_dht_extvote {
	lws_dht_extvote_vote_t	votes[LWS_DHT_EXTVOTE_SLOTS];
	lws_sockaddr46		decided;	/* family 0 until decided */
} lws_dht_extvote_t;

enum {
	LWS_DHT_EXTVOTE_NO_CHANGE,
	LWS_DHT_EXTVOTE_FIRST,		/* the first decided address */
	LWS_DHT_EXTVOTE_SHIFT,		/* a different address is decided */
};

/*
 * What a per-source share in the dht is accounted to: the IPv4 address, or
 * the IPv6 /64, so one host is one source however many ports, or addresses in
 * its prefix, it uses.  Fills a 16-byte key; -1 for a family we don't handle.
 * Admission, the bucket cap, subscriber and peer shares and the
 * external-address vote all count peers by it.
 */
int
dht_source_key(const struct sockaddr *sa, uint8_t key[LWS_DHT_EXTVOTE_KEY_LEN]);

/*
 * Record the witness at `voter` saying we are at `reported`, at `now`, and
 * decide.  On a change, `peers` (room for *num_peers) gets the addresses of
 * the current witnesses for the decided address and *num_peers how many there
 * were.  Returns LWS_DHT_EXTVOTE_..., or -1 if the voter's family is not one
 * we handle.
 */
int
lws_dht_extvote_add(lws_dht_extvote_t *ev, const lws_sockaddr46 *voter,
		    const lws_sockaddr46 *reported, time_t now, int quorum,
		    lws_sockaddr46 *peers, int *num_peers);

#endif
