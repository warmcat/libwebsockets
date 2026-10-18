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
 * The external-address vote: see dht-extvote.h
 */

#include "dht-extvote.h"

#include <string.h>

int
dht_source_key(const struct sockaddr *sa, uint8_t key[LWS_DHT_EXTVOTE_KEY_LEN])
{
	const lws_sockaddr46 *sa46 = (const lws_sockaddr46 *)sa;

	memset(key, 0, LWS_DHT_EXTVOTE_KEY_LEN);

	switch (sa->sa_family) {
	case AF_INET:
		memcpy(key, &sa46->sa4.sin_addr, 4);
		return 0;
#if defined(LWS_WITH_IPV6)
	case AF_INET6:
		memcpy(key, &sa46->sa6.sin6_addr, 8);
		return 0;
#endif
	default:
		return -1;
	}
}

/* the same external endpoint: family, address and port */

static int
extvote_same(const lws_sockaddr46 *a, const lws_sockaddr46 *b)
{
	if (a->sa4.sin_family != b->sa4.sin_family)
		return 0;

	switch (a->sa4.sin_family) {
	case AF_INET:
		return a->sa4.sin_port == b->sa4.sin_port &&
		       !memcmp(&a->sa4.sin_addr, &b->sa4.sin_addr,
			       sizeof(a->sa4.sin_addr));
#if defined(LWS_WITH_IPV6)
	case AF_INET6:
		return a->sa6.sin6_port == b->sa6.sin6_port &&
		       !memcmp(&a->sa6.sin6_addr, &b->sa6.sin6_addr,
			       sizeof(a->sa6.sin6_addr));
#endif
	default:
		return 0;
	}
}

/*
 * A vote counts while it is younger than the window.  If the clock stepped
 * back past it, it is as current as a vote can be; it ages out once the clock
 * has caught up and gone a window beyond it.
 */

static int
extvote_current(const lws_dht_extvote_vote_t *v, time_t now)
{
	return v->when && (v->when >= now ||
			   now - v->when < LWS_DHT_EXTVOTE_WINDOW_SECS);
}

/* how many current votes there are for the address vote n reports */

static int
extvote_tally(const lws_dht_extvote_t *ev, int n, time_t now)
{
	int m, count = 0;

	for (m = 0; m < LWS_DHT_EXTVOTE_SLOTS; m++)
		if (extvote_current(&ev->votes[m], now) &&
		    extvote_same(&ev->votes[m].reported, &ev->votes[n].reported))
			count++;

	return count;
}

int
lws_dht_extvote_add(lws_dht_extvote_t *ev, const lws_sockaddr46 *voter_sa,
		    const lws_sockaddr46 *reported, time_t now, int quorum,
		    lws_sockaddr46 *peers, int *num_peers)
{
	int n, slot = -1, best = -1, best_count = 0, tie = 0, count, ret;
	uint8_t voter[LWS_DHT_EXTVOTE_KEY_LEN];

	if (dht_source_key((const struct sockaddr *)voter_sa, voter))
		return -1;

	/*
	 * A witness has one vote, its latest: it replaces what it said before.
	 * Otherwise take a free or expired slot, and failing that the oldest
	 * vote, which is the nearest to expiring anyway.
	 */

	for (n = 0; n < LWS_DHT_EXTVOTE_SLOTS; n++)
		if (ev->votes[n].when &&
		    !memcmp(ev->votes[n].voter, voter, LWS_DHT_EXTVOTE_KEY_LEN)) {
			slot = n;
			break;
		}

	if (slot < 0)
		for (n = 0; n < LWS_DHT_EXTVOTE_SLOTS; n++) {
			if (!extvote_current(&ev->votes[n], now)) {
				slot = n;
				break;
			}
			if (slot < 0 || ev->votes[n].when < ev->votes[slot].when)
				slot = n;
		}

	memcpy(ev->votes[slot].voter, voter, LWS_DHT_EXTVOTE_KEY_LEN);
	ev->votes[slot].voter_sa	= *voter_sa;
	ev->votes[slot].reported	= *reported;
	ev->votes[slot].when		= now;

	/*
	 * Find the address with the most current votes, and whether another
	 * address has as many: a tie decides nothing
	 */

	for (n = 0; n < LWS_DHT_EXTVOTE_SLOTS; n++) {
		if (!extvote_current(&ev->votes[n], now))
			continue;

		if (best >= 0 &&
		    extvote_same(&ev->votes[n].reported, &ev->votes[best].reported))
			continue;

		count = extvote_tally(ev, n, now);
		if (count > best_count) {
			best = n;
			best_count = count;
			tie = 0;
		} else if (count == best_count)
			tie = 1;
	}

	if (quorum < 1)
		quorum = 1;

	if (best < 0 || tie || best_count < quorum ||
	    extvote_same(&ev->decided, &ev->votes[best].reported))
		return LWS_DHT_EXTVOTE_NO_CHANGE;

	ret = ev->decided.sa4.sin_family ? LWS_DHT_EXTVOTE_SHIFT :
					   LWS_DHT_EXTVOTE_FIRST;
	ev->decided = ev->votes[best].reported;

	count = 0;
	for (n = 0; n < LWS_DHT_EXTVOTE_SLOTS && count < *num_peers; n++)
		if (extvote_current(&ev->votes[n], now) &&
		    extvote_same(&ev->votes[n].reported, &ev->decided))
			peers[count++] = ev->votes[n].voter_sa;
	*num_peers = count;

	return ret;
}
