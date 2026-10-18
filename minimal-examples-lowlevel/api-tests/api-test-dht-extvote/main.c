/*
 * lws-api-test-dht-extvote
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 * Note: CC0 1.0 Universal Public Domain Dedication
 *
 * Drives the DHT's vote on our external address (lib/misc/dht/dht-extvote.c)
 * with made-up witnesses and clock values.  The dht feeds it the answers to
 * its nonce-bound probes; what is checked here is what those answers are
 * worth (G-094, G-095).
 *
 *  - a witness is a host: three IPv4 witnesses agreeing decide at quorum 3,
 *    but three addresses inside one IPv6 /64 are one witness, and a second
 *    /64 makes two
 *  - votes age out: witnesses agreeing a window apart never add up to a
 *    quorum
 *  - votes compete: a minority voting for another address does not move a
 *    decided one, even when it reaches the quorum on its own; when the
 *    majority moves, the decision does.  A tie decides nothing
 *  - a witness has one vote, its latest
 *  - slots are reclaimed: a flood of junk from many hosts does not stop a
 *    real quorum being counted afterwards
 */

#include <libwebsockets.h>
#include <string.h>

#include "dht-extvote.h"

#define EV_T0		100000

static int fails;

static lws_sockaddr46
ev_v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port)
{
	lws_sockaddr46 sa;
	uint8_t *p = (uint8_t *)&sa.sa4.sin_addr;

	memset(&sa, 0, sizeof(sa));
	sa.sa4.sin_family = AF_INET;
	sa.sa4.sin_port = htons(port);
	p[0] = a;
	p[1] = b;
	p[2] = c;
	p[3] = d;

	return sa;
}

#if defined(LWS_WITH_IPV6)
/* 2001:db8:0:<net>::<host> */
static lws_sockaddr46
ev_v6(uint8_t net, uint8_t host, uint16_t port)
{
	lws_sockaddr46 sa;
	uint8_t *p = (uint8_t *)&sa.sa6.sin6_addr;

	memset(&sa, 0, sizeof(sa));
	sa.sa6.sin6_family = AF_INET6;
	sa.sa6.sin6_port = htons(port);
	p[0] = 0x20;
	p[1] = 0x01;
	p[2] = 0x0d;
	p[3] = 0xb8;
	p[7] = net;
	p[15] = host;

	return sa;
}
#endif

static void
ev_expect(const char *what, lws_dht_extvote_t *ev, const lws_sockaddr46 *voter,
	  const lws_sockaddr46 *reported, time_t now, int quorum, int expected)
{
	lws_sockaddr46 peers[8];
	int num_peers = (int)LWS_ARRAY_SIZE(peers),
	    r = lws_dht_extvote_add(ev, voter, reported, now, quorum, peers,
				    &num_peers);

	if (r == expected)
		return;

	lwsl_err("%s: %s: got %d, expected %d\n", __func__, what, r, expected);
	fails++;
}

int
main(void)
{
	lws_sockaddr46 real = ev_v4(203, 0, 113, 7, 4444),
		       fake = ev_v4(198, 51, 100, 9, 4444), junk;
	lws_dht_extvote_t ev;
	int n;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);
	lwsl_user("LWS API selftest: dht external address vote\n");

	/* three IPv4 hosts agreeing decide at quorum 3 */

	memset(&ev, 0, sizeof(ev));
	{
		lws_sockaddr46 w1 = ev_v4(192, 0, 2, 1, 6881),
			       w2 = ev_v4(192, 0, 2, 2, 6881),
			       w2b = ev_v4(192, 0, 2, 2, 6882),
			       w3 = ev_v4(192, 0, 2, 3, 6881);

		ev_expect("v4 1", &ev, &w1, &real, EV_T0, 3,
			  LWS_DHT_EXTVOTE_NO_CHANGE);
		ev_expect("v4 2", &ev, &w2, &real, EV_T0, 3,
			  LWS_DHT_EXTVOTE_NO_CHANGE);
		/* the same host from another port is the same witness */
		ev_expect("v4 2 again", &ev, &w2b, &real, EV_T0, 3,
			  LWS_DHT_EXTVOTE_NO_CHANGE);
		ev_expect("v4 3", &ev, &w3, &real, EV_T0, 3,
			  LWS_DHT_EXTVOTE_FIRST);
	}

#if defined(LWS_WITH_IPV6)
	/* three addresses in one /64 are one witness, a second /64 two */

	memset(&ev, 0, sizeof(ev));
	{
		lws_sockaddr46 w1 = ev_v6(1, 1, 6881), w2 = ev_v6(1, 2, 6881),
			       w3 = ev_v6(1, 3, 6881), w4 = ev_v6(2, 1, 6881),
			       w5 = ev_v6(3, 1, 6881), r6 = ev_v6(9, 9, 4444);

		ev_expect("v6 /64 1", &ev, &w1, &r6, EV_T0, 3,
			  LWS_DHT_EXTVOTE_NO_CHANGE);
		ev_expect("v6 /64 2", &ev, &w2, &r6, EV_T0, 3,
			  LWS_DHT_EXTVOTE_NO_CHANGE);
		ev_expect("v6 /64 3", &ev, &w3, &r6, EV_T0, 3,
			  LWS_DHT_EXTVOTE_NO_CHANGE);
		ev_expect("v6 second /64", &ev, &w4, &r6, EV_T0, 3,
			  LWS_DHT_EXTVOTE_NO_CHANGE);
		ev_expect("v6 third /64", &ev, &w5, &r6, EV_T0, 3,
			  LWS_DHT_EXTVOTE_FIRST);

		/* with only two hosts probed, the two /64s are the quorum */
		memset(&ev, 0, sizeof(ev));
		ev_expect("v6 q2 /64 1", &ev, &w1, &r6, EV_T0, 2,
			  LWS_DHT_EXTVOTE_NO_CHANGE);
		ev_expect("v6 q2 /64 1 again", &ev, &w3, &r6, EV_T0, 2,
			  LWS_DHT_EXTVOTE_NO_CHANGE);
		ev_expect("v6 q2 second /64", &ev, &w4, &r6, EV_T0, 2,
			  LWS_DHT_EXTVOTE_FIRST);
	}
#endif

	/* votes a window apart never make a quorum */

	memset(&ev, 0, sizeof(ev));
	{
		lws_sockaddr46 w1 = ev_v4(192, 0, 2, 1, 6881),
			       w2 = ev_v4(192, 0, 2, 2, 6881),
			       w3 = ev_v4(192, 0, 2, 3, 6881);

		ev_expect("aged 1", &ev, &w1, &fake, EV_T0, 3,
			  LWS_DHT_EXTVOTE_NO_CHANGE);
		ev_expect("aged 2", &ev, &w2, &fake,
			  EV_T0 + LWS_DHT_EXTVOTE_WINDOW_SECS / 2, 3,
			  LWS_DHT_EXTVOTE_NO_CHANGE);
		ev_expect("aged 3", &ev, &w3, &fake,
			  EV_T0 + LWS_DHT_EXTVOTE_WINDOW_SECS, 3,
			  LWS_DHT_EXTVOTE_NO_CHANGE);
		/* ...but w1 voting again within the window of w2 and w3 does */
		ev_expect("aged 1 renewed", &ev, &w1, &fake,
			  EV_T0 + LWS_DHT_EXTVOTE_WINDOW_SECS, 3,
			  LWS_DHT_EXTVOTE_FIRST);
	}

	/* votes compete */

	memset(&ev, 0, sizeof(ev));
	{
		lws_sockaddr46 h[6];

		for (n = 0; n < 6; n++)
			h[n] = ev_v4(192, 0, 2, (uint8_t)(1 + n), 6881);

		/* hosts 0..2 decide the real address */
		ev_expect("honest 0", &ev, &h[0], &real, EV_T0, 3,
			  LWS_DHT_EXTVOTE_NO_CHANGE);
		ev_expect("honest 1", &ev, &h[1], &real, EV_T0, 3,
			  LWS_DHT_EXTVOTE_NO_CHANGE);
		ev_expect("honest 2", &ev, &h[2], &real, EV_T0, 3,
			  LWS_DHT_EXTVOTE_FIRST);

		/* two others say otherwise: that quorum is still outvoted */
		ev_expect("minority 3", &ev, &h[3], &fake, EV_T0 + 1, 2,
			  LWS_DHT_EXTVOTE_NO_CHANGE);
		ev_expect("minority 4", &ev, &h[4], &fake, EV_T0 + 1, 2,
			  LWS_DHT_EXTVOTE_NO_CHANGE);

		/* a third: 3 - 3 is a tie, which moves nothing */
		ev_expect("tie", &ev, &h[5], &fake, EV_T0 + 2, 2,
			  LWS_DHT_EXTVOTE_NO_CHANGE);

		/* an honest host changes its mind: now the majority moves it */
		ev_expect("majority", &ev, &h[2], &fake, EV_T0 + 3, 2,
			  LWS_DHT_EXTVOTE_SHIFT);

		/* a host repeating its vote changes nothing */
		ev_expect("repeat", &ev, &h[2], &fake, EV_T0 + 4, 2,
			  LWS_DHT_EXTVOTE_NO_CHANGE);
	}

	/* a flood of junk from many hosts does not lock out a real quorum */

	memset(&ev, 0, sizeof(ev));
	{
		lws_sockaddr46 w;

		for (n = 0; n < 3 * LWS_DHT_EXTVOTE_SLOTS; n++) {
			w = ev_v4(192, 0, 2, (uint8_t)(1 + n), 6881);
			junk = ev_v4(198, 51, 100, (uint8_t)(1 + n), 4444);
			ev_expect("junk", &ev, &w, &junk, EV_T0, 3,
				  LWS_DHT_EXTVOTE_NO_CHANGE);
		}

		for (n = 0; n < 3; n++) {
			w = ev_v4(203, 0, 113, (uint8_t)(1 + n), 6881);
			ev_expect("after junk", &ev, &w, &real, EV_T0 + 1, 3,
				  n == 2 ? LWS_DHT_EXTVOTE_FIRST :
					   LWS_DHT_EXTVOTE_NO_CHANGE);
		}
	}

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
