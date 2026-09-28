/*
 * lws-api-test-sansio-link
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The sansIO half linked alone (README.sans-io-split.md, "The contract"):
 * libwebsockets-sansio is the sansIO sources, the substrate neither half
 * owns and the platform's injected clock, random source and file access,
 * linked with every unresolved symbol an error, so that it links at all is
 * the test.  This program links against it and nothing else of lws, and
 * runs a little of each: a sansIO parser and writer, and the substrate's
 * address helpers and clock.
 */

#include <libwebsockets.h>
#include <string.h>
#include <time.h>

int
main(void)
{
	/* the http date sansIO writes into responses and parses from them */
	const time_t t = 784111777; /* RFC 7231's Sun, 06 Nov 1994 08:49:37 */
	char buf[64];
	lws_sockaddr46 sa46;
	time_t t1 = 0;
	int e = 0;

	if (lws_http_date_render_from_unix(buf, sizeof(buf), &t) ||
	    strcmp(buf, "Sun, 06 Nov 1994 08:49:37 GMT") ||
	    lws_http_date_parse_unix(buf, strlen(buf), &t1) || t1 != t) {
		printf("http date: rendered '%s', parsed %llu\n", buf,
		       (unsigned long long)t1);
		e++;
	}

	/* the substrate's address helpers */
	memset(&sa46, 0, sizeof(sa46));
	if (lws_sa46_parse_numeric_address("192.168.1.2", &sa46) ||
	    lws_sa46_write_numeric_address(&sa46, buf, sizeof(buf)) < 0 ||
	    strcmp(buf, "192.168.1.2")) {
		printf("address: '%s'\n", buf);
		e++;
	}

	/* the injected clock */
	if (!lws_now_usecs()) {
		printf("no clock\n");
		e++;
	}

	printf("Completed: %s\n", e ? "FAIL" : "PASS");

	return e;
}
