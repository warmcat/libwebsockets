/*
 * lws-api-test-dht-dnssec-origin
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A zone published in the DHT is signed with the keys of a domain, and
 * auth-dns installs it as that domain's zone.  Which domain's keys to check
 * comes from the payload before it is authenticated, so the zone that is
 * then installed must be exactly that domain's, as the parser serving it
 * sees it, or the owner of one domain publishes a zone that is served as
 * another (G-117).  This checks, with the lws-dht-dnssec plugin built in:
 *
 *  - the unauthenticated scan only takes a $ORIGIN where the zone parser
 *    does, at the start of a line, and refuses text with more than one
 *  - a payload whose signature was confirmed for a domain is refused
 *    unless it is exactly that domain's zone: a trailing $ORIGIN for
 *    another domain, a zone that is wholly another domain's, or records
 *    outside the zone are all refused, while the domain's own zone passes
 *    with its serial
 */

#include <libwebsockets.h>

#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define LWS_PLUGIN_STATIC
#include "../../../plugins/protocol_lws_dht_dnssec/protocol_lws_dht_dnssec.c"

#define ORT_PAYLOAD	"origin-test.payload"

static int fails;

#define ORT_SOA(_o) "@ IN SOA ns1." _o ". host." _o ". " \
		    "( 2026100101 3600 1800 604800 60 )\n"

static void
scan_case(const char *what, const char *text, int want_ret,
	  const char *want)
{
	char got[256];
	int r = dht_dnssec_scan_origin(text, strlen(text), got, sizeof(got));

	if (r != want_ret || (!r && strcmp(got, want))) {
		lwsl_err("%s: FAILED: %s: returned %d '%s'\n", __func__, what,
			 r, got);
		fails++;
		return;
	}

	lwsl_user("%s: ok: %s\n", __func__, what);
}

static void
payload_case(const char *what, const char *text, const char *domain,
	     int want_refused)
{
	size_t l = strlen(text);
	time_t sig_expiry, ttl;
	uint64_t serial;
	int fd, r;

	fd = open(ORT_PAYLOAD, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0 || write(fd, text, l) != (ssize_t)l) {
		if (fd >= 0)
			close(fd);
		lwsl_err("%s: FAILED: %s: can't write payload\n", __func__,
			 what);
		fails++;
		return;
	}
	close(fd);

	r = dht_dnssec_payload_check(ORT_PAYLOAD, domain, &serial,
				     &sig_expiry, &ttl);

	if (!r != !want_refused || (!r && serial != 2026100101ull)) {
		lwsl_err("%s: FAILED: %s: %s\n", __func__, what,
			 r ? "refused" : "accepted");
		fails++;
		return;
	}

	lwsl_user("%s: ok: %s\n", __func__, what);
}

int
main(void)
{
	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);
	lwsl_user("LWS API selftest: dht-dnssec zone identity\n");

	scan_case("one $ORIGIN", "$ORIGIN a.example.\n" ORT_SOA("a.example"),
		  0, "a.example");
	scan_case("no $ORIGIN", ORT_SOA("a.example"), 1, NULL);
	scan_case("trailing $ORIGIN refused", "$ORIGIN a.example.\n"
		  ORT_SOA("a.example") "$ORIGIN victim.\n", -1, NULL);
	scan_case("indented $ORIGIN is not one", "  $ORIGIN a.example.\n"
		  "$ORIGIN victim.\n" ORT_SOA("victim"), 0, "victim");

	payload_case("the domain's own zone", "$ORIGIN a.example.\n"
		     ORT_SOA("a.example") "www IN A 127.0.0.1\n",
		     "a.example", 0);
	payload_case("trailing $ORIGIN for another domain",
		     "$ORIGIN a.example.\n" ORT_SOA("a.example")
		     "$ORIGIN victim.\n" ORT_SOA("victim")
		     "www IN A 127.0.0.66\n", "a.example", 1);
	payload_case("indented $ORIGIN ahead of another domain's",
		     "  $ORIGIN a.example.\n$ORIGIN victim.\n"
		     ORT_SOA("victim"), "a.example", 1);
	payload_case("wholly another domain's zone", "$ORIGIN victim.\n"
		     ORT_SOA("victim"), "a.example", 1);
	payload_case("records outside the zone", "$ORIGIN a.example.\n"
		     ORT_SOA("a.example") "www.victim. IN A 127.0.0.66\n",
		     "a.example", 1);

	unlink(ORT_PAYLOAD);

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
