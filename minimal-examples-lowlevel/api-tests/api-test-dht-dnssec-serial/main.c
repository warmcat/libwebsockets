/*
 * lws-api-test-dht-dnssec-serial
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Before the lws-dht-dnssec plugin signs a zone, it bumps the SOA serial in
 * the zone file.  Holders of the zone only take a later serial than the one
 * they have, and silently drop anything else, so this checks
 *
 *  - an old serial, or one from earlier today, moves on to today's
 *  - a file written back with a serial older than the one it was last
 *    signed with (<zone>.signed) continues from the signed one, and the
 *    "RRSIG SOA" lines of the signed zone are not taken for its SOA
 *  - a serial set ahead of the last signed one by hand is kept moving on
 *  - the multiline SOA form with comments, and the rest of the file is
 *    left as it was
 *  - a file without a SOA is refused and left alone
 */

#include <libwebsockets.h>

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>

#define LWS_PLUGIN_STATIC
#include "../../../plugins/protocol_lws_dht_dnssec/protocol_lws_dht_dnssec.c"

#define SER_ZONE	"serial-test.zone"
#define SER_SIGNED	SER_ZONE ".signed"

static int fails;

static int
ser_write(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	size_t len = strlen(text);

	if (fd < 0)
		return 1;
	if (write(fd, text, len) != (ssize_t)len) {
		close(fd);
		return 1;
	}

	return close(fd);
}

/* the zone file after the bump must be exactly want */

static void
ser_case(const char *what, const char *zone, const char *signed_zone,
	 int want_ret, const char *want)
{
	char got[1024];
	ssize_t n;
	int fd, r;

	unlink(SER_SIGNED);
	if (ser_write(SER_ZONE, zone) ||
	    (signed_zone && ser_write(SER_SIGNED, signed_zone))) {
		lwsl_err("%s: FAILED: %s: can't write the files\n", __func__,
			 what);
		fails++;
		return;
	}

	r = lws_dht_dnssec_bump_zone_serial(NULL, SER_ZONE);

	fd = open(SER_ZONE, O_RDONLY);
	n = fd < 0 ? -1 : read(fd, got, sizeof(got) - 1);
	if (fd >= 0)
		close(fd);
	if (n < 0)
		n = 0;
	got[n] = '\0';

	if (r != want_ret || strcmp(got, want)) {
		lwsl_err("%s: FAILED: %s: returned %d, file now:\n%s\n",
			 __func__, what, r, got);
		fails++;
		return;
	}

	lwsl_user("%s: ok: %s\n", __func__, what);
}

int
main(void)
{
	char today1[16], today6[16], today7[16], today8[16], z[512], s[512],
	     w[512];
	struct tm tmp, *tm;
	time_t t;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);
	lwsl_user("LWS API selftest: dht-dnssec zone serial bump\n");

	t = time(NULL);
	tm = gmtime_r(&t, &tmp);
	if (!tm)
		return 1;
	strftime(today1, sizeof(today1), "%Y%m%d01", tm);
	strftime(today6, sizeof(today6), "%Y%m%d06", tm);
	strftime(today7, sizeof(today7), "%Y%m%d07", tm);
	strftime(today8, sizeof(today8), "%Y%m%d08", tm);

#define SOA1(_s) "$ORIGIN ser.example.\n$TTL 3600\n" \
		 "@\tIN\tSOA\tns1.ser.example. host.ser.example. " _s \
		 " 3600 1800 604800 60\n@\tIN\tNS\tns1.ser.example.\n"

	lws_snprintf(w, sizeof(w), SOA1("%s"), today1);
	ser_case("old serial moves on to today", SOA1("2000010101"), NULL, 0,
		 w);

	lws_snprintf(z, sizeof(z), SOA1("%s"), today6);
	lws_snprintf(w, sizeof(w), SOA1("%s"), today7);
	ser_case("today's serial counts on", z, NULL, 0, w);

	/*
	 * As the signer writes it: the RRSIG over the SOA sorts first here,
	 * and its "SOA 13 2 3600" must not be read as a serial of 3600
	 */
	lws_snprintf(s, sizeof(s), "$ORIGIN ser.example.\n$TTL 3600\n\n"
		"ser.example.\t3600\tIN\tRRSIG\tSOA 13 2 3600 2000000000 "
		"1000000000 1234 ser.example. c2ln\n"
		"ser.example.\t3600\tIN\tSOA\tns1.ser.example. "
		"host.ser.example. %s 3600 1800 604800 60\n", today7);
	lws_snprintf(z, sizeof(z), SOA1("%s"), today1);
	lws_snprintf(w, sizeof(w), SOA1("%s"), today8);
	ser_case("file behind the last signed continues from it", z, s, 0, w);

	ser_case("file set ahead by hand counts on from itself",
		 SOA1("4000000000"), s, 0, SOA1("4000000001"));

#define SOAML(_s) "$ORIGIN ser.example.\n" \
		  "@ 3600 IN SOA ns1.ser.example. host.ser.example. (\n" \
		  "\t\t; the serial\n\t\t" _s " ; serial\n" \
		  "\t\t3600 1800 604800 60 )\n" \
		  "www IN A 127.0.0.1\n"

	lws_snprintf(w, sizeof(w), SOAML("%s"), today1);
	ser_case("multiline SOA with comments", SOAML("2026010203"), NULL, 0,
		 w);

	ser_case("no SOA is refused", "$ORIGIN ser.example.\n@ IN NS ns1.\n",
		 NULL, -1, "$ORIGIN ser.example.\n@ IN NS ns1.\n");

	unlink(SER_ZONE);
	unlink(SER_SIGNED);

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
