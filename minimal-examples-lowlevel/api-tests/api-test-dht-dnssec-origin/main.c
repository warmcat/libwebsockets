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
 *
 * and that it is refused unless it is in date and no older than what was
 * taken before (G-505):
 *
 *  - a zone without an RRSIG over its SOA, or with any RRSIG expired or not
 *    yet valid, is refused; a little clock skew is allowed
 *  - once a version of a zone was taken, its high-water mark refuses an
 *    older serial (in RFC 1982 order) or an earlier signing, even when the
 *    zone's payload has gone from storage, but takes the same version again
 *  - the mark outlives the payload, and is swept once the version it records
 *    has long expired
 *  - a mark that can't be read refuses every version, is neither replaced
 *    nor swept, and only a mark that is not there admits anything (G-533);
 *    a <hash>.hwm.tmp a crash left is swept
 */

#include <libwebsockets.h>

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <utime.h>

#define LWS_PLUGIN_STATIC
#include "../../../plugins/protocol_lws_dht_dnssec/protocol_lws_dht_dnssec.c"

#define ORT_PAYLOAD	"origin-test.payload"
#define ORT_STORE	"origin-store"
/* a zone key, stored as <store>/ab/cd/<key> */
#define ORT_HASH	"abcd000000000000000000000000000000000000000000000000000000000001"

static int fails;

#define ORT_SOA(_o) "@ IN SOA ns1." _o ". host." _o ". " \
		    "( 2026100101 3600 1800 604800 60 )\n"

/* the RRSIG times of the cases, as zone text: YYYYMMDDHHMMSS */
static char ort_exp_ok[16], ort_inc_ok[16], ort_exp_past[16], ort_inc_past[16],
	    ort_inc_future[16], ort_exp_skew[16], ort_inc_skew[16];

static void
ort_time(char *buf, size_t len, time_t t)
{
	struct tm tm;

	gmtime_r(&t, &tm);
	lws_snprintf(buf, len, "%04d%02d%02d%02d%02d%02d", tm.tm_year + 1900,
		     tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
		     tm.tm_sec);
}

/* an RRSIG over type _t at the apex of a.example, with the given period */
static char *
ort_rrsig(char *buf, size_t len, const char *type, const char *exp,
	  const char *inc)
{
	lws_snprintf(buf, len, "@ IN RRSIG %s 8 2 60 %s %s 12345 a.example. "
		     "AAAA\n", type, exp, inc);

	return buf;
}

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
	struct lws_auth_dns_zone_validity zv;
	size_t l = strlen(text);
	time_t ttl;
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

	r = dht_dnssec_payload_check(ORT_PAYLOAD, domain, &zv, &ttl);

	if (!r != !want_refused || (!r && zv.serial != 2026100101u)) {
		lwsl_err("%s: FAILED: %s: %s\n", __func__, what,
			 r ? "refused" : "accepted");
		fails++;
		return;
	}

	lwsl_user("%s: ok: %s\n", __func__, what);
}

static int
ort_expect(int cond, const char *what)
{
	if (!cond) {
		lwsl_err("%s: FAILED: %s\n", __func__, what);
		fails++;

		return 1;
	}

	lwsl_user("%s: ok: %s\n", __func__, what);

	return 0;
}

/* a version of the zone, as dht_dnssec_payload_check() describes it */
static void
ort_zv(struct lws_auth_dns_zone_validity *zv, uint32_t serial,
       time_t inception, time_t expiration)
{
	memset(zv, 0, sizeof(*zv));
	zv->serial		= serial;
	zv->soa_inception	= inception;
	zv->inception		= inception;
	zv->expiration		= expiration;
	zv->soa_signed		= 1;
}

/*
 * Is there a file at path: asked by opening it, rather than by access(), a
 * check of the path that what we do with it next can't rely on
 */
static int
ort_present(const char *path)
{
	int fd = open(path, O_RDONLY);

	if (fd < 0)
		return 0;
	close(fd);

	return 1;
}

static void
hwm_cases(time_t now)
{
	struct lws_auth_dns_zone_validity zv;
	struct dht_dnssec_hwm seen;
	struct lws_dir_entry lde;
	char path[512];
	int fd;

	lws_snprintf(path, sizeof(path), "%s/ab/cd/%s.hwm", ORT_STORE,
		     ORT_HASH);

	/* what an interrupted earlier run left */
	unlink(path);
	rmdir(ORT_STORE "/ab/cd");
	rmdir(ORT_STORE "/ab");
	rmdir(ORT_STORE);

	if (mkdir(ORT_STORE, 0700) || mkdir(ORT_STORE "/ab", 0700) ||
	    mkdir(ORT_STORE "/ab/cd", 0700)) {
		ort_expect(0, "make the store");
		return;
	}

	/* nothing was ever taken: anything goes */
	ort_zv(&zv, 2026100101, now - 3600, now + 86400);
	ort_expect(!dht_dnssec_hwm_refuses(ORT_STORE, ORT_HASH, &zv, &seen),
		   "a zone never taken before is admitted");

	/* take serial 2026100105, signed an hour ago */
	ort_zv(&zv, 2026100105, now - 3600, now + 86400);
	ort_expect(!dht_dnssec_hwm_update(ORT_STORE, ORT_HASH, &zv),
		   "the version taken is recorded");

	ort_zv(&zv, 2026100101, now - 7200, now + 86400);
	ort_expect(dht_dnssec_hwm_refuses(ORT_STORE, ORT_HASH, &zv, &seen),
		   "an older serial is refused after a newer one");

	ort_zv(&zv, 2026100101, now, now + 86400);
	ort_expect(dht_dnssec_hwm_refuses(ORT_STORE, ORT_HASH, &zv, &seen),
		   "an older serial is refused even if signed later");

	ort_zv(&zv, 2026100106, now - 7200, now + 86400);
	ort_expect(dht_dnssec_hwm_refuses(ORT_STORE, ORT_HASH, &zv, &seen),
		   "a newer serial signed before the version taken is refused");

	ort_zv(&zv, 2026100105, now - 3600, now + 86400);
	ort_expect(!dht_dnssec_hwm_refuses(ORT_STORE, ORT_HASH, &zv, &seen),
		   "the version taken is admitted again");

	ort_zv(&zv, 2026100106, now - 60, now + 86400);
	ort_expect(!dht_dnssec_hwm_refuses(ORT_STORE, ORT_HASH, &zv, &seen),
		   "a newer version is admitted");

	/* an older one handed to update leaves the mark as it was */
	ort_zv(&zv, 2026100101, now - 7200, now + 86400);
	dht_dnssec_hwm_update(ORT_STORE, ORT_HASH, &zv);
	ort_expect(!dht_dnssec_hwm_read(ORT_STORE, ORT_HASH, &seen) &&
		   seen.serial == 2026100105 &&
		   seen.inception == (uint64_t)(now - 3600),
		   "an older version does not lower the mark");

	/* serials wrap: 5 is after 0xffffff00 */
	ort_zv(&zv, 0xffffff00u, now - 60, now + 86400);
	dht_dnssec_hwm_update(ORT_STORE, ORT_HASH, &zv);
	ort_zv(&zv, 5, now - 30, now + 86400);
	ort_expect(!dht_dnssec_hwm_refuses(ORT_STORE, ORT_HASH, &zv, &seen),
		   "a serial after the mark across the wrap is admitted");
	ort_zv(&zv, 0xfffffe00u, now - 30, now + 86400);
	ort_expect(dht_dnssec_hwm_refuses(ORT_STORE, ORT_HASH, &zv, &seen),
		   "a serial before the mark across the wrap is refused");

	/* the sweep keeps a mark whose version is still in date */
	memset(&lde, 0, sizeof(lde));
	lde.type = LDOT_FILE;
	lde.name = ORT_HASH ".hwm";
	dht_dnssec_sweep_level2_cb(ORT_STORE "/ab/cd", NULL, &lde);
	ort_expect(ort_present(path), "the sweep keeps a current mark");

	/* ...and expunges one whose version expired more than a week ago */
	ort_zv(&zv, 6, now - 30, now + 86400);
	dht_dnssec_hwm_update(ORT_STORE, ORT_HASH, &zv);
	fd = open(path, O_RDWR);
	if (fd >= 0) {
		uint8_t b[8];

		lws_ser_wu64be(b, (uint64_t)(now - DHT_DNSSEC_HWM_KEEP_SECS -
					     60));
		if (lseek(fd, 12, SEEK_SET) != 12 ||
		    write(fd, b, sizeof(b)) != (ssize_t)sizeof(b))
			ort_expect(0, "age the mark");
		close(fd);
	}
	dht_dnssec_sweep_level2_cb(ORT_STORE "/ab/cd", NULL, &lde);
	ort_expect(!ort_present(path), "the sweep expunges a long-expired mark");

	/*
	 * an unreadable mark fails closed (G-533): it refuses every version,
	 * is not replaced by the next one taken, and is not swept
	 */
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd >= 0) {
		if (write(fd, "x", 1) != 1)
			ort_expect(0, "write a short mark");
		close(fd);
	}
	ort_zv(&zv, 7, now - 30, now + 86400);
	ort_expect(dht_dnssec_hwm_refuses(ORT_STORE, ORT_HASH, &zv, &seen),
		   "a short mark refuses the zone");
	ort_expect(dht_dnssec_hwm_update(ORT_STORE, ORT_HASH, &zv) &&
		   dht_dnssec_hwm_read(ORT_STORE, ORT_HASH, &seen) ==
						DHT_DNSSEC_HWM_UNREADABLE,
		   "a short mark is not overwritten");
	dht_dnssec_sweep_level2_cb(ORT_STORE "/ab/cd", NULL, &lde);
	ort_expect(ort_present(path), "the sweep keeps a short mark");

	/* only a mark that is not there admits anything */
	unlink(path);
	ort_expect(!dht_dnssec_hwm_refuses(ORT_STORE, ORT_HASH, &zv, &seen) &&
		   !dht_dnssec_hwm_update(ORT_STORE, ORT_HASH, &zv) &&
		   dht_dnssec_hwm_read(ORT_STORE, ORT_HASH, &seen) ==
							DHT_DNSSEC_HWM_OK &&
		   seen.serial == 7,
		   "with the mark removed, the zone is taken and marked again");

	/*
	 * a mark being written left by a crash is swept once stale, one being
	 * written now is not
	 */
	{
		static const char *tmpname = ORT_HASH ".hwm.tmp";
		struct lws_dir_entry tde;
		char tpath[600];
		struct utimbuf ut;

		lws_snprintf(tpath, sizeof(tpath), "%s.tmp", path);
		fd = open(tpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd >= 0)
			close(fd);
		memset(&tde, 0, sizeof(tde));
		tde.type = LDOT_FILE;
		tde.name = tmpname;
		dht_dnssec_sweep_level2_cb(ORT_STORE "/ab/cd", NULL, &tde);
		ort_expect(ort_present(tpath),
			   "the sweep keeps a mark being written");

		ut.actime = ut.modtime = now - DHT_DNSSEC_HWM_TMP_STALE_SECS -
									60;
		ort_expect(!utime(tpath, &ut), "age the mark being written");
		dht_dnssec_sweep_level2_cb(ORT_STORE "/ab/cd", NULL, &tde);
		ort_expect(!ort_present(tpath),
			   "the sweep expunges a stale mark being written");
		unlink(tpath);
	}

	unlink(path);
	rmdir(ORT_STORE "/ab/cd");
	rmdir(ORT_STORE "/ab");
	rmdir(ORT_STORE);
}

int
main(void)
{
	char z[2048], sig[256], sig2[256];
	time_t now = time(NULL);

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);
	lwsl_user("LWS API selftest: dht-dnssec zone identity\n");

	ort_time(ort_exp_ok, sizeof(ort_exp_ok), now + 30 * 86400);
	ort_time(ort_inc_ok, sizeof(ort_inc_ok), now - 3600);
	ort_time(ort_exp_past, sizeof(ort_exp_past), now - 3600);
	ort_time(ort_inc_past, sizeof(ort_inc_past), now - 31 * 86400);
	ort_time(ort_inc_future, sizeof(ort_inc_future), now + 3600);
	/* inside LWS_AUTH_DNS_RRSIG_SKEW_SECS of now, either side */
	ort_time(ort_exp_skew, sizeof(ort_exp_skew), now - 60);
	ort_time(ort_inc_skew, sizeof(ort_inc_skew), now + 60);

	scan_case("one $ORIGIN", "$ORIGIN a.example.\n" ORT_SOA("a.example"),
		  0, "a.example");
	scan_case("no $ORIGIN", ORT_SOA("a.example"), 1, NULL);
	scan_case("trailing $ORIGIN refused", "$ORIGIN a.example.\n"
		  ORT_SOA("a.example") "$ORIGIN victim.\n", -1, NULL);
	scan_case("indented $ORIGIN is not one", "  $ORIGIN a.example.\n"
		  "$ORIGIN victim.\n" ORT_SOA("victim"), 0, "victim");

	lws_snprintf(z, sizeof(z), "$ORIGIN a.example.\n" ORT_SOA("a.example")
		     "%swww IN A 127.0.0.1\n", ort_rrsig(sig, sizeof(sig),
					"SOA", ort_exp_ok, ort_inc_ok));
	payload_case("the domain's own zone", z, "a.example", 0);

	payload_case("the domain's own zone, unsigned", "$ORIGIN a.example.\n"
		     ORT_SOA("a.example") "www IN A 127.0.0.1\n",
		     "a.example", 1);

	lws_snprintf(z, sizeof(z), "$ORIGIN a.example.\n" ORT_SOA("a.example")
		     "%swww IN A 127.0.0.1\n", ort_rrsig(sig, sizeof(sig),
					"A", ort_exp_ok, ort_inc_ok));
	payload_case("RRSIGs, but none over the SOA", z, "a.example", 1);

	lws_snprintf(z, sizeof(z), "$ORIGIN a.example.\n" ORT_SOA("a.example")
		     "%swww IN A 127.0.0.1\n", ort_rrsig(sig, sizeof(sig),
					"SOA", ort_exp_past, ort_inc_past));
	payload_case("SOA RRSIG expired", z, "a.example", 1);

	lws_snprintf(z, sizeof(z), "$ORIGIN a.example.\n" ORT_SOA("a.example")
		     "%swww IN A 127.0.0.1\n", ort_rrsig(sig, sizeof(sig),
					"SOA", ort_exp_ok, ort_inc_future));
	payload_case("SOA RRSIG not yet valid", z, "a.example", 1);

	lws_snprintf(z, sizeof(z), "$ORIGIN a.example.\n" ORT_SOA("a.example")
		     "%s%swww IN A 127.0.0.1\n", ort_rrsig(sig, sizeof(sig),
					"SOA", ort_exp_ok, ort_inc_ok),
		     ort_rrsig(sig2, sizeof(sig2), "NS", ort_exp_past,
			       ort_inc_past));
	payload_case("another RRSIG expired", z, "a.example", 1);

	lws_snprintf(z, sizeof(z), "$ORIGIN a.example.\n" ORT_SOA("a.example")
		     "%s%swww IN A 127.0.0.1\n", ort_rrsig(sig, sizeof(sig),
					"SOA", ort_exp_skew, ort_inc_ok),
		     ort_rrsig(sig2, sizeof(sig2), "NS", ort_exp_ok,
			       ort_inc_skew));
	payload_case("periods just out, inside the clock skew", z,
		     "a.example", 0);

	hwm_cases(now);
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
