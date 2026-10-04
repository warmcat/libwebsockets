/*
 * lws-api-test-dnssec-monitor-extip
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 * Note: CC0 1.0 Universal Public Domain Dedication
 *
 * Exercises the dnssec-monitor plugin's handling of the DHT-detected
 * external addresses on the zone signing side (monitor-extip.c):
 *
 *  - the first control line is the UDS IPC auth token: it is only
 *    installed if it is exactly 128 hex chars, and is consumed either way,
 *    so a bad token cannot be mistaken for an ext-ips line or vice versa
 *  - the proxy -> root control channel reassembles ext-ips lines across
 *    reads, takes only literal addresses of the right family, rejects
 *    malformed JSON, resyncs after an overlong line, and only counts a
 *    new generation when the addresses really changed
 *  - the IPv6 suffix replaces the low 16 bits of the detected address,
 *    and a malformed suffix leaves the address alone
 *  - zonefiles are classified by the ${EXTIP4} / ${EXTIP6} macros they use
 *  - a family the proxy stops reporting keeps its last address: only a
 *    different address replaces it
 *  - the per-zone record of the addresses a zone was signed with matches
 *    only the same values, so an address or suffix change re-signs it
 *  - a family with no live address is signed with the address in the
 *    zone's record, with the current suffix, and a record value that is not
 *    an address of its family is not used
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include "private.h"

static int
t_expect(int cond, const char *what)
{
	if (!cond) {
		lwsl_err("%s: FAILED: %s\n", __func__, what);

		return 1;
	}

	return 0;
}

static int
t_write_file(const char *path, const char *content)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	size_t l = strlen(content);

	if (fd < 0)
		return 1;
	if (write(fd, content, l) != (ssize_t)l) {
		close(fd);

		return 1;
	}
	close(fd);

	return 0;
}

static int
t_mkdir(const char *path)
{
	if (mkdir(path, 0700) && errno != EEXIST)
		return 1;

	return 0;
}

static void
t_ctl(struct vhd *vhd, const char *s)
{
	monitor_extip_ctl_rx(vhd, s, strlen(s));
}

static int
t_key_is(struct vhd *vhd, const uint8_t *key)
{
	return vhd->auth_jwk.kty == LWS_GENCRYPTO_KTY_OCT &&
	       vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].len ==
							MON_AUTH_KEY_LEN &&
	       !memcmp(vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf, key,
		       MON_AUTH_KEY_LEN);
}

/* the token line and anything after it, delivered over the given reads */

static int
t_token(const char *const *reads, const uint8_t *key, const char *what)
{
	struct vhd vhd;
	int fails = 0;

	memset(&vhd, 0, sizeof(vhd));
	while (*reads)
		t_ctl(&vhd, *reads++);

	if (key)
		fails += t_expect(t_key_is(&vhd, key), what);
	else
		fails += t_expect(!vhd.auth_jwk.kty &&
				  !vhd.auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf &&
				  !vhd.auth_token[0], what);

	/* whatever the token was, the next line is taken as ext-ips */
	fails += t_expect(vhd.extip_gen == 1 &&
			  !strcmp(vhd.extip4, "192.0.2.5"),
			  "ext-ips line after the token");

	lws_jwk_destroy(&vhd.auth_jwk);

	return fails;
}

static int
t_suffix(const char *ip6, const char *suffix, const char *expect)
{
	char out[64];

	monitor_extip_apply_suffix(out, sizeof(out), ip6, suffix);
	if (strcmp(out, expect)) {
		lwsl_err("%s: '%s' + '%s' -> '%s', expected '%s'\n", __func__,
			 ip6, suffix, out, expect);

		return 1;
	}

	return 0;
}

int main(void)
{
	char ip4[64], ip6[64], big[1024], tok[(MON_AUTH_KEY_LEN * 2) + 2],
	     tok_crlf[sizeof(tok) + 1], tok_short[sizeof(tok) - 1],
	     tok_bad[sizeof(tok)];
	static const char *xl = "{\"ext-ips\": [\"192.0.2.5\"]}\n";
	uint8_t key[MON_AUTH_KEY_LEN];
	struct vhd vhd;
	unsigned int gen;
	int fails = 0;
	size_t n;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);
	lwsl_user("LWS API selftest: dnssec-monitor external addresses\n");

	memset(&vhd, 0, sizeof(vhd));
	vhd.base_dir = (char *)"./extip-corpus";

	lws_dir("./extip-corpus", NULL, lws_dir_rm_rf_cb);
	rmdir("./extip-corpus");

	if (t_mkdir("./extip-corpus") ||
	    t_mkdir("./extip-corpus/domains") ||
	    t_write_file("./extip-corpus/both.zone",
			 "@ IN A ${EXTIP4}\n"
			 "@ IN AAAA ${EXTIP6}\n"
			 "www IN A 192.0.2.1\n") ||
	    t_write_file("./extip-corpus/v6.zone",
			 "mx 60 IN AAAA ${EXTIP6}\n") ||
	    t_write_file("./extip-corpus/static.zone",
			 "@ IN A 192.0.2.1\n"
			 "; ${EXTIP} is not one of ours\n")) {
		lwsl_err("%s: unable to create the corpus\n", __func__);

		return 1;
	}

	/* control channel: the first line is the IPC auth token */

	for (n = 0; n < sizeof(key); n++)
		key[n] = (uint8_t)(n * 37 + 11);
	lws_hex_from_byte_array(key, sizeof(key), tok, sizeof(tok) - 1);
	lws_snprintf(tok_crlf, sizeof(tok_crlf), "%s\r\n", tok);
	memcpy(tok_short, tok, sizeof(tok_short) - 2);
	tok_short[sizeof(tok_short) - 2] = '\n';
	tok_short[sizeof(tok_short) - 1] = '\0';
	lws_strncpy(tok_bad, tok, sizeof(tok_bad));
	tok_bad[5] = 'g';
	n = strlen(tok);
	tok[n] = '\n';
	tok[n + 1] = '\0';
	tok_bad[n] = '\n';
	tok_bad[n + 1] = '\0';

	{
		const char *whole[] = { tok, xl, NULL };
		const char *crlf[] = { tok_crlf, xl, NULL };
		const char *shrt[] = { tok_short, xl, NULL };
		const char *bad[] = { tok_bad, xl, NULL };
		const char *over[] = { big, "\n", xl, NULL };
		char split1[80], both[sizeof(tok) + 64];
		const char *split[] = { split1, tok + sizeof(split1) - 1,
					xl, NULL };
		const char *one[] = { both, NULL };

		lws_strncpy(split1, tok, sizeof(split1));
		lws_snprintf(both, sizeof(both), "%s%s", tok, xl);

		memset(big, 'a', sizeof(big) - 1);
		big[sizeof(big) - 1] = '\0';

		fails += t_token(whole, key, "token installed");
		fails += t_token(crlf, key, "token with CRLF installed");
		fails += t_token(split, key, "token split over reads");
		fails += t_token(one, key, "token and ext-ips in one read");
		fails += t_token(shrt, NULL, "short token refused");
		fails += t_token(bad, NULL, "non-hex token refused");
		fails += t_token(over, NULL, "overlong token refused");
	}

	/* the rest of the tests run after a bootstrapped channel */

	t_ctl(&vhd, tok);
	fails += t_expect(t_key_is(&vhd, key) && !vhd.extip_gen,
			  "token is not an ext-ips line");

	/* control channel: a line split over reads only lands when complete */

	t_ctl(&vhd, "{\"ext-ips\": [\"203.0.113.");
	fails += t_expect(!vhd.extip_gen && !vhd.extip4[0],
			  "partial line not acted on");
	t_ctl(&vhd, "7\", \"2001:db8:ffff:0:0:0:0:1\"]}\n");
	fails += t_expect(vhd.extip_gen == 1 &&
			  !strcmp(vhd.extip4, "203.0.113.7") &&
			  !strcmp(vhd.extip6, "2001:db8:ffff::1") &&
			  vhd.extip_since,
			  "reassembled line sets canonical addresses");

	gen = vhd.extip_gen;
	t_ctl(&vhd, "{\"ext-ips\": [\"203.0.113.7\", \"2001:db8:ffff::1\"]}\n");
	fails += t_expect(vhd.extip_gen == gen, "unchanged addresses no new gen");

	/*
	 * non-address strings and a second address per family are ignored,
	 * and v6 going unreported keeps the v6 address we had
	 */
	t_ctl(&vhd, "{\"ext-ips\": [\"x\\\"y\", \"198.51.100.2\", "
		    "\"198.51.100.3\"]}\n");
	fails += t_expect(vhd.extip_gen == gen + 1 &&
			  !strcmp(vhd.extip4, "198.51.100.2") &&
			  !strcmp(vhd.extip6, "2001:db8:ffff::1"),
			  "only the first literal per family, v6 kept");

	/* nothing at all reported is no change either */
	gen = vhd.extip_gen;
	t_ctl(&vhd, "{\"ext-ips\": []}\n");
	fails += t_expect(vhd.extip_gen == gen &&
			  !strcmp(vhd.extip4, "198.51.100.2") &&
			  !strcmp(vhd.extip6, "2001:db8:ffff::1"),
			  "empty report keeps both");

	/* v4 unreported but v6 changed: only v6 moves */
	t_ctl(&vhd, "{\"ext-ips\": [\"2001:db8:eeee::1\"]}\n");
	fails += t_expect(vhd.extip_gen == gen + 1 &&
			  !strcmp(vhd.extip4, "198.51.100.2") &&
			  !strcmp(vhd.extip6, "2001:db8:eeee::1"),
			  "v6 change with v4 unreported keeps v4");

	gen = vhd.extip_gen;
	t_ctl(&vhd, "{\"ext-ips\": [\"192.0.2.99\"\n");
	fails += t_expect(vhd.extip_gen == gen &&
			  !strcmp(vhd.extip4, "198.51.100.2"),
			  "malformed line rejected");

	/* an overlong line is dropped whole, and the next line still works */
	memset(big, 'a', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';
	t_ctl(&vhd, big);
	t_ctl(&vhd, "\"]}\n{\"ext-ips\": [\"203.0.113.7\", \"2001:db8:ffff::1\"]}\n");
	fails += t_expect(vhd.extip_gen == gen + 1 &&
			  !strcmp(vhd.extip4, "203.0.113.7") &&
			  !strcmp(vhd.extip6, "2001:db8:ffff::1"),
			  "resync after overlong line");

	/* suffix: one hex group replacing the low 16 bits */

	fails += t_suffix("2001:db8:ffff::1", "", "2001:db8:ffff::1");
	fails += t_suffix("2001:db8:ffff::1", "ab", "2001:db8:ffff::ab");
	fails += t_suffix("2001:db8:ffff::1", "BEEF", "2001:db8:ffff::beef");
	fails += t_suffix("2001:db8:1:2:3:4:5:6", "f", "2001:db8:1:2:3:4:5:f");
	fails += t_suffix("2001:db8::", "1", "2001:db8::1");
	fails += t_suffix("2001:db8:ffff::1", "12345", "2001:db8:ffff::1");
	fails += t_suffix("2001:db8:ffff::1", "zz", "2001:db8:ffff::1");
	fails += t_suffix("2001:db8:ffff::1", "1:2", "2001:db8:ffff::1");

	/* zone macro usage */

	fails += t_expect(monitor_extip_zone_uses("./extip-corpus/both.zone") ==
			  (MON_EXTIP_USES_4 | MON_EXTIP_USES_6), "both macros");
	fails += t_expect(monitor_extip_zone_uses("./extip-corpus/v6.zone") ==
			  MON_EXTIP_USES_6, "v6 macro only");
	fails += t_expect(!monitor_extip_zone_uses("./extip-corpus/static.zone"),
			  "no macros");
	fails += t_expect(monitor_extip_zone_uses("./extip-corpus/nope.zone") < 0,
			  "missing zone");

	/* values handed to the signer, with and without a stored suffix */

	monitor_extip_for_zone(&vhd, MON_EXTIP_USES_4 | MON_EXTIP_USES_6, NULL,
			       ip4, sizeof(ip4), ip6, sizeof(ip6));
	fails += t_expect(!strcmp(ip4, "203.0.113.7") &&
			  !strcmp(ip6, "2001:db8:ffff::1"),
			  "no suffix: DHT addresses as detected");

	fails += t_expect(!t_write_file("./extip-corpus/domains/ipv6_suffix.txt",
					"a1\n"), "write suffix");
	monitor_extip_for_zone(&vhd, MON_EXTIP_USES_6, NULL, ip4, sizeof(ip4),
			       ip6, sizeof(ip6));
	fails += t_expect(!ip4[0] && !strcmp(ip6, "2001:db8:ffff::a1"),
			  "suffix applied, unused family empty");

	/* the signed-with record */

	fails += t_expect(!monitor_extip_signed_matches(
				"./extip-corpus/both.zone.signed.extip",
				"203.0.113.7", "2001:db8:ffff::a1"),
			  "no record: never signed with these");
	fails += t_expect(!monitor_extip_record(
				"./extip-corpus/both.zone.signed.extip",
				"203.0.113.7", "2001:db8:ffff::a1"),
			  "record written");
	fails += t_expect(monitor_extip_signed_matches(
				"./extip-corpus/both.zone.signed.extip",
				"203.0.113.7", "2001:db8:ffff::a1"),
			  "record matches the same values");
	fails += t_expect(!monitor_extip_signed_matches(
				"./extip-corpus/both.zone.signed.extip",
				"203.0.113.7", "2001:db8:ffff::1"),
			  "suffix change does not match");
	fails += t_expect(!monitor_extip_signed_matches(
				"./extip-corpus/both.zone.signed.extip",
				"203.0.113.8", "2001:db8:ffff::a1"),
			  "v4 change does not match");
	fails += t_expect(!monitor_extip_signed_matches(
				"./extip-corpus/both.zone.signed.extip",
				"203.0.113.7", ""),
			  "lost v6 does not match");

	/*
	 * a family with no live address is signed with the recorded one, eg,
	 * after a restart before the detector has found it again
	 */

	{
		struct vhd v2;
		const char *sp = "./extip-corpus/both.zone.signed.extip";

		memset(&v2, 0, sizeof(v2));
		v2.base_dir = vhd.base_dir;

		monitor_extip_for_zone(&v2, MON_EXTIP_USES_4 |
				       MON_EXTIP_USES_6, sp, ip4, sizeof(ip4),
				       ip6, sizeof(ip6));
		fails += t_expect(!strcmp(ip4, "203.0.113.7") &&
				  !strcmp(ip6, "2001:db8:ffff::a1"),
				  "no live addresses: the recorded ones");

		monitor_extip_for_zone(&v2, MON_EXTIP_USES_4 |
				       MON_EXTIP_USES_6, NULL, ip4, sizeof(ip4),
				       ip6, sizeof(ip6));
		fails += t_expect(!ip4[0] && !ip6[0],
				  "no live addresses and no record: empty");

		/* a live address of either family beats the record */
		lws_strncpy(v2.extip6, "2001:db8:dddd::1", sizeof(v2.extip6));
		monitor_extip_for_zone(&v2, MON_EXTIP_USES_4 |
				       MON_EXTIP_USES_6, sp, ip4, sizeof(ip4),
				       ip6, sizeof(ip6));
		fails += t_expect(!strcmp(ip4, "203.0.113.7") &&
				  !strcmp(ip6, "2001:db8:dddd::a1"),
				  "live v6 with recorded v4");
		v2.extip6[0] = '\0';

		/* the recorded v6 takes a changed suffix */
		fails += t_expect(!t_write_file(
				"./extip-corpus/domains/ipv6_suffix.txt",
				"b2\n"), "write new suffix");
		monitor_extip_for_zone(&v2, MON_EXTIP_USES_6, sp, ip4,
				       sizeof(ip4), ip6, sizeof(ip6));
		fails += t_expect(!ip4[0] && !strcmp(ip6, "2001:db8:ffff::b2"),
				  "recorded v6 with the new suffix");

		/* a record value that is not an address of its family */
		fails += t_expect(!t_write_file(sp,
				"EXTIP4=2001:db8::5\nEXTIP6=bogus\n"),
				"write bad record");
		monitor_extip_for_zone(&v2, MON_EXTIP_USES_4 |
				       MON_EXTIP_USES_6, sp, ip4, sizeof(ip4),
				       ip6, sizeof(ip6));
		fails += t_expect(!ip4[0] && !ip6[0],
				  "bad record values not used");

		/* a zone signed without v4 has nothing recorded for it */
		fails += t_expect(!monitor_extip_record(sp, "",
					"2001:db8:ffff::b2"),
				  "record without v4");
		monitor_extip_for_zone(&v2, MON_EXTIP_USES_4 |
				       MON_EXTIP_USES_6, sp, ip4, sizeof(ip4),
				       ip6, sizeof(ip6));
		fails += t_expect(!ip4[0] && !strcmp(ip6, "2001:db8:ffff::b2"),
				  "empty recorded v4 stays empty");
	}

	lws_jwk_destroy(&vhd.auth_jwk);

	lws_dir("./extip-corpus", NULL, lws_dir_rm_rf_cb);
	rmdir("./extip-corpus");

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
