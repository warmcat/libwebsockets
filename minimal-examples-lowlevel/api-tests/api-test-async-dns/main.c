/*
 * lws-api-test-async-dns
 *
 * Written in 2019-2025 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This api test confirms various kinds of async dns apis
 */

#include <libwebsockets.h>

#if !defined(WIN32)
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/resource.h>
/*
 * We test the platform DNS server watcher end to end by pointing the whole
 * discovery machinery at a scratch resolv.conf we control, and checking the
 * SMD LWSSMDCL_DNS publications that come out of it.
 */
#define RESOLV_TEST_CONF	"resolv-test.conf"
#define RESOLV_TEST_WATCH_MS	"200"
#endif

enum {
	LWS_SW_D,
	LWS_SW_L,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_L]	= { "-l",              "Enable -l feature" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

#include <signal.h>

static int dtest, ok, fail, _exp = 22;
static uint32_t fail_mask;
struct lws_context *context;

/*
 * These are used to test the apis to parse and print ipv4 / ipv6 literal
 * address strings for various cases.
 *
 * Expected error cases are not used to test the ip data -> string api.
 */

static const struct ipparser_tests {
	const char	*test;
	int		rlen;
	const char	*emit_test;
	int		emit_len;
	uint8_t		b[16];
} ipt[] = {
	{ "2001:db8:85a3:0:0:8a2e:370:7334", 16,
	  "2001:db8:85a3::8a2e:370:7334", 28,
		{ 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
		  0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34 } },

	{ "2001:db8:85a3::8a2e:370:7334", 16,
	  "2001:db8:85a3::8a2e:370:7334", 28,
		{ 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
		  0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34 } },

	{ "::1", 16, "::1", 3,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },

	{ "::",  16, "::", 2,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } },

	{ "::ffff:192.0.2.128", 16,  "::ffff:192.0.2.128", 18,
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xff, 0xff, 0xc0, 0x00, 0x02, 0x80 } },

	{ "cats", -1, "", 0,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },

	{ "onevalid.bogus.warmcat.com", -1, "", 0,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },

	{ "1.cat.dog.com", -1, "", 0,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },

	{ ":::1", -8, "", 0,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },

	{ "0:0::0:1", 16, "::1", 3,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },

	{ "1.2.3.4", 4, "1.2.3.4", 7, { 1, 2, 3, 4 } },

	/*
	 * F-017 regression cases: overlong literals must fail with -15 when
	 * the next group does not fit in the result buffer, rather than
	 * writing 1 - 2 bytes past the end of it first
	 */

	{ "1:2:3:4:5:6:7:8:9", -15, "", 0,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },

	{ "1:2:3:4:5:6:7:8::", -15, "", 0,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },

	{ "::ffff:1.2.3.4.5", -15, "", 0,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },

	{ "1.2.3.4.5", -12, "", 0,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
};

#define TEST_FLAG_NOCHECK_RESULT_IP 0x100000

static struct async_dns_tests {
	const char *dns_name;
	int recordtype;
	int addrlen;
	uint8_t ads[16];
} adt[] = {
	{ "ml.warmcat.com", TEST_FLAG_NOCHECK_RESULT_IP | LWS_ADNS_RECORD_A | LWS_ADNS_IGNORE_HOSTS_FILE | LWS_ADNS_INDICATE_LACKS_DNSSEC, 4,
		{ 46, 105, 127, 147, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
		/* test coming from cache */
	{ "ml.warmcat.com", TEST_FLAG_NOCHECK_RESULT_IP | LWS_ADNS_RECORD_A | LWS_ADNS_INDICATE_LACKS_DNSSEC, 4,
		{ 46, 105, 127, 147, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "libwebsockets.org", TEST_FLAG_NOCHECK_RESULT_IP | LWS_ADNS_RECORD_A | LWS_ADNS_IGNORE_HOSTS_FILE | LWS_ADNS_INDICATE_LACKS_DNSSEC, 4,
		{ 46, 105, 127, 147, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "doesntexist", LWS_ADNS_RECORD_A | LWS_ADNS_INDICATE_LACKS_DNSSEC, 0,
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "localhost", LWS_ADNS_RECORD_A | LWS_ADNS_INDICATE_LACKS_DNSSEC, 4,
		{ 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "ipv4only.warmcat.com", LWS_ADNS_RECORD_A | LWS_ADNS_INDICATE_LACKS_DNSSEC, 4,
		{ 212, 83, 179, 61, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "onevalid.bogus.warmcat.com", LWS_ADNS_RECORD_A | LWS_ADNS_INDICATE_LACKS_DNSSEC, 4,
		{ 212, 83, 179, 61, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
#if defined(LWS_WITH_IPV6)
	{ "mail.warmcat.com", LWS_ADNS_RECORD_AAAA | LWS_ADNS_INDICATE_LACKS_DNSSEC, 16, /* check ipv6 */
		{ 0x20, 0x01, 0x0b, 0xc8, 0x60, 0x10, 0x02, 0x13,
				0x02, 0x08, 0xa2, 0xff, 0xfe, 0x0c, 0x72, 0xce, } },
	{ "ipv6only.warmcat.com", LWS_ADNS_RECORD_AAAA | LWS_ADNS_INDICATE_LACKS_DNSSEC, 16, /* check ipv6 */
		{ 0x20, 0x01, 0x0b, 0xc8, 0x60, 0x10, 0x02, 0x13,
				0x02, 0x08, 0xa2, 0xff, 0xfe, 0x0c, 0x72, 0xce, } },
#endif
//	{ "c.msn.com", TEST_FLAG_NOCHECK_RESULT_IP |
//		       LWS_ADNS_SYNTHETIC | LWS_ADNS_RECORD_A | LWS_ADNS_INDICATE_LACKS_DNSSEC, 4,
//		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "c.msn.com", TEST_FLAG_NOCHECK_RESULT_IP |
		       LWS_ADNS_SYNTHETIC | LWS_ADNS_RECORD_A | LWS_ADNS_INDICATE_LACKS_DNSSEC, 0,
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "assets.msn.com", TEST_FLAG_NOCHECK_RESULT_IP |
		       LWS_ADNS_SYNTHETIC | LWS_ADNS_RECORD_A | LWS_ADNS_INDICATE_LACKS_DNSSEC, 4,
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "e28578.d.akamaiedge.net", TEST_FLAG_NOCHECK_RESULT_IP |
		       LWS_ADNS_SYNTHETIC | LWS_ADNS_RECORD_A | LWS_ADNS_INDICATE_LACKS_DNSSEC, 0,
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "a-0003.a-msedge.net", TEST_FLAG_NOCHECK_RESULT_IP |
		       LWS_ADNS_SYNTHETIC | LWS_ADNS_RECORD_A | LWS_ADNS_INDICATE_LACKS_DNSSEC, 0,
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
//	{ "c-msn-com-europe-vip.trafficmanager.net", TEST_FLAG_NOCHECK_RESULT_IP |
//		       LWS_ADNS_SYNTHETIC | LWS_ADNS_RECORD_A | LWS_ADNS_INDICATE_LACKS_DNSSEC, 0,
//		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "tcp-fallback.libwebsockets.org", LWS_ADNS_SYNTHETIC | LWS_ADNS_RECORD_A | LWS_ADNS_INDICATE_LACKS_DNSSEC, 0,
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	/*
	 * CNAME to a shorter name (mudpuddle.shwaine.com -> shwaine.com),
	 * covers the cache name length after CNAME.  Third-party address,
	 * has changed before, so we only check that it resolves.
	 */
	{ "mudpuddle.shwaine.com", TEST_FLAG_NOCHECK_RESULT_IP | LWS_ADNS_RECORD_A | LWS_ADNS_INDICATE_LACKS_DNSSEC, 4,
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "awsrealm.majicrealm.com", LWS_ADNS_RECORD_A | LWS_ADNS_INDICATE_LACKS_DNSSEC, 4,
		{ 35, 88, 197, 177, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "lwsbiglongtesthostname.lociterm.com", LWS_ADNS_RECORD_A | LWS_ADNS_INDICATE_LACKS_DNSSEC, 4,
		{ 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "game.addictmud.org", LWS_ADNS_RECORD_A | LWS_ADNS_INDICATE_LACKS_DNSSEC, 4,
		{ 167, 172, 227, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "grow.lociterm.com", LWS_ADNS_RECORD_A | LWS_ADNS_INDICATE_LACKS_DNSSEC, 4,
		{ 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "letsgobigorgohome.lociterm.com", LWS_ADNS_RECORD_A | LWS_ADNS_INDICATE_LACKS_DNSSEC, 4,
		{ 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "terrafirma.terra.mud.org", LWS_ADNS_RECORD_A | LWS_ADNS_INDICATE_LACKS_DNSSEC, 4,
		{ 92,205,179,40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
	{ "warmcat.com", TEST_FLAG_NOCHECK_RESULT_IP | LWS_ADNS_RECORD_SOA | LWS_ADNS_INDICATE_LACKS_DNSSEC, 0,
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, } },
};

static uint8_t canned_c_msn_com[] = {
	0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02,
	0x00, 0x01, 0x00, 0x00, 0x01, 0x63, 0x03, 0x6D,
	0x73, 0x6E, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00,
	0x1C, 0x00, 0x01, 0xC0, 0x0C, 0x00, 0x05, 0x00,
	0x01, 0x00, 0x00, 0x54, 0x5E, 0x00, 0x24, 0x0F,
	0x63, 0x2D, 0x6D, 0x73, 0x6E, 0x2D, 0x63, 0x6F,
	0x6D, 0x2D, 0x6E, 0x73, 0x61, 0x74, 0x63, 0x0E,
	0x74, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63, 0x6D,
	0x61, 0x6E, 0x61, 0x67, 0x65, 0x72, 0x03, 0x6E,
	0x65, 0x74, 0x00, 0xC0, 0x27, 0x00, 0x05, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x3A, 0x00, 0x17, 0x14,
	0x63, 0x2D, 0x6D, 0x73, 0x6E, 0x2D, 0x63, 0x6F,
	0x6D, 0x2D, 0x65, 0x75, 0x72, 0x6F, 0x70, 0x65,
	0x2D, 0x76, 0x69, 0x70, 0xC0, 0x37, 0xC0, 0x37,
	0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1C,
	0x00, 0x2E, 0x03, 0x74, 0x6D, 0x31, 0x06, 0x64,
	0x6E, 0x73, 0x2D, 0x74, 0x6D, 0xC0, 0x12, 0x0A,
	0x68, 0x6F, 0x73, 0x74, 0x6D, 0x61, 0x73, 0x74,
	0x65, 0x72, 0xC0, 0x37, 0x77, 0x64, 0x96, 0x60,
	0x00, 0x00, 0x03, 0x84, 0x00, 0x00, 0x01, 0x2C,
	0x00, 0x24, 0xEA, 0x00, 0x00, 0x00, 0x00, 0x1E,
}, canned_assets_msn_com[] = {
	219,29,129,128,0,1,0,2,0,1,0,0,6,97,115,115,101,116,115,3,109,115,
	110,3,99,111,109,0,0,28,0,1,192,12,0,5,0,1,0,0,81,199,0,28,6,97,115,
	115,101,116,115,3,109,115,110,3,99,111,109,7,101,100,103,101,107,101,
	121,3,110,101,116,0,192,44,0,5,0,1,0,0,0,235,0,22,6,101,50,56,53,55,
	56,1,100,10,97,107,97,109,97,105,101,100,103,101,192,67,192,91,0,6,
	0,1,0,0,1,79,0,46,3,110,48,100,192,93,10,104,111,115,116,109,97,115,
	116,101,114,6,97,107,97,109,97,105,192,23,97,106,246,231,0,0,3,232,0,
	0,3,232,0,0,3,232,0,0,7,8,
}, canned_e28578_d_akamaiedge_net[] = {
	20,191,129,128,0,1,0,0,0,1,0,0,6,101,50,56,53,55,56,1,100,10,97,107,97,
	109,97,105,101,100,103,101,3,110,101,116,0,0,28,0,1,192,19,0,6,0,1,0,0,
	1,17,0,49,3,110,48,100,192,21,10,104,111,115,116,109,97,115,116,101,114,
	6,97,107,97,109,97,105,3,99,111,109,0,97,107,217,31,0,0,3,232,0,0,3,232,
	0,0,3,232,0,0,7,8
}, canned_a_0003_a_msedge_net[] = {
	126,215,129,128,0,1,0,0,0,1,0,0,6,97,45,48,48,48,51,8,97,45,109,115,101,
	100,103,101,3,110,101,116,0,0,28,0,1,192,19,0,6,0,1,0,0,0,172,0,48,3,
	110,115,49,192,19,6,109,115,110,104,115,116,9,109,105,99,114,111,115,
	111,102,116,3,99,111,109,0,120,43,34,229,0,0,7,8,0,0,3,132,0,36,234,0,
	0,0,0,240
}, canned_c_msn_com_europe_vip_trafficmanager_net[] = {
	73,87,129,128,0,1,0,0,0,1,0,0,20,99,45,109,115,110,45,99,111,109,45,101,
	117,114,111,112,101,45,118,105,112,14,116,114,97,102,102,105,99,109,97,
	110,97,103,101,114,3,110,101,116,0,0,28,0,1,192,33,0,6,0,1,0,0,0,30,0,
	49,3,116,109,49,6,100,110,115,45,116,109,3,99,111,109,0,10,104,111,115,
	116,109,97,115,116,101,114,192,33,7,11,234,133,0,0,3,132,0,0,1,44,0,36,
	234,0,0,0,0,30,
}, canned_tc_libwebsockets_org[] = {
	0x00, 0x00,
	0x83, 0x80,
	0x00, 0x01,
	0x00, 0x00,
	0x00, 0x00,
	0x00, 0x00,
	12, 't', 'c', 'p', '-', 'f', 'a', 'l', 'l', 'b', 'a', 'c', 'k',
	13, 'l', 'i', 'b', 'w', 'e', 'b', 's', 'o', 'c', 'k', 'e', 't', 's',
	3, 'o', 'r', 'g', 0,
	0x00, 0x01,
	0x00, 0x01
};

static lws_sorted_usec_list_t sul, sul_timeout;

/*
 * SMD observer for LWSSMDCL_DNS: registered as an early smd participant so
 * it's in place before the async dns machinery publishes its initial server
 * list during context creation.
 */

static int watch_msgs, watch_fail;
static char watch_last_payload[256];

static int
smd_dns_cb(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp,
	   void *buf, size_t len)
{
	size_t l = len;

	(void)opaque;
	(void)timestamp;

	if (_class != LWSSMDCL_DNS)
		return 0;

	if (l >= sizeof(watch_last_payload))
		l = sizeof(watch_last_payload) - 1;
	memcpy(watch_last_payload, buf, l);
	watch_last_payload[l] = '\0';
	watch_msgs++;

	lwsl_user("SMD LWSSMDCL_DNS: %s\n", watch_last_payload);

	return 0;
}

#if !defined(WIN32)

/*
 * Watcher test leg:
 *
 * 1) wait for the gratuitous initial publication of the server set from the
 *    scratch resolv.conf (one nameserver),
 * 2) append a second nameserver to the scratch file, and an IPv6 one,
 * 3) wait for a new publication that contains it, and in builds with IPv6,
 *    the IPv6 one: a ':' used to end the token, so IPv6 nameservers were
 *    dropped, and an IPv6-only build pointed only at "::1" had none at all.
 *
 * When the leg is done (or has failed), the real async dns subtests start.
 */

static void next_test_cb(lws_sorted_usec_list_t *sul);

static lws_sorted_usec_list_t sul_watch_leg;
static int watch_leg_phase, watch_leg_ticks;

static void
sul_watch_leg_cb(lws_sorted_usec_list_t *s)
{
	switch (watch_leg_phase) {

	case 0: /* waiting for the initial gratuitous report */
		if (!watch_msgs)
			break;

		{
			int fd = open(RESOLV_TEST_CONF, O_WRONLY | O_APPEND);

			if (fd < 0) {
				lwsl_err("%s: can't append to " RESOLV_TEST_CONF "\n", __func__);
				goto fail;
			}
			if (write(fd, "nameserver 127.0.0.2\n"
				      "nameserver 2001:db8::53\n", 45) < 0) {
				close(fd);
				goto fail;
			}
			close(fd);
			watch_leg_phase = 1;
		}
		break;

	case 1: /* waiting for the change to be detected and published */
		if (strstr(watch_last_payload, "127.0.0.2")
#if defined(LWS_WITH_IPV6)
		    && strstr(watch_last_payload, "2001:db8::53")
#endif
		)
			goto pass;
		break;
	}

	if (++watch_leg_ticks < 40) { /* ~8s at the test poll interval */
		lws_sul_schedule(context, 0, &sul_watch_leg,
				 sul_watch_leg_cb, 200 * LWS_US_PER_MS);
		return;
	}

fail:
	lwsl_err("%s: watcher test leg failed (phase %d, msgs %d, last '%s')\n",
			__func__, watch_leg_phase, watch_msgs,
			watch_last_payload);
	watch_fail++;

pass:

	/* kick off the real async dns subtests */

	lws_sul_schedule(context, 0, &sul, next_test_cb, 1);
}
#endif

#if !defined(WIN32) && defined(LWS_WITH_SYS_STATE)

/*
 * State gate leg: uses its own context with no pinned DNS servers and an
 * initially empty platform server set (the scratch resolv.conf).  The
 * system state must hold at LWS_SYSTATE_DNS until the watcher acquires a
 * server, and then reach OPERATIONAL; we observe both via SMD.
 */

static struct lws_context *gate_cx;
static lws_sorted_usec_list_t sul_gate;
static int gate_dns_seen, gate_op_before, gate_op_after;
static int gate_leg_ticks, gate_do_write;

static int
payload_contains(void *buf, size_t len, const char *needle)
{
	char tmp[256];
	size_t l = len;

	if (l >= sizeof(tmp))
		l = sizeof(tmp) - 1;
	memcpy(tmp, buf, l);
	tmp[l] = '\0';

	return !!strstr(tmp, needle);
}

static int
smd_gate_cb(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp,
	    void *buf, size_t len)
{
	(void)opaque;
	(void)timestamp;

	if (_class == LWSSMDCL_DNS) {
		/* only count a non-empty server set as "servers acquired" */
		if (payload_contains(buf, len, "127.0.0.3")) {
			gate_dns_seen = 1;
			lwsl_user("GATE: SMD DNS: %.*s\n", (int)len,
					(const char *)buf);
		}

		return 0;
	}

	if (_class == LWSSMDCL_SYSTEM_STATE &&
	    payload_contains(buf, len, "OPERATIONAL")) {
		if (gate_dns_seen)
			gate_op_after = 1;
		else
			gate_op_before = 1;
		lwsl_user("GATE: SMD STATE: %.*s\n", (int)len,
				(const char *)buf);

		/*
		 * In the give-up scenario, reaching OPERATIONAL without any
		 * server is the expected outcome... we're done
		 */

		if (!gate_do_write && gate_op_before)
			lws_default_loop_exit(gate_cx);
	}

	return 0;
}

static void
sul_gate_cb(lws_sorted_usec_list_t *s)
{
	(void)s;

	if (gate_do_write && gate_leg_ticks == 5) {
		/* ~1s in: the platform gets its first DNS server */
		int fd = open(RESOLV_TEST_CONF, O_WRONLY | O_APPEND);

		if (fd < 0)
			lwsl_err("%s: can't open " RESOLV_TEST_CONF "\n",
					__func__);
		else {
			if (write(fd, "nameserver 127.0.0.3\n", 21) < 0)
				lwsl_err("%s: append failed\n", __func__);
			close(fd);
		}
	}

	if (++gate_leg_ticks > 14) /* ~3s: give up waiting */
		lws_default_loop_exit(gate_cx);
	else
		lws_sul_schedule(gate_cx, 0, &sul_gate, sul_gate_cb,
				 200 * LWS_US_PER_MS);
}

static void
gate_reset(void)
{
	int fd = open(RESOLV_TEST_CONF, O_WRONLY | O_TRUNC, 0600);

	gate_dns_seen = gate_op_before = gate_op_after = 0;
	gate_leg_ticks = 0;

	if (fd < 0) {
		lwsl_err("%s: can't reset " RESOLV_TEST_CONF "\n", __func__);
		watch_fail++;
		return;
	}
	close(fd);
}

static int
gate_run(void)
{
	struct lws_context_creation_info gi;

	gate_reset();

	lws_context_info_defaults(&gi, NULL);
	gi.early_smd_cb = smd_gate_cb;
	gi.early_smd_class_filter = LWSSMDCL_DNS | LWSSMDCL_SYSTEM_STATE;

	gate_cx = lws_create_context(&gi);
	if (!gate_cx) {
		lwsl_err("%s: gate context create failed\n", __func__);
		return 1;
	}

	lws_sul_schedule(gate_cx, 0, &sul_gate, sul_gate_cb,
			 200 * LWS_US_PER_MS);

	while (lws_service(gate_cx, 0) >= 0)
		;

	lws_context_destroy(gate_cx);
	gate_cx = NULL;

	return 0;
}

/*
 * Scenario A: no servers at first, a server appears at ~1s; the state must
 * hold at LWS_SYSTATE_DNS until then and reach OPERATIONAL after.
 */

static void
gate_hold_release_test(void)
{
	if (gate_run()) {
		watch_fail++;
		return;
	}

	if (gate_op_before) {
		lwsl_err("%s: reached OPERATIONAL with no DNS servers\n",
				__func__);
		watch_fail++;
	} else if (!gate_dns_seen || !gate_op_after) {
		lwsl_err("%s: no OPERATIONAL after servers appeared "
			 "(dns %d, op_after %d)\n", __func__,
			 gate_dns_seen, gate_op_after);
		watch_fail++;
	} else
		lwsl_user("Gate hold/release leg: PASS\n");
}

/*
 * Scenario B: no server ever appears; the bounded hold must give way and
 * let the context reach OPERATIONAL anyway (with a warning), rather than
 * wedging pre-OPERATIONAL forever.
 */

static void
gate_giveup_test(void)
{
	setenv("LWS_ASYNCDNS_GATE_MAX_MS", "300", 1);

	if (gate_run()) {
		watch_fail++;
		goto bail;
	}

	if (!gate_op_before || gate_dns_seen) {
		lwsl_err("%s: expected bounded give-up to OPERATIONAL "
			 "(op %d, dns %d)\n", __func__,
			 gate_op_before, gate_dns_seen);
		watch_fail++;
	} else
		lwsl_user("Gate give-up leg: PASS\n");

bail:
	unsetenv("LWS_ASYNCDNS_GATE_MAX_MS");
}
#endif

#if !defined(WIN32)

/*
 * Resolver source-check legs (C-433).
 *
 * An answer only means anything if it came from the nameserver we asked.
 * The resolver's UDP socket is connect()ed to the chosen nameserver, so the
 * kernel enforces that for us, but the resolver doesn't rely on it: it does
 * the check itself in callback_async_dns() as well, which also covers a stack
 * that doesn't filter connected UDP sockets (see lib/io/adopt.c).
 * recvfrom() also leaves the datagram's source in wsi->udp->sa46, which is
 * the send target too, so the chosen server has to be put back there before
 * the check.
 *
 * Both legs stand a fake nameserver up on a loopback UDP socket of our own
 * and point a private context's resolver at it:
 *
 *  - the plain leg has that fake nameserver answer the query itself, and the
 *    query must complete with the address it gave.
 *
 *  - the foreign leg has a second local socket, bound to a different port,
 *    answer first with a different address and the right tid.  That answer
 *    must be ignored, and the later answer from the real fake nameserver
 *    accepted.  Nothing may arrive at the second socket afterwards either,
 *    which is what proves wsi->udp->sa46 was put back to the chosen server
 *    instead of being left pointing at the foreign source.
 *
 * A third leg uses the same fake nameserver to check the cache entry's
 * lifetime: the A half of the pair is answered with a TTL of 0, and the AAAA
 * half only a few ticks later.  The entry made from the A answer expires in
 * between, while the query that owns it is still waiting to chain the AAAA
 * answer on to it, so the entry must outlive its TTL until the query is done
 * with it.  It used to be freed at the expiry and then written to by the AAAA
 * answer, seen as a use-after-free under ASAN.
 *
 * This is a unit test of our own filtering against sockets we own on
 * loopback; nothing leaves the machine.
 */

#define SC_NAME			"srccheck.invalid"
#define SC_TICK_US		(50 * LWS_US_PER_MS)
#define SC_QUIET_TICKS		2	/* no new query = lws asked all it will */
#define SC_FOREIGN_TICKS	10	/* > the 300ms first async-dns retry */
#define SC_DEADLINE_TICKS	120	/* ~6s */
#define SC_TTL0_TICKS		4	/* < the 300ms first async-dns retry */
#define SC_MAX_QUERIES		8

/* the fake nameserver's answer, and the one the foreign socket tries */

static const uint8_t sc_ads_good[] = { 127, 0, 0, 9 },
		     sc_ads_foreign[] = { 10, 9, 8, 7 };

struct sc_query {
	struct sockaddr_storage	peer;
	socklen_t		peer_len;
	size_t			len;
	int			answered;
	uint8_t			pkt[512];
};

static struct sc_query sc_q[SC_MAX_QUERIES];
static struct lws_context *sc_cx;
static lws_sorted_usec_list_t sul_sc;
static int sc_fd = -1, sc_foreign_fd = -1;
enum {
	SC_MODE_PLAIN,
	SC_MODE_FOREIGN,
	SC_MODE_TTL0,
};

static int sc_fail, sc_mode, sc_done;
static int sc_qs, sc_ticks, sc_quiet, sc_phase, sc_phase_ticks;
static int sc_resolved, sc_bad_ads, sc_redirected;

/* a nonblocking UDP socket on an ephemeral loopback port */

static int
sc_socket(uint16_t *port)
{
	struct sockaddr_in sin;
	socklen_t sl = sizeof(sin);
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		return -1;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family		= AF_INET;
	sin.sin_addr.s_addr	= htonl(INADDR_LOOPBACK);

	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) ||
	    getsockname(fd, (struct sockaddr *)&sin, &sl) ||
	    fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		close(fd);
		return -1;
	}

	*port = ntohs(sin.sin_port);

	return fd;
}

/*
 * Offset of the QTYPE in a query packet, ie, just past the qname; 0 if the
 * packet doesn't hold a whole question.  Also tells us where the question
 * section ends, which is where our answer RR goes.
 */

static size_t
sc_qtype_ofs(const uint8_t *pkt, size_t len)
{
	size_t o = 12; /* past the DNS header */

	while (o < len && pkt[o]) {
		if (pkt[o] > 63) /* a query qname has no compression pointers */
			return 0;
		o += (size_t)pkt[o] + 1;
	}

	if (o + 5 > len)
		return 0;

	return o + 1;
}

/* the QTYPE a captured query asks for, or 0 if it's not a whole question */

static uint16_t
sc_qtype(const struct sc_query *q)
{
	size_t qo = sc_qtype_ofs(q->pkt, q->len);

	if (!qo)
		return 0;

	return (uint16_t)((q->pkt[qo] << 8) | q->pkt[qo + 1]);
}

/*
 * Answer one captured query from the given socket: A gets the given address
 * with the given TTL, anything else (ie, the AAAA half of the A/AAAA pair lws
 * asks) gets an empty NOERROR answer, which is enough for the query to be
 * considered answered for that family.
 */

static void
sc_answer(struct sc_query *q, int fd, const uint8_t *ads, uint8_t ttl)
{
	uint8_t resp[sizeof(q->pkt) + 16];
	size_t qo = sc_qtype_ofs(q->pkt, q->len), o;
	uint16_t qtype = sc_qtype(q);

	if (!qo)
		return;

	o = qo + 4; /* the question section ends after QTYPE + QCLASS */

	memcpy(resp, q->pkt, o);

	resp[2] = 0x81;			/* QR + RD */
	resp[3] = 0x80;			/* RA, rcode NOERROR */
	resp[6] = 0; resp[7] = 0;	/* ANCOUNT */
	resp[8] = 0; resp[9] = 0;	/* NSCOUNT */
	resp[10] = 0; resp[11] = 0;	/* ARCOUNT */

	if (qtype == LWS_ADNS_RECORD_A) {
		resp[7] = 1;
		resp[o++] = 0xc0;	/* NAME: pointer to the qname */
		resp[o++] = 0x0c;
		resp[o++] = 0;
		resp[o++] = (uint8_t)LWS_ADNS_RECORD_A;
		resp[o++] = 0; resp[o++] = 1;	/* CLASS IN */
		resp[o++] = 0; resp[o++] = 0;
		resp[o++] = 0; resp[o++] = ttl;	/* TTL, seconds */
		resp[o++] = 0; resp[o++] = 4;	/* RDLENGTH */
		memcpy(&resp[o], ads, 4);
		o += 4;
	}

	if (sendto(fd, (const char *)resp, o, 0, (struct sockaddr *)&q->peer,
		   q->peer_len) < 0)
		lwsl_err("%s: sendto failed, errno %d\n", __func__, errno);
}

/* answer what's not been answered, only queries for qtype if it's nonzero */

static void
sc_answer_all(int fd, const uint8_t *ads, uint16_t qtype, uint8_t ttl,
	      int mark)
{
	int n;

	for (n = 0; n < sc_qs; n++)
		if (!sc_q[n].answered &&
		    (!qtype || sc_qtype(&sc_q[n]) == qtype)) {
			sc_answer(&sc_q[n], fd, ads, ttl);
			if (mark)
				sc_q[n].answered = 1;
		}
}

/* collect whatever the resolver sent our fake nameserver since last time */

static void
sc_harvest(void)
{
	for (;;) {
		struct sc_query dump, *q = sc_qs < SC_MAX_QUERIES ?
						&sc_q[sc_qs] : &dump;
		ssize_t n;

		q->peer_len = sizeof(q->peer);
		n = recvfrom(sc_fd, (char *)q->pkt, sizeof(q->pkt), 0,
			     (struct sockaddr *)&q->peer, &q->peer_len);
		if (n < 12)
			return;

		sc_quiet = 0;

		if (q == &dump) /* more retries than we have room for, fine */
			continue;

		q->len = (size_t)n;
		q->answered = 0;
		sc_qs++;
	}
}

/*
 * Nothing may ever arrive at the foreign socket: if the resolver had adopted
 * the foreign source as its send target, its retry would land here.
 */

static void
sc_check_foreign(void)
{
	uint8_t dump[512];

	while (recv(sc_foreign_fd, (char *)dump, sizeof(dump), 0) >= 0)
		sc_redirected++;
}

static struct lws *
sc_cb(struct lws *wsi_unused, const char *ads, const struct addrinfo *a, int n,
      void *opaque)
{
	const struct addrinfo *ac = a;

	(void)wsi_unused;
	(void)ads;
	(void)n;
	(void)opaque;

	sc_resolved = 1;
	sc_bad_ads = 1;

	while (ac) {
		if (ac->ai_family == AF_INET &&
		    !memcmp(&((struct sockaddr_in *)ac->ai_addr)->sin_addr,
			    sc_ads_good, sizeof(sc_ads_good)))
			sc_bad_ads = 0;

		ac = ac->ai_next;
	}

	lws_async_dns_freeaddrinfo(&a);

	return NULL;
}

static void
sul_sc_cb(lws_sorted_usec_list_t *s)
{
	(void)s;

	sc_harvest();
	sc_check_foreign();

	switch (sc_phase) {

	case 0: /* wait until lws has sent all the queries it is going to */
		if (!sc_qs || ++sc_quiet < SC_QUIET_TICKS)
			break;

		if (sc_mode == SC_MODE_TTL0) {
			lwsl_user("%s: answering A with TTL 0, AAAA later\n",
					__func__);
			sc_answer_all(sc_fd, sc_ads_good, LWS_ADNS_RECORD_A,
				      0, 1);
			sc_phase = 3;
			break;
		}

		if (sc_mode != SC_MODE_FOREIGN) {
			sc_phase = 2;
			break;
		}

		lwsl_user("%s: answering from the wrong source port\n",
				__func__);
		sc_answer_all(sc_foreign_fd, sc_ads_foreign, 0, 60, 0);
		sc_phase = 1;
		break;

	case 1: /* the foreign answer must not be taken, nor redirect us */
		if (sc_resolved) {
			lwsl_err("%s: took an answer from a foreign source\n",
					__func__);
			sc_fail++;
			sc_done = 1;
			lws_default_loop_exit(sc_cx);
			break;
		}

		if (++sc_phase_ticks >= SC_FOREIGN_TICKS)
			sc_phase = 2;
		break;

	case 2: /* the nameserver we actually asked answers */
		sc_answer_all(sc_fd, sc_ads_good, 0, 60, 1);
		if (sc_resolved) {
			sc_done = 1;
			lws_default_loop_exit(sc_cx);
		}
		break;

	case 3: /* the A answer's entry expires while the AAAA is held back */
		if (++sc_phase_ticks >= SC_TTL0_TICKS)
			sc_phase = 2;
		break;
	}

	if (++sc_ticks >= SC_DEADLINE_TICKS) {
		lwsl_err("%s: timed out in phase %d (%d queries seen)\n",
				__func__, sc_phase, sc_qs);
		sc_fail++;
		sc_done = 1;
		lws_default_loop_exit(sc_cx);
	}

	if (!sc_done)
		lws_sul_schedule(sc_cx, 0, &sul_sc, sul_sc_cb, SC_TICK_US);
}

static const char * const sc_mode_names[] = {
	"plain", "foreign answer", "ttl 0 expiry"
};

static void
sc_run(int mode)
{
	static const char *sc_servers[] = { "127.0.0.1", NULL };
	struct lws_context_creation_info ci;
	uint16_t port = 0, foreign_port = 0;
	char saved[16], portstr[16];
	const char *env;
	int had_saved;

	memset(sc_q, 0, sizeof(sc_q));
	sc_qs = sc_ticks = sc_quiet = sc_phase = sc_phase_ticks = 0;
	sc_resolved = sc_bad_ads = sc_redirected = sc_done = 0;
	sc_mode = mode;

	lwsl_user("*** resolver source-check leg (%s)\n", sc_mode_names[mode]);

	sc_fd = sc_socket(&port);
	sc_foreign_fd = sc_socket(&foreign_port);
	if (sc_fd < 0 || sc_foreign_fd < 0) {
		lwsl_err("%s: can't make the loopback sockets\n", __func__);
		sc_fail++;
		goto bail;
	}

	/* point the resolver's nameserver port at our fake nameserver */

	env = getenv("LWS_ASYNCDNS_PORT");
	had_saved = !!env;
	if (env)
		lws_strncpy(saved, env, sizeof(saved));
	lws_snprintf(portstr, sizeof(portstr), "%u", port);
	setenv("LWS_ASYNCDNS_PORT", portstr, 1);

	lws_context_info_defaults(&ci, NULL);
	ci.port			= CONTEXT_PORT_NO_LISTEN;
	ci.options		= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	ci.async_dns_servers	= sc_servers;

	sc_cx = lws_create_context(&ci);
	if (!sc_cx) {
		lwsl_err("%s: context create failed\n", __func__);
		sc_fail++;
		goto restore;
	}

	/* only the pinned nameserver, ie, only our own fake one */

	{
		lws_sockaddr46 sa46;
		int index = 0;

		while (!lws_plat_asyncdns_get_server(sc_cx, index++, &sa46))
			lws_async_dns_server_remove(sc_cx, &sa46);
	}

	if (lws_async_dns_query(sc_cx, 0, SC_NAME,
				(adns_query_type_t)(LWS_ADNS_RECORD_A |
						LWS_ADNS_NOCACHE |
						LWS_ADNS_IGNORE_HOSTS_FILE |
						LWS_ADNS_INDICATE_LACKS_DNSSEC),
				sc_cb, NULL, NULL, NULL) !=
						LADNS_RET_CONTINUING) {
		lwsl_err("%s: query did not start\n", __func__);
		sc_fail++;
		goto destroy;
	}

	lws_sul_schedule(sc_cx, 0, &sul_sc, sul_sc_cb, SC_TICK_US);

	while (lws_service(sc_cx, 0) >= 0)
		;

destroy:
	lws_sul_cancel(&sul_sc);
	lws_context_destroy(sc_cx);
	sc_cx = NULL;

restore:
	if (had_saved)
		setenv("LWS_ASYNCDNS_PORT", saved, 1);
	else
		unsetenv("LWS_ASYNCDNS_PORT");

bail:
	if (sc_fd >= 0)
		close(sc_fd);
	if (sc_foreign_fd >= 0)
		close(sc_foreign_fd);
	sc_fd = sc_foreign_fd = -1;

	if (sc_fail)
		return;

	if (!sc_resolved) {
		lwsl_err("%s: query never completed\n", __func__);
		sc_fail++;
	} else if (sc_bad_ads) {
		lwsl_err("%s: query completed without the nameserver's "
			 "address\n", __func__);
		sc_fail++;
	}

	if (sc_redirected) {
		lwsl_err("%s: %d datagram(s) went to the foreign source\n",
				__func__, sc_redirected);
		sc_fail++;
	}

	if (!sc_fail)
		lwsl_user("Resolver source-check leg (%s): PASS\n",
				sc_mode_names[mode]);
}

/*
 * Search list legs
 *
 * resolv.conf's "search" line gives the domains a name with fewer than ndots
 * dots is tried under, and ndots decides whether that is before or after the
 * name as given.  The fake nameserver from the source-check legs captures
 * what the resolver asks about, so each leg checks the sequence of names
 * asked about, and what the requester is told in the end:
 *
 *  - a single-label name is asked about under the search domain first, and
 *    the answer for that is what the requester gets, as the name it asked
 *    for
 *
 *  - a name with as many dots as ndots is asked about as given first, and
 *    then under the search domain; NXDOMAIN for both is NXDOMAIN
 *
 *  - a name ending in a dot is absolute: only asked about as given
 *
 * The scratch resolv.conf the main context's discovery is pointed at holds
 * the search list for the legs' private contexts; it is emptied again after.
 */

#define SRCH_TICK_US		(50 * LWS_US_PER_MS)
#define SRCH_DEADLINE_TICKS	120	/* ~6s */
#define SRCH_MAX_NAMES		4

struct srch_leg {
	const char	*name;		/* what we ask lws for */
	const char	*asked[3];	/* what lws must ask about, in order */
	const char	*answer;	/* the one answered with an address */
	int		expect;		/* what the requester must be told */
};

static const struct srch_leg srch_legs[] = {
	{ "srchtest", { "srchtest.lan", NULL, NULL }, "srchtest.lan",
	  LADNS_RET_FOUND },
	{ "nx.srchtest", { "nx.srchtest", "nx.srchtest.lan", NULL }, NULL,
	  LADNS_RET_NXDOMAIN },
	{ "srchtest.", { "srchtest", NULL, NULL }, NULL, LADNS_RET_NXDOMAIN },
};

static const struct srch_leg *srch_leg;
static int srch_fail, srch_completed, srch_ret, srch_names, srch_bad_ads,
	   srch_bad_name;
static char srch_seen[SRCH_MAX_NAMES][64];

/* the dotted QNAME of a captured query, or NULL if it's not a whole one */

static const char *
sc_qname(const struct sc_query *q, char *buf, size_t len)
{
	size_t o = 12, used = 0;

	if (!sc_qtype_ofs(q->pkt, q->len))
		return NULL;

	while (q->pkt[o]) {
		size_t l = q->pkt[o++];

		if (used + l + 2 > len)
			return NULL;
		if (used)
			buf[used++] = '.';
		memcpy(buf + used, &q->pkt[o], l);
		used += l;
		o += l;
	}
	buf[used] = '\0';

	return buf;
}

/* answer a captured query with an empty NXDOMAIN */

static void
sc_answer_nxdomain(struct sc_query *q, int fd)
{
	uint8_t resp[sizeof(q->pkt)];
	size_t qo = sc_qtype_ofs(q->pkt, q->len), o;

	if (!qo)
		return;

	o = qo + 4;
	memcpy(resp, q->pkt, o);

	resp[2] = 0x81;			/* QR + RD */
	resp[3] = 0x83;			/* RA, rcode NXDOMAIN */
	resp[6] = 0; resp[7] = 0;	/* ANCOUNT */
	resp[8] = 0; resp[9] = 0;	/* NSCOUNT */
	resp[10] = 0; resp[11] = 0;	/* ARCOUNT */

	if (sendto(fd, (const char *)resp, o, 0, (struct sockaddr *)&q->peer,
		   q->peer_len) < 0)
		lwsl_err("%s: sendto failed, errno %d\n", __func__, errno);
}

static struct lws *
srch_cb(struct lws *wsi_unused, const char *ads, const struct addrinfo *a,
	int n, void *opaque)
{
	const struct addrinfo *ac = a;

	(void)wsi_unused;
	(void)opaque;

	srch_ret = n;
	srch_completed = 1;

	/* the requester is told about the name it asked for */
	if (!ads || strcmp(ads, srch_leg->name))
		srch_bad_name = 1;

	if (n == LADNS_RET_FOUND) {
		srch_bad_ads = 1;
		while (ac) {
			if (ac->ai_family == AF_INET &&
			    !memcmp(&((struct sockaddr_in *)ac->ai_addr)->sin_addr,
				    sc_ads_good, sizeof(sc_ads_good)))
				srch_bad_ads = 0;
			ac = ac->ai_next;
		}
	}

	if (a)
		lws_async_dns_freeaddrinfo(&a);

	return NULL;
}

static void
sul_srch_cb(lws_sorted_usec_list_t *s)
{
	int n;

	(void)s;

	sc_harvest();

	/* answer whatever came, as the leg says, noting each new name */

	for (n = 0; n < sc_qs; n++) {
		char qn[64];

		if (sc_q[n].answered || !sc_qname(&sc_q[n], qn, sizeof(qn)))
			continue;

		if (!srch_names || strcmp(srch_seen[srch_names - 1], qn)) {
			if (srch_names < SRCH_MAX_NAMES)
				lws_strncpy(srch_seen[srch_names], qn,
					    sizeof(srch_seen[0]));
			srch_names++;
		}

		if (srch_leg->answer && !strcmp(qn, srch_leg->answer))
			sc_answer(&sc_q[n], sc_fd, sc_ads_good, 60);
		else
			sc_answer_nxdomain(&sc_q[n], sc_fd);
		sc_q[n].answered = 1;
	}

	/* once told, nothing more may be asked: wait a little to be sure */
	if (srch_completed && ++sc_quiet >= SC_QUIET_TICKS) {
		sc_done = 1;
		lws_default_loop_exit(sc_cx);
	}

	if (++sc_ticks >= SRCH_DEADLINE_TICKS) {
		lwsl_err("%s: timed out (%d queries seen)\n", __func__, sc_qs);
		srch_fail++;
		sc_done = 1;
		lws_default_loop_exit(sc_cx);
	}

	if (!sc_done)
		lws_sul_schedule(sc_cx, 0, &sul_sc, sul_srch_cb, SRCH_TICK_US);
}

static void
srch_run(const struct srch_leg *leg)
{
	static const char *srch_servers[] = { "127.0.0.1", NULL };
	struct lws_context_creation_info ci;
	char saved[16], portstr[16];
	uint16_t port = 0;
	const char *env;
	int had_saved, n, fd;

	memset(sc_q, 0, sizeof(sc_q));
	memset(srch_seen, 0, sizeof(srch_seen));
	sc_qs = sc_ticks = sc_quiet = sc_done = 0;
	srch_completed = srch_names = srch_bad_ads = srch_bad_name = 0;
	srch_ret = LADNS_RET_CONTINUING;
	srch_leg = leg;

	lwsl_user("*** search list leg (%s)\n", leg->name);

	fd = open(RESOLV_TEST_CONF, O_WRONLY | O_TRUNC, 0600);
	if (fd < 0 || write(fd, "search lan\noptions ndots:1\n", 27) < 0) {
		lwsl_err("%s: can't write " RESOLV_TEST_CONF "\n", __func__);
		if (fd >= 0)
			close(fd);
		srch_fail++;
		return;
	}
	close(fd);

	sc_fd = sc_socket(&port);
	if (sc_fd < 0) {
		lwsl_err("%s: can't make the loopback socket\n", __func__);
		srch_fail++;
		goto bail;
	}

	env = getenv("LWS_ASYNCDNS_PORT");
	had_saved = !!env;
	if (env)
		lws_strncpy(saved, env, sizeof(saved));
	lws_snprintf(portstr, sizeof(portstr), "%u", port);
	setenv("LWS_ASYNCDNS_PORT", portstr, 1);

	lws_context_info_defaults(&ci, NULL);
	ci.port			= CONTEXT_PORT_NO_LISTEN;
	ci.options		= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	ci.async_dns_servers	= srch_servers;

	sc_cx = lws_create_context(&ci);
	if (!sc_cx) {
		lwsl_err("%s: context create failed\n", __func__);
		srch_fail++;
		goto restore;
	}

	if (lws_async_dns_query(sc_cx, 0, leg->name,
				(adns_query_type_t)(LWS_ADNS_RECORD_A |
						LWS_ADNS_NOCACHE |
						LWS_ADNS_IGNORE_HOSTS_FILE |
						LWS_ADNS_INDICATE_LACKS_DNSSEC),
				srch_cb, NULL, NULL, NULL) !=
						LADNS_RET_CONTINUING) {
		lwsl_err("%s: query did not start\n", __func__);
		srch_fail++;
		goto destroy;
	}

	lws_sul_schedule(sc_cx, 0, &sul_sc, sul_srch_cb, SRCH_TICK_US);

	while (lws_service(sc_cx, 0) >= 0)
		;

destroy:
	lws_sul_cancel(&sul_sc);
	lws_context_destroy(sc_cx);
	sc_cx = NULL;

restore:
	if (had_saved)
		setenv("LWS_ASYNCDNS_PORT", saved, 1);
	else
		unsetenv("LWS_ASYNCDNS_PORT");

bail:
	if (sc_fd >= 0)
		close(sc_fd);
	sc_fd = -1;

	fd = open(RESOLV_TEST_CONF, O_WRONLY | O_TRUNC, 0600);
	if (fd >= 0)
		close(fd);

	if (!srch_completed) {
		lwsl_err("%s: query never completed\n", __func__);
		srch_fail++;
		return;
	}

	if (srch_ret != leg->expect) {
		lwsl_err("%s: requester told %d, expected %d\n", __func__,
			 srch_ret, leg->expect);
		srch_fail++;
	}

	if (srch_bad_name) {
		lwsl_err("%s: requester told about the wrong name\n",
			 __func__);
		srch_fail++;
	}

	if (srch_bad_ads) {
		lwsl_err("%s: completed without the nameserver's address\n",
			 __func__);
		srch_fail++;
	}

	for (n = 0; n < (int)LWS_ARRAY_SIZE(leg->asked); n++) {
		const char *seen = n < srch_names && n < SRCH_MAX_NAMES ?
							srch_seen[n] : NULL;

		if ((!leg->asked[n] && !seen) ||
		    (leg->asked[n] && seen && !strcmp(leg->asked[n], seen)))
			continue;

		lwsl_err("%s: asked about '%s' at step %d, expected '%s'\n",
			 __func__, seen ? seen : "(nothing)", n,
			 leg->asked[n] ? leg->asked[n] : "(nothing)");
		srch_fail++;
		break;
	}

	if (!srch_fail)
		lwsl_user("Search list leg (%s): PASS\n", leg->name);
}

/*
 * Send-failure leg
 *
 * A send that fails on the resolver's UDP socket leaves it unusable: eg, the
 * socket took the icmp error for an earlier datagram the nameserver refused.
 * If a query sent on it earlier in the same pass had asked for a writeable
 * to send its AAAA half, the socket also kept POLLOUT armed, and the
 * level-triggered poll reported it on every pass from then on, since nothing
 * dropped POLLOUT on a socket that can no longer write.  The resolver also
 * kept the dead socket, so its later queries could not be sent at all.
 *
 * Two queries go out together to a loopback port nothing is listening on.
 * On Linux the first send's icmp port unreachable is back before the second
 * send, which fails with it.  The failed query must fail promptly, then our
 * fake nameserver comes up on that port, and the other query must be
 * answered through the resolver's new socket.  Elsewhere the second send
 * may not fail, and both queries are answered once the nameserver is up.
 * Either way, the leg must not burn the cpu.  That is measured as cpu time
 * rather than by counting service passes: the poll loop also returns many
 * times, polling with no wait, through the last fraction of a millisecond
 * before each timer is due.
 */

#define SF_TICK_US		(20 * LWS_US_PER_MS)
#define SF_UP_US		(200 * LWS_US_PER_MS) /* if no send failed */
#define SF_PROMPT_US		(100 * LWS_US_PER_MS)
#define SF_DEADLINE_US		(5 * LWS_US_PER_SEC)
#define SF_MAX_CPU_US		(100 * LWS_US_PER_MS) /* a spin uses ~all */

static const char * const sf_names[] = { "sf1.invalid", "sf2.invalid" };
static const uint8_t sf_ads[] = { 127, 0, 0, 9 };

static struct sc_query sf_q;
static struct lws_context *sf_cx;
static lws_sorted_usec_list_t sul_sf, sul_sf_deadline;
static lws_usec_t sf_issued;
static uint16_t sf_port;
static int sf_fd = -1, sf_fail, sf_failed, sf_resolved, sf_completed;

static void
sf_finish(int failed)
{
	sf_fail += failed;
	lws_sul_cancel(&sul_sf);
	lws_sul_cancel(&sul_sf_deadline);
	lws_default_loop_exit(sf_cx);
}

/* the fake nameserver comes up on the port the queries were refused at */

static void
sf_nameserver_up(void)
{
	struct sockaddr_in sin;

	if (sf_fd >= 0)
		return;

	sf_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sf_fd < 0)
		goto bail;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family		= AF_INET;
	sin.sin_addr.s_addr	= htonl(INADDR_LOOPBACK);
	sin.sin_port		= htons(sf_port);

	if (!bind(sf_fd, (struct sockaddr *)&sin, sizeof(sin)) &&
	    fcntl(sf_fd, F_SETFL, O_NONBLOCK) >= 0)
		return;

	close(sf_fd);
	sf_fd = -1;

bail:
	lwsl_err("%s: can't bring the nameserver up on %u\n", __func__,
		 sf_port);
	sf_finish(1);
}

static struct lws *
sf_cb(struct lws *wsi_unused, const char *ads, const struct addrinfo *a, int n,
      void *opaque)
{
	lws_usec_t took = lws_now_usecs() - sf_issued;
	const struct addrinfo *ac = a;

	(void)wsi_unused;
	(void)n;
	(void)opaque;

	sf_completed++;

	if (!a) {
		lwsl_user("%s: %s failed after %dms\n", __func__, ads,
			  (int)(took / LWS_US_PER_MS));
		sf_failed++;
		if (took > SF_PROMPT_US) {
			lwsl_err("%s: %s was slow to fail\n", __func__, ads);
			sf_fail++;
		}

		/* its send failed: what is left can be answered now */
		sf_nameserver_up();
	} else {
		while (ac) {
			if (ac->ai_family == AF_INET &&
			    !memcmp(&((struct sockaddr_in *)ac->ai_addr)->sin_addr,
				    sf_ads, sizeof(sf_ads)))
				sf_resolved++;
			ac = ac->ai_next;
		}
		lws_async_dns_freeaddrinfo(&a);
	}

	if (sf_completed == (int)LWS_ARRAY_SIZE(sf_names))
		sf_finish(0);

	return NULL;
}

/* the fake nameserver answers each datagram that arrives */

static void
sul_sf_cb(lws_sorted_usec_list_t *s)
{
	(void)s;

	if (lws_now_usecs() - sf_issued >= SF_UP_US)
		sf_nameserver_up();

	while (sf_fd >= 0) {
		ssize_t r;

		sf_q.peer_len = sizeof(sf_q.peer);
		r = recvfrom(sf_fd, (char *)sf_q.pkt, sizeof(sf_q.pkt), 0,
			     (struct sockaddr *)&sf_q.peer, &sf_q.peer_len);
		if (r < 12)
			break;

		sf_q.len = (size_t)r;
		sc_answer(&sf_q, sf_fd, sf_ads, 60);
	}

	lws_sul_schedule(sf_cx, 0, &sul_sf, sul_sf_cb, SF_TICK_US);
}

static void
sul_sf_deadline_cb(lws_sorted_usec_list_t *s)
{
	(void)s;

	lwsl_err("%s: timed out, %d of %d queries completed\n", __func__,
		 sf_completed, (int)LWS_ARRAY_SIZE(sf_names));
	sf_finish(1);
}

static lws_usec_t
sf_cpu_us(void)
{
	struct rusage ru;

	if (getrusage(RUSAGE_SELF, &ru))
		return 0;

	return ((lws_usec_t)ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) *
						LWS_US_PER_SEC +
	       ru.ru_utime.tv_usec + ru.ru_stime.tv_usec;
}

static void
sf_run(void)
{
	static const char *sf_servers[] = { "127.0.0.1", NULL };
	struct lws_context_creation_info ci;
	char saved[16], portstr[16];
	lws_usec_t cpu = 0;
	int had_saved;
	const char *env;
	size_t n;

	lwsl_user("*** resolver send-failure leg\n");

	sf_fail = sf_failed = sf_resolved = sf_completed = 0;

	/* a loopback port that refuses, until the nameserver comes up on it */

	sf_fd = sc_socket(&sf_port);
	if (sf_fd < 0) {
		lwsl_err("%s: can't make the loopback socket\n", __func__);
		sf_fail++;
		return;
	}
	close(sf_fd);
	sf_fd = -1;

	env = getenv("LWS_ASYNCDNS_PORT");
	had_saved = !!env;
	if (env)
		lws_strncpy(saved, env, sizeof(saved));
	lws_snprintf(portstr, sizeof(portstr), "%u", sf_port);
	setenv("LWS_ASYNCDNS_PORT", portstr, 1);

	lws_context_info_defaults(&ci, NULL);
	ci.port			= CONTEXT_PORT_NO_LISTEN;
	ci.options		= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	ci.async_dns_servers	= sf_servers;

	sf_cx = lws_create_context(&ci);
	if (!sf_cx) {
		lwsl_err("%s: context create failed\n", __func__);
		sf_fail++;
		goto restore;
	}

	/* only the pinned nameserver, ie, only our own fake one */

	{
		lws_sockaddr46 sa46;
		int index = 0;

		while (!lws_plat_asyncdns_get_server(sf_cx, index++, &sa46))
			lws_async_dns_server_remove(sf_cx, &sa46);
	}

	/* both queries are sent on the same writeable */

	sf_issued = lws_now_usecs();
	for (n = 0; n < LWS_ARRAY_SIZE(sf_names); n++)
		if (lws_async_dns_query(sf_cx, 0, sf_names[n],
				(adns_query_type_t)(LWS_ADNS_RECORD_A |
						LWS_ADNS_NOCACHE |
						LWS_ADNS_IGNORE_HOSTS_FILE |
						LWS_ADNS_INDICATE_LACKS_DNSSEC),
				sf_cb, NULL, NULL, NULL) !=
						LADNS_RET_CONTINUING) {
			lwsl_err("%s: %s did not start\n", __func__,
				 sf_names[n]);
			sf_fail++;
			goto destroy;
		}

	lws_sul_schedule(sf_cx, 0, &sul_sf, sul_sf_cb, SF_TICK_US);
	lws_sul_schedule(sf_cx, 0, &sul_sf_deadline, sul_sf_deadline_cb,
			 SF_DEADLINE_US);

	cpu = sf_cpu_us();
	while (lws_service(sf_cx, 0) >= 0)
		;
	cpu = sf_cpu_us() - cpu;

	if (cpu > SF_MAX_CPU_US) {
		lwsl_err("%s: used %dms of cpu, spinning\n", __func__,
			 (int)(cpu / LWS_US_PER_MS));
		sf_fail++;
	}

destroy:
	lws_sul_cancel(&sul_sf);
	lws_sul_cancel(&sul_sf_deadline);
	lws_context_destroy(sf_cx);
	sf_cx = NULL;

restore:
	if (had_saved)
		setenv("LWS_ASYNCDNS_PORT", saved, 1);
	else
		unsetenv("LWS_ASYNCDNS_PORT");

	if (sf_fd >= 0)
		close(sf_fd);
	sf_fd = -1;

	if (sf_fail)
		return;

	if (sf_failed + sf_resolved != (int)LWS_ARRAY_SIZE(sf_names) ||
	    !sf_resolved) {
		lwsl_err("%s: %d failed and %d resolved\n", __func__,
			 sf_failed, sf_resolved);
		sf_fail++;
		return;
	}

	lwsl_user("Resolver send-failure leg: PASS (%d send failed, %dms cpu)\n",
		  sf_failed, (int)(cpu / LWS_US_PER_MS));
}
#endif

#if !defined(WIN32)

/*
 * Forced-family legs (-4 / -6)
 *
 * A client connection with one family disabled at context level, exactly
 * what the -4 / -6 commandline switches produce, must only ask the
 * resolver for the surviving family: the suppressed family's query is
 * never issued.  Each leg stands a fake nameserver up on a loopback UDP
 * socket of our own (never answered, so nothing but the queries
 * themselves is exercised) and counts the qtypes that arrive at it.
 *
 * The control leg forces nothing and must see both A and AAAA, which is
 * what proves the suppression legs are really testing suppression rather
 * than the resolver just not asking for the other family.
 *
 * Only meaningful when both families are in the build.  The -4 / -6 parse
 * check below is not, so it counts its failure here too.
 */

static int ff_fail;

#if defined(LWS_WITH_IPV4) && defined(LWS_WITH_IPV6)

#define FF_TICK_US		(50 * LWS_US_PER_MS)
#define FF_QUIET_TICKS		3	/* no new query = lws asked all it will */
#define FF_DEADLINE_TICKS	120	/* ~6s */

static const char *ff_names[] = {
	"famboth.invalid", "fam4.invalid", "fam6.invalid"
};

static int ff_http_cb(struct lws *wsi, enum lws_callback_reasons reason,
		      void *user, void *in, size_t len)
{
	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols ff_protocols[] = {
	{ "http", ff_http_cb, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static struct lws_context *ff_cx;
static lws_sorted_usec_list_t sul_ff;
static int ff_fd = -1;
static int ff_ticks, ff_quiet, ff_a, ff_aaaa, ff_done;

static void
ff_harvest(void)
{
	for (;;) {
		uint8_t pkt[512];
		size_t qo;
		ssize_t n;

		n = recvfrom(ff_fd, (char *)pkt, sizeof(pkt), 0, NULL, NULL);
		if (n < 12)
			return;

		ff_quiet = 0;

		qo = sc_qtype_ofs(pkt, (size_t)n);
		if (!qo)
			continue;

		switch ((pkt[qo] << 8) | pkt[qo + 1]) {
		case LWS_ADNS_RECORD_A:		ff_a++;		break;
		case LWS_ADNS_RECORD_AAAA:	ff_aaaa++;	break;
		default:	break; /* not family-specific, ignore it */
		}
	}
}

static void
sul_ff_cb(lws_sorted_usec_list_t *s)
{
	(void)s;

	ff_harvest();

	if (++ff_quiet >= FF_QUIET_TICKS || ++ff_ticks >= FF_DEADLINE_TICKS) {
		ff_done = 1;
		lws_default_loop_exit(ff_cx);
	} else
		lws_sul_schedule(ff_cx, 0, &sul_ff, sul_ff_cb, FF_TICK_US);
}

static void
ff_run(int mode) /* 0 = control, 4 = -4, 6 = -6 */
{
	static const char *ff_servers[] = { "127.0.0.1", NULL };
	struct lws_context_creation_info ci;
	struct lws_client_connect_info i;
	char saved[16], portstr[16];
	const char *env;
	uint16_t port = 0;
	int had_saved, idx = mode == 4 ? 1 : mode == 6 ? 2 : 0;
	int bad = 1;

	ff_a = ff_aaaa = ff_ticks = ff_quiet = ff_done = 0;

	lwsl_user("*** forced-family leg (%s)\n",
		  mode == 4 ? "-4" : mode == 6 ? "-6" : "control");

	ff_fd = sc_socket(&port);
	if (ff_fd < 0) {
		lwsl_err("%s: can't make the loopback socket\n", __func__);
		ff_fail++;
		return;
	}

	/* point the resolver's nameserver port at our fake nameserver */

	env = getenv("LWS_ASYNCDNS_PORT");
	had_saved = !!env;
	if (env)
		lws_strncpy(saved, env, sizeof(saved));
	lws_snprintf(portstr, sizeof(portstr), "%u", port);
	setenv("LWS_ASYNCDNS_PORT", portstr, 1);

	lws_context_info_defaults(&ci, NULL);
	ci.port			= CONTEXT_PORT_NO_LISTEN;
	ci.options		= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	if (mode == 4)
		ci.options |= LWS_SERVER_OPTION_DISABLE_IPV6;
	if (mode == 6)
		ci.options |= LWS_SERVER_OPTION_DISABLE_IPV4;
	ci.protocols		= ff_protocols;
	ci.async_dns_servers	= ff_servers;

	ff_cx = lws_create_context(&ci);
	if (!ff_cx) {
		lwsl_err("%s: context create failed\n", __func__);
		ff_fail++;
		goto restore;
	}

	/* only the pinned nameserver, ie, only our own fake one */

	{
		lws_sockaddr46 sa46;
		int index = 0;

		while (!lws_plat_asyncdns_get_server(ff_cx, index++, &sa46))
			lws_async_dns_server_remove(ff_cx, &sa46);
	}

	memset(&i, 0, sizeof(i));
	i.context	= ff_cx;
	i.address	= ff_names[idx];
	i.host		= ff_names[idx];
	i.origin	= ff_names[idx];
	i.port		= 80;
	i.protocol	= "http";
	i.method	= "GET";
	i.path		= "/";

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: client connect did not start\n", __func__);
		ff_fail++;
		goto destroy;
	}

	lws_sul_schedule(ff_cx, 0, &sul_ff, sul_ff_cb, FF_TICK_US);

	while (lws_service(ff_cx, 0) >= 0)
		;

destroy:
	lws_sul_cancel(&sul_ff);
	lws_context_destroy(ff_cx);
	ff_cx = NULL;

restore:
	if (had_saved)
		setenv("LWS_ASYNCDNS_PORT", saved, 1);
	else
		unsetenv("LWS_ASYNCDNS_PORT");

	if (ff_fd >= 0)
		close(ff_fd);
	ff_fd = -1;

	if (ff_fail)
		return;

	/* judge the query qtypes against the forced family */

	if (mode == 4)
		bad = !ff_a || ff_aaaa;
	else if (mode == 6)
		bad = !ff_aaaa || ff_a;
	else
		bad = !ff_a || !ff_aaaa;

	if (bad) {
		lwsl_err("%s: saw %d A and %d AAAA queries in mode %d\n",
			 __func__, ff_a, ff_aaaa, mode);
		ff_fail++;
	} else
		lwsl_user("Forced-family leg (%s): PASS\n",
			  mode == 4 ? "-4" : mode == 6 ? "-6" : "control");
}

#endif /* dual family */

/*
 * The -4 / -6 commandline switches must disable the other family at
 * context level, and giving both must leave -6 in force.  Called last so
 * the log level side-effect of the builtin handler only meets user logs.
 */
static void
ff_parse_check(void)
{
	struct lws_context_creation_info ti;
	const char *a4[] =  { "test", "-4", NULL };
	const char *a6[] =  { "test", "-6", NULL };
	const char *a46[] = { "test", "-4", "-6", NULL };

	lws_context_info_defaults(&ti, NULL);
	lws_cmdline_option_handle_builtin(2, a4, &ti);
	if (!(ti.options & LWS_SERVER_OPTION_DISABLE_IPV6) ||
	     (ti.options & LWS_SERVER_OPTION_DISABLE_IPV4))
		goto bad;

	lws_context_info_defaults(&ti, NULL);
	lws_cmdline_option_handle_builtin(2, a6, &ti);
	if (!(ti.options & LWS_SERVER_OPTION_DISABLE_IPV4) ||
	     (ti.options & LWS_SERVER_OPTION_DISABLE_IPV6))
		goto bad;

	lws_context_info_defaults(&ti, NULL);
	lws_cmdline_option_handle_builtin(3, a46, &ti);
	if (!(ti.options & LWS_SERVER_OPTION_DISABLE_IPV4) ||
	     (ti.options & LWS_SERVER_OPTION_DISABLE_IPV6))
		goto bad;

	lwsl_user("Cmdline -4/-6 parse check: PASS\n");

	return;
bad:
	lwsl_err("%s: -4/-6 switch handling wrong\n", __func__);
	ff_fail++;
}
#endif

struct lws *
cb1(struct lws *wsi_unused, const char *ads, const struct addrinfo *a, int n,
    void *opaque);

static int first = 1;

static void
timeout_cb(lws_sorted_usec_list_t *sul)
{
	lws_default_loop_exit(context);
}

static void
next_test_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_adns_q *q;
	int m;

	lwsl_user("*** Start of subtest %d\n", dtest + 1);
	lwsl_notice("%s: querying %s\n", __func__, adt[dtest].dns_name);

	m = lws_async_dns_query(context, 0,
				adt[dtest].dns_name,
				(adns_query_type_t)adt[dtest].recordtype, cb1, NULL,
				context, &q);
	if (m != LADNS_RET_CONTINUING && m != LADNS_RET_FOUND && m != LADNS_RET_FAILED_WSI_CLOSED) {
		lwsl_err("%s: adns 1: %s failed: %d\n", __func__, adt[dtest].dns_name, m);
		lws_default_loop_exit(context);
	}

	if (adt[dtest].recordtype & LWS_ADNS_SYNTHETIC) {

		lwsl_notice("%s: injecting result\n", __func__);

		if (!strcmp(adt[dtest].dns_name, "c.msn.com")) {
			canned_c_msn_com[0] = (uint8_t)(lws_adns_get_tid(q) >> 8);
			canned_c_msn_com[1] = (uint8_t)lws_adns_get_tid(q);
			lws_adns_parse_udp(lws_adns_get_async_dns(q),
					   canned_c_msn_com,
					   sizeof(canned_c_msn_com), lws_adns_get_server(q));
		}

		if (!strcmp(adt[dtest].dns_name, "assets.msn.com")) {
			canned_assets_msn_com[0] = (uint8_t)(lws_adns_get_tid(q) >> 8);
			canned_assets_msn_com[1] = (uint8_t)lws_adns_get_tid(q);
			lws_adns_parse_udp(lws_adns_get_async_dns(q),
					   canned_assets_msn_com,
					   sizeof(canned_assets_msn_com), lws_adns_get_server(q));
		}

		if (!strcmp(adt[dtest].dns_name, "e28578.d.akamaiedge.net")) {
			canned_e28578_d_akamaiedge_net[0] = (uint8_t)(lws_adns_get_tid(q) >> 8);
			canned_e28578_d_akamaiedge_net[1] = (uint8_t)lws_adns_get_tid(q);
			lws_adns_parse_udp(lws_adns_get_async_dns(q),
					canned_e28578_d_akamaiedge_net,
					   sizeof(canned_e28578_d_akamaiedge_net), lws_adns_get_server(q));
		}
		if (!strcmp(adt[dtest].dns_name, "a-0003.a-msedge.net")) {
			canned_a_0003_a_msedge_net[0] = (uint8_t)(lws_adns_get_tid(q) >> 8);
			canned_a_0003_a_msedge_net[1] = (uint8_t)lws_adns_get_tid(q);
			lws_adns_parse_udp(lws_adns_get_async_dns(q),
					canned_a_0003_a_msedge_net,
					   sizeof(canned_a_0003_a_msedge_net), lws_adns_get_server(q));
		}
		if (first &&
		    !strcmp(adt[dtest].dns_name, "c-msn-com-europe-vip.trafficmanager.net")) {
			first = 0;
			canned_c_msn_com_europe_vip_trafficmanager_net[0] =
					(uint8_t)(lws_adns_get_tid(q) >> 8);
			canned_c_msn_com_europe_vip_trafficmanager_net[1] =
					(uint8_t)lws_adns_get_tid(q);
			lws_adns_parse_udp(lws_adns_get_async_dns(q),
				canned_c_msn_com_europe_vip_trafficmanager_net,
				sizeof(canned_c_msn_com_europe_vip_trafficmanager_net), lws_adns_get_server(q));
		}
		if (!strcmp(adt[dtest].dns_name, "tcp-fallback.libwebsockets.org")) {
			canned_tc_libwebsockets_org[0] = (uint8_t)(lws_adns_get_tid(q) >> 8);
			canned_tc_libwebsockets_org[1] = (uint8_t)lws_adns_get_tid(q);
			lws_adns_parse_udp(lws_adns_get_async_dns(q),
					canned_tc_libwebsockets_org,
					sizeof(canned_tc_libwebsockets_org), lws_adns_get_server(q));
		}
	}
}

struct lws *
cb1(struct lws *wsi_unused, const char *ads, const struct addrinfo *a, int n,
    void *opaque)
{
	const struct addrinfo *ac = a;
#if (_LWS_ENABLED_LOGS & LLL_DEBUG)
	int ctr = 0;
#endif
	int alen = 0;
	uint8_t *addr = NULL;
	char buf[64];

	dtest++;

	if (!ac)
		lwsl_debug("%s: no results\n", __func__);

	/* dump the results */

	while (ac) {
		if (ac->ai_family == AF_INET) {
			addr = (uint8_t *)&(((struct sockaddr_in *)
					ac->ai_addr)->sin_addr.s_addr);
			alen = 4;
		} else {
			addr = (uint8_t *)&(((struct sockaddr_in6 *)
					ac->ai_addr)->sin6_addr.s6_addr);
			alen = 16;
		}
		strcpy(buf, "unknown");
		lws_write_numeric_address(addr, alen, buf, sizeof(buf));

		lwsl_debug("%s: %d: %s %d %s\n", __func__, ctr++, ads, alen, buf);

		ac = ac->ai_next;
	}

	ac = a;
	while (ac) {
		if (ac->ai_family == AF_INET) {
			addr = (uint8_t *)&(((struct sockaddr_in *)
					ac->ai_addr)->sin_addr.s_addr);
			alen = 4;
		} else {
#if defined(LWS_WITH_IPV6)
			addr = (uint8_t *)&(((struct sockaddr_in6 *)
					ac->ai_addr)->sin6_addr.s6_addr);
			alen = 16;
#else
			goto again;
#endif
		}
		if ((adt[dtest - 1].recordtype & TEST_FLAG_NOCHECK_RESULT_IP) ||
		    (alen == adt[dtest - 1].addrlen &&
		    !memcmp(adt[dtest - 1].ads, addr, (unsigned int)alen))) {
			if ((adt[dtest - 1].recordtype & 0xff) == LWS_ADNS_RECORD_SOA) {
				uint16_t pl = 0;
				const uint8_t *s = lws_async_dns_get_rr_cache(
					(struct lws_context *)opaque,
					adt[dtest - 1].dns_name,
					LWS_ADNS_RECORD_SOA, &pl);
				if (!s) {
					lwsl_err("%s: dns test %d: LADNS_RET_FOUND but NO SOA IN CACHE!\n",
						 __func__, dtest);
					goto fail;
				}
				lwsl_notice("%s: API TEST SOA CACHED EXTRACTED FOUND! paylen=%d\n", __func__, (int)pl);
			}
			ok++;
			goto next;
		}
#if !defined(LWS_WITH_IPV6)
again:
#endif
		ac = ac->ai_next;
	}

	/* testing for NXDOMAIN? */

	if (!a && !adt[dtest - 1].addrlen) { if (adt[dtest - 1].recordtype & LWS_ADNS_RECORD_SOA) { uint16_t pl = 0; const uint8_t *s = lws_async_dns_get_rr_cache((struct lws_context *)opaque, adt[dtest - 1].dns_name, LWS_ADNS_RECORD_SOA, &pl); if (!s) { lwsl_err("API TEST SOA MISSING!\n"); goto fail; } lwsl_user("API TEST SOA CACHED EXTRACTED FOUND!\n"); }
		ok++;
		goto next;
	}

fail:
	lwsl_err("%s: dns test %d: no match (expected addrlen %d)\n", __func__, dtest, adt[dtest - 1].addrlen);
	if (adt[dtest - 1].addrlen) {
		lwsl_notice("EXPECTED:\n");
		lwsl_hexdump_notice(adt[dtest - 1].ads, (size_t)adt[dtest - 1].addrlen);
	}
	if (addr) {
		lwsl_notice("ACTUAL (on wire from resolver):\n");
		lwsl_hexdump_notice(addr, (size_t)alen);
	}
	lwsl_user("*** SUBTEST FAILED\n");
	fail++;
	fail_mask |= (1u << (dtest - 1));

next:
	lws_async_dns_freeaddrinfo(&a);
	if (dtest == (int)LWS_ARRAY_SIZE(adt)) {
		lws_default_loop_exit(context);
	} else
		lws_sul_schedule(context, 0, &sul, next_test_cb, 1);

	return NULL;
}

static lws_sorted_usec_list_t sul_l;

struct lws *
cb_loop(struct lws *wsi_unused, const char *ads, const struct addrinfo *a, int n,
		void *opaque)
{
	if (!a) {
		lwsl_err("%s: no results\n", __func__);
		return NULL;
	}

	lwsl_notice("%s: addrinfo %p\n", __func__, a);\
	lws_async_dns_freeaddrinfo(&a);

	return NULL;
}


static void
sul_retry_l(struct lws_sorted_usec_list *sul)
{
	int m;

	lwsl_user("%s: starting new query\n", __func__);

	m = lws_async_dns_query(context, 0, "ml.warmcat.com",
				    (adns_query_type_t)LWS_ADNS_RECORD_A,
				    cb_loop, NULL, context, NULL);
	switch (m) {
	case LADNS_RET_FAILED_WSI_CLOSED:
		lwsl_warn("%s: LADNS_RET_FAILED_WSI_CLOSED "
			  "(== from cache / success in this test)\n", __func__);
		break;
	case LADNS_RET_NXDOMAIN:
		lwsl_warn("%s: LADNS_RET_NXDOMAIN\n", __func__);
		break;
	case LADNS_RET_TIMEDOUT:
		lwsl_warn("%s: LADNS_RET_TIMEDOUT\n", __func__);
		break;
	case LADNS_RET_FAILED:
		lwsl_warn("%s: LADNS_RET_FAILED\n", __func__);
		break;
	case LADNS_RET_FOUND:
		lwsl_warn("%s: LADNS_RET_FOUND\n", __func__);
		break;
	case LADNS_RET_CONTINUING:
		lwsl_warn("%s: LADNS_RET_CONTINUING\n", __func__);
		break;
	}

	lws_sul_schedule(context, 0, &sul_l, sul_retry_l, 5 * LWS_US_PER_SEC);
}

void sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int
fixup(int idx)
{
	struct addrinfo hints, *ai;
	int m;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	m = getaddrinfo(adt[idx].dns_name, "80", &hints, &ai);
	if (m) {
		lwsl_err("Unable to look up %s: %s", adt[0].dns_name,
				gai_strerror(m));
		return 1;
	}
	adt[idx].ads[0] = (uint8_t)((struct sockaddr *)ai->ai_addr)->sa_data[2];
	adt[idx].ads[1] = (uint8_t)((struct sockaddr *)ai->ai_addr)->sa_data[3];
	adt[idx].ads[2] = (uint8_t)((struct sockaddr *)ai->ai_addr)->sa_data[4];
	adt[idx].ads[3] = (uint8_t)((struct sockaddr *)ai->ai_addr)->sa_data[5];

	freeaddrinfo(ai);

	lwsl_notice("%s: %u.%u.%u.%u\n", __func__,
		adt[idx].ads[0], adt[idx].ads[1], adt[idx].ads[2], adt[idx].ads[3]);

	return 0;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	uint8_t mac[6];
	int n = 1;

	lws_context_info_defaults(&info, NULL);lws_cmdline_option_handle_builtin(argc, argv, &info);

	/* the normal lws init */
	(void)switches;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: Async DNS\n");

	static const char *dns[] = { "8.8.8.8", NULL };
	const char *p;

#if !defined(WIN32)
	{
		int fd = open(RESOLV_TEST_CONF, O_CREAT | O_WRONLY | O_TRUNC,
			      0600);

		if (fd < 0) {
			lwsl_err("%s: can't create " RESOLV_TEST_CONF "\n",
					__func__);
			return 1;
		}
		close(fd);

		setenv("LWS_ASYNCDNS_RESOLV_CONF", RESOLV_TEST_CONF, 1);
		setenv("LWS_ASYNCDNS_WATCH_MS", RESOLV_TEST_WATCH_MS, 1);

#if defined(LWS_WITH_SYS_STATE)
		lwsl_user("*** state gate test legs\n");
		gate_do_write = 1;
		gate_hold_release_test();
		gate_do_write = 0;
		gate_giveup_test();
#endif

		/*
		 * C-433: an answer is only taken from the nameserver we asked.
		 * Own context, own fake nameserver on loopback.
		 */

		sc_run(SC_MODE_PLAIN);
		sc_run(SC_MODE_FOREIGN);

		/*
		 * A cache entry whose TTL runs out while its query still
		 * holds it lives until the query is done with it
		 */

		sc_run(SC_MODE_TTL0);

		/*
		 * A failed send on the resolver's socket drops it for a new
		 * one, instead of leaving it to spin the loop
		 */

		sf_run();

		/*
		 * A name with fewer dots than ndots is tried under the
		 * resolv.conf search list, in libc's order
		 */

		{
			int m;

			for (m = 0; m < (int)LWS_ARRAY_SIZE(srch_legs); m++)
				srch_run(&srch_legs[m]);
		}

		/*
		 * Client connects with one family disabled (what -4 / -6
		 * produce) must only ask the resolver for the other family
		 */
#if defined(LWS_WITH_IPV4) && defined(LWS_WITH_IPV6)
		ff_run(0);
		ff_run(4);
		ff_run(6);
#endif

		/* platform server set for the main context's watcher leg */

		fd = open(RESOLV_TEST_CONF, O_WRONLY | O_TRUNC, 0600);
		if (fd < 0) {
			lwsl_err("%s: can't reset " RESOLV_TEST_CONF "\n",
					__func__);
			return 1;
		}
		if (write(fd, "nameserver 127.0.0.1\n", 21) < 0) {
			close(fd);
			return 1;
		}
		close(fd);
	}
#endif

	if ((p = lws_cmdline_option(argc, argv, "-s")))
		dns[0] = p;

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	lws_system_ops_t ops;
	memset(&ops, 0, sizeof ops);
	ops.async_dns_dnssec_mode = LWS_ADNS_DNSSEC_REQUIRE;
	info.system_ops = &ops;
	info.async_dns_servers = dns;
	info.early_smd_cb = smd_dns_cb;
	info.early_smd_class_filter = LWSSMDCL_DNS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (!p) {
		fixup(0);
		fixup(5);
		fixup(6);
	}

	{
		lws_sockaddr46 sa46;
		int index = 0;

		while (!lws_plat_asyncdns_get_server(context, index++, &sa46)) {
			char buf[64];
			lws_sa46_write_numeric_address(&sa46, buf, sizeof(buf));
			lwsl_user("REMOVING SYSTEM DNS: %s\n", buf);
			lws_async_dns_server_remove(context, &sa46);
		}
	}

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_L].sw)) {
		lws_sul_schedule(context, 0, &sul_l, sul_retry_l, LWS_US_PER_SEC);
		goto evloop;
	}


	/* ip address parser tests */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(ipt); n++) {
		uint8_t u[16];
		int m = lws_parse_numeric_address(ipt[n].test, u, sizeof(u));

		if (m != ipt[n].rlen) {
			lwsl_err("%s: fail %s ret %d\n",
					__func__, ipt[n].test, m);
			fail++;
			continue;
		}

		if (m > 0) {
			if (memcmp(ipt[n].b, u, (unsigned int)m)) {
				lwsl_err("%s: fail %s compare\n", __func__,
						ipt[n].test);
				lwsl_hexdump_notice(u, (unsigned int)m);
				fail++;
				continue;
			}
		}
		ok++;
	}

	/* ip address formatter tests */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(ipt); n++) {
		char buf[64];
		int m;

		/* don't attempt to reverse the ones that are meant to fail */
		if (ipt[n].rlen < 0)
			continue;

		m = lws_write_numeric_address(ipt[n].b, ipt[n].rlen, buf,
						sizeof(buf));
		if (m != ipt[n].emit_len) {
			lwsl_err("%s: fail %s ret %d\n",
					__func__, ipt[n].emit_test, m);
			fail++;
			continue;
		}

		if (m > 0) {
			if (strcmp(ipt[n].emit_test, buf)) {
				lwsl_err("%s: fail %s compare\n", __func__,
						ipt[n].test);
				lwsl_hexdump_notice(buf, (unsigned int)m);
				fail++;
				continue;
			}
		}
		ok++;
	}

	/* mac address parser tests */

	if (lws_parse_mac("11:ff:ce:CE:22:33", mac)) {
		lwsl_err("%s: mac fail 1\n", __func__);
		lwsl_hexdump_notice(mac, 6);
		fail++;
	} else
		if (mac[0] != 0x11 || mac[1] != 0xff || mac[2] != 0xce ||
		    mac[3] != 0xce || mac[4] != 0x22 || mac[5] != 0x33) {
			lwsl_err("%s: mac fail 2\n", __func__);
			lwsl_hexdump_notice(mac, 6);
			fail++;
		}
	if (!lws_parse_mac("11:ff:ce:CE:22:3", mac)) {
		lwsl_err("%s: mac fail 3\n", __func__);
		lwsl_hexdump_notice(mac, 6);
		fail++;
	}
	if (!lws_parse_mac("11:ff:ce:CE:22", mac)) {
		lwsl_err("%s: mac fail 4\n", __func__);
		lwsl_hexdump_notice(mac, 6);
		fail++;
	}
	if (!lws_parse_mac("11:ff:ce:CE:22:", mac)) {
		lwsl_err("%s: mac fail 5\n", __func__);
		lwsl_hexdump_notice(mac, 6);
		fail++;
	}
	if (!lws_parse_mac("11:ff:ce:CE22", mac)) {
		lwsl_err("%s: mac fail 6\n", __func__);
		lwsl_hexdump_notice(mac, 6);
		fail++;
	}


	/* kick off the async dns tests */

#if !defined(WIN32)
	lwsl_user("*** watcher test leg\n");
	lws_sul_schedule(context, 0, &sul_watch_leg, sul_watch_leg_cb,
			 100 * LWS_US_PER_MS);
#else
	lws_sul_schedule(context, 0, &sul, next_test_cb, 1);
#endif
	lws_sul_schedule(context, 0, &sul_timeout, timeout_cb, 45 * LWS_USEC_PER_SEC);

evloop:
	/* the usual lws event loop */

	n = 1;
	while (n >= 0)
		n = lws_service(context, 0);

	lws_context_destroy(context);

#if !defined(WIN32)
	unlink(RESOLV_TEST_CONF);
#endif

	_exp += (int)LWS_ARRAY_SIZE(adt);

#if !defined(WIN32)
	ff_parse_check();
#endif

	if (fail || ok != _exp) {
		lwsl_user("Completed: PASS: %d / %d, FAIL: %d\n", ok, _exp,
				fail);
		for (n = 0; n < (int)LWS_ARRAY_SIZE(adt); n++)
			if (fail_mask & (1ul << n))
				lwsl_user("  Subtest %d (%s) failed\n", n + 1, adt[n].dns_name);
	} else
		lwsl_user("Completed: ALL PASS: %d / %d\n", ok, _exp);

#if !defined(WIN32)
	lwsl_user("Watcher leg: %s (%d publications)\n",
		  watch_fail ? "FAIL" : "PASS", watch_msgs);
	lwsl_user("Resolver source-check legs: %s\n", sc_fail ? "FAIL" : "PASS");
	lwsl_user("Forced-family: %s\n", ff_fail ? "FAIL" : "PASS");
	lwsl_user("Resolver send-failure leg: %s\n", sf_fail ? "FAIL" : "PASS");
	lwsl_user("Search list legs: %s\n", srch_fail ? "FAIL" : "PASS");

	return !(ok == _exp && !fail && !watch_fail && !sc_fail && !ff_fail &&
		 !sf_fail && !srch_fail);
#else

	return !(ok == _exp && !fail && !watch_fail);
#endif
}
