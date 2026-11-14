/*
 * lws-api-test-captive-dns
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Checks the captive portal's dns, which answers every name with one address.
 *
 * lws_captive_dns_answer() is given queries made here, well-formed and not:
 *
 *  - an A query, or ANY, is answered with the address, with a TTL of 0
 *
 *  - other types, and classes other than IN, are answered with no records
 *
 *  - an EDNS OPT record with the question is accepted, and not echoed
 *
 *  - a name of 255 is answered, one longer isn't, nor are labels over 63,
 *    compressed names, or queries cut short anywhere
 *
 *  - responses, and anything but a single question, aren't answered, and an
 *    opcode other than QUERY is "not implemented"
 *
 *  - no answer is ever more than 16 bytes more than its query, or longer than
 *    the room given for it, for many random datagrams
 *
 * Then lws_captive_dns_start() on 127.0.0.1 and --port is asked over UDP, by
 * a client in the same process, for an A record, and then again once it has
 * been stopped and started again, on the same port at once.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

enum {
	LWS_SW_PORT,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_PORT]	= { "--port",	"UDP port to answer dns queries on" },
	[LWS_SW_HELP]	= { "--help",	"Show this help information" },
};

#define T_A		1
#define T_AAAA		28
#define T_HTTPS		65
#define T_ANY		255
#define C_IN		1
#define C_CH		3

static struct lws_context *cx;
static lws_sorted_usec_list_t sul_timeout;
static int fail, interrupted, port = 5353, asked, answers;
static uint16_t qid;

static void
expect(int cond, const char *what)
{
	if (cond)
		return;

	lwsl_err("%s: FAIL\n", what);
	fail = 1;
}

/* a query for name, a dotted name, or NULL for the root */

static size_t
mkq(uint8_t *b, size_t bl, uint16_t id, uint16_t flags, const char *name,
    uint16_t qtype, uint16_t qclass)
{
	size_t pos = 12;
	const char *dot;
	size_t l;

	if (bl < 12)
		return 0;

	memset(b, 0, 12);
	lws_ser_wu16be(b, id);
	lws_ser_wu16be(b + 2, flags);
	lws_ser_wu16be(b + 4, 1);

	while (name && *name) {
		dot = strchr(name, '.');
		l = dot ? (size_t)(dot - name) : strlen(name);
		if (pos + 1 + l >= bl)
			return 0;
		b[pos++] = (uint8_t)l;
		memcpy(b + pos, name, l);
		pos += l;
		name += l + (dot ? 1 : 0);
	}

	if (pos + 5 > bl)
		return 0;

	b[pos++] = 0;
	lws_ser_wu16be(b + pos, qtype);
	lws_ser_wu16be(b + pos + 2, qclass);

	return pos + 4;
}

static int
is_answer(const uint8_t *r, size_t rl, const uint8_t *q, size_t ql,
	  uint16_t type, const uint8_t *rdata, size_t alen)
{
	/* the id and question come back, then one answer */
	return rl == ql + 12 + alen &&
	       !memcmp(r, q, 2) &&
	       lws_ser_ru16be(r + 2) == (0x8400 | (lws_ser_ru16be(q + 2) &
						    0x0100)) &&
	       lws_ser_ru16be(r + 4) == 1 && lws_ser_ru16be(r + 6) == 1 &&
	       !lws_ser_ru16be(r + 8) && !lws_ser_ru16be(r + 10) &&
	       !memcmp(r + 12, q + 12, ql - 12) &&
	       r[ql] == 0xc0 && r[ql + 1] == 12 &&
	       lws_ser_ru16be(r + ql + 2) == type &&
	       lws_ser_ru16be(r + ql + 4) == C_IN &&
	       !lws_ser_ru32be(r + ql + 6) &&
	       lws_ser_ru16be(r + ql + 10) == alen &&
	       !memcmp(r + ql + 12, rdata, alen);
}

static int
is_nodata(const uint8_t *r, size_t rl, const uint8_t *q, size_t ql)
{
	return rl == ql && !memcmp(r, q, 2) &&
	       lws_ser_ru16be(r + 2) == (0x8400 | (lws_ser_ru16be(q + 2) &
						    0x0100)) &&
	       lws_ser_ru16be(r + 4) == 1 && !lws_ser_ru16be(r + 6) &&
	       !lws_ser_ru16be(r + 8) && !lws_ser_ru16be(r + 10) &&
	       !memcmp(r + 12, q + 12, ql - 12);
}

static void
test_answer(void)
{
	static const uint8_t ap[] = { 192, 168, 4, 1 };
	uint8_t q[600], r[600];
	lws_sockaddr46 ans;
	uint32_t lcg = 12345;
	size_t ql, rl, n;
	int i, bad = 0;

	memset(&ans, 0, sizeof(ans));
	expect(!lws_sa46_parse_numeric_address("192.168.4.1", &ans),
	       "parse answer address");

	/* what a phone asks first */
	ql = mkq(q, sizeof(q), 0x1234, 0x0100, "connectivitycheck.gstatic.com",
		 T_A, C_IN);
	rl = lws_captive_dns_answer(q, ql, &ans, r, sizeof(r));
	expect(is_answer(r, rl, q, ql, T_A, ap, 4), "A answered");

	/* without recursion desired, it's not set in the answer either */
	ql = mkq(q, sizeof(q), 0x1235, 0, "example.com", T_A, C_IN);
	rl = lws_captive_dns_answer(q, ql, &ans, r, sizeof(r));
	expect(is_answer(r, rl, q, ql, T_A, ap, 4), "A answered, no RD");

	ql = mkq(q, sizeof(q), 2, 0x0100, "example.com", T_ANY, C_IN);
	rl = lws_captive_dns_answer(q, ql, &ans, r, sizeof(r));
	expect(is_answer(r, rl, q, ql, T_A, ap, 4), "ANY answered with A");

	ql = mkq(q, sizeof(q), 3, 0x0100, "example.com", T_A, T_ANY);
	rl = lws_captive_dns_answer(q, ql, &ans, r, sizeof(r));
	expect(is_answer(r, rl, q, ql, T_A, ap, 4), "class ANY answered");

	/* the root is a name too */
	ql = mkq(q, sizeof(q), 4, 0x0100, NULL, T_A, C_IN);
	rl = lws_captive_dns_answer(q, ql, &ans, r, sizeof(r));
	expect(is_answer(r, rl, q, ql, T_A, ap, 4), "root answered");

	/* types we have nothing for: no records */
	ql = mkq(q, sizeof(q), 5, 0x0100, "example.com", T_AAAA, C_IN);
	rl = lws_captive_dns_answer(q, ql, &ans, r, sizeof(r));
	expect(is_nodata(r, rl, q, ql), "AAAA has no records");

	ql = mkq(q, sizeof(q), 6, 0x0100, "example.com", T_HTTPS, C_IN);
	rl = lws_captive_dns_answer(q, ql, &ans, r, sizeof(r));
	expect(is_nodata(r, rl, q, ql), "HTTPS has no records");

	ql = mkq(q, sizeof(q), 7, 0x0100, "version.bind", T_A, C_CH);
	rl = lws_captive_dns_answer(q, ql, &ans, r, sizeof(r));
	expect(is_nodata(r, rl, q, ql), "class CH has no records");

	/* an EDNS OPT record after the question isn't echoed */
	ql = mkq(q, sizeof(q), 8, 0x0100, "example.com", T_A, C_IN);
	lws_ser_wu16be(q + 10, 1);
	memcpy(q + ql, "\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00", 11);
	rl = lws_captive_dns_answer(q, ql + 11, &ans, r, sizeof(r));
	lws_ser_wu16be(q + 10, 0); /* it's compared with the question alone */
	expect(is_answer(r, rl, q, ql, T_A, ap, 4), "EDNS OPT not echoed");

	/* the longest name, 255: 3 x 63 labels and one of 61 */
	ql = mkq(q, sizeof(q), 9, 0x0100,
		 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
		 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb."
		 "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc."
		 "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		 T_A, C_IN);
	expect(ql == 12 + 255 + 4, "255 name made");
	rl = lws_captive_dns_answer(q, ql, &ans, r, sizeof(r));
	expect(is_answer(r, rl, q, ql, T_A, ap, 4), "255 name answered");

	/* ... one more and it isn't */
	ql = mkq(q, sizeof(q), 10, 0x0100,
		 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
		 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb."
		 "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc."
		 "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		 T_A, C_IN);
	expect(!lws_captive_dns_answer(q, ql, &ans, r, sizeof(r)),
	       "256 name refused");

	/* a label of 64 has a bit of the label types set */
	ql = mkq(q, sizeof(q), 11, 0x0100,
		 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		 ".com", T_A, C_IN);
	expect(!lws_captive_dns_answer(q, ql, &ans, r, sizeof(r)),
	       "label of 64 refused");

	/* a compressed name, pointing at the header */
	ql = mkq(q, sizeof(q), 12, 0x0100, "a", T_A, C_IN);
	q[14] = 0xc0;
	q[15] = 0;
	expect(!lws_captive_dns_answer(q, ql, &ans, r, sizeof(r)),
	       "compressed name refused");

	/* cut short: in the header, the name, and the type and class */
	ql = mkq(q, sizeof(q), 13, 0x0100, "example.com", T_A, C_IN);
	for (n = 0; n < ql; n++)
		if (lws_captive_dns_answer(q, n, &ans, r, sizeof(r)))
			bad = 1;
	expect(!bad, "cut short refused");
	expect(!!lws_captive_dns_answer(q, ql, &ans, r, sizeof(r)),
	       "whole answered");

	/* not enough room for the answer */
	expect(!lws_captive_dns_answer(q, ql, &ans, r, ql + 15),
	       "too little room refused");
	expect(lws_captive_dns_answer(q, ql, &ans, r, ql + 16) == ql + 16,
	       "just enough room");

	/* a response */
	ql = mkq(q, sizeof(q), 14, 0x8180, "example.com", T_A, C_IN);
	expect(!lws_captive_dns_answer(q, ql, &ans, r, sizeof(r)),
	       "response not answered");

	/* other than one question */
	ql = mkq(q, sizeof(q), 15, 0x0100, "example.com", T_A, C_IN);
	lws_ser_wu16be(q + 4, 2);
	expect(!lws_captive_dns_answer(q, ql, &ans, r, sizeof(r)),
	       "two questions refused");
	lws_ser_wu16be(q + 4, 0);
	expect(!lws_captive_dns_answer(q, ql, &ans, r, sizeof(r)),
	       "no question refused");
	lws_ser_wu16be(q + 4, 1);
	lws_ser_wu16be(q + 6, 1);
	expect(!lws_captive_dns_answer(q, ql, &ans, r, sizeof(r)),
	       "question with an answer refused");

	/* opcode 2, STATUS, isn't implemented */
	ql = mkq(q, sizeof(q), 0xbeef, (2 << 11) | 0x0100, "example.com",
		 T_A, C_IN);
	rl = lws_captive_dns_answer(q, ql, &ans, r, sizeof(r));
	expect(rl == 12 && lws_ser_ru16be(r) == 0xbeef &&
	       lws_ser_ru16be(r + 2) == (0x8000 | (2 << 11) | 0x0100 | 4) &&
	       !lws_ser_ru16be(r + 4) && !lws_ser_ru16be(r + 6),
	       "opcode not implemented");

#if defined(LWS_WITH_IPV6)
	{
		static const uint8_t ap6[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0,
						 0, 0, 0, 0, 0, 0, 0, 1 };
		lws_sockaddr46 ans6;

		memset(&ans6, 0, sizeof(ans6));
		expect(!lws_sa46_parse_numeric_address("fd00::1", &ans6),
		       "parse v6 answer address");

		ql = mkq(q, sizeof(q), 16, 0x0100, "example.com", T_AAAA, C_IN);
		rl = lws_captive_dns_answer(q, ql, &ans6, r, sizeof(r));
		expect(is_answer(r, rl, q, ql, T_AAAA, ap6, 16),
		       "AAAA answered for a v6 address");

		ql = mkq(q, sizeof(q), 17, 0x0100, "example.com", T_A, C_IN);
		rl = lws_captive_dns_answer(q, ql, &ans6, r, sizeof(r));
		expect(is_nodata(r, rl, q, ql), "A has no records for v6");
	}
#endif

	/*
	 * Random datagrams, many of them starting like a query: whatever comes
	 * back is never more than 16 more than came, nor more than the room
	 */
	for (i = 0; i < 200000; i++) {
		size_t room;

		lcg = lcg * 1103515245u + 12345u;
		ql = (lcg >> 8) % 300;
		for (n = 0; n < ql; n++) {
			lcg = lcg * 1103515245u + 12345u;
			q[n] = (uint8_t)(lcg >> 16);
			/* mostly short labels, so names often end in time */
			if (n >= 12 && (lcg & 0x300))
				q[n] &= 0x0f;
		}
		if (ql >= 12 && (i & 1)) {
			q[2] &= 0x07;	/* a QUERY, not a response */
			q[4] = 0;
			q[5] = 1;	/* one question */
			q[6] = q[7] = q[8] = q[9] = 0;
		}
		room = (i & 2) ? sizeof(r) : (size_t)(lcg % 64);

		rl = lws_captive_dns_answer(q, ql, &ans, r, room);
		if (rl > ql + 16 || rl > room)
			bad = 1;
		if (rl)
			answers++;
	}
	expect(!bad, "random datagrams");
	lwsl_user("%d of the random datagrams were answered\n", answers);
	expect(answers > 1000, "random datagrams answered sometimes");
	answers = 0;
}

/*
 * Over UDP: a client in the same process asks the captive dns we start
 */

static uint8_t qbuf[LWS_PRE + 64];
static size_t qlen;

static void
timed_out(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: no answer\n", __func__);
	fail = 1;
	interrupted = 1;
	lws_cancel_service(cx);
}

static int
ask(void)
{
	struct lws *wsi;

	qid++;
	qlen = mkq(qbuf + LWS_PRE, sizeof(qbuf) - LWS_PRE, qid, 0x0100,
		   "detectportal.firefox.com", T_A, C_IN);

	wsi = lws_create_adopt_udp(lws_get_vhost_by_name(cx, "default"),
				   "127.0.0.1", port, 0, "dns-client", NULL,
				   NULL, NULL, NULL, "dns-client");
	if (!wsi) {
		lwsl_err("%s: unable to make client\n", __func__);
		return 1;
	}

	lws_sul_schedule(cx, 0, &sul_timeout, timed_out, 3 * LWS_US_PER_SEC);

	return 0;
}

static int
callback_client(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	static const uint8_t lo[] = { 127, 0, 0, 1 };

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (asked == answers + 1)
			break;
		asked++;
		if (lws_write(wsi, qbuf + LWS_PRE, qlen, LWS_WRITE_RAW) !=
								(int)qlen)
			return -1;
		break;

	case LWS_CALLBACK_RAW_RX:
		lws_sul_cancel(&sul_timeout);
		expect(is_answer((const uint8_t *)in, len, qbuf + LWS_PRE, qlen,
				 T_A, lo, 4), "answered over UDP");
		answers++;
		lwsl_user("answer %d over UDP\n", answers);

		if (answers == 1) {
			/* again, once it has been stopped and started */
			lws_captive_dns_stop(cx);
			expect(!lws_captive_dns_start(cx, "127.0.0.1", port),
			       "restart on the same port");
			if (ask())
				fail = interrupted = 1;
		} else
			interrupted = 1;

		return -1; /* this client is done */

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "dns-client", callback_client, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	signal(SIGINT, sigint_handler);
	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);
	lwsl_user("LWS API Test - captive dns\n");

	p = lws_cmdline_option(argc, argv, switches[LWS_SW_PORT].sw);
	if (p)
		port = atoi(p);

	test_answer();

	memset(&info, 0, sizeof(info));
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_CPD_BYPASS;
	info.protocols = protocols;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	expect(lws_captive_dns_start(cx, "not-an-address", port) != 0,
	       "a name refused");
	expect(lws_captive_dns_start(cx, "127.0.0.1", port) == 0, "start");

	if (!fail && !ask()) {
		n = 0;
		while (n >= 0 && !interrupted)
			n = lws_service(cx, 0);
	} else
		fail = 1;

	expect(answers == 2, "both answered over UDP");

	lws_sul_cancel(&sul_timeout);
	lws_captive_dns_stop(cx);
	lws_context_destroy(cx);

	lwsl_user("Completed: %s\n", fail ? "FAIL" : "PASS");

	return fail;
}
