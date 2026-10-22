/*
 * lws-api-test-auth-dns-names
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * G-474: the zone parser used to split every line with lws_tokenize(), which
 * silently dropped anything it saw as a delimiter, '*' and '\' among them.
 * So "*.wild" was stored as ".wild", an NS target "*.wild.x." as ".wild.x.",
 * and name_to_wire() encoded the leading empty label as the root label in
 * the middle of the name: the RRs went out as malformed wire names.
 *
 * The plugin is built into this test, which parses zones the way the plugin
 * does and looks at what it would send, and checks that
 *
 *  - a wildcard owner and a wildcard NS target are kept, and go out on the
 *    wire with a '*' leftmost label: in an RR emitted at the wildcard owner,
 *    and in the NS rdata of a referral
 *  - RFC 1035 5.1 escapes (\X, \DDD) in owner names are resolved, and
 *    ';' or parentheses inside a quoted string are not taken as a comment
 *    or a continuation
 *  - zones with a name that would encode an empty label (a leading dot,
 *    "a..b"), or that has a '*' anywhere but as the whole leftmost label, a
 *    label that would need an escape to be written (an escaped '.', space),
 *    a bad \DDD, an overlong label, an escape in rdata, an unsupported
 *    directive or no type are refused at load, with an error naming the
 *    line
 *  - the plugin's name_to_wire() refuses an empty label anywhere but the
 *    root
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>

#define LWS_PLUGIN_STATIC
#include "../../../plugins/protocol_lws_auth_dns/protocol_lws_auth_dns.c"

/* the plugin's protocol, as an application building it in would list it */
static const struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_AUTH_DNS,
	LWS_PROTOCOL_LIST_TERM
};

static int fails;

#if (_LWS_ENABLED_LOGS & LLL_ERR)
static char last_err[512];

static void
emit(int level, const char *line)
{
	if (level == LLL_ERR)
		lws_strncpy(last_err, line, sizeof(last_err));

	lwsl_emit_stderr(level, line);
}
#endif

static int
expect(int cond, const char *what)
{
	if (!cond) {
		lwsl_err("%s: FAILED: %s\n", __func__, what);
		fails++;

		return 1;
	}

	lwsl_user("%s: ok: %s\n", __func__, what);

	return 0;
}

static const char *zone_head =
	"$ORIGIN names.example.\n"
	"$TTL 300\n"
	"@ IN SOA ns.names.example. admin.names.example. (\n"
	"		1 3600 600 86400 300 )\n"
	"@ IN NS ns.names.example.\n"
	"ns IN A 192.0.2.1\n";	/* the next line is line 7 */

static const char *zone_good =
	"*.wild IN A 192.0.2.30\n"
	"*.wild IN TXT \"wild\"\n"
	"w IN NS *.wild.names.example.\n"
	"\\065bc IN A 192.0.2.31\n"
	"x\\-y IN A 192.0.2.32\n"
	"t IN TXT \"semi;colon (and parens)\"\n";

/* *.wild.names.example. on the wire */
static const uint8_t wild_wire[] = {
	1, '*', 4, 'w', 'i', 'l', 'd', 5, 'n', 'a', 'm', 'e', 's',
	7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0
};

static const struct {
	const char	*line;
	const char	*why;
} bad[] = {
	{ ".wild IN A 192.0.2.30\n",		"leading empty label" },
	{ "a..b IN A 192.0.2.30\n",		"empty label inside" },
	{ "w IN NS .wild.names.example.\n",	"NS target leading empty label" },
	{ "w IN NS a..b.names.example.\n",	"NS target empty label inside" },
	{ "a.*.b IN A 192.0.2.30\n",		"'*' not leftmost" },
	{ "a* IN A 192.0.2.30\n",		"'*' not a whole label" },
	{ "w IN NS a.*.names.example.\n",	"NS target '*' not leftmost" },
	{ "a\\.b IN A 192.0.2.30\n",		"escaped '.'" },
	{ "a\\046b IN A 192.0.2.30\n",		"\\DDD '.'" },
	{ "a\\ b IN A 192.0.2.30\n",		"escaped space" },
	{ "a\\25 IN A 192.0.2.30\n",		"\\DDD of two digits" },
	{ "a\\256 IN A 192.0.2.30\n",		"\\DDD over 255" },
	{ "w IN NS a\\.b.names.example.\n",	"escape in rdata" },
	{ "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		" IN A 192.0.2.30\n",		"64-byte label" },
	{ "$INCLUDE other.zone\n",		"unsupported directive" },
	{ "lonely\n",				"no type" },
	{ "x IN -1 A 192.0.2.30\n",		"junk before the type" },
};

static int
parse(struct auth_dns_zone *z, const char *body)
{
	char buf[2048];
	int n;

	n = lws_snprintf(buf, sizeof(buf), "%s%s", zone_head, body);
	memset(z, 0, sizeof(*z));

	return lws_auth_dns_parse_zone_buf(buf, (size_t)n, z);
}

static struct auth_dns_rrset *
find(struct auth_dns_zone *z, const char *name, uint16_t type)
{
	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&z->rrset_list)) {
		struct auth_dns_rrset *rs = lws_container_of(d,
					struct auth_dns_rrset, list);

		if (rs->type == type && !strcmp(rs->name, name))
			return rs;
	} lws_end_foreach_dll(d);

	return NULL;
}

static struct auth_dns_rr *
first_rr(struct auth_dns_rrset *rs)
{
	struct lws_dll2 *d = rs ? lws_dll2_get_head(&rs->rr_list) : NULL;

	return d ? lws_container_of(d, struct auth_dns_rr, list) : NULL;
}

/* is wild_wire[] anywhere in the len bytes at p */

static int
has_wild_wire(const uint8_t *p, size_t len)
{
	size_t n;

	for (n = 0; n + sizeof(wild_wire) <= len; n++)
		if (!memcmp(p + n, wild_wire, sizeof(wild_wire)))
			return 1;

	return 0;
}

static void
test_good(void)
{
	static const char *qn[] = { "foo", "w", "names", "example" };
	struct per_vhost_data__auth_dns vhd;
	struct auth_dns_rrset *rs, *cut;
	struct auth_dns_cache_entry *ce;
	uint8_t q[64], *dbuf, *rp;
	struct auth_dns_rr *rr;
	size_t ql = 0;
	int n;

	memset(&vhd, 0, sizeof(vhd));
	lws_dll2_owner_clear(&vhd.zones);

	ce = calloc(1, sizeof(*ce));
	dbuf = malloc(4096);
	if (!ce || !dbuf) {
		expect(0, "OOM");
		free(ce);
		free(dbuf);

		return;
	}

	n = parse(&ce->zone, zone_good);
	if (expect(!n && !auth_dns_ce_add(&vhd, ce),
		   "zone with wildcard and escaped owners installed")) {
		lws_auth_dns_free_zone(&ce->zone);
		free(ce);
		free(dbuf);

		return;
	}

	rs = find(&ce->zone, "*.wild.names.example.", 1);
	expect(rs && find(&ce->zone, "*.wild.names.example.", 16) &&
	       !find(&ce->zone, ".wild.names.example.", 1),
	       "wildcard owner kept as *.wild");
	expect(!!find(&ce->zone, "abc.names.example.", 1),
	       "\\065bc read as abc");
	expect(!!find(&ce->zone, "x-y.names.example.", 1),
	       "x\\-y read as x-y");

	rr = first_rr(find(&ce->zone, "t.names.example.", 16));
	expect(rr && rr->rdata &&
	       !strcmp(rr->rdata, "semi;colon (and parens)"),
	       "';' and parentheses inside quotes are text");

	rr = first_rr(find(&ce->zone, "w.names.example.", 2));
	expect(rr && rr->wire_rdata_len == sizeof(wild_wire) &&
	       !memcmp(rr->wire_rdata, wild_wire, sizeof(wild_wire)),
	       "wildcard NS target encodes as *.wild");

	/* the A RR at the wildcard owner, as the plugin emits it */

	rp = dbuf;
	n = rs ? auth_dns_emit_rrset(&rp, dbuf, 4096, &ce->zone, rs, 0) : -1;
	expect(n == 1 && lws_ptr_diff_size_t(rp, dbuf) ==
						sizeof(wild_wire) + 10 + 4 &&
	       !memcmp(dbuf, wild_wire, sizeof(wild_wire)) &&
	       lws_ser_ru16be(dbuf + sizeof(wild_wire)) == 1 &&
	       lws_ser_ru16be(dbuf + sizeof(wild_wire) + 8) == 4 &&
	       !memcmp(dbuf + sizeof(wild_wire) + 10, "\xc0\x00\x02\x1e", 4),
	       "A RR at *.wild goes out with a well-formed owner");

	/* a referral to w carries the wildcard NS target well-formed */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(qn); n++) {
		size_t l = strlen(qn[n]);

		q[ql++] = (uint8_t)l;
		memcpy(q + ql, qn[n], l);
		ql += l;
	}
	q[ql++] = 0;
	lws_ser_wu16be(q + ql, 1);
	lws_ser_wu16be(q + ql + 2, 1);
	ql += 4;

	cut = lws_auth_dns_zone_cut(&ce->zone, "foo.w.names.example");
	if (!expect(!!cut, "foo.w is below the cut at w")) {
		memset(dbuf, 0, 12);
		rp = auth_dns_referral(dbuf, dbuf, 4096, 0, q, ql, &ce->zone,
				       &ce->idx, cut, 0, 0);
		expect(rp && lws_ser_ru16be(dbuf + 8) == 1 &&
		       has_wild_wire(dbuf + 12 + ql,
				     lws_ptr_diff_size_t(rp, dbuf + 12 + ql)),
		       "referral NS rdata is *.wild, well-formed");
	}

	auth_dns_ce_destroy(ce);
	free(dbuf);
}

static void
test_bad(void)
{
	struct auth_dns_zone z;
	char what[128];
	size_t n;
	int r;

	for (n = 0; n < LWS_ARRAY_SIZE(bad); n++) {
#if (_LWS_ENABLED_LOGS & LLL_ERR)
		last_err[0] = '\0';
#endif
		r = parse(&z, bad[n].line);
		lws_auth_dns_free_zone(&z);

		lws_snprintf(what, sizeof(what), "refused: %s", bad[n].why);
		expect(r != 0, what);

#if (_LWS_ENABLED_LOGS & LLL_ERR)
		lws_snprintf(what, sizeof(what), "error names line 7: %s",
			     bad[n].why);
		expect(!!strstr(last_err, "line 7:"), what);
#endif
	}
}

static void
test_name_to_wire(void)
{
	uint8_t w[256];
	size_t l;

	l = sizeof(w);
	expect(name_to_wire(".x.", "", w, &l) != 0,
	       "name_to_wire refuses a leading empty label");
	l = sizeof(w);
	expect(name_to_wire("a..x.", "", w, &l) != 0,
	       "name_to_wire refuses an empty label inside");
	l = sizeof(w);
	expect(name_to_wire("x", ".y.", w, &l) != 0,
	       "name_to_wire refuses an empty label from the origin");
	l = sizeof(w);
	expect(!name_to_wire(".", "", w, &l) && l == 1 && !w[0],
	       "name_to_wire encodes the root");
	l = sizeof(w);
	expect(!name_to_wire("*.wild", "names.example.", w, &l) &&
	       l == sizeof(wild_wire) && !memcmp(w, wild_wire, l),
	       "name_to_wire encodes *.wild");
}

int
main(int argc, const char **argv)
{
#if (_LWS_ENABLED_LOGS & LLL_ERR)
	/* the errors are evidence, so none may be held back as spew */
	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLLF_LOG_SPEW_OFF,
			  emit);
#else
	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);
#endif
	lwsl_user("LWS API selftest: %s zone names\n", protocols[0].name);
	(void)argc;
	(void)argv;

	test_good();
	test_bad();
	test_name_to_wire();

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
