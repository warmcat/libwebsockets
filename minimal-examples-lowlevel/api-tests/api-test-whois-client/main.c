/*
 * lws-api-test-whois-client
 *
 * Runs lws_whois_query() against a local fake registry serving canned
 * answers in the shapes real registries use, and checks what the whois
 * client makes of them, and that its results serialize to canonical JSON
 * that lws_whois_json_purify() accepts unchanged.
 *
 * The fake registry also has a domain it takes the query for and then
 * never answers: the query's deadline must fail it.  Finally two of those
 * are left in flight, one connected and one just started, when the context
 * is destroyed: both callers must still hear the query failed.
 *
 * Copyright (c) 2026 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>

#include <signal.h>
#include <string.h>

/*
 * The fake registry writes its answer this many bytes at a time, so the
 * client sees it in pieces, including ones splitting UTF-8 chars
 */
#define WCT_WRITE_CHUNK		5
/* the deadline given to queries the fake registry never answers */
#define WCT_SHORT_DEADLINE_MS	500
/* what the fake registry sits on without answering */
#define WCT_SILENT_DOMAIN	"silent.example"

struct wct_case {
	const char	*domain;
	const char	*answer;

	/* what the whois client should make of it */
	lws_usec_t	creation_date;
	lws_usec_t	expiry_date;
	lws_usec_t	updated_date;
	const char	*nameservers;
	const char	*dnssec;
	const char	*ds_data;

	/* ...and lws_whois_results_to_json() of that */
	const char	*json;
	char		ns_dropped;	/* nameservers[] couldn't hold them all */

	uint32_t	timeout_ms;	/* 0 = the default deadline */
	char		fails;		/* the query must fail */
};

/* 33 chars: seven of them, comma-separated, fit in nameservers[256] */
#define WCT_LONG_NS(_n)		"ns" _n ".long-nameserver-name.example"


static const struct wct_case cases[] = {
	{
		/*
		 * RNIDS (.rs): DD.MM.YYYY local time dates, lowercase key
		 * names, "DNS:" with a "-" where glue would go, "DNSSEC
		 * signed:", and a UTF-8 postal address before the lines we
		 * want
		 */
		"example.rs",
		"% The data in the Whois database are provided by RNIDS\r\n"
		"% All timestamps are given in Serbian local time.\r\n"
		"%\r\n"
		"Domain name: example.rs\r\n"
		"Domain status: Active https://www.rnids.rs/en/domain-name-status-codes#Active\r\n"
		"Domain status: clientUpdateProhibited https://www.rnids.rs/en/domain-name-status-codes#ClientUpdateProhibited\r\n"
		"Registration date: 30.09.2026 14:04:37\r\n"
		"Modification date: 30.09.2026 14:21:13\r\n"
		"Expiration date: 30.09.2029 14:04:37\r\n"
		"Confirmed: 30.09.2026 14:09:48\r\n"
		"Registrar: Example Registrar\r\n"
		"\r\n"
		"\r\n"
		"Registrant: Individual\r\n"
		"\r\n"
		"Technical contact: Example Registrar\r\n"
		"Address: Ulica Milo\xc5\xa1" "a \xc5\xbd" "unji\xc4\x87" "a 1\xc5\xbe, Beograd, Serbia\r\n"
		"Postal Code: 11000\r\n"
		"\r\n"
		"\r\n"
		"DNS: ns1.example.com - \r\n"
		"DNS: ns2.example.rs - 192.0.2.53\r\n"
		"\r\n"
		"\r\n"
		"DNSSEC signed: yes\r\n"
		"\r\n"
		"Whois Timestamp: 30.09.2026 14:21:56\r\n",

		1790777077, 1885471477, 1790778073,
		"ns1.example.com, ns2.example.rs", "yes", "",

		"{\"creation_date\":1790777077,\"expiry_date\":1885471477,"
		"\"updated_date\":1790778073,"
		"\"nameservers\":[\"ns1.example.com\",\"ns2.example.rs\"],"
		"\"dnssec\":\"yes\"}",

		0,

		0, 0
	},
	{
		/*
		 * gTLD registry style: ISO 8601 dates, uppercase nameservers,
		 * DS data, and the last line has no line ending
		 */
		"example.com",
		"   Domain Name: EXAMPLE.COM\r\n"
		"   Registry Domain ID: 2336799_DOMAIN_COM-VRSN\r\n"
		"   Updated Date: 2026-01-16T18:26:50Z\r\n"
		"   Creation Date: 1995-08-14T04:00:00Z\r\n"
		"   Registry Expiry Date: 2026-08-13T04:00:00Z\r\n"
		"   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\r\n"
		"   Name Server: A.IANA-SERVERS.NET\r\n"
		"   Name Server: B.IANA-SERVERS.NET\r\n"
		"   DNSSEC: signedDelegation\r\n"
		"   DNSSEC DS Data: 370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C",

		808372800, 1786593600, 1768588010,
		"A.IANA-SERVERS.NET, B.IANA-SERVERS.NET", "signedDelegation",
		"370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C",

		"{\"creation_date\":808372800,\"expiry_date\":1786593600,"
		"\"updated_date\":1768588010,"
		"\"nameservers\":[\"A.IANA-SERVERS.NET\",\"B.IANA-SERVERS.NET\"],"
		"\"dnssec\":\"signedDelegation\","
		"\"ds_data\":\"370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C\"}",

		0,

		0, 0
	},
	{
		/*
		 * Not UTF-8 at all (Latin-1): lines with bad bytes are
		 * dropped, even a wanted one, but not the lines around them
		 */
		"example.de",
		"Domain: example.de\n"
		"Address: Stra\xdf" "e 1\n"
		"Nserver: ns1.example.de\n"
		"Nserver: ns2.ex\xe4mple.de\n"
		"Nserver: ns3.example.de\n"
		"Created On: 2020-02-29\n"
		"Expiry Date: 28.02.2031\n",

		1582934400, 1930003200, 0,
		"ns1.example.de, ns3.example.de", "", "",

		"{\"creation_date\":1582934400,\"expiry_date\":1930003200,"
		"\"nameservers\":[\"ns1.example.de\",\"ns3.example.de\"]}",

		0,

		0, 0
	},
	{
		/*
		 * The connection is up and the query taken, but the registry
		 * neither answers nor closes: only the deadline ends it
		 */
		WCT_SILENT_DOMAIN, NULL,

		0, 0, 0, NULL, NULL, NULL,

		NULL, 0,

		WCT_SHORT_DEADLINE_MS, 1
	},
	{
		/*
		 * More nameservers than fit in the results: only whole names
		 * are listed, and the rest are reported as left out
		 */
		"manyns.example",
		"Domain Name: manyns.example\r\n"
		"Name Server: " WCT_LONG_NS("01") "\r\n"
		"Name Server: " WCT_LONG_NS("02") "\r\n"
		"Name Server: " WCT_LONG_NS("03") "\r\n"
		"Name Server: " WCT_LONG_NS("04") "\r\n"
		"Name Server: " WCT_LONG_NS("05") "\r\n"
		"Name Server: " WCT_LONG_NS("06") "\r\n"
		"Name Server: " WCT_LONG_NS("07") "\r\n"
		"Name Server: " WCT_LONG_NS("08") "\r\n"
		"Name Server: " WCT_LONG_NS("09") "\r\n",

		0, 0, 0,
		WCT_LONG_NS("01") ", " WCT_LONG_NS("02") ", "
		WCT_LONG_NS("03") ", " WCT_LONG_NS("04") ", "
		WCT_LONG_NS("05") ", " WCT_LONG_NS("06") ", "
		WCT_LONG_NS("07"), "", "",

		"{\"nameservers\":[\"" WCT_LONG_NS("01") "\",\""
		WCT_LONG_NS("02") "\",\"" WCT_LONG_NS("03") "\",\""
		WCT_LONG_NS("04") "\",\"" WCT_LONG_NS("05") "\",\""
		WCT_LONG_NS("06") "\",\"" WCT_LONG_NS("07") "\"]}", 1,

		0, 0
	},
};

struct wct_pss {
	char		query[128];
	size_t		query_len;
	const char	*answer;
	size_t		answer_len;
	size_t		sent;
	char		silent;
};

static struct lws_context *cx;
static lws_sorted_usec_list_t sul_timeout;
static int port = 7043, fails, oks, interrupted, reaped;
static size_t case_idx;

static int
wct_query(const char *domain, uint32_t timeout_ms, lws_whois_cb_t cb);
static void
wct_reap_cb(void *opaque, const struct lws_whois_results *res);

static const struct wct_case *
wct_find_case(const char *domain)
{
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(cases); n++)
		if (!strcmp(cases[n].domain, domain))
			return &cases[n];

	return NULL;
}

/* the fake registry: one query line in, the canned answer out, close */

static int
callback_fake_registry(struct lws *wsi, enum lws_callback_reasons reason,
		       void *user, void *in, size_t len)
{
	struct wct_pss *pss = (struct wct_pss *)user;
	const struct wct_case *c;
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		if (pss->answer || pss->silent)
			break;

		for (n = 0; n < len; n++) {
			char ch = ((const char *)in)[n];

			if (ch == '\n') {
				if (pss->query_len &&
				    pss->query[pss->query_len - 1] == '\r')
					pss->query_len--;
				pss->query[pss->query_len] = '\0';

				c = wct_find_case(pss->query);
				if (!c) {
					lwsl_err("%s: unexpected query '%s'\n",
						 __func__, pss->query);
					fails++;
					return -1;
				}
				if (!c->answer) {
					/* take the query, and sit on it */
					pss->silent = 1;
					if (case_idx != LWS_ARRAY_SIZE(cases))
						break;

					/*
					 * The first of the queries left in
					 * flight is connected: start the
					 * second, and destroy the context
					 * straight away
					 */
					if (wct_query(WCT_SILENT_DOMAIN, 0,
						      wct_reap_cb))
						fails++;
					interrupted = 1;
					lws_cancel_service(cx);
					break;
				}
				pss->answer = c->answer;
				pss->answer_len = strlen(c->answer);
				lws_callback_on_writable(wsi);
				break;
			}

			if (pss->query_len == sizeof(pss->query) - 1)
				return -1;
			pss->query[pss->query_len++] = ch;
		}
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!pss->answer)
			break;

		/* everything already written has drained, we can close */
		if (pss->sent == pss->answer_len)
			return -1;

		n = pss->answer_len - pss->sent;
		if (n > WCT_WRITE_CHUNK)
			n = WCT_WRITE_CHUNK;

		if (lws_write(wsi, (unsigned char *)pss->answer + pss->sent, n,
			      LWS_WRITE_RAW) != (int)n)
			return -1;

		pss->sent += n;
		lws_callback_on_writable(wsi);
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_registry[] = {
	{ "fake-registry", callback_fake_registry, sizeof(struct wct_pss),
	  0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static int
wct_check_str(const char *what, const char *got, const char *want)
{
	if (!strcmp(got, want))
		return 0;

	lwsl_err("%s: %s: %s: got '%s', want '%s'\n", __func__,
		 cases[case_idx].domain, what, got, want);

	return 1;
}

static int
wct_check_date(const char *what, lws_usec_t got, lws_usec_t want)
{
	if (got == want)
		return 0;

	lwsl_err("%s: %s: %s: got %llu, want %llu\n", __func__,
		 cases[case_idx].domain, what, (unsigned long long)got,
		 (unsigned long long)want);

	return 1;
}

static int
wct_check(const struct lws_whois_results *res)
{
	const struct wct_case *c = &cases[case_idx];
	char json[LWS_WHOIS_CANON_MAX + 1], again[LWS_WHOIS_CANON_MAX + 1];
	int bad = 0, problems, n;

	if (c->fails) {
		if (!res)
			return 0;

		lwsl_err("%s: %s: should have failed\n", __func__, c->domain);
		return 1;
	}

	if (!res) {
		lwsl_err("%s: %s: no results\n", __func__, c->domain);
		return 1;
	}

	bad |= wct_check_date("creation_date", res->creation_date,
			      c->creation_date);
	bad |= wct_check_date("expiry_date", res->expiry_date, c->expiry_date);
	bad |= wct_check_date("updated_date", res->updated_date,
			      c->updated_date);
	bad |= wct_check_str("nameservers", res->nameservers, c->nameservers);
	bad |= wct_check_str("dnssec", res->dnssec, c->dnssec);
	bad |= wct_check_str("ds_data", res->ds_data, c->ds_data);
	if (!res->nameservers_dropped != !c->ns_dropped) {
		lwsl_err("%s: %s: nameservers_dropped %d\n", __func__,
			 c->domain, res->nameservers_dropped);
		bad = 1;
	}

	/* ...leaving nameservers out is a problem for the JSON too */
	n = lws_whois_results_to_json(json, sizeof(json), res, &problems);
	if (n < 0 || !problems != !c->ns_dropped) {
		lwsl_err("%s: %s: results_to_json %d, problems %d\n", __func__,
			 c->domain, n, problems);
		return 1;
	}
	bad |= wct_check_str("json", json, c->json);

	/* what we made must pass the purifier unchanged */

	n = lws_whois_json_purify(again, sizeof(again), json, strlen(json),
				  &problems);
	if (n < 0 || problems) {
		lwsl_err("%s: %s: purify %d, problems %d\n", __func__,
			 c->domain, n, problems);
		return 1;
	}
	bad |= wct_check_str("purified json", again, json);

	return bad;
}

static void
wct_next(void);

static void
wct_whois_cb(void *opaque, const struct lws_whois_results *res)
{
	(void)opaque;

	if (wct_check(res))
		fails++;
	else {
		lwsl_user("%s: %s: OK\n", __func__, cases[case_idx].domain);
		oks++;
	}

	case_idx++;
	wct_next();
}

/* the queries in flight when the context is destroyed end up here */

static void
wct_reap_cb(void *opaque, const struct lws_whois_results *res)
{
	(void)opaque;

	if (res) {
		lwsl_err("%s: results from a query that can't have any\n",
			 __func__);
		fails++;
	}

	reaped++;
}

static int
wct_query(const char *domain, uint32_t timeout_ms, lws_whois_cb_t cb)
{
	struct lws_whois_args a;

	memset(&a, 0, sizeof(a));
	a.context	= cx;
	a.domain	= domain;
	a.server	= "127.0.0.1";
	a.port		= (uint16_t)port;
	a.cb		= cb;
	a.timeout_ms	= timeout_ms;

	if (!lws_whois_query(&a))
		return 0;

	lwsl_err("%s: %s: query failed to start\n", __func__, domain);

	return 1;
}

static void
wct_next(void)
{
	if (case_idx == LWS_ARRAY_SIZE(cases)) {
		/*
		 * Leave queries in flight for the context destroy... the
		 * fake registry starts the second and ends the test when it
		 * has this one's query
		 */
		if (wct_query(WCT_SILENT_DOMAIN, 0, wct_reap_cb)) {
			fails++;
			interrupted = 1;
			lws_cancel_service(cx);
		}
		return;
	}

	if (wct_query(cases[case_idx].domain, cases[case_idx].timeout_ms,
		      wct_whois_cb)) {
		fails++;
		interrupted = 1;
		lws_cancel_service(cx);
	}
}

static void
wct_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out on case %d\n", __func__, (int)case_idx);
	fails++;
	interrupted = 1;
	lws_cancel_service(cx);
}

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

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* the listener and both ends of the whois connection */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: whois client\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.port = port;
	info.vhost_name = "fake-registry";
	info.protocols = protocols_registry;
	info.options |= LWS_SERVER_OPTION_ONLY_RAW;
	if (!lws_create_vhost(cx, &info)) {
		lwsl_err("Failed to create fake registry vhost\n");
		fails++;
		goto bail;
	}

	lws_sul_schedule(cx, 0, &sul_timeout, wct_timeout_cb,
			 10 * LWS_US_PER_SEC);

	wct_next();

	while (!interrupted)
		if (lws_service(cx, 0) < 0)
			break;

	lws_sul_cancel(&sul_timeout);

bail:
	lws_context_destroy(cx);

	/* both queries left in flight must have been told they failed */
	if (!fails && reaped != 2) {
		lwsl_err("%s: %d in-flight queries completed at destroy, "
			 "want 2\n", __func__, reaped);
		fails++;
	}

	lwsl_user("Completed: PASS: %d, FAIL: %d\n", oks, fails);

	return !(oks == (int)LWS_ARRAY_SIZE(cases) && !fails);
}
