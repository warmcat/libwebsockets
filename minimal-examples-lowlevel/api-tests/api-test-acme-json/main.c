/*
 * lws-api-test-acme-json
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 * Note: CC0 1.0 Universal Public Domain Dedication
 *
 * Runs the ACME client plugin's parsers for the ACME server's JSON (see
 * plugins/protocol_lws_acme_client/acme-json.c) on canned responses in the
 * shapes Let's Encrypt answers with, fed both in one piece and a byte at a
 * time, as they can arrive over http, and checks what each one picks out.
 *
 * Covered behaviours:
 *
 *  - the directory's urls are found among members we don't care about
 *  - an order gives its status, authorization and finalize urls
 *  - an authz with several challenges takes up the one of the type the
 *    cert is configured for, dns-01 or http-01, and its url and token
 *  - the answer to starting that challenge is accepted for either type...
 *    it once insisted on http-01, failing every dns-01 acquisition
 *  - ...but an answer about a different type of challenge is refused
 *  - an error body's detail is kept
 *  - a challenge token that is not base64url is refused, but only for the
 *    challenge we take up
 *
 * It also runs the plugin's framing of the root daemon's answers on the IPC
 * stream, fed in one read and a byte at a time:
 *
 *  - two answers arriving in one read are two answers... they were once
 *    counted as one, leaving a save forever outstanding
 *  - a line sent to every client ("cert_status") answers nothing of ours
 *  - a refusal with no "req" (eg, authentication failed) is told apart
 *  - a validity answer gives its days, and a refused save that stores the
 *    cert is flagged
 *  - an overlong line is dropped without losing the line after it
 */

#include <libwebsockets.h>

#include <string.h>

#include "private-acme-client.h"

#define AJT_LE "https://acme-v02.api.letsencrypt.org/acme/"

static const char *ajt_dir =
	"{\n"
	"  \"S0mEraNd0mK3y\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\",\n"
	"  \"keyChange\": \"" AJT_LE "key-change\",\n"
	"  \"meta\": {\n"
	"    \"caaIdentities\": [\n      \"letsencrypt.org\"\n    ],\n"
	"    \"profiles\": {\n"
	"      \"classic\": \"https://letsencrypt.org/docs/profiles#classic\",\n"
	"      \"shortlived\": \"https://letsencrypt.org/docs/profiles#shortlived\"\n"
	"    },\n"
	"    \"termsOfService\": \"https://letsencrypt.org/documents/LE-SA-v1.5-February-24-2025.pdf\",\n"
	"    \"website\": \"https://letsencrypt.org\"\n"
	"  },\n"
	"  \"newAccount\": \"" AJT_LE "new-acct\",\n"
	"  \"newNonce\": \"" AJT_LE "new-nonce\",\n"
	"  \"newOrder\": \"" AJT_LE "new-order\",\n"
	"  \"renewalInfo\": \"https://acme-v02.api.letsencrypt.org/draft-ietf-acme-ari-03/renewalInfo\",\n"
	"  \"revokeCert\": \"" AJT_LE "revoke-cert\"\n"
	"}";

static const char *ajt_order =
	"{\n"
	"  \"status\": \"pending\",\n"
	"  \"expires\": \"2026-10-07T15:42:10Z\",\n"
	"  \"identifiers\": [\n"
	"    {\n      \"type\": \"dns\",\n      \"value\": \"npro.rs\"\n    }\n"
	"  ],\n"
	"  \"profile\": \"classic\",\n"
	"  \"authorizations\": [\n"
	"    \"" AJT_LE "authz/3809481706/790409035666\"\n"
	"  ],\n"
	"  \"finalize\": \"" AJT_LE "finalize/3809481706/452829000123\"\n"
	"}";

static const char *ajt_authz =
	"{\n"
	"  \"identifier\": {\n    \"type\": \"dns\",\n    \"value\": \"npro.rs\"\n  },\n"
	"  \"status\": \"pending\",\n"
	"  \"expires\": \"2026-10-07T15:42:10Z\",\n"
	"  \"challenges\": [\n"
	"    {\n"
	"      \"type\": \"http-01\",\n"
	"      \"url\": \"" AJT_LE "chall/3809481706/790409035666/XrNd8A\",\n"
	"      \"status\": \"pending\",\n"
	"      \"token\": \"http01-token-mBnq0x7GkQ\"\n"
	"    },\n"
	"    {\n"
	"      \"type\": \"dns-01\",\n"
	"      \"url\": \"" AJT_LE "chall/3809481706/790409035666/dLFlkw\",\n"
	"      \"status\": \"pending\",\n"
	"      \"token\": \"Ub6D315kflFKV8LXKceqovfdGeC0hvGNxO-zf9J9GkI\"\n"
	"    },\n"
	"    {\n"
	"      \"type\": \"tls-alpn-01\",\n"
	"      \"url\": \"" AJT_LE "chall/3809481706/790409035666/Qm5wKw\",\n"
	"      \"status\": \"pending\",\n"
	"      \"token\": \"alpn-token-Zp3Lr9\"\n"
	"    }\n"
	"  ]\n"
	"}";

/* exactly what LE answered to starting the dns-01 challenge */
static const char *ajt_chac_dns =
	"{\n"
	"  \"type\": \"dns-01\",\n"
	"  \"url\": \"" AJT_LE "chall/3809481706/790409035666/dLFlkw\",\n"
	"  \"status\": \"pending\",\n"
	"  \"token\": \"Ub6D315kflFKV8LXKceqovfdGeC0hvGNxO-zf9J9GkI\"\n"
	"}";

static const char *ajt_chac_http =
	"{\n"
	"  \"type\": \"http-01\",\n"
	"  \"url\": \"" AJT_LE "chall/3809481706/790409035666/XrNd8A\",\n"
	"  \"status\": \"pending\",\n"
	"  \"token\": \"http01-token-mBnq0x7GkQ\"\n"
	"}";

static const char *ajt_authz_error =
	"{\n"
	"  \"type\": \"urn:ietf:params:acme:error:unauthorized\",\n"
	"  \"detail\": \"Account is not authorized\",\n"
	"  \"status\": 403\n"
	"}";

/*
 * The daemon's answers to a cert fetch saved over IPC, with a line for every
 * client in between, then the answer to an aging check, and a refusal
 */

static const char *ajt_ipc_lines =
	"{\"req\":\"save_cert\",\"status\":\"ok\"}\n"
	"{\"req\":\"save_key\",\"status\":\"error\",\"msg\":\"Could not open file for writing\"}\n"
	"{\"req\":\"cert_status\",\"subdomain\":\"www.npro.rs\",\"port\":443,\"status\":\"ok\",\"msg\":\"\",\"local_msg\":\"\",\"issuer\":\"R11\"}\n"
	"{\"req\":\"save_cert\",\"status\":\"ok\"}\n"
	"{\"req\":\"get_cert_validity\",\"status\":\"ok\",\"days_left\":4,\"total_days\":6}\n"
	"{\"status\":\"error\",\"msg\":\"Authentication Failed\"}\n";

static const struct acme_ipc_reply ajt_ipc_want[] = {
	{ ACME_IPC_LINE_SAVE,		0, 0, 1, 1 },
	{ ACME_IPC_LINE_SAVE,		0, 0, 0, 1 },
	{ ACME_IPC_LINE_UNRELATED,	0, 0, 1, 0 },
	{ ACME_IPC_LINE_SAVE,		0, 0, 1, 1 },
	{ ACME_IPC_LINE_VALIDITY,	4, 6, 1, 0 },
	{ ACME_IPC_LINE_REFUSED,	0, 0, 0, 0 },
};

struct ajt_ipc_got {
	struct acme_ipc_reply	r[LWS_ARRAY_SIZE(ajt_ipc_want) + 1];
	size_t			count;
};

/* the http-01 challenge's token is not base64url */

static const char *ajt_authz_bad_token =
	"{\n"
	"  \"identifier\": {\n    \"type\": \"dns\",\n    \"value\": \"npro.rs\"\n  },\n"
	"  \"status\": \"pending\",\n"
	"  \"challenges\": [\n"
	"    {\n"
	"      \"type\": \"http-01\",\n"
	"      \"url\": \"" AJT_LE "chall/3809481706/790409035666/XrNd8A\",\n"
	"      \"status\": \"pending\",\n"
	"      \"token\": \"not a token\"\n"
	"    },\n"
	"    {\n"
	"      \"type\": \"dns-01\",\n"
	"      \"url\": \"" AJT_LE "chall/3809481706/790409035666/dLFlkw\",\n"
	"      \"status\": \"pending\",\n"
	"      \"token\": \"Ub6D315kflFKV8LXKceqovfdGeC0hvGNxO-zf9J9GkI\"\n"
	"    }\n"
	"  ]\n"
	"}";

static struct per_vhost_data__lws_acme_client vhd;
static struct lws_acme_cert_config cert;
static struct acme_connection ac;
static int fails, oks;

/*
 * Parse json with one of the plugin's parsers, in one piece or a byte at a
 * time.  Returns what lejp_parse() last said: >= 0 for a complete parse.
 */

static int
ajt_parse(lejp_callback cb, void *user, const char * const *paths,
	  unsigned char count_paths, const char *json, int bytewise)
{
	struct lejp_ctx ctx;
	size_t n, len = strlen(json);
	int m = LEJP_CONTINUE;

	lejp_construct(&ctx, cb, user, paths, count_paths);

	if (!bytewise)
		m = lejp_parse(&ctx, (const uint8_t *)json, (int)len);
	else
		for (n = 0; n < len && m == LEJP_CONTINUE; n++)
			m = lejp_parse(&ctx, (const uint8_t *)json + n, 1);

	lejp_destruct(&ctx);

	return m;
}

static int
ajt_expect(const char *what, int bytewise, const char *got, const char *want)
{
	if (!strcmp(got, want))
		return 0;

	lwsl_err("%s (%s): got '%s', want '%s'\n", what,
		 bytewise ? "bytewise" : "whole", got, want);

	return 1;
}

static int
ajt_directory(int bw)
{
	int bad = 0;

	memset(&ac, 0, sizeof(ac));
	if (ajt_parse(acme_cb_dir, &vhd, acme_jdir_tok,
		      LWS_ARRAY_SIZE(acme_jdir_tok), ajt_dir, bw) < 0) {
		lwsl_err("directory (%d): parse failed\n", bw);
		return 1;
	}

	bad |= ajt_expect("newAccount", bw, ac.urls[JAD_NEW_ACCOUNT_URL],
			  AJT_LE "new-acct");
	bad |= ajt_expect("newNonce", bw, ac.urls[JAD_NEW_NONCE_URL],
			  AJT_LE "new-nonce");
	bad |= ajt_expect("newOrder", bw, ac.urls[JAD_NEW_ORDER_URL],
			  AJT_LE "new-order");
	bad |= ajt_expect("termsOfService", bw, ac.urls[JAD_TOS_URL],
			  "https://letsencrypt.org/documents/LE-SA-v1.5-February-24-2025.pdf");

	return bad;
}

static int
ajt_order_(int bw)
{
	int bad = 0;

	memset(&ac, 0, sizeof(ac));
	if (ajt_parse(acme_cb_order, &ac, acme_jorder_tok,
		      LWS_ARRAY_SIZE(acme_jorder_tok), ajt_order, bw) < 0) {
		lwsl_err("order (%d): parse failed\n", bw);
		return 1;
	}

	bad |= ajt_expect("order status", bw, ac.status, "pending");
	bad |= ajt_expect("authorizations", bw, ac.authz_url,
			  AJT_LE "authz/3809481706/790409035666");
	bad |= ajt_expect("finalize", bw, ac.finalize_url,
			  AJT_LE "finalize/3809481706/452829000123");

	return bad;
}

/* authz, then starting the challenge it chose, for one challenge type */

static int
ajt_challenge(lws_acme_challenge_type type, int bw)
{
	int dns = type == LWS_ACME_CHALLENGE_TYPE_DNS_01, bad = 0;
	const char *want_type = dns ? "dns-01" : "http-01";

	memset(&ac, 0, sizeof(ac));
	cert.challenge_type = type;

	if (ajt_parse(acme_cb_authz, &vhd, acme_jauthz_tok,
		      LWS_ARRAY_SIZE(acme_jauthz_tok), ajt_authz, bw) < 0) {
		lwsl_err("authz %s (%d): parse failed\n", want_type, bw);
		return 1;
	}

	bad |= ajt_expect("authz chall type", bw, ac.chall_type, want_type);
	bad |= ajt_expect("authz chall url", bw, ac.challenge_uri, dns ?
			  AJT_LE "chall/3809481706/790409035666/dLFlkw" :
			  AJT_LE "chall/3809481706/790409035666/XrNd8A");
	bad |= ajt_expect("authz chall token", bw, ac.chall_token, dns ?
			  "Ub6D315kflFKV8LXKceqovfdGeC0hvGNxO-zf9J9GkI" :
			  "http01-token-mBnq0x7GkQ");

	/* the answer to starting the challenge we took up is accepted... */

	ac.status[0] = '\0';
	if (ajt_parse(acme_cb_chac, &ac, acme_jchac_tok,
		      LWS_ARRAY_SIZE(acme_jchac_tok),
		      dns ? ajt_chac_dns : ajt_chac_http, bw) < 0) {
		lwsl_err("chall answer %s (%d): refused\n", want_type, bw);
		return 1;
	}
	bad |= ajt_expect("chall status", bw, ac.status, "pending");

	/* ...but one about the other type of challenge is not */

	if (ajt_parse(acme_cb_chac, &ac, acme_jchac_tok,
		      LWS_ARRAY_SIZE(acme_jchac_tok),
		      dns ? ajt_chac_http : ajt_chac_dns, bw) !=
						LEJP_REJECT_CALLBACK) {
		lwsl_err("chall answer for the wrong type accepted (%s, %d)\n",
			 want_type, bw);
		bad = 1;
	}

	return bad;
}

static int
ajt_error(int bw)
{
	memset(&ac, 0, sizeof(ac));
	cert.challenge_type = LWS_ACME_CHALLENGE_TYPE_DNS_01;

	if (ajt_parse(acme_cb_authz, &vhd, acme_jauthz_tok,
		      LWS_ARRAY_SIZE(acme_jauthz_tok), ajt_authz_error, bw) < 0) {
		lwsl_err("authz error body (%d): parse failed\n", bw);
		return 1;
	}

	return ajt_expect("error detail", bw, ac.detail,
			  "Account is not authorized") |
	       ajt_expect("error chall token", bw, ac.chall_token, "");
}

static int
ajt_bad_token(int bw)
{
	int bad = 0;

	/* taking up http-01, its token is refused... */

	memset(&ac, 0, sizeof(ac));
	cert.challenge_type = LWS_ACME_CHALLENGE_TYPE_HTTP_01;
	if (ajt_parse(acme_cb_authz, &vhd, acme_jauthz_tok,
		      LWS_ARRAY_SIZE(acme_jauthz_tok), ajt_authz_bad_token,
		      bw) != LEJP_REJECT_CALLBACK) {
		lwsl_err("bad token (%d): accepted\n", bw);
		bad = 1;
	}
	bad |= ajt_expect("bad token", bw, ac.chall_token, "");

	/* ...but it's nothing to do with us when we take up dns-01 */

	memset(&ac, 0, sizeof(ac));
	cert.challenge_type = LWS_ACME_CHALLENGE_TYPE_DNS_01;
	if (ajt_parse(acme_cb_authz, &vhd, acme_jauthz_tok,
		      LWS_ARRAY_SIZE(acme_jauthz_tok), ajt_authz_bad_token,
		      bw) < 0) {
		lwsl_err("bad token, other type (%d): refused\n", bw);
		return 1;
	}

	return bad | ajt_expect("other token", bw, ac.chall_token,
				"Ub6D315kflFKV8LXKceqovfdGeC0hvGNxO-zf9J9GkI");
}

static int
ajt_ipc_line(void *opaque, const char *line, size_t len)
{
	struct ajt_ipc_got *g = (struct ajt_ipc_got *)opaque;

	if (strlen(line) != len) {
		lwsl_err("ipc line: length %d but NUL at %d\n", (int)len,
			 (int)strlen(line));
		g->count = LWS_ARRAY_SIZE(g->r); /* fails the count check */
		return 1;
	}

	if (g->count < LWS_ARRAY_SIZE(g->r))
		acme_ipc_classify(line, len, &g->r[g->count++]);

	return 0;
}

static int
ajt_ipc(int bw)
{
	struct acme_ipc_rx rx;
	struct ajt_ipc_got g;
	char longline[sizeof(rx.buf) + 64];
	size_t n, len = strlen(ajt_ipc_lines);
	int bad = 0;

	memset(&rx, 0, sizeof(rx));
	memset(&g, 0, sizeof(g));

	/* a line longer than the reassembly buffer, answering nothing */
	memset(longline, 'x', sizeof(longline) - 1);
	longline[sizeof(longline) - 2] = '\n';
	longline[sizeof(longline) - 1] = '\0';
	acme_ipc_rx(&rx, longline, strlen(longline), ajt_ipc_line, &g);

	if (!bw)
		acme_ipc_rx(&rx, ajt_ipc_lines, len, ajt_ipc_line, &g);
	else
		for (n = 0; n < len; n++)
			acme_ipc_rx(&rx, ajt_ipc_lines + n, 1, ajt_ipc_line, &g);

	if (g.count != LWS_ARRAY_SIZE(ajt_ipc_want)) {
		lwsl_err("ipc (%d): %d lines, want %d\n", bw, (int)g.count,
			 (int)LWS_ARRAY_SIZE(ajt_ipc_want));
		return 1;
	}

	for (n = 0; n < g.count; n++) {
		const struct acme_ipc_reply *w = &ajt_ipc_want[n], *r = &g.r[n];

		if (r->type != w->type || r->ok != w->ok ||
		    r->stores_cert != w->stores_cert ||
		    r->days_left != w->days_left ||
		    r->total_days != w->total_days) {
			lwsl_err("ipc (%d): line %d: type %d ok %d cert %d "
				 "days %d/%d, want %d %d %d %d/%d\n", bw, (int)n,
				 r->type, r->ok, r->stores_cert, r->days_left,
				 r->total_days, w->type, w->ok, w->stores_cert,
				 w->days_left, w->total_days);
			bad = 1;
		}
	}

	return bad;
}

static void
ajt_result(const char *name, int bad)
{
	if (bad) {
		lwsl_err("%s: FAIL\n", name);
		fails++;
	} else
		oks++;
}

int
main(int argc, const char **argv)
{
	int bw;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);
	lwsl_user("LWS API selftest: ACME client JSON parsing\n");

	vhd.ac = &ac;
	vhd.active_cert = &cert;

	for (bw = 0; bw < 2; bw++) {
		ajt_result("directory", ajt_directory(bw));
		ajt_result("order", ajt_order_(bw));
		ajt_result("dns-01", ajt_challenge(LWS_ACME_CHALLENGE_TYPE_DNS_01, bw));
		ajt_result("http-01", ajt_challenge(LWS_ACME_CHALLENGE_TYPE_HTTP_01, bw));
		ajt_result("error", ajt_error(bw));
		ajt_result("bad token", ajt_bad_token(bw));
		ajt_result("ipc", ajt_ipc(bw));
	}

	lwsl_user("Completed: PASS: %d, FAIL: %d\n", oks, fails);

	return !(oks && !fails);
}
