/*
 * lws-api-test-lws-login-bff
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * PURPOSE
 *
 * End-to-end test of lws-login's background BFF renewal endpoint
 * (.lws-login-refresh), focussing on how it treats the auth_csrf sidecar
 * cookie that pairs with auth_refresh_session.
 *
 * The side-channel exchange POSTs csrf_token=<csrf> alongside the browser's
 * forwarded cookie jar to the auth server /api/sso_exchange, which
 * double-submits the form field against the auth_csrf cookie in that jar.
 * The incident class this guards against: the jar's auth_csrf expires or is
 * lost while auth_refresh_session lives on (they are minted by different
 * flows -- a native login on the auth server's own host plants an unpaired
 * Domain-scoped refresh cookie), and the renewal used to be denied with 401.
 * The login widget maps any 401 to "session dead" and answers by navigating
 * the whole page to the auth form, trashing whatever the user was doing.
 *
 * Scenarios:
 *
 *  - "paired-jar": both cookies present -> renewal runs, 200 + rotated
 *    auth_session / auth_csrf cookies;
 *
 *  - "self-heal": only auth_refresh_session present -> the BFF mints the
 *    double-submit pair for the side channel itself, the exchange succeeds
 *    and the response rotates fresh cookies.  The mock auth server asserts
 *    the minted pair really did arrive matching, so the self-heal cannot
 *    regress into submitting an inconsistent pair;
 *
 *  - "anonymous": no auth cookies at all -> still denied with 401 (an
 *    anonymous visitor's renewal probe must never start an exchange).
 *
 * plus /.lws-login-sso scenarios exercising the origin/referer CSRF gate
 * around the cross-domain SSO form POST (F-020):
 *
 *  - "sso-nohdrs": validly-signed token POSTed with neither Origin nor
 *    Referer (sandboxed iframe + no-referrer suppresses both) -> must be
 *    rejected 403 with nothing planted, not accepted as the browser's
 *    session;
 *
 *  - "sso-origin-null": same but with the literal "Origin: null" a
 *    sandboxed iframe sends;
 *
 *  - "sso-origin-good": Origin matching auth-server-url scheme+host+port,
 *    exactly like the auth server's auto-submitting form -> 302 and the
 *    submitted token planted as auth_session (positive control);
 *
 *  - "sso-origin-evil": Origin naming anything else -> 403, nothing
 *    planted;
 *
 *  - "sso-referer-good": no Origin, Referer on the auth server origin ->
 *    302 and planted (the fallback legitimate UAs without Origin use).
 *
 * plus a widget-JS render-boundary fence scenario (F-021):
 *
 *  - "widget-js-fence": GET /lws-login.js and check the served bytes carry
 *    the escaping fence -- every dynamic string the widget composes into
 *    innerHTML must go through window.lwsLoginEsc() (the device-provided
 *    preauth strings reaching the admin's page over WS are
 *    unauthenticated-attacker-controlled), and the device_code query value
 *    must be encodeURIComponent'd.  Asserting against the served bytes (not
 *    the C source) keeps the fence honest about what deployments get.
 *
 * plus an F-022 Set-Cookie attribute-tail fence, applied to every scenario
 * that mints cookies: the SSO token is deliberately minted near the
 * LWS_SSO_MAX_COOKIE cap, so composing its auth_session cookie runs the
 * plugin's buffer math at the limit -- any Set-Cookie frag carrying one of
 * the session cookies must keep its complete HttpOnly / SameSite / Secure
 * tail, never a silently truncated remainder.
 *
 * The app vhost runs the real lws-login plugin (builtin plugins build) with
 * lws_login_client enabled on the same vhost as the side channel requires,
 * against an in-process mock auth server.  Ports come from the CI port
 * allocator; the plugin's sqlite db-path points into the build dir.
 */

#include <libwebsockets.h>

#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>

/* -------------------------------------------------------------- scenarios */

struct scenario {
	const char	*name;
	const char	*path;		/* request path */
	const char	*body;		/* urlencoded body, NULL for bodyless */
	const char	*origin;	/* Origin: value, NULL = header absent */
	const char	*referer;	/* Referer: value, NULL = header absent */
	const char	*cookie;	/* Cookie: header to send, NULL for none */
	unsigned	expect_status;
	int		expect_pair;	/* mock must see a matching csrf pair */
	int		expect_rotate;	/* response must rotate the auth cookies */
	int		expect_sso;	/* /.lws-login-sso outcome: 1 = must plant
					 * the submitted token as auth_session,
					 * -1 = must plant nothing, 0 = n/a */
	const char	*method;	/* "POST" (as before) or "GET" */
	int		expect_js;	/* 1 = response body is lws-login.js and
					 * must carry the F-021 render-boundary
					 * escaping fence */
};

/* minted in main() once the context and allocated ports exist */
static char	minted_jwt[LWS_SSO_MAX_COOKIE];
static char	sso_body[LWS_SSO_MAX_COOKIE * 3 + 64];
static char	o_origin_good[64], o_origin_evil[64], o_referer_good[64];

/*
 * Throwaway P-256 keypair: parsed by the plugin at init to validate tokens,
 * and by the test to MINT them (it carries the private member), so the SSO
 * scenarios' tokens are genuinely validly-signed and exercise only the
 * origin/referer gate.
 */
static const char jwk_json[] =
	"{\"crv\":\"P-256\",\"d\":\"D4EjZm33VsKBwIO2_BXL-GRKuQpn65wDo0a9Tc7TdMI\",\"kty\":\"EC\",\"x\":\"M_5UuNbZp2RGuV_6_us0qstvioPr4nd6d_FU0dTfsBc\",\"y\":\"2hmXygj6XfChnLtCtLeLO1y8OOWWLRYzabvjBUVVbJk\"}";

static const struct scenario scenarios[] = {
	{ "paired-jar", "/.lws-login-refresh", NULL, NULL, NULL,
	  "auth_refresh_session=0123456789abcdef0123456789abcdef; "
	  "auth_csrf=fedcba9876543210fedcba9876543210", 200u, 1, 1, 0,
	  "POST", 0 },
	{ "self-heal", "/.lws-login-refresh", NULL, NULL, NULL,
	  "auth_refresh_session=0123456789abcdef0123456789abcdef", 200u, 1, 1, 0,
	  "POST", 0 },
	{ "anonymous", "/.lws-login-refresh", NULL, NULL, NULL, NULL, 401u, 0, 0, 0,
	  "POST", 0 },

	/* F-027: an auth_session cookie holding a compact JWT whose JOSE
	 * header has no "alg" member must be cleanly rejected by the
	 * per-request session gate, not kill the server process */
	{ "alg-less-session-jwt", "/", NULL, NULL, NULL,
	  "auth_session=eyJ0eXAiOiJKV1QifQ.e30.AQ", 303u, 0, 0, 0, "GET", 0 },

	/* F-020: the token below is genuinely signed by the plugin's own JWK
	 * (the throwaway key carries its private member), so these scenarios
	 * exercise the origin/referer gate and nothing else */
	{ "sso-nohdrs", "/.lws-login-sso", sso_body, NULL, NULL, NULL,
	  403u, 0, 0, -1, "POST", 0 },
	{ "sso-origin-null", "/.lws-login-sso", sso_body, "null", NULL, NULL,
	  403u, 0, 0, -1, "POST", 0 },
	{ "sso-origin-good", "/.lws-login-sso", sso_body, o_origin_good, NULL,
	  NULL, 302u, 0, 0, 1, "POST", 0 },
	{ "sso-origin-evil", "/.lws-login-sso", sso_body, o_origin_evil, NULL,
	  NULL, 403u, 0, 0, -1, "POST", 0 },
	{ "sso-referer-good", "/.lws-login-sso", sso_body, NULL, o_referer_good,
	  NULL, 302u, 0, 0, 1, "POST", 0 },

	/* F-021: the widget JS served to (admin) pages must HTML-escape every
	 * dynamic string at its innerHTML render boundary */
	{ "widget-js-fence", "/lws-login.js", NULL, NULL, NULL, NULL, 200u, 0, 0,
	  0, "GET", 1 },
};

#define N_SCENARIOS  (int)LWS_ARRAY_SIZE(scenarios)

/* -------------------------------------------------------------- globals */

static struct lws_context *context;
static volatile sig_atomic_t interrupted;

static int	g_port_app, g_port_auth;
static struct lws_vhost *g_vh_cli;

static int	step;
static int	step_done;		/* 1 = completed, -1 = failed */

/* Captured from the response headers of the step in flight. */
static unsigned	got_status;
/* joined (frag-chain) copy must hold the planted long-token session cookie */
static char	got_sc[LWS_SSO_MAX_COOKIE + 512];

/*
 * F-022 probe state: every Set-Cookie header frag the client parsed, so the
 * attribute-tail fence can look at each cookie the plugin minted on its own
 * (a truncated first cookie must not hide behind an intact second one in the
 * joined copy).
 */
#define MAX_SC_FRAGS	8
#define SC_FRAG_SZ	(LWS_SSO_MAX_COOKIE + 64)
static char	got_sc_frags[MAX_SC_FRAGS][SC_FRAG_SZ];
static int	got_sc_nfrags;

/* Captured from the response body of the step in flight (widget-js fence). */
static char	got_body[32768];
static size_t	got_body_len;
static int	got_body_trunc;

/* Captured by the mock auth server from the side-channel exchange. */
static int	mock_hits, mock_got_refresh, mock_pair_ok;

static int	tests, fail;
static volatile sig_atomic_t sequence_done;
static struct lws	*current_wsi;
static int	result = 1;		/* 0 = PASS (api-test idiom) */

/* ------------------------------------------------------- mock auth server */

struct pss_auth {
	lws_sorted_usec_list_t sul_resp;
	struct lws	*wsi;
	char		body[256];
	size_t		body_len;
};

#define MOCK_TOKEN_JSON "{\"token\":\"apitest.refreshed.jwt\"}"

/*
 * The response is written from its own sul callback a few ms after the POST
 * body completed: answering inline from BODY_COMPLETION can leave the
 * client-side response bytes buffered but never surfaced in some
 * interleavings.
 */
static void
sul_respond_cb(lws_sorted_usec_list_t *sul)
{
	struct pss_auth *pss = lws_container_of(sul, struct pss_auth, sul_resp);
	struct lws *wsi = pss->wsi;
	uint8_t buf[LWS_PRE + 256], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	size_t blen = strlen(MOCK_TOKEN_JSON);

	if (!wsi)
		return;

	if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
					"application/json", (lws_filepos_t)blen,
					&p, end) ||
	    lws_finalize_http_header(wsi, &p, end))
		return;

	memcpy(p, MOCK_TOKEN_JSON, blen);
	p += blen;

	if (lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
		      LWS_WRITE_HTTP_HEADERS) < 0)
		return;

	if (lws_http_transaction_completed(wsi))
		lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
				   "mock tx done");
}

static int
callback_authmock(struct lws *wsi, enum lws_callback_reasons reason,
		  void *user, void *in, size_t len)
{
	struct pss_auth *pss = (struct pss_auth *)user;
	const char *uri;

	switch (reason) {

	case LWS_CALLBACK_HTTP:
		pss->wsi = wsi;
		/* Normalize the URI to begin with '/' (lws strips it, since
		 * the mount is at "/") */
		uri = (const char *)in;
		if (uri && uri[0] != '/') {
			static char normalized[128];

			lws_snprintf(normalized, sizeof(normalized), "/%s", uri);
			uri = normalized;
		}

		if (!uri || strcmp(uri, "/api/sso_exchange")) {
			lwsl_err("%s: mock auth: unexpected uri '%s'\n",
				 __func__, uri ? uri : "(null)");
			return 1;
		}
		/* wait for the POST body, then answer from a later pass */
		lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT, 10);
		return 0;

	case LWS_CALLBACK_HTTP_BODY:
		if (pss->body_len + len < sizeof(pss->body)) {
			memcpy(pss->body + pss->body_len, in, len);
			pss->body_len += len;
		} else {
			lwsl_err("%s: mock auth: body too large\n", __func__);
			return 1;
		}
		return 0;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION: {
		/*
		 * This is the auth server's csrf double-submit check: the
		 * csrf_token= form field must match the auth_csrf cookie in
		 * the (forwarded) jar.  The side channel always posts exactly
		 * "csrf_token=<csrf>" as the whole body.
		 */
		char csrf_ck[64] = {0};
		size_t csrf_ck_len = sizeof(csrf_ck);
		char refresh[128] = {0};
		size_t refresh_len = sizeof(refresh);
		int got_cookie_csrf;

		mock_hits++;
		mock_got_refresh =
			lws_http_cookie_get(wsi, "auth_refresh_session",
					    refresh, &refresh_len) == 0 &&
			refresh[0];
		got_cookie_csrf =
			lws_http_cookie_get(wsi, "auth_csrf",
					    csrf_ck, &csrf_ck_len) == 0 &&
			csrf_ck[0];

		mock_pair_ok = 0;
		if (got_cookie_csrf && mock_got_refresh) {
			/*
			 * The side channel posts exactly
			 * "csrf_token=<cookie value>" as the whole body; a
			 * strict full-body comparison catches any drift from
			 * that contract.
			 */
			size_t expect_len = sizeof("csrf_token=") - 1 +
							strlen(csrf_ck);

			mock_pair_ok = pss->body_len == expect_len &&
				!memcmp(pss->body, "csrf_token=",
					sizeof("csrf_token=") - 1) &&
				!lws_timingsafe_bcmp(csrf_ck,
					pss->body + sizeof("csrf_token=") - 1,
					(uint32_t)strlen(csrf_ck));
		}

		lwsl_notice("%s: mock exchange validated: refresh=%d "
			    "pair=%d\n", __func__, mock_got_refresh,
			    mock_pair_ok);

		lws_sul_schedule(lws_get_context(wsi), 0, &pss->sul_resp,
				 sul_respond_cb, 10 * LWS_US_PER_MS);
		return 0;
	}

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* ---------------------------------------------------------------- client */

static void
step_advance(void);

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	/*
	 * Ignore callbacks from any wsi that isn't the in-flight step's wsi:
	 * the plugin's own outgoing /api/sso_exchange client connection runs
	 * concurrently under its own protocol on the app vhost.  A genuine
	 * step failure always arrives on the step's own wsi, which i.pwsi
	 * parked in current_wsi.
	 */
	if (wsi != current_wsi)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in;
		unsigned char *end = (*p) + len;

		if (scenarios[step].body) {
			/*
			 * The auth server's auto-submitting SSO form: a real
			 * urlencoded body carrying the token, sized honestly.
			 */
			char cl[16];

			lws_snprintf(cl, sizeof(cl), "%d",
				     (int)strlen(scenarios[step].body));
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_TYPE,
					(const unsigned char *)"application/x-www-form-urlencoded",
					33, p, end) ||
			    lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_LENGTH,
					(const unsigned char *)cl,
					(int)strlen(cl), p, end))
				return -1;

			lws_client_http_body_pending(wsi, 1);
			lws_callback_on_writable(wsi);
		} else if (!scenarios[step].method ||
			   strcmp(scenarios[step].method, "GET")) {
			/*
			 * A bodyless POST, exactly like the widget's fetch():
			 * the plugin answers from the request headers alone
			 * (it suspends the wsi against the side channel), and
			 * a request body would interact with that suspension.
			 */
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_TYPE,
					(const unsigned char *)"application/x-www-form-urlencoded",
					33, p, end) ||
			    lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_LENGTH,
					(const unsigned char *)"0", 1, p, end))
				return -1;
		}
		/* GET: no body-shape headers at all */

		/*
		 * On SSO scenarios the Origin/Referer pair must be exactly
		 * what the scenario says, including both-absent (the filed
		 * F-020 vector); lws synthesizes "Origin: http://<origin>"
		 * from connect-info .origin on POSTs, so the driver leaves
		 * that NULL on SSO paths and the headers are added here
		 * instead, under the test's sole control.
		 */
		if (scenarios[step].origin &&
		    lws_add_http_header_by_token(wsi, WSI_TOKEN_ORIGIN,
				(const unsigned char *)scenarios[step].origin,
				(int)strlen(scenarios[step].origin), p, end))
			return -1;

		if (scenarios[step].referer &&
		    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_REFERER,
				(const unsigned char *)scenarios[step].referer,
				(int)strlen(scenarios[step].referer), p, end))
			return -1;

		if (scenarios[step].cookie &&
		    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_COOKIE,
				(const unsigned char *)scenarios[step].cookie,
				(int)strlen(scenarios[step].cookie), p, end))
			return -1;
		break;
	}

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE: {
		const char *body = scenarios[step].body;
		uint8_t buf[LWS_PRE + sizeof(sso_body)], *start = &buf[LWS_PRE];
		size_t blen;

		if (!body)
			return 0;

		blen = strlen(body);
		memcpy(start, body, blen);
		lws_client_http_body_pending(wsi, 0);

		/* single-part body: this write is also the stream end */
		if (lws_write(wsi, start, blen, LWS_WRITE_HTTP_FINAL) < 0)
			return -1;
		break;
	}

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		lwsl_notice("%s: scenario '%s': response %d\n", __func__,
			    scenarios[step].name,
			    (int)lws_http_client_http_response(wsi));

	got_status = lws_http_client_http_response(wsi);
	got_sc[0] = '\0';
	if (lws_hdr_copy(wsi, got_sc, sizeof(got_sc),
			 WSI_TOKEN_HTTP_SET_COOKIE) < 0)
		got_sc[0] = '\0';

	/* ... and every Set-Cookie frag, for the F-022 attribute-tail fence */
	got_sc_nfrags = 0;
	while (got_sc_nfrags < MAX_SC_FRAGS &&
	       lws_hdr_copy_fragment(wsi, got_sc_frags[got_sc_nfrags],
				      SC_FRAG_SZ, WSI_TOKEN_HTTP_SET_COOKIE,
				      got_sc_nfrags) >= 0) {
		got_sc_nfrags++;
	}

		if (scenarios[step].expect_js) {
			/*
			 * The body (the served lws-login.js) is what the
			 * fence scenario asserts on: keep the connection and
			 * drain it via RECEIVE_CLIENT_HTTP(_READ).
			 */
			got_body_len = 0;
			got_body_trunc = 0;
			break;
		}

		/* headers are all we came for */
		if (!step_done)
			step_done = 1;
		step_advance();

		return -1;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP: {
		char abuf[LWS_PRE + 2048], *px = abuf + LWS_PRE;
		int alen = (int)sizeof(abuf) - LWS_PRE;

		/* h1 requires the callback to pull the body itself (h2 mux
		 * delivers RECEIVE_CLIENT_HTTP_READ directly) */
		if (lws_http_client_read(wsi, &px, &alen) < 0)
			return -1;
		break;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (got_body_len + len < sizeof(got_body)) {
			memcpy(got_body + got_body_len, in, len);
			got_body_len += len;
		} else
			got_body_trunc = 1;
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (!step_done)
			step_done = 1;
		step_advance();
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!step_done)
			step_done = 1;
		step_advance();
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: scenario '%s' connect error: %s\n", __func__,
			 scenarios[step].name,
			 in ? (const char *)in : "(null)");
		step_done = -1;
		step_advance();
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* ------------------------------------------------------------- protocols */

static const struct lws_protocols
	defprot = { "defprot", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	prot_auth = { "lws-api-test-lws-login-bff-authmock", callback_authmock,
		      sizeof(struct pss_auth), 0, 0, NULL, 0 },
	prot_cli = { "lws-api-test-lws-login-bff-cli", callback_cli,
		     0, 0, 0, NULL, 0 };

static const struct lws_protocols
	*pprotocols_auth[] = { &defprot, &prot_auth, NULL },
	*pprotocols_cli[]  = { &defprot, &prot_cli, NULL },
	*pprotocols_app[]  = { &defprot, NULL };

static const struct lws_http_mount
	mount_auth = {
		.mountpoint		= "/",
		.protocol		= "lws-api-test-lws-login-bff-authmock",
		.origin_protocol	= LWSMPRO_CALLBACK,
		.mountpoint_len		= 1,
	},
	/*
	 * Route http on the app vhost to the real lws-login plugin protocol
	 * (present in the vhost protocol table because the build has builtin
	 * plugins)
	 */
	mount_app = {
		.mountpoint		= "/",
		.protocol		= "lws-login",
		.origin_protocol	= LWSMPRO_CALLBACK,
		.mountpoint_len		= 1,
	};

/*
 * pvo chain handing the plugin its vhd config.  The lws-login entry both
 * enables the protocol on the vhost and carries its options; a second,
 * optionless entry enables lws_login_client, which the side channel
 * resolves on its own vhost before it will start an exchange.  The
 * auth-server-url value is computed in main() once the listen port is
 * known.
 */
static struct lws_protocol_vhost_options
	pvo_dbpath	= { NULL, NULL, "db-path", NULL },
	/*
	 * cookie-domain set so the Domain= variants of the rotated
	 * auth_session / auth_csrf cookies (the longest csrf cookie string
	 * this plugin can emit) are the ones under test
	 */
	pvo_cdom	= { NULL, NULL, "cookie-domain", "127.0.0.1" },
	pvo_asu		= { NULL, NULL, "auth-server-url", NULL },
	pvo_jwk	= {
		NULL, NULL, "jwt-jwk", jwk_json
	},
	pvo_login	= { NULL, NULL, "lws-login", NULL },
	pvo_lc		= { NULL, NULL, "lws_login_client", NULL };

/* -------------------------------------------------------------- driver */

static lws_sorted_usec_list_t sul_next;
static lws_sorted_usec_list_t sul_timeout;

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;
	lwsl_err("%s: scenario '%s' timed out\n", __func__,
		 scenarios[step].name);
	step_done = -1;
	step_advance();
}

/*
 * F-022 class fence: truncation always removes a suffix, so a Set-Cookie
 * frag carrying one of the plugin's session cookies must contain all three
 * security attributes or its tail was chopped.  The SSO token is
 * deliberately minted near the LWS_SSO_MAX_COOKIE cap: pre-fix, composing
 * its auth_session cookie truncated the trailing "; HttpOnly; SameSite=Lax;
 * Secure" into the fixed 4096-byte buffer.
 */
static int
sc_frag_tail_check(void)
{
	int i;

	for (i = 0; i < got_sc_nfrags; i++) {
		if (!(strstr(got_sc_frags[i], "auth_session=") ||
		      strstr(got_sc_frags[i], "auth_csrf=") ||
		      strstr(got_sc_frags[i], "auth_refresh_session=")))
			continue;
		if (!strstr(got_sc_frags[i], "HttpOnly") ||
		    !strstr(got_sc_frags[i], "SameSite=Lax") ||
		    !strstr(got_sc_frags[i], "Secure")) {
			lwsl_err("%s: set-cookie frag %d lost its attribute "
				 "tail: '%s'\n", __func__, i,
				 got_sc_frags[i]);
			return 1;
		}
	}

	return 0;
}

static void
start_step(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	static char host_hdr[32];

	(void)sul;

	step_done = 0;
	got_status = 0;
	got_sc[0] = '\0';
	got_sc_nfrags = 0;
	got_body_len = 0;
	got_body_trunc = 0;
	mock_hits = 0;
	mock_got_refresh = 0;
	mock_pair_ok = 0;

	/* Host: header must name the app vhost */
	lws_snprintf(host_hdr, sizeof(host_hdr), "127.0.0.1:%d", g_port_app);

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost		= g_vh_cli;
	i.address		= "127.0.0.1";
	i.port			= g_port_app;
	i.path			= scenarios[step].path;
	i.host			= host_hdr;
	/* see APPEND_HANDSHAKE_HEADER: SSO scenarios own their Origin header,
	 * including its absence */
	i.origin		= strcmp(scenarios[step].path, "/.lws-login-sso")
					? host_hdr : NULL;
	i.method		= scenarios[step].method ? scenarios[step].method
							: "POST";
	/* we assert the response ourselves rather than following it */
	i.ssl_connection	= LCCSCF_HTTP_NO_FOLLOW_REDIRECT;
	i.protocol		= "defprot";
	i.local_protocol_name	= "lws-api-test-lws-login-bff-cli";
	i.pwsi			= &current_wsi;

	current_wsi = NULL;
	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed (scenario '%s')\n", __func__,
			 scenarios[step].name);
		step_done = -1;
		lws_cancel_service(context);
		return;
	}

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 20 * LWS_US_PER_SEC);
}

static void
step_advance(void)
{
	if (sequence_done || step >= N_SCENARIOS)
		return;

	for (;;) {
		if (interrupted) {
			result = 1;
			sequence_done = 1;
			lws_cancel_service(context);
			return;
		}

		if (step_done <= 0) {
			if (step_done < 0) {
				lwsl_err("%s: scenario '%s' failed\n", __func__,
					 scenarios[step].name);
				fail++;
				result = 1;
				sequence_done = 1;
				lws_cancel_service(context);
				return;
			}
			return; /* still in flight */
		}

		lws_sul_cancel(&sul_timeout);
		tests++;

		if (got_status != scenarios[step].expect_status) {
			fail++;
			lwsl_err("%s: FAIL scenario '%s': status %d, "
				 "expect %d (set-cookie '%s')\n", __func__,
				 scenarios[step].name, got_status,
				 scenarios[step].expect_status, got_sc);
			result = 1;
			sequence_done = 1;
			lws_cancel_service(context);
			return;
		}

		if (scenarios[step].expect_pair &&
		    (!mock_hits || !mock_got_refresh || !mock_pair_ok)) {
			fail++;
			lwsl_err("%s: FAIL scenario '%s': exchange not "
				 "validated (hits=%d refresh=%d pair=%d)\n",
				 __func__, scenarios[step].name, mock_hits,
				 mock_got_refresh, mock_pair_ok);
			result = 1;
			sequence_done = 1;
			lws_cancel_service(context);
			return;
		}

		if (!scenarios[step].expect_pair && mock_hits) {
			fail++;
			lwsl_err("%s: FAIL scenario '%s': exchange started "
				 "but must not\n", __func__,
				 scenarios[step].name);
			result = 1;
			sequence_done = 1;
			lws_cancel_service(context);
			return;
		}

		if (scenarios[step].expect_rotate &&
		    (!strstr(got_sc, "auth_session=") ||
		     !strstr(got_sc, "auth_csrf=") ||
		     !strstr(got_sc, "Domain=127.0.0.1"))) {
			fail++;
			lwsl_err("%s: FAIL scenario '%s': rotated cookies "
				 "missing (set-cookie '%s')\n", __func__,
				 scenarios[step].name, got_sc);
			result = 1;
			sequence_done = 1;
			lws_cancel_service(context);
			return;
		}

		if (scenarios[step].expect_sso > 0 &&
		    (!strstr(got_sc, "auth_session=") ||
		     !strstr(got_sc, minted_jwt))) {
			fail++;
			lwsl_err("%s: FAIL scenario '%s': SSO cookie not "
				 "planted with the submitted token "
				 "(set-cookie '%s')\n", __func__,
				 scenarios[step].name, got_sc);
			result = 1;
			sequence_done = 1;
			lws_cancel_service(context);
			return;
		}

		if (scenarios[step].expect_sso < 0 &&
		    strstr(got_sc, "auth_session=")) {
			fail++;
			lwsl_err("%s: FAIL scenario '%s': token planted "
				 "despite failed origin check (set-cookie "
				 "'%s')\n", __func__, scenarios[step].name,
				 got_sc);
			result = 1;
			sequence_done = 1;
			lws_cancel_service(context);
			return;
		}

		/*
		 * F-022 class fence: every cookie the plugin minted must
		 * keep its complete HttpOnly / SameSite / Secure tail.
		 */
		if ((scenarios[step].expect_rotate ||
		     scenarios[step].expect_sso > 0) &&
		    sc_frag_tail_check()) {
			fail++;
			result = 1;
			sequence_done = 1;
			lws_cancel_service(context);
			return;
		}

		if (scenarios[step].expect_js) {
			/*
			 * F-021 render-boundary fence, asserted against the
			 * actually-served lws-login.js: the escaper must exist
			 * and every dynamic innerHTML interpolation must go
			 * through it (or encodeURIComponent for the query
			 * value).  The banned patterns are the raw
			 * interpolations as they existed pre-fix.
			 */
			static const char * const fence_need[] = {
				"window.lwsLoginEsc=function",
				"window.lwsLoginEsc(d.name)",
				"window.lwsLoginEsc(st.identity)",
				"encodeURIComponent(d.user_code)",
			};
			static const char * const fence_banned[] = {
				"+d.name+'",
				"+st.identity+'",
				"+d.user_code+'",
			};
			size_t fi;
			int bad = got_body_trunc;

			got_body[got_body_len] = '\0';

			for (fi = 0; fi < LWS_ARRAY_SIZE(fence_need); fi++)
				if (!strstr(got_body, fence_need[fi])) {
					lwsl_err("%s: FAIL scenario '%s': "
						 "served lws-login.js lacks "
						 "'%s'\n", __func__,
						 scenarios[step].name,
						 fence_need[fi]);
					bad = 1;
				}

			for (fi = 0; fi < LWS_ARRAY_SIZE(fence_banned); fi++)
				if (strstr(got_body, fence_banned[fi])) {
					lwsl_err("%s: FAIL scenario '%s': "
						 "served lws-login.js still "
						 "composes '%s' raw into "
						 "innerHTML\n", __func__,
						 scenarios[step].name,
						 fence_banned[fi]);
					bad = 1;
				}

			if (bad) {
				fail++;
				result = 1;
				sequence_done = 1;
				lws_cancel_service(context);
				return;
			}
		}

		lwsl_user("  scenario[%d] '%s': PASS\n", step,
			  scenarios[step].name);

		step_done = 0;
		current_wsi = NULL;

		step++;
		if (step >= N_SCENARIOS)
			break;

		lws_sul_schedule(context, 0, &sul_next, start_step, 1);
		return;
	}

	if (!fail)
		result = 0;
	sequence_done = 1;
	lws_cancel_service(context);
}

static void
sigint_handler(int sig)
{
	(void)sig;
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	/* see api-test-oauth2-client: two listening vhosts + a client + the
	 * plugin's side-channel connection need the real fd limit */
	info.fd_limit_per_thread	= 0;

	/*
	 * F-022: the planted auth_session Set-Cookie for the near-cap SSO
	 * token is ~4.1KB; the default client ah data area (4096) cannot
	 * parse a response carrying it (browsers allow much larger header
	 * sets, this only sizes the test client's receive buffer)
	 */
	info.max_http_header_data	= LWS_SSO_MAX_COOKIE + 1024;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		g_port_app = atoi(p);
	g_port_auth = g_port_app + 1;

	pvo_dbpath.value = lws_cmdline_option(argc, argv, "--db-path");
	if (!pvo_dbpath.value)
		pvo_dbpath.value = "lws-api-test-lws-login-bff.sqlite3";

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: lws-login BFF refresh / csrf self-heal"
		  " + SSO origin gate + widget JS fence\n");

	{
		static char auth_url[128];

		lws_snprintf(auth_url, sizeof(auth_url), "http://127.0.0.1:%d",
			     g_port_auth);
		pvo_asu.value = auth_url;
	}

	/* options chain for lws-login:
	 * jwk -> auth-server-url -> cookie-domain -> db-path */
	pvo_jwk.next	= &pvo_asu;
	pvo_asu.next	= &pvo_cdom;
	pvo_cdom.next	= &pvo_dbpath;
	pvo_login.options = &pvo_jwk;

	/* protocol-enabling chain: lws-login (with options) then the
	 * optionless side-channel client protocol */
	pvo_login.next	= &pvo_lc;

	/* --------------------------------------------------- context/vhosts */

	info.options		= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/*
	 * Mint the SSO token and the port-dependent header values once the
	 * context exists (signing needs it), so every sso-* scenario submits
	 * exactly the same genuinely-signed token and differs only in the
	 * Origin/Referer pair it carries.
	 *
	 * F-022: the token is deliberately minted near the LWS_SSO_MAX_COOKIE
	 * cap (~4040 bytes): planting it must compose an auth_session
	 * Set-Cookie larger than the plugin's old fixed 4096-byte buffer, so
	 * any truncation would cost the cookie its HttpOnly / SameSite /
	 * Secure tail (the fence assertion in step_advance).
	 */
	{
		struct lws_jwk jwk;
		static char pad[LWS_SSO_MAX_COOKIE];
		char payload[LWS_SSO_MAX_COOKIE];
		/* must hold the b64 jose + payload + sig segments at once */
		char temp[LWS_SSO_MAX_COOKIE * 2];
		size_t padlen = 2900;
		int tries = 0;

		memset(&jwk, 0, sizeof(jwk));
		if (lws_jwk_import(&jwk, NULL, NULL, jwk_json,
				   strlen(jwk_json))) {
			lwsl_err("%s: SSO token mint failed\n", __func__);
			goto bail;
		}

		memset(pad, 'a', sizeof(pad) - 1);

		for (;;) {
			size_t out_len = sizeof(minted_jwt);

			lws_snprintf(payload, sizeof(payload),
				     "{\"iss\":\"apitest\",\"sub\":\"sso\","
				     "\"pad\":\"%.*s\"}",
				     (int)padlen, pad);

			if (lws_jwt_sign_compact(context, &jwk, "ES256",
						 minted_jwt, &out_len, temp,
						 sizeof(temp), payload)) {
				lws_jwk_destroy(&jwk);
				lwsl_err("%s: SSO token mint failed\n",
					 __func__);
				goto bail;
			}

			/* converges in one step: b64 grows 4/3 as fast */
			if (out_len >= 4030 && out_len <= 4090) {
				lwsl_notice("%s: minted %llu-byte SSO "
					    "token\n", __func__,
					    (unsigned long long)out_len);
				break;
			}
			if (++tries > 4 || out_len > LWS_SSO_MAX_COOKIE - 8) {
				lws_jwk_destroy(&jwk);
				lwsl_err("%s: cannot size the long SSO token "
					 "(last %llu)\n", __func__,
					 (unsigned long long)out_len);
				goto bail;
			}
			padlen += (4060 - out_len) * 3 / 4;
		}
		lws_jwk_destroy(&jwk);

		lws_snprintf(sso_body, sizeof(sso_body), "token=%s&target=/",
			     minted_jwt);
		lws_snprintf(o_origin_good, sizeof(o_origin_good),
			     "http://127.0.0.1:%d", g_port_auth);
		lws_snprintf(o_origin_evil, sizeof(o_origin_evil),
			     "http://127.0.0.1:%d", g_port_app);
		lws_snprintf(o_referer_good, sizeof(o_referer_good),
			     "http://127.0.0.1:%d/login", g_port_auth);
	}

	/* mock auth server vhost */
	info.port		= g_port_auth;
	info.vhost_name		= "auth";
	info.protocols		= NULL;
	info.pprotocols		= pprotocols_auth;
	info.mounts		= &mount_auth;
	info.pvo		= NULL;

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create mock auth vhost\n");
		goto bail;
	}

	/* app vhost: real lws-login plugin via a pvo chain */
	info.port		= g_port_app;
	info.vhost_name		= "app";
	info.pprotocols		= pprotocols_app;
	info.mounts		= &mount_app;
	info.pvo		= &pvo_login;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create app vhost\n");
		goto bail;
	}

	/* client vhost: no listener */
	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.vhost_name		= "cli";
	info.pprotocols		= pprotocols_cli;
	info.mounts		= NULL;
	info.pvo		= NULL;

	g_vh_cli = lws_create_vhost(context, &info);
	if (!g_vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	/* kick off the scenario sequence */
	step = 0;
	lws_sul_schedule(context, 0, &sul_next, start_step, 1);

	while (n >= 0 && !interrupted && !sequence_done)
		n = lws_service(context, 0);

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s (tests=%d fail=%d)\n",
		  result ? "FAIL" : "PASS", tests, fail);

	return result;
}
