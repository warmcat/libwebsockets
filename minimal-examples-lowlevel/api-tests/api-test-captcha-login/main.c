/*
 * lws-api-test-captcha-login
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * lws_captcha_ratelimit in front of a public page, on a vhost that also runs
 * lws-login, with the page's mount "unauth-allow" for lws-login: anonymous
 * visitors may see it, after waiting out the captcha.  A visitor with a live
 * lws-login session holding the grant skips the captcha's delays.
 *
 * The captcha asks lws-login about the visitor when its challenge is
 * submitted.  It once asked with lws-login's interceptor check, which says
 * "let it through" for an anonymous visitor on an unauth-allow mount too, so
 * anybody got the pass cookie at once by submitting the challenge straight
 * away, and the rate limit was gone (G-249).
 *
 * The challenge page's interceptor-config.js tells captcha.js whether to
 * submit the challenge at once for a logged-in visitor.  captcha.js once
 * decided that from lws-login's /.lws-login-status, which reports a grant
 * level >= 1 for the service of the *status URL's* mount, while the server
 * wants min-grant-level for the *gated* mount's service.  Where those differ
 * the page auto-submitted, was refused for the pre-delay, got a fresh
 * challenge and auto-submitted again, forever (G-340, G-341).  So here the
 * vhost's min-grant-level is 2 and the gated mount names its own
 * service-name, and the config js must agree with the submission's outcome
 * for sessions that fall in each gap.
 *
 * Each step is one request from a fresh client connection:
 *
 *  - "visit": GET the page with no cookies: the captcha page is served,
 *    with its visit cookie, which the later steps send back, and
 *    cache-control: no-store
 *
 *  - "<who>-config": GET the page's interceptor-config.js with the session
 *    (if any): lws_interceptor_session_live must be 1 only for "live".  The
 *    config js is about the visitor, so it must be cache-control: no-store
 *    and cross-origin-resource-policy: same-origin (G-344)
 *
 *  - "<who>-submit": submit the challenge at once, with the visit cookie and
 *    the session (if any): the pass cookie must come at once only for
 *    "live", everybody else is refused for the pre-delay
 *
 * The visitors are
 *
 *  - "anon": no session
 *  - "nogrant": a genuine, live session with no grant for any service here
 *  - "wrongsvc": level 2 for lws-login's vhost-wide service-name, not the
 *    one the gated mount names (G-340)
 *  - "lowlevel": level 1 for the gated mount's service, under the vhost's
 *    min-grant-level 2 (G-341)
 *  - "live": level 2 for the gated mount's service, who skips the delays
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#define LWS_PLUGIN_STATIC
#include "protocol_lws_login.c"
#include "protocol_lws_captcha_ratelimit.c"

/* the captcha's own pass cookie, and the visit cookie the interceptor mints */
#define PASS_COOKIE		"lws_apitest_captcha"
#define VISIT_COOKIE		"lws_interceptor_v"
#define COOKIE_PREFIX		"__Host-"

/*
 * Long enough that no step can meet it: an immediate submission is refused
 * for the pre-delay, never handed the pass cookie after the post-delay
 */
#define PRE_DELAY_MS		"30000"

#define PAGE			"/public/"
#define CONFIG_JS		"/public/interceptor-config.js"
#define LIVE_VAR		"var lws_interceptor_session_live = "

/* the sessions the visitors carry, minted in main() */
enum {
	SESS_NONE,
	SESS_NOGRANT,
	SESS_WRONGSVC,
	SESS_LOWLEVEL,
	SESS_LIVE,

	SESS_COUNT
};

static const char * const session_grants[] = {
	[SESS_NOGRANT]	= "\"other-service\":2",
	[SESS_WRONGSVC]	= "\"default-service\":2",
	[SESS_LOWLEVEL]	= "\"public-svc\":1",
	[SESS_LIVE]	= "\"public-svc\":2",
};

static char sessions[SESS_COUNT][1024];

static const struct step {
	const char	*name;
	const char	*method;
	const char	*path;
	int		session;	/* SESS_ */
	unsigned int	status;		/* expected */
	char		visit;		/* the response must mint the visit
					 * cookie */
	char		pass;		/* 1: it must set the pass cookie,
					 * 0: it must not */
	signed char	live;		/* -1: not the config js, else the
					 * lws_interceptor_session_live it must
					 * report */
} steps[] = {
	{ "visit",		"GET",  PAGE,      SESS_NONE,     200, 1, 0, -1 },
	{ "anon-config",	"GET",  CONFIG_JS, SESS_NONE,     200, 0, 0,  0 },
	{ "anon-submit",	"POST", PAGE,      SESS_NONE,     303, 0, 0, -1 },
	{ "nogrant-config",	"GET",  CONFIG_JS, SESS_NOGRANT,  200, 0, 0,  0 },
	{ "nogrant-submit",	"POST", PAGE,      SESS_NOGRANT,  303, 0, 0, -1 },
	{ "wrongsvc-config",	"GET",  CONFIG_JS, SESS_WRONGSVC, 200, 0, 0,  0 },
	{ "wrongsvc-submit",	"POST", PAGE,      SESS_WRONGSVC, 303, 0, 0, -1 },
	{ "lowlevel-config",	"GET",  CONFIG_JS, SESS_LOWLEVEL, 200, 0, 0,  0 },
	{ "lowlevel-submit",	"POST", PAGE,      SESS_LOWLEVEL, 303, 0, 0, -1 },
	{ "live-config",	"GET",  CONFIG_JS, SESS_LIVE,     200, 0, 0,  1 },
	{ "live-submit",	"POST", PAGE,      SESS_LIVE,     303, 0, 1, -1 },
};

/* the config js body, as it arrives */
static char body[1024];
static size_t body_len;

/*
 * Throwaway P-256 key: the test signs session tokens with it, lws-login
 * is only given its public half to verify them with
 */
static const char jwk_priv[] =
	"{\"crv\":\"P-256\",\"d\":\"D4EjZm33VsKBwIO2_BXL-GRKuQpn65wDo0a9Tc7TdMI\","
	"\"kty\":\"EC\",\"x\":\"M_5UuNbZp2RGuV_6_us0qstvioPr4nd6d_FU0dTfsBc\","
	"\"y\":\"2hmXygj6XfChnLtCtLeLO1y8OOWWLRYzabvjBUVVbJk\"}",
	jwk_pub[] =
	"{\"crv\":\"P-256\",\"kty\":\"EC\","
	"\"x\":\"M_5UuNbZp2RGuV_6_us0qstvioPr4nd6d_FU0dTfsBc\","
	"\"y\":\"2hmXygj6XfChnLtCtLeLO1y8OOWWLRYzabvjBUVVbJk\"}";

/* the captcha's own HS256 key, only for its visit and pass cookies */
static const char jwk_captcha[] =
	"{\"kty\":\"oct\",\"k\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\"}";

static struct lws_context *cx;
static struct lws_vhost *vh_cli;
static struct lws *current_wsi;
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static char visit[LWS_JWT_COOKIE_ASCII_LEN + 32];
static int port = 7681, step = -1, fails, done;

static void
finish(void)
{
	if (done)
		return;
	done = 1;
	lws_sul_cancel(&sul_next);
	lws_sul_cancel(&sul_watchdog);
	lws_default_loop_exit(cx);
}

static void
next_step(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	static char host[32];

	if (++step == (int)LWS_ARRAY_SIZE(steps)) {
		finish();
		return;
	}

	lwsl_user("%s: step %d: %s\n", __func__, step, steps[step].name);

	body_len = 0;

	lws_snprintf(host, sizeof(host), "127.0.0.1:%d", port);

	memset(&i, 0, sizeof(i));
	i.context		= cx;
	i.vhost			= vh_cli;
	i.address		= "127.0.0.1";
	i.port			= port;
	i.path			= steps[step].path;
	i.host			= host;
	i.origin		= host;
	i.method		= steps[step].method;
	/* we judge the response ourselves rather than following it */
	i.ssl_connection	= LCCSCF_HTTP_NO_FOLLOW_REDIRECT;
	i.protocol		= "cli";
	i.local_protocol_name	= "cli";
	i.pwsi			= &current_wsi;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: step %d: connect failed\n", __func__, step);
		fails++;
		finish();
	}
}

static int
append_headers(struct lws *wsi, unsigned char **p, unsigned char *end)
{
	const char *session = steps[step].session == SESS_NONE ? NULL :
			      sessions[steps[step].session];
	char cookie[sizeof(visit) + sizeof(sessions[0]) + 64];

	if (!visit[0])
		return 0;

	/* what we were sent, and the session if the visitor has one */
	lws_snprintf(cookie, sizeof(cookie), "%s%s%s", visit,
		     session ? "; " : "", session ? session : "");

	if (strcmp(steps[step].method, "POST"))
		return lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_COOKIE,
				(const unsigned char *)cookie,
				(int)strlen(cookie), p, end);

	/* the challenge form's bodyless submission */
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
			(const unsigned char *)"application/x-www-form-urlencoded",
			33, p, end) ||
	    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH,
			(const unsigned char *)"0", 1, p, end) ||
	    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_COOKIE,
			(const unsigned char *)cookie, (int)strlen(cookie),
			p, end))
		return 1;

	return 0;
}

/*
 * The challenge page and the config js are about this visitor: no cache may
 * keep them, and no other origin may include the config js as a script
 */
static int
judge_private(struct lws *wsi)
{
	char v[64];

	if (lws_hdr_copy(wsi, v, sizeof(v), WSI_TOKEN_HTTP_CACHE_CONTROL) <= 0 ||
	    strcmp(v, "no-store")) {
		lwsl_err("%s: step %d: cache-control must be no-store\n",
			 __func__, step);
		return 1;
	}

#if defined(LWS_WITH_CUSTOM_HEADERS)
	if (steps[step].live >= 0 &&
	    (lws_hdr_custom_copy(wsi, v, sizeof(v),
				 "cross-origin-resource-policy:", 29) <= 0 ||
	     strcmp(v, "same-origin"))) {
		lwsl_err("%s: step %d: config js needs "
			 "cross-origin-resource-policy: same-origin\n",
			 __func__, step);
		return 1;
	}
#endif

	return 0;
}

/*
 * Judge the response headers of the step: its status, and which of the
 * captcha's cookies it set
 */
static int
judge(struct lws *wsi)
{
	unsigned int status = (unsigned int)lws_http_client_http_response(wsi);
	char frag[LWS_JWT_COOKIE_ASCII_LEN + 128], *sc;
	int n = 0, got_visit = 0, got_pass = 0;
	size_t l;

	while (lws_hdr_copy_fragment(wsi, frag, sizeof(frag),
				     WSI_TOKEN_HTTP_SET_COOKIE, n++) >= 0) {
		/* the cookies may carry the __Host- prefix */
		sc = frag;
		if (!strncmp(sc, COOKIE_PREFIX, strlen(COOKIE_PREFIX)))
			sc += strlen(COOKIE_PREFIX);

		if (!strncmp(sc, PASS_COOKIE "=", strlen(PASS_COOKIE) + 1))
			got_pass = 1;
		if (strncmp(sc, VISIT_COOKIE "=", strlen(VISIT_COOKIE) + 1))
			continue;

		/* what goes back is the whole name=value, as a browser would */
		got_visit = 1;
		l = strcspn(frag, ";");
		if (l >= sizeof(visit))
			return 1;
		memcpy(visit, frag, l);
		visit[l] = '\0';
	}

	lwsl_user("%s: step %d: %s: status %u, visit cookie %d, pass cookie "
		  "%d\n", __func__, step, steps[step].name, status, got_visit,
		  got_pass);

	if (status != steps[step].status) {
		lwsl_err("%s: step %d: expected status %u\n", __func__, step,
			 steps[step].status);
		return 1;
	}
	if (got_visit != steps[step].visit) {
		lwsl_err("%s: step %d: visit cookie %s\n", __func__, step,
			 got_visit ? "unexpected" : "missing");
		return 1;
	}
	if (got_pass != steps[step].pass) {
		lwsl_err("%s: step %d: %s\n", __func__, step,
			 got_pass ? "pass cookie issued without the captcha's "
				    "delay or a session" :
				    "a live session did not skip the delays");
		return 1;
	}

	if ((steps[step].visit || steps[step].live >= 0) && judge_private(wsi))
		return 1;

	return 0;
}

/*
 * Judge the config js body: it must say whether submitting the challenge
 * is waved through, and say what the submission step for the same visitor
 * then finds
 */
static int
judge_config(void)
{
	const char *p;
	int live;

	body[body_len] = '\0';
	p = strstr(body, LIVE_VAR);
	if (!p) {
		lwsl_err("%s: step %d: no lws_interceptor_session_live in "
			 "the config js\n", __func__, step);
		return 1;
	}
	live = atoi(p + strlen(LIVE_VAR));

	lwsl_user("%s: step %d: %s: session_live %d\n", __func__, step,
		  steps[step].name, live);

	if (live != steps[step].live) {
		lwsl_err("%s: step %d: expected session_live %d: captcha.js "
			 "would %s\n", __func__, step, steps[step].live,
			 live ? "auto-submit a challenge the server refuses" :
				"not auto-submit for a live session");
		return 1;
	}

	return 0;
}

static void
step_done(void)
{
	/* we are done with this connection */
	current_wsi = NULL;
	lws_sul_schedule(cx, 0, &sul_next, next_step, 1);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	if (wsi != current_wsi)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		if (append_headers(wsi, (unsigned char **)in,
				   (*(unsigned char **)in) + len))
			return -1;
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (judge(wsi)) {
			fails++;
			finish();
			return -1;
		}
		if (steps[step].live >= 0)
			break; /* go on to read the config js body */

		/* the headers are all we came for */
		step_done();
		return -1;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
	{
		char buf[LWS_PRE + 1024], *px = buf + LWS_PRE;
		int lenx = sizeof(buf) - LWS_PRE;

		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;

		return 0;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (len >= sizeof(body) - body_len) {
			lwsl_err("%s: step %d: config js too large\n",
				 __func__, step);
			fails++;
			finish();
			return -1;
		}
		memcpy(body + body_len, in, len);
		body_len += len;

		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (judge_config()) {
			fails++;
			finish();
			return -1;
		}
		step_done();
		return -1;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: step %d: connection error: %s\n", __func__, step,
			 in ? (const char *)in : "(null)");
		fails++;
		finish();
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!done) {
			lwsl_err("%s: step %d: closed without a response\n",
				 __func__, step);
			fails++;
			finish();
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols
	prot_defprot = { "defprot", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	prot_login = LWS_PLUGIN_PROTOCOL_LWS_LOGIN,
	/* lws-login's side channel, unused here */
	prot_login_client = { "lws_login_client", callback_lws_login_client,
			      0, 0, 0, NULL, 0 },
	prot_captcha = LWS_PLUGIN_PROTOCOL_LWS_CAPTCHA_RATELIMIT,
	prot_cli = { "cli", callback_cli, 0, 0, 0, NULL, 0 };

static const struct lws_protocols *pprotocols_app[] = {
	&prot_defprot, &prot_login, &prot_login_client, &prot_captcha, NULL
}, *pprotocols_cli[] = { &prot_cli, NULL };

/*
 * lws-login lets anonymous visitors see the public page, whose service is
 * not lws-login's vhost-wide one
 */
static const struct lws_protocol_vhost_options pmo_service = {
	NULL, NULL, "service-name", "public-svc"
}, pmo_unauth = {
	&pmo_service, NULL, "unauth-allow", "1"
};

static const struct lws_http_mount mount_public = {
	.mountpoint		= "/public",
	.mountpoint_len		= 7,
	.protocol		= "defprot",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.interceptor_path	= "/captcha",
	.cgienv			= &pmo_unauth,
}, mount_captcha = {
	.mount_next		= &mount_public,
	.mountpoint		= "/captcha",
	.mountpoint_len		= 8,
	.protocol		= "lws_captcha_ratelimit",
	.origin_protocol	= LWSMPRO_CALLBACK,
};

static struct lws_protocol_vhost_options
	pvo_c_assets	= { NULL, NULL, "asset-dir", NULL },
	pvo_c_post	= { &pvo_c_assets, NULL, "post-delay-ms", "1000" },
	pvo_c_pre	= { &pvo_c_post, NULL, "pre-delay-ms", PRE_DELAY_MS },
	pvo_c_cookie	= { &pvo_c_pre, NULL, "cookie-name", PASS_COOKIE },
	pvo_c_jwk	= { &pvo_c_cookie, NULL, "jwt-jwk", jwk_captcha },
	pvo_captcha	= { NULL, &pvo_c_jwk, "lws_captcha_ratelimit", "" },

	pvo_l_asu	= { NULL, NULL, "auth-server-url",
			    "https://auth.invalid/login" },
	/* a grant of level 1 is not enough for anything on this vhost */
	pvo_l_level	= { &pvo_l_asu, NULL, "min-grant-level", "2" },
	pvo_l_jwk	= { &pvo_l_level, NULL, "jwt-jwk", jwk_pub },
	pvo_login	= { &pvo_captcha, &pvo_l_jwk, "lws-login", "" };

/* a genuine, unexpired lws-login session token with the given grants */
static int
mint_session(struct lws_jwk *jwk, char *ck, size_t ck_len, const char *grants)
{
	unsigned long long now = (unsigned long long)time(NULL);
	char tok[768], temp[2048];
	size_t tok_len = sizeof(tok);

	if (lws_jwt_sign_compact(cx, jwk, "ES256", tok, &tok_len, temp,
				 sizeof(temp),
				 "{\"iss\":\"apitest\",\"pur\":\""
				 LWS_JWT_AUTH_PURPOSE_SSO "\",\"sub\":\"alice\","
				 "\"uid\":1,\"sec\":1,\"iat\":%llu,\"exp\":%llu,"
				 "\"grants\":{%s}}", now, now + 3600, grants)) {
		lwsl_err("%s: session token mint failed\n", __func__);
		return 1;
	}

	lws_snprintf(ck, ck_len, "auth_session=%s", tok);

	return 0;
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: step %d timed out\n", __func__, step);
	fails++;
	finish();
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_jwk jwk;
	const char *p;
	int n = 0;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	pvo_c_assets.value = lws_cmdline_option(argc, argv, "--assets");
	if (!pvo_c_assets.value) {
		lwsl_err("--assets <captcha-assets dir> is required\n");
		return 1;
	}

	lwsl_user("LWS API selftest: captcha_ratelimit with lws-login\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	memset(&jwk, 0, sizeof(jwk));
	if (lws_jwk_import(&jwk, NULL, NULL, jwk_priv, strlen(jwk_priv))) {
		lwsl_err("jwk import failed\n");
		goto bail;
	}
	for (n = SESS_NOGRANT; n < SESS_COUNT; n++)
		if (mint_session(&jwk, sessions[n], sizeof(sessions[n]),
				 session_grants[n]))
			break;
	lws_jwk_destroy(&jwk);
	if (n != SESS_COUNT)
		goto bail;

	info.vhost_name		= "app";
	info.port		= port;
	info.pprotocols		= pprotocols_app;
	info.mounts		= &mount_captcha;
	info.pvo		= &pvo_login;
	if (!lws_create_vhost(cx, &info)) {
		lwsl_err("app vhost creation failed\n");
		goto bail;
	}

	info.vhost_name		= "cli";
	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.pprotocols		= pprotocols_cli;
	info.mounts		= NULL;
	info.pvo		= NULL;
	vh_cli = lws_create_vhost(cx, &info);
	if (!vh_cli) {
		lwsl_err("client vhost creation failed\n");
		goto bail;
	}

	lws_sul_schedule(cx, 0, &sul_watchdog, watchdog_cb,
			 10 * LWS_USEC_PER_SEC);
	lws_sul_schedule(cx, 0, &sul_next, next_step, 1);

	n = 0;
	while (n >= 0 && !done)
		n = lws_service(cx, 0);

bail:
	lws_sul_cancel(&sul_next);
	lws_sul_cancel(&sul_watchdog);
	lws_context_destroy(cx);

	if (fails || !done) {
		lwsl_user("Completed: failed\n");
		return 1;
	}

	lwsl_user("Completed: OK\n");

	return 0;
}
