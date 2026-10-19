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
 * Each step is one request from a fresh client connection:
 *
 *  - "visit": GET the page with no cookies: the captcha page is served,
 *    with its visit cookie, which the later steps send back
 *
 *  - "anon-submit": submit the challenge at once with only the visit
 *    cookie: no pass cookie, since the pre-delay has not passed
 *
 *  - "nogrant-submit": the same, also with a genuine, live lws-login session
 *    that lacks the page's service grant: no pass cookie either
 *
 *  - "live-submit": the same with a live session holding the grant: the
 *    pass cookie comes at once (the logged-in user skips the delays)
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

enum {
	ST_VISIT,
	ST_ANON_SUBMIT,
	ST_NOGRANT_SUBMIT,
	ST_LIVE_SUBMIT,
};

static const struct step {
	const char	*name;
	const char	*method;
	unsigned int	status;		/* expected */
	char		visit;		/* the response must mint the visit
					 * cookie */
	char		pass;		/* 1: it must set the pass cookie,
					 * 0: it must not */
} steps[] = {
	{ "visit",		"GET",  200, 1, 0 },
	{ "anon-submit",	"POST", 303, 0, 0 },
	{ "nogrant-submit",	"POST", 303, 0, 0 },
	{ "live-submit",	"POST", 303, 0, 1 },
};

/* minted in main() */
static char ck_live[1024], ck_nogrant[1024];

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

	lws_snprintf(host, sizeof(host), "127.0.0.1:%d", port);

	memset(&i, 0, sizeof(i));
	i.context		= cx;
	i.vhost			= vh_cli;
	i.address		= "127.0.0.1";
	i.port			= port;
	i.path			= "/public/";
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
	const char *session = step == ST_NOGRANT_SUBMIT ? ck_nogrant :
			      step == ST_LIVE_SUBMIT ? ck_live : NULL;
	char cookie[sizeof(visit) + sizeof(ck_live) + 64];

	if (step == ST_VISIT)
		return 0;

	/* the challenge form's bodyless submission, with what we were sent */
	lws_snprintf(cookie, sizeof(cookie), "%s%s%s", visit,
		     session ? "; " : "", session ? session : "");

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

	return 0;
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
		/* the headers are all we came for */
		current_wsi = NULL;
		lws_sul_schedule(cx, 0, &sul_next, next_step, 1);
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

/* lws-login lets anonymous visitors see the public page */
static const struct lws_protocol_vhost_options pmo_unauth = {
	NULL, NULL, "unauth-allow", "1"
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
	pvo_l_jwk	= { &pvo_l_asu, NULL, "jwt-jwk", jwk_pub },
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
	n = mint_session(&jwk, ck_live, sizeof(ck_live),
			 "\"default-service\":1") ||
	    mint_session(&jwk, ck_nogrant, sizeof(ck_nogrant),
			 "\"other-service\":1");
	lws_jwk_destroy(&jwk);
	if (n)
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
