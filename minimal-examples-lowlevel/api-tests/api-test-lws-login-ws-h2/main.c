/*
 * lws-api-test-lws-login-ws-h2
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * lws-login judges a request by the grant its mount names: the gated mount's
 * interceptor_path points at an lws-login mount whose "service-name" PMO
 * overrides the vhost-wide one, as sai's /sai is gated by /lws-login-sai with
 * "service-name": "lws-sai".  To find the mount, lws-login needs the request's
 * URI.
 *
 * A ws upgrade over h1 is a GET, but over h2 (RFC 8441) it is an extended
 * CONNECT, whose :path lws keeps under WSI_TOKEN_CONNECT.  lws-login only
 * looked under the other methods' tokens, so for a ws-over-h2 upgrade it
 * found no URI, no mount and so no PMOs, and judged the token against the
 * vhost's default service instead.  A user holding only the mount's grant
 * was then let through as anonymous, and its backend never saw them as the
 * admin they are.
 *
 * Here one TLS vhost serving h2 and h1 runs the real lws-login plugin, with
 * "default-service" as its vhost-wide service, gating a ws protocol behind
 * a mount whose lws-login mount says "app-svc".  The client upgrades to it
 * with a session token holding app-svc:2 only, once over h1 and once over h2,
 * and the ws protocol reports what lws-login stamped.  Both times it must be
 * x-lws-login-state 3 (an admin of the app) for service "app-svc".
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#define WSH2_PROT	"lws-api-test-lws-login-ws-h2"
#define WSH2_SVC	"app-svc"

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_timeout;
static int port = 7681, result = 1, step;
static const char *server = "127.0.0.1";
static char cookie[1024];

static const struct {
	const char	*name;
	const char	*alpn;
	int		h2;		/* 1 = must be encapsulated in h2 */
} steps[] = {
	{ "ws-h1", "http/1.1", 0 },
	{ "ws-h2", "h2", 1 },
};

/* what the server side of the current step saw */
static char got_state[8], got_service[64];
static int got_established, step_failed;

/*
 * Throwaway P-256 keypair: parsed by the plugin to validate tokens, and by
 * the test to mint them (it carries the private member)
 */
static const char jwk_json[] =
	"{\"crv\":\"P-256\",\"d\":\"D4EjZm33VsKBwIO2_BXL-GRKuQpn65wDo0a9Tc7TdMI\",\"kty\":\"EC\",\"x\":\"M_5UuNbZp2RGuV_6_us0qstvioPr4nd6d_FU0dTfsBc\",\"y\":\"2hmXygj6XfChnLtCtLeLO1y8OOWWLRYzabvjBUVVbJk\"}";

static void
step_start(void);

static void
step_end(int failed)
{
	lws_sul_cancel(&sul_timeout);

	if (!failed && (!got_established || strcmp(got_state, "3") ||
			strcmp(got_service, WSH2_SVC))) {
		lwsl_err("%s: FAIL '%s': established %d, state '%s', "
			 "service '%s', expected state 3 for '%s'\n", __func__,
			 steps[step].name, got_established, got_state,
			 got_service, WSH2_SVC);
		failed = 1;
	}

	if (failed) {
		lwsl_err("%s: scenario '%s' failed\n", __func__,
			 steps[step].name);
		lws_default_loop_exit(context);
		return;
	}

	lwsl_user("%s: '%s' OK\n", __func__, steps[step].name);

	if (++step == (int)LWS_ARRAY_SIZE(steps)) {
		result = 0;
		lws_default_loop_exit(context);
		return;
	}

	step_start();
}

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;
	lwsl_err("%s: scenario '%s' timed out\n", __func__, steps[step].name);
	lws_default_loop_exit(context);
}

/*
 * The app behind the gated mount: it does no auth of its own and records
 * what lws-login stamped on its upgrade
 */
static int
callback_app(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	if (reason == LWS_CALLBACK_ESTABLISHED) {
		got_established = 1;
		if (lws_http_get_onward_header(wsi, LWS_LOGIN_HDR_STATE,
					       got_state,
					       sizeof(got_state)) < 0)
			lws_strncpy(got_state, "-", sizeof(got_state));
		if (lws_http_get_onward_header(wsi, LWS_LOGIN_HDR_SERVICE,
					       got_service,
					       sizeof(got_service)) < 0)
			lws_strncpy(got_service, "-", sizeof(got_service));
		lwsl_notice("%s: stamped state '%s', service '%s'\n", __func__,
			    got_state, got_service);
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in, *end = (*p) + len;

		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_COOKIE,
				(const unsigned char *)cookie,
				(int)strlen(cookie), p, end))
			return -1;
		break;
	}

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		/* a test of ws-over-h2 that fell back to h1 tests nothing */
		if ((lws_get_network_wsi(wsi) != wsi) != steps[step].h2) {
			lwsl_err("%s: '%s': %sencapsulated in h2\n", __func__,
				 steps[step].name, steps[step].h2 ? "not " : "");
			step_failed = 1;
		}
		lws_set_timeout(wsi, PENDING_TIMEOUT_USER_OK, LWS_TO_KILL_ASYNC);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: '%s': connection error: %s\n", __func__,
			 steps[step].name, in ? (const char *)in : "(null)");
		step_end(1);
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		step_end(step_failed);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols
	defprot  = { "defprot", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	prot_app = { WSH2_PROT, callback_app, 0, 0, 0, NULL, 0 },
	prot_cli = { WSH2_PROT, callback_cli, 0, 0, 0, NULL, 0 };

static const struct lws_protocols
	*pprotocols_srv[] = { &defprot, &prot_app, NULL },
	*pprotocols_cli[] = { &prot_cli, NULL };

/* the gated mount's lws-login mount says which grant it is for */
static const struct lws_protocol_vhost_options
	pmo_svc = { NULL, NULL, "service-name", WSH2_SVC };

static const struct lws_http_mount
	/* the mount the gated one names as its interceptor */
	mount_login_app = {
		.mountpoint		= "/login-app",
		.protocol		= "lws-login",
		.origin_protocol	= LWSMPRO_CALLBACK,
		.mountpoint_len		= 10,
		.cgienv			= &pmo_svc,
	},
	mount_app = {
		.mount_next		= &mount_login_app,
		.mountpoint		= "/app",
		.protocol		= "defprot",
		.origin_protocol	= LWSMPRO_CALLBACK,
		.mountpoint_len		= 4,
		.interceptor_path	= "/login-app",
	},
	mount_root = {
		.mount_next		= &mount_app,
		.mountpoint		= "/",
		.protocol		= "lws-login",
		.origin_protocol	= LWSMPRO_CALLBACK,
		.mountpoint_len		= 1,
	};

/* lws-login's vhost-wide service-name is left at "default-service" */
static struct lws_protocol_vhost_options
	pvo_asu		= { NULL, NULL, "auth-server-url",
			    "https://127.0.0.1/auth/" },
	pvo_jwk		= { &pvo_asu, NULL, "jwt-jwk", jwk_json },
	pvo_login	= { NULL, &pvo_jwk, "lws-login", NULL };

static void
step_start(void)
{
	struct lws_client_connect_info i;

	got_established = 0;
	step_failed = 0;
	got_state[0] = got_service[0] = '\0';

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server;
	i.port			= port;
	i.path			= "/app";
	i.host			= server;
	i.origin		= server;
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	i.alpn			= steps[step].alpn;
	i.protocol		= WSH2_PROT;
	i.local_protocol_name	= WSH2_PROT;

	lwsl_user("%s: '%s'\n", __func__, steps[step].name);

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: '%s': connect failed\n", __func__,
			 steps[step].name);
		lws_default_loop_exit(context);
		return;
	}

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 10 * LWS_US_PER_SEC);
}

/*
 * A Cookie: header carrying a genuinely-signed, unexpired session token in
 * the shape the auth server mints, holding the gated mount's grant at level 2
 * and nothing else
 */
static int
mint_cookie(void)
{
	unsigned long long now = (unsigned long long)time(NULL);
	char tok[1024], temp[2048];
	size_t tok_len = sizeof(tok);
	struct lws_jwk jwk;
	int r;

	memset(&jwk, 0, sizeof(jwk));
	if (lws_jwk_import(&jwk, NULL, NULL, jwk_json, strlen(jwk_json)))
		return 1;

	r = lws_jwt_sign_compact(context, &jwk, "ES256", tok, &tok_len, temp,
				 sizeof(temp),
				 "{\"iss\":\"apitest\",\"pur\":\""
				 LWS_JWT_AUTH_PURPOSE_SSO "\",\"sub\":\"alice\","
				 "\"uid\":1,\"sec\":1,\"iat\":%llu,"
				 "\"exp\":%llu,\"grants\":{\"" WSH2_SVC "\":2}}",
				 now, now + 3600);
	lws_jwk_destroy(&jwk);
	if (r)
		return 1;

	lws_snprintf(cookie, sizeof(cookie), "auth_session=%s", tok);

	return 0;
}

static void
sigint_handler(int sig)
{
	(void)sig;
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: lws-login gates ws over h1 and h2\n");

	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (mint_cookie()) {
		lwsl_err("%s: session token mint failed\n", __func__);
		goto bail;
	}

	/* the app vhost: lws-login gating the ws app, over h2 or h1 */
	info.port			= port;
	info.vhost_name			= "app";
	info.alpn			= "h2,http/1.1";
	info.pprotocols			= pprotocols_srv;
	info.mounts			= &mount_root;
	info.pvo			= &pvo_login;
	info.ssl_cert_filepath		= "localhost-100y.cert";
	info.ssl_private_key_filepath	= "localhost-100y.key";

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create app vhost\n");
		goto bail;
	}

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.vhost_name			= "cli";
	info.alpn			= NULL;
	info.pprotocols			= pprotocols_cli;
	info.mounts			= NULL;
	info.pvo			= NULL;
	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;

	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	step_start();

	lws_context_default_loop_run_destroy(context);
	context = NULL;

bail:
	if (context)
		lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
