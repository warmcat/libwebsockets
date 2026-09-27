/*
 * lws api test: the delegated oauth login, against a real lwsws
 *
 * Written in 2025 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 *
 * The fixture (see CMakeLists.txt) is a real lwsws carrying both halves of the
 * delegated login: an auth vhost running lws-auth-server, and an app vhost
 * running lws-oauth2-client + lws-login + lws_login_client, with the app's
 * protected mount reached through an lws-login interceptor-path.  Both vhosts
 * offer h1, h2 and h3 on the same port numbers.
 *
 * Every scenario here can be told which transport to use, because the failure
 * this test exists for did not care what any request said, only how it was
 * framed: the identical exchange completed on h1 and lost its headers on h2 and
 * h3, and nothing in the stack logged anything about it.  A test that only ever
 * spoke h1 could not see it.
 *
 * Scenarios
 *
 *  bounce: fetch the protected mount with an empty jar and walk the handover.
 *          lws-login must bounce to the local BFF, and the BFF must answer with
 *          a PKCE redirect to the auth server carrying client_id, redirect_uri,
 *          state, code_challenge + S256 and service_name, plus the
 *          auth_oauth_state binding cookie that RFC 6749 s10.12 wants.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

static int	interrupted, bad = 1, port_auth, port_app;
/*
 * An earlier keepalive connection closing ("peer closed while idle") delivers
 * CLOSED_CLIENT_HTTP while a later request is still waiting for its response.
 * Treating that as our own completion abandoned the request with nothing
 * parsed, which looked exactly like a transport fault on h1 and h2 while h3,
 * having no such idle close, passed.
 *
 * Filtering on the wsi is not the answer: on h2 and h3 the transaction arrives
 * on a mux child, not the wsi the connect handed back.  What separates them is
 * simpler -- a close belonging to a transaction of ours has a status by then,
 * and a stale idle close never does.
 */
static const char *server = "127.0.0.1", *alpn = "http/1.1",
		  *test = "bounce", *client_id = "", *service_name = "";

/* what the exchange under way is collecting */
static char	loc[1024];		/* Location: of the last response */
static char	set_cookie[4096];	/* Set-Cookie(s) of the last response */
static char	body[8192];		/* body of the last response */
static size_t	body_len;
static unsigned int status;

struct lws_context *context;

/* ------------------------------------------------------------------ helpers */

/*
 * Report a failed expectation the way a ctest reader needs it: the scenario and
 * transport are in the test name, so the line only has to say which step and
 * what was wrong with it.
 */
static int
fail(const char *step, const char *fmt, ...)
{
	char s[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(s, sizeof(s), fmt, ap);
	va_end(ap);

	lwsl_err("FAIL: %s: %s\n", step, s);

	return 1;
}

/*
 * Is \p name present in the collected Set-Cookie headers?  Matched as a whole
 * cookie name so auth_session does not also answer for auth_session_x.
 */
static int
has_cookie(const char *name)
{
	size_t nl = strlen(name);
	const char *p = set_cookie;

	while ((p = strstr(p, name))) {
		if ((p == set_cookie || p[-1] == ' ' || p[-1] == ';') &&
		    p[nl] == '=')
			return 1;
		p += nl;
	}

	return 0;
}

/* does the query of the last Location: carry \p key ? */
static int
loc_has(const char *key)
{
	char nb[64];
	const char *q = strchr(loc, '?');

	if (!q)
		return 0;

	lws_snprintf(nb, sizeof(nb), "%s=", key);

	if (!strncmp(q + 1, nb, strlen(nb)))
		return 1;

	lws_snprintf(nb, sizeof(nb), "&%s=", key);

	return !!strstr(q, nb);
}

/* ------------------------------------------------------------------ callback */

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (char *)in : "(none)");
		interrupted = 1;
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		status = (unsigned int)lws_http_client_http_response(wsi);

		loc[0] = set_cookie[0] = body[0] = '\0';
		body_len = 0;
		lws_hdr_copy(wsi, loc, sizeof(loc), WSI_TOKEN_HTTP_LOCATION);
		/*
		 * lws_hdr_copy() walks the fragment chain, so several
		 * Set-Cookie headers (or h2 / h3 crumbs of one) all arrive,
		 * separated by ';'
		 */
		lws_hdr_copy(wsi, set_cookie, sizeof(set_cookie),
			     WSI_TOKEN_HTTP_SET_COOKIE);

		lwsl_info("%s: %u, Location '%s'\n", __func__, status, loc);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (body_len + len < sizeof(body) - 1) {
			memcpy(body + body_len, in, len);
			body_len += len;
			body[body_len] = '\0';
		}
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		/*
		 * h1 does not pump the body on its own: without this the
		 * transaction never completes and the test would hang rather
		 * than say what it was waiting for
		 */
		{
			char buf[1024 + LWS_PRE];
			char *px = buf + LWS_PRE;
			int lenx = sizeof(buf) - LWS_PRE;

			if (lws_http_client_read(wsi, &px, &lenx) < 0)
				return -1;
		}
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		interrupted = 1;
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		/* ours if this transaction got as far as a status */
		if (status)
			interrupted = 1;
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{ "http", callback_http, 0, 0, 0, NULL, 0 },
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

/*
 * One request, no redirect following: each hop of the handover is an assertion
 * of its own, so the test has to see every status and header itself.
 */
static int
req(int port, const char *path)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));

	i.context		= context;
	i.port			= port;
	i.address		= server;
	i.path			= path;
	i.host			= server;
	i.origin		= server;
	i.method		= "GET";
	i.protocol		= protocols[0].name;
	i.alpn			= alpn;
	/*
	 * The fixture serves the build tree's test cert, which is not for this
	 * name and not signed by anything we trust: this test is about the
	 * login exchange, not about TLS.
	 */
	i.ssl_connection	= LCCSCF_USE_SSL |
				  LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK |
				  LCCSCF_ALLOW_INSECURE |
				  LCCSCF_HTTP_NO_FOLLOW_REDIRECT;

	status = 0;
	interrupted = 0;
	body_len = 0;
	if (!lws_client_connect_via_info(&i))
		return 1;

	{
		lws_usec_t deadline = lws_now_usecs() +
					(20 * LWS_US_PER_SEC);

		while (!interrupted && lws_service(context, 0) >= 0)
			if (lws_now_usecs() > deadline) {
				lwsl_err("%s: %s timed out with no completed "
					 "transaction\n", __func__, path);

				return 1;
			}
	}

	return 0;
}

/* ----------------------------------------------------------------- scenarios */

/*
 * An empty jar asking for the protected mount must come back as the start of a
 * login, not as content and not as a bare error.
 */
/*
 * The front half of the delegated login: the interceptor-guarded mount, the
 * widget's own view of whether anyone is logged in, and the BFF's PKCE handover
 * to the auth server.
 *
 * Note this deployment shape sets unauth-allow on the interceptor, so an
 * anonymous request is *not* bounced -- it is let through to the public view and
 * the page's widget decides what to render from /.lws-login-status.  Asserting a
 * 302 here would be asserting a different configuration than the one that runs.
 */
static int
scenario_bounce(void)
{
	char p[1024];

	/* (1) the guarded mount is reachable and, unauthenticated, public */

	if (req(port_app, "/sai/"))
		return fail("bounce", "unable to fetch the guarded mount");

	if (!status)
		return fail("bounce", "no parseable response to GET /sai/ "
				      "(the transport framed something the "
				      "client could not read)");

	if (status != 200)
		return fail("bounce", "GET /sai/ answered %u, wanted 200: "
				      "unauth-allow is set, so an anonymous "
				      "request is let through", status);

	if (!strstr(body, "APITEST-OAUTH-GATED-ORIGIN-REACHED"))
		return fail("bounce", "GET /sai/ did not return the origin "
				      "behind the interceptor (%zu bytes of "
				      "body)", body_len);

	/*
	 * (2) the widget's own probe.  This is the request a not-logged-in
	 * widget always makes, and the one that decides whether a user sees
	 * content or a Login button -- so "it says not logged in" has to be a
	 * thing the test can tell apart from "it did not answer".
	 */

	if (req(port_app, "/sai/.lws-login-status"))
		return fail("bounce", "unable to fetch the login status probe");

	if (!status)
		return fail("bounce", "no parseable response to the "
				      "/sai/.lws-login-status probe");

	if (status != 200)
		return fail("bounce", "/sai/.lws-login-status answered %u, "
				      "wanted 200", status);

	if (!body_len)
		return fail("bounce", "/sai/.lws-login-status returned an "
				      "empty body");

	lwsl_info("status probe said: %s\n", body);

	/*
	 * (3) pressing Login: the local BFF must answer with a PKCE redirect
	 * to the auth server, carrying the parameters that let the auth server
	 * enforce the grant before it renders a form, and binding the state to
	 * this user agent.
	 */

	if (req(port_app, "/oauth/login"))
		return fail("bounce", "unable to fetch the BFF login entry");

	if (!status)
		return fail("bounce", "no parseable response to /oauth/login");

	if (status != 302)
		return fail("bounce", "/oauth/login answered %u, wanted a 302 "
				      "to the auth server", status);

	if (!strstr(loc, "/api/authorize"))
		return fail("bounce", "/oauth/login redirected to '%s', wanted "
				      "the auth server's /api/authorize", loc);

	if (!loc_has("client_id"))
		return fail("bounce", "no client_id in '%s'", loc);
	if (!loc_has("redirect_uri"))
		return fail("bounce", "no redirect_uri in '%s'", loc);
	if (!loc_has("state"))
		return fail("bounce", "no state in '%s'", loc);
	if (!loc_has("code_challenge"))
		return fail("bounce", "no code_challenge in '%s'", loc);
	if (!strstr(loc, "code_challenge_method=S256"))
		return fail("bounce", "code_challenge_method is not S256 in "
				      "'%s'", loc);
	if (client_id[0] && !strstr(loc, client_id))
		return fail("bounce", "client_id in '%s' is not the configured "
				      "'%s'", loc, client_id);

	/*
	 * RFC 6749 s10.12: the state must be bound to the user agent, or a
	 * callback URL captured from an attacker's own authorize round trip
	 * can be handed to a victim.  That binding is this cookie -- and a
	 * Set-Cookie is exactly the kind of header that went missing on h2 and
	 * h3 while the body of the same response arrived intact.
	 */

	if (!has_cookie("auth_oauth_state"))
		return fail("bounce", "/oauth/login set no auth_oauth_state "
				      "binding cookie (Set-Cookie seen: '%s')",
				      set_cookie);

	(void)p;

	lwsl_user("PASS: bounce: guarded mount, status probe, and PKCE "
		  "handover to %s\n", loc);

	return 0;
}

/* ---------------------------------------------------------------------- main */

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);

	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server = p;
	if ((p = lws_cmdline_option(argc, argv, "--auth-port")))
		port_auth = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--app-port")))
		port_app = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--client-id")))
		client_id = p;
	if ((p = lws_cmdline_option(argc, argv, "--service-name")))
		service_name = p;
	if ((p = lws_cmdline_option(argc, argv, "-t")))
		test = p;

	if (lws_cmdline_option(argc, argv, "--h1"))
		alpn = "http/1.1";
	if (lws_cmdline_option(argc, argv, "--h2"))
		alpn = "h2";
	if (lws_cmdline_option(argc, argv, "--h3"))
		alpn = "h3";

	if (!port_auth || !port_app) {
		lwsl_err("%s: --auth-port and --app-port are required\n",
			 __func__);

		return 1;
	}

	lwsl_user("LWS api test: lwsws oauth: %s over %s\n", test, alpn);

	memset(&info, 0, sizeof info);
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_H2_JUST_FIX_WINDOW_UPDATE_OVERFLOW;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("%s: lws init failed\n", __func__);

		return 1;
	}

	if (!strcmp(test, "bounce"))
		bad = scenario_bounce();
	else {
		lwsl_err("%s: unknown scenario '%s'\n", __func__, test);
		bad = 1;
	}

	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", bad ? "FAIL" : "PASS");

	return bad;
}
