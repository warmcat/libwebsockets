/*
 * lws-api-test-http-basic-auth
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A mount with a basic auth login file, over every http transport the
 * build has: h1, h2 with prior knowledge, h2 over tls and h3.  A request
 * with no credentials, or with credentials the file does not list, is
 * answered 401 with a WWW-Authenticate challenge, so a browser can ask
 * the user for them; one with credentials the file lists is served.
 *
 * The protected mount, /private, serves ./docroot/private, inside the
 * origin of the public mount at /.  Where the filesystem finds a file by
 * other names than its own (case on windows and macOS, trailing dots and
 * spaces on windows), /PRIVATE/... and /private./... miss /private and go
 * to /, which must still not serve them without credentials.  Elsewhere
 * there is no such file: either way, the private file is not served.
 *
 * /who is a callback mount behind the same login file, whose callback gives
 * the request headers back at once and then answers with the name
 * lws_http_basic_auth_user() reports: it must be the user the credentials
 * were for, without the headers.
 *
 * A ws upgrade meets the same gates as an http request to its path (G-489),
 * over h1, h2 over tls and h3:
 *
 *  - /private/ws lands in the /private mount, and binds a local ws protocol:
 *    "ba-ws-open", which nothing else protects, or "ba-ws", which also has
 *    the same login file as its "basic-auth" pvo.  The upgrade must be
 *    refused 401, with the challenge, without credentials, and with them must
 *    pass every check, the mount's and the pvo's, and be told the user
 *    lws_http_basic_auth_user() reports
 *
 *  - /proxied is a reverse proxy mount, behind the login file, onto a backend
 *    vhost serving "ba-ws" with no auth of its own: without credentials the
 *    upgrade must be refused 401 and never reach the backend, with them it
 *    is proxied there.  /proxied/refuse has credentials, but the app's
 *    FILTER_PROTOCOL_CONNECTION refuses it, which it must be asked for a
 *    proxied upgrade as for one it serves.
 *
 * lws is both ends here.  The login file is ./basic-auth.txt and the files
 * are in ./docroot, so run it with the test directory as the cwd.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

enum xport {
	XP_H1,
	XP_H2C,
	XP_H2_TLS,
	XP_H3,
};

static const char * const xport_names[] = { "h1", "h2c", "h2-tls", "h3" };

enum creds {
	CR_NONE,
	CR_WRONG,
	CR_RIGHT,
};

static const char * const creds_names[] = { "no", "wrong", "right" };

enum expect {
	EX_CHALLENGE,	/* 401 with a Basic challenge */
	EX_PRIVATE,	/* 200, the private file */
	EX_PUBLIC,	/* 200, the public file */
	EX_NOT_PRIVATE,	/* anything but the private file */
	EX_WHO,		/* 200, naming the authenticated user */
	EX_WS_CHALLENGE,/* ws upgrade refused 401 with a Basic challenge */
	EX_WS_REFUSED,	/* ws upgrade refused */
	EX_WS_FRONT,	/* ws upgrade to the local protocol, as the user */
	EX_WS_BACKEND,	/* ws upgrade proxied to the backend */
};

#define is_ws(c)	((c)->expect >= EX_WS_CHALLENGE)

struct xcase {
	uint8_t		xport;
	uint8_t		creds;
	uint8_t		expect;
	const char	*path;
	const char	*ws_pcol;	/* the ws protocol a ws case offers */
};

#define PRIVATE_MARK	"lws-basic-auth-private"
#define PUBLIC_MARK	"lws-basic-auth-public"
#define WHO_MARK	"who=test-user"
#define WS_FRONT_MARK	"front user=test-user"
#define WS_BACKEND_MARK	"backend user=(nobody)"

#define XP_CASES(x) \
	{ x, CR_NONE,  EX_CHALLENGE,   "/private/index.html", NULL }, \
	{ x, CR_WRONG, EX_CHALLENGE,   "/private/index.html", NULL }, \
	{ x, CR_RIGHT, EX_PRIVATE,     "/private/index.html", NULL }, \
	{ x, CR_NONE,  EX_PUBLIC,      "/index.html", NULL }, \
	{ x, CR_NONE,  EX_NOT_PRIVATE, "/PRIVATE/index.html", NULL }, \
	{ x, CR_NONE,  EX_NOT_PRIVATE, "/Private/index.html", NULL }, \
	{ x, CR_NONE,  EX_NOT_PRIVATE, "/private./index.html", NULL }, \
	{ x, CR_NONE,  EX_NOT_PRIVATE, "/private%20/index.html", NULL }, \
	{ x, CR_NONE,  EX_CHALLENGE,   "/who", NULL }, \
	{ x, CR_RIGHT, EX_WHO,         "/who", NULL }

#if defined(LWS_ROLE_WS)
/*
 * "ba-ws" has the login file as its pvo too, "ba-ws-open" has nothing but
 * the mount's basic auth in front of it
 */
#define WS_LOCAL_CASES(x) \
	{ x, CR_NONE,  EX_WS_CHALLENGE, "/private/ws", "ba-ws-open" }, \
	{ x, CR_WRONG, EX_WS_CHALLENGE, "/private/ws", "ba-ws-open" }, \
	{ x, CR_RIGHT, EX_WS_FRONT,     "/private/ws", "ba-ws-open" }, \
	{ x, CR_NONE,  EX_WS_CHALLENGE, "/private/ws", "ba-ws" }, \
	{ x, CR_RIGHT, EX_WS_FRONT,     "/private/ws", "ba-ws" },
#else
#define WS_LOCAL_CASES(x)
#endif

#if defined(LWS_ROLE_WS) && defined(LWS_WITH_HTTP_PROXY)
#define BA_WS_PROXY
#define WS_PROXY_CASES(x) \
	{ x, CR_NONE,  EX_WS_CHALLENGE, "/proxied/ws", "ba-ws" }, \
	{ x, CR_WRONG, EX_WS_CHALLENGE, "/proxied/ws", "ba-ws" }, \
	{ x, CR_RIGHT, EX_WS_REFUSED,   "/proxied/refuse", "ba-ws" }, \
	{ x, CR_RIGHT, EX_WS_BACKEND,   "/proxied/ws", "ba-ws" },
#else
#define WS_PROXY_CASES(x)
#endif

static const struct xcase cases[] = {
	XP_CASES(XP_H1),
	WS_LOCAL_CASES(XP_H1)
	WS_PROXY_CASES(XP_H1)
#if defined(LWS_WITH_HTTP2)
	XP_CASES(XP_H2C),
#if defined(LWS_WITH_TLS)
	XP_CASES(XP_H2_TLS),
	WS_LOCAL_CASES(XP_H2_TLS)
	WS_PROXY_CASES(XP_H2_TLS)
#endif
#endif
#if defined(LWS_ROLE_H3)
	XP_CASES(XP_H3),
	WS_LOCAL_CASES(XP_H3)
	WS_PROXY_CASES(XP_H3)
#endif
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
#if defined(LWS_ROLE_WS)
static struct lws_vhost *vh_backend;
#endif
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static int result = 1, cur = -1, port_h1 = 7681, port_h2c = 7682,
	   port_tls = 7683, port_h3 = 7684, port_backend = 7685;
static const char *server_addr = "127.0.0.1";

/* what the client heard for the current case */
static struct {
	char		body[256];
	char		challenge[64];
	size_t		body_len;
	int		status;
	int		done;
	int		ws_established;
} cli;

#if defined(LWS_WITH_TLS)
/* a self-signed test cert does for the client's alpn */

static const char * const test_cert =
"-----BEGIN CERTIFICATE-----\n"
"MIIF5jCCA86gAwIBAgIJANq50IuwPFKgMA0GCSqGSIb3DQEBCwUAMIGGMQswCQYD\n"
"VQQGEwJHQjEQMA4GA1UECAwHRXJld2hvbjETMBEGA1UEBwwKQWxsIGFyb3VuZDEb\n"
"MBkGA1UECgwSbGlid2Vic29ja2V0cy10ZXN0MRIwEAYDVQQDDAlsb2NhbGhvc3Qx\n"
"HzAdBgkqhkiG9w0BCQEWEG5vbmVAaW52YWxpZC5vcmcwIBcNMTgwMzIwMDQxNjA3\n"
"WhgPMjExODAyMjQwNDE2MDdaMIGGMQswCQYDVQQGEwJHQjEQMA4GA1UECAwHRXJl\n"
"d2hvbjETMBEGA1UEBwwKQWxsIGFyb3VuZDEbMBkGA1UECgwSbGlid2Vic29ja2V0\n"
"cy10ZXN0MRIwEAYDVQQDDAlsb2NhbGhvc3QxHzAdBgkqhkiG9w0BCQEWEG5vbmVA\n"
"aW52YWxpZC5vcmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCjYtuW\n"
"aICCY0tJPubxpIgIL+WWmz/fmK8IQr11Wtee6/IUyUlo5I602mq1qcLhT/kmpoR8\n"
"Di3DAmHKnSWdPWtn1BtXLErLlUiHgZDrZWInmEBjKM1DZf+CvNGZ+EzPgBv5nTek\n"
"LWcfI5ZZtoGuIP1Dl/IkNDw8zFz4cpiMe/BFGemyxdHhLrKHSm8Eo+nT734tItnH\n"
"KT/m6DSU0xlZ13d6ehLRm7/+Nx47M3XMTRH5qKP/7TTE2s0U6+M0tsGI2zpRi+m6\n"
"jzhNyMBTJ1u58qAe3ZW5/+YAiuZYAB6n5bhUp4oFuB5wYbcBywVR8ujInpF8buWQ\n"
"Ujy5N8pSNp7szdYsnLJpvAd0sibrNPjC0FQCNrpNjgJmIK3+mKk4kXX7ZTwefoAz\n"
"TK4l2pHNuC53QVc/EF++GBLAxmvCDq9ZpMIYi7OmzkkAKKC9Ue6Ef217LFQCFIBK\n"
"Izv9cgi9fwPMLhrKleoVRNsecBsCP569WgJXhUnwf2lon4fEZr3+vRuc9shfqnV0\n"
"nPN1IMSnzXCast7I2fiuRXdIz96KjlGQpP4XfNVA+RGL7aMnWOFIaVrKWLzAtgzo\n"
"GMTvP/AuehKXncBJhYtW0ltTioVx+5yTYSAZWl+IssmXjefxJqYi2/7QWmv1QC9p\n"
"sNcjTMaBQLN03T1Qelbs7Y27sxdEnNUth4kI+wIDAQABo1MwUTAdBgNVHQ4EFgQU\n"
"9mYU23tW2zsomkKTAXarjr2vjuswHwYDVR0jBBgwFoAU9mYU23tW2zsomkKTAXar\n"
"jr2vjuswDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEANjIBMrow\n"
"YNCbhAJdP7dhlhT2RUFRdeRUJD0IxrH/hkvb6myHHnK8nOYezFPjUlmRKUgNEDuA\n"
"xbnXZzPdCRNV9V2mShbXvCyiDY7WCQE2Bn44z26O0uWVk+7DNNLH9BnkwUtOnM9P\n"
"wtmD9phWexm4q2GnTsiL6Ul6cy0QlTJWKVLEUQQ6yda582e23J1AXqtqFcpfoE34\n"
"H3afEiGy882b+ZBiwkeV+oq6XVF8sFyr9zYrv9CvWTYlkpTQfLTZSsgPdEHYVcjv\n"
"xQ2D+XyDR0aRLRlvxUa9dHGFHLICG34Juq5Ai6lM1EsoD8HSsJpMcmrH7MWw2cKk\n"
"ujC3rMdFTtte83wF1uuF4FjUC72+SmcQN7A386BC/nk2TTsJawTDzqwOu/VdZv2g\n"
"1WpTHlumlClZeP+G/jkSyDwqNnTu1aodDmUa4xZodfhP1HWPwUKFcq8oQr148QYA\n"
"AOlbUOJQU7QwRWd1VbnwhDtQWXC92A2w1n/xkZSR1BM/NUSDhkBSUU1WjMbWg6Gg\n"
"mnIZLRerQCu1Oozr87rOQqQakPkyt8BUSNK3K42j2qcfhAONdRl8Hq8Qs5pupy+s\n"
"8sdCGDlwR3JNCMv6u48OK87F4mcIxhkSefFJUFII25pCGN5WtE4p5l+9cnO1GrIX\n"
"e2Hl/7M0c/lbZ4FvXgARlex2rkgS0Ka06HE=\n"
"-----END CERTIFICATE-----\n";

static const char * const test_key =
"-----BEGIN PRIVATE KEY-----\n"
"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\n"
"fBrpEY1IATtPq1taBZZogRqI3rOkkPk=\n"
"-----END PRIVATE KEY-----\n";
#endif

/*
 * The server: a public file mount at /, and inside its origin the origin of
 * a file mount at /private that is behind the login file.  A file neither
 * has goes to the mount's protocol, the dummy callback, which answers 404.
 */

#if defined(BA_WS_PROXY)
/*
 * /proxied: a reverse proxy onto the backend vhost, behind the login file.
 * Its origin names the backend's port, so it is filled in at runtime.
 */
static char origin_backend[128];

static const struct lws_http_mount mount_proxied = {
	.mountpoint		= "/proxied",
	.origin			= origin_backend,
	.origin_protocol	= LWSMPRO_HTTP,
	.mountpoint_len		= 8,
	.basic_auth_login_file	= "./basic-auth.txt",
};
#endif

static const struct lws_http_mount mount_who = {
#if defined(BA_WS_PROXY)
	.mount_next		= &mount_proxied,
#endif
	.mountpoint		= "/who",
	.origin			= "who",
	.protocol		= "who",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 4,
	.basic_auth_login_file	= "./basic-auth.txt",
};

static const struct lws_http_mount mount_private = {
	.mount_next		= &mount_who,
	.mountpoint		= "/private",
	.origin			= "./docroot/private",
	.def			= "index.html",
	.protocol		= "http",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 8,
	.basic_auth_login_file	= "./basic-auth.txt",
};

static const struct lws_http_mount mount = {
	.mount_next		= &mount_private,
	.mountpoint		= "/",
	.origin			= "./docroot",
	.def			= "index.html",
	.protocol		= "http",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 1,
};

static void
next_case(lws_sorted_usec_list_t *sul);

static void
case_done(const char *why)
{
	const struct xcase *c = &cases[cur];

	if (why) {
		lwsl_err("--- %s, %s%s%s, %s credentials: FAIL: %s ---\n",
			 xport_names[c->xport], c->path,
			 c->ws_pcol ? " ws " : "",
			 c->ws_pcol ? c->ws_pcol : "", creds_names[c->creds],
			 why);
		lws_default_loop_exit(context);
		return;
	}

	lwsl_user("--- %s, %s%s%s, %s credentials: %d: PASS ---\n",
		  xport_names[c->xport], c->path, c->ws_pcol ? " ws " : "",
		  c->ws_pcol ? c->ws_pcol : "", creds_names[c->creds],
		  cli.status);
	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
}

static void
case_evaluate(void)
{
	const struct xcase *c = &cases[cur];
	int priv = !!strstr(cli.body, PRIVATE_MARK);

	switch (c->expect) {
	case EX_CHALLENGE:
		if (cli.status != HTTP_STATUS_UNAUTHORIZED || priv)
			case_done("not answered 401");
		else if (strncmp(cli.challenge, "Basic realm=", 12))
			case_done("401 has no basic auth challenge");
		else
			case_done(NULL);
		return;

	case EX_PRIVATE:
		if (cli.status != HTTP_STATUS_OK || !priv)
			case_done("not served");
		else
			case_done(NULL);
		return;

	case EX_PUBLIC:
		if (cli.status != HTTP_STATUS_OK ||
		    !strstr(cli.body, PUBLIC_MARK))
			case_done("not served");
		else
			case_done(NULL);
		return;

	case EX_WHO:
		if (cli.status != HTTP_STATUS_OK || !strstr(cli.body, WHO_MARK))
			case_done("not answered with the authenticated user");
		else
			case_done(NULL);
		return;

	case EX_WS_CHALLENGE:
		if (cli.ws_established)
			case_done("ws upgrade let through without credentials");
		else if (cli.status != HTTP_STATUS_UNAUTHORIZED)
			case_done("ws upgrade not answered 401");
		else if (strncmp(cli.challenge, "Basic realm=", 12))
			case_done("ws upgrade's 401 has no basic auth challenge");
		else
			case_done(NULL);
		return;

	case EX_WS_REFUSED:
		if (cli.ws_established)
			case_done("ws upgrade let through");
		else if (cli.status != HTTP_STATUS_FORBIDDEN)
			case_done("ws upgrade not answered 403");
		else
			case_done(NULL);
		return;

	case EX_WS_FRONT:
		if (!strstr(cli.body, WS_FRONT_MARK))
			case_done("ws not established with the local protocol "
				  "as the authenticated user");
		else
			case_done(NULL);
		return;

	case EX_WS_BACKEND:
		if (!strstr(cli.body, WS_BACKEND_MARK))
			case_done("ws not proxied to the backend");
		else
			case_done(NULL);
		return;

	default:
		if (cli.status == HTTP_STATUS_OK || priv)
			case_done("served the private file without credentials");
		else
			case_done(NULL);
		return;
	}
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 1024], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
	case LWS_CALLBACK_CLIENT_RECEIVE:
	case LWS_CALLBACK_CLIENT_CLOSED:
		/*
		 * An earlier case's connection finishing its close is not
		 * news.  The request carries its case, onto the h2 / h3
		 * stream as well.
		 */
		if (cur < 0 || lws_get_opaque_user_data(wsi) != &cases[cur])
			return lws_callback_http_dummy(wsi, reason, user, in,
						       len);
		break;
	default:
		break;
	}

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in, *end = (*p) + len;
		char b[128];

		if (cases[cur].creds == CR_NONE)
			break;

		if (lws_http_basic_auth_gen("test-user",
				cases[cur].creds == CR_RIGHT ? "test-password" :
							       "not-the-password",
				b, sizeof(b)) ||
		    lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_AUTHORIZATION,
				(unsigned char *)b, (int)strlen(b), p, end)) {
			lwsl_err("%s: no room for the credentials\n",
				 __func__);
			return -1;
		}
		break;
	}

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		cli.status = (int)lws_http_client_http_response(wsi);
		if (lws_hdr_copy(wsi, cli.challenge, sizeof(cli.challenge),
				 WSI_TOKEN_HTTP_WWW_AUTHENTICATE) < 0)
			cli.challenge[0] = '\0';
		if (is_ws(&cases[cur]) && cli.status != 101 &&
		    cli.status != HTTP_STATUS_OK) {
			/*
			 * The upgrade was answered with something else than
			 * accepting it: 101 on h1, 200 on h2 / h3 (RFC 8441)
			 */
			if (!cli.done) {
				cli.done = 1;
				case_evaluate();
			}
			return -1;
		}
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		/* the ws server, local or the backend, sends what it is */
		cli.ws_established = 1;
		if (cases[cur].expect < EX_WS_FRONT) {
			if (!cli.done) {
				cli.done = 1;
				case_evaluate();
			}
			return -1;
		}
		return 0;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		if (len >= sizeof(cli.body))
			len = sizeof(cli.body) - 1;
		memcpy(cli.body, in, len);
		cli.body[len] = '\0';
		if (!cli.done) {
			cli.done = 1;
			case_evaluate();
		}
		return -1;

	case LWS_CALLBACK_CLIENT_CLOSED:
		if (!cli.done) {
			cli.done = 1;
			case_done("ws closed before the server said anything");
		}
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (cli.body_len + len >= sizeof(cli.body))
			len = sizeof(cli.body) - 1 - cli.body_len;
		memcpy(cli.body + cli.body_len, in, len);
		cli.body_len += len;
		cli.body[cli.body_len] = '\0';
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (!cli.done) {
			cli.done = 1;
			case_evaluate();
		}
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (!cli.done) {
			cli.done = 1;
			if (is_ws(&cases[cur])) {
				/*
				 * A refused ws upgrade may be reported this
				 * way, with what the server answered
				 */
				cli.status = (int)lws_http_client_http_response(wsi);
				case_evaluate();
			} else
				case_done(in ? (const char *)in :
					       "connection error");
		}
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!cli.done) {
			cli.done = 1;
			case_done("closed without completing");
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * /who: done with the request headers at once, then names the user basic
 * auth accepted
 */
static int
callback_who(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	const char *u;
	char body[64];

	if (reason != LWS_CALLBACK_HTTP)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	if (lws_http_headers_detach(wsi))
		return -1;

	u = lws_http_basic_auth_user(wsi);
	lws_snprintf(body, sizeof(body), "who=%s", u ? u : "(nobody)");

	if (lws_return_http_status(wsi, HTTP_STATUS_OK, body) ||
	    lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}

/*
 * protocols[0] on the server vhosts: the dummy callback, which also does the
 * proxying, except that it refuses a ws upgrade to /proxied/refuse.  There is
 * no local ws protocol for a proxied upgrade, so it is the protocol asked.
 */
static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	      void *in, size_t len)
{
	char *uri;
	int ul;

	if (reason == LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION &&
	    lws_http_get_uri_and_method(wsi, &uri, &ul) >= 0 &&
	    strstr(uri, "/refuse")) {
		lwsl_user("%s: refusing ws upgrade to %s\n", __func__, uri);
		return 1;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

#if defined(LWS_ROLE_WS)

struct pss_ba_ws {
	char		msg[64];
	char		sent;
};

/*
 * The ws protocol, on the server vhosts and on the backend: once established,
 * says which it is and the user basic auth accepted for the upgrade
 */
static int
callback_ba_ws(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	       void *in, size_t len)
{
	struct pss_ba_ws *pss = (struct pss_ba_ws *)user;
	uint8_t buf[LWS_PRE + sizeof(pss->msg)];
	const char *u;
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		u = lws_http_basic_auth_user(wsi);
		lws_snprintf(pss->msg, sizeof(pss->msg), "%s user=%s",
			     lws_get_vhost(wsi) == vh_backend ? "backend" :
								"front",
			     u ? u : "(nobody)");
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (pss->sent)
			break;
		pss->sent = 1;
		n = strlen(pss->msg);
		memcpy(buf + LWS_PRE, pss->msg, n);
		if (lws_write(wsi, buf + LWS_PRE, n, LWS_WRITE_TEXT) < (int)n)
			return -1;
		break;

	default:
		break;
	}

	return 0;
}

/* the ws protocol needs the login file too, for the front vhosts only */

static const struct lws_protocol_vhost_options pvo_ba_ws_auth = {
	NULL, NULL, "basic-auth", "./basic-auth.txt"
}, pvo_ba_ws = {
	NULL, &pvo_ba_ws_auth, "ba-ws", ""
};

#define BA_WS_PROTOCOL \
	{ "ba-ws", callback_ba_ws, sizeof(struct pss_ba_ws), 0, 0, NULL, 0 }, \
	{ "ba-ws-open", callback_ba_ws, sizeof(struct pss_ba_ws), 0, 0, NULL, 0 },
#else
#define BA_WS_PROTOCOL
#endif

static const struct lws_protocols protocols_srv[] = {
	{ "http", callback_http, 0, 0, 0, NULL, 0 },
	{ "who", callback_who, 0, 0, 0, NULL, 0 },
	BA_WS_PROTOCOL
	LWS_PROTOCOL_LIST_TERM
};

#if defined(BA_WS_PROXY)
static const struct lws_protocols protocols_backend[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	BA_WS_PROTOCOL
	LWS_PROTOCOL_LIST_TERM
};
#endif

static const struct lws_protocols protocols_cli[] = {
	{ "cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	const struct xcase *c;

	if (++cur == (int)LWS_ARRAY_SIZE(cases)) {
		lwsl_user("--- all cases passed ---\n");
		result = 0;
		lws_default_loop_exit(context);
		return;
	}
	c = &cases[cur];
	memset(&cli, 0, sizeof(cli));

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.path			= c->path;
	if (is_ws(c))
		/* a ws upgrade, offering the case's protocol */
		i.protocol	= c->ws_pcol;
	else {
		i.method	= "GET";
		i.protocol	= "cli";
	}
	i.local_protocol_name	= "cli";

	switch (c->xport) {
	case XP_H1:
		i.port = port_h1;
		break;
#if defined(LWS_WITH_HTTP2)
	case XP_H2C:
		i.port = port_h2c;
		i.ssl_connection = LCCSCF_H2_PRIOR_KNOWLEDGE;
		break;
#if defined(LWS_WITH_TLS)
	case XP_H2_TLS:
		i.port = port_tls;
		i.alpn = "h2";
		i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
		break;
#endif
#endif
#if defined(LWS_ROLE_H3)
	case XP_H3:
		i.port = port_h3;
		i.alpn = "h3";
		i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
		break;
#endif
	default:
		break;
	}

	i.opaque_user_data	= (void *)&cases[cur];

	if (!lws_client_connect_via_info(&i))
		case_done("connect failed");
}

static void
sul_watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("--- timed out in case %d ---\n", cur);
	lws_default_loop_exit(context);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

#if defined(LWS_ROLE_H3)
/*
 * The quic listener, on udp.  "localhost" is both 127.0.0.1 and ::1, and a
 * client may try either first: on FreeBSD, ::1.  A udp socket bound to the
 * name gets only its first address, so a client trying the other relies on
 * an ICMP port unreachable to move on, which can be lost, or not sent when
 * the kernel rate limits them under parallel tests.  So for "localhost",
 * listen on both.
 */
static int
quic_listen(struct lws_vhost *vh, int port, const char *protocol)
{
	static const char * const lo[] = {
#if defined(LWS_WITH_IPV4)
		"127.0.0.1",
#endif
#if defined(LWS_WITH_IPV6)
		"::1",
#endif
	};
	size_t n;

	if (!vh)
		return 1;

	if (strcmp(server_addr, "localhost"))
		return !lws_create_adopt_udp(vh, server_addr, port,
					     LWS_CAUDP_BIND, protocol, NULL,
					     NULL, NULL, NULL, "quic_listen");

	for (n = 0; n < LWS_ARRAY_SIZE(lo); n++)
		if (!lws_create_adopt_udp(vh, lo[n], port, LWS_CAUDP_BIND,
					  protocol, NULL, NULL, NULL, NULL,
					  "quic_listen"))
			return 1;

	return 0;
}
#endif

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_h1 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--h2c-port")))
		port_h2c = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--tls-port")))
		port_tls = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--h3-port")))
		port_h3 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;
	if ((p = lws_cmdline_option(argc, argv, "--backend-port")))
		port_backend = atoi(p);

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: http basic auth\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
#if defined(LWS_WITH_TLS)
	info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
#endif

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

#if defined(BA_WS_PROXY)
	/*
	 * The backend /proxied proxies to: a ws protocol and no auth of its
	 * own, so only the proxy's gates stand in front of it.  The proxy
	 * takes no ipv6 literal for its origin host.
	 */
	info.port = port_backend;
	info.vhost_name = "backend";
	info.protocols = protocols_backend;
	vh_backend = lws_create_vhost(context, &info);
	if (!vh_backend)
		goto bail;
	lws_snprintf(origin_backend, sizeof(origin_backend), "%s:%d/",
		     strchr(server_addr, ':') ? "localhost" : server_addr,
		     port_backend);
#endif

	info.protocols = protocols_srv;
	info.mounts = &mount;
#if defined(LWS_ROLE_WS)
	info.pvo = &pvo_ba_ws;
#endif

	info.port = port_h1;
	info.vhost_name = "srv-h1";
	if (!lws_create_vhost(context, &info))
		goto bail;

#if defined(LWS_WITH_HTTP2)
	info.port = port_h2c;
	info.vhost_name = "srv-h2c";
	info.options |= LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
	if (!lws_create_vhost(context, &info))
		goto bail;
	info.options &= ~(uint64_t)LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
#endif

#if defined(LWS_WITH_TLS)
	info.server_ssl_cert_mem = test_cert;
	info.server_ssl_cert_mem_len = (unsigned int)strlen(test_cert);
	info.server_ssl_private_key_mem = test_key;
	info.server_ssl_private_key_mem_len = (unsigned int)strlen(test_key);

#if defined(LWS_WITH_HTTP2)
	info.port = port_tls;
	info.vhost_name = "srv-tls";
	if (!lws_create_vhost(context, &info))
		goto bail;
#endif

#if defined(LWS_ROLE_H3)
	{
		struct lws_vhost *vh;

		/* a quic listener on udp only */
		info.port = CONTEXT_PORT_NO_LISTEN_SERVER;
		info.vhost_name = "srv-h3";
		info.listen_accept_role = "quic";
		info.listen_accept_protocol = "http";
		info.alpn = "h3";
		vh = lws_create_vhost(context, &info);
		if (!vh || quic_listen(vh, port_h3, "http"))
			goto bail;
		info.listen_accept_role = NULL;
		info.listen_accept_protocol = NULL;
		info.alpn = NULL;
	}
#endif
	info.server_ssl_cert_mem = NULL;
	info.server_ssl_cert_mem_len = 0;
	info.server_ssl_private_key_mem = NULL;
	info.server_ssl_private_key_mem_len = 0;
#endif

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.mounts = NULL;
	info.pvo = NULL;
	info.protocols = protocols_cli;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli)
		goto bail;

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
	lws_sul_schedule(context, 0, &sul_watchdog, sul_watchdog_cb,
			 50 * LWS_US_PER_SEC);

	while (n >= 0)
		n = lws_service(context, 0);

bail:
	if (cur < 0)
		lwsl_err("--- setup failed ---\n");
	lws_sul_cancel(&sul_watchdog);
	lws_context_destroy(context);
	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
