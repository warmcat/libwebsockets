/*
 * lws-api-test-h3-client-auth
 *
 * Written in 2010 - 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * What the h3 client sends for the request besides what the caller asked
 * for: the answer to a digest challenge, and the cookies from its jar.  The
 * h1 and h2 clients always sent both, but the h3 client's request composer
 * sent neither, so a digest challenge over h3 was answered without its
 * Authorization, and a site's cookies never went back to it over h3.
 *
 * Both ends are in this process, on h3 only (no fallback to tcp).
 *
 *  --case digest: the client has credentials, and GETs /digest, which is
 *    answered 401 with a digest challenge unless it carries a digest
 *    Authorization for them.  It must end 200.
 *
 *  --case cookie: the client keeps cookies.  It GETs /set, answered with a
 *    Secure cookie, then makes a new connection to GET /check, which
 *    answers with the Cookie header it came with.  It must be the cookie.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>

#define H3CA_TIMEOUT_S		10
#define H3CA_USER		"h3user"
#define H3CA_COOKIE		"h3c=yum"
#define H3CA_CHALLENGE		"Digest realm=\"h3ca\", qop=\"auth\", " \
				"nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c0\""

struct pss_srv {
	char		resp[LWS_PRE + 128];
	size_t		resp_len;
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_watchdog;
static int port = 7790, timed_out, status, cookie_case, step;
static char body[128];
static size_t body_len;

/*
 * Keep what fits of in in buf, after the used bytes it already has, and keep
 * it NUL-terminated.  The rest is dropped: the cases' answers are short.
 */
static void
keep(char *buf, size_t size, size_t *used, const void *in, size_t len)
{
	if (*used >= size - 1)
		return;
	if (len > size - 1 - *used)
		len = size - 1 - *used;
	memcpy(buf + *used, in, len);
	*used += len;
	buf[*used] = '\0';
}

/* the server */

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t hdr[LWS_PRE + 512], *start = &hdr[LWS_PRE], *p = start,
		*end = &hdr[sizeof(hdr) - 1];
	const char *path = (const char *)in, *set = NULL;
	char auth[512], cookie[64];
	int code = HTTP_STATUS_OK;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		if (lws_hdr_copy(wsi, auth, sizeof(auth),
				 WSI_TOKEN_HTTP_AUTHORIZATION) < 0)
			auth[0] = '\0';
		if (lws_hdr_copy(wsi, cookie, sizeof(cookie),
				 WSI_TOKEN_HTTP_COOKIE) < 0)
			cookie[0] = '\0';

		/* what came, not the credentials themselves */
		lwsl_user("%s: %s, %s Authorization, %s Cookie\n", __func__,
			  path, strncmp(auth, "Digest ", 7) ? "no digest" :
							      "a digest",
			  cookie[0] ? "a" : "no");

		pss->resp_len = 0;
		if (!strcmp(path, "/digest")) {
			if (strncmp(auth, "Digest ", 7) ||
			    !strstr(auth, "username=\"" H3CA_USER "\""))
				code = HTTP_STATUS_UNAUTHORIZED;
			pss->resp_len = (size_t)lws_snprintf(&pss->resp[LWS_PRE],
					sizeof(pss->resp) - LWS_PRE, "%s",
					code == HTTP_STATUS_OK ? "digest" :
								 "who?");
		} else if (!strcmp(path, "/set")) {
			set = H3CA_COOKIE "; Path=/; Secure";
			pss->resp_len = (size_t)lws_snprintf(&pss->resp[LWS_PRE],
					sizeof(pss->resp) - LWS_PRE, "set");
		} else
			pss->resp_len = (size_t)lws_snprintf(&pss->resp[LWS_PRE],
					sizeof(pss->resp) - LWS_PRE,
					"cookie=%s", cookie);

		if (lws_add_http_common_headers(wsi, (unsigned int)code,
						"text/plain",
						(lws_filepos_t)pss->resp_len,
						&p, end))
			return -1;
		if (code == HTTP_STATUS_UNAUTHORIZED &&
		    lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_WWW_AUTHENTICATE,
				(unsigned char *)H3CA_CHALLENGE,
				(int)strlen(H3CA_CHALLENGE), &p, end))
			return -1;
		if (set && lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_SET_COOKIE, (unsigned char *)set,
				(int)strlen(set), &p, end))
			return -1;
		if (lws_finalize_write_http_header(wsi, start, &p, end))
			return -1;

		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss || !pss->resp_len)
			break;
		if (lws_write(wsi, (uint8_t *)&pss->resp[LWS_PRE],
			      pss->resp_len, LWS_WRITE_HTTP_FINAL) !=
							(int)pss->resp_len)
			return -1;
		pss->resp_len = 0;
		if (lws_http_transaction_completed(wsi))
			return -1;
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* the client */

static int
client_connect(const char *path)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= "127.0.0.1";
	/* the host the cookie jar sees, and the cert is for */
	i.host			= "localhost";
	i.origin		= i.host;
	i.port			= port;
	i.path			= path;
	i.method		= "GET";
	i.protocol		= "h3ca";
	i.alpn			= "h3";
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	/* it must be decided on h3, not by a fallback to tcp */
	i.disable_h3_fallback	= 1;

	if (cookie_case)
		i.ssl_connection |= LCCSCF_CACHE_COOKIES;
	else {
		i.auth_username	= H3CA_USER;
		i.auth_password	= "sesame"; /* NOSONAR: test fixture */
	}

	body_len = 0;
	body[0] = '\0';
	status = 0;

	return !lws_client_connect_via_info(&i);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 256], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		status = (int)lws_http_client_http_response(wsi);
		lwsl_user("%s: status %d\n", __func__, status);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		keep(body, sizeof(body), &body_len, in, len);
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		lwsl_user("%s: completed %d '%s'\n", __func__, status, body);
		if (cookie_case && !step++ && status == HTTP_STATUS_OK) {
			/* the jar has the cookie: a new connection gets it */
			if (client_connect("/check"))
				lws_default_loop_exit(context);
			break;
		}
		step = 2;
		lws_default_loop_exit(context);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: connection error: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		lws_default_loop_exit(context);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "h3ca", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "h3ca", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	timed_out = 1;
	lws_default_loop_exit(context);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	const char *p, *cert, *key, *mode, *jar = "./h3-client-auth-jar.txt";
	struct lws_context_creation_info info;
	int result = 1;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* listeners on tcp and udp, and both ends */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--jar")))
		jar = p;
	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");
	mode = lws_cmdline_option(argc, argv, "--case");

	if (!cert || !key || !mode ||
	    (strcmp(mode, "digest") && strcmp(mode, "cookie"))) {
		lwsl_err("--cert, --key and --case digest|cookie are "
			 "required\n");
		return 1;
	}
	cookie_case = !strcmp(mode, "cookie");
#if !defined(LWS_WITH_CACHE_NSCOOKIEJAR)
	if (cookie_case) {
		lwsl_err("--case cookie needs LWS_WITH_CACHE_NSCOOKIEJAR\n");
		return 1;
	}
#endif

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: h3 client %s\n", mode);

	/* start from an empty jar */
	remove(jar);

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
#if defined(LWS_WITH_CACHE_NSCOOKIEJAR)
	info.http_nsc_filepath = jar;
#endif

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the server: alpn naming h3 brings up a quic listener on its port */

	info.port			= port;
	info.protocols			= protocols_srv;
	info.ssl_cert_filepath		= cert;
	info.ssl_private_key_filepath	= key;
	info.alpn			= "h2,http/1.1,h3";
	info.vhost_name			= "srv";
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create the server vhost\n");
		goto bail;
	}

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;
	info.alpn			= NULL;
	info.vhost_name			= "cli";
	info.protocols			= protocols_cli;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create the client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 H3CA_TIMEOUT_S * LWS_US_PER_SEC);

	if (client_connect(cookie_case ? "/set" : "/digest")) {
		lwsl_err("The connection could not be started\n");
		goto bail;
	}

	while (lws_service(context, 0) >= 0)
		;

	if (timed_out)
		lwsl_err("FAIL: timed out\n");
	else if (step != 2 && cookie_case)
		lwsl_err("FAIL: the cookie wasn't set\n");
	else if (status != HTTP_STATUS_OK)
		lwsl_err("FAIL: ended %d, want 200\n", status);
	else if (strcmp(body, cookie_case ? "cookie=" H3CA_COOKIE : "digest"))
		lwsl_err("FAIL: body '%s'\n", body);
	else
		result = 0;

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_context_destroy(context);
	remove(jar);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
