/*
 * lws-api-test-log-redact
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Logs outlive the connection and reach a wider audience than the owner of
 * what passes through it, so credentials must never be written to them, at
 * any log level.  This captures every log line lws emits, at every level,
 * through a custom emit function, while it carries known secrets, and fails
 * if any of them shows up.
 *
 *  --case h1 / h2 / h3: an in-process client sends Authorization, Cookie and
 *    X-Api-Key (a name lws has no token for) to an in-process server over
 *    that protocol.  The server checks each arrived intact.  On h2 the
 *    client sends two requests on one connection: the first adds the cookie
 *    to the HPACK dynamic table, the second sends it as an index into it,
 *    so the server's indexed-header path is covered too (G-350).
 *
 *  --case redirect: the h1 client is redirected to a Location whose query
 *    carries an OAuth-style code=, and follows it (G-351).
 *
 *  --case pem: lws_tls_alloc_pem_to_der_file() converts the PEM private
 *    key, from memory and from the file (G-349).
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#if !defined(WIN32)
#include <unistd.h>
#endif

#define LRD_TIMEOUT_S	10

/*
 * Each secret carries a marker of its own, that must never appear in a log
 * line.  The markers are short, so that a hexdump (16 bytes a line) is
 * likely to show one whole
 */
#define LRD_M_AUTH	"LwsRdAuth7Q2x"
#define LRD_M_COOKIE	"LwsRdCook9K4m"
#define LRD_M_APIKEY	"LwsRdApik3Z8p"
#define LRD_M_QUERY	"LwsRdQury5T1w"

static const char lrd_auth[]	= "Bearer " LRD_M_AUTH "-0123456789",
		  lrd_cookie[]	= "sid=" LRD_M_COOKIE "-0123456789abcdef",
		  lrd_apikey[]	= LRD_M_APIKEY "-0123456789",
		  lrd_landing[]	= "/landing?code=" LRD_M_QUERY "&state=1";

/* plus, for --case pem, four 16-byte pieces of the key's base64 body */
#define LRD_PEM_MARKS	4
static char lrd_pem_mark[LRD_PEM_MARKS][17];

static const char * const lrd_markers[] = {
	LRD_M_AUTH, LRD_M_COOKIE, LRD_M_APIKEY, LRD_M_QUERY
};

enum {
	LRD_H1,
	LRD_H2,
	LRD_H3,
	LRD_REDIRECT,
	LRD_PEM,
};

static const struct lrd_case {
	const char	*name;
	const char	*alpn;
	const char	*path;
	int		requests;	/* client transactions to complete */
} lrd_cases[] = {
	[LRD_H1]	= { "h1",	"http/1.1",	"/creds",	1 },
	[LRD_H2]	= { "h2",	"h2",		"/creds",	2 },
	[LRD_H3]	= { "h3",	"h3",		"/creds",	1 },
	[LRD_REDIRECT]	= { "redirect",	"http/1.1",	"/redir",	1 },
	[LRD_PEM]	= { "pem",	NULL,		NULL,		0 },
};

static struct lws_context *context;
static lws_sorted_usec_list_t sul_watchdog, sul_next;
static struct lws_vhost *vh_cli;
static const struct lrd_case *tc;
static int port = 7700, timed_out, failed, leaks, lines, creds_ok, landed,
	   done, started;

/* the emit function every log line goes through */

static void
lrd_emit(int level, const char *line)
{
	size_t n;

	lines++;

	for (n = 0; n < LWS_ARRAY_SIZE(lrd_markers); n++)
		if (strstr(line, lrd_markers[n]))
			goto leak;

	for (n = 0; n < LRD_PEM_MARKS; n++)
		if (lrd_pem_mark[n][0] && strstr(line, lrd_pem_mark[n]))
			goto leak;

	/* pass on only what a default log level shows */
	if (level & (LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_USER))
		lwsl_emit_stderr(level, line);

	return;

leak:
	leaks++;
	fprintf(stderr, "LEAKED at log level 0x%x: %s", level, line);
}

/* the server */

struct pss_srv {
	char		resp[LWS_PRE + 16];
	size_t		resp_len;
};

static int
lrd_hdr_is(struct lws *wsi, enum lws_token_indexes tok, const char *want)
{
	char v[128];

	return lws_hdr_copy(wsi, v, sizeof(v), tok) == (int)strlen(want) &&
	       !strcmp(v, want);
}

static int
lrd_creds_arrived(struct lws *wsi)
{
#if defined(LWS_WITH_CUSTOM_HEADERS)
	char v[128];

	if (lws_hdr_custom_copy(wsi, v, sizeof(v), "x-api-key:", 10) !=
						(int)strlen(lrd_apikey) ||
	    strcmp(v, lrd_apikey)) {
		lwsl_user("%s: x-api-key did not arrive intact\n", __func__);
		return 0;
	}
#endif

	if (!lrd_hdr_is(wsi, WSI_TOKEN_HTTP_AUTHORIZATION, lrd_auth) ||
	    !lrd_hdr_is(wsi, WSI_TOKEN_HTTP_COOKIE, lrd_cookie)) {
		lwsl_user("%s: authorization or cookie did not arrive "
			  "intact\n", __func__);
		return 0;
	}

	return 1;
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t hdr[LWS_PRE + 384], *start = &hdr[LWS_PRE], *p = start,
		*end = &hdr[sizeof(hdr) - 1];
	char v[64];

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		if (!strcmp((const char *)in, "/redir")) {
			if (lws_http_redirect(wsi, HTTP_STATUS_FOUND,
					      (const uint8_t *)lrd_landing,
					      (int)strlen(lrd_landing),
					      &p, end) < 0)
				return -1;

			return lws_http_transaction_completed(wsi) ? -1 : 0;
		}

		if (!strcmp((const char *)in, "/landing")) {
			if (lws_get_urlarg_by_name_safe(wsi, "code", v,
							(int)sizeof(v)) ==
						(int)strlen(LRD_M_QUERY) &&
			    !strcmp(v, LRD_M_QUERY))
				landed++;
		} else
			creds_ok += lrd_creds_arrived(wsi);

		pss->resp_len = 2;
		memcpy(&pss->resp[LWS_PRE], "ok", 2);

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain",
						(lws_filepos_t)pss->resp_len,
						&p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
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

/*
 * HPACK (RFC 7541 6.2.1): a literal field with incremental indexing and a
 * literal name, so it goes in the server's dynamic table at index 62, the
 * first dynamic index, since the lws h2 client indexes nothing itself...
 */

static int
lrd_h2_cookie_indexed(unsigned char **p, unsigned char *end)
{
	size_t vl = strlen(lrd_cookie);

	if (vl > 126 || lws_ptr_diff_size_t(end, *p) < 3 + 6 + vl)
		return 1;

	*(*p)++ = 0x40;
	*(*p)++ = 6;
	memcpy(*p, "cookie", 6);
	*p += 6;
	*(*p)++ = (unsigned char)vl;
	memcpy(*p, lrd_cookie, vl);
	*p += vl;

	return 0;
}

/* ... and an indexed field (6.1) naming that entry */

static int
lrd_h2_cookie_by_index(unsigned char **p, unsigned char *end)
{
	if (*p >= end)
		return 1;

	*(*p)++ = 0x80 | 62;

	return 0;
}

static int
lrd_append_creds(struct lws *wsi, unsigned char **p, unsigned char *end)
{
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_AUTHORIZATION,
					 (const unsigned char *)lrd_auth,
					 (int)strlen(lrd_auth), p, end) ||
	    lws_add_http_header_by_name(wsi, (const unsigned char *)"x-api-key:",
					(const unsigned char *)lrd_apikey,
					(int)strlen(lrd_apikey), p, end))
		return 1;

	if (tc == &lrd_cases[LRD_H2])
		return started == 1 ? lrd_h2_cookie_indexed(p, end) :
				      lrd_h2_cookie_by_index(p, end);

	return lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_COOKIE,
					    (const unsigned char *)lrd_cookie,
					    (int)strlen(lrd_cookie), p, end);
}

static int
lrd_connect(void)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= "localhost";
	i.host			= i.address;
	i.origin		= i.address;
	i.port			= port;
	i.path			= tc->path;
	i.method		= "GET";
	i.protocol		= "lrd";
	i.alpn			= tc->alpn;
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK |
				  /* h2: the second request joins the first's
				   * connection, and so its HPACK state */
				  LCCSCF_PIPELINE;
	/* an h3 case must be decided on h3, not by a fallback to tcp */
	i.disable_h3_fallback	= 1;

	started++;

	return !lws_client_connect_via_info(&i);
}

static void
lrd_next_cb(lws_sorted_usec_list_t *sul)
{
	if (lrd_connect()) {
		failed = 1;
		lws_cancel_service(context);
	}
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 256], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		if (tc == &lrd_cases[LRD_REDIRECT])
			return 0;
		{
			unsigned char **p = (unsigned char **)in,
				      *end = (*p) + len;

			if (lrd_append_creds(wsi, p, end))
				return -1;
		}
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (++done == tc->requests)
			lws_cancel_service(context);
		else
			/* the next request, from outside this callback */
			lws_sul_schedule(context, 0, &sul_next,
					 lrd_next_cb, 1);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: connection error: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		failed = 1;
		lws_cancel_service(context);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "lrd", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "lrd", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	timed_out = 1;
	lws_cancel_service(context);
}

static void
sigint_handler(int sig)
{
	failed = 1;
	lws_cancel_service(context);
}

/*
 * Read the PEM key into a heap buffer, and take four 16-byte pieces of its
 * base64 body as markers.  Returns the buffer, or NULL.
 */

static char *
lrd_pem_load(const char *path, size_t *len)
{
	char *buf, *b, *e;
	ssize_t r;
	size_t n;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;

	buf = malloc(8192);
	if (!buf) {
		close(fd);
		return NULL;
	}

	r = read(fd, buf, 8191);
	close(fd);
	if (r <= 0) {
		free(buf);
		return NULL;
	}
	buf[r] = '\0';
	*len = (size_t)r;

	/* the body starts on the line after "-----BEGIN ..." */
	b = strchr(buf, '\n');
	e = strstr(buf, "-----END");
	if (!b || !e || e - ++b < LRD_PEM_MARKS * 16) {
		free(buf);
		return NULL;
	}

	for (n = 0; n < LRD_PEM_MARKS; n++) {
		memcpy(lrd_pem_mark[n], b + (n * 16), 16);
		lrd_pem_mark[n][16] = '\0';
		/* a line break inside a piece can't match a log line */
		if (strchr(lrd_pem_mark[n], '\n'))
			lrd_pem_mark[n][0] = '\0';
	}

	return buf;
}

static int
lrd_pem(const char *key)
{
	lws_filepos_t amount;
	uint8_t *der;
	size_t len;
	char *pem;

	pem = lrd_pem_load(key, &len);
	if (!pem || !lrd_pem_mark[0][0]) {
		lwsl_err("unable to read the key %s\n", key);
		free(pem);
		return 1;
	}

	/* from memory, then from the file */

	if (lws_tls_alloc_pem_to_der_file(context, NULL, pem,
					  (lws_filepos_t)len, &der, &amount)) {
		lwsl_err("FAIL: mem PEM did not convert\n");
		free(pem);
		return 1;
	}
	lws_realloc(der, 0, "lrd der");
	free(pem);

	if (lws_tls_alloc_pem_to_der_file(context, key, NULL, 0, &der,
					  &amount)) {
		lwsl_err("FAIL: file PEM did not convert\n");
		return 1;
	}
	lws_realloc(der, 0, "lrd der");

	return 0;
}

int main(int argc, const char **argv)
{
	const char *p, *cert = NULL, *key = NULL, *mode = NULL;
	struct lws_context_creation_info info;
	int result = 1;
	size_t n;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* a server and its client in one process */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");
	mode = lws_cmdline_option(argc, argv, "--case");

	for (n = 0; mode && n < LWS_ARRAY_SIZE(lrd_cases); n++)
		if (!strcmp(mode, lrd_cases[n].name))
			tc = &lrd_cases[n];

	if (!cert || !key || !tc) {
		lwsl_err("--cert, --key and --case h1|h2|h3|redirect|pem "
			 "are required\n");
		return 1;
	}

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: no secrets in logs, %s\n", mode);

	/*
	 * Every level, whatever -d said, through our emit function, and with
	 * no spew limiting, which would drop lines unseen
	 */
	lws_set_log_level(((1 << LLL_COUNT) - 1) | LLLF_LOG_SPEW_OFF,
			  lrd_emit);

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (tc == &lrd_cases[LRD_PEM]) {
		result = lrd_pem(key);
		goto bail;
	}

	info.port			= port;
	info.protocols			= protocols_srv;
	info.ssl_cert_filepath		= cert;
	info.ssl_private_key_filepath	= key;
	info.alpn			= "h2,http/1.1,h3";
	info.vhost_name			= "localhost";

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
			 LRD_TIMEOUT_S * LWS_US_PER_SEC);

	if (lrd_connect()) {
		lwsl_err("The connection could not be started\n");
		goto bail;
	}

	while (!timed_out && !failed && done < tc->requests &&
	       lws_service(context, 0) >= 0)
		;

	if (timed_out)
		lwsl_err("FAIL: timed out\n");
	else if (failed || done != tc->requests)
		lwsl_err("FAIL: %d of %d requests completed\n", done,
			 tc->requests);
	else if (tc == &lrd_cases[LRD_REDIRECT] && landed != 1)
		lwsl_err("FAIL: the redirect was not followed intact\n");
	else if (tc != &lrd_cases[LRD_REDIRECT] && creds_ok != tc->requests)
		lwsl_err("FAIL: credentials arrived intact on %d of %d "
			 "requests\n", creds_ok, tc->requests);
	else
		result = 0;

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_next);
	lws_context_destroy(context);

	/* the context destroy logs too: count leaks only now */
	if (leaks) {
		lwsl_err("FAIL: %d of %d log lines leaked a secret\n", leaks,
			 lines);
		result = 1;
	} else
		lwsl_user("%d log lines captured, no secret in any\n", lines);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
