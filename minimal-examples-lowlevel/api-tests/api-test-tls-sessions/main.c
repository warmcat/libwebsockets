/*
 * lws-api-test-tls-sessions
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An lws client and an lws tls server in one process confirm how the
 * client's tls session cache names the sessions it keeps.
 *
 * A session is cached under a tag made from the client vhost's name, the
 * host and the port, and a later connection resumes the session cached under
 * its own tag... skipping the server certificate check, since a resumed
 * handshake carries no certificate.  So the tag must identify the host
 * exactly: a host name too long for the tag must not be cached at all,
 * rather than under a truncated tag that another host sharing its beginning
 * would find.
 *
 * The server's cert, signed by ca.crt, which the client trusts, is valid for
 * short.example and for a 99-character name.  The client makes a fully
 * verified connection to each, by name, and afterwards:
 *
 *  - short.example: a session is cached for it, so the cache is in play
 *  - the long name: no session is cached for it, and none for another name
 *    with the same first 91 characters either
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#define CASE_TIMEOUT_S	20

/* the first 91 characters of both long names, which is all a tag holds */
#define LONG_PREFIX "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa." \
		    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

static const struct {
	const char	*host;		/* the name the client connects to */
	const char	*other;		/* another name that must not see it */
	char		cached;		/* is a session expected to be cached */
} cases[] = {
	{ "short.example",		NULL,			1 },
	{ LONG_PREFIX ".example",	LONG_PREFIX ".sample",	0 },
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static const char *server_addr = "localhost", *certs = ".";
static int port = 7681, cur = -1, failures, result = 1;
static char case_over, completed;

static void next_case(lws_sorted_usec_list_t *sul);

static int
count_save(struct lws_context *cx, struct lws_tls_session_dump *info)
{
	(*(int *)info->opaque)++;

	return 0;
}

/* how many sessions lws would hand the app for host (0 or 1) */

static int
cached(const char *host)
{
	int saves = 0;

	if (lws_tls_session_dump_save(vh_cli, host, (uint16_t)port,
				      count_save, &saves))
		return 0;

	return saves;
}

static void
case_finish(const char *why)
{
	int n;

	if (case_over)
		return;
	case_over = 1;
	lws_sul_cancel(&sul_watchdog);

	if (!why && !completed)
		why = "the request did not complete";

	if (!why) {
		n = cached(cases[cur].host);
		if (n != cases[cur].cached) {
			lwsl_err("%s: %d sessions cached, expected %d\n",
				 cases[cur].host, n, cases[cur].cached);
			why = "wrong sessions cached";
		} else if (cases[cur].other && cached(cases[cur].other)) {
			lwsl_err("%s: found a session for %s\n",
				 cases[cur].other, cases[cur].host);
			why = "a session was found for another host";
		}
	}

	if (why) {
		lwsl_err("case %d (%s): FAIL: %s\n", cur, cases[cur].host, why);
		failures++;
	} else
		lwsl_user("case %d (%s): PASS\n", cur, cases[cur].host);

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	case_finish("the case did not complete in time");
}

/* the server */

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	uint8_t hdr[LWS_PRE + 256], *start = &hdr[LWS_PRE], *p = start,
		*end = &hdr[sizeof(hdr) - 1];

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain", 0, &p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return -1;
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
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 256], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	/* only the current case's connection has anything to say */

	if (cur < 0 || (intptr_t)lws_get_opaque_user_data(wsi) != cur + 1)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		completed = lws_http_client_http_response(wsi) == 200;
		case_finish(completed ? NULL : "the server did not answer 200");
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (const char *)in : "(null)");
		case_finish("connection error");
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		case_finish(NULL);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	if (++cur >= (int)LWS_ARRAY_SIZE(cases)) {
		result = !!failures;
		lws_default_loop_exit(context);
		return;
	}

	lwsl_user("=== case %d: %s ===\n", cur, cases[cur].host);

	case_over = 0;
	completed = 0;

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 CASE_TIMEOUT_S * LWS_US_PER_SEC);

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= cases[cur].host;
	i.origin		= cases[cur].host;
	i.port			= port;
	i.path			= "/";
	i.method		= "GET";
	i.protocol		= "sessions";
	i.alpn			= "http/1.1";
	i.opaque_user_data	= (void *)(intptr_t)(cur + 1);
	/* fully verified: only such sessions are cached under the plain tag */
	i.ssl_connection	= LCCSCF_USE_SSL;

	if (!lws_client_connect_via_info(&i))
		case_finish("the connection could not be started");
}

static const struct lws_protocols protocols_srv[] = {
	{ "sessions", callback_srv, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "sessions", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	char ca[256], srv_cert[256], srv_key[256];
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* a listener and both ends of the connections */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "-s")))
		server_addr = p;
	if ((p = lws_cmdline_option(argc, argv, "--certs")))
		certs = p;

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: tls session cache tags\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	lws_snprintf(srv_cert, sizeof(srv_cert), "%s/server.crt", certs);
	lws_snprintf(srv_key, sizeof(srv_key), "%s/server.key", certs);
	lws_snprintf(ca, sizeof(ca), "%s/ca.crt", certs);

	/* the tls server vhost, h1 only: the client asks for http/1.1 */

	info.port			= port;
	info.vhost_name			= "srv";
	info.protocols			= protocols_srv;
	info.ssl_cert_filepath		= srv_cert;
	info.ssl_private_key_filepath	= srv_key;
	info.alpn			= "http/1.1";

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create the server vhost\n");
		goto bail;
	}

	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;
	info.alpn			= NULL;

	/* the client vhost, trusting ca.crt, no listener */

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.vhost_name			= "cli";
	info.protocols			= protocols_cli;
	info.client_ssl_ca_filepath	= ca;

	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create the client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);

	while (n >= 0)
		n = lws_service(context, 0);

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_context_destroy(context);

	lwsl_user("Completed: %s (%d of %d cases failed)\n",
		  result ? "FAIL" : "PASS", failures,
		  (int)LWS_ARRAY_SIZE(cases));

	return result;
}
