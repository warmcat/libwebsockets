/*
 * lws-api-test-tls-renew
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An lws client and an lws tls server in one process confirm a server
 * vhost's tls ctx made by lws_tls_cert_updated() is set up like the one it
 * got when it was created: the tls backends keep things like the alpn and
 * the client-cert policy on the ctx, not the vhost.
 *
 * The server vhost is created with LWS_SERVER_OPTION_IGNORE_MISSING_CERT and
 * a cert path that does not exist, the way a vhost waiting for its first
 * ACME cert is, so it comes up with no ctx at all.  Then:
 *
 *  - the cert "arrives", lws_tls_cert_updated() makes the vhost's first ctx,
 *    and an h2 request to it must be served over h2
 *  - the cert is renewed, lws_tls_cert_updated() makes a replacement ctx,
 *    and an h2 request must again be served over h2
 *
 * The cert is handed over in memory, the paths only select the vhost.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#define CASE_TIMEOUT_S	20
#define PEM_MAX		8192

static const char * const cases[] = {
	"the first cert arrived",
	"the cert was renewed",
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static const char *server_addr = "localhost", *certs = ".";
static char pem_cert[PEM_MAX], pem_key[PEM_MAX];
static char cert_path[256], key_path[256];
static size_t pem_cert_len, pem_key_len;
static int port = 7681, cur = -1, failures, result = 1;
static char case_over, on_h2;

static void next_case(lws_sorted_usec_list_t *sul);

static void
case_finish(const char *why)
{
	if (case_over)
		return;
	case_over = 1;
	lws_sul_cancel(&sul_watchdog);

	if (!why && !on_h2)
		why = "the request was not served over h2";

	if (why) {
		lwsl_err("case %d (%s): FAIL: %s\n", cur, cases[cur], why);
		failures++;
	} else
		lwsl_user("case %d (%s): PASS\n", cur, cases[cur]);

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
		*end = &hdr[sizeof(hdr) - 1], body[LWS_PRE + 2];

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain", 2, &p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return -1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		memcpy(&body[LWS_PRE], "ok", 2);
		if (lws_write(wsi, &body[LWS_PRE], 2, LWS_WRITE_HTTP_FINAL) != 2)
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
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		/*
		 * over h2 the request is a stream of a network connection; if
		 * the server offered no alpn, it went over h1 on its own
		 */
		on_h2 = lws_get_network_wsi(wsi) != wsi;
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		case_finish(lws_http_client_http_response(wsi) == 200 ? NULL :
			    "the server did not answer 200");
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (const char *)in : "(null)");
		case_finish("connection error");
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		case_finish("closed before it completed");
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

	lwsl_user("=== case %d: %s ===\n", cur, cases[cur]);

	case_over = 0;
	on_h2 = 0;

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 CASE_TIMEOUT_S * LWS_US_PER_SEC);

	/* the vhost using these paths gets a new ctx with this cert */

	if (lws_tls_cert_updated(context, cert_path, key_path,
				 pem_cert, pem_cert_len,
				 pem_key, pem_key_len)) {
		case_finish("lws_tls_cert_updated() failed");
		return;
	}

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= "short.example";
	i.origin		= "short.example";
	i.port			= port;
	i.path			= "/";
	i.method		= "GET";
	i.protocol		= "renew";
	i.alpn			= "h2";
	i.opaque_user_data	= (void *)(intptr_t)(cur + 1);
	i.ssl_connection	= LCCSCF_USE_SSL;

	if (!lws_client_connect_via_info(&i))
		case_finish("the connection could not be started");
}

static const struct lws_protocols protocols_srv[] = {
	{ "renew", callback_srv, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "renew", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

static int
load_pem(const char *name, char *buf, size_t *len)
{
	char path[256];
	int n;

	lws_snprintf(path, sizeof(path), "%s/%s", certs, name);
	n = lws_plat_read_file(path, buf, PEM_MAX - 1);
	if (n <= 0 || n >= PEM_MAX - 1) {
		lwsl_err("%s: can't read %s\n", __func__, path);
		return 1;
	}
	buf[n] = '\0';
	*len = (size_t)n;

	return 0;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	char ca[256];
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

	if (load_pem("server.crt", pem_cert, &pem_cert_len) ||
	    load_pem("server.key", pem_key, &pem_key_len))
		return 1;

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: tls ctx made by lws_tls_cert_updated()\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/*
	 * The server vhost, whose cert is not there yet: paths nothing is
	 * at, so it comes up without a tls ctx.  Its alpn is the build's
	 * default, which has h2 in it
	 */

	lws_snprintf(cert_path, sizeof(cert_path), "%s/not-yet/server.crt",
		     certs);
	lws_snprintf(key_path, sizeof(key_path), "%s/not-yet/server.key",
		     certs);

	info.port			= port;
	info.vhost_name			= "srv";
	info.protocols			= protocols_srv;
	info.ssl_cert_filepath		= cert_path;
	info.ssl_private_key_filepath	= key_path;
	info.options			|= LWS_SERVER_OPTION_IGNORE_MISSING_CERT;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create the server vhost\n");
		goto bail;
	}

	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;
	info.options			&= ~(uint64_t)
					LWS_SERVER_OPTION_IGNORE_MISSING_CERT;

	/* the client vhost, trusting ca.crt, no listener */

	lws_snprintf(ca, sizeof(ca), "%s/ca.crt", certs);

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
