/*
 * lws-api-test-quic-next-address
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A quic client is aimed at one of the addresses its peer's name resolves
 * to.  If that address refuses it, with an ICMP port unreachable, before
 * anything came back from it, the peer is not there: the client must move on
 * to the next address at once, as a refused tcp connect does, rather than
 * retransmit into nothing until its handshake times out, or on h3, until its
 * grace gives up on quic.
 *
 * The h3 server in this process listens on one literal address only, --bind,
 * "::1" or "127.0.0.1", and the client asks for "localhost", which resolves
 * to both.  Which of them the client tries first is the platform's and the
 * routing table's choice: ctest runs the test once for each, so that one of
 * them always has the client refused first.  Either way the request must be
 * served over h3, with no fallback to tcp, inside a second and a half, less
 * than the h3 grace, and so well before any retransmission to the refusing
 * address could have helped.
 *
 * A host with no ipv6 loopback can't bind "::1": the test is skipped there.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define QNA_TIMEOUT_S	10
#define QNA_WITHIN_MS	1500
#define QNA_SKIP	77

static struct lws_context *context;
static lws_sorted_usec_list_t sul_watchdog;
static lws_usec_t us_start, us_done;
static char body[64];
static size_t body_len;
static int port = 7695, completed, timed_out;

struct pss_srv {
	char		resp[LWS_PRE + 16];
	size_t		resp_len;
};

/* the server */

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t hdr[LWS_PRE + 256], *start = &hdr[LWS_PRE], *p = start,
		*end = &hdr[sizeof(hdr) - 1];

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		pss->resp_len = (size_t)lws_snprintf(&pss->resp[LWS_PRE],
				sizeof(pss->resp) - LWS_PRE, "served");

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

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 256], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (len > sizeof(body) - 1 - body_len)
			len = sizeof(body) - 1 - body_len;
		memcpy(body + body_len, in, len);
		body_len += len;
		body[body_len] = '\0';
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		us_done = lws_now_usecs();
		completed = 1;
		lws_default_loop_exit(context);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: connection error: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		lws_default_loop_exit(context);
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		lws_default_loop_exit(context);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "qna", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "qna", callback_cli, 0, 0, 0, NULL, 0 },
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
	const char *p, *cert = NULL, *key = NULL, *bind_ads = "::1",
		   *ads = "localhost";
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	struct lws_vhost *vh;
	int result = 1;

	if (lws_cmdline_option(argc, argv, "--help")) {
		lwsl_user("%s [-p <port>] --cert <file> --key <file> "
			  "[--bind <literal>] [--address <name>] [-d <level>]\n"
			  "  --bind: the server's only quic address (::1)\n"
			  "  --address: what the client asks for (localhost)\n",
			  argv[0]);
		return 0;
	}

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");
	if ((p = lws_cmdline_option(argc, argv, "--bind")))
		bind_ads = p;
	if ((p = lws_cmdline_option(argc, argv, "--address")))
		ads = p;

	if (!cert || !key) {
		lwsl_err("--cert and --key are required\n");
		return 1;
	}

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: quic moves on from a refusing address, "
		  "server on %s, client to %s\n", bind_ads, ads);

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the h3 server, on a quic listener bound to one literal address */

	info.port			= CONTEXT_PORT_NO_LISTEN_SERVER;
	info.vhost_name			= "srv";
	info.protocols			= protocols_srv;
	info.listen_accept_role		= "quic";
	info.listen_accept_protocol	= "qna";
	info.alpn			= "h3";
	info.ssl_cert_filepath		= cert;
	info.ssl_private_key_filepath	= key;

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create the server vhost\n");
		goto bail;
	}

	if (!lws_create_adopt_udp(vh, bind_ads, port, LWS_CAUDP_BIND, "qna",
				  NULL, NULL, NULL, NULL, "quic_listen")) {
		lwsl_user("Unable to bind %s: skipped\n", bind_ads);
		result = QNA_SKIP;
		goto bail;
	}

	info.listen_accept_role		= NULL;
	info.listen_accept_protocol	= NULL;
	info.alpn			= NULL;
	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;

	/* the client */

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.vhost_name			= "cli";
	info.protocols			= protocols_cli;
	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create the client vhost\n");
		goto bail;
	}

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh;
	i.address		= ads;
	i.host			= ads;
	i.origin		= ads;
	i.port			= port;
	i.path			= "/";
	i.method		= "GET";
	i.protocol		= "qna";
	i.alpn			= "h3";
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	/* served over h3, or not at all: there is no tcp server */
	i.disable_h3_fallback	= 1;

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 QNA_TIMEOUT_S * LWS_US_PER_SEC);

	us_start = lws_now_usecs();
	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("The connection could not be started\n");
		goto bail;
	}

	while (lws_service(context, 0) >= 0)
		;

	if (timed_out)
		lwsl_err("FAIL: not served inside %ds\n", QNA_TIMEOUT_S);
	else if (!completed || strcmp(body, "served"))
		lwsl_err("FAIL: not served ('%s')\n", body);
	else if (us_done - us_start > QNA_WITHIN_MS * LWS_US_PER_MS)
		lwsl_err("FAIL: served after %dms, want inside %dms\n",
			 (int)((us_done - us_start) / LWS_US_PER_MS),
			 QNA_WITHIN_MS);
	else {
		lwsl_user("served over h3 in %dms\n",
			  (int)((us_done - us_start) / LWS_US_PER_MS));
		result = 0;
	}

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", !result ? "PASS" :
				    (result == QNA_SKIP ? "SKIP" : "FAIL"));

	return result;
}
