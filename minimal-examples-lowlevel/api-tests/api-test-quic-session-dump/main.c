/*
 * lws-api-test-quic-session-dump
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An lws h3 server and lws quic clients in one process confirm that a quic
 * client session can be saved with lws_tls_session_dump_save_flags() and
 * loaded with lws_tls_session_dump_load_flags(), and that the next quic
 * connection resumes it and sends its request as 0-RTT early data.
 *
 * Quic sessions are cached apart from tls over tcp ones, so three client
 * vhosts, each with its own session cache, play the parts of a client before
 * and after a restart:
 *
 *  - cli1 makes a fully verified h3 connection.  Its session is then saved
 *    with LWS_TLS_SESSION_DUMP_F_QUIC, and nothing is found without the flag
 *
 *  - cli2 has the saved session loaded with LWS_TLS_SESSION_DUMP_F_QUIC: its
 *    h3 connection resumes it, and the server receives the request as 0-RTT
 *
 *  - cli3 has the same session loaded without the flag, as a tls over tcp
 *    session: its h3 connection must not resume it, nor send 0-RTT
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#define CASE_TIMEOUT_S	20
#define TEST_HOST	"short.example"

enum {
	CLI1,
	CLI2,
	CLI3,

	CLI_COUNT
};

static const struct {
	const char	*name;
	char		early;	/* must the request go out, and in, as 0-RTT */
} cases[] = {
	[CLI1] = { "cli1: first connection, session saved",		0 },
	[CLI2] = { "cli2: quic session loaded, resumed with 0-RTT",	1 },
	[CLI3] = { "cli3: loaded as a tcp session, not used by quic",	0 },
};

static struct lws_context *context;
static struct lws_vhost *vh_cli[CLI_COUNT];
static lws_sorted_usec_list_t sul_next, sul_watchdog, sul_save;
static const char *server_addr = "localhost", *certs = ".";
static int port = 7681, cur = -1, failures, result = 1;
static char case_over, completed, early_cb, srv_early;
static unsigned int status;

/* the session saved from cli1, as an app would keep it on disk */
static uint8_t saved[8192];
static size_t saved_len;

static void next_case(lws_sorted_usec_list_t *sul);

static int
save_cb(struct lws_context *cx, struct lws_tls_session_dump *info)
{
	if (info->blob_len > sizeof(saved))
		return 1;

	memcpy(saved, info->blob, info->blob_len);
	saved_len = info->blob_len;

	return 0;
}

static int
load_cb(struct lws_context *cx, struct lws_tls_session_dump *info)
{
	/* lws takes ownership of the blob and frees it */
	info->blob = malloc(saved_len);
	if (!info->blob)
		return 1;

	memcpy(info->blob, saved, saved_len);
	info->blob_len = saved_len;

	return 0;
}

static int
count_save(struct lws_context *cx, struct lws_tls_session_dump *info)
{
	(*(int *)info->opaque)++;

	return 0;
}

static void
case_finish(const char *why)
{
	if (case_over)
		return;
	case_over = 1;
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_save);

	if (!why && !completed)
		why = "the request did not complete";

	if (!why && early_cb != cases[cur].early)
		why = early_cb ? "the client offered 0-RTT" :
				 "the client did not offer 0-RTT";

	if (!why && srv_early != cases[cur].early)
		why = srv_early ? "the server received the request as 0-RTT" :
				  "the server did not receive the request "
				  "as 0-RTT";

	if (why) {
		lwsl_err("case %d (%s): FAIL: %s\n", cur, cases[cur].name, why);
		failures++;
	} else
		lwsl_user("case %d (%s): PASS\n", cur, cases[cur].name);

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	case_finish("the case did not complete in time");
}

/*
 * cli1's session is cached when its server cert has been accepted and the
 * server's NewSessionTicket has arrived after the handshake, which is not
 * ordered with the response: look for it until it is there
 */

static void
save_poll_cb(lws_sorted_usec_list_t *sul)
{
	int n = 0;

	if (lws_tls_session_dump_save_flags(vh_cli[CLI1], TEST_HOST,
					    (uint16_t)port,
					    LWS_TLS_SESSION_DUMP_F_QUIC,
					    save_cb, NULL)) {
		lws_sul_schedule(context, 0, &sul_save, save_poll_cb,
				 50 * LWS_US_PER_MS);
		return;
	}

	lwsl_user("%s: saved a %u-byte quic session\n", __func__,
		  (unsigned int)saved_len);

	/* the plain tag is tls over tcp's, which cli1 never used */

	if (!lws_tls_session_dump_save_flags(vh_cli[CLI1], TEST_HOST,
					     (uint16_t)port, 0, count_save,
					     &n) || n) {
		case_finish("the quic session was saved as a tcp one");
		return;
	}

	if (!lws_tls_session_dump_save_flags(vh_cli[CLI1], TEST_HOST,
					     (uint16_t)port, 1u << 7,
					     count_save, &n) || n) {
		case_finish("an unknown flag was accepted");
		return;
	}

	if (lws_tls_session_dump_load_flags(vh_cli[CLI2], TEST_HOST,
					    (uint16_t)port,
					    LWS_TLS_SESSION_DUMP_F_QUIC,
					    load_cb, NULL)) {
		case_finish("the quic session could not be loaded");
		return;
	}

	if (lws_tls_session_dump_load_flags(vh_cli[CLI3], TEST_HOST,
					    (uint16_t)port, 0, load_cb, NULL)) {
		case_finish("the session could not be loaded as a tcp one");
		return;
	}

	case_finish(NULL);
}

/* the server */

static const char body[] = "ok\n";

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	uint8_t hdr[LWS_PRE + 256], *start = &hdr[LWS_PRE], *p = start,
		*end = &hdr[sizeof(hdr) - 1], b[LWS_PRE + sizeof(body)];

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		/* the request arrived under the client's early data keys */
		srv_early = lws_tls_0rtt_status(wsi) ==
						LWS_0RTT_STATUS_ACCEPTED;

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain",
						sizeof(body) - 1, &p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return -1;

		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		memcpy(&b[LWS_PRE], body, sizeof(body) - 1);
		if (lws_write(wsi, &b[LWS_PRE], sizeof(body) - 1,
			      LWS_WRITE_HTTP_FINAL) != (int)sizeof(body) - 1)
			return -1;
		if (lws_http_transaction_completed(wsi))
			return -1;
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* the clients */

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
	case LWS_CALLBACK_CLIENT_ESTABLISHED_EARLY:
		/* a resumed session's early keys are up: send the request */
		early_cb = 1;
		return 1;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		status = lws_http_client_http_response(wsi);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (status != 200) {
			case_finish("the server did not answer 200");
			break;
		}
		completed = 1;
		if (cur == CLI1) {
			/* the case ends when the session is saved and loaded */
			lws_sul_schedule(context, 0, &sul_save, save_poll_cb,
					 1);
			break;
		}
		case_finish(NULL);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (const char *)in : "(null)");
		case_finish("connection error");
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

	if (failures) {
		/* the later cases need the session cli1 saved */
		lws_default_loop_exit(context);
		return;
	}

	lwsl_user("=== case %d: %s ===\n", cur, cases[cur].name);

	case_over = 0;
	completed = 0;
	early_cb = 0;
	srv_early = 0;
	status = 0;

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 CASE_TIMEOUT_S * LWS_US_PER_SEC);

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli[cur];
	i.address		= server_addr;
	i.host			= TEST_HOST;
	i.origin		= TEST_HOST;
	i.port			= port;
	i.path			= "/";
	i.method		= "GET";
	i.protocol		= "quic-sessions";
	i.alpn			= "h3";
	i.opaque_user_data	= (void *)(intptr_t)(cur + 1);
	/*
	 * Fully verified: only such sessions are visible to the dump apis.
	 * Every client is willing to send 0-RTT, so it is the session it
	 * finds that decides whether it does
	 */
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_EARLY_DATA;

	if (!lws_client_connect_via_info(&i))
		case_finish("the connection could not be started");
}

static const struct lws_protocols protocols_srv[] = {
	{ "quic-sessions", callback_srv, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "quic-sessions", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	char ca[256], srv_cert[256], srv_key[256], vhn[CLI_COUNT][8];
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
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
	lwsl_user("LWS API selftest: quic session dump and 0-RTT\n");

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

	/* the h3 server vhost: a quic listener on udp only, taking 0-RTT */

	info.port			= CONTEXT_PORT_NO_LISTEN_SERVER;
	info.vhost_name			= "srv-h3";
	info.protocols			= protocols_srv;
	info.listen_accept_role		= "quic";
	info.listen_accept_protocol	= "quic-sessions";
	info.alpn			= "h3";
	info.ssl_cert_filepath		= srv_cert;
	info.ssl_private_key_filepath	= srv_key;
	info.options		       |= LWS_SERVER_OPTION_ALLOW_EARLY_DATA;

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create the h3 server vhost\n");
		goto bail;
	}

	if (!lws_create_adopt_udp(vh, server_addr, port, LWS_CAUDP_BIND,
				  "quic-sessions", NULL, NULL, NULL, NULL,
				  "quic_listen")) {
		lwsl_err("Failed to bind the quic listener\n");
		goto bail;
	}

	info.options		       &= ~(uint64_t)
					LWS_SERVER_OPTION_ALLOW_EARLY_DATA;
	info.listen_accept_role		= NULL;
	info.listen_accept_protocol	= NULL;
	info.alpn			= NULL;
	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;

	/* the client vhosts, each with its own session cache, trusting ca.crt */

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.protocols			= protocols_cli;
	info.client_ssl_ca_filepath	= ca;

	for (n = 0; n < CLI_COUNT; n++) {
		lws_snprintf(vhn[n], sizeof(vhn[n]), "cli%d", n + 1);
		info.vhost_name = vhn[n];

		vh_cli[n] = lws_create_vhost(context, &info);
		if (!vh_cli[n]) {
			lwsl_err("Failed to create client vhost %s\n", vhn[n]);
			goto bail;
		}
	}

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);

	n = 0;
	while (n >= 0)
		n = lws_service(context, 0);

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_save);
	lws_context_destroy(context);

	lwsl_user("Completed: %s (%d of %d cases failed)\n",
		  result ? "FAIL" : "PASS", failures,
		  (int)LWS_ARRAY_SIZE(cases));

	return result;
}
