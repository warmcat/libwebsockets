/*
 * lws-minimal-http-client-openhitls-ssl-info-positive
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Verifies a successful OpenHiTLS HTTPS exchange while SSL info callbacks
 * are enabled on the vhost.  The server sends the response in multiple
 * writes so the client and server exercise buffered TLS read / write flow
 * before the connection closes cleanly.
 */

#include <libwebsockets.h>
#include <hitls_debug.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_TEST_PORT 7880
#define TEST_CA_CERT \
	"../minimal-http-client-openhitls-mtls-file-positive/mtls-file-ca.cert"
#define TEST_SERVER_CERT \
	"../minimal-http-client-openhitls-mtls-file-positive/mtls-file-server.cert"
#define TEST_SERVER_KEY \
	"../minimal-http-client-openhitls-mtls-file-positive/mtls-file-server.key"
#define EXPECTED_SERVER_CN "localhost"
#define TEST_BODY \
	"openhitls ssl-info positive chunk 01\n" \
	"openhitls ssl-info positive chunk 02\n" \
	"openhitls ssl-info positive chunk 03\n" \
	"openhitls ssl-info positive chunk 04\n" \
	"openhitls ssl-info positive chunk 05\n" \
	"openhitls ssl-info positive chunk 06\n"
#define SERVER_TX_CHUNK 23
#define CLIENT_RX_CHUNK 17

struct pss_http {
	char body[LWS_PRE + sizeof(TEST_BODY)];
	size_t body_len;
	size_t tx_ofs;
};

static struct lws_context *context;
static struct lws *client_wsi;
static lws_sorted_usec_list_t sul_finish;
static int interrupted, bad, completed, response_status;
static int test_port = DEFAULT_TEST_PORT;
static unsigned int finish_scheduled;
static unsigned int server_http_seen;
static unsigned int server_writeable_count;
static unsigned int client_rx_read_count;
static unsigned int ssl_info_events;
static unsigned int ssl_info_handshake_start;
static unsigned int ssl_info_handshake_done;
static unsigned int ssl_info_read;
static unsigned int ssl_info_write;
static unsigned int peer_verified;
static char peer_cn[128];
static char response_body[sizeof(TEST_BODY)];
static size_t response_body_len;

static void
cancel_service(void)
{
	if (context) {
		lws_cancel_service(context);
	}
}

static void
fail_test(const char *why)
{
	lwsl_err("%s\n", why);
	bad = 1;
	completed = 1;
	cancel_service();
}

static int
copy_cert_cn(struct lws *wsi, char *dest, size_t dest_len, unsigned int *verified)
{
	union lws_tls_cert_info_results ir;

	if (lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_COMMON_NAME, &ir,
				   sizeof(ir.ns.name))) {
		return -1;
	}

	lws_strncpy(dest, ir.ns.name, dest_len);

	if (lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_VERIFIED, &ir, 0)) {
		return -1;
	}

	*verified = ir.verified;

	return 0;
}

static void
finish_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;

	completed = 1;
	cancel_service();
}

static void
finalize_client_result(void)
{
	if (response_status != HTTP_STATUS_OK) {
		fail_test("unexpected HTTP status");
		return;
	}

	if (!server_http_seen) {
		fail_test("server never handled the HTTP transaction");
		return;
	}

	if (!ssl_info_events) {
		fail_test("no SSL info callbacks were delivered");
		return;
	}

	if (!ssl_info_handshake_start && !ssl_info_handshake_done) {
		fail_test("no SSL handshake info callbacks were delivered");
		return;
	}

	if (server_writeable_count < 2) {
		fail_test("response was not written across multiple TLS writes");
		return;
	}

	if (client_rx_read_count < 2) {
		fail_test("response was not received across multiple client reads");
		return;
	}

	if (strcmp(peer_cn, EXPECTED_SERVER_CN)) {
		fail_test("unexpected server certificate CN");
		return;
	}

	if (!peer_verified) {
		fail_test("server certificate was not verified");
		return;
	}

	if (strcmp(response_body, TEST_BODY)) {
		fail_test("unexpected HTTP response body");
		return;
	}

	lwsl_user("ssl-info events=%u hs-start=%u hs-done=%u read=%u write=%u\n",
		  ssl_info_events, ssl_info_handshake_start,
		  ssl_info_handshake_done, ssl_info_read, ssl_info_write);

	if (!finish_scheduled) {
		finish_scheduled = 1;
		lws_sul_schedule(context, 0, &sul_finish, finish_cb,
				 50 * LWS_US_PER_MS);
	}
}

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	      void *in, size_t len)
{
	struct pss_http *pss = (struct pss_http *)user;
	uint8_t headers[LWS_PRE + LWS_RECOMMENDED_MIN_HEADER_SPACE],
		*start = &headers[LWS_PRE], *p = start,
		*end = &headers[sizeof(headers) - 1];

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		server_http_seen = 1;
		pss->body_len = sizeof(TEST_BODY) - 1;
		pss->tx_ofs = 0;
		memcpy(&pss->body[LWS_PRE], TEST_BODY, pss->body_len);

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/plain",
						(lws_filepos_t)pss->body_len,
						&p, end)) {
			return 1;
		}

		if (lws_finalize_write_http_header(wsi, start, &p, end)) {
			return 1;
		}

		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
	{
		size_t remaining = pss->body_len - pss->tx_ofs;
		size_t chunk = remaining > SERVER_TX_CHUNK ?
			       SERVER_TX_CHUNK : remaining;
		enum lws_write_protocol wp = LWS_WRITE_HTTP;

		if (pss->tx_ofs + chunk == pss->body_len) {
			wp = LWS_WRITE_HTTP_FINAL;
		}

		if (lws_write(wsi,
			      (unsigned char *)&pss->body[LWS_PRE + pss->tx_ofs],
			      (unsigned int)chunk, wp) != (int)chunk) {
			return 1;
		}

		server_writeable_count++;
		pss->tx_ofs += chunk;

		if (pss->tx_ofs < pss->body_len) {
			lws_callback_on_writable(wsi);
			return 0;
		}

		if (lws_http_transaction_completed(wsi)) {
			return -1;
		}
		return 0;
	}

	case LWS_CALLBACK_SSL_INFO:
	{
		const struct lws_ssl_info *si =
			(const struct lws_ssl_info *)in;

		ssl_info_events++;
		if (si->where & INDICATE_EVENT_HANDSHAKE_START) {
			ssl_info_handshake_start++;
		}
		if (si->where & INDICATE_EVENT_HANDSHAKE_DONE) {
			ssl_info_handshake_done++;
		}
		if (si->where & INDICATE_EVENT_READ) {
			ssl_info_read++;
		}
		if (si->where & INDICATE_EVENT_WRITE) {
			ssl_info_write++;
		}
		return 0;
	}

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (const char *)in : "(null)");
		client_wsi = NULL;
		fail_test("client handshake failed");
		return 0;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		response_status = (int)lws_http_client_http_response(wsi);
		if (copy_cert_cn(wsi, peer_cn, sizeof(peer_cn), &peer_verified)) {
			fail_test("failed to read server certificate info");
			return 0;
		}

		lwsl_user("client observed server CN '%s' verified=%u status=%d\n",
			  peer_cn, peer_verified, response_status);
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (response_body_len + len >= sizeof(response_body)) {
			fail_test("response body exceeded test buffer");
			return -1;
		}

		memcpy(response_body + response_body_len, in, len);
		response_body_len += len;
		response_body[response_body_len] = '\0';
		client_rx_read_count++;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
	{
		unsigned char buf[LWS_PRE + CLIENT_RX_CHUNK],
			      *pp = &buf[LWS_PRE];
		int n = CLIENT_RX_CHUNK;

		if (lws_http_client_read(wsi, (char **)&pp, &n) < 0) {
			fail_test("lws_http_client_read failed");
			return -1;
		}
		return 0;
	}

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		client_wsi = NULL;
		if (!completed) {
			finalize_client_result();
		}
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{
		"http",
		callback_http,
		sizeof(struct pss_http),
		0, 0, NULL, 0
	},
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	(void)sig;

	interrupted = 1;
	cancel_service();
}

static int
start_client(void)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.address = "localhost";
	i.host = i.address;
	i.origin = i.address;
	i.path = "/";
	i.method = "GET";
	i.port = test_port;
	i.ssl_connection = LCCSCF_USE_SSL;
	i.protocol = protocols[0].name;
	i.pwsi = &client_wsi;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("lws_client_connect_via_info failed\n");
		return -1;
	}

	return 0;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	memset(&info, 0, sizeof(info));
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	p = lws_cmdline_option(argc, argv, "--port");
	if (p) {
		test_port = atoi(p);
	}

	lwsl_user("LWS minimal http client openhitls ssl-info positive\n");

	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.port = test_port;
	info.protocols = protocols;
	info.ssl_cert_filepath = TEST_SERVER_CERT;
	info.ssl_private_key_filepath = TEST_SERVER_KEY;
	info.client_ssl_ca_filepath = TEST_CA_CERT;
	info.ssl_info_event_mask = INDICATE_EVENT_HANDSHAKE_START |
				   INDICATE_EVENT_HANDSHAKE_DONE |
				   INDICATE_EVENT_READ |
				   INDICATE_EVENT_WRITE |
				   INDICATE_EVENT_ALERT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (start_client()) {
		lws_context_destroy(context);
		return 1;
	}

	while (n >= 0 && !interrupted && !completed) {
		n = lws_service(context, 0);
	}

	lws_context_destroy(context);

	if (interrupted && !completed) {
		return 1;
	}

	lwsl_user("Completed: %s\n", bad ? "failed" : "OK");

	return bad;
}
