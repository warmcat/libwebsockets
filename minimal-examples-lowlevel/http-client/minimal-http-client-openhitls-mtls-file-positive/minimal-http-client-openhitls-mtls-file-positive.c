/*
 * lws-minimal-http-client-openhitls-mtls-file-positive
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Verifies a successful OpenHiTLS mutual TLS handshake using certificate
 * files on both sides.  The client trusts a local test CA, presents a client
 * certificate and encrypted private key from files, and then validates:
 *
 * - HTTP 200 response
 * - server-observed client certificate CN
 * - client-observed server certificate CN
 * - verified status on both peers
 */

#include <libwebsockets.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_TEST_PORT 7810
#define TEST_CA_CERT "mtls-file-ca.cert"
#define TEST_SERVER_CERT "mtls-file-server.cert"
#define TEST_SERVER_KEY "mtls-file-server.key"
#define TEST_CLIENT_CERT "mtls-file-client.cert"
#define TEST_CLIENT_KEY "mtls-file-client.key.enc"
#define TEST_CLIENT_KEY_PASS "openhitls-file-pass"
#define EXPECTED_SERVER_CN "localhost"
#define EXPECTED_CLIENT_CN "openhitls-mtls-file-client"
#define TEST_BODY "openhitls-mtls-file-positive ok\n"

struct pss_http {
	char body[LWS_PRE + sizeof(TEST_BODY)];
	size_t body_len;
};

static struct lws_context *context;
static struct lws *client_wsi;
static int interrupted, bad, completed, response_status;
static int test_port = DEFAULT_TEST_PORT;
static char response_body[128];
static size_t response_body_len;
static char client_peer_cn[128];
static char server_peer_cn[128];
static unsigned int client_peer_verified;
static unsigned int server_peer_verified;
static unsigned int verify_cb_seen;
static unsigned int verify_cb_preverify_ok;
static unsigned int server_http_seen;

static void
fail_test(const char *why)
{
	lwsl_err("%s\n", why);
	bad = 1;
	completed = 1;
	if (context) {
		lws_cancel_service(context);
	}
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
finalize_client_result(struct lws *wsi)
{
	(void)wsi;

	if (response_status != HTTP_STATUS_OK) {
		fail_test("unexpected HTTP status");
		return;
	}

	if (!server_http_seen) {
		fail_test("server never handled the HTTP transaction");
		return;
	}

	if (!verify_cb_seen) {
		fail_test("server client-cert verification callback was not called");
		return;
	}

	if (!verify_cb_preverify_ok) {
		fail_test("server client-cert preverify was false");
		return;
	}

	if (strcmp(client_peer_cn, EXPECTED_SERVER_CN)) {
		fail_test("unexpected server certificate CN");
		return;
	}

	if (!client_peer_verified) {
		fail_test("server certificate was not verified");
		return;
	}

	if (strcmp(server_peer_cn, EXPECTED_CLIENT_CN)) {
		fail_test("unexpected client certificate CN");
		return;
	}

	if (!server_peer_verified) {
		fail_test("client certificate was not verified");
		return;
	}

	if (strcmp(response_body, TEST_BODY)) {
		fail_test("unexpected HTTP response body");
		return;
	}

	completed = 1;
	lws_cancel_service(context);
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
	case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
		verify_cb_seen = 1;
		verify_cb_preverify_ok = (unsigned int)!!len;
		return 0;

	case LWS_CALLBACK_HTTP:
		server_http_seen = 1;
		if (copy_cert_cn(wsi, server_peer_cn, sizeof(server_peer_cn),
				 &server_peer_verified)) {
			return 1;
		}

		lwsl_user("server observed client CN '%s' verified=%u\n",
			  server_peer_cn, server_peer_verified);

		pss->body_len = sizeof(TEST_BODY) - 1;
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
		if (lws_write(wsi, (unsigned char *)&pss->body[LWS_PRE],
			      (unsigned int)pss->body_len,
			      LWS_WRITE_HTTP_FINAL) != (int)pss->body_len) {
			return 1;
		}

		if (lws_http_transaction_completed(wsi)) {
			return -1;
		}
		return 0;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (const char *)in : "(null)");
		client_wsi = NULL;
		fail_test("client handshake failed");
		return 0;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		response_status = (int)lws_http_client_http_response(wsi);
		if (copy_cert_cn(wsi, client_peer_cn, sizeof(client_peer_cn),
				 &client_peer_verified)) {
			fail_test("failed to read server certificate info");
			return 0;
		}

		lwsl_user("client observed server CN '%s' verified=%u status=%d\n",
			  client_peer_cn, client_peer_verified, response_status);
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (response_body_len + len >= sizeof(response_body)) {
			fail_test("response body exceeded test buffer");
			return -1;
		}

		memcpy(response_body + response_body_len, in, len);
		response_body_len += len;
		response_body[response_body_len] = '\0';
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
	{
		unsigned char buf[LWS_PRE + 128], *pp = &buf[LWS_PRE];
		int n = (int)sizeof(buf) - LWS_PRE;

		if (lws_http_client_read(wsi, (char **)&pp, &n) < 0) {
			fail_test("lws_http_client_read failed");
			return -1;
		}

		return 0;
	}

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		client_wsi = NULL;
		if (!completed) {
			finalize_client_result(wsi);
		}
		return 0;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		client_wsi = NULL;
		if (!completed) {
			finalize_client_result(wsi);
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
	if (context) {
		lws_cancel_service(context);
	}
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

	lwsl_user("connecting to https://%s:%d/\n", i.address, i.port);

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

	lwsl_user("LWS minimal http client openhitls mtls file positive\n");

	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;
	info.port = test_port;
	info.protocols = protocols;
	info.ssl_ca_filepath = TEST_CA_CERT;
	info.ssl_cert_filepath = TEST_SERVER_CERT;
	info.ssl_private_key_filepath = TEST_SERVER_KEY;
	/*
	 * The current OpenHiTLS server setup path binds the server password
	 * callback before it knows only the client key is encrypted.
	 */
	info.ssl_private_key_password = TEST_CLIENT_KEY_PASS;
	info.client_ssl_ca_filepath = TEST_CA_CERT;
	info.client_ssl_cert_filepath = TEST_CLIENT_CERT;
	info.client_ssl_private_key_filepath = TEST_CLIENT_KEY;
	info.client_ssl_private_key_password = TEST_CLIENT_KEY_PASS;

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

	if (interrupted && !completed) {
		return 1;
	}

	lwsl_user("Completed: %s\n", bad ? "failed" : "OK");

	return bad;
}
