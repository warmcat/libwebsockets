/*
 * lws-api-test-ws-h2-pmd
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests permessage-deflate over ws-over-h2 (RFC 8441) tx.
 *
 * A ws server vhost and an h2 ws client run in one process, both offering
 * permessage-deflate.  The server bulk-sends a 64KB deterministic pattern in
 * 4KB messages, gated only on lws_send_pipe_choked(), like typical user code.
 * Alternate messages are highly compressible (so the deflated frame is much
 * smaller than the caller's payload) and incompressible (so the deflated
 * output overflows pmd's default 1KB chunk buffer and the extension must
 * drain across several POLLOUT services).
 *
 * That exercises the two encapsulated-tx bugs this test was written against:
 *
 *  - lws_write() on a ws-over-h2 stream returned the POST-COMPRESSION frame
 *    size instead of the caller's payload length, so any well-compressed
 *    message made callers checking (wr < len) conclude a short write and
 *    kill the connection, and
 *
 *  - ws->tx_draining_ext was never serviced for h2-encapsulated children
 *    (only rops_handle_POLLOUT_ws() does it, which mux children never
 *    reach), while lws_send_pipe_choked() reports choked during the drain,
 *    so the first message whose compressed output exceeded the pmd chunk
 *    buffer wedged the stream permanently.
 *
 * The test fails if
 *  - the negotiated connection is not actually ws-over-h2,
 *  - the client's upgrade did not offer permessage-deflate (the test would
 *    be vacuous),
 *  - any server lws_write() accepts fewer bytes than requested,
 *  - the received pattern is corrupted, or
 *  - the transfer doesn't complete in time (the drain wedge shows up here).
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int interrupted;
static int result = 1;
static struct lws_context *context;

static const char * const test_cert =
"-----BEGIN CERTIFICATE-----\n"
"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\n"
"e2Hl/7M0c/lbZ4FvXgARlex2rkgS0Ka06HE=\n"
"-----END CERTIFICATE-----\n";

static const char * const test_key =
"-----BEGIN PRIVATE KEY-----\n"
"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\n"
"fBrpEY1IATtPq1taBZZogRqI3rOkkPk=\n"
"-----END PRIVATE KEY-----\n";

#define TEST_TOTAL	65536
#define TEST_CHUNK	4096

static struct lws *client_wsi;
static size_t srv_sent;
static size_t cli_rx;
static int saw_pmd_offer;
static int port_tcp = 7681;
static lws_sorted_usec_list_t sul_timeout;

static const struct lws_extension extensions[] = {
	{
		"permessage-deflate",
		lws_extension_callback_pm_deflate,
		"permessage-deflate"
		 "; client_no_context_takeover"
		 "; client_max_window_bits"
	},
	{ NULL, NULL, NULL /* terminator */ }
};

/*
 * Deterministic pattern both sides can generate from the absolute byte
 * offset: even 4KB blocks are a trivially-compressible letter cycle (the
 * deflated frame is a fraction of the payload, catching a short lws_write()
 * return), odd blocks are multiplicative-hash noise that deflate cannot
 * shrink (the compressed output overflows pmd's 1KB chunk buffer, forcing
 * the tx_draining_ext path).
 */
static uint8_t
pattern_byte(size_t o)
{
	uint32_t v;

	if (!((o / TEST_CHUNK) & 1))
		return (uint8_t)('A' + (o % 26));

	v = (uint32_t)o * 2654435761u;

	return (uint8_t)(v ^ (v >> 11) ^ (v >> 22));
}

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("--- timeout: rx %d / %d, sent %d ---\n",
		 (int)cli_rx, TEST_TOTAL, (int)srv_sent);
	interrupted = 1;
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION: {
		char buf[256];

		/*
		 * prove the client's upgrade actually offered pmd over the
		 * extended CONNECT, so a silently-dropped negotiation can't
		 * turn this into a test of nothing
		 */
		if (lws_hdr_copy(wsi, buf, sizeof(buf),
				 WSI_TOKEN_EXTENSIONS) > 0 &&
		    strstr(buf, "permessage-deflate"))
			saw_pmd_offer = 1;
		break;
	}

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_user("%s: server: established\n", __func__);
		if (!saw_pmd_offer) {
			lwsl_err("--- no permessage-deflate offer seen ---\n");
			interrupted = 1;
			return -1;
		}
		srv_sent = 0;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE: {
		uint8_t buf[LWS_PRE + TEST_CHUNK];
		size_t n;

		/*
		 * bulk-send gated only on choked, like typical user code;
		 * while pmd is draining a big compressed message, choked
		 * reports 1 and the h2 child loop must advance the drain
		 * itself or we never come back here
		 */
		while (srv_sent < TEST_TOTAL && !lws_send_pipe_choked(wsi)) {
			n = TEST_TOTAL - srv_sent;
			if (n > TEST_CHUNK)
				n = TEST_CHUNK;
			for (size_t i = 0; i < n; i++)
				buf[LWS_PRE + i] = pattern_byte(srv_sent + i);
			int wr = lws_write(wsi, &buf[LWS_PRE], n,
					   LWS_WRITE_BINARY);
			lwsl_info("%s: srv wrote %d of %d\n", __func__, wr,
				  (int)n);
			if (wr < (int)n) {
				lwsl_err("--- short write: accepted %d of %d "
					 "(post-compression size leaked?) ---\n",
					 wr, (int)n);
				interrupted = 1;
				return -1;
			}
			srv_sent += n;
		}
		if (srv_sent < TEST_TOTAL)
			lws_callback_on_writable(wsi);
		break;
	}

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lwsl_user("%s: client: established\n", __func__);
		if (lws_get_network_wsi(wsi) == wsi) {
			lwsl_err("--- not encapsulated in h2 ---\n");
			interrupted = 1;
			return -1;
		}
		client_wsi = wsi;
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		for (size_t i = 0; i < len; i++)
			if (((uint8_t *)in)[i] != pattern_byte(cli_rx + i)) {
				lwsl_err("--- pattern corrupt at ofs %d ---\n",
					 (int)(cli_rx + i));
				interrupted = 1;
				return -1;
			}
		cli_rx += len;

		if (cli_rx == TEST_TOTAL) {
			lwsl_user("--- transfer complete and intact. "
				  "Test passed. ---\n");
			result = 0;
			interrupted = 1;
			return -1;
		}
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("--- client connection error: %s ---\n",
			 in ? (char *)in : "(null)");
		interrupted = 1;
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		lwsl_user("%s: client: closed (rx %d sent %d)\n", __func__,
			  (int)cli_rx, (int)srv_sent);
		client_wsi = NULL;
		if (result)
			interrupted = 1;
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	{ "pmdt", callback_srv, 0, TEST_CHUNK, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "pmdt", callback_cli, 0, TEST_CHUNK, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

void sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	struct lws_vhost *vh;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_tcp = atoi(p);

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: ws-over-h2 permessage-deflate\n");

	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* ws server vhost, h2 alpn, pmd on offer */
	info.port = port_tcp;
	info.vhost_name = "srv";
	info.alpn = "h2,http/1.1";
	info.protocols = protocols_srv;
	info.extensions = extensions;
	info.server_ssl_cert_mem = test_cert;
	info.server_ssl_cert_mem_len = (unsigned int)strlen(test_cert);
	info.server_ssl_private_key_mem = test_key;
	info.server_ssl_private_key_mem_len = (unsigned int)strlen(test_key);

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create server vhost\n");
		goto bail;
	}

	/* client vhost, pmd on offer */
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	info.server_ssl_cert_mem = NULL;
	info.server_ssl_cert_mem_len = 0;
	info.server_ssl_private_key_mem = NULL;
	info.server_ssl_private_key_mem_len = 0;

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.vhost = vh;
	i.address = "127.0.0.1";
	i.port = port_tcp;
	i.path = "/";
	i.host = "localhost";
	i.origin = "localhost";
	i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
			   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	i.alpn = "h2";
	i.protocol = "pmdt";
	i.local_protocol_name = "pmdt";

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("client connect failed\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 20 * LWS_US_PER_SEC);

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
