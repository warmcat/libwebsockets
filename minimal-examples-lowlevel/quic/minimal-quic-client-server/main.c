/*
 * lws-minimal-quic-client-server
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates the native libwebsockets QUIC transport implementation,
 * instantiating a server via lejp-conf, and optionally a client that links up
 * and passes bulk bidirectional data.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int interrupted;
static int result = 1; /* 1 means failed/timeout, 0 means success */
static int server_only = 0;

static const struct lws_http_mount mount_redir = {
	.mountpoint = "/",
	.origin = "warmcat.com/git/blog",
	.origin_protocol = LWSMPRO_REDIR_HTTPS,
	.mountpoint_len = 1,
	.exact_match = 1,
};

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

#define TOTAL_DATA (128 * 1024)

static size_t client_sent = 0;
static size_t client_rx = 0;
static uint32_t client_hash = 5381; /* djb2 init */
static int client_done = 0;

static size_t server_sent = 0;
static size_t server_rx = 0;
static uint32_t server_hash = 5381; /* djb2 init */
static int server_done = 0;

static lws_usec_t last_rx_us;

static uint32_t
simple_hash(uint32_t hash, const uint8_t *data, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++)
		hash = (hash << 5) + hash + data[i]; /* hash * 33 + c */
	return hash;
}



static void
teardown_cb(lws_sorted_usec_list_t *sul)
{
	interrupted = 1;
}

static lws_sorted_usec_list_t sul_teardown;

static void
check_test_completion(struct lws *wsi)
{
	if (client_done && server_done) {
		lwsl_notice("Test completed successfully! Both sides received full data. Waiting 1.5s for ACKs...\n");
		result = 0;
		if (!server_only)
			lws_sul_schedule(lws_get_context(wsi), 0, &sul_teardown, teardown_cb, 1500 * 1000);
	}
}

/*
 * This is the application protocol callback for the QUIC stream data.
 */
static int
callback_quic_test(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_PROTOCOL_INIT:
	{
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
		struct lws_vhost *vh = lws_get_vhost(wsi);
		lwsl_vhost_notice(vh, "Protocol init");
#endif
		break;
	}

	case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
		lwsl_notice("Server received new QUIC client connection!\n");
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lwsl_notice("Client %p successfully established QUIC connection!\n", wsi);
		/* Trigger a write to send bulk data */
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
	{
		uint8_t buf[LWS_PRE + 1024];

		if (client_sent >= TOTAL_DATA)
			break;

		size_t to_send = TOTAL_DATA - client_sent;
		if (to_send > 1024)
			to_send = 1024;
		memset(&buf[LWS_PRE], (client_sent & 0xff), to_send);
                lwsl_notice("CLIENT WSI allowance=%d\n", (int)lws_get_peer_write_allowance(wsi));
		int n = lws_write(wsi, &buf[LWS_PRE], to_send, LWS_WRITE_BINARY);
                if (n > 0) {
                        client_sent += (size_t)n;
                        if (client_sent < TOTAL_DATA)
                                lws_callback_on_writable(wsi);
                }
		break;
	}
	case LWS_CALLBACK_ESTABLISHED:
		lwsl_notice("SERVER ESTABLISHED!\n");
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
	{
		uint8_t buf[LWS_PRE + 1024];

		if (server_only)
			break;

		if (server_sent >= TOTAL_DATA)
                        break;
		size_t to_send = TOTAL_DATA - server_sent;
		if (to_send > 1024)
			to_send = 1024;
		memset(&buf[LWS_PRE], (server_sent & 0xff), to_send);
                lwsl_notice("SERVER WSI allowance=%d\n", (int)lws_get_peer_write_allowance(wsi));
		int n = lws_write(wsi, &buf[LWS_PRE], to_send, LWS_WRITE_BINARY);
		if (n > 0) {
			server_sent += (size_t)n;
			if (server_sent < TOTAL_DATA)
				lws_callback_on_writable(wsi);
		} else {
                        lwsl_err("SERVER WROTE FAILED n=%d\n", n);
		}
		break;
	}

	case LWS_CALLBACK_QT_CLIENT_RECEIVE:
	{
		last_rx_us = lws_now_usecs();

		client_rx += len;
		client_hash = simple_hash(client_hash, in, len);
		if (client_rx >= TOTAL_DATA && !client_done) {
			lwsl_notice("Client received all %lu bytes, hash %u\n", (unsigned long)client_rx, client_hash);
			client_done = 1;
			check_test_completion(wsi);
		}
		break;
	}

	case LWS_CALLBACK_QT_SERVER_RECEIVE:
	{
		last_rx_us = lws_now_usecs();

		server_rx += len;
		server_hash = simple_hash(server_hash, in, len);
		if (server_rx >= TOTAL_DATA && !server_done) {
			lwsl_notice("Server received all %lu bytes, hash %u\n", (unsigned long)server_rx, server_hash);
			server_done = 1;
			check_test_completion(wsi);
		}
		break;
	}

	default:
		break;
	}

	return 0;
}

static struct lws_protocols protocols[] = {
	{ "quic-test-protocol", callback_quic_test, 0, 2048, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

void sigint_handler(int sig)
{
	interrupted = 1;
}

enum {
	LWS_SW_HELP,
	LWS_SW_URL,
	LWS_SW_PORT,
	LWS_SW_SERVER_ONLY,
};

static const struct lws_switches switches[] = {
	[LWS_SW_HELP]	= { "--help",	"Show this help information" },
	[LWS_SW_URL]	= { "-u",	"URL to connect to (if absent, acts as server too)" },
	[LWS_SW_PORT]	= { "-p",	"Port to connect to / listen on (default 7681)" },
	[LWS_SW_SERVER_ONLY] = { "-s",	"Server only mode (do not launch client, do not send data unprompted)" },
};

#if defined(WIN32) && defined(LWS_WITH_SCHANNEL)
#include <windows.h>
static int is_quic_supported_on_os(void) {
    OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0, {0}, 0, 0 };
    DWORDLONG const dwlConditionMask = VerSetConditionMask(
        VerSetConditionMask(
        VerSetConditionMask(
            0, VER_MAJORVERSION, VER_GREATER_EQUAL),
               VER_MINORVERSION, VER_GREATER_EQUAL),
               VER_BUILDNUMBER,  VER_GREATER_EQUAL);

    osvi.dwMajorVersion = 10;
    osvi.dwMinorVersion = 0;
    osvi.dwBuildNumber  = 20348; /* Windows Server 2022 */

    return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_BUILDNUMBER, dwlConditionMask) != FALSE;
}
#endif

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	struct lws_context *context;
	struct lws *client_wsi;
	struct lws_vhost *vh;
	lws_usec_t start_us;
	char url_buf[128];
	const char *p, *prot, *address, *path;
	int port = 7681;
	int url_port = 0;

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

#if defined(WIN32) && defined(LWS_WITH_SCHANNEL)
	if (!is_quic_supported_on_os()) {
		lwsl_user("SChannel QUIC requires Windows 11+ / Server 2022+\n");
		return 0;
	}
#endif

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}

	p = lws_cmdline_option(argc, argv, "-p");
	if (p)
		port = atoi(p);

	if (lws_cmdline_option(argc, argv, "-s"))
		server_only = 1;

	p = lws_cmdline_option(argc, argv, "-u");
	if (p) {
		lws_strncpy(url_buf, p, sizeof(url_buf));
		if (lws_parse_uri(url_buf, &prot, &address, &url_port, &path)) {
			lwsl_err("Failed to parse URL\n");
			return 1;
		}
		port = url_port;
	}

	signal(SIGINT, sigint_handler);

	info.port                               = 7681;
	info.protocols                          = protocols;
	info.options                            = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
						  LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (!p) {
		/*
		 * We instantiate the QUIC server vhost explicitly.
		 * We pass CONTEXT_PORT_NO_LISTEN_SERVER so it doesn't create a TCP listener!
		 */
		info.port			        = CONTEXT_PORT_NO_LISTEN_SERVER;
		info.vhost_name			        = "quic-server";
		info.listen_accept_role		        = "quic";
		info.listen_accept_protocol	        = "quic-test-protocol";
		info.alpn				= "h3,lws-quic";

		/* TLS 1.3 requires valid certificates for QUIC. Use our in-memory certs. */
		info.server_ssl_cert_mem	        = test_cert;
		info.server_ssl_cert_mem_len            = (unsigned int)strlen(test_cert);
		info.server_ssl_private_key_mem         = test_key;
		info.server_ssl_private_key_mem_len     = (unsigned int)strlen(test_key);
		info.mounts                             = &mount_redir;
	} else {
		info.port			        = CONTEXT_PORT_NO_LISTEN;
		info.vhost_name			        = "quic-client";
	}

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create QUIC vhost\n");
		goto bail;
	}

	if (!p) {
		/* Explicitly instantiate a UDP listener socket and bind it to QUIC! */
		if (!lws_create_adopt_udp(vh, "127.0.0.1", port, LWS_CAUDP_BIND,
						"quic-test-protocol", NULL, NULL, NULL,
						NULL, "quic_listen")) {
			lwsl_err("Failed to bind QUIC UDP listener\n");
			goto bail;
		}
	}

	if (!server_only) {
		/*
		 * Immediately launch the client.
		 */
		memset(&i, 0, sizeof(i));
		i.context		= context;
		i.port			= port;
		i.address		= p ? address : "127.0.0.1";
		i.host			= p ? address : "localhost";
		i.origin		= i.address;
		i.vhost			= vh;
		i.ssl_connection	= LCCSCF_USE_SSL;
		if (!p) /* by default, we use our canned selfsigned cert for local tests */
			i.ssl_connection |= LCCSCF_ALLOW_SELFSIGNED |
					    LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
		i.protocol		= "quic-test-protocol";
		i.alpn			= "lws-quic";
		i.local_protocol_name	= "quic-test-protocol";
		i.method		= "QUIC";

		client_wsi = lws_client_connect_via_info(&i);
		if (!client_wsi) {
			lwsl_err("Client connection failed\n");
			goto bail;
		}
	}

	start_us = lws_now_usecs();
	last_rx_us = start_us;

        while (lws_service(context, 0) >= 0 && !interrupted) {
		if (!server_only) {
			if (lws_now_usecs() - start_us > 60000000) {
				lwsl_err("Timeout waiting for QUIC transfer (60s absolute)\n");
				result = 1;
				break;
			}
			if (lws_now_usecs() - last_rx_us > 15000000) {
				lwsl_err("Timeout waiting for QUIC transfer (15s idle RX)\n");
				result = 1;
				break;
			}
		}
	}

bail:
	lws_context_destroy(context);

        return lws_cmdline_passfail(argc, argv, result);
}
