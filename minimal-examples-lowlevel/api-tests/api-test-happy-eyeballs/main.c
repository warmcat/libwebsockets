/*
 * lws-api-test-happy-eyeballs
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int interrupted;
static int result = 1;
static struct lws_context *context;
static struct lws_vhost *vh_quic_server;
static struct lws_vhost *vh_tcp_server;



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

static int client_step = 0;
static struct lws *client_wsi = NULL;
static int established_success = 0;
static int next_step = 0;

static int port_tcp = 7681;
static int port_quic = 7682;

static void
start_client_connection(void)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.vhost = lws_get_vhost_by_name(context, "client");
	i.port = port_tcp;
	i.address = "localhost";
	i.host = "localhost";
	i.origin = "localhost";
	i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
			   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	i.protocol = "http";
	if (client_step == 0)
		i.alpn = "h2,http/1.1";
	else
		i.alpn = "h3,h2";
	i.method = "GET";
	i.path = "/";

	client_wsi = lws_client_connect_via_info(&i);
	if (!client_wsi && !established_success) {
		lwsl_err("Client connection failed for step %d\n", client_step);
		result = 1;
		interrupted = 1;
	} else if (!client_wsi && established_success) {
		established_success = 0;
		client_step++;
		next_step = 1;
	}
}

static int
callback_client(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		lwsl_notice("CLIENT ESTABLISHED HTTP: step %d\n", client_step);
		established_success = 1;
		return -1;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_notice("CLIENT CONNECTION ERROR: %s\n", in ? (char *)in : "(null)");
		/* fallthru */
	case LWS_CALLBACK_CLIENT_CLOSED:
		lwsl_notice("CLIENT CLOSED/ERROR: step %d\n", client_step);
		client_wsi = NULL;

		if (established_success) {
			established_success = 0;
			client_step++;
			next_step = 1;
		} else {
			lwsl_err("--- Failed to establish connection in step %d ---\n", client_step);
			result = 1;
			interrupted = 1;
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static struct lws_protocols protocols_client[] = {
	{ "http", callback_client, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static int
callback_quic_server(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_HTTP:
		{
			uint8_t buf[LWS_PRE + 2048], *start = &buf[LWS_PRE], *p = start,
				*end = &buf[sizeof(buf) - 1];

			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
					"text/html",
					13, &p, end))
				return 1;
			if (lws_finalize_write_http_header(wsi, start, &p, end))
				return 1;

			uint8_t body[LWS_PRE + 16];
			memcpy(body + LWS_PRE, "hello from h3", 13);
			lws_write(wsi, body + LWS_PRE, 13, LWS_WRITE_HTTP_FINAL);
			if (lws_http_transaction_completed(wsi))
				return -1;
			return 0;
		}
	default:
		break;
	}
	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
callback_tcp_server(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_HTTP:
		{
			uint8_t buf[LWS_PRE + 2048], *start = &buf[LWS_PRE], *p = start,
				*end = &buf[sizeof(buf) - 1];
			char altsvc[64];
			int altsvc_len;

			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
					"text/html",
					13, &p, end))
				return 1;
			/* Inject Alt-Svc pointing to our QUIC vhost */
			altsvc_len = lws_snprintf(altsvc, sizeof(altsvc), "h3=\":%d\"", port_quic);
			if (lws_add_http_header_by_name(wsi, (unsigned char *)"alt-svc:",
					(unsigned char *)altsvc, altsvc_len, &p, end))
				return 1;
			if (lws_finalize_write_http_header(wsi, start, &p, end))
				return 1;

			uint8_t body[LWS_PRE + 16];
			memcpy(body + LWS_PRE, "hello from h2", 13);
			lws_write(wsi, body + LWS_PRE, 13, LWS_WRITE_HTTP_FINAL);
			if (lws_http_transaction_completed(wsi))
				return -1;
			return 0;
		}
	default:
		break;
	}
	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static struct lws_protocols protocols_quic[] = {
	{ "http", callback_quic_server, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static struct lws_protocols protocols_tcp[] = {
	{ "http", callback_tcp_server, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

void sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_tcp = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "-q")))
		port_quic = atoi(p);

	signal(SIGINT, sigint_handler);

	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_H2_JUST_FIX_WINDOW_UPDATE_OVERFLOW;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* QUIC server */
	info.port = CONTEXT_PORT_NO_LISTEN_SERVER;
	info.vhost_name = "quic-server";
	info.listen_accept_role = "quic";
	info.listen_accept_protocol = "http";
	info.alpn = "h3,lws-quic";
	info.protocols = protocols_quic;
	info.server_ssl_cert_mem = test_cert;
	info.server_ssl_cert_mem_len = (unsigned int)strlen(test_cert);
	info.server_ssl_private_key_mem = test_key;
	info.server_ssl_private_key_mem_len = (unsigned int)strlen(test_key);

	vh_quic_server = lws_create_vhost(context, &info);
	if (!vh_quic_server) {
		lwsl_err("Failed to create QUIC vhost\n");
		goto bail;
	}

	if (!lws_create_adopt_udp(vh_quic_server, NULL, port_quic, LWS_CAUDP_BIND,
				  "http", NULL, NULL, NULL,
				  NULL, "quic_listen")) {
		lwsl_err("Failed to bind QUIC UDP listener (IPv6)\n");
		goto bail;
	}

	if (!lws_create_adopt_udp(vh_quic_server, "127.0.0.1", port_quic, LWS_CAUDP_BIND,
				  "http", NULL, NULL, NULL,
				  NULL, "quic_listen")) {
		lwsl_err("Failed to bind QUIC UDP listener (IPv4)\n");
		goto bail;
	}

	/* TCP server */
	info.port = port_tcp;
	info.vhost_name = "tcp-server";
	info.listen_accept_role = "h2";
	info.listen_accept_protocol = "http";
	info.alpn = "h2,http/1.1";
	info.protocols = protocols_tcp;

	vh_tcp_server = lws_create_vhost(context, &info);
	if (!vh_tcp_server) {
		lwsl_err("Failed to create TCP vhost\n");
		goto bail;
	}

	/* Client vhost */
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "client";
	info.listen_accept_role = NULL;
	info.listen_accept_protocol = NULL;
	info.alpn = "h3,h2,http/1.1";
	info.protocols = protocols_client;
	info.server_ssl_cert_mem = NULL;
	info.server_ssl_cert_mem_len = 0;
	info.server_ssl_private_key_mem = NULL;
	info.server_ssl_private_key_mem_len = 0;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create Client vhost\n");
		goto bail;
	}

	lwsl_notice("--- Starting Step 1: TCP connection for Alt-Svc ---\n");
	start_client_connection();

	int n = 0;
	while (n >= 0 && !interrupted) {
		n = lws_service(context, 0);

		if (next_step && !client_wsi) {
			next_step = 0;
			if (client_step == 1) {
				lwsl_notice("--- Starting Step 2: H3 success ---\n");
				start_client_connection();
			} else if (client_step == 2) {
				lwsl_notice("--- Starting Step 3: H3 failure, TCP fallback ---\n");
				if (vh_quic_server) {
					lws_vhost_destroy(vh_quic_server);
					vh_quic_server = NULL;
				}
				start_client_connection();
			} else if (client_step == 3) {
				lwsl_notice("--- Step 3 complete. Test passed. ---\n");
				result = 0;
				interrupted = 1;
			}
		}
	}

bail:
	lws_context_destroy(context);
	return result;
}
