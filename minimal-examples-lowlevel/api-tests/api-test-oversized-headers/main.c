/*
 * lws-api-test-oversized-headers
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A request whose headers don't fit the server's header table (the ah,
 * max_http_header_data, 4096 bytes by default) is answered 431, with a
 * body saying "Oversized headers", over every http transport the build
 * has: h1, h2 with prior knowledge, h2 over tls and h3.  It's not cut
 * short and served, and on h2 / h3 it is only that stream that is
 * refused, not the whole connection.
 *
 * lws is both ends here: for each transport the client sends a request
 * with a 6000 byte cookie, which has to get a 431 saying why, then one
 * with a small cookie, which has to get the server's 200.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define BIG_COOKIE	6000

enum xport {
	XP_H1,
	XP_H2C,
	XP_H2_TLS,
	XP_H3,
};

static const char * const xport_names[] = { "h1", "h2c", "h2-tls", "h3" };

struct xcase {
	uint8_t		xport;
	uint8_t		big;	/* send the oversized cookie */
};

static const struct xcase cases[] = {
	{ XP_H1, 1 }, { XP_H1, 0 },
#if defined(LWS_WITH_HTTP2)
	{ XP_H2C, 1 }, { XP_H2C, 0 },
#if defined(LWS_WITH_TLS)
	{ XP_H2_TLS, 1 }, { XP_H2_TLS, 0 },
#endif
#endif
#if defined(LWS_ROLE_H3)
	{ XP_H3, 1 }, { XP_H3, 0 },
#endif
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static int result = 1, cur = -1, port_h1 = 7681, port_h2c = 7682,
	   port_tls = 7683, port_h3 = 7684;
static const char *server_addr = "127.0.0.1";
static char cookie[BIG_COOKIE + 1];

/* what the client heard for the current case */
static struct {
	char		body[256];
	size_t		body_len;
	int		status;
	int		done;
} cli;

#if defined(LWS_WITH_TLS)
/* a self-signed test cert does for the client's alpn */

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
#endif

/* the server: 200 "ok" to anything that gets as far as it */

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 256], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
				"text/plain", 2, &p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		memcpy(start, "ok", 2);
		if (lws_write(wsi, start, 2, LWS_WRITE_HTTP_FINAL) != 2)
			return 1;
		if (lws_http_transaction_completed(wsi))
			return -1;
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
next_case(lws_sorted_usec_list_t *sul);

static void
case_done(const char *why)
{
	const struct xcase *c = &cases[cur];

	if (why) {
		lwsl_err("--- %s, %s cookie: FAIL: %s ---\n",
			 xport_names[c->xport], c->big ? "big" : "small", why);
		lws_default_loop_exit(context);
		return;
	}

	lwsl_user("--- %s, %s cookie: %d: PASS ---\n", xport_names[c->xport],
		  c->big ? "big" : "small", cli.status);
	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
}

static void
case_evaluate(void)
{
	const struct xcase *c = &cases[cur];

	if (c->big) {
		if (cli.status != HTTP_STATUS_REQ_HEADER_FIELDS_TOO_LARGE)
			case_done("not answered 431");
		else if (!strstr(cli.body, "Oversized headers"))
			case_done("431 does not say why");
		else
			case_done(NULL);
		return;
	}

	if (cli.status != HTTP_STATUS_OK ||
	    cli.body_len != 2 || memcmp(cli.body, "ok", 2))
		case_done("not served");
	else
		case_done(NULL);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 1024], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		/*
		 * An earlier case's connection finishing its close is not
		 * news.  The request carries its case, onto the h2 / h3
		 * stream as well.
		 */
		if (cur < 0 || lws_get_opaque_user_data(wsi) != &cases[cur])
			return lws_callback_http_dummy(wsi, reason, user, in,
						       len);
		break;
	default:
		break;
	}

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in, *end = (*p) + len;
		size_t cl = cases[cur].big ? BIG_COOKIE : 8;

		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_COOKIE,
					(unsigned char *)cookie, (int)cl,
					p, end)) {
			lwsl_err("%s: no room for the cookie\n", __func__);
			return -1;
		}
		break;
	}

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		cli.status = (int)lws_http_client_http_response(wsi);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (cli.body_len + len >= sizeof(cli.body))
			len = sizeof(cli.body) - 1 - cli.body_len;
		memcpy(cli.body + cli.body_len, in, len);
		cli.body_len += len;
		cli.body[cli.body_len] = '\0';
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (!cli.done) {
			cli.done = 1;
			case_evaluate();
		}
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (!cli.done) {
			cli.done = 1;
			case_done(in ? (const char *)in : "connection error");
		}
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!cli.done) {
			cli.done = 1;
			case_done("closed without completing");
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", callback_srv, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	const struct xcase *c;

	if (++cur == (int)LWS_ARRAY_SIZE(cases)) {
		lwsl_user("--- all cases passed ---\n");
		result = 0;
		lws_default_loop_exit(context);
		return;
	}
	c = &cases[cur];
	memset(&cli, 0, sizeof(cli));

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.path			= "/";
	i.method		= "GET";
	i.protocol		= "cli";
	i.local_protocol_name	= "cli";

	switch (c->xport) {
	case XP_H1:
		i.port = port_h1;
		break;
#if defined(LWS_WITH_HTTP2)
	case XP_H2C:
		i.port = port_h2c;
		i.ssl_connection = LCCSCF_H2_PRIOR_KNOWLEDGE;
		break;
#if defined(LWS_WITH_TLS)
	case XP_H2_TLS:
		i.port = port_tls;
		i.alpn = "h2";
		i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
		break;
#endif
#endif
#if defined(LWS_ROLE_H3)
	case XP_H3:
		i.port = port_h3;
		i.alpn = "h3";
		i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
		break;
#endif
	default:
		break;
	}

	i.opaque_user_data	= (void *)&cases[cur];

	if (!lws_client_connect_via_info(&i))
		case_done("connect failed");
}

static void
sul_watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("--- timed out in case %d ---\n", cur);
	lws_default_loop_exit(context);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_h1 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--h2c-port")))
		port_h2c = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--tls-port")))
		port_tls = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--h3-port")))
		port_h3 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: oversized request headers get 431\n");

	memset(cookie, 'c', BIG_COOKIE);
	memcpy(cookie, "a=", 2);

	/* room for the client to compose the big cookie */
	info.pt_serv_buf_size = 32768;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
#if defined(LWS_WITH_TLS)
	info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
#endif

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.protocols = protocols_srv;

	info.port = port_h1;
	info.vhost_name = "srv-h1";
	if (!lws_create_vhost(context, &info))
		goto bail;

#if defined(LWS_WITH_HTTP2)
	info.port = port_h2c;
	info.vhost_name = "srv-h2c";
	info.options |= LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
	if (!lws_create_vhost(context, &info))
		goto bail;
	info.options &= ~(uint64_t)LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
#endif

#if defined(LWS_WITH_TLS)
	info.server_ssl_cert_mem = test_cert;
	info.server_ssl_cert_mem_len = (unsigned int)strlen(test_cert);
	info.server_ssl_private_key_mem = test_key;
	info.server_ssl_private_key_mem_len = (unsigned int)strlen(test_key);

#if defined(LWS_WITH_HTTP2)
	info.port = port_tls;
	info.vhost_name = "srv-tls";
	if (!lws_create_vhost(context, &info))
		goto bail;
#endif

#if defined(LWS_ROLE_H3)
	{
		struct lws_vhost *vh;

		/* a quic listener on udp only */
		info.port = CONTEXT_PORT_NO_LISTEN_SERVER;
		info.vhost_name = "srv-h3";
		info.listen_accept_role = "quic";
		info.listen_accept_protocol = "http";
		info.alpn = "h3";
		vh = lws_create_vhost(context, &info);
		if (!vh || !lws_create_adopt_udp(vh, server_addr, port_h3,
					LWS_CAUDP_BIND, "http", NULL, NULL,
					NULL, NULL, "quic_listen"))
			goto bail;
		info.listen_accept_role = NULL;
		info.listen_accept_protocol = NULL;
		info.alpn = NULL;
	}
#endif
	info.server_ssl_cert_mem = NULL;
	info.server_ssl_cert_mem_len = 0;
	info.server_ssl_private_key_mem = NULL;
	info.server_ssl_private_key_mem_len = 0;
#endif

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli)
		goto bail;

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
	lws_sul_schedule(context, 0, &sul_watchdog, sul_watchdog_cb,
			 30 * LWS_US_PER_SEC);

	while (n >= 0)
		n = lws_service(context, 0);

bail:
	if (cur < 0)
		lwsl_err("--- setup failed ---\n");
	lws_sul_cancel(&sul_watchdog);
	lws_context_destroy(context);
	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
