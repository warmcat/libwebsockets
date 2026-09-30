/*
 * lws-api-test-mtls
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An lws server vhost requiring a valid client certificate, and lws clients
 * presenting different ones, in one process, confirm the vhost's policy
 * holds on every transport it is served over.
 *
 * The server vhost has the build's default alpn, so beside its tcp listener
 * it opens a quic one on the same port, the same as any tls vhost with h3 in
 * its alpn does.  It trusts client certs signed by ca.crt, and answers a
 * request with the CN of the client cert it was served under.
 *
 * Three client vhosts connect to it:
 *
 *  - "none", presenting no client cert: refused
 *  - "self", presenting a self-signed cert ca.crt did not sign: refused.  It
 *    is under the CA's own name, since a client presents only a cert whose
 *    issuer is one the server said it trusts... this one says so, and the
 *    server has to find out it is not
 *  - "node1", presenting node1.crt, which ca.crt signed: served, and the
 *    response carries its CN
 *
 * over h1 and h2 over tls, and h3 over quic (--transport picks one).  For
 * each case the server has to have seen a connection of the case's
 * transport, a tcp accept or a quic connection, so that a refusal on the
 * wrong transport cannot pass, and the h3 client does not fall back to tcp.
 * The refused ones must end without any request being served, when the
 * server's connection for them has gone (the client is not always told when
 * a connection it has not made a stream on yet goes away); node1 is last, so
 * no alt-svc its response teaches the client can move the refused ones to
 * another transport.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#define CASE_TIMEOUT_S	20

enum {
	XP_H1,
	XP_H2,
	XP_H3,
	XP_COUNT
};

static const char * const xport_names[] = { "h1", "h2", "h3" };
static const char * const xport_alpn[] = { "http/1.1", "h2", "h3" };

enum {
	ID_NONE,
	ID_SELF,
	ID_NODE1,
	ID_COUNT
};

static const struct {
	const char	*name;
	const char	*cert;
	const char	*key;
	char		served;
} idents[] = {
	{ "none",  NULL,			NULL,			0 },
	{ "self",  "self-signed.crt",		"self-signed.key",	0 },
	{ "node1", "node1.crt",		"node1.key",		1 },
};

static struct lws_context *context;
static struct lws_vhost *vh_cli[ID_COUNT];
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static const char *server_addr = "localhost", *certs = ".";
static int port = 7681, xport = -1, cur = -1, failures, result = 1;

/* what the server saw during the current case */

static struct {
	struct lws	*conn;		/* the case's connection wsi */
	int		tcp_accepted;
	int		quic_accepted;
	int		served;
} srv;

/* what the client saw during the current case */

static struct {
	char		body[128];
	size_t		body_len;
	int		status;
	char		completed;
} cli;

static char case_over;

struct pss_srv {
	char		resp[LWS_PRE + 128];
	size_t		resp_len;
};

static void next_case(lws_sorted_usec_list_t *sul);

static void
case_finish(const char *why)
{
	int want_served = idents[cur].served, saw;
	char cn[80];

	if (case_over)
		return;
	case_over = 1;
	lws_sul_cancel(&sul_watchdog);

	saw = xport == XP_H3 ? srv.quic_accepted : srv.tcp_accepted;
	lws_snprintf(cn, sizeof(cn), "cn=%s.example.com", idents[cur].name);

	if (why) {
		lwsl_err("%s %s: FAIL: %s\n", xport_names[xport],
			 idents[cur].name, why);
		failures++;
	} else if (!saw) {
		lwsl_err("%s %s: FAIL: the server saw no %s connection\n",
			 xport_names[xport], idents[cur].name,
			 xport == XP_H3 ? "quic" : "tcp");
		failures++;
	} else if (want_served &&
		   (cli.status != 200 || !cli.completed || srv.served != 1 ||
		    cli.body_len != strlen(cn) ||
		    memcmp(cli.body, cn, cli.body_len))) {
		lwsl_err("%s %s: FAIL: expected to be served as %s: status "
			 "%d, completed %d, served %d, body '%.*s'\n",
			 xport_names[xport], idents[cur].name, cn, cli.status,
			 cli.completed, srv.served, (int)cli.body_len,
			 cli.body);
		failures++;
	} else if (!want_served && (srv.served || cli.status)) {
		lwsl_err("%s %s: FAIL: expected to be refused, but served %d, "
			 "status %d\n", xport_names[xport], idents[cur].name,
			 srv.served, cli.status);
		failures++;
	} else
		lwsl_user("%s %s: PASS (%s)\n", xport_names[xport],
			  idents[cur].name, want_served ? "served" : "refused");

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
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t hdr[LWS_PRE + 256], *start = &hdr[LWS_PRE], *p = start,
		*end = &hdr[sizeof(hdr) - 1];
	union lws_tls_cert_info_results ir;

	switch (reason) {
	case LWS_CALLBACK_WSI_CREATE:
		/*
		 * The server's connection wsis: an accepted tcp connection is
		 * tagged "adopted", the connection wsi the quic listener
		 * makes for a quic one "quic child"
		 */
		if (!lws_wsi_tag(wsi) || cur < 0)
			break;
		if (strstr(lws_wsi_tag(wsi), "|adopted"))
			srv.tcp_accepted++;
		else if (strstr(lws_wsi_tag(wsi), "quic child"))
			srv.quic_accepted++;
		else
			break;
		srv.conn = wsi;
		break;

	case LWS_CALLBACK_WSI_DESTROY:
		/* a refused case is over when his connection has gone */
		if (wsi != srv.conn)
			break;
		srv.conn = NULL;
		if (cur >= 0 && cur < ID_COUNT && !idents[cur].served)
			case_finish(NULL);
		break;

	case LWS_CALLBACK_HTTP:
		srv.served++;

		/* the client cert this request is being served under */

		if (lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_COMMON_NAME,
					   &ir, sizeof(ir.ns.name)))
			lws_strncpy(ir.ns.name, "(none)", sizeof(ir.ns.name));

		pss->resp_len = (size_t)lws_snprintf(&pss->resp[LWS_PRE],
					sizeof(pss->resp) - LWS_PRE, "cn=%s",
					ir.ns.name);

		lwsl_user("%s: server: serving %s\n", __func__,
			  &pss->resp[LWS_PRE]);

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

	/* only the current case's connection has anything to say */

	if (cur < 0 || (intptr_t)lws_get_opaque_user_data(wsi) != cur + 1)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		cli.status = (int)lws_http_client_http_response(wsi);
		lwsl_user("%s: client: status %d\n", __func__, cli.status);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (len > sizeof(cli.body) - cli.body_len)
			len = sizeof(cli.body) - cli.body_len;
		memcpy(cli.body + cli.body_len, in, len);
		cli.body_len += len;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		cli.completed = 1;
		lwsl_user("%s: client: completed\n", __func__);
		case_finish(NULL);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: client: connection error: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		case_finish(NULL);
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		lwsl_user("%s: client: closed\n", __func__);
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

	if (++cur >= ID_COUNT) {
		result = !!failures;
		lws_default_loop_exit(context);
		return;
	}

	lwsl_user("=== %s: client cert %s ===\n", xport_names[xport],
		  idents[cur].name);

	memset(&srv, 0, sizeof(srv));
	memset(&cli, 0, sizeof(cli));
	case_over = 0;

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 CASE_TIMEOUT_S * LWS_US_PER_SEC);

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli[cur];
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.port			= port;
	i.path			= "/";
	i.method		= "GET";
	i.protocol		= "mtls";
	i.opaque_user_data	= (void *)(intptr_t)(cur + 1);
	i.alpn			= xport_alpn[xport];
	/* the server's own cert is not what is under test here */
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	/* an h3 case must be decided on h3, not by a fallback to tcp */
	i.disable_h3_fallback	= 1;

	if (!lws_client_connect_via_info(&i))
		/* he failed without a connection error callback */
		case_finish("the connection could not be started");
}

static const struct lws_protocols protocols_srv[] = {
	{ "mtls", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "mtls", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	char cert[256], key[256], ca[256], srv_cert[256], srv_key[256];
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* listeners on tcp and udp, and both ends of the connections */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "-s")))
		server_addr = p;
	if ((p = lws_cmdline_option(argc, argv, "--certs")))
		certs = p;
	if ((p = lws_cmdline_option(argc, argv, "--transport")))
		for (n = 0; n < XP_COUNT; n++)
			if (!strcmp(p, xport_names[n]))
				xport = n;
	if (xport < 0) {
		lwsl_err("--transport h1 | h2 | h3 is required\n");
		return 1;
	}
#if !defined(LWS_WITH_HTTP2)
	if (xport == XP_H2) {
		lwsl_err("h2 is not in this build\n");
		return 1;
	}
#endif
#if !defined(LWS_ROLE_H3)
	if (xport == XP_H3) {
		lwsl_err("h3 is not in this build\n");
		return 1;
	}
#endif

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: mTLS vhost policy over %s\n",
		  xport_names[xport]);

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/*
	 * The mTLS server vhost.  Its alpn is the build's default, so it
	 * listens for quic on the same port too, when the build has h3
	 */

	lws_snprintf(srv_cert, sizeof(srv_cert), "%s/localhost-100y.cert",
		     certs);
	lws_snprintf(srv_key, sizeof(srv_key), "%s/localhost-100y.key", certs);
	lws_snprintf(ca, sizeof(ca), "%s/ca.crt", certs);

	info.port			= port;
	info.vhost_name			= "srv";
	info.protocols			= protocols_srv;
	info.ssl_cert_filepath		= srv_cert;
	info.ssl_private_key_filepath	= srv_key;
	info.ssl_ca_filepath		= ca;
	info.options			|=
			LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create the server vhost\n");
		goto bail;
	}

	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;
	info.ssl_ca_filepath		= NULL;
	info.options			&= ~(uint64_t)
			LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;

	/* a client vhost per identity, no listener */

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.protocols			= protocols_cli;

	for (n = 0; n < ID_COUNT; n++) {
		info.vhost_name = idents[n].name;
		info.client_ssl_cert_filepath = NULL;
		info.client_ssl_private_key_filepath = NULL;
		if (idents[n].cert) {
			lws_snprintf(cert, sizeof(cert), "%s/%s", certs,
				     idents[n].cert);
			lws_snprintf(key, sizeof(key), "%s/%s", certs,
				     idents[n].key);
			info.client_ssl_cert_filepath = cert;
			info.client_ssl_private_key_filepath = key;
		}

		vh_cli[n] = lws_create_vhost(context, &info);
		if (!vh_cli[n]) {
			lwsl_err("Failed to create client vhost %s\n",
				 idents[n].name);
			goto bail;
		}
	}

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);

	n = 0;
	while (n >= 0)
		n = lws_service(context, 0);

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_context_destroy(context);

	lwsl_user("Completed: %s (%d of %d cases failed)\n",
		  result ? "FAIL" : "PASS", failures, ID_COUNT);

	return result;
}
