/*
 * lws-api-test-h3-authority
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Fences G-021: an h3 request may move to the vhost its :authority names
 * only among the vhosts sharing the listener the connection arrived on, as
 * an h1 request may by its Host.  The h3 server used to go on to look for
 * the name among the vhosts on port 443, and then among those with listen
 * port 0, which is what a unix socket vhost has: so a request from the
 * network naming a unix socket vhost, that only local processes can reach,
 * was served by it.
 *
 * Both ends are in this process.  Two tls vhosts, "pub-a" then a second,
 * share one tcp + quic listener on the test port, neither the SNI
 * fallback.  The client dials the literal 127.0.0.1, so his handshake
 * carries no SNI and stays on the vhost owning the listener, pub-a.  Each
 * vhost answers with its own name.
 *
 *  --case same-listener: the second vhost on the listener is named
 *    "127.0.0.1", and so is the :authority.  The request must move to it:
 *    the control, that reselection by :authority still works where it
 *    should.
 *
 *  --case unix-socket: the second vhost on the listener is "pub-b", and a
 *    plain unix socket vhost is named "127.0.0.1", as is the :authority.
 *    Nothing on the listener has that name, so the request must stay on
 *    pub-a.
 *
 * Fences G-148: an h2 or h3 request carrying a Host header as well as its
 * :authority must have them name the same authority (RFC 9113 8.3.1, RFC
 * 9114 4.3.1), or it is malformed and refused, since lws routes on
 * :authority but redirects, origin checks and user code read Host.  These
 * cases run on h2 or h3 (--alpn), with the second vhost "pub-b", so nothing
 * moves the request off pub-a, except where said.  The client adds a Host
 * header to the :authority it sends:
 *
 *  --case host-same:	      Host as :authority: served
 *  --case host-default-port: Host has :443, the https default, :authority
 *			      no port, so they name one origin: served
 *  --case host-case:	      :authority "localhost", which is also the SNI,
 *			      and so the second vhost's name, and Host
 *			      "LocalHost", the same but for case: served
 *  --case host-v6:	      :authority given to lws as the bare IPv6
 *			      literal "::1", Host "[::1]": lws must send the
 *			      :authority bracketed, the same: served
 *  --case host-name:	      Host names another host: refused
 *  --case host-port:	      Host has a port that is not the default and
 *			      :authority none: refused
 *
 * A refused request must not reach the server's LWS_CALLBACK_HTTP, and the
 * client must hear of the refusal before the deadline.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define H3A_TIMEOUT_S	10
#define H3A_NAME	"127.0.0.1"	/* literal: no SNI from the client */

static const struct h3a_case {
	const char	*name;
	const char	*second_vh;	/* the second vhost on the listener */
	const char	*authority;	/* what the client sends as :authority */
	const char	*host;		/* a Host header to add too, or NULL */
	const char	*want_vh;	/* the vhost that serves it, NULL: refused */
	uint8_t		unix_vh;	/* also a unix socket vhost H3A_NAME */
	uint8_t		host_port;	/* append ":<test port>" to host */
	uint8_t		h3_only;	/* about h3's :authority reselection */
} h3a_cases[] = {
	{ "same-listener",	H3A_NAME, H3A_NAME,	NULL,
	  H3A_NAME,	0, 0, 1 },
	{ "unix-socket",	"pub-b", H3A_NAME,	NULL,
	  "pub-a",	1, 0, 1 },
	{ "host-same",		"pub-b", H3A_NAME,	H3A_NAME,
	  "pub-a",	0, 0, 0 },
	{ "host-default-port",	"pub-b", H3A_NAME,	H3A_NAME ":443",
	  "pub-a",	0, 0, 0 },
	{ "host-case",		"localhost", "localhost", "LocalHost",
	  "localhost",	0, 0, 0 },
	{ "host-v6",		"pub-b", "::1",		"[::1]",
	  "pub-a",	0, 0, 0 },
	{ "host-name",		"pub-b", H3A_NAME,	"evil.example",
	  NULL,		0, 0, 0 },
	{ "host-port",		"pub-b", H3A_NAME,	H3A_NAME,
	  NULL,		0, 1, 0 },
};

static struct lws_context *context;
static lws_sorted_usec_list_t sul_watchdog;
static char body[256], host_hdr[64];
static size_t body_len;
static int port = 7690, completed, timed_out, served;

struct pss_srv {
	char		resp[LWS_PRE + 64];
	size_t		resp_len;
};

/* the server: every vhost answers with its own name */

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
				sizeof(pss->resp) - LWS_PRE, "vh=%s",
				lws_get_vhost_name(lws_get_vhost(wsi)));

		lwsl_user("%s: served by %s\n", __func__, &pss->resp[LWS_PRE]);
		served++;

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
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		if (host_hdr[0]) {
			/* a Host alongside the :authority lws sends */
			unsigned char **p = (unsigned char **)in,
				      *end = (*p) + len;

			if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HOST,
					(unsigned char *)host_hdr,
					(int)strlen(host_hdr), p, end))
				return -1;
		}
		return 0;

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
	{ "h3a", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "h3a", callback_cli, 0, 0, 0, NULL, 0 },
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
	const char *p, *cert = NULL, *key = NULL, *mode = NULL, *alpn = "h3";
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	const struct h3a_case *tc = NULL;
	struct lws_vhost *vh_cli;
	char uds_path[64], want[64];
	int result = 1;
	size_t n;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* listeners on tcp, udp and a unix socket, and both ends */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");
	mode = lws_cmdline_option(argc, argv, "--case");
	if ((p = lws_cmdline_option(argc, argv, "--alpn")))
		alpn = p;

	for (n = 0; mode && n < LWS_ARRAY_SIZE(h3a_cases); n++)
		if (!strcmp(mode, h3a_cases[n].name))
			tc = &h3a_cases[n];

	if (!cert || !key || !tc ||
	    (strcmp(alpn, "h3") && (strcmp(alpn, "h2") || tc->h3_only))) {
		lwsl_err("--cert, --key and --case are required; --alpn is h3 "
			 "(default), or h2 for the host-* cases\n");
		return 1;
	}

	if (tc->host)
		lws_snprintf(host_hdr, sizeof(host_hdr), "%s", tc->host);
	if (tc->host_port) {
		n = strlen(host_hdr);
		lws_snprintf(host_hdr + n, sizeof(host_hdr) - n, ":%d", port);
	}

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: %s :authority, %s\n", alpn, mode);

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/*
	 * The two tls vhosts on one listener.  An alpn naming h3 has a vhost
	 * bring up a quic listener on its port, which the second shares like
	 * its tcp one.  pub-a is first, so it owns them
	 */

	info.port			= port;
	info.protocols			= protocols_srv;
	info.ssl_cert_filepath		= cert;
	info.ssl_private_key_filepath	= key;
	info.alpn			= "h2,http/1.1,h3";

	info.vhost_name = "pub-a";
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create pub-a\n");
		goto bail;
	}

	info.vhost_name = tc->second_vh;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create %s\n", info.vhost_name);
		goto bail;
	}

	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;
	info.alpn			= NULL;

	if (tc->unix_vh) {
		/*
		 * The unix socket vhost the network must not reach.  Named
		 * after our port so parallel runs do not collide; on linux it
		 * is abstract, leaving no file
		 */
#if defined(__linux__)
		lws_snprintf(uds_path, sizeof(uds_path),
			     "@lws-api-test-h3-authority-%d", port);
#else
		lws_snprintf(uds_path, sizeof(uds_path),
			     "lws-api-test-h3-authority-%d.sock", port);
		unlink(uds_path);
#endif
		info.port	= 0;
		info.iface	= uds_path;
		info.vhost_name	= H3A_NAME;
		info.options	|= LWS_SERVER_OPTION_UNIX_SOCK;

		if (!lws_create_vhost(context, &info)) {
			lwsl_err("Failed to create the unix socket vhost\n");
			goto bail;
		}

		info.options	&= ~(uint64_t)LWS_SERVER_OPTION_UNIX_SOCK;
		info.iface	= NULL;
	}

	/* the client vhost */

	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.vhost_name		= "cli";
	info.protocols		= protocols_cli;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create the client vhost\n");
		goto bail;
	}

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= H3A_NAME;
	/* the :authority he sends */
	i.host			= tc->authority;
	i.origin		= tc->authority;
	i.port			= port;
	i.path			= "/";
	i.method		= "GET";
	i.protocol		= "h3a";
	i.alpn			= alpn;
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	/* an h3 case must be decided on h3, not by a fallback to tcp */
	i.disable_h3_fallback	= 1;

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 H3A_TIMEOUT_S * LWS_US_PER_SEC);

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("The connection could not be started\n");
		goto bail;
	}

	while (lws_service(context, 0) >= 0)
		;

	if (tc->want_vh)
		lws_snprintf(want, sizeof(want), "vh=%s", tc->want_vh);

	if (timed_out)
		lwsl_err("FAIL: timed out\n");
	else if (!tc->want_vh) {
		if (served || completed)
			lwsl_err("FAIL: served (%d) as '%s', want refused\n",
				 served, body);
		else
			result = 0;
	} else if (!completed)
		lwsl_err("FAIL: the request did not complete\n");
	else if (strcmp(body, want))
		lwsl_err("FAIL: served as '%s', want '%s'\n", body, want);
	else
		result = 0;

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
