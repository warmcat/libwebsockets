/*
 * lws-api-test-alpn-transport
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * h3 is only ever carried by quic, and the h1 and h2 roles only by tcp: a
 * connection that negotiated an alpn on the wrong transport would migrate to
 * a role that can never make progress on it.  So neither a client nor a
 * server may negotiate h3 on tcp, and a request the client may only make with
 * h3 must go on quic, also when it is redirected.
 *
 * One process has five server vhosts, each on its own port with the alpn list
 * "h3,h2,http/1.1", so each listens on both tcp and quic, and a client.  The
 * servers answer with the protocol the request came on, "h1", "h2" or "h3".
 * Each step is a GET to an origin the client knows nothing about yet, so what
 * it learned about the others' h3 doesn't decide its transport:
 *
 *  - h3 alone: the client asks for "h3" alone: served over h3, although the
 *    client knows of no h3 there
 *
 *  - h3 alone, redirected: the server redirects the request, which only h3
 *    can carry, to another the client knows nothing about either: the
 *    redirect is followed on quic too, and served over h3
 *
 *  - tcp, h3 offered: the client asks for "h3,h2,http/1.1", and as it knows of
 *    no h3 there, connects on tcp, leaving h3 out of what it offers: served
 *    over h2
 *
 *  - tcp, h3 offered anyway: the client offers "h3,http/1.1" on tcp as it was
 *    given (fault tls_alpn_unfiltered, as a client that is not lws might): the
 *    server does not select h3 there, it is served over h1.  Only with
 *    LWS_WITH_SYS_FAULT_INJECTION
 *
 *  - h3 alone, slow handshake: the client takes 2.5s of cpu to verify the
 *    server's cert (fault tls_quic_cert_slow), as a slow device may, which is
 *    longer than its grace for quic to show it gets through at all: that was
 *    answered when the server's handshake reached it, so it carries on, and
 *    the request is served over h3.  Only with LWS_WITH_SYS_FAULT_INJECTION
 *
 * The test fails if a step isn't served over what it expects, or the steps
 * don't finish inside the watchdog period.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define STEP_TIMEOUT_S	10

static const struct step {
	const char	*name;
	const char	*alpn;
	const char	*path;
	const char	*fault;		/* the client wsi's, or NULL */
	unsigned int	verify_ms;	/* fault: the client's cert verify takes */
	int		server;		/* index of the server it goes to */
	int		redir;		/* index of the server /redir goes to */
	const char	*served;	/* over what it must be served */
} steps[] = {
	{ "h3 alone: made on quic",
	  "h3", "/", NULL, 0, 0, 0, "h3" },
	{ "h3 alone, redirected: the redirect is followed on quic",
	  "h3", "/redir", NULL, 0, 0, 1, "h3" },
	{ "tcp, h3 offered: h3 left out on tcp",
	  "h3,h2,http/1.1", "/", NULL, 0, 2, 0, "h2" },
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	{ "tcp, h3 offered anyway: the server doesn't select it on tcp",
	  "h3,http/1.1", "/", "tls_alpn_unfiltered", 0, 3, 0, "h1" },
	{ "h3 alone, slow handshake: not abandoned after the path is proven",
	  "h3", "/", NULL, 2500, 4, 0, "h3" },
#endif
};

static struct lws_context *context;
static lws_sorted_usec_list_t sul_step, sul_watchdog;
static const char *server_addr = "127.0.0.1";
static int ports[] = { 7700, 7701, 7702, 7703, 7704 }, cur = -1, failures;

static struct {
	char		body[16];
	size_t		body_len;
	char		completed;
	char		failed;
} st;

struct pss_srv {
	char		resp[LWS_PRE + 16];
	size_t		resp_len;
};

/* the servers: answer with the protocol the request came on */

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t hdr[LWS_PRE + 256], *start = &hdr[LWS_PRE], *p = start,
		*end = &hdr[sizeof(hdr) - 1];
	const char *over;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		if (in && !strcmp((const char *)in, "/redir")) {
			char loc[64];
			int n;

			/* only h3 can carry the request there */
			n = lws_snprintf(loc, sizeof(loc), "https://%s:%d/",
					 server_addr, ports[steps[cur].redir]);
			if (lws_http_redirect(wsi, HTTP_STATUS_FOUND,
					      (const unsigned char *)loc, n,
					      &p, end) < 0 ||
			    lws_http_transaction_completed(wsi))
				return -1;
			return 0;
		}

		/*
		 * A quic connection has no socket of its own, it shares its
		 * listener's.  Of the tcp ones, h1 has no :path, h2 does
		 */
		if (lws_get_socket_fd(lws_get_network_wsi(wsi)) ==
							LWS_SOCK_INVALID)
			over = "h3";
		else
			over = lws_hdr_total_length(wsi,
					WSI_TOKEN_HTTP_COLON_PATH) ? "h2" : "h1";

		pss->resp_len = (size_t)lws_snprintf(&pss->resp[LWS_PRE],
				sizeof(pss->resp) - LWS_PRE, "%s", over);

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

static void
next_step(lws_sorted_usec_list_t *sul);

static void
step_done(void)
{
	const struct step *s = &steps[cur];
	int bad = !st.completed || st.failed || strcmp(st.body, s->served);

	lws_sul_cancel(&sul_watchdog);

	if (bad) {
		lwsl_err("%s: %s, served over '%s', expected '%s'\n", s->name,
			 st.completed ? "completed" : "never completed",
			 st.body, s->served);
		failures++;
	}

	lwsl_user("%s: step %d: %s\n", bad ? "FAIL" : "PASS", cur, s->name);

	lws_sul_schedule(context, 0, &sul_step, next_step, 1);
}

/* the client */

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 256], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if ((intptr_t)lws_get_opaque_user_data(wsi) != cur + 1)
			/* not the connection of the step we are on */
			return lws_callback_http_dummy(wsi, reason, user,
						       in, len);
		break;
	default:
		break;
	}

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: connection error: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		st.failed = 1;
		step_done();
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (len > sizeof(st.body) - 1 - st.body_len)
			len = sizeof(st.body) - 1 - st.body_len;
		memcpy(st.body + st.body_len, in, len);
		st.body_len += len;
		st.body[st.body_len] = '\0';
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		st.completed = 1;
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		step_done();
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "alpnt", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "alpnt", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: step %d timed out\n", __func__, cur);
	failures++;
	lws_default_loop_exit(context);
}

static void
next_step(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	const struct step *s;
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	lws_fi_t fi;
#endif

	if (++cur == (int)LWS_ARRAY_SIZE(steps)) {
		lws_default_loop_exit(context);
		return;
	}

	s = &steps[cur];
	memset(&st, 0, sizeof(st));
	lwsl_user("%s: step %d: %s\n", __func__, cur, s->name);

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.port			= ports[s->server];
	i.path			= s->path;
	i.method		= "GET";
	i.protocol		= "alpnt";
	i.alpn			= s->alpn;
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	/* which step the connection is for */
	i.opaque_user_data	= (void *)(intptr_t)(cur + 1);

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	if (s->fault) {
		memset(&fi, 0, sizeof(fi));
		fi.name = s->fault;
		fi.type = LWSFI_ALWAYS;
		if (lws_fi_add(&i.fic, &fi)) {
			failures++;
			lws_default_loop_exit(context);
			return;
		}
	}
	if (s->verify_ms) {
		/* only the first of the server's Handshake flight is slow... */
		memset(&fi, 0, sizeof(fi));
		fi.name = "tls_quic_cert_slow";
		fi.type = LWSFI_DETERMINISTIC;
		fi.count = 1;
		if (lws_fi_add(&i.fic, &fi)) {
			failures++;
			lws_default_loop_exit(context);
			return;
		}
		/* ... and takes this long */
		fi.name = "tls_quic_cert_slow_ms";
		fi.type = LWSFI_RANGE;
		fi.pre = s->verify_ms;
		fi.count = s->verify_ms + 1;
		if (lws_fi_add(&i.fic, &fi)) {
			failures++;
			lws_default_loop_exit(context);
			return;
		}
	}
#endif

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 STEP_TIMEOUT_S * LWS_US_PER_SEC);

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: the connection could not be started\n", s->name);
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
		lws_fi_destroy(&i.fic);
#endif
		failures++;
		lws_default_loop_exit(context);
	}
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	const char *p, *cert = NULL, *key = NULL;
	struct lws_context_creation_info info;
	char opt[16], vhn[LWS_ARRAY_SIZE(ports)][8];
	size_t n;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.fd_limit_per_thread = 0;

	for (n = 0; n < LWS_ARRAY_SIZE(ports); n++) {
		lws_snprintf(opt, sizeof(opt), "--port%d", (int)n);
		if ((p = lws_cmdline_option(argc, argv, opt)))
			ports[n] = atoi(p);
	}
	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");

	if (!cert || !key) {
		lwsl_err("--cert and --key are required\n");
		return 1;
	}

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: alpn and the transport carrying it\n");

	/* the context's default vhost is the client one */

	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols_cli;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.protocols			= protocols_srv;
	info.ssl_cert_filepath		= cert;
	info.ssl_private_key_filepath	= key;

	/*
	 * Listing h3 makes each listen on quic as well as tcp, and advertise
	 * it there.  Each step goes to its own server, so that what the client
	 * learned at another doesn't decide the transport
	 */

	info.alpn = "h3,h2,http/1.1";
	for (n = 0; n < LWS_ARRAY_SIZE(ports); n++) {
		lws_snprintf(vhn[n], sizeof(vhn[n]), "srv%d", (int)n);
		info.vhost_name	= vhn[n];
		info.port	= ports[n];
		if (!lws_create_vhost(context, &info)) {
			lwsl_err("Failed to create server vhost %s\n", vhn[n]);
			goto bail;
		}
	}

	lws_sul_schedule(context, 0, &sul_step, next_step, 1);

	while (lws_service(context, 0) >= 0)
		;

bail:
	lws_sul_cancel(&sul_step);
	lws_sul_cancel(&sul_watchdog);
	lws_context_destroy(context);

	lwsl_user("Completed: %s (%d of %d steps failed)\n",
		  failures ? "FAIL" : "PASS", failures,
		  (int)LWS_ARRAY_SIZE(steps));

	return !!failures;
}
