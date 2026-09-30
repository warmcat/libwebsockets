/*
 * lws-api-test-tls-cert-rotate
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A tls server vhost's certificate is renewed while it is serving, the way a
 * cert renewal does it: the cert and key files the vhost was created with
 * are rewritten, and lws_tls_cert_updated() is told about the paths.
 *
 * lws is both ends here.  After each step a fresh client connection to the
 * vhost must be served, under the certificate the step expects:
 *
 *  - the cert the vhost was created with
 *  - a renewed cert, after the rotation
 *  - the renewed cert still, after a rotation that could not load (the new
 *    key file is still empty), since a failed rotation leaves the vhost on
 *    what it had
 *  - the first cert again, after a second rotation
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define LIVE_CERT	"tls-cert-rotate-live.cert"
#define LIVE_KEY	"tls-cert-rotate-live.key"

enum rotation {
	ROT_NONE,	/* connect to the vhost as it is */
	ROT_OK,		/* renew the cert, then connect */
	ROT_NO_KEY,	/* renewal half-written: the key file is still empty */
};

struct step {
	const char	*name;
	const char	*cert;		/* in --certs dir, to write into LIVE_ */
	const char	*key;
	enum rotation	rot;
	const char	*expect_cn;	/* the cert the client must be shown */
};

static const struct step steps[] = {
	{ "initial cert", NULL, NULL, ROT_NONE, "localhost" },
	{ "rotated", "wronghost.example.com.cert", "wronghost.example.com.key",
	  ROT_OK, "wronghost.example.com" },
	{ "rotation without a key keeps the cert", "localhost-100y.cert", NULL,
	  ROT_NO_KEY, "wronghost.example.com" },
	{ "rotated back", "localhost-100y.cert", "localhost-100y.key",
	  ROT_OK, "localhost" },
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static int result = 1, cur = -1, port = 7681;
static const char *server_addr = "127.0.0.1", *certs_dir = ".";

/* what the client saw for the current step */
static struct {
	char		cn[64];
	int		status;
	int		done;
	int		failed;
} cli;

/* the server: 200 "ok" to anything */

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

/*
 * Copy a file from the --certs dir over one of the live files the server
 * vhost was created with.  NULL leaves the live file empty.
 */

static int
write_live(const char *live, const char *from)
{
	static char buf[8192];
	char path[256];
	int n = 0;

	if (from) {
		lws_snprintf(path, sizeof(path), "%s/%s", certs_dir, from);
		n = lws_plat_read_file(path, buf, sizeof(buf));
		if (n <= 0 || n == (int)sizeof(buf)) {
			lwsl_err("%s: can't read %s\n", __func__, path);
			return 1;
		}
	}

	if (lws_plat_write_file(live, buf, (size_t)n)) {
		lwsl_err("%s: can't write %s\n", __func__, live);
		return 1;
	}

	return 0;
}

static void
next_step(lws_sorted_usec_list_t *sul);

static void
step_done(const char *why)
{
	if (why) {
		lwsl_err("--- %s: FAIL: %s ---\n", steps[cur].name, why);
		lws_default_loop_exit(context);
		return;
	}

	lwsl_user("--- %s: served under '%s': PASS ---\n", steps[cur].name,
		  cli.cn);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	union lws_tls_cert_info_results ir;
	char buf[LWS_PRE + 256], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		/* only the current step's connection is news */
		if (cur < 0 || lws_get_opaque_user_data(wsi) != &steps[cur])
			return lws_callback_http_dummy(wsi, reason, user, in,
						       len);
		break;
	default:
		break;
	}

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		cli.status = (int)lws_http_client_http_response(wsi);
		if (!lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_COMMON_NAME,
					    &ir, sizeof(ir.ns.name)))
			lws_strncpy(cli.cn, ir.ns.name, sizeof(cli.cn));
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP: {
		const char *why = NULL;

		if (cli.done)
			break;
		cli.done = 1;

		if (cli.status != HTTP_STATUS_OK)
			why = "not served";
		else if (strcmp(cli.cn, steps[cur].expect_cn))
			why = "served under the wrong cert";

		cli.failed = !!why;
		step_done(why);

		/*
		 * Don't let the connection keep warm: the next step must make
		 * a new tls connection, to see what the vhost serves then
		 */
		return -1;
	}

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (!cli.done) {
			cli.done = 1;
			cli.failed = 1;
			step_done(in ? (const char *)in : "connection error");
		}
		return 0;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!cli.done) {
			cli.done = 1;
			cli.failed = 1;
			step_done("closed without completing");
			break;
		}
		if (!cli.failed)
			lws_sul_schedule(context, 0, &sul_next, next_step, 1);
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
next_step(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	const struct step *s;

	if (++cur == (int)LWS_ARRAY_SIZE(steps)) {
		lwsl_user("--- all steps passed ---\n");
		result = 0;
		lws_default_loop_exit(context);
		return;
	}
	s = &steps[cur];
	memset(&cli, 0, sizeof(cli));

	if (s->rot != ROT_NONE) {
		if (write_live(LIVE_CERT, s->cert) ||
		    write_live(LIVE_KEY, s->rot == ROT_OK ? s->key : NULL)) {
			step_done("unable to renew the files");
			return;
		}

		if (lws_tls_cert_updated(context, LIVE_CERT, LIVE_KEY,
					 NULL, 0, NULL, 0)) {
			step_done("lws_tls_cert_updated() failed");
			return;
		}
	}

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.port			= port;
	i.path			= "/";
	i.method		= "GET";
	i.protocol		= "cli";
	i.local_protocol_name	= "cli";
	i.alpn			= "http/1.1";
	/* both certs are self-signed, and neither is for server_addr */
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	i.opaque_user_data	= (void *)s;

	if (!lws_client_connect_via_info(&i))
		step_done("connect failed");
}

static void
sul_watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("--- timed out in step %d ---\n", cur);
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
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;
	if ((p = lws_cmdline_option(argc, argv, "--certs")))
		certs_dir = p;

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: tls server cert rotation\n");

	/* the vhost starts out on the first cert */

	if (write_live(LIVE_CERT, "localhost-100y.cert") ||
	    write_live(LIVE_KEY, "localhost-100y.key"))
		return 1;

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.protocols			= protocols_srv;
	info.port			= port;
	info.vhost_name			= "srv";
	info.ssl_cert_filepath		= LIVE_CERT;
	info.ssl_private_key_filepath	= LIVE_KEY;
	if (!lws_create_vhost(context, &info))
		goto bail;

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.vhost_name			= "cli";
	info.protocols			= protocols_cli;
	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli)
		goto bail;

	lws_sul_schedule(context, 0, &sul_next, next_step, 1);
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
