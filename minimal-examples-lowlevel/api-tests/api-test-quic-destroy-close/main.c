/*
 * lws-api-test-quic-destroy-close
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A quic connection still open when its context is destroyed tells the peer
 * with CONNECTION_CLOSE (RFC 9000 10.2).  A tcp connection's peer hears of
 * it from the kernel's FIN, but quic has no transport close: without it, the
 * peer holds the connection until it idles out, and may take a last packet
 * of ours arriving from an address it sees changed (eg, a NAT rebinding) for
 * a migration, probing a path nobody is left to answer.
 *
 * An h3 server runs on the main thread, with its own context.  A client, on
 * another thread with a context of its own, GETs from it, and destroys its
 * context as soon as it has the answer, leaving its connection kept warm.
 * The server, which would wait QDC_IDLE_S for the connection's next request,
 * must see the connection go within QDC_GONE_MAX_US of the client's context
 * being destroyed.
 */

#include <libwebsockets.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define QDC_TIMEOUT_S		20
/* the server would hold an idle connection this long */
#define QDC_IDLE_S		10
/* how soon after the client's context went the server must see it go */
#define QDC_GONE_MAX_US		(1 * LWS_US_PER_SEC)

static struct lws_context *cx_srv;
static lws_sorted_usec_list_t sul_watchdog, sul_poll;
static const char *server_addr = "127.0.0.1";
static int port, result = 1, finished;

/*
 * what the two threads know of each other, under lock: when the client's
 * context was destroyed, and when the server saw the connection go
 */
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct lws_context *cx_cli;
static lws_usec_t cli_destroyed, srv_conn_gone;
static int cli_status, cli_stop;

/* ------------------------------------------------------------- server */

struct pss_srv {
	char			respond;
};

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t buf[LWS_PRE + 256], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		/* mark the connection the request came on, to see it go */
		lws_set_opaque_user_data(lws_get_network_wsi(wsi),
					 (void *)&lock);
		pss->respond = 1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		/* h3 asks for WRITEABLE for its own reasons as well */
		if (!pss || !pss->respond)
			break;
		pss->respond = 0;

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain", 2, &p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return -1;
		memcpy(start, "ok", 2);
		if (lws_write(wsi, start, 2, LWS_WRITE_HTTP_FINAL) != 2)
			return -1;
		if (lws_http_transaction_completed(wsi))
			return -1;
		break;

	case LWS_CALLBACK_WSI_DESTROY:
		/* the network connection, not one of its streams */
		if (lws_get_network_wsi(wsi) == wsi &&
		    lws_get_opaque_user_data(wsi) == (void *)&lock) {
			pthread_mutex_lock(&lock);
			srv_conn_gone = lws_now_usecs();
			pthread_mutex_unlock(&lock);
			lwsl_user("%s: server: the connection went\n",
				  __func__);
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
qdc_finish(const char *why, int ok)
{
	if (finished)
		return;
	finished = 1;
	if (ok) {
		result = 0;
		lwsl_user("%s: %s\n", __func__, why);
	} else
		lwsl_err("%s: FAIL: %s\n", __func__, why);

	/* a client still waiting for its answer stops waiting */
	pthread_mutex_lock(&lock);
	cli_stop = 1;
	if (cx_cli)
		lws_cancel_service(cx_cli);
	pthread_mutex_unlock(&lock);

	lws_default_loop_exit(cx_srv);
}

/* on the server thread: has what we wait for happened yet? */
static void
poll_cb(lws_sorted_usec_list_t *sul)
{
	lws_usec_t destroyed, gone, now = lws_now_usecs();
	int status;

	pthread_mutex_lock(&lock);
	destroyed = cli_destroyed;
	gone = srv_conn_gone;
	status = cli_status;
	pthread_mutex_unlock(&lock);

	if (status < 0) {
		qdc_finish("the client's GET failed", 0);
		return;
	}

	if (destroyed && gone) {
		lwsl_user("%s: the connection went %lldms after the client's "
			  "context\n", __func__,
			  (long long)(gone - destroyed) / LWS_US_PER_MS);
		if (gone < destroyed)
			qdc_finish("the connection went before the client's "
				   "context", 0);
		else if (gone - destroyed > QDC_GONE_MAX_US)
			qdc_finish("the server held the connection after the "
				   "client's context went", 0);
		else
			qdc_finish("the client's context going closed its "
				   "connection at the server", 1);
		return;
	}

	if (destroyed && now - destroyed > QDC_GONE_MAX_US) {
		qdc_finish("the server holds the connection the client's "
			   "context left", 0);
		return;
	}

	lws_sul_schedule(cx_srv, 0, &sul_poll, poll_cb, 50 * LWS_US_PER_MS);
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	qdc_finish("timed out", 0);
}

/* ------------------------------------------------------------- client */

static int cli_done;

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 1024], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE, status = 0;

	switch (reason) {
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		status = (int)lws_http_client_http_response(wsi);
		lwsl_user("%s: client: GET answered %d\n", __func__, status);
		if (status != 200)
			status = -1;
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: client: connection error: %s\n", __func__,
			 in ? (const char *)in : "(null)");
		status = -1;
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		status = -1;
		break;

	default:
		break;
	}

	if (status && !cli_done) {
		cli_done = 1;
		pthread_mutex_lock(&lock);
		cli_status = status;
		pthread_mutex_unlock(&lock);
		/* the answered GET's connection stays, kept warm */
		lws_cancel_service(lws_get_context(wsi));
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_cli[] = {
	{ "cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void *
client_thread(void *d)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	struct lws_context *cx;
	int stop = 0;

	lws_context_info_defaults(&info, NULL);
	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.protocols		= protocols_cli;
	info.options		= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("%s: client context failed\n", __func__);
		goto bail;
	}

	pthread_mutex_lock(&lock);
	cx_cli = cx;
	pthread_mutex_unlock(&lock);

	memset(&i, 0, sizeof(i));
	i.context		= cx;
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.port			= port;
	i.path			= "/";
	i.method		= "GET";
	i.alpn			= "h3";
	i.protocol		= "cli";
	i.local_protocol_name	= "cli";
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	i.disable_h3_fallback	= 1;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: client connect failed\n", __func__);
		goto bail_cx;
	}

	while (!cli_done && !stop && lws_service(cx, 0) >= 0) {
		pthread_mutex_lock(&lock);
		stop = cli_stop;
		pthread_mutex_unlock(&lock);
	}

	/* the connection is still open: the context going must close it */
	pthread_mutex_lock(&lock);
	cli_destroyed = lws_now_usecs();
	cx_cli = NULL;
	pthread_mutex_unlock(&lock);
	lws_context_destroy(cx);
	lwsl_user("%s: client: context destroyed\n", __func__);

	return NULL;

bail_cx:
	pthread_mutex_lock(&lock);
	cx_cli = NULL;
	pthread_mutex_unlock(&lock);
	lws_context_destroy(cx);
bail:
	pthread_mutex_lock(&lock);
	cli_status = -1;
	pthread_mutex_unlock(&lock);

	return NULL;
}

static void
sigint_handler(int sig)
{
	qdc_finish("interrupted", 0);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p, *cert, *key;
	pthread_t thr;
	int started = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");
	if (!cert || !key || port < 1 || port > 65535) {
		lwsl_err("-p <port>, --cert and --key are required\n");
		return 1;
	}

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: a quic connection closes with its "
		  "context\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	cx_srv = lws_create_context(&info);
	if (!cx_srv) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* an alpn naming h3 has the vhost bring up a quic listener too */
	info.port			= port;
	info.protocols			= protocols_srv;
	info.ssl_cert_filepath		= cert;
	info.ssl_private_key_filepath	= key;
	info.alpn			= "h3";
	info.vhost_name			= "srv";
	/* longer than we wait to see the connection go */
	info.keepalive_timeout		= QDC_IDLE_S;
	if (!lws_create_vhost(cx_srv, &info)) {
		lwsl_err("Failed to create the server vhost\n");
		goto bail;
	}

	if (pthread_create(&thr, NULL, client_thread, NULL)) {
		lwsl_err("Failed to start the client thread\n");
		goto bail;
	}
	started = 1;

	lws_sul_schedule(cx_srv, 0, &sul_watchdog, watchdog_cb,
			 QDC_TIMEOUT_S * LWS_US_PER_SEC);
	lws_sul_schedule(cx_srv, 0, &sul_poll, poll_cb, 50 * LWS_US_PER_MS);

	while (!finished && lws_service(cx_srv, 0) >= 0)
		;

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_poll);
	if (started)
		pthread_join(thr, NULL);
	lws_context_destroy(cx_srv);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
