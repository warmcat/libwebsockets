/*
 * lws-api-test-tls-accept-async
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An lws tls server and a burst of lws clients in one process confirm that
 * every connection is served, however its tls accept was done.
 *
 * With LWS_WITH_ASYNC_QUEUE and LWS_MAX_SMP > 1, a server's tls accept steps
 * go to a worker thread, whose queue holds ten jobs per worker.  The poll
 * set takes nothing for the connection while its step is out on the worker.
 * When the queue is full the step is done inline on the service thread
 * instead... and that step can be the one completing the handshake, with the
 * client's request already sent behind its Finished.  The connection must be
 * reading again then, or the request waits for the connection's timeout.
 *
 * The clients make --count concurrent connections at once, alternately h1
 * and h2, each a GET the server answers with a short body, and every one
 * must complete with a 200 and the whole body.
 *
 * Run as is, the burst races the single worker, and some accepts may find
 * its queue full.  With --fault-injection "async_queue_full" every one does,
 * so each tls accept is done inline after being refused by the queue.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#define TAAQ_TIMEOUT_S		20
#define TAAQ_MAX_CONNS		64

static const char body[] = "tls accept async api test body\n";

struct taaq_conn {
	size_t		rx;		/* body bytes the client received */
	char		done;		/* finished, one way or another */
	char		ok;		/* ... with a 200 and the whole body */
};

static struct taaq_conn conns[TAAQ_MAX_CONNS];
static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_start, sul_watchdog;
static const char *server_addr = "localhost", *certs = ".";
static int port = 7681, count = 24, finished, failures, result = 1;

static void
taaq_finish(int idx, int ok, const char *why)
{
	if (idx < 0 || idx >= count || conns[idx].done)
		return;

	conns[idx].done = 1;
	conns[idx].ok = (char)ok;
	if (!ok) {
		lwsl_err("conn %d (%s): FAIL: %s\n", idx,
			 idx & 1 ? "h2" : "h1", why);
		failures++;
	}

	if (++finished == count) {
		lws_sul_cancel(&sul_watchdog);
		result = !!failures;
		lws_default_loop_exit(context);
	}
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	int n;

	for (n = 0; n < count; n++)
		taaq_finish(n, 0, "not complete in time");
}

/* the server: a short body for any GET */

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 256], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain",
						sizeof(body) - 1, &p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		memcpy(start, body, sizeof(body) - 1);
		if (lws_write(wsi, start, sizeof(body) - 1,
			      LWS_WRITE_HTTP_FINAL) != (int)sizeof(body) - 1)
			return 1;
		if (lws_http_transaction_completed(wsi))
			return -1;
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* the clients */

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	int idx = (int)(intptr_t)lws_get_opaque_user_data(wsi) - 1;
	char buf[LWS_PRE + 256], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	if (idx < 0 || idx >= count)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		taaq_finish(idx, 0, in ? (const char *)in : "connection error");
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		conns[idx].rx += len;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (lws_http_client_http_response(wsi) != 200)
			taaq_finish(idx, 0, "not a 200");
		else if (conns[idx].rx != sizeof(body) - 1)
			taaq_finish(idx, 0, "the body was not all received");
		else
			taaq_finish(idx, 1, NULL);
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		taaq_finish(idx, 0, "closed before completing");
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* every connection is started at once, so the accepts arrive as a burst */

static void
start_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	int n;

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 TAAQ_TIMEOUT_S * LWS_US_PER_SEC);

	for (n = 0; n < count; n++) {
		memset(&i, 0, sizeof(i));
		i.context		= context;
		i.vhost			= vh_cli;
		i.address		= server_addr;
		i.host			= "localhost";
		i.origin		= "localhost";
		i.port			= port;
		i.path			= "/";
		i.method		= "GET";
		i.protocol		= "taaq";
		/* each its own connection, so each its own tls accept */
		i.alpn			= n & 1 ? "h2" : "http/1.1";
		i.opaque_user_data	= (void *)(intptr_t)(n + 1);
		i.ssl_connection	= LCCSCF_USE_SSL |
					  LCCSCF_ALLOW_SELFSIGNED |
					  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;

		if (!lws_client_connect_via_info(&i))
			taaq_finish(n, 0, "the connection could not be started");
	}
}

static const struct lws_protocols protocols_srv[] = {
	{ "taaq", callback_srv, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "taaq", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	char srv_cert[256], srv_key[256];
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* a listener and both ends of every connection */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "-s")))
		server_addr = p;
	if ((p = lws_cmdline_option(argc, argv, "--certs")))
		certs = p;
	if ((p = lws_cmdline_option(argc, argv, "--count"))) {
		count = atoi(p);
		if (count < 1 || count > TAAQ_MAX_CONNS) {
			lwsl_err("--count must be 1 .. %d\n", TAAQ_MAX_CONNS);
			return 1;
		}
	}

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: tls accepts, async and inline\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
#if defined(LWS_WITH_ASYNC_QUEUE)
	/* one worker, so its queue holds ten jobs */
	info.count_async_threads = 1;
#endif

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	lws_snprintf(srv_cert, sizeof(srv_cert), "%s/localhost-100y.cert", certs);
	lws_snprintf(srv_key, sizeof(srv_key), "%s/localhost-100y.key", certs);

	info.port			= port;
	info.vhost_name			= "srv";
	info.protocols			= protocols_srv;
	info.ssl_cert_filepath		= srv_cert;
	info.ssl_private_key_filepath	= srv_key;
	info.alpn			= "h2,http/1.1";

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create the server vhost\n");
		goto bail;
	}

	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;
	info.alpn			= NULL;

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.vhost_name			= "cli";
	info.protocols			= protocols_cli;

	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create the client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_start, start_cb, 1);

	while (n >= 0)
		n = lws_service(context, 0);

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_context_destroy(context);

	lwsl_user("Completed: %s (%d of %d connections failed)\n",
		  result ? "FAIL" : "PASS", failures, count);

	return result;
}
