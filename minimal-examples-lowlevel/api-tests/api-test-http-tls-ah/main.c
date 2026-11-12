/*
 * lws-api-test-http-tls-ah
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A server http connection's header table (ah) comes from a small pool, and
 * its hold, timeout_secs_ah_idle, is the deadline for the request head.  A
 * tls connection must only take one when its handshake has completed: the
 * handshake is bounded by the tls accept timeout, timeout_secs, and needs no
 * ah.  Otherwise a peer that connects and never finishes its handshake pins
 * an ah from the pool until the ah idle timeout, and a slow handshake, eg,
 * on a server short of cpu, eats into the time its request head is given.
 *
 * The server's pool has room for exactly what one https request needs, its
 * own and that of the lws client in the same process.  On h2, the server's
 * own is its stream's: a network connection alpn made h2 takes none.  Then:
 *
 *  - a raw connection connects to the tls server and sends nothing
 *
 *  - a little later, an lws https client GETs /, over h1 or, with --h2, h2
 *    by alpn.  It must be answered well inside the ah idle timeout: if the
 *    silent connection held an ah, there would be none for this one until
 *    the silent one's hold expired.
 *
 *  - the silent connection must then be closed by the server's tls accept
 *    timeout, not at the ah idle timeout, which only an ah would have
 *    given it.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

/* the server's ah idle timeout, and its other timeouts, longer */
#define TAH_AH_IDLE_S		2
#define TAH_TIMEOUT_S		4
/* the https client starts this long after the silent connection connected */
#define TAH_LEAD_MS		200
/* ... and must be answered within this, well inside the ah idle timeout */
#define TAH_ANSWER_MS		1000
/* the silent connection must last at least this long */
#define TAH_SILENT_MIN_MS	((TAH_AH_IDLE_S * 1000) + 1000)
#define TAH_DEADLINE_S		15

/*
 * What one https GET needs from the pool, the server's and the lws client's
 * own, which share it here: one each.  On h2, that is the server's stream:
 * its network connection must not hold one as well.
 */
#define TAH_POOL		2

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_watchdog, sul_get;
static const char *server_addr = "127.0.0.1";
static int port = 7681, result = 1, finished, h2;

static struct {
	lws_usec_t	silent_up;	/* the silent connection connected */
	lws_usec_t	get_start;	/* the https GET was started */
	int		answered;
	int		status;
} st;

static void
finish(int ok, const char *why)
{
	if (finished)
		return;

	finished = 1;
	result = !ok;
	if (ok)
		lwsl_user("%s: %s\n", __func__, why);
	else
		lwsl_err("%s: FAIL: %s\n", __func__, why);

	lws_default_loop_exit(context);
}

/*
 * The server: a small answer for any GET
 */

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
			return -1;

		lws_callback_on_writable(wsi);

		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		memcpy(start, "ok", 2);
		if (lws_write(wsi, start, 2, LWS_WRITE_HTTP_FINAL) != 2)
			return -1;

		if (lws_http_transaction_completed(wsi))
			return -1;

		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * The silent connection: connects and sends nothing
 */

static void
start_get(lws_sorted_usec_list_t *sul);

static int
callback_silent(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	char why[128];
	lws_usec_t ms;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		finish(0, in ? (const char *)in :
			       "silent connection: connection error");
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		st.silent_up = lws_now_usecs();
		lws_sul_schedule(context, 0, &sul_get, start_get,
				 TAH_LEAD_MS * LWS_US_PER_MS);
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		ms = (lws_now_usecs() - st.silent_up) / LWS_US_PER_MS;

		if (!st.answered) {
			lws_snprintf(why, sizeof(why), "silent connection "
				     "closed after %dms, before the GET was "
				     "answered", (int)ms);
			finish(0, why);
			break;
		}

		if (ms < TAH_SILENT_MIN_MS) {
			lws_snprintf(why, sizeof(why), "silent connection "
				     "closed after %dms, want the tls accept "
				     "timeout (%ds), not the ah idle (%ds)",
				     (int)ms, TAH_TIMEOUT_S, TAH_AH_IDLE_S);
			finish(0, why);
			break;
		}

		lws_snprintf(why, sizeof(why), "silent connection closed "
			     "after %dms", (int)ms);
		finish(1, why);
		break;

	default:
		break;
	}

	return 0;
}

/*
 * The https client
 */

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 256], *px = buf + LWS_PRE, why[128];
	int lenx = (int)(sizeof(buf) - LWS_PRE), mux;
	lws_usec_t ms;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		finish(0, in ? (const char *)in : "https client: connection "
						  "error");
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		/* an h2 stream is not the wsi with the connection */
		mux = lws_get_network_wsi(wsi) != wsi;
		st.status = (int)lws_http_client_http_response(wsi);
		lwsl_user("%s: status %d, on %s\n", __func__, st.status,
			  mux ? "h2" : "h1");
		if (h2 != mux) {
			finish(0, "the GET went on the wrong protocol");
			return -1;
		}
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;

		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		ms = (lws_now_usecs() - st.get_start) / LWS_US_PER_MS;

		if (st.status != HTTP_STATUS_OK) {
			lws_snprintf(why, sizeof(why), "GET answered %d",
				     st.status);
			finish(0, why);
			break;
		}

		if (ms > TAH_ANSWER_MS) {
			lws_snprintf(why, sizeof(why), "GET answered after "
				     "%dms, want within %dms", (int)ms,
				     TAH_ANSWER_MS);
			finish(0, why);
			break;
		}

		lwsl_user("%s: GET answered after %dms\n", __func__, (int)ms);
		st.answered = 1;
		/* now we wait for the server to close the silent connection */
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
start_get(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.port			= port;
	i.path			= "/";
	i.method		= "GET";
	i.protocol		= "tah-cli";
	i.alpn			= h2 ? "h2" : "http/1.1";
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;

	st.get_start = lws_now_usecs();
	if (!lws_client_connect_via_info(&i))
		finish(0, "the https GET could not be started");
}

static const struct lws_protocols protocols_srv[] = {
	{ "tah", callback_srv, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "tah-cli", callback_cli, 0, 0, 0, NULL, 0 },
	{ "tah-silent", callback_silent, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	finish(0, st.answered ? "timed out waiting for the silent connection "
				"to close" : "timed out waiting for the GET");
}

static void
sigint_handler(int sig)
{
	finish(0, "interrupted");
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	const char *p, *cert, *key;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* a server and its clients */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;
	h2 = !!lws_cmdline_option(argc, argv, "--h2");
	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");

	if (!cert || !key) {
		lwsl_err("Usage: %s --cert <path> --key <path> [-p <port>] "
			 "[--server <addr>] [--h2]\n", argv[0]);
		return 1;
	}

#if !defined(LWS_ROLE_H2)
	if (h2) {
		lwsl_err("this build has no h2\n");
		return 1;
	}
#endif

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: tls connection's ah, on %s\n",
		  h2 ? "h2" : "h1");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.timeout_secs = TAH_TIMEOUT_S;
	info.timeout_secs_ah_idle = TAH_AH_IDLE_S;
	info.max_http_header_pool = TAH_POOL;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.port			= port;
	info.vhost_name			= "tah";
	info.protocols			= protocols_srv;
	info.ssl_cert_filepath		= cert;
	info.ssl_private_key_filepath	= key;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create the server vhost\n");
		goto bail;
	}

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.vhost_name			= "cli";
	info.protocols			= protocols_cli;
	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;

	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create the client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 TAH_DEADLINE_S * LWS_US_PER_SEC);

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.port			= port;
	i.method		= "RAW";
	i.protocol		= "tah-silent";
	i.local_protocol_name	= "tah-silent";

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("The silent connection could not be started\n");
		goto bail;
	}

	while (!finished && lws_service(context, 0) >= 0)
		;

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_get);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
