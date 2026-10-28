/*
 * lws-api-test-h3-goaway-retry
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An h3 server closing a connection of its own accord, because it waited
 * long enough for a request, or for the next one, sends GOAWAY saying which
 * requests it did not process (RFC 9114 5.2), then CONNECTION_CLOSE with
 * H3_NO_ERROR.  A client whose request was lost on its way, so the server
 * never heard of it, used to see its request fail with the connection.  Now
 * a GET or HEAD the server did not answer goes again, once, on a new
 * connection, and the app sees only its answer.
 *
 * An h3 server and its clients are in this process, each part's client on
 * its own vhost so it has a connection of its own.  The server waits
 * GRT_IDLE_S for a connection's first request, and as long for its next.  The
 * h3_req_lost fault loses a request's first try.
 *
 *  A: a GET's first try is lost.  The server closes the connection after
 *     GRT_IDLE_S, and the GET is answered on a new one.
 *
 *  B: a POST's first try is lost.  It is not idempotent, so it is not sent
 *     again: it fails with the connection, and the server never sees it.
 *
 *  C: a GET is answered, then a second GET on the same connection is lost.
 *     The server's GOAWAY says it took the first stream only, and the second
 *     GET is answered on a new connection.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define GRT_TIMEOUT_S		20
#define GRT_IDLE_S		1
/* the lost requests can be answered only after the server gave up on them */
#define GRT_RETRY_MIN_US	((GRT_IDLE_S * LWS_US_PER_SEC) - (200 * LWS_US_PER_MS))

enum {
	GRT_A,
	GRT_B,
	GRT_C1,
	GRT_C2,

	GRT_COUNT
};

struct grt_req {
	const char		*path;
	const char		*method;
	lws_usec_t		start;
	int			status; /* 0 until it ends, -1 if it failed */
	int			srv_hits;
	char			srv_conn[64];
	char			lost; /* its first try is lost */
	char			want_ok;
};

static struct grt_req reqs[GRT_COUNT] = {
	[GRT_A]  = { .path = "/a",  .method = "GET",  .lost = 1, .want_ok = 1 },
	[GRT_B]  = { .path = "/b",  .method = "POST", .lost = 1 },
	[GRT_C1] = { .path = "/c1", .method = "GET",             .want_ok = 1 },
	[GRT_C2] = { .path = "/c2", .method = "GET",  .lost = 1, .want_ok = 1 },
};

static struct lws_context *context;
static struct lws_vhost *vh_cli[3];
static lws_sorted_usec_list_t sul_watchdog, sul_c2;
static const char *server_addr = "127.0.0.1";
static int port, result = 1, finished;

static void grt_check(void);

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
	int n;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		for (n = 0; n < GRT_COUNT; n++)
			if (!strcmp((const char *)in, reqs[n].path)) {
				reqs[n].srv_hits++;
				lws_strncpy(reqs[n].srv_conn,
					    lws_wsi_tag(lws_get_network_wsi(wsi)),
					    sizeof(reqs[n].srv_conn));
			}
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

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* ------------------------------------------------------------- client */

static int
grt_request(int idx)
{
	struct grt_req *r = &reqs[idx];
	struct lws_client_connect_info i;
	lws_fi_t fi;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	/* C's two requests share a connection, the others have their own */
	i.vhost			= vh_cli[idx < GRT_C1 ? idx : 2];
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.port			= port;
	i.path			= r->path;
	i.method		= r->method;
	i.alpn			= "h3";
	i.protocol		= "cli";
	i.local_protocol_name	= "cli";
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK |
				  LCCSCF_PIPELINE;
	i.disable_h3_fallback	= 1;
	i.opaque_user_data	= r;

	if (r->lost) {
		/* the request's first try, and only that, is lost */
		memset(&fi, 0, sizeof(fi));
		fi.name = "h3_req_lost";
		fi.type = LWSFI_DETERMINISTIC;
		fi.pre = 0;
		fi.count = 1;
		if (lws_fi_add(&i.fic, &fi))
			return 1;
	}

	r->start = lws_now_usecs();
	if (!lws_client_connect_via_info(&i)) {
		/* the client wsi takes the fault, unless there was none */
		lws_fi_destroy(&i.fic);
		r->status = -1;
		return 1;
	}

	return 0;
}

static void
c2_cb(lws_sorted_usec_list_t *sul)
{
	if (grt_request(GRT_C2))
		grt_check();
}

static void
grt_req_done(struct grt_req *r, int status)
{
	if (!r || r->status)
		return;
	r->status = status;

	lwsl_user("%s: %s %s: %d after %lldms\n", __func__, r->method, r->path,
		  status, (long long)(lws_now_usecs() - r->start) /
							LWS_US_PER_MS);

	/* C's second request goes on the connection its first one used */
	if (r == &reqs[GRT_C1] && status > 0) {
		/* from the event loop, not the callback of a request closing */
		lws_sul_schedule(context, 0, &sul_c2, c2_cb, 1);
		return;
	}

	grt_check();
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct grt_req *r = (struct grt_req *)lws_get_opaque_user_data(wsi);
	char buf[LWS_PRE + 1024], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		grt_req_done(r, (int)lws_http_client_http_response(wsi));
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: CONNECTION_ERROR: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		grt_req_done(r, -1);
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		grt_req_done(r, -1);
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

static const struct lws_protocols protocols_cli[] = {
	{ "cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
grt_finish(const char *why, int ok)
{
	if (finished)
		return;
	finished = 1;
	if (ok) {
		result = 0;
		lwsl_user("%s: %s\n", __func__, why);
	} else
		lwsl_err("%s: FAIL: %s\n", __func__, why);
	lws_default_loop_exit(context);
}

/* once every request ended, did each end as it should? */
static void
grt_check(void)
{
	struct grt_req *r;
	int n;

	for (n = 0; n < GRT_COUNT; n++)
		if (!reqs[n].status)
			return;

	for (n = 0; n < GRT_COUNT; n++) {
		r = &reqs[n];

		if (r->want_ok && r->status != 200) {
			lwsl_err("%s: %s %s ended %d\n", __func__, r->method,
				 r->path, r->status);
			grt_finish("a GET the server never heard was not answered", 0);
			return;
		}
		if (!r->want_ok && r->status > 0) {
			grt_finish("the POST was answered", 0);
			return;
		}
		/* the server sees each request it answers once, the POST never */
		if (r->srv_hits != (r->want_ok ? 1 : 0)) {
			lwsl_err("%s: the server saw %s %d times\n", __func__,
				 r->path, r->srv_hits);
			grt_finish("the server saw a request the wrong number "
				   "of times", 0);
			return;
		}
	}

	/* A and C2 were answered only after their connection was given up */
	if (lws_now_usecs() - reqs[GRT_A].start < GRT_RETRY_MIN_US) {
		grt_finish("A was answered before its connection closed", 0);
		return;
	}

	/* C2 went on C1's connection first, and was answered on another */
	if (!strcmp(reqs[GRT_C1].srv_conn, reqs[GRT_C2].srv_conn)) {
		grt_finish("C2 was answered on C1's connection", 0);
		return;
	}

	grt_finish("lost GETs answered on a new connection, the lost POST "
		   "failed", 1);
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	int n;

	for (n = 0; n < GRT_COUNT; n++)
		lwsl_err("%s: %s %s: %d\n", __func__, reqs[n].method,
			 reqs[n].path, reqs[n].status);
	grt_finish("timed out", 0);
}

static void
sigint_handler(int sig)
{
	grt_finish("interrupted", 0);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p, *cert, *key;
	int n;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* a server and its clients */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");
	if (!cert || !key || port < 1 || port > 65535) {
		lwsl_err("-p <port>, --cert and --key are required\n");
		return 1;
	}

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: h3 GOAWAY and retry of unanswered GETs\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
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
	/* how long it waits for a connection's first request, and its next */
	info.timeout_secs_ah_idle	= GRT_IDLE_S;
	info.keepalive_timeout		= GRT_IDLE_S;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create the server vhost\n");
		goto bail;
	}

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;
	info.alpn			= NULL;
	info.protocols			= protocols_cli;
	info.timeout_secs_ah_idle	= 0;
	info.keepalive_timeout		= 0;
	for (n = 0; n < (int)LWS_ARRAY_SIZE(vh_cli); n++) {
		/* the vhost keeps the name */
		static const char * const names[] = { "cli-a", "cli-b", "cli-c" };

		info.vhost_name = names[n];
		vh_cli[n] = lws_create_vhost(context, &info);
		if (!vh_cli[n]) {
			lwsl_err("Failed to create the client vhosts\n");
			goto bail;
		}
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 GRT_TIMEOUT_S * LWS_US_PER_SEC);

	if (grt_request(GRT_A) || grt_request(GRT_B) || grt_request(GRT_C1)) {
		lwsl_err("Failed to start the requests\n");
		goto bail;
	}

	while (!finished && lws_service(context, 0) >= 0)
		;

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_c2);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
