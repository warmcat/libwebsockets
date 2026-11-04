/*
 * lws-api-test-h3-client-no-ah
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An h3 client stream keeps the headers of its response in an ah, taken
 * when they arrive.  When there is none to be had, because the heap can't
 * make one or the pool is in use, only that stream fails: it is cancelled
 * with H3_REQUEST_CANCELLED and its client sees it closed with no response.
 * It used to close the whole connection with QPACK_DECOMPRESSION_FAILED, and
 * every other stream on it with it.
 *
 * An h3 server and its client are in this process, the client's requests
 * all on one connection.  The h3_rx_no_ah fault finds no ah for a
 * response's headers.
 *
 *  A: a GET is answered, bringing up the connection.
 *
 *  S, B: a GET whose answer the server holds back CNA_SLOW_MS goes, and
 *     with it a GET whose response finds no ah.  B fails, and S is answered
 *     after it, on the same connection.
 *
 *  C: once both ended, a GET is answered on the same connection again.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define CNA_TIMEOUT_S		20
#define CNA_SLOW_MS		500

enum {
	CNA_A,
	CNA_S,
	CNA_B,
	CNA_C,

	CNA_COUNT
};

struct cna_req {
	const char		*path;
	lws_usec_t		done;
	int			status; /* 0 until it ends, -1 if it failed */
	int			srv_hits;
	char			srv_conn[64];
	const char		*fault;
	char			want_ok;
};

static struct cna_req reqs[CNA_COUNT] = {
	[CNA_A] = { .path = "/a", .want_ok = 1 },
	[CNA_S] = { .path = "/s", .want_ok = 1 },
	[CNA_B] = { .path = "/b", .fault = "h3_rx_no_ah" },
	[CNA_C] = { .path = "/c", .want_ok = 1 },
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_watchdog, sul_next;
static const char *server_addr = "127.0.0.1";
static int port, result = 1, finished, stage;

static void cna_check(void);

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
		for (n = 0; n < CNA_COUNT; n++)
			if (!strcmp((const char *)in, reqs[n].path)) {
				reqs[n].srv_hits++;
				lws_strncpy(reqs[n].srv_conn,
					    lws_wsi_tag(lws_get_network_wsi(wsi)),
					    sizeof(reqs[n].srv_conn));
			}

		/* S's answer comes later, after B ended */
		if (!strcmp((const char *)in, reqs[CNA_S].path)) {
			lws_set_timer_usecs(wsi, CNA_SLOW_MS * LWS_US_PER_MS);
			return 0;
		}
		pss->respond = 1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_TIMER:
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
cna_request(int idx)
{
	struct cna_req *r = &reqs[idx];
	struct lws_client_connect_info i;
	lws_fi_t fi;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.port			= port;
	i.path			= r->path;
	i.method		= "GET";
	i.alpn			= "h3";
	i.protocol		= "cli";
	i.local_protocol_name	= "cli";
	/* each request joins the connection A brought up */
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK |
				  LCCSCF_PIPELINE;
	i.disable_h3_fallback	= 1;
	i.opaque_user_data	= r;

	if (r->fault) {
		memset(&fi, 0, sizeof(fi));
		fi.name = r->fault;
		fi.type = LWSFI_ALWAYS;
		if (lws_fi_add(&i.fic, &fi))
			return 1;
	}

	if (!lws_client_connect_via_info(&i)) {
		/* the client wsi takes the fault, unless there was none */
		lws_fi_destroy(&i.fic);
		r->status = -1;
		return 1;
	}

	return 0;
}

/* from the event loop, not the callback of a request closing */

static void
next_cb(lws_sorted_usec_list_t *sul)
{
	if (!stage++) {
		if (cna_request(CNA_S) || cna_request(CNA_B))
			cna_check();
		return;
	}

	if (cna_request(CNA_C))
		cna_check();
}

static void
cna_req_done(struct cna_req *r, int status)
{
	if (!r || r->status)
		return;
	r->status = status;
	r->done = lws_now_usecs();

	lwsl_user("%s: GET %s: %d\n", __func__, r->path, status);

	/* A brought up the connection: S and B go on it */
	if (r == &reqs[CNA_A] && status > 0) {
		lws_sul_schedule(context, 0, &sul_next, next_cb, 1);
		return;
	}

	/* S and B both ended: C goes on the same connection */
	if (stage == 1 && reqs[CNA_S].status > 0 && reqs[CNA_B].status) {
		lws_sul_schedule(context, 0, &sul_next, next_cb, 1);
		return;
	}

	cna_check();
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct cna_req *r = (struct cna_req *)lws_get_opaque_user_data(wsi);
	char buf[LWS_PRE + 1024], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		cna_req_done(r, (int)lws_http_client_http_response(wsi));
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: CONNECTION_ERROR: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		cna_req_done(r, -1);
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		cna_req_done(r, -1);
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
cna_finish(const char *why, int ok)
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
cna_check(void)
{
	struct cna_req *r;
	int n;

	/* what went must have ended; what didn't go counts as failed */
	for (n = 0; n < CNA_COUNT; n++)
		if (!reqs[n].status && stage >= (n == CNA_A ? 0 :
						 (n == CNA_C ? 2 : 1)))
			return;

	for (n = 0; n < CNA_COUNT; n++) {
		r = &reqs[n];

		if (r->want_ok && r->status != 200) {
			lwsl_err("%s: GET %s ended %d\n", __func__, r->path,
				 r->status);
			cna_finish("a GET on the connection was not answered", 0);
			return;
		}
		if (!r->want_ok && r->status > 0) {
			cna_finish("the GET finding no ah was answered", 0);
			return;
		}
		/* the server saw each one, once, on the one connection */
		if (r->srv_hits != 1 ||
		    strcmp(r->srv_conn, reqs[CNA_A].srv_conn)) {
			lwsl_err("%s: the server saw %s %d times, on %s\n",
				 __func__, r->path, r->srv_hits, r->srv_conn);
			cna_finish("a GET was not on A's connection, once", 0);
			return;
		}
	}

	/* S's answer was held back until after B ended */
	if (reqs[CNA_S].done < reqs[CNA_B].done) {
		cna_finish("S was answered before B failed", 0);
		return;
	}

	cna_finish("a response finding no ah failed alone, its connection "
		   "and the other streams on it went on", 1);
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	int n;

	for (n = 0; n < CNA_COUNT; n++)
		lwsl_err("%s: GET %s: %d\n", __func__, reqs[n].path,
			 reqs[n].status);
	cna_finish("timed out", 0);
}

static void
sigint_handler(int sig)
{
	cna_finish("interrupted", 0);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p, *cert, *key;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* a server and its client */
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
	lwsl_user("LWS API selftest: h3 client response finding no ah\n");

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
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create the server vhost\n");
		goto bail;
	}

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;
	info.alpn			= NULL;
	info.protocols			= protocols_cli;
	info.vhost_name			= "cli";
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create the client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 CNA_TIMEOUT_S * LWS_US_PER_SEC);

	if (cna_request(CNA_A)) {
		lwsl_err("Failed to start the requests\n");
		goto bail;
	}

	while (!finished && lws_service(context, 0) >= 0)
		;

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_next);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
