/*
 * lws-api-test-h3-stream-reset
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * "Rapid reset" (CVE-2023-44487 class) on h3.  QUIC's stream limit counts
 * the streams the peer opened, and gives it more only with a MAX_STREAMS
 * (RFC 9000 4.6), but the server raised its limit the moment a peer stream
 * ended and held the peer to that, not to what it had told it.  So a peer
 * resetting each request once it had been dispatched had new ones
 * dispatched for as long as it liked, with nothing counting the resets.
 *
 * An h3 server and its client are in this process.  The server's vhost
 * allows HSR_LIMIT streams ended before they were answered per connection
 * per 10s.
 *
 * Part 1: client A sends HSR_ATTACK GETs on one connection, HSR_BATCH at a
 * time.  The server starts each answer and never finishes it; A gives up on
 * each stream as soon as the answer's headers arrive, which sends the server
 * STOP_SENDING, and sends the next batch once the whole batch went.  The
 * server must close each connection A uses with H3_EXCESSIVE_LOAD, after not
 * many more than HSR_LIMIT requests dispatched on it.
 *
 * Part 2: client B, which gives up on nothing, has HSR_GOOD GETs answered,
 * HSR_BATCH at a time, on one connection.  That is more streams than the
 * server's initial limit (400), so B must have been given more by
 * MAX_STREAMS as its streams completed.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define HSR_TIMEOUT_S		30
#define HSR_LIMIT		20
#define HSR_BATCH		8
#define HSR_ATTACK		(8 * HSR_BATCH)
#define HSR_GOOD		(56 * HSR_BATCH)

static struct lws_context *context;
static struct lws_vhost *vh_cli[2];
static lws_sorted_usec_list_t sul_watchdog, sul_next;
static const char *server_addr = "127.0.0.1";
static int port, result = 1, part, sent, finished, answered, failed_reqs;

/* ------------------------------------------------------------- server */

/* the server connection the last request came on, and its count */
static char srv_conn[64];
static int srv_conn_reqs, srv_conn_max, srv_conns;

struct pss_srv {
	char			slow;
	char			respond;
};

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t buf[LWS_PRE + 256], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	const char *tag;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		/* which connection is it on? */
		tag = lws_wsi_tag(lws_get_network_wsi(wsi));
		if (strcmp(tag, srv_conn)) {
			lws_strncpy(srv_conn, tag, sizeof(srv_conn));
			srv_conn_reqs = 0;
			srv_conns++;
		}
		if (++srv_conn_reqs > srv_conn_max)
			srv_conn_max = srv_conn_reqs;

		pss->slow = !strcmp((const char *)in, "/slow");
		pss->respond = 1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		/* h3 asks for WRITEABLE for its own reasons as well */
		if (!pss || !pss->respond)
			break;
		pss->respond = 0;

		if (pss->slow) {
			/* the work goes on: its answer is started, not ended */
			if (lws_add_http_header_status(wsi, HTTP_STATUS_OK,
						       &p, end) ||
			    lws_finalize_write_http_header(wsi, start, &p, end))
				return -1;
			return 0;
		}

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

struct hsr_req {
	char			done;
};

static struct hsr_req reqs[HSR_GOOD];

static void
hsr_finish(const char *why, int ok)
{
	if (finished)
		return;
	finished = 1;
	if (ok) {
		result = 0;
		lwsl_user("%s: %s\n", __func__, why);
	} else
		lwsl_err("%s: FAIL: %s\n", __func__, why);
	lws_sul_cancel(&sul_next);
	lws_default_loop_exit(context);
}

static void
hsr_part_check(void)
{
	if (!part) {
		lwsl_user("%s: A: %d requests, the server dispatched at most "
			  "%d on one connection, on %d connections\n",
			  __func__, sent, srv_conn_max, srv_conns);
		/* not many more than the limit, then the connection ended */
		if (srv_conn_max > HSR_LIMIT + 2 * HSR_BATCH) {
			hsr_finish("A's resets never stopped it", 0);
			return;
		}
		if (srv_conns < 2) {
			hsr_finish("A's connection was never closed", 0);
			return;
		}
		/* B's turn */
		part = 1;
		sent = answered = 0;
		srv_conn[0] = '\0';
		srv_conns = srv_conn_max = 0;
		memset(reqs, 0, sizeof(reqs));
		return;
	}

	if (failed_reqs || answered != HSR_GOOD) {
		lwsl_err("%s: B: %d of %d answered, %d failed\n", __func__,
			 answered, HSR_GOOD, failed_reqs);
		hsr_finish("B was not served", 0);
		return;
	}
	if (srv_conns != 1) {
		lwsl_err("%s: B used %d connections\n", __func__, srv_conns);
		hsr_finish("B's requests did not all go on one connection", 0);
		return;
	}

	hsr_finish("A closed with H3_EXCESSIVE_LOAD, B served past the initial "
		   "stream limit", 1);
}

static void
hsr_batch_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	int n, total = part ? HSR_GOOD : HSR_ATTACK;

	if (finished)
		return;

	if (sent == total) {
		hsr_part_check();
		if (finished)
			return;
	}

	for (n = 0; n < HSR_BATCH; n++) {
		memset(&i, 0, sizeof(i));
		i.context		= context;
		/* a client vhost per part, so B gets a connection of its own */
		i.vhost			= vh_cli[part];
		i.address		= server_addr;
		/* with the Host its address, and pipelining, they share one */
		i.host			= server_addr;
		i.origin		= server_addr;
		i.port			= port;
		i.path			= part ? "/ok" : "/slow";
		i.method		= "GET";
		i.alpn			= "h3";
		i.protocol		= "cli";
		i.local_protocol_name	= "cli";
		i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
					  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK |
					  LCCSCF_PIPELINE;
		i.disable_h3_fallback	= 1;
		i.opaque_user_data	= &reqs[sent];

		sent++;
		if (!lws_client_connect_via_info(&i)) {
			reqs[sent - 1].done = 1;
			failed_reqs++;
		}
	}
}

/* a request is over: when the whole batch is, the next one goes */
static void
hsr_req_done(struct hsr_req *r, int ok)
{
	int n, first;

	if (!r || r->done)
		return;
	r->done = 1;
	if (ok)
		answered++;
	else if (part)
		failed_reqs++;

	first = (int)(r - reqs) / HSR_BATCH * HSR_BATCH;
	for (n = first; n < first + HSR_BATCH; n++)
		if (!reqs[n].done)
			return;

	/* from the event loop, not the callback of a request closing */
	lws_sul_schedule(context, 0, &sul_next, hsr_batch_cb, 1);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct hsr_req *r = (struct hsr_req *)lws_get_opaque_user_data(wsi);
	char buf[LWS_PRE + 1024], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		/*
		 * Joining a live connection also says ESTABLISHED, before
		 * there is any answer
		 */
		if (part || !lws_http_client_http_response(wsi))
			break;
		/* A: the answer started, give up on the stream */
		hsr_req_done(r, 1);
		return -1;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		hsr_req_done(r, lws_http_client_http_response(wsi) == 200);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		hsr_req_done(r, 0);
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
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: part %d: %d sent, %d answered\n", __func__, part, sent,
		 answered);
	hsr_finish("timed out", 0);
}

static void
sigint_handler(int sig)
{
	hsr_finish("interrupted", 0);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p, *cert, *key;

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
	lwsl_user("LWS API selftest: h3 streams reset per connection\n");

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
	info.mux_reset_limit		= HSR_LIMIT;
	info.mux_reset_window_secs	= 10;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create the server vhost\n");
		goto bail;
	}

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;
	info.alpn			= NULL;
	info.protocols			= protocols_cli;
	info.vhost_name			= "cli-a";
	vh_cli[0] = lws_create_vhost(context, &info);
	info.vhost_name			= "cli-b";
	vh_cli[1] = lws_create_vhost(context, &info);
	if (!vh_cli[0] || !vh_cli[1]) {
		lwsl_err("Failed to create the client vhosts\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 HSR_TIMEOUT_S * LWS_US_PER_SEC);
	lws_sul_schedule(context, 0, &sul_next, hsr_batch_cb, 1);

	while (!finished && lws_service(context, 0) >= 0)
		;

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_next);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
