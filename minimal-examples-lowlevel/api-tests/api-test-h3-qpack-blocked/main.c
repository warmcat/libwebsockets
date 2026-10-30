/*
 * lws-api-test-h3-qpack-blocked
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * QPACK blocked streams (RFC 9204 2.1.2) on h3.  A request whose field
 * section refers to a dynamic table insert the server doesn't have yet must
 * wait for it, not fail, and no more streams may wait at once than the
 * server advertised with SETTINGS_QPACK_BLOCKED_STREAMS.
 *
 * An h3 server and its client are in this process.  The client's requests
 * refer to the one cookie entry the h3_qpack_enc_big_entry faults have its
 * encoder stream insert, and the server answers 200 only if the cookie it
 * decoded is that entry's.
 *
 * Part 1: the insert only goes after the connection's first request did
 * (h3_qpack_enc_big_entry_late), so the request arrives first and blocks.
 * It must be answered 200 once the insert comes.
 *
 * Part 2: the insert never goes (h3_qpack_enc_big_entry_never), and one
 * more request refers to it than the server lets wait, which the client
 * sends anyway (h3_qpack_enc_no_hold).  The server must fail the
 * connection, answering none of them.
 *
 * Part 3: as many requests as may wait refer to the insert that never goes,
 * and the client gives up on them.  Then one more does, with a request that
 * refers to nothing: if the server still counted the ones given up on, the
 * one more is too many and fails the connection, so the plain request must
 * be answered 200.
 *
 * Part 4: a second server lets no stream wait (h3_qpack_blocked_streams_0),
 * and the insert again only goes after the request tried to.  The client may
 * not send a request the server might have to block, so must hold it until
 * the server acknowledges the insert: then it is answered 200.  Sent at once,
 * it arrives before the insert and the server fails the connection.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define HQB_TIMEOUT_S		20
/* lws' SETTINGS_QPACK_BLOCKED_STREAMS, LWS_QPACK_BLOCKED_STREAMS */
#define HQB_BLOCKED		8
/* the value length of the faults' cookie entry, LWS_H3_FI_BIG_ENTRY_LEN */
#define HQB_COOKIE_LEN		4058
/* how long part 3 gives requests to reach the server and block there */
#define HQB_SETTLE_MS		300

enum {
	HQB_REF,	/* the request refers to the cookie entry */
	HQB_PLAIN,	/* the request refers to nothing in the table */
};

struct hqb_req {
	struct lws		*wsi;
	int			status;
	uint8_t			kind;
	uint8_t			done;
};

static struct lws_context *context;
static struct lws_vhost *vh_cli[4];
static lws_sorted_usec_list_t sul_watchdog, sul_next;
static const char *server_addr = "127.0.0.1";
static struct hqb_req reqs[HQB_BLOCKED + 2];
static int port, port_nb, result = 1, part, nreqs, finished;
/* part 3: the requests given up on are all gone */
static uint8_t gave_up;

/* ------------------------------------------------------------- server */

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 256], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	int status = HTTP_STATUS_OK;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		/* a request referring to the entry has the whole cookie */
		if (!strcmp((const char *)in, "/ref") &&
		    lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COOKIE) !=
							HQB_COOKIE_LEN) {
			lwsl_err("%s: cookie length %d\n", __func__,
				 lws_hdr_total_length(wsi,
						      WSI_TOKEN_HTTP_COOKIE));
			status = HTTP_STATUS_BAD_REQUEST;
		}

		if (lws_add_http_common_headers(wsi, (unsigned int)status,
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

/* ------------------------------------------------------------- client */

static void
hqb_finish(const char *why, int ok)
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

static int
hqb_send(uint8_t kind, const char *fault, const char *fault2)
{
	struct lws_client_connect_info i;
	struct hqb_req *r = &reqs[nreqs++];
	lws_fi_t fi;

	memset(r, 0, sizeof(*r));
	r->kind = kind;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	/* a client vhost per part, so each gets a connection of its own */
	i.vhost			= vh_cli[part];
	i.address		= server_addr;
	/* with the Host its address, and pipelining, they share one */
	i.host			= server_addr;
	i.origin		= server_addr;
	/* part 4 is for the server that lets no stream wait */
	i.port			= part == 3 ? port_nb : port;
	i.path			= kind == HQB_REF ? "/ref" : "/plain";
	i.method		= "GET";
	i.alpn			= "h3";
	i.protocol		= "cli";
	i.local_protocol_name	= "cli";
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK |
				  LCCSCF_PIPELINE;
	i.disable_h3_fallback	= 1;
	i.opaque_user_data	= r;

	/* the faults are the connection's, it makes the insert once */
	memset(&fi, 0, sizeof(fi));
	fi.type = LWSFI_ALWAYS;
	if (fault) {
		fi.name = fault;
		if (lws_fi_add(&i.fic, &fi))
			return 1;
	}
	if (fault2) {
		fi.name = fault2;
		if (lws_fi_add(&i.fic, &fi)) {
			lws_fi_destroy(&i.fic);
			return 1;
		}
	}

	r->wsi = lws_client_connect_via_info(&i);
	if (!r->wsi) {
		/* the client wsi takes the faults, unless there was none */
		lws_fi_destroy(&i.fic);
		r->done = 1;

		return 1;
	}

	return 0;
}

static void
hqb_part_cb(lws_sorted_usec_list_t *sul)
{
	int n;

	if (finished)
		return;

	switch (part) {
	case 0:
		lwsl_user("%s: 1: a request arrives before its insert\n",
			  __func__);
		if (hqb_send(HQB_REF, "h3_qpack_enc_big_entry_late", NULL))
			hqb_finish("request not sent", 0);
		return;

	case 1:
		lwsl_user("%s: 2: %d requests wait for an insert that never "
			  "comes\n", __func__, HQB_BLOCKED + 1);
		for (n = 0; n <= HQB_BLOCKED; n++)
			if (hqb_send(HQB_REF, "h3_qpack_enc_big_entry_never",
				     "h3_qpack_enc_no_hold")) {
				hqb_finish("request not sent", 0);
				return;
			}
		return;

	case 2:
		if (!gave_up) {
			lwsl_user("%s: 3: %d requests wait and are given up "
				  "on\n", __func__, HQB_BLOCKED);
			for (n = 0; n < HQB_BLOCKED; n++)
				if (hqb_send(HQB_REF,
					     "h3_qpack_enc_big_entry_never",
					     NULL)) {
					hqb_finish("request not sent", 0);
					return;
				}
			/* once they are blocked at the server, give up */
			lws_sul_schedule(context, 0, &sul_next, hqb_part_cb,
					 HQB_SETTLE_MS * LWS_US_PER_MS);
			gave_up = 1;
			return;
		}

		if (reqs[0].wsi && !reqs[0].done) {
			/* it is time to give up on them */
			for (n = 0; n < HQB_BLOCKED; n++)
				if (!reqs[n].done)
					lws_set_timeout(reqs[n].wsi,
						PENDING_TIMEOUT_HTTP_CONTENT,
						LWS_TO_KILL_ASYNC);
			return;
		}

		lwsl_user("%s: 3: one more waits, with one that doesn't\n",
			  __func__);
		if (hqb_send(HQB_REF, NULL, NULL) ||
		    hqb_send(HQB_PLAIN, NULL, NULL))
			hqb_finish("request not sent", 0);
		return;

	case 3:
		lwsl_user("%s: 4: a request that might block waits for its "
			  "insert to be acknowledged\n", __func__);
		if (hqb_send(HQB_REF, "h3_qpack_enc_big_entry_late", NULL))
			hqb_finish("request not sent", 0);
		return;
	}
}

static void
hqb_next_part(void)
{
	part++;
	nreqs = 0;
	gave_up = 0;
	lws_sul_schedule(context, 0, &sul_next, hqb_part_cb, 1);
}

/* a request is over: when they all are, see how the part went */
static void
hqb_req_done(struct hqb_req *r, int status)
{
	int n, answered = 0;

	if (!r || r->done || finished)
		return;
	r->done = 1;
	r->status = status;
	lwsl_user("%s: part %d, req %d: %d\n", __func__, part + 1,
		  (int)(r - reqs), status);

	/* part 3: the plain request is answered with one more waiting */
	if (part == 2 && nreqs == HQB_BLOCKED + 2 && r == &reqs[nreqs - 1]) {
		if (status != HTTP_STATUS_OK) {
			hqb_finish("3: the requests given up on still "
				   "counted", 0);
			return;
		}
		hqb_next_part();
		return;
	}

	for (n = 0; n < nreqs; n++) {
		if (!reqs[n].done)
			return;
		if (reqs[n].status == HTTP_STATUS_OK)
			answered++;
	}

	switch (part) {
	case 0:
		if (answered != 1) {
			hqb_finish("1: the request was not answered 200", 0);
			return;
		}
		hqb_next_part();
		return;

	case 1:
		if (answered) {
			hqb_finish("2: requests were answered with one too "
				   "many waiting", 0);
			return;
		}
		hqb_next_part();
		return;

	case 2:
		/* the ones given up on are gone: now one more waits */
		if (nreqs == HQB_BLOCKED)
			lws_sul_schedule(context, 0, &sul_next, hqb_part_cb,
					 HQB_SETTLE_MS * LWS_US_PER_MS);
		return;

	case 3:
		if (answered != 1) {
			hqb_finish("4: the request was sent while it might "
				   "block, to a server letting none", 0);
			return;
		}
		hqb_finish("1: the request waited for its insert, 2: one "
			   "too many waiting failed the connection, 3: the "
			   "ones given up on stopped counting, 4: the client "
			   "held a request that might block", 1);
		return;
	}
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct hqb_req *r = (struct hqb_req *)lws_get_opaque_user_data(wsi);
	char buf[LWS_PRE + 1024], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE, m;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		if (!r || r->kind != HQB_REF)
			break;
		/*
		 * The section's prefix says it needs the one entry the fault
		 * inserts, with a base of 0: the reference is a one-byte
		 * post-base index 0 to it
		 */
		{
			unsigned char **p = (unsigned char **)in,
				      *end = (*p) + len;

			lws_qpack_set_wsi_base_and_ric(wsi, 0, 1);
			m = lws_qpack_tx_encode_dynamic_index(*p,
					lws_ptr_diff_size_t(end, *p), 0, 0);
			if (m < 0)
				return -1;
			*p += m;
		}
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		hqb_req_done(r, (int)lws_http_client_http_response(wsi));
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		hqb_req_done(r, 0);
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
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: part %d, %d requests\n", __func__, part + 1, nreqs);
	hqb_finish("timed out", 0);
}

static void
sigint_handler(int sig)
{
	hqb_finish("interrupted", 0);
}

/*
 * The quic listener, on udp.  "localhost" is both 127.0.0.1 and ::1, and a
 * client may try either first: on FreeBSD, ::1.  A udp socket bound to the
 * name gets only its first address, so a client trying the other relies on
 * an ICMP port unreachable to move on, which can be lost, or not sent when
 * the kernel rate limits them under parallel tests.  So for "localhost",
 * listen on both.
 */
static int
quic_listen(struct lws_vhost *vh, int port, const char *protocol)
{
	static const char * const lo[] = {
#if defined(LWS_WITH_IPV4)
		"127.0.0.1",
#endif
#if defined(LWS_WITH_IPV6)
		"::1",
#endif
	};
	size_t n;

	if (!vh)
		return 1;

	if (strcmp(server_addr, "localhost"))
		return !lws_create_adopt_udp(vh, server_addr, port,
					     LWS_CAUDP_BIND, protocol, NULL,
					     NULL, NULL, NULL, "quic_listen");

	for (n = 0; n < LWS_ARRAY_SIZE(lo); n++)
		if (!lws_create_adopt_udp(vh, lo[n], port, LWS_CAUDP_BIND,
					  protocol, NULL, NULL, NULL, NULL,
					  "quic_listen"))
			return 1;

	return 0;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p, *cert, *key;
	struct lws_vhost *vh;
	char name[8];
	lws_fi_t fi;
	size_t n;
	int m = 0;

	signal(SIGINT, sigint_handler);
	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: h3 qpack blocked streams\n");

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--nb-port")))
		port_nb = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;
	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");
	if (!cert || !key || port < 1 || port > 65535 ||
	    port_nb < 1 || port_nb > 65535) {
		lwsl_err("-p <port>, --nb-port <port>, --cert and --key are "
			 "required\n");
		return 1;
	}

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the h3 server, a quic listener on udp only */
	info.port			= CONTEXT_PORT_NO_LISTEN_SERVER;
	info.vhost_name			= "localhost";
	info.protocols			= protocols_srv;
	info.listen_accept_role		= "quic";
	info.listen_accept_protocol	= "http";
	info.alpn			= "h3";
	info.ssl_cert_filepath		= cert;
	info.ssl_private_key_filepath	= key;
	if (quic_listen(lws_create_vhost(context, &info), port, "http"))
		goto bail;

	/* the server for part 4, letting no stream wait for inserts */
	memset(&fi, 0, sizeof(fi));
	fi.name = "h3_qpack_blocked_streams_0";
	fi.type = LWSFI_ALWAYS;
	if (lws_fi_add(&info.fic, &fi))
		goto bail;
	info.vhost_name = "localhost-nb";
	vh = lws_create_vhost(context, &info); /* it takes the fault */
	if (!vh || quic_listen(vh, port_nb, "http"))
		goto bail;

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.protocols			= protocols_cli;
	info.listen_accept_role		= NULL;
	info.listen_accept_protocol	= NULL;
	info.alpn			= NULL;
	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;
	for (n = 0; n < LWS_ARRAY_SIZE(vh_cli); n++) {
		lws_snprintf(name, sizeof(name), "cli%u", (unsigned int)n);
		info.vhost_name = name;
		vh_cli[n] = lws_create_vhost(context, &info);
		if (!vh_cli[n])
			goto bail;
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 HQB_TIMEOUT_S * LWS_US_PER_SEC);
	lws_sul_schedule(context, 0, &sul_next, hqb_part_cb, 1);

	while (m >= 0 && !finished)
		m = lws_service(context, 0);

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_next);
	lws_context_destroy(context);
	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
