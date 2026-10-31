/*
 * lws-api-test-quic-credit
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Fences G-033: QUIC flow control limits are absolute 62-bit offsets, but
 * our tx credit is an int32.  A peer granting more than 2GiB beyond what we
 * have sent, in its transport parameters or a MAX_DATA / MAX_STREAM_DATA,
 * used to wrap our credit negative or to 0, so we stopped sending on that
 * connection.  Credit must instead saturate, and sending carry on.
 *
 * An h3 server and its client are in this process.  The client GETs a
 * response of QCR_BULK bytes of a pattern, and must receive all of it.
 *
 * Run it with one of these fault injections (applying to both ends):
 *
 *  - wsi/quic_tp_window(V..V+1): advertise V as initial_max_data and every
 *    initial_max_stream_data_* in our transport parameters
 *
 *  - wsi/quic_max_data(V..V+1): advertise V in every MAX_DATA and
 *    MAX_STREAM_DATA.  QCR_BULK is more than half the receive window, so the
 *    client must send them while the server is still sending.
 *
 * with V eg 2^31, 2^32 or 2^62 - 1.  Only the advertisement is bigger, not
 * what is enforced, so QCR_BULK stays under the receive window we really
 * give (1MiB).  Without fault injection, it is a plain 768KiB transfer.
 *
 * With --quic-rx-window W, both ends give a receive window of only W, so the
 * transfer can only complete if all that the peer sends, including h3's own
 * framing, is given back to it as it is dealt with.
 *
 * With --manual N, the client asks for manual rx flow control
 * (LCCSCF_H2_MANUAL_RXFLOW) with an initial credit of N, and only gives the
 * server more, QCR_STEP at a time, when it has had all it was given before:
 * the server must never send more than it was given, and the client's
 * estimate of what the server may still send, lws_wsi_tx_credit(wsi,
 * LWSTXCR_PEER_TO_US, 0), must reach 0 exactly when it has.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define QCR_TIMEOUT_S		15
#define QCR_BULK		(768 * 1024)
#define QCR_CHUNK		4096
#define QCR_PAT(_n)		((char)('a' + ((_n) % 26)))
#define QCR_STEP		16384
#define QCR_POLL_US		(20 * LWS_US_PER_MS)

static struct lws_context *context;
static lws_sorted_usec_list_t sul_watchdog, sul_credit;
static struct lws *cli_wsi;
static size_t body_len, granted;
static int completed, timed_out, body_bad, overrun, est_bad, stalls;

/* ------------------------------------------------------------- server */

struct pss_srv {
	size_t			sent;
};

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t buf[LWS_PRE + QCR_CHUNK], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		pss->sent = 0;
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
				"text/plain", (lws_filepos_t)QCR_BULK,
				&p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return -1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		/* h3 asks for WRITEABLE for its own reasons as well */
		if (!pss || pss->sent >= QCR_BULK)
			break;
		for (n = 0; n < QCR_CHUNK; n++)
			start[n] = (uint8_t)QCR_PAT(pss->sent + n);
		pss->sent += QCR_CHUNK;
		if (lws_write(wsi, start, QCR_CHUNK, pss->sent == QCR_BULK ?
				LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP) < 0)
			return -1;
		if (pss->sent < QCR_BULK) {
			lws_callback_on_writable(wsi);
			break;
		}
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
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 1024], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		cli_wsi = wsi;
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ: {
		const char *c = (const char *)in;
		size_t n;

		for (n = 0; n < len; n++, body_len++)
			if (c[n] != QCR_PAT(body_len))
				body_bad = 1;

		if (granted && body_len > granted) {
			lwsl_err("%s: server sent %u, only given %u\n",
				 __func__, (unsigned int)body_len,
				 (unsigned int)granted);
			overrun = 1;
		}
		return 0;
	}

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		completed = 1;
		cli_wsi = NULL;
		lws_default_loop_exit(context);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (const char *)in : "(null)");
		lws_default_loop_exit(context);
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		cli_wsi = NULL;
		lws_default_loop_exit(context);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "qcr", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "qcr", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/*
 * --manual: once the server has used all the credit it was given, check it
 * sent exactly that, and give it some more
 */
static void
credit_cb(lws_sorted_usec_list_t *sul)
{
	int est;

	if (cli_wsi && granted < QCR_BULK) {
		est = lws_wsi_tx_credit(cli_wsi, LWSTXCR_PEER_TO_US, 0);
		if (est < 0 || (size_t)est > granted - body_len) {
			lwsl_err("%s: est %d, but given %u and had %u\n",
				 __func__, est, (unsigned int)granted,
				 (unsigned int)body_len);
			est_bad = 1;
			lws_default_loop_exit(context);
			return;
		}
		if (!est && body_len == granted) {
			stalls++;
			lws_wsi_tx_credit(cli_wsi, LWSTXCR_PEER_TO_US, QCR_STEP);
			granted += QCR_STEP;
		}
	}

	lws_sul_schedule(context, 0, sul, credit_cb, QCR_POLL_US);
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;
	timed_out = 1;
	lws_default_loop_exit(context);
}

static void
sigint_handler(int sig)
{
	(void)sig;
	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	const char *p, *cert, *key;
	struct lws_vhost *vh_cli;
	int result = 1, port = 7710, manual = 0;

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
	if ((p = lws_cmdline_option(argc, argv, "--manual"))) {
		manual = atoi(p);
		if (manual < 1 || manual >= QCR_BULK) {
			lwsl_err("--manual takes an initial credit 1 .. %d\n",
				 QCR_BULK - 1);
			return 1;
		}
	}

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: QUIC flow control credit\n");

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
	info.vhost_name			= "cli";
	info.protocols			= protocols_cli;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create the client vhost\n");
		goto bail;
	}

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= "127.0.0.1";
	i.host			= "localhost";
	i.origin		= "localhost";
	i.port			= port;
	i.path			= "/bulk";
	i.method		= "GET";
	i.protocol		= "qcr";
	i.alpn			= "h3";
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	/* this is about the quic connection, not a fallback to tcp */
	i.disable_h3_fallback	= 1;

	if (manual) {
		i.ssl_connection |= LCCSCF_H2_MANUAL_RXFLOW;
		i.manual_initial_tx_credit = manual;
		granted = (size_t)manual;
		lws_sul_schedule(context, 0, &sul_credit, credit_cb,
				 QCR_POLL_US);
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 QCR_TIMEOUT_S * LWS_US_PER_SEC);

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("The connection could not be started\n");
		goto bail;
	}

	while (lws_service(context, 0) >= 0)
		;

	if (timed_out)
		lwsl_err("FAIL: timed out with %u of %u bytes\n",
			 (unsigned int)body_len, (unsigned int)QCR_BULK);
	else if (!completed || body_bad || body_len != QCR_BULK)
		lwsl_err("FAIL: got %u of %u bytes%s\n",
			 (unsigned int)body_len, (unsigned int)QCR_BULK,
			 body_bad ? ", not what was sent" : "");
	else if (overrun || est_bad)
		lwsl_err("FAIL: manual rx flow control not honoured\n");
	else if (manual &&
		 stalls < (QCR_BULK - manual + QCR_STEP - 1) / QCR_STEP)
		/* each grant must have been used up before the next */
		lwsl_err("FAIL: only %d credit stalls\n", stalls);
	else
		result = 0;

bail:
	lws_sul_cancel(&sul_credit);
	lws_sul_cancel(&sul_watchdog);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
