/*
 * lws-api-test-quic-ack-work
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Fences G-648: what a QUIC peer's ACKs cost us must be bounded by what they
 * say, not by what they say times what we have in flight.  Each ACK range
 * used to cost a walk of the whole in-flight list, and nothing limited the
 * ACK frames in a packet, so a peer sending ACKs of many small ranges, many
 * times in each packet, had us look at every frame in flight hundreds of
 * times per datagram.
 *
 * An h3 server and its client are in this process.  The client GETs a
 * response of QAW_BULK bytes of a pattern, and must receive all of it.  Both
 * ends run with the faults
 *
 *  - wsi/quic_ack_ranges: every ACK in the application PN space carries,
 *    past its true first range, up to 96 more ranges of one long settled PN
 *    each, and goes three times in its packet.  Every other one reports PNs
 *    only up to 16 below the largest received, so the sender still has what
 *    it sent since in flight when it takes the ranges
 *
 *  - wsi/quic_ack_late: an ACK in the application PN space goes for every 32
 *    ack-eliciting packets, or at max_ack_delay, not every second one, so
 *    the sender has more in flight when it comes
 *
 *  - wsi/quic_stats: when a connection goes, it logs how many ACK frames it
 *    acted on and ignored, their ranges, the frames they acked, how many
 *    in-flight frames ACK processing and loss detection looked at, and the
 *    most frames it had in flight
 *
 * For each connection, only one ACK frame per packet may be acted on, so
 * some must have been ignored, and each ACK frame acted on may look at no
 * more in-flight frames than one per range, plus two per frame in flight
 * when it came (once by the ranges, once by loss detection), plus a few
 * where the walks stop.  Before, each range looked at everything still in
 * flight, so an ACK frame that came with frames in flight beyond its Largest
 * Acknowledged cost its 97 ranges times those.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define QAW_TIMEOUT_S		30
#define QAW_BULK		(768 * 1024)
#define QAW_CHUNK		(64 * 1024)
#define QAW_PAT(_n)		((char)('a' + ((_n) % 26)))
/* the stopping places of the walks, see the top */
#define QAW_EXCESS_MAX		4

struct qaw_stats {
	uint64_t		ack_frames;
	uint64_t		ack_ignored;
	uint64_t		ranges;
	uint64_t		acked;
	uint64_t		visits;
	uint64_t		in_flight_peak;
	uint64_t		excess_max;
};

static struct lws_context *context;
static lws_sorted_usec_list_t sul_watchdog;
static struct qaw_stats st_srv, st_cli;
static size_t body_len;
static int completed, timed_out, body_bad, seen_srv, seen_cli, stats_bad;

/* ------------------------------------------------------- the stats lines */

/*
 * The number after "<key> " in line, eg "ranges 1234"; *bad is set if the key
 * is missing or no number follows it
 */
static uint64_t
stat_get(const char *line, const char *key, int *bad)
{
	const char *p = strstr(line, key);
	char *e;
	uint64_t u;

	if (!p) {
		*bad = 1;
		return 0;
	}

	p += strlen(key);
	u = strtoull(p, &e, 10);
	if (e == p)
		*bad = 1;

	return u;
}

static void
emit_cb(int level, const char *line)
{
	struct qaw_stats *st;
	const char *p;
	int bad = 0;

	lwsl_emit_stderr(level, line);

	if (!(level & LLL_NOTICE) || !(p = strstr(line, "QUIC FI stats: ")))
		return;

	if (strstr(p, "server,")) {
		st = &st_srv;
		seen_srv++;
	} else {
		st = &st_cli;
		seen_cli++;
	}

	st->ack_frames		= stat_get(p, "ack frames ", &bad);
	st->ack_ignored		= stat_get(p, "ignored ", &bad);
	st->ranges		= stat_get(p, "ranges ", &bad);
	st->acked		= stat_get(p, "acked ", &bad);
	st->visits		= stat_get(p, "visits ", &bad);
	st->in_flight_peak	= stat_get(p, "in flight peak ", &bad);
	st->excess_max		= stat_get(p, "excess max ", &bad);

	if (bad)
		stats_bad = 1;
}

/* is what this end's ACK processing cost within the bound, see the top */
static int
stats_check(const char *what, const struct qaw_stats *st, int bulk)
{
	lwsl_user("%s: ACK frames %llu (ignored %llu), ranges %llu, acked "
		  "%llu, in flight peak %llu: looked at %llu frames, at most "
		  "%llu more in one ACK frame than its bound\n", what,
		  (unsigned long long)st->ack_frames,
		  (unsigned long long)st->ack_ignored,
		  (unsigned long long)st->ranges,
		  (unsigned long long)st->acked,
		  (unsigned long long)st->in_flight_peak,
		  (unsigned long long)st->visits,
		  (unsigned long long)st->excess_max);

	/*
	 * Only the server, which sent the bulk, sent enough packets for its
	 * peer's ACKs to have the extra ranges
	 */
	if (bulk && (!st->ack_frames || st->ranges <= st->ack_frames)) {
		lwsl_err("FAIL: %s: the ACKs had no extra ranges\n", what);
		return 1;
	}

	if (bulk && !st->ack_ignored) {
		lwsl_err("FAIL: %s: every ACK frame was acted on\n", what);
		return 1;
	}

	if (st->excess_max > QAW_EXCESS_MAX) {
		lwsl_err("FAIL: %s: an ACK frame looked at %llu in-flight "
			 "frames more than its bound\n", what,
			 (unsigned long long)st->excess_max);
		return 1;
	}

	return 0;
}

/* ------------------------------------------------------------- server */

struct pss_srv {
	size_t			sent;
};

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	static uint8_t buf[LWS_PRE + QAW_CHUNK];
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t *start = &buf[LWS_PRE], *p = start, *end = &buf[sizeof(buf) - 1];
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		pss->sent = 0;
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
				"text/plain", (lws_filepos_t)QAW_BULK,
				&p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return -1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		/* h3 asks for WRITEABLE for its own reasons as well */
		if (!pss || pss->sent >= QAW_BULK)
			break;
		for (n = 0; n < QAW_CHUNK; n++)
			start[n] = (uint8_t)QAW_PAT(pss->sent + n);
		pss->sent += QAW_CHUNK;
		if (lws_write(wsi, start, QAW_CHUNK, pss->sent == QAW_BULK ?
				LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP) < 0)
			return -1;
		if (pss->sent < QAW_BULK) {
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

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ: {
		const char *c = (const char *)in;
		size_t n;

		for (n = 0; n < len; n++, body_len++)
			if (c[n] != QAW_PAT(body_len))
				body_bad = 1;
		return 0;
	}

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		completed = 1;
		lws_default_loop_exit(context);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (const char *)in : "(null)");
		lws_default_loop_exit(context);
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		lws_default_loop_exit(context);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "qaw", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "qaw", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

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

/* the faults this test runs with, on every wsi of both ends */
static const char * const faults[] = {
	"wsi/quic_ack_ranges",
	"wsi/quic_ack_late",
	"wsi/quic_stats",
};

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	const char *p, *cert, *key;
	struct lws_vhost *vh_cli;
	int result = 1, port = 7711;
	size_t n;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, emit_cb);

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

	lwsl_user("LWS API selftest: QUIC ACK processing work\n");

	for (n = 0; n < LWS_ARRAY_SIZE(faults); n++) {
		lws_fi_t fi;

		memset(&fi, 0, sizeof(fi));
		fi.name = faults[n];
		fi.type = LWSFI_ALWAYS;
		if (lws_fi_add(&info.fic, &fi)) {
			lwsl_err("OOM adding faults\n");
			return 1;
		}
	}

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
	i.protocol		= "qaw";
	i.alpn			= "h3";
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	/* this is about the quic connection, not a fallback to tcp */
	i.disable_h3_fallback	= 1;

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 QAW_TIMEOUT_S * LWS_US_PER_SEC);

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("The connection could not be started\n");
		goto bail;
	}

	while (lws_service(context, 0) >= 0)
		;

	if (timed_out)
		lwsl_err("FAIL: timed out with %u of %u bytes\n",
			 (unsigned int)body_len, (unsigned int)QAW_BULK);
	else if (!completed || body_bad || body_len != QAW_BULK)
		lwsl_err("FAIL: got %u of %u bytes%s\n",
			 (unsigned int)body_len, (unsigned int)QAW_BULK,
			 body_bad ? ", not what was sent" : "");
	else
		result = 0;

bail:
	lws_sul_cancel(&sul_watchdog);
	/* the connections go, and log their stats, with the context */
	lws_context_destroy(context);

	if (!result) {
		if (seen_srv != 1 || seen_cli != 1 || stats_bad) {
			lwsl_err("FAIL: stats lines: server %d, client %d%s\n",
				 seen_srv, seen_cli,
				 stats_bad ? ", unreadable" : "");
			result = 1;
		} else
			result = stats_check("server", &st_srv, 1) |
				 stats_check("client", &st_cli, 0);
	}

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
