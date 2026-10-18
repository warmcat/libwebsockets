/*
 * lws-api-test-quic-forged
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Fences G-104: a QUIC packet that fails authentication was not sent by the
 * peer, and must not change anything about the connection (RFC 9001 5.5,
 * 6.6).  The server used to close the connection with NO_VIABLE_PATH after
 * 256 such packets in a row, and stop following the peer's key updates after
 * 8 of them with the key phase bit flipped, so anybody who could see the
 * connection's DCID could kill it with a burst of datagrams.
 *
 * Both ends are in this process, with a udp relay between them that stands
 * for whoever is on the path: the client dials the relay, which passes its
 * datagrams on to the server from a socket of its own, and the server's back.
 * The relay learns the server's connection ID from the handshake and the
 * client's DCID from its short header packets.
 *
 * The client asks for a slow response, which comes in two halves 1.5s apart.
 * When the first half reaches the client, the relay sends the server, from
 * where the client's datagrams come from, QFG_FORGED short header datagrams
 * with the connection's DCID and random contents: about half of them have the
 * key phase bit flipped once header protection is taken off.  The second half
 * must still arrive on the same connection, and the request complete.
 *
 * Both ends update their keys every few packets (the interop option
 * LWS_SERVER_OPTION_QUIC_EARLY_KEY_UPDATE), and the second half is large
 * enough that both have to do it again after the burst: the forged key phase
 * bits must not have stopped the server following the client's updates.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define QFG_TIMEOUT_S		15
#define QFG_FORGED		1000	/* well past the old limit of 256 */
#define QFG_PER_TICK		100
#define QFG_TICK_US		(5 * LWS_US_PER_MS)

/*
 * The slow response, in two halves the burst goes between: a short first
 * one, then QFG_BULK bytes of a pattern, sent QFG_CHUNK at a time
 */
#define QFG_SLOW_1		"first half|"
#define QFG_BULK		(48 * 1024)
#define QFG_CHUNK		1024
#define QFG_PAT(_n)		((char)('a' + ((_n) % 26)))

static struct lws_context *context;
static lws_sorted_usec_list_t sul_watchdog, sul_burst;
static size_t body_len;
static int port_srv, port_relay, completed, timed_out, forged_sent,
	   burst_before_second, body_bad, key_updates, key_updates_at_burst;

/* key updates either end completed, as they log them */

static void
emit_cb(int level, const char *line)
{
	if ((level & LLL_NOTICE) && strstr(line, "Key Update completed"))
		key_updates++;

	lwsl_emit_stderr(level, line);
}

/* ------------------------------------------------------------- server */

struct pss_srv {
	lws_sorted_usec_list_t	sul;
	struct lws		*wsi;
	size_t			sent;	/* of the second half */
	int			half;	/* the next half to send, 1 or 2 */
	int			due;	/* the second half's time has come */
};

static void
second_half_cb(lws_sorted_usec_list_t *sul)
{
	struct pss_srv *pss = lws_container_of(sul, struct pss_srv, sul);

	pss->due = 1;
	lws_callback_on_writable(pss->wsi);
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t buf[LWS_PRE + QFG_CHUNK], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		pss->wsi = wsi;
		pss->half = 1;
		pss->due = 0;
		pss->sent = 0;
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
				"text/plain", (lws_filepos_t)
				(strlen(QFG_SLOW_1) + QFG_BULK),
				&p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return -1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss || !pss->wsi)
			break;
		if (pss->half == 1) {
			memcpy(start, QFG_SLOW_1, strlen(QFG_SLOW_1));
			if (lws_write(wsi, start, strlen(QFG_SLOW_1),
				      LWS_WRITE_HTTP) < 0)
				return -1;
			pss->half = 2;
			lws_sul_schedule(lws_get_context(wsi), 0, &pss->sul,
					 second_half_cb, 1500 * LWS_US_PER_MS);
			break;
		}
		/* h3 asks for WRITEABLE for its own reasons as well */
		if (pss->half != 2 || !pss->due)
			break;

		for (n = 0; n < QFG_CHUNK; n++)
			start[n] = (uint8_t)QFG_PAT(pss->sent + n);
		pss->sent += QFG_CHUNK;
		if (lws_write(wsi, start, QFG_CHUNK, pss->sent == QFG_BULK ?
				LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP) < 0)
			return -1;
		if (pss->sent < QFG_BULK) {
			lws_callback_on_writable(wsi);
			break;
		}
		pss->half = 0;
		if (lws_http_transaction_completed(wsi))
			return -1;
		break;

	case LWS_CALLBACK_CLOSED_HTTP:
		if (pss)
			lws_sul_cancel(&pss->sul);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* -------------------------------------------------------------- relay */

/*
 * The client sends to relay_in, which passes it on to the server from
 * relay_out, and what the server sends back there goes back to the client
 */
static struct lws *relay_in, *relay_out;
static lws_sockaddr46 relay_client;

/* the server's connection ID, and the DCID the client last sent it */
static uint8_t srv_cid[20], dcid[20];
static size_t srv_cid_len, dcid_len;

static void
relay_sendto(struct lws *wsi, const void *buf, size_t len,
	     const lws_sockaddr46 *to)
{
	if (wsi && to->sa4.sin_family)
		(void)sendto(lws_get_socket_fd(wsi), (const char *)buf,
			     LWS_POSIX_LENGTH_CAST(len), 0, sa46_sockaddr(to),
			     sa46_socklen(to));
}

static int
server_sa46(lws_sockaddr46 *sa46)
{
	memset(sa46, 0, sizeof(*sa46));
	if (lws_sa46_parse_numeric_address("127.0.0.1", sa46))
		return 1;
	sa46_sockport(sa46, htons((uint16_t)port_srv));

	return 0;
}

static int
callback_relay(struct lws *wsi, enum lws_callback_reasons reason,
	       void *user, void *in, size_t len)
{
	const uint8_t *d = (const uint8_t *)in;
	lws_sockaddr46 srv;

	(void)user;

	if (reason != LWS_CALLBACK_RAW_RX || !lws_get_udp(wsi))
		return 0;

	if (wsi == relay_in) {
		relay_client = lws_get_udp(wsi)->sa46;

		/* a short header: the DCID is the server's cid length */
		if (srv_cid_len && len > 1 + srv_cid_len && !(d[0] & 0x80) &&
		    (d[0] & 0x40)) {
			memcpy(dcid, d + 1, srv_cid_len);
			dcid_len = srv_cid_len;
		}

		if (!server_sa46(&srv))
			relay_sendto(relay_out, in, len, &srv);
		return 0;
	}

	/*
	 * The server's long header packets name its connection ID: flags,
	 * version, dcid len, dcid, scid len, scid
	 */
	if (!srv_cid_len && len > 6 && (d[0] & 0x80) &&
	    len > 6 + (size_t)d[5]) {
		size_t sl = d[6 + d[5]];

		if (sl && sl <= sizeof(srv_cid) &&
		    len >= 7 + (size_t)d[5] + sl) {
			memcpy(srv_cid, d + 7 + d[5], sl);
			srv_cid_len = sl;
		}
	}

	relay_sendto(relay_in, in, len, &relay_client);

	return 0;
}

/*
 * What anyone who has seen the DCID can send: a short header naming the
 * connection, and random bytes where the packet number and protected
 * payload go
 */

static void
burst_cb(lws_sorted_usec_list_t *sul)
{
	uint8_t pkt[1 + 20 + 48];
	lws_sockaddr46 srv;
	int n;

	(void)sul;

	if (server_sa46(&srv))
		return;

	for (n = 0; n < QFG_PER_TICK && forged_sent < QFG_FORGED; n++) {
		lws_get_random(context, pkt, sizeof(pkt));
		pkt[0] = (uint8_t)((pkt[0] & 0x3f) | 0x40);
		memcpy(pkt + 1, dcid, dcid_len);
		relay_sendto(relay_out, pkt, 1 + dcid_len + 48, &srv);
		forged_sent++;
	}

	if (forged_sent < QFG_FORGED) {
		lws_sul_schedule(context, 0, &sul_burst, burst_cb, QFG_TICK_US);
		return;
	}

	burst_before_second = body_len == strlen(QFG_SLOW_1);
	key_updates_at_burst = key_updates;
	lwsl_user("%s: %d forged datagrams sent, %d key updates so far\n",
		  __func__, forged_sent, key_updates);
}

/* ------------------------------------------------------------- client */

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 256], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ: {
		const char *c = (const char *)in;
		size_t n, s1 = strlen(QFG_SLOW_1);

		/* the first half, then the pattern */
		for (n = 0; n < len; n++, body_len++)
			if (body_len < s1 ? c[n] != QFG_SLOW_1[body_len] :
					    c[n] != QFG_PAT(body_len - s1))
				body_bad = 1;

		if (!forged_sent && body_len == s1) {
			if (!dcid_len) {
				lwsl_err("%s: the relay saw no DCID\n",
					 __func__);
				lws_default_loop_exit(context);
				return 0;
			}
			lws_sul_schedule(context, 0, &sul_burst, burst_cb, 1);
		}
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
	{ "qfg", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "qfg", callback_cli, 0, 0, 0, NULL, 0 },
	{ "qfg-relay", callback_relay, 0, 0, 0, NULL, 0 },
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

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	const char *p, *cert, *key;
	struct lws_vhost *vh_cli;
	int result = 1;

	lws_context_info_defaults(&info, NULL);
	/* the builtin options keep the emit function we set here */
	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, emit_cb);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* a server and its client */
	info.fd_limit_per_thread = 0;

	port_srv = 7700;
	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_srv = atoi(p);
	port_relay = port_srv + 1;
	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");

	if (!cert || !key || port_srv < 1 || port_srv > 65534) {
		lwsl_err("-p <port>, --cert and --key are required\n");
		return 1;
	}

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: forged QUIC packets change nothing\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);

	/* both ends update their keys every few packets */
	info.options |= LWS_SERVER_OPTION_QUIC_EARLY_KEY_UPDATE;
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* an alpn naming h3 has the vhost bring up a quic listener too */

	info.port			= port_srv;
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

	relay_in = lws_create_adopt_udp(vh_cli, "127.0.0.1", port_relay,
					LWS_CAUDP_BIND, "qfg-relay", NULL,
					NULL, NULL, NULL, NULL);
	relay_out = lws_create_adopt_udp(vh_cli, "127.0.0.1", 0,
					 LWS_CAUDP_BIND, "qfg-relay", NULL,
					 NULL, NULL, NULL, NULL);
	if (!relay_in || !relay_out) {
		lwsl_err("Failed to create the relay\n");
		goto bail;
	}

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= "127.0.0.1";
	i.host			= "localhost";
	i.origin		= "localhost";
	i.port			= port_relay;
	i.path			= "/slow";
	i.method		= "GET";
	i.protocol		= "qfg";
	i.alpn			= "h3";
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	/* this is about the quic connection, not a fallback to tcp */
	i.disable_h3_fallback	= 1;

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 QFG_TIMEOUT_S * LWS_US_PER_SEC);

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("The connection could not be started\n");
		goto bail;
	}

	while (lws_service(context, 0) >= 0)
		;

	if (timed_out)
		lwsl_err("FAIL: timed out\n");
	else if (forged_sent != QFG_FORGED)
		lwsl_err("FAIL: only %d forged datagrams were sent\n",
			 forged_sent);
	else if (!burst_before_second)
		lwsl_err("FAIL: the burst did not fall between the halves\n");
	else if (!completed || body_bad ||
		 body_len != strlen(QFG_SLOW_1) + QFG_BULK)
		lwsl_err("FAIL: the connection did not survive the burst: "
			 "got %u bytes%s\n", (unsigned int)body_len,
			 body_bad ? ", not what was sent" : "");
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
	else if (key_updates <= key_updates_at_burst)
		lwsl_err("FAIL: no key update after the burst (%d before)\n",
			 key_updates_at_burst);
#endif
	else
		result = 0;

	lwsl_user("%d key updates, %d after the burst\n", key_updates,
		  key_updates - key_updates_at_burst);

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_burst);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
