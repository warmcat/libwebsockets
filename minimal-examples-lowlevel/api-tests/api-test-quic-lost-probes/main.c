/*
 * lws-api-test-quic-lost-probes
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Replays what stalled a server in the interop runner's handshakecorruption
 * case.  Its lost PTO probes were taken for persistent congestion (RFC 9002
 * 7.6), though one sent between them had got through, so its congestion
 * window was cut to the minimum; then a PMTUD probe, lost too, held most of
 * that window until an ack came, and its response went only a packet a PTO,
 * until it gave up on the connection.
 *
 * An h3 server and its clients are in this process, with a udp "NAT" between
 * them that sees each datagram's direction and size, nothing more, and keeps
 * a mapping of its own for each connection.  For each of two connections,
 * the server's PMTUD search sends its last probe, a datagram the size of its
 * ceiling, and
 *
 *  - the NAT drops it.  The server's PTO sends a PING, which gets an ack,
 *    the probe is found lost, and goes again.  By then everything else the
 *    server sent was acked, so it has only the probe in flight
 *
 *  - the NAT drops the probe again, and from then on, everything the client
 *    sends.  The server's PTOs now send PINGs, each a datagram of its own, at
 *    1, 3, 7 and 15 times its PTO after the probe, since with no ack the
 *    backoff doubles: P1 to P4.  The NAT passes P4, and from then on what the
 *    client sends again, its ack of P4 first
 *
 * no congestion: the client GETs a short answer, and the NAT drops P1 and P3,
 * passing P2 and P4.  The client's ack of P4 must report P2 as well: an ACK
 * reports every range of PNs it has, not only the run down from its largest
 * (RFC 9000 13.2.3, 19.3.1), since the ack that reported P2 was lost, and
 * nothing sends that again.  The server finds P1 and P3 lost, which were sent
 * six PTOs apart, more than persistent congestion's period of three.  But P2
 * was acked between them, so it is no persistent congestion (RFC 9002 7.6.2).
 *
 * congestion: the client GETs an answer the server holds back, and the NAT
 * drops P1, P2 and P3.  Now it is persistent congestion, and the server cuts
 * its window to the minimum.  The probe was found lost by the same ack, so it
 * goes a third time, and the NAT drops it once more.  Then the server sends
 * its held answer, two packets of the path's size.  A PMTUD probe's bytes are
 * not in flight for congestion control (RFC 8899 3, item 7), so the window
 * has room for the answer's first packet at once, and the rest as acks come.
 * Counted, the lost probe held most of the window, and the answer could go
 * only in the probe of a PTO.
 *
 * wsi/quic_stats has the server log, as each connection goes, how many times
 * it found persistent congestion, and how many packets took stream data for
 * the first time only as a PTO's probe, past a full congestion window.  One
 * connection must have found persistent congestion and the other not, and
 * neither may have sent stream data first in a PTO's probe.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define QLP_TIMEOUT_S		50
/*
 * Only the last probe of the server's PMTUD search, of its 1500 byte ceiling,
 * is a datagram this big: the probes before it are 1332 and 1432 bytes
 */
#define QLP_PROBE_MIN		1441
/* a PTO's PING with nothing else to send again is a small datagram */
#define QLP_PING_MAX		64
/* after the client's ack of P4 goes, the server has long taken it */
#define QLP_SETTLE_US		(300 * LWS_US_PER_MS)
/* the held answer: two packets of the path's size */
#define QLP_HELD_LEN		2400

enum {
	QLP_PHASE_NO_CONGESTION,
	QLP_PHASE_CONGESTION,

	QLP_PHASE_COUNT
};

/* what the NAT does, as the server's datagrams come */
enum {
	QLP_PASS,		/* until the probe first goes */
	QLP_PROBE_AGAIN,	/* dropped it once, waiting for it again */
	QLP_PROBES,		/* dropped it again: the PTO probes come */
	QLP_PROBE_THIRD,	/* P4 passed: congestion drops the probe again */
	QLP_DONE,		/* everything goes */
};

static struct lws_context *cx;
static lws_sorted_usec_list_t sul_watchdog, sul_next;
static struct lws_vhost *vh_cli[QLP_PHASE_COUNT];
/*
 * Each phase's connection has a NAT mapping of its own, a pair of sockets, as
 * a real NAT keeps one per flow: the first phase's connection stays up, and
 * what passes between it and the server meanwhile must not be taken for, or
 * go to, the next phase's client
 */
static struct lws *nat_in[QLP_PHASE_COUNT], *nat_out[QLP_PHASE_COUNT],
		  *srv_held;
static lws_sockaddr46 nat_client[QLP_PHASE_COUNT], nat_srv;
static int port_srv = 7720, phase, state, pto_probes, timed_out, fails,
	   completed[QLP_PHASE_COUNT], cli_dropped[QLP_PHASE_COUNT],
	   probes_seen[QLP_PHASE_COUNT], held_released, stats_lines;
static size_t body_len[QLP_PHASE_COUNT];
/* the server connections' stats, in the order they went */
static uint64_t srv_pc[QLP_PHASE_COUNT], srv_pto_fresh[QLP_PHASE_COUNT];

static void
check(int ok, const char *what)
{
	if (ok)
		lwsl_user("  PASS: %s\n", what);
	else {
		lwsl_err("  FAIL: %s\n", what);
		fails++;
	}
}

static unsigned int
port_of(const lws_sockaddr46 *sa46)
{
#if defined(LWS_WITH_IPV6)
	if (sa46->sa4.sin_family == AF_INET6)
		return ntohs(sa46->sa6.sin6_port);
#endif
	return ntohs(sa46->sa4.sin_port);
}

static unsigned int
local_port(struct lws *wsi)
{
	lws_sockfd_type fd = lws_get_socket_fd(wsi);
	lws_sockaddr46 sa46;
	socklen_t sl = sizeof(sa46);

	if (fd == LWS_SOCK_INVALID)
		return 0;

	memset(&sa46, 0, sizeof(sa46));
	if (getsockname(fd, (struct sockaddr *)&sa46, &sl))
		return 0;

	return port_of(&sa46);
}

/* ------------------------------------------------------- the stats lines */

/*
 * The number after "<key> " in line, eg "pto fresh 0"; *bad is set if the key
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
	const char *p;
	int bad = 0;

	lwsl_emit_stderr(level, line);

	if (!(level & LLL_NOTICE) ||
	    !(p = strstr(line, "QUIC FI stats: server,")))
		return;

	if (stats_lines >= QLP_PHASE_COUNT) {
		stats_lines++;
		return;
	}

	srv_pc[stats_lines]		= stat_get(p, "persistent congestion ",
						   &bad);
	srv_pto_fresh[stats_lines]	= stat_get(p, "pto fresh ", &bad);
	if (bad)
		fails++;
	stats_lines++;
}

/* ------------------------------------------------------------- NAT */

static void
qlp_next(lws_sorted_usec_list_t *sul);

static void
nat_sendto(struct lws *wsi, const void *buf, size_t len, lws_sockaddr46 *to)
{
	if (wsi && to->sa4.sin_family)
		(void)sendto(lws_get_socket_fd(wsi), (const char *)buf,
			     LWS_POSIX_LENGTH_CAST(len), 0, sa46_sockaddr(to),
			     sa46_socklen(to));
}

/* does the NAT drop P<n>, n from 1 to 4, in this phase? */
static int
qlp_drops(int n)
{
	if (phase == QLP_PHASE_NO_CONGESTION)
		return n & 1;

	return n < 4;
}

/* a datagram from the server: does it go on to the client? */
static int
nat_srv_dgram(size_t len)
{
	switch (state) {
	case QLP_PASS:
		if (len < QLP_PROBE_MIN)
			return 1;
		lwsl_user("  NAT: drops the server's PMTUD probe\n");
		state = QLP_PROBE_AGAIN;
		return 0;

	case QLP_PROBE_AGAIN:
		if (len < QLP_PROBE_MIN)
			return 1;
		lwsl_user("  NAT: drops the server's PMTUD probe again, and "
			  "what the client sends\n");
		state = QLP_PROBES;
		return 0;

	case QLP_PROBES:
		/*
		 * The server hears nothing from the client meanwhile, so all
		 * it sends is its PTO's probes
		 */
		if (len > QLP_PING_MAX) {
			lwsl_err("  NAT: a %u byte datagram is no PTO's PING\n",
				 (unsigned int)len);
			fails++;
			state = QLP_DONE;
			return 1;
		}
		pto_probes++;
		probes_seen[phase]++;
		lwsl_user("  NAT: %s the server's PTO probe P%d\n",
			  qlp_drops(pto_probes) ? "drops" : "passes",
			  pto_probes);
		if (pto_probes < 4)
			return !qlp_drops(pto_probes);

		if (phase == QLP_PHASE_NO_CONGESTION) {
			state = QLP_DONE;
			lws_sul_schedule(cx, 0, &sul_next, qlp_next,
					 QLP_SETTLE_US);
		} else
			state = QLP_PROBE_THIRD;
		return 1;

	case QLP_PROBE_THIRD:
		if (len < QLP_PROBE_MIN)
			return 1;
		/*
		 * The window was cut to the minimum when this probe's last
		 * try was found lost, and it went again at once
		 */
		lwsl_user("  NAT: drops the server's PMTUD probe a third "
			  "time: the server answers\n");
		state = QLP_DONE;
		held_released = 1;
		if (srv_held)
			lws_callback_on_writable(srv_held);
		return 0;

	default:
		return 1;
	}
}

static int
callback_nat(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	int n;

	(void)user;

	if (reason != LWS_CALLBACK_RAW_RX || !lws_get_udp(wsi) || !len)
		return 0;

	for (n = 0; n < QLP_PHASE_COUNT; n++)
		if (wsi == nat_in[n] || wsi == nat_out[n])
			break;
	if (n == QLP_PHASE_COUNT)
		return 0;

	if (wsi == nat_in[n]) {
		/* only phase n's client sends to its mapping */
		nat_client[n] = lws_get_udp(wsi)->sa46;
		/* from the probe's second drop until passing P4, nothing */
		if (n == phase && state == QLP_PROBES) {
			cli_dropped[phase]++;
			return 0;
		}
		nat_sendto(nat_out[n], in, len, &nat_srv);
		return 0;
	}

	/* only the phase's own connection sees the drops */
	if (n != phase || nat_srv_dgram(len))
		nat_sendto(nat_in[n], in, len, &nat_client[n]);

	return 0;
}

/* ------------------------------------------------------------- server */

struct pss_srv {
	int			held;	/* its answer waits for the release */
};

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	uint8_t buf[LWS_PRE + QLP_HELD_LEN], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	struct pss_srv *pss = (struct pss_srv *)user;
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		pss->held = in && !strcmp((const char *)in, "/held");
		if (pss->held)
			srv_held = wsi;
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
				"text/plain", pss->held ? QLP_HELD_LEN : 2,
				&p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss)
			break;
		if (!pss->held) {
			memcpy(start, "ok", 2);
			n = 2;
		} else {
			if (!held_released)
				break;
			memset(start, 'x', QLP_HELD_LEN);
			n = QLP_HELD_LEN;
		}
		if (lws_write(wsi, start, n, LWS_WRITE_HTTP_FINAL) < 0)
			return -1;
		return lws_http_transaction_completed(wsi) ? -1 : 0;

	case LWS_CALLBACK_CLOSED_HTTP:
		if (wsi == srv_held)
			srv_held = NULL;
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* ------------------------------------------------------------- client */

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	char buf[LWS_PRE + 256], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		body_len[phase] += len;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		/* the connection stays up, for the server's probes */
		completed[phase] = 1;
		if (phase == QLP_PHASE_CONGESTION)
			lws_sul_schedule(cx, 0, &sul_next, qlp_next,
					 QLP_SETTLE_US);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (const char *)in : "(null)");
		lws_default_loop_exit(cx);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols
	pcol_srv = { "qlp-srv", callback_srv, sizeof(struct pss_srv), 0, 0,
		     NULL, 0 },
	pcol_cli = { "qlp-cli", callback_cli, 0, 0, 0, NULL, 0 },
	pcol_nat = { "qlp-nat", callback_nat, 0, 0, 0, NULL, 0 };

static const struct lws_protocols
	*pp_srv[] = { &pcol_srv, NULL },
	*pp_cli[] = { &pcol_cli, &pcol_nat, NULL };

/* ------------------------------------------------------------- sequence */

/* the phase's client connects through the NAT, from a vhost of its own */
static int
qlp_get(const char *path)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= cx;
	i.vhost			= vh_cli[phase];
	i.address		= "127.0.0.1";
	i.port			= (int)local_port(nat_in[phase]);
	i.host			= "localhost";
	i.origin		= "localhost";
	i.path			= path;
	i.method		= "GET";
	i.alpn			= "h3";
	i.protocol		= "qlp-cli";
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	/* this is about the quic connection, not a fallback to tcp */
	i.disable_h3_fallback	= 1;

	return !lws_client_connect_via_info(&i);
}

static void
qlp_next(lws_sorted_usec_list_t *sul)
{
	(void)sul;

	if (phase == QLP_PHASE_NO_CONGESTION) {
		phase		= QLP_PHASE_CONGESTION;
		state		= QLP_PASS;
		pto_probes	= 0;
		lwsl_user("congestion: the server answers once its window "
			  "was cut\n");
		if (qlp_get("/held")) {
			lwsl_err("The connection could not be started\n");
			lws_default_loop_exit(cx);
		}
		return;
	}

	lws_default_loop_exit(cx);
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;
	timed_out = 1;
	lws_default_loop_exit(cx);
}

static void
sigint_handler(int sig)
{
	(void)sig;
	lws_default_loop_exit(cx);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p, *cert, *key;
	char name[16];
	lws_fi_t fi;
	int n;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, emit_cb);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_srv = atoi(p);
	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");
	if (!cert || !key || port_srv < 1 || port_srv > 65535) {
		lwsl_err("-p <port>, --cert and --key are required\n");
		return 1;
	}

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: QUIC lost PTO probes\n");

	/* the server logs what it found as its connections go */
	memset(&fi, 0, sizeof(fi));
	fi.name = "wsi/quic_stats";
	fi.type = LWSFI_ALWAYS;
	if (lws_fi_add(&info.fic, &fi)) {
		lwsl_err("OOM adding faults\n");
		return 1;
	}

	/* a server, its clients and the NAT's sockets */
	info.fd_limit_per_thread = 0;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* an alpn naming h3 has the vhost bring up a quic listener too */
	info.port			= port_srv;
	info.pprotocols			= pp_srv;
	info.vhost_name			= "localhost";
	info.ssl_cert_filepath		= cert;
	info.ssl_private_key_filepath	= key;
	info.alpn			= "h3";
	if (!lws_create_vhost(cx, &info)) {
		lwsl_err("Failed to create the server vhost\n");
		goto bail;
	}

	/* each phase's client has a vhost of its own, so joins no connection */
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.pprotocols			= pp_cli;
	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;
	info.alpn			= NULL;
	for (n = 0; n < QLP_PHASE_COUNT; n++) {
		lws_snprintf(name, sizeof(name), "qlp-cli-%d", n);
		info.vhost_name		= name;
		vh_cli[n] = lws_create_vhost(cx, &info);
		if (!vh_cli[n]) {
			lwsl_err("Failed to create a client vhost\n");
			goto bail;
		}
	}

	/* each phase's NAT mapping, on ports the kernel picks */
	for (n = 0; n < QLP_PHASE_COUNT; n++) {
		nat_in[n] = lws_create_adopt_udp(vh_cli[n], "127.0.0.1", 0,
						 LWS_CAUDP_BIND, "qlp-nat",
						 NULL, NULL, NULL, NULL, NULL);
		nat_out[n] = lws_create_adopt_udp(vh_cli[n], "127.0.0.1", 0,
						  LWS_CAUDP_BIND, "qlp-nat",
						  NULL, NULL, NULL, NULL, NULL);
		if (!nat_in[n] || !nat_out[n] || !local_port(nat_in[n])) {
			lwsl_err("Failed to create the NAT\n");
			goto bail;
		}
	}
	memset(&nat_srv, 0, sizeof(nat_srv));
	if (lws_sa46_parse_numeric_address("127.0.0.1", &nat_srv)) {
		lwsl_err("Failed to create the NAT\n");
		goto bail;
	}
	sa46_sockport(&nat_srv, htons((uint16_t)port_srv));

	lws_sul_schedule(cx, 0, &sul_watchdog, watchdog_cb,
			 QLP_TIMEOUT_S * LWS_US_PER_SEC);

	lwsl_user("no congestion: a probe got through between lost ones\n");
	if (qlp_get("/")) {
		lwsl_err("The connection could not be started\n");
		goto bail;
	}

	while (lws_service(cx, 0) >= 0)
		;

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_next);
	/* the connections go, and log their stats, with the context */
	lws_context_destroy(cx);

	check(!timed_out, "the phases completed in time");
	for (n = 0; n < QLP_PHASE_COUNT; n++) {
		check(completed[n], "the client got its answer");
		check(probes_seen[n] == 4,
		      "the NAT saw the server's four PTO probes");
	}
	/*
	 * The client must ack P2, and the NAT drop it, so only a later ack's
	 * ranges can tell the server of P2.  With P1 to P3 all dropped, the
	 * client may have nothing to send meanwhile.
	 */
	check(cli_dropped[QLP_PHASE_NO_CONGESTION] > 0,
	      "the NAT dropped what the client sent meanwhile, its ack "
	      "of P2 with it");
	check(body_len[QLP_PHASE_CONGESTION] == QLP_HELD_LEN,
	      "the held answer came whole");
	check(stats_lines == QLP_PHASE_COUNT,
	      "the server logged its connections' stats");

	/* the connections go in no particular order */
	lwsl_user("server: persistent congestion %llu and %llu, stream data "
		  "first in a PTO's probe %llu and %llu\n",
		  (unsigned long long)srv_pc[0], (unsigned long long)srv_pc[1],
		  (unsigned long long)srv_pto_fresh[0],
		  (unsigned long long)srv_pto_fresh[1]);
	check(!srv_pc[0] != !srv_pc[1],
	      "one connection found persistent congestion, the other not");
	check(!srv_pto_fresh[0] && !srv_pto_fresh[1],
	      "no stream data went first in a PTO's probe");

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
