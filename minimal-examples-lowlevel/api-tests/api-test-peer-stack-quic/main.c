/*
 * lws-api-test-peer-stack-quic
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The peer address stack (lws_peer_walk() and friends) of QUIC connections,
 * whose peer is only a datagram's source address until QUIC proves more:
 *
 *  - levels: an h3 client's connection to the server is HEARSAY while it
 *    dials, and CRYPTO once its handshake is done, and the server sees the
 *    client the same way: validated (RFC 9000 8.1) and then bound to the
 *    keys of the completed handshake.  So the server's logs and its access
 *    log show the client by its bare address, as for a TCP connection;
 *
 *  - migration: the client reaches the server through a little udp "NAT"
 *    in the test, which partway through a slow response moves its side to
 *    a new port, as a NAT rebinding does.  Once the server has validated the
 *    new path and moved the connection to it (RFC 9000 9), its peer entry
 *    is the new address and port, at ROUTABLE: a new path starts again from
 *    hearsay and is raised by its validation, it keeps nothing of what the
 *    handshake proved about the old one.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>

#define PQ_PHASE_US	(10 * LWS_US_PER_SEC)

/* the slow response, in two halves either side of the NAT rebinding */
#define PQ_SLOW_1	"first half|"
#define PQ_SLOW_2	"second half"

enum {
	PQ_PHASE_LEVELS,
	PQ_PHASE_MIGRATE,

	PQ_PHASE_COUNT
};

static const char * const phase_names[] = {
	"levels: hearsay while dialling, crypto once the handshake is done",
	"migration: a new path is only routable once validated",
};

static struct lws_context *cx;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_phase;
static const char *cert, *key;
static int phase = -1, fails, finished, phase_done, port_srv, port_nat;
static char body[256];
static size_t body_len;

#if defined(LWS_WITH_ACCESS_LOG)
static const char *alog;		/* the server's access log file */
static char alog_host[LWS_PEER_DESC_LEN]; /* the levels phase's host field */
#endif

/*
 * The "NAT": the client sends to nat_in, which passes it on to the server
 * from nat_out[nat_cur], and what the server sends back there goes back to
 * the client.  Moving nat_cur is a NAT rebinding, as the server sees it.
 */
static struct lws *nat_in, *nat_out[2];
static lws_sockaddr46 nat_client;
static unsigned int nat_out_port[2];
static int nat_cur;

static void
pq_next(lws_sorted_usec_list_t *sul);

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

static void
check_str(const char *got, const char *exp, const char *what)
{
	int ok = !strcmp(got, exp);

	check(ok, what);
	if (!ok)
		lwsl_err("        got '%s', expected '%s'\n", got, exp);
}

static void
pq_phase_end(const char *why)
{
	if (phase_done)
		return;
	phase_done = 1;
	lws_sul_cancel(&sul_phase);

	if (why)
		check(0, why);

	lws_sul_schedule(cx, 0, &sul_phase, pq_next, 1);
}

static void
pq_deadline(lws_sorted_usec_list_t *sul)
{
	(void)sul;

	pq_phase_end("phase did not complete in time");
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
	lws_sockaddr46 sa46;
	socklen_t sl = sizeof(sa46);

	memset(&sa46, 0, sizeof(sa46));
	if (getsockname(lws_get_socket_fd(wsi), (struct sockaddr *)&sa46, &sl))
		return 0;

	return port_of(&sa46);
}

/*
 * The connection's stack is one SOCKET entry at cred, on the port given
 * (if not 0): what a direct QUIC connection's always is
 */
static int
one_socket_entry(struct lws *wsi, lws_peer_cred_t cred, unsigned int port,
		 const char *who)
{
	lws_peer_entry_t e[LWS_PEER_WALK_MAX];
	char what[128];
	int n = lws_peer_walk(wsi, e, LWS_ARRAY_SIZE(e)), ok;

	ok = n == 1 && e[0].kind == LWS_PEER_KIND_SOCKET &&
	     e[0].cred == cred && (!port || port_of(&e[0].sa46) == port);
	lws_snprintf(what, sizeof(what), "%s: one socket entry, %s%s", who,
		     lws_peer_cred_name(cred), port ? ", on its port" : "");
	check(ok, what);
	if (!ok && n)
		lwsl_err("        got %d entries, top %s/%s port %u\n", n,
			 lws_peer_kind_name((lws_peer_kind_t)e[0].kind),
			 lws_peer_cred_name((lws_peer_cred_t)e[0].cred),
			 port_of(&e[0].sa46));

	return ok;
}

/* ------------------------------------------------------------- server */

struct pss_srv {
	lws_sorted_usec_list_t	sul;
	struct lws		*wsi;
	int			slow;	/* 1: first half to go, 2: second */
	int			due;	/* the second half's time has come */
	int			done;	/* the whole answer went */
};

static void
pq_slow_due(lws_sorted_usec_list_t *sul)
{
	struct pss_srv *pss = lws_container_of(sul, struct pss_srv, sul);

	pss->due = 1;
	lws_callback_on_writable(pss->wsi);
}

/* the levels phase's GET: what the server sees of a validated client */
static void
pq_srv_levels(struct lws *wsi)
{
	char simple[64], desc[LWS_PEER_DESC_LEN];

	one_socket_entry(wsi, LWS_PEER_CRED_CRYPTO, 0, "server");

	lws_get_peer_simple(wsi, simple, sizeof(simple));
	check_str(lws_peer_describe(wsi, desc, sizeof(desc),
				    LWS_PEER_DESC_BARE_SINGLE), simple,
		  "server: logs show the client by its bare address");
#if defined(LWS_WITH_ACCESS_LOG)
	check_str(lws_peer_describe(wsi, desc, sizeof(desc),
				    LWS_PEER_DESC_TOKEN |
				    LWS_PEER_DESC_BARE_SINGLE), simple,
		  "server: so does the access log's host field");
	/* what the access log line must start with */
	lws_strncpy(alog_host, simple, sizeof(alog_host));
#endif
}

static int
pq_srv_answer(struct lws *wsi, const char *path)
{
	uint8_t buf[LWS_PRE + 256], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	size_t len = 2;

	if (!strcmp(path, "/slow"))
		len = strlen(PQ_SLOW_1) + strlen(PQ_SLOW_2);

	if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/plain",
					(lws_filepos_t)len, &p, end) ||
	    lws_finalize_write_http_header(wsi, start, &p, end))
		return 1;

	lws_callback_on_writable(wsi);

	return 0;
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t buf[LWS_PRE + 64], *start = &buf[LWS_PRE];
	const char *s;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		pss->wsi = wsi;
		if (in && !strcmp((const char *)in, "/slow")) {
			if (phase != PQ_PHASE_MIGRATE)
				return 1;
			/* the handshake was done on the NAT's first port */
			one_socket_entry(wsi, LWS_PEER_CRED_CRYPTO,
					 nat_out_port[0], "server, first path");
			pss->slow = 1;
			return pq_srv_answer(wsi, "/slow");
		}
		if (phase == PQ_PHASE_LEVELS)
			pq_srv_levels(wsi);

		return pq_srv_answer(wsi, "/");

	case LWS_CALLBACK_HTTP_WRITEABLE:
		/* h3 also asks for WRITEABLE for its own reasons */
		if (!pss || !pss->wsi || pss->done)
			break;

		if (!pss->slow) {
			memcpy(start, "ok", 2);
			if (lws_write(wsi, start, 2, LWS_WRITE_HTTP_FINAL) < 0)
				return -1;
			pss->done = 1;
			return lws_http_transaction_completed(wsi) ? -1 : 0;
		}

		if (pss->slow == 1) {
			memcpy(start, PQ_SLOW_1, strlen(PQ_SLOW_1));
			if (lws_write(wsi, start, strlen(PQ_SLOW_1),
				      LWS_WRITE_HTTP) < 0)
				return -1;
			pss->slow = 2;
			lws_sul_schedule(cx, 0, &pss->sul, pq_slow_due,
					 LWS_US_PER_SEC);
			break;
		}

		if (!pss->due)
			break;

		/*
		 * The second half goes once the connection has moved to the
		 * client's new path, which it does when it validated it
		 */
		{
			lws_peer_entry_t e;

			if (lws_peer_effective(wsi, &e) ||
			    port_of(&e.sa46) != nat_out_port[1]) {
				pss->due = 0;
				lws_sul_schedule(cx, 0, &pss->sul, pq_slow_due,
						 100 * LWS_US_PER_MS);
				break;
			}
		}
		one_socket_entry(wsi, LWS_PEER_CRED_ROUTABLE, nat_out_port[1],
				 "server, migrated path");

		s = PQ_SLOW_2;
		memcpy(start, s, strlen(s));
		if (lws_write(wsi, start, strlen(s), LWS_WRITE_HTTP_FINAL) < 0)
			return -1;
		pss->done = 1;

		return lws_http_transaction_completed(wsi) ? -1 : 0;

	case LWS_CALLBACK_CLOSED_HTTP:
		if (pss)
			lws_sul_cancel(&pss->sul);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* ------------------------------------------------------------- NAT */

static void
nat_sendto(struct lws *wsi, const void *buf, size_t len, lws_sockaddr46 *to)
{
	if (wsi && to->sa4.sin_family)
		(void)sendto(lws_get_socket_fd(wsi), (const char *)buf,
			     LWS_POSIX_LENGTH_CAST(len), 0, sa46_sockaddr(to),
			     sa46_socklen(to));
}

static int
callback_nat(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	lws_sockaddr46 srv;

	if (reason != LWS_CALLBACK_RAW_RX || !lws_get_udp(wsi))
		return 0;

	if (wsi == nat_in) {
		nat_client = lws_get_udp(wsi)->sa46;
		memset(&srv, 0, sizeof(srv));
		if (lws_sa46_parse_numeric_address("127.0.0.1", &srv))
			return 0;
		sa46_sockport(&srv, htons((uint16_t)port_srv));
		nat_sendto(nat_out[nat_cur], in, len, &srv);
		return 0;
	}

	/* a rebinding NAT has forgotten the old mapping */
	if (wsi == nat_out[nat_cur])
		nat_sendto(nat_in, in, len, &nat_client);

	(void)user;

	return 0;
}

/* ------------------------------------------------------------- client */

static struct lws *cli_wsi;

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	char buf[LWS_PRE + 1024], *px;
	int alen;

	if (wsi != cli_wsi && reason != LWS_CALLBACK_CONNECTING)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {
	case LWS_CALLBACK_CONNECTING:
		/* nothing has answered from where we dial yet */
		if (lws_get_opaque_user_data(wsi) ==
					(void *)(intptr_t)(phase + 1))
			one_socket_entry(wsi, LWS_PEER_CRED_HEARSAY, 0,
					 "client, dialling");
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (phase == PQ_PHASE_LEVELS)
			one_socket_entry(wsi, LWS_PEER_CRED_CRYPTO, 0,
					 "client, handshake done");
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		px = buf + LWS_PRE;
		alen = (int)sizeof(buf) - LWS_PRE;
		if (lws_http_client_read(wsi, &px, &alen) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (phase == PQ_PHASE_MIGRATE && !nat_cur) {
			/* the first half is here: the NAT rebinds */
			lwsl_user("  NAT rebinding to a new port\n");
			nat_cur = 1;
		}
		if (body_len + len < sizeof(body)) {
			memcpy(body + body_len, in, len);
			body_len += len;
			body[body_len] = '\0';
		}
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		check_str(body, phase == PQ_PHASE_MIGRATE ?
				PQ_SLOW_1 PQ_SLOW_2 : "ok",
			  "client: the whole answer arrived");
		cli_wsi = NULL;
		pq_phase_end(NULL);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		cli_wsi = NULL;
		pq_phase_end(in ? (const char *)in : "connection error");
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		cli_wsi = NULL;
		pq_phase_end("closed before the answer was complete");
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
pq_get(int port, const char *path)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= cx;
	i.vhost			= vh_cli;
	i.address		= "127.0.0.1";
	i.port			= port;
	i.host			= "localhost";
	i.origin		= "localhost";
	i.path			= path;
	i.method		= "GET";
	i.alpn			= "h3";
	i.disable_h3_fallback	= 1;
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	i.protocol		= "pq-cli";
	i.local_protocol_name	= "pq-cli";
	i.opaque_user_data	= (void *)(intptr_t)(phase + 1);
	i.pwsi			= &cli_wsi;

	return !lws_client_connect_via_info(&i);
}

static const struct lws_protocols
	pcol_srv = { "pq-srv", callback_srv, sizeof(struct pss_srv), 0, 0,
		     NULL, 0 },
	pcol_cli = { "pq-cli", callback_cli, 0, 0, 0, NULL, 0 },
	pcol_nat = { "pq-nat", callback_nat, 0, 0, 0, NULL, 0 };

static const struct lws_protocols
	*pp_srv[] = { &pcol_srv, NULL },
	*pp_cli[] = { &pcol_cli, &pcol_nat, NULL };

/* ------------------------------------------------------------- sequence */

static void
pq_next(lws_sorted_usec_list_t *sul)
{
	int r = 0;

	(void)sul;

	if (++phase == PQ_PHASE_COUNT) {
		finished = 1;
		lws_cancel_service(cx);
		return;
	}

	lwsl_user("%s:\n", phase_names[phase]);
	phase_done	= 0;
	body_len	= 0;
	body[0]		= '\0';
	lws_sul_schedule(cx, 0, &sul_phase, pq_deadline, PQ_PHASE_US);

	switch (phase) {
	case PQ_PHASE_LEVELS:
		r = pq_get(port_srv, "/");
		break;
	case PQ_PHASE_MIGRATE:
		r = pq_get(port_nat, "/slow");
		break;
	}

	if (r)
		pq_phase_end("connect failed");
}

#if defined(LWS_WITH_ACCESS_LOG)

/*
 * The server's access log, once the context has closed it: the levels
 * phase's GET is logged with just the client's address as its host field,
 * as a TCP connection's is, not with a hearsay port and cred
 */

static void
pq_access_log(void)
{
	char log[4096], want[LWS_PEER_DESC_LEN + 8];
	const char *p = log, *eol;
	size_t wl;
	int n;

	lwsl_user("access log:\n");

	n = lws_plat_read_file(alog, log, sizeof(log) - 1);
	if (n <= 0) {
		check(0, "the access log was written");
		return;
	}
	log[n] = '\0';

	if (!alog_host[0]) {
		check(0, "the levels phase's request was seen");
		return;
	}

	lws_snprintf(want, sizeof(want), "%s - - [", alog_host);
	wl = strlen(want);

	while (*p) {
		eol = strchr(p, '\n');
		if (!eol)
			break;
		if (!strncmp(p, want, wl) &&
		    lws_nstrstr(p, lws_ptr_diff_size_t(eol, p), "\"GET / ", 6)) {
			check(1, "an h3 client's line starts with just its "
				 "address");
			return;
		}
		p = eol + 1;
	}

	check(0, "an h3 client's line starts with just its address");
	lwsl_err("        no line starting '%s' in:\n%s\n", want, log);
}
#endif

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int m = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");
	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_srv = atoi(p);
	if (!cert || !key || !port_srv) {
		lwsl_err("--cert, --key and -p are required\n");
		return 1;
	}
#if defined(LWS_WITH_ACCESS_LOG)
	alog = lws_cmdline_option(argc, argv, "--access-log");
	/* only this run's lines in it */
	if (alog && lws_plat_write_file(alog, (void *)"", 0)) {
		lwsl_err("can't truncate %s\n", alog);
		return 1;
	}
#endif

	lwsl_user("LWS API selftest: peer address stack on QUIC\n");

	/* a server and a client in one process: don't budget fds */
	info.fd_limit_per_thread	= 0;
	info.options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
					  LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.port			= port_srv;
	info.pprotocols			= pp_srv;
	info.vhost_name			= "localhost";
	info.ssl_cert_filepath		= cert;
	info.ssl_private_key_filepath	= key;
	info.alpn			= "h3";
#if defined(LWS_WITH_ACCESS_LOG)
	info.log_filepath		= alog;
#endif
	if (!lws_create_vhost(cx, &info))
		goto bail;

#if defined(LWS_WITH_ACCESS_LOG)
	info.log_filepath		= NULL;
#endif
	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;
	info.alpn			= NULL;
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.pprotocols			= pp_cli;
	info.vhost_name			= "pq-cli";
	vh_cli = lws_create_vhost(cx, &info);
	if (!vh_cli)
		goto bail;

	/* the NAT's two sides, on ports the kernel picks */
	nat_in = lws_create_adopt_udp(vh_cli, "127.0.0.1", 0, LWS_CAUDP_BIND,
				      "pq-nat", NULL, NULL, NULL, NULL, NULL);
	nat_out[0] = lws_create_adopt_udp(vh_cli, "127.0.0.1", 0,
					  LWS_CAUDP_BIND, "pq-nat", NULL, NULL,
					  NULL, NULL, NULL);
	nat_out[1] = lws_create_adopt_udp(vh_cli, "127.0.0.1", 0,
					  LWS_CAUDP_BIND, "pq-nat", NULL, NULL,
					  NULL, NULL, NULL);
	if (!nat_in || !nat_out[0] || !nat_out[1])
		goto bail;
	port_nat	= (int)local_port(nat_in);
	nat_out_port[0]	= local_port(nat_out[0]);
	nat_out_port[1]	= local_port(nat_out[1]);
	if (!port_nat || !nat_out_port[0] || !nat_out_port[1])
		goto bail;

	lws_sul_schedule(cx, 0, &sul_phase, pq_next, 1);

	while (m >= 0 && !finished)
		m = lws_service(cx, 0);

	if (!finished) {
		lwsl_err("service loop ended early\n");
		fails++;
	}

	lws_sul_cancel(&sul_phase);
	lws_context_destroy(cx);

#if defined(LWS_WITH_ACCESS_LOG)
	/* the vhost flushed and closed it */
	if (alog)
		pq_access_log();
#endif

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;

bail:
	lwsl_err("setup failed\n");
	lws_context_destroy(cx);

	return 1;
}
