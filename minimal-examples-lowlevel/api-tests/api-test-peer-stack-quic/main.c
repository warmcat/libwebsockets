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
 *    handshake proved about the old one;
 *
 *  - slow probe: the same, but the NAT holds what the client sends from its
 *    new port after the first datagram, past the server's first PTO.  That
 *    datagram is small, so the server's PATH_CHALLENGE spends the 3x
 *    allowance it gives (RFC 9000 9.3.1) and no resend fits.  The probe must
 *    still stand, and take the late PATH_RESPONSE to that challenge, which
 *    comes before its deadline (8.2.4): a probe given up early holds the
 *    address off, so it couldn't be validated that soon;
 *
 *  - split: the NAT sends the client's first Initial from one port, and
 *    every later long header packet, its Handshake packets among them, from
 *    another, whose answers it drops.  The Handshake keys prove the address
 *    the server's Initial went to (RFC 9000 8.1), not where a Handshake
 *    packet claims to come from, so the server sees the client on the first
 *    port at CRYPTO, keyed as its own host, not as unproven.
 *
 * and with LWS_WITH_PEER_LIMITS, the unproven budget, in a context of its own,
 * so that nothing of the phases above is still counted, with ip_limit_wsi and
 * unproven_limit_wsi both 1.  Each client has a client vhost of its own, so
 * that none joins another's connection:
 *
 *  - hold: a client's request is held unanswered by the server, so its
 *    validated connection stays up, counted against its host, 127.0.0.1;
 *
 *  - host: another client from 127.0.0.1 is let in while its address is
 *    unproven, but refused when QUIC validates it, since its host is then
 *    at its limit: pl_notify_cb is told about 127.0.0.1;
 *
 *  - unproven: a lone QUIC Initial sent from a raw socket in the test, which
 *    never goes on to validate its address, is let in: the held connection
 *    no longer counts in the unproven budget.  It fills that budget, so the
 *    next client's Initial is refused for it, and pl_notify_cb is told about
 *    no address, since the client's is only hearsay at that point;
 *
 *  - release: the held request is answered, its connection unaffected by
 *    the full unproven budget.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>

#define PQ_PHASE_US	(10 * LWS_US_PER_SEC)
/* how long an Initial nobody refuses takes to be let in, at most */
#define PQ_SETTLE_US	(300 * LWS_US_PER_MS)

/* the slow response, in two halves either side of the NAT rebinding */
#define PQ_SLOW_1	"first half|"
#define PQ_SLOW_2	"second half"

/*
 * The slow probe phase: how long the NAT holds the client's datagrams from
 * its new port, after the first.  It is past the server's first probe PTO
 * (500ms here, where the rtt is tiny) and short of the probe's deadline,
 * three PTOs.  Once they go, the server must have moved to the new path
 * within PQ_PROBE_SOON_US: before the 1s holdoff a probe given up at the
 * first PTO would have to wait out before probing the address again.
 */
#define PQ_PROBE_HOLD_US	(900 * LWS_US_PER_MS)
#define PQ_PROBE_SOON_US	(450 * LWS_US_PER_MS)

/*
 * The largest first datagram from the new port that leaves the server no room
 * for a resend of its challenge.  The challenge is padded to the 3x allowance
 * that datagram earned, but no further than one datagram can go, at least
 * 1200 bytes (RFC 9000 14.1).  So up to a third of that, the first challenge
 * spends the whole allowance.  The client's ack of the first half is far
 * smaller, but a slow box may send something bigger first, eg, coalesced
 * with more: then resends fit, and the phase checks only that the server kept
 * within the allowance.
 */
#define PQ_PROBE_SMALL_MAX	(1200 / 3)

enum {
	PQ_PHASE_LEVELS,
	PQ_PHASE_MIGRATE,
	PQ_PHASE_SLOW_PROBE,
	PQ_PHASE_SPLIT,

	/* the budget part, in a context of its own */
	PQ_PHASE_HOLD,
	PQ_PHASE_HOST,
	PQ_PHASE_UNPROVEN,
	PQ_PHASE_RELEASE,

	PQ_PHASE_COUNT
};

static const char * const phase_names[] = {
	"levels: hearsay while dialling, crypto once the handshake is done",
	"migration: a new path is only routable once validated",
	"slow probe: a probe whose allowance is spent waits for its answer",
	"split: Handshake packets from another port prove the Initial's path",
	"hold: a validated client's request is held",
	"host: a client is refused only once validated, at its host's limit",
	("unproven: an unvalidated Initial fills the unproven budget, the next "
		"is refused"),
	"release: the held client is unaffected",
};

static struct lws_context *cx;
static struct lws_vhost *vh_cli[PQ_PHASE_COUNT];
static lws_sorted_usec_list_t sul_phase;
static const char *cert, *key;
static int phase = -1, phase_last, fails, finished, phase_done, port_srv,
	   port_nat;

/* each phase's client, and what it was answered */
static struct lws *cli[PQ_PHASE_COUNT];
static char body[PQ_PHASE_COUNT][64];
static size_t body_len[PQ_PHASE_COUNT];

#if defined(LWS_WITH_PEER_LIMITS)
static struct lws *hold_wsi;		/* the server's held request */
static struct lws *raw_udp;		/* sends the lone Initial */
static lws_sorted_usec_list_t sul_settle, sul_kill;
static int refused_host, refused_unproven;
#endif

#if defined(LWS_WITH_ACCESS_LOG)
static const char *alog;		/* the server's access log file */
static char alog_host[LWS_PEER_DESC_LEN]; /* the levels phase's host field */
#endif

/*
 * The "NAT": the client sends to nat_in, which passes it on to the server
 * from nat_out[nat_cur], and what the server sends back there goes back to
 * the client.  Moving nat_cur is a NAT rebinding, as the server sees it.
 * [0] and [1] are the migration phase's ports, before and after; [2] is the
 * split phase's, and [3] the one it sends the client's long header packets
 * after the first from, answers to which go nowhere; [4] and [5] are the
 * slow probe phase's, before and after.  nat_first and nat_rebound are the
 * current phase's before and after.  nat_client is the phase's client, the
 * only one it passes on.
 */
static struct lws *nat_in, *nat_out[6];
static lws_sockaddr46 nat_client;
static unsigned int nat_out_port[6];
static int nat_cur, nat_first, nat_rebound, nat_long_headers;

/*
 * The slow probe phase's held datagrams, from the client's new port, the
 * size of the one let through before them, and how many datagrams and bytes
 * the server sent there while they were held
 */
struct nat_held {
	lws_dll2_t	list;
	size_t		len;
	/* the datagram follows */
};
static lws_dll2_owner_t nat_held_owner;
static lws_sorted_usec_list_t sul_nat_release, sul_probe_check;
static struct lws *srv_slow;		/* the server's slow request */
static lws_usec_t nat_released;
static size_t nat_rebound_first_len, nat_probe_bytes;
static int nat_holding, nat_rebound_tx, nat_probe_dgrams, probe_checked;

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
	int			held;	/* the answer waits for the release */
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
	char simple[64], desc[LWS_PEER_DESC_LEN], hk[LWS_HOST_KEY_LEN];

	one_socket_entry(wsi, LWS_PEER_CRED_CRYPTO, 0, "server");
	check_str(lws_get_peer_host_key(wsi, hk, sizeof(hk)), "127.0.0.1",
		  "server: the client is keyed as its own host");

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
			if (phase != PQ_PHASE_MIGRATE &&
			    phase != PQ_PHASE_SLOW_PROBE)
				return 1;
			/* the handshake was done on the NAT's first port */
			one_socket_entry(wsi, LWS_PEER_CRED_CRYPTO,
					 nat_out_port[nat_first],
					 "server, first path");
			pss->slow = 1;
			srv_slow = wsi;
			return pq_srv_answer(wsi, "/slow");
		}
		if (in && !strcmp((const char *)in, "/split")) {
			char hk[LWS_HOST_KEY_LEN];

			if (phase != PQ_PHASE_SPLIT)
				return 1;
			/* its Handshake packets proved the Initial's path */
			one_socket_entry(wsi, LWS_PEER_CRED_CRYPTO,
					 nat_out_port[2], "server, split");
			check_str(lws_get_peer_host_key(wsi, hk, sizeof(hk)),
				  "127.0.0.1", "server, split: the client is "
					       "keyed as its own host");
			return pq_srv_answer(wsi, "/");
		}
		if (phase == PQ_PHASE_LEVELS)
			pq_srv_levels(wsi);
#if defined(LWS_WITH_PEER_LIMITS)
		if (in && !strcmp((const char *)in, "/hold")) {
			if (phase != PQ_PHASE_HOLD)
				return 1;
			/* validated, and counted against 127.0.0.1 */
			one_socket_entry(wsi, LWS_PEER_CRED_CRYPTO, 0,
					 "server, held request");
			pss->held = 1;
			hold_wsi = wsi;
			pq_phase_end(NULL);
		} else if (phase == PQ_PHASE_HOST || phase == PQ_PHASE_UNPROVEN)
			check(0, "server: a request over a limit was served");
#endif

		return pq_srv_answer(wsi, "/");

	case LWS_CALLBACK_HTTP_WRITEABLE:
		/* h3 also asks for WRITEABLE for its own reasons */
		if (!pss || !pss->wsi || pss->done)
			break;

		if (pss->held)
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

		/* the slow probe phase checks the new path first */
		if (phase == PQ_PHASE_SLOW_PROBE && !probe_checked)
			break;

		/*
		 * The second half goes once the connection has moved to the
		 * client's new path, which it does when it validated it
		 */
		{
			lws_peer_entry_t e;

			if (lws_peer_effective(wsi, &e) ||
			    port_of(&e.sa46) != nat_out_port[nat_rebound]) {
				pss->due = 0;
				lws_sul_schedule(cx, 0, &pss->sul, pq_slow_due,
						 100 * LWS_US_PER_MS);
				break;
			}
		}
		one_socket_entry(wsi, LWS_PEER_CRED_ROUTABLE,
				 nat_out_port[nat_rebound],
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
		if (wsi == srv_slow)
			srv_slow = NULL;
#if defined(LWS_WITH_PEER_LIMITS)
		if (wsi == hold_wsi)
			hold_wsi = NULL;
#endif
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
nat_srv(lws_sockaddr46 *srv)
{
	memset(srv, 0, sizeof(*srv));
	if (lws_sa46_parse_numeric_address("127.0.0.1", srv))
		return 1;
	sa46_sockport(srv, htons((uint16_t)port_srv));

	return 0;
}

static void
nat_held_drop(void)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&nat_held_owner)) {
		struct nat_held *h = lws_container_of(d, struct nat_held, list);

		lws_dll2_remove(&h->list);
		free(h);
	} lws_end_foreach_dll_safe(d, d1);
}

/* has the server moved the slow request onto the client's new port yet? */
static int
srv_on_rebound_port(void)
{
	lws_peer_entry_t e;

	return srv_slow && !lws_peer_effective(srv_slow, &e) &&
	       port_of(&e.sa46) == nat_out_port[nat_rebound];
}

/*
 * Polled from the release until the server is on the new path, or
 * PQ_PROBE_SOON_US has gone by.  The server's slow request waits for it, so
 * it is still there to ask.
 */
static void
pq_probe_check(lws_sorted_usec_list_t *sul)
{
	int moved = srv_on_rebound_port();

	if (!moved && srv_slow &&
	    lws_now_usecs() - nat_released < PQ_PROBE_SOON_US) {
		lws_sul_schedule(cx, 0, sul, pq_probe_check,
				 10 * LWS_US_PER_MS);
		return;
	}

	check(moved, "server: the late answer to its challenge validated "
		     "the new path");
	probe_checked = 1;
	if (srv_slow)
		lws_callback_on_writable(srv_slow);
}

/*
 * The slow probe phase's hold is over: the client's held datagrams, its
 * PATH_RESPONSE among them, go to the server in the order they came
 */
static void
pq_nat_release(lws_sorted_usec_list_t *sul)
{
	lws_sockaddr46 srv;

	(void)sul;

	nat_holding = 0;

	lwsl_user("  the server sent %d datagrams, %u bytes, to the new port "
		  "on the strength of %u bytes from it\n", nat_probe_dgrams,
		  (unsigned int)nat_probe_bytes,
		  (unsigned int)nat_rebound_first_len);

	/* RFC 9000 9.3.1: never more than 3x what the address sent */
	check(nat_probe_dgrams >= 1 &&
	      nat_probe_bytes <= 3 * nat_rebound_first_len,
	      "server: the probe kept within its allowance");

	/* or the probe wasn't held up by its allowance, as meant */
	if (nat_rebound_first_len <= PQ_PROBE_SMALL_MAX)
		check(nat_probe_dgrams == 1, "server: the probe spent its "
					     "allowance on its first challenge");
	else
		lwsl_user("  the first datagram had room for resends: the "
			  "probe's wait for its answer is not tested\n");
	check(!srv_on_rebound_port(), "server: the new path waited for its "
				      "answer");

	if (!nat_srv(&srv))
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&nat_held_owner)) {
			struct nat_held *h = lws_container_of(d,
						struct nat_held, list);

			nat_sendto(nat_out[nat_rebound], &h[1], h->len, &srv);
		} lws_end_foreach_dll(d);
	nat_held_drop();

	nat_released = lws_now_usecs();
	lws_sul_schedule(cx, 0, &sul_probe_check, pq_probe_check, 1);
}

static int
callback_nat(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	lws_sockaddr46 srv;

	if (reason != LWS_CALLBACK_RAW_RX || !lws_get_udp(wsi))
		return 0;

	if (wsi == nat_in) {
		const lws_sockaddr46 *from = &lws_get_udp(wsi)->sa46;
		struct lws *out = nat_out[nat_cur];

		/*
		 * The NAT serves the phase's own client: an earlier phase's
		 * connection, still up, would otherwise follow its rebinding.
		 * The phase's client is whoever sends the first long header
		 * packet, its first Initial: the earlier connections are past
		 * their handshakes and send only short headers, eg, acks or
		 * their close, which can come before the new client's first
		 * Initial and must not be taken for it.
		 */
		if (!nat_client.sa4.sin_family) {
			if (!len || (*(const uint8_t *)in & 0xc0) != 0xc0)
				return 0;
		} else
			if (lws_sa46_compare_ads(from, &nat_client) ||
			    port_of(from) != port_of(&nat_client))
				return 0;
		nat_client = *from;
		if (nat_srv(&srv))
			return 0;

		/*
		 * In the slow probe phase, the first datagram from the new
		 * port goes at once, and starts the server's probe; what
		 * follows it, the answer to the probe among it, is held
		 */
		if (phase == PQ_PHASE_SLOW_PROBE && nat_cur == nat_rebound) {
			if (!nat_rebound_tx++) {
				nat_rebound_first_len = len;
				nat_holding = 1;
				lws_sul_schedule(cx, 0, &sul_nat_release,
						 pq_nat_release,
						 PQ_PROBE_HOLD_US);
			} else if (nat_holding) {
				struct nat_held *h = malloc(sizeof(*h) +
							    len);

				if (!h)
					return 0;
				memset(&h->list, 0, sizeof(h->list));
				h->len = len;
				memcpy(&h[1], in, len);
				lws_dll2_add_tail(&h->list, &nat_held_owner);

				return 0;
			}
		}
		/*
		 * In the split phase, the client's long header packets after
		 * its first Initial, its Handshake packets among them, leave
		 * from another port
		 */
		if (phase == PQ_PHASE_SPLIT && len &&
		    (((const uint8_t *)in)[0] & 0x80) && nat_long_headers++)
			out = nat_out[3];
		nat_sendto(out, in, len, &srv);
		return 0;
	}

	/* a rebinding NAT has forgotten the old mapping */
	if (wsi == nat_out[nat_cur]) {
		if (nat_holding) {
			/* before its answer, only its probe can come here */
			nat_probe_dgrams++;
			nat_probe_bytes += len;
		}
		nat_sendto(nat_in, in, len, &nat_client);
	}

	(void)user;

	return 0;
}

/* ------------------------------------------------------------- client */

/*
 * A phase's client ended, answered (ok) or not.  Most are to be answered
 * within their phase, but those over a limit must not be, and the held one
 * only once the release phase lets the server answer it.
 */
static void
pq_client_done(int ph, int ok, const char *why)
{
	if (!cli[ph])
		return; /* it already ended */
	cli[ph] = NULL;

	switch (ph) {
#if defined(LWS_WITH_PEER_LIMITS)
	case PQ_PHASE_HOST:
		check(!ok && refused_host == 1 && !refused_unproven,
		      "client: refused, its host at its limit, once validated");
		if (ok || refused_host != 1 || refused_unproven)
			lwsl_err("        answered %d, refusals: %d for the "
				 "host, %d unproven\n", ok, refused_host,
				 refused_unproven);
		pq_phase_end(NULL);
		return;

	case PQ_PHASE_UNPROVEN:
		check(!ok && refused_unproven >= 1 && refused_host == 1,
		      "client: its unvalidated Initial was refused for the "
		      "unproven budget");
		if (ok || !refused_unproven || refused_host != 1)
			lwsl_err("        answered %d, refusals: %d for the "
				 "host, %d unproven\n", ok, refused_host,
				 refused_unproven);
		pq_phase_end(NULL);
		return;

	case PQ_PHASE_HOLD:
		if (phase != PQ_PHASE_RELEASE) {
			check(0, "client: the held request ended before its "
				 "release");
			return;
		}
		break;
#endif
	default:
		break;
	}

	if (!ok) {
		pq_phase_end(why);
		return;
	}

	check_str(body[ph], ph == PQ_PHASE_MIGRATE ||
			    ph == PQ_PHASE_SLOW_PROBE ? PQ_SLOW_1 PQ_SLOW_2 :
							"ok",
		  "client: the whole answer arrived");
	pq_phase_end(NULL);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	int ph = (int)(intptr_t)lws_get_opaque_user_data(wsi) - 1;
	char buf[LWS_PRE + 1024], *px;
	int alen;

	if (ph < 0 || ph >= PQ_PHASE_COUNT)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {
	case LWS_CALLBACK_CONNECTING: {
		char hk[LWS_HOST_KEY_LEN];

		/* nothing has answered from where we dial yet */
		one_socket_entry(wsi, LWS_PEER_CRED_HEARSAY, 0,
				 "client, dialling");
		/* so nothing may be keyed on its address */
		check_str(lws_get_peer_host_key(wsi, hk, sizeof(hk)),
			  LWS_HOST_KEY_UNPROVEN,
			  "client, dialling: the host key is the unproven one");
		break;
	}

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (ph == PQ_PHASE_LEVELS)
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
		if ((ph == PQ_PHASE_MIGRATE || ph == PQ_PHASE_SLOW_PROBE) &&
		    nat_cur == nat_first) {
			/* the first half is here: the NAT rebinds */
			lwsl_user("  NAT rebinding to a new port\n");
			nat_cur = nat_rebound;
		}
		if (body_len[ph] + len < sizeof(body[ph])) {
			memcpy(body[ph] + body_len[ph], in, len);
			body_len[ph] += len;
			body[ph][body_len[ph]] = '\0';
		}
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		pq_client_done(ph, 1, NULL);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		pq_client_done(ph, 0, in ? (const char *)in :
					   "connection error");
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		pq_client_done(ph, 0, "closed before the answer was complete");
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
	i.vhost			= vh_cli[phase];
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
	i.pwsi			= &cli[phase];

	return !lws_client_connect_via_info(&i);
}

#if defined(LWS_WITH_PEER_LIMITS)

/* ------------------------------------------------------------- budget */

static void
pq_kill_unproven(lws_sorted_usec_list_t *sul)
{
	(void)sul;

	if (cli[PQ_PHASE_UNPROVEN])
		lws_set_timeout(cli[PQ_PHASE_UNPROVEN], PENDING_TIMEOUT_USER_OK,
				LWS_TO_KILL_ASYNC);
}

static int
pq_pl_notify(struct lws_context *ctx, lws_sockfd_type sockfd,
	     lws_sockaddr46 *sa46)
{
	(void)ctx;
	(void)sockfd;

	if (sa46->sa4.sin_family) {
		refused_host++;
		return 0;
	}

	/* a refusal for the unproven budget names no address */
	if (!refused_unproven++ && phase == PQ_PHASE_UNPROVEN)
		/* it would try again: we have seen what we came for */
		lws_sul_schedule(cx, 0, &sul_kill, pq_kill_unproven, 1);

	return 0;
}

/*
 * A QUIC Initial that will never decrypt, padded to the 1200 bytes a server
 * insists on: the server takes it for a new client, whose address is never
 * validated, and keeps it until its handshake times out
 */
static int
pq_send_lone_initial(void)
{
	uint8_t d[1200];
	lws_sockaddr46 srv;
	size_t plen = sizeof(d) - 26;

	if (lws_get_random(cx, d, sizeof(d)) != sizeof(d))
		return 1;

	d[0]	= 0xc3;			/* long header, Initial, 4-byte pn */
	d[1]	= 0;			/* version 1 */
	d[2]	= 0;
	d[3]	= 0;
	d[4]	= 1;
	d[5]	= 8;			/* random DCID */
	d[14]	= 8;			/* random SCID */
	d[23]	= 0;			/* no token */
	d[24]	= (uint8_t)(0x40 | (plen >> 8)); /* 2-byte length */
	d[25]	= (uint8_t)(plen & 0xff);

	memset(&srv, 0, sizeof(srv));
	if (lws_sa46_parse_numeric_address("127.0.0.1", &srv))
		return 1;
	sa46_sockport(&srv, htons((uint16_t)port_srv));

	return sendto(lws_get_socket_fd(raw_udp), (const char *)d,
		      LWS_POSIX_LENGTH_CAST(sizeof(d)), 0, sa46_sockaddr(&srv),
		      sa46_socklen(&srv)) != (int)sizeof(d);
}

/* the lone Initial had its chance to be refused: was it let in? */
static void
pq_settled(lws_sorted_usec_list_t *sul)
{
	(void)sul;

	check(!refused_unproven, "server: the lone unvalidated Initial was "
				 "let in, the held client counts elsewhere");

	if (pq_get(port_srv, "/"))
		pq_phase_end("connect failed");
}
#endif

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

	if (phase == phase_last) {
		/* this context's part is done */
		finished = 1;
		lws_cancel_service(cx);
		return;
	}
	phase++;

	lwsl_user("%s:\n", phase_names[phase]);
	phase_done	= 0;
	lws_sul_schedule(cx, 0, &sul_phase, pq_deadline, PQ_PHASE_US);

	switch (phase) {
	case PQ_PHASE_LEVELS:
	case PQ_PHASE_HOST:
		r = pq_get(port_srv, "/");
		break;
	case PQ_PHASE_MIGRATE:
		nat_first	= 0;
		nat_rebound	= 1;
		nat_cur		= nat_first;
		memset(&nat_client, 0, sizeof(nat_client));
		r = pq_get(port_nat, "/slow");
		break;
	case PQ_PHASE_SLOW_PROBE:
		nat_first	= 4;
		nat_rebound	= 5;
		nat_cur		= nat_first;
		memset(&nat_client, 0, sizeof(nat_client));
		r = pq_get(port_nat, "/slow");
		break;
	case PQ_PHASE_SPLIT:
		nat_cur = 2;
		memset(&nat_client, 0, sizeof(nat_client));
		r = pq_get(port_nat, "/split");
		break;
#if defined(LWS_WITH_PEER_LIMITS)
	case PQ_PHASE_HOLD:
		r = pq_get(port_srv, "/hold");
		break;
	case PQ_PHASE_UNPROVEN:
		r = pq_send_lone_initial();
		if (!r)
			lws_sul_schedule(cx, 0, &sul_settle, pq_settled,
					 PQ_SETTLE_US);
		break;
	case PQ_PHASE_RELEASE:
		if (!hold_wsi || !cli[PQ_PHASE_HOLD]) {
			pq_phase_end("the held request is gone");
			return;
		}
		/* answer the held request now: the client ends the phase */
		{
			struct pss_srv *pss = (struct pss_srv *)
					lws_wsi_user(hold_wsi);

			pss->held = 0;
			lws_callback_on_writable(hold_wsi);
		}
		break;
#endif
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

/*
 * Run the phases first..last in a context of their own: the server, a client
 * vhost for each phase, and the udp sockets the phases need
 */
static int
pq_run(const struct lws_context_creation_info *ci, int first, int last)
{
	struct lws_context_creation_info info = *ci;
	char name[16];
	int m = 0, n;

	phase		= first - 1;
	phase_last	= last;
	finished	= 0;

#if defined(LWS_WITH_PEER_LIMITS)
	if (first == PQ_PHASE_HOLD) {
		/* one connection per host, and one still proving its address */
		info.ip_limit_wsi	= 1;
		info.unproven_limit_wsi	= 1;
		info.pl_notify_cb	= pq_pl_notify;
	}
#endif

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
	if (first == PQ_PHASE_LEVELS)
		info.log_filepath	= alog;
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
	for (n = first; n <= last; n++) {
		lws_snprintf(name, sizeof(name), "pq-cli-%d", n);
		info.vhost_name		= name;
		vh_cli[n] = lws_create_vhost(cx, &info);
		if (!vh_cli[n])
			goto bail;
	}

	if (first == PQ_PHASE_LEVELS) {
		/* the NAT's sides, on ports the kernel picks */
		nat_in = lws_create_adopt_udp(vh_cli[first], "127.0.0.1", 0,
					      LWS_CAUDP_BIND, "pq-nat", NULL,
					      NULL, NULL, NULL, NULL);
		port_nat = nat_in ? (int)local_port(nat_in) : 0;
		if (!port_nat)
			goto bail;
		for (n = 0; n < (int)LWS_ARRAY_SIZE(nat_out); n++) {
			nat_out[n] = lws_create_adopt_udp(vh_cli[first],
						"127.0.0.1", 0, LWS_CAUDP_BIND,
						"pq-nat", NULL, NULL, NULL,
						NULL, NULL);
			nat_out_port[n] = nat_out[n] ?
						local_port(nat_out[n]) : 0;
			if (!nat_out_port[n])
				goto bail;
		}
	}
#if defined(LWS_WITH_PEER_LIMITS)
	if (first == PQ_PHASE_HOLD) {
		raw_udp = lws_create_adopt_udp(vh_cli[first], "127.0.0.1", 0,
					       LWS_CAUDP_BIND, "pq-nat", NULL,
					       NULL, NULL, NULL, NULL);
		if (!raw_udp)
			goto bail;
	}
#endif

	lws_sul_schedule(cx, 0, &sul_phase, pq_next, 1);

	while (m >= 0 && !finished)
		m = lws_service(cx, 0);

	if (!finished) {
		lwsl_err("service loop ended early\n");
		fails++;
	}

	lws_sul_cancel(&sul_phase);
	lws_sul_cancel(&sul_nat_release);
	lws_sul_cancel(&sul_probe_check);
	nat_held_drop();
#if defined(LWS_WITH_PEER_LIMITS)
	lws_sul_cancel(&sul_settle);
	lws_sul_cancel(&sul_kill);
#endif
	lws_context_destroy(cx);

	return 0;

bail:
	lwsl_err("setup failed\n");
	lws_context_destroy(cx);

	return 1;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;

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

	/* servers and clients in one process: don't budget fds */
	info.fd_limit_per_thread	= 0;
	info.options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
					  LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	if (pq_run(&info, PQ_PHASE_LEVELS, PQ_PHASE_SPLIT))
		return 1;

#if defined(LWS_WITH_ACCESS_LOG)
	/* the vhost flushed and closed it */
	if (alog)
		pq_access_log();
#endif

#if defined(LWS_WITH_PEER_LIMITS)
	if (pq_run(&info, PQ_PHASE_HOLD, PQ_PHASE_RELEASE))
		return 1;
#endif

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
