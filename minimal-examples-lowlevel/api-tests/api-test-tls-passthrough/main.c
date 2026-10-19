/*
 * lws-api-test-tls-passthrough
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * End to end test of tls passthrough and PROXY v2, all in one process:
 *
 *  - "backend" terminates tls itself, and trusts 127.0.0.1 (where the front
 *    connects from) to send a PROXY v2 header first.  Its http answer says
 *    who it believes the client is, from lws_get_peer_simple();
 *
 *  - "front.test" terminates tls on the front port, and answers "front";
 *
 *  - "pass.test", on the same front port, has no certificate: its
 *    connections are passed to the backend undecrypted, with a PROXY v2
 *    header naming the client;
 *
 *  - "capture" is a raw listener, that a tls client is pointed at only to
 *    record a real ClientHello naming pass.test, for the raw scenarios.
 *
 * In order, it checks:
 *
 *  - a client naming front.test is served by the front itself;
 *
 *  - a client naming pass.test is served by the backend, through the front,
 *    and the backend sees the real client: where the build has IPv6, the
 *    client dials the front on ::1 while the front reaches the backend from
 *    127.0.0.1, so ::1 can only have come from the PROXY v2 header;
 *
 *  - the recorded ClientHello, split into three tls records sent as three
 *    tcp writes a little apart, is still seen as naming pass.test and passed
 *    through: the backend answers it with a ServerHello;
 *
 *  - half of the recorded ClientHello, the rest sent only a second later:
 *    while the front waits for the rest it must not keep looking at the half
 *    it has, which kept the event loop turning every few ms for as long as a
 *    peer liked, and it must still pass the connection through once the rest
 *    comes;
 *
 *  - straight to the backend from 127.0.0.1, which it trusts, without a
 *    PROXY v2 header, the connection is dropped unanswered;
 *
 *  - straight to the backend from ::1, which it does not trust, a forged
 *    PROXY v2 header is not believed, just tls garbage: no ServerHello;
 *
 *  - a forged PROXY v2 header sent to the front ahead of the ClientHello is
 *    not passed through at all: the backend never even sees a connection.
 *
 * and where the build has h3, the same over QUIC, where the front relays the
 * datagrams of a passed through name to the backend's QUIC, each after a
 * PROXY v2 header, and the backend's back the same way:
 *
 *  - an h3 client naming front.test is served by the front;
 *
 *  - an h3 client naming pass.test is served by the backend, which sees the
 *    real client;
 *
 *  - an h3 client reaching the front through a little udp "NAT" in the test,
 *    which partway through a slow response moves its side to a new port, as
 *    a NAT rebinding does: the front must follow the flow by its connection
 *    ID, the backend's QUIC validate the new path, and the rest of the
 *    response reach the client through the new port;
 *
 *  - an h3 client through a second NAT, while during its slow response a
 *    spoofer on 127.0.0.1, which the backend trusts, but from another port
 *    than the front's, sends the backend datagrams with PROXY v2 headers:
 *    some claiming to carry the live client, and a flood claiming thousands
 *    of others.  The backend's QUIC proved the client's relay in its
 *    handshake, so none of it may move where the backend answers the
 *    client, or push its relay out: the rest of the response must still
 *    reach the client through the front, and nothing the backend sends
 *    reach the spoofer.  The backend sees the client as a relayed claim,
 *    and the front's socket below it, both proven.
 *
 * Each NAT only passes back what comes from the front, so an answer the
 * backend sends anywhere else is lost, as it would be in real life.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

enum {
	ST_TERMINATED,
	ST_PASSTHROUGH,
	ST_CAPTURE,
	ST_MULTIRECORD,
	ST_PARTIAL_IDLE,
	ST_TRUSTED_NO_HEADER,
	ST_UNTRUSTED_FORGED,
	ST_FRONT_FORGED,
	ST_H3_TERMINATED,
	ST_H3_PASSTHROUGH,
	ST_H3_MIGRATE,
	ST_H3_SPOOF,
	ST_DONE
};

static const char * const step_names[] = {
	"a client naming front.test is served by the front",
	"a client naming pass.test is served by the backend, which sees "
		"the real client",
	"a real ClientHello for pass.test is recorded",
	"a ClientHello in three records and three writes is passed through",
	"waiting a second for the rest of a ClientHello costs the front only "
		"a few looks at it",
	"a trusted peer without a PROXY v2 header is dropped",
	"a forged PROXY v2 header from an untrusted peer is not believed",
	"a forged PROXY v2 header sent to the front is not passed through",
	"an h3 client naming front.test is served by the front",
	"an h3 client naming pass.test is served by the backend, which sees "
		"the real client",
	"an h3 flow through a NAT that rebinds midway is followed to the end",
	"spoofed relay datagrams from a trusted address neither move nor "
		"evict a proven relayed h3 client",
};

/* the slow response, in two halves either side of the NAT rebinding */
#define SLOW_1	"first half|"
#define SLOW_2	"second half"

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_step, sul_send;
static int port_front, port_back, port_capture, port_nat, port_nat2, step,
	   tests, fail, done;
static int backend_accepts, accepts_at_step;

/* who the backend's last slow request said its peer was, top first */
static lws_peer_entry_t backend_stack[LWS_PEER_WALK_MAX];
static int backend_stack_count;

static const char *certs = ".";

/* what the current step's client saw */
static char body[256];
static size_t body_len;
static int got_server_hello, rx_bytes, step_closed;

/* the ClientHello the capture listener recorded */
static uint8_t hello[16384];
static size_t hello_len;

/* what the raw client sends, in pieces, this far apart */
static uint8_t tx[16384 + 64];
static size_t tx_len, tx_pos, tx_piece;
static lws_usec_t tx_gap;

#define PT_GAP_US		(30 * LWS_US_PER_MS)
#define PT_IDLE_GAP_US		LWS_US_PER_SEC

/*
 * Times the event loop slept and woke, and how many of those there were while
 * the front waited for the rest of a ClientHello.  A turn of the loop that
 * took at least PT_SLEPT_US slept in poll() until something woke it: the
 * turns that did not are the loop polling without waiting through the last
 * millisecond before a timer, which only says how fast this machine is.
 * Waiting properly for a second wakes ten or so times; looking again every
 * 10ms wakes a hundred.
 */
static unsigned int wakes, wakes_at_piece, wakes_waited;
#define PT_SLEPT_US		LWS_US_PER_MS
#define PT_IDLE_MAX_WAKES	40

static void
expect(const char *what, int ok)
{
	tests++;
	if (!ok)
		fail++;
	lwsl_user("  %s: %s\n", ok ? "PASS" : "FAIL", what);
}

/* ------------------------------------------------------------- servers */

/*
 * Both servers answer with who they are and who they believe the client is.
 * The headers go now, the body from WRITEABLE: on h2 and h3 they are
 * different frames.  The backend may instead give a slow answer in two
 * halves, for the h3 migration step.
 */
struct pss_srv {
	lws_sorted_usec_list_t	sul;
	struct lws		*wsi;
	char			resp[LWS_PRE + 128];
	size_t			resp_len;
	int			slow;	/* 1: first half to go, 2: second */
	int			due;	/* the second half's time has come */
};

static int
answer(struct lws *wsi, struct pss_srv *pss, const char *who)
{
	uint8_t buf[LWS_PRE + 512], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	char peer[64];

	lws_get_peer_simple(wsi, peer, sizeof(peer));
	pss->wsi = wsi;
	pss->resp_len = (size_t)lws_snprintf(&pss->resp[LWS_PRE],
				sizeof(pss->resp) - LWS_PRE, "%s %s", who, peer);

	if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/plain",
					(lws_filepos_t)pss->resp_len, &p, end) ||
	    lws_finalize_write_http_header(wsi, start, &p, end))
		return -1;

	lws_callback_on_writable(wsi);

	return 0;
}

static int
answer_writeable(struct lws *wsi, struct pss_srv *pss)
{
	if (!pss->resp_len)
		return 0;

	if (lws_write(wsi, (uint8_t *)&pss->resp[LWS_PRE], pss->resp_len,
		      LWS_WRITE_HTTP_FINAL) < 0)
		return -1;
	pss->resp_len = 0;

	return lws_http_transaction_completed(wsi) ? -1 : 0;
}

static int
slow_hold(void);

static void
slow_next_cb(lws_sorted_usec_list_t *sul)
{
	struct pss_srv *pss = lws_container_of(sul, struct pss_srv, sul);

	if (slow_hold()) {
		/* not yet: the spoofing step's flood is still going */
		lws_sul_schedule(lws_get_context(pss->wsi), 0, &pss->sul,
				 slow_next_cb, 100 * LWS_US_PER_MS);
		return;
	}

	pss->due = 1;
	lws_callback_on_writable(pss->wsi);
}

static int
callback_backend(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t buf[LWS_PRE + 256], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];

	switch (reason) {
	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
		backend_accepts++;
		break;
	case LWS_CALLBACK_HTTP:
		if (!in || !strstr((const char *)in, "slow"))
			return answer(wsi, pss, "backend");

		/* the first half now, the second a while later */
		backend_stack_count = lws_peer_walk(wsi, backend_stack,
					(int)LWS_ARRAY_SIZE(backend_stack));
		pss->wsi = wsi;
		pss->slow = 1;
		pss->due = 0;
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
				"text/plain", (lws_filepos_t)
				(strlen(SLOW_1) + strlen(SLOW_2)), &p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss || !pss->wsi)
			break;
		if (!pss->slow)
			return answer_writeable(wsi, pss);
		if (pss->slow == 1) {
			memcpy(start, SLOW_1, strlen(SLOW_1));
			if (lws_write(wsi, start, strlen(SLOW_1),
				      LWS_WRITE_HTTP) < 0)
				return -1;
			pss->slow = 2;
			lws_sul_schedule(lws_get_context(wsi), 0, &pss->sul,
					 slow_next_cb, 1500 * LWS_US_PER_MS);
			break;
		}
		/* h3 asks for WRITEABLE for its own reasons as well */
		if (pss->slow == 2 && pss->due) {
			memcpy(start, SLOW_2, strlen(SLOW_2));
			if (lws_write(wsi, start, strlen(SLOW_2),
				      LWS_WRITE_HTTP_FINAL) < 0)
				return -1;
			pss->slow = 0;
			if (lws_http_transaction_completed(wsi))
				return -1;
		}
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

#if defined(LWS_WITH_UDP) && defined(LWS_WITH_HTTP3)
#define TPT_QUIC

/*
 * A "NAT": the client sends to in, which passes it on to the front from
 * out[cur], and what the front sends back there goes back to the client.
 * Moving cur is a NAT rebinding, as the front sees it.  Only what comes from
 * the front's address and port goes back: anything else is a stray.
 */
typedef struct tpt_nat {
	struct lws		*in, *out[2];
	lws_sockaddr46		client;
	int			cur, rx_after_rebind, strays;
} tpt_nat_t;

/* the migration step's, and the spoofing step's */
static tpt_nat_t nat, nat2;

static void
nat_sendto(struct lws *wsi, const void *buf, size_t len,
	   const lws_sockaddr46 *to)
{
	if (wsi && to->sa4.sin_family)
		(void)sendto(lws_get_socket_fd(wsi), (const char *)buf,
			     LWS_POSIX_LENGTH_CAST(len), 0, sa46_sockaddr(to),
			     sa46_socklen(to));
}

static int
loopback_port(lws_sockaddr46 *sa46, int port)
{
	memset(sa46, 0, sizeof(*sa46));
	if (lws_sa46_parse_numeric_address("127.0.0.1", sa46))
		return 1;
	sa46_sockport(sa46, htons((uint16_t)port));

	return 0;
}

static int
port_of(const lws_sockaddr46 *sa46)
{
#if defined(LWS_WITH_IPV6)
	if (sa46->sa4.sin_family == AF_INET6)
		return ntohs(sa46->sa6.sin6_port);
#endif

	return ntohs(sa46->sa4.sin_port);
}

/* the port a udp wsi of ours is bound to */
static int
bound_port(struct lws *wsi)
{
	lws_sockaddr46 sa46;
	socklen_t sl = sizeof(sa46);

	if (getsockname(lws_get_socket_fd(wsi), sa46_sockaddr(&sa46), &sl))
		return 0;

	return port_of(&sa46);
}

static void
nat_rx(tpt_nat_t *t, struct lws *wsi, const void *in, size_t len)
{
	lws_sockaddr46 front;

	if (loopback_port(&front, port_front))
		return;

	if (wsi == t->in) {
		t->client = lws_get_udp(wsi)->sa46;
		nat_sendto(t->out[t->cur], in, len, &front);
		return;
	}

	/* a rebinding NAT has forgotten the old mapping */
	if (wsi != t->out[t->cur])
		return;

	/* only the front's answers are let back in */
	if (lws_sa46_compare_ads(&lws_get_udp(wsi)->sa46, &front) ||
	    lws_get_udp(wsi)->sa46.sa4.sin_port != front.sa4.sin_port) {
		t->strays++;
		return;
	}

	if (t->cur == 1)
		t->rx_after_rebind++;
	nat_sendto(t->in, in, len, &t->client);
}

/*
 * The spoofer: a udp socket on 127.0.0.1, which the backend trusts to relay
 * QUIC, but not the front's socket
 */
static struct lws *spoofer;
static lws_sorted_usec_list_t sul_spoof;
static int spoofer_rx, spoof_sent, flood_sent;

#define TPT_SPOOF_US		(10 * LWS_US_PER_MS)
#define TPT_FLOOD_TOTAL		6000
#define TPT_FLOOD_BATCH		128

static int
slow_hold(void)
{
	return step == ST_H3_SPOOF && flood_sent < TPT_FLOOD_TOTAL;
}

static int
callback_nat(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	(void)user;

	if (reason != LWS_CALLBACK_RAW_RX || !lws_get_udp(wsi))
		return 0;

	if (wsi == spoofer) {
		/* the backend answered the spoofer: it believed it */
		spoofer_rx++;
		return 0;
	}

	nat_rx(wsi == nat2.in || wsi == nat2.out[0] || wsi == nat2.out[1] ?
	       &nat2 : &nat, wsi, in, len);

	return 0;
}

/*
 * A relayed datagram claiming to be from client: a PROXY v2 header naming it,
 * then a short header QUIC packet for a connection ID nobody has, which the
 * backend's QUIC drops.  It is the header that is the attack.
 */
static void
spoof_one(const lws_sockaddr46 *client)
{
	uint8_t b[LWS_PROXY_V2_MAX + 64];
	lws_sockaddr46 back;
	lws_proxy_v2_t pv;
	int n;

	memset(&pv, 0, sizeof(pv));
	pv.dgram = 1;
	pv.src = *client;
	if (loopback_port(&pv.dst, port_front) ||
	    loopback_port(&back, port_back))
		return;

	n = lws_proxy_v2_render(&pv, b, sizeof(b));
	if (n < 0 || (size_t)n + 29 > sizeof(b))
		return;
	b[n] = 0x40;
	lws_get_random(context, &b[n + 1], 28);

	nat_sendto(spoofer, b, (size_t)n + 29, &back);
}

static void
spoof_cb(lws_sorted_usec_list_t *sul)
{
	lws_sockaddr46 claim;
	int n;

	/* the live client, as the front names it: its NAT's outside port */
	if (step != ST_H3_SPOOF ||
	    loopback_port(&claim, bound_port(nat2.out[0])))
		return;
	spoof_one(&claim);
	spoof_sent++;

	/* and a flood of claims for clients the backend never saw */
	for (n = 0; n < TPT_FLOOD_BATCH && flood_sent < TPT_FLOOD_TOTAL; n++) {
		char ads[32];

		lws_snprintf(ads, sizeof(ads), "198.18.%d.%d",
			     (flood_sent >> 8) & 0xff, flood_sent & 0xff);
		memset(&claim, 0, sizeof(claim));
		if (lws_sa46_parse_numeric_address(ads, &claim))
			break;
		sa46_sockport(&claim, htons((uint16_t)(40000 + flood_sent)));
		spoof_one(&claim);
		flood_sent++;
	}

	lws_sul_schedule(context, 0, sul, spoof_cb, TPT_SPOOF_US);
}
#else
static int
slow_hold(void)
{
	return 0;
}
#endif

static int
callback_front(struct lws *wsi, enum lws_callback_reasons reason,
	       void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;

	if (reason == LWS_CALLBACK_HTTP)
		return answer(wsi, pss, "front");
	if (reason == LWS_CALLBACK_HTTP_WRITEABLE && pss)
		return answer_writeable(wsi, pss);

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
step_next(void);

static int
callback_capture(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		if (hello_len + len > sizeof(hello))
			return -1;
		memcpy(hello + hello_len, in, len);
		hello_len += len;
		/* the first record whole is all we want */
		if (hello_len >= 5 &&
		    hello_len >= 5 + (((size_t)hello[3] << 8) | hello[4]))
			return -1;
		break;
	default:
		break;
	}

	return 0;
}

/* ------------------------------------------------------------- clients */

static void
send_piece(lws_sorted_usec_list_t *sul);

/* the current step's client connection: the earlier ones are done with */
static struct lws *step_wsi;

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	char *px;
	int alen;

	if (wsi != step_wsi)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {

	/* the https steps */

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_notice("%s: step %d: connection error: %s\n", __func__,
			    step, in ? (const char *)in : "?");
		step_closed = 1;
		lws_sul_schedule(context, 0, &sul_step, (sul_cb_t)step_next, 1);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP: {
		char buf[LWS_PRE + 1024];

		px = buf + LWS_PRE;
		alen = (int)sizeof(buf) - LWS_PRE;
		if (lws_http_client_read(wsi, &px, &alen) < 0)
			return -1;
		return 0;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
#if defined(TPT_QUIC)
		if (step == ST_H3_MIGRATE && !nat.cur) {
			/* the first half is here: the NAT rebinds */
			lwsl_user("  NAT rebinding to a new port\n");
			nat.cur = 1;
		}
		if (step == ST_H3_SPOOF && !spoof_sent) {
			/*
			 * The first half is here, the backend's QUIC proved
			 * where its client is: spoof until the second half
			 * comes, so the last word before it is the spoofer's
			 */
			lwsl_user("  spoofing\n");
			spoof_cb(&sul_spoof);
		}
#endif
		if (body_len + len < sizeof(body)) {
			memcpy(body + body_len, in, len);
			body_len += len;
			body[body_len] = '\0';
		}
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!step_closed) {
			step_closed = 1;
			lws_sul_schedule(context, 0, &sul_step,
					 (sul_cb_t)step_next, 1);
		}
		break;

	/* the raw steps */

	case LWS_CALLBACK_RAW_CONNECTED:
		tx_pos = 0;
		lws_sul_schedule(context, 0, &sul_send, send_piece, 1);
		break;

	case LWS_CALLBACK_RAW_RX:
		if (!rx_bytes && len >= 1 && ((uint8_t *)in)[0] == 0x16)
			got_server_hello = 1;
		rx_bytes += (int)len;
		if (got_server_hello)
			/* that is the answer we were waiting for */
			return -1;
		break;

	case LWS_CALLBACK_RAW_WRITEABLE: {
		uint8_t buf[LWS_PRE + sizeof(tx)];
		size_t n = tx_piece;

		if (tx_pos + n > tx_len)
			n = tx_len - tx_pos;
		if (!n)
			break;
		if (tx_pos)
			/* the loop woke this often while we held back */
			wakes_waited = wakes - wakes_at_piece;
		memcpy(buf + LWS_PRE, tx + tx_pos, n);
		if (lws_write(wsi, buf + LWS_PRE, n, LWS_WRITE_RAW) < (int)n)
			return -1;
		tx_pos += n;
		wakes_at_piece = wakes;
		if (tx_pos < tx_len)
			/* the next piece a little later, as its own segment */
			lws_sul_schedule(context, 0, &sul_send, send_piece,
					 tx_gap);
		break;
	}

	case LWS_CALLBACK_RAW_CLOSE:
		lws_sul_cancel(&sul_send);
		if (!step_closed) {
			step_closed = 1;
			lws_sul_schedule(context, 0, &sul_step,
					 (sul_cb_t)step_next, 1);
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
send_piece(lws_sorted_usec_list_t *sul)
{
	(void)sul;
	if (step_wsi)
		lws_callback_on_writable(step_wsi);
}

static int
https_get(const char *address, int port, const char *host, const char *path,
	  const char *alpn)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= address;
	i.port			= port;
	i.host			= host;
	i.origin		= host;
	i.path			= path;
	i.method		= "GET";
	i.alpn			= alpn;
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK |
				  LCCSCF_ALLOW_INSECURE;
	i.protocol		= "cli";
	i.local_protocol_name	= "cli";
	i.pwsi			= &step_wsi;

	return !lws_client_connect_via_info(&i);
}

/* a raw connection that sends tx[] in pieces of piece bytes */
static int
raw_send(const char *address, int port, size_t piece)
{
	struct lws_client_connect_info i;

	tx_piece = piece;
	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= address;
	i.port			= port;
	i.host			= address;
	i.method		= "RAW";
	i.local_protocol_name	= "cli";
	i.pwsi			= &step_wsi;

	return !lws_client_connect_via_info(&i);
}

/* a forged PROXY v2 header claiming the client is 192.0.2.66, into tx */
static size_t
forged_header(void)
{
	lws_proxy_v2_t pv;
	int n;

	memset(&pv, 0, sizeof(pv));
	if (lws_sa46_parse_numeric_address("192.0.2.66", &pv.src) ||
	    lws_sa46_parse_numeric_address("192.0.2.1", &pv.dst))
		return 0;
	n = lws_proxy_v2_render(&pv, tx, sizeof(tx));

	return n > 0 ? (size_t)n : 0;
}

/* ------------------------------------------------------------- sequence */

static const char *
loopback6(void)
{
#if defined(LWS_WITH_IPV6)
	return "::1";
#else
	return "127.0.0.1";
#endif
}

/*
 * A step whose client is starved is failed after a while, not left to the
 * deadline: its connection may be kept alive for longer by its own retries
 */
static lws_sorted_usec_list_t sul_guard;
#define TPT_GUARD_US		(8 * LWS_US_PER_SEC)

static void
step_next(void);

static void
guard_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;
	lwsl_user("  step %d took too long\n", step);
	step_closed = 1;
	step_next();
}

#if defined(TPT_QUIC)
/* what the backend said about its slow request's peer, as expected? */
static int
spoof_stack_ok(void)
{
	char d[LWS_PEER_DESC_LEN];

	lws_peer_entries_describe(backend_stack, backend_stack_count, d,
				  sizeof(d), 0);
	lwsl_user("  the backend saw its client as %s\n", d);

	return backend_stack_count == 2 &&
	       backend_stack[0].kind == LWS_PEER_KIND_RELAY &&
	       backend_stack[0].cred >= LWS_PEER_CRED_ROUTABLE &&
	       port_of(&backend_stack[0].sa46) == bound_port(nat2.out[0]) &&
	       backend_stack[1].kind == LWS_PEER_KIND_SOCKET &&
	       backend_stack[1].cred >= LWS_PEER_CRED_ROUTABLE;
}
#endif

static void
step_start(void)
{
	size_t n, rl, part, pos;

	body_len = 0;
	body[0] = '\0';
	got_server_hello = 0;
	rx_bytes = 0;
	step_closed = 0;
	step_wsi = NULL;
	accepts_at_step = backend_accepts;
	tx_gap = PT_GAP_US;
	wakes_waited = 0;

	switch (step) {
	case ST_TERMINATED:
		if (https_get("127.0.0.1", port_front, "front.test", "/", "http/1.1"))
			goto fail;
		break;

	case ST_PASSTHROUGH:
		if (https_get(loopback6(), port_front, "pass.test", "/", "http/1.1"))
			goto fail;
		break;

	case ST_CAPTURE:
		/* it fails, the capture listener hangs up once it has it */
		if (https_get("127.0.0.1", port_capture, "pass.test", "/", "http/1.1"))
			goto fail;
		break;

	case ST_MULTIRECORD:
		/*
		 * The recorded ClientHello's handshake message, re-framed as
		 * three records, each sent as its own write
		 */
		rl = hello_len - 5;
		part = (rl + 2) / 3;
		tx_len = 0;
		for (pos = 0; pos < rl; pos += part) {
			n = rl - pos < part ? rl - pos : part;
			tx[tx_len++] = 0x16;
			tx[tx_len++] = hello[1];
			tx[tx_len++] = hello[2];
			tx[tx_len++] = (uint8_t)(n >> 8);
			tx[tx_len++] = (uint8_t)n;
			memcpy(tx + tx_len, hello + 5 + pos, n);
			tx_len += n;
		}
		if (raw_send("127.0.0.1", port_front, 5 + part))
			goto fail;
		break;

	case ST_PARTIAL_IDLE:
		/*
		 * Half the ClientHello's record, then nothing for a second:
		 * the front has to wait for the rest
		 */
		memcpy(tx, hello, hello_len);
		tx_len = hello_len;
		tx_gap = PT_IDLE_GAP_US;
		if (raw_send("127.0.0.1", port_front, (hello_len + 1) / 2))
			goto fail;
		break;

	case ST_TRUSTED_NO_HEADER:
		memcpy(tx, hello, hello_len);
		tx_len = hello_len;
		if (raw_send("127.0.0.1", port_back, tx_len))
			goto fail;
		break;

	case ST_UNTRUSTED_FORGED:
	case ST_FRONT_FORGED:
		n = forged_header();
		if (!n)
			goto fail;
		memcpy(tx + n, hello, hello_len);
		tx_len = n + hello_len;
		if (raw_send(step == ST_FRONT_FORGED ? "127.0.0.1" : loopback6(),
			     step == ST_FRONT_FORGED ? port_front : port_back,
			     tx_len))
			goto fail;
		break;

	case ST_H3_TERMINATED:
		if (https_get("127.0.0.1", port_front, "front.test", "/", "h3"))
			goto fail;
		break;

	case ST_H3_PASSTHROUGH:
		if (https_get(loopback6(), port_front, "pass.test", "/", "h3"))
			goto fail;
		break;

	case ST_H3_MIGRATE:
		if (https_get("127.0.0.1", port_nat, "pass.test", "/slow", "h3"))
			goto fail;
		break;

	case ST_H3_SPOOF:
		backend_stack_count = 0;
		lws_sul_schedule(context, 0, &sul_guard, guard_cb,
				 TPT_GUARD_US);
		if (https_get("127.0.0.1", port_nat2, "pass.test", "/slow", "h3"))
			goto fail;
		break;
	}

	return;

fail:
	expect(step_names[step], 0);
	done = 1;
	lws_cancel_service(context);
}

static void
step_next(void)
{
	int ok = 0;

	if (done || step < 0 || step >= ST_DONE)
		/* a late close or error after the last step finished */
		return;

	switch (step) {
	case ST_TERMINATED:
		ok = !strncmp(body, "front ", 6);
		break;
	case ST_PASSTHROUGH:
		lwsl_user("  passed through, the backend said '%s'\n", body);
		ok = !strncmp(body, "backend ", 8) &&
		     !strcmp(body + 8, loopback6());
		break;
	case ST_CAPTURE:
		ok = hello_len >= 5 && hello[0] == 0x16 &&
		     hello_len >= 5 + (((size_t)hello[3] << 8) | hello[4]);
		/* only the first record */
		if (ok)
			hello_len = 5 + (((size_t)hello[3] << 8) | hello[4]);
		break;
	case ST_MULTIRECORD:
		/*
		 * The front's own tls would answer with a ServerHello too, if
		 * the name were not found: it must be the backend's
		 */
		ok = got_server_hello && backend_accepts > accepts_at_step;
		break;
	case ST_PARTIAL_IDLE:
		lwsl_user("  the event loop woke %u times while the front "
			  "waited\n", wakes_waited);
		ok = got_server_hello && backend_accepts > accepts_at_step &&
		     wakes_waited && wakes_waited < PT_IDLE_MAX_WAKES;
		break;
	case ST_TRUSTED_NO_HEADER:
		ok = !got_server_hello && !rx_bytes;
		break;
	case ST_UNTRUSTED_FORGED:
		ok = !got_server_hello;
		break;
	case ST_FRONT_FORGED:
		ok = !got_server_hello && backend_accepts == accepts_at_step;
		break;
	case ST_H3_TERMINATED:
		ok = !strncmp(body, "front ", 6);
		break;
	case ST_H3_PASSTHROUGH:
		lwsl_user("  over h3, the backend said '%s'\n", body);
		ok = !strncmp(body, "backend ", 8) &&
		     !strcmp(body + 8, loopback6());
		break;
#if defined(TPT_QUIC)
	case ST_H3_MIGRATE:
		lwsl_user("  through the NAT: '%s', %d datagrams to the new "
			  "port\n", body, nat.rx_after_rebind);
		ok = !strcmp(body, SLOW_1 SLOW_2) && nat.rx_after_rebind &&
		     !nat.strays;
		break;
	case ST_H3_SPOOF:
		lws_sul_cancel(&sul_spoof);
		lws_sul_cancel(&sul_guard);
		lwsl_user("  '%s' after %d spoofs and a flood of %d: the "
			  "spoofer got %d datagrams, the NAT %d strays\n", body,
			  spoof_sent, flood_sent, spoofer_rx, nat2.strays);
		ok = spoof_stack_ok() && !strcmp(body, SLOW_1 SLOW_2) &&
		     spoof_sent && flood_sent == TPT_FLOOD_TOTAL &&
		     !spoofer_rx && !nat2.strays;
		break;
#endif
	default:
		break;
	}

	expect(step_names[step], ok);
	if (!ok || ++step == ST_DONE) {
		done = 1;
		lws_cancel_service(context);
		return;
	}

#if !defined(LWS_WITH_IPV6)
	if (step == ST_UNTRUSTED_FORGED)
		/* nowhere to connect from that the backend does not trust */
		step++;
#endif
#if !defined(TPT_QUIC)
	if (step == ST_H3_TERMINATED) {
		/* no QUIC in this build */
		done = 1;
		step = ST_DONE;
		lws_cancel_service(context);
		return;
	}
#endif

	step_start();
}

static void
sigint_handler(int sig)
{
	(void)sig;
	lws_default_loop_exit(context);
}

static const struct lws_protocols
	pcol_backend = { "backend", callback_backend,
			 sizeof(struct pss_srv), 0, 0, NULL, 0 },
	pcol_front = { "front", callback_front, sizeof(struct pss_srv), 0, 0,
		       NULL, 0 },
	pcol_capture = { "capture", callback_capture, 0, 0, 0, NULL, 0 },
	pcol_cli = { "cli", callback_cli, 0, 0, 0, NULL, 0 };
#if defined(TPT_QUIC)
static const struct lws_protocols
	pcol_nat = { "nat", callback_nat, 0, 0, 0, NULL, 0 };
#endif

static const struct lws_protocols
	*pp_backend[] = { &pcol_backend, NULL },
	*pp_front[] = { &pcol_front, NULL },
	*pp_capture[] = { &pcol_capture, NULL },
	*pp_cli[] = { &pcol_cli,
#if defined(TPT_QUIC)
		      &pcol_nat,
#endif
		      NULL };

static const struct lws_http_mount
	mount_backend = {
		.mountpoint		= "/",
		.protocol		= "backend",
		.origin_protocol	= LWSMPRO_CALLBACK,
		.mountpoint_len		= 1,
	},
	mount_front = {
		.mountpoint		= "/",
		.protocol		= "front",
		.origin_protocol	= LWSMPRO_CALLBACK,
		.mountpoint_len		= 1,
	};

static lws_sorted_usec_list_t sul_deadline;

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;
	expect(step < ST_DONE ? step_names[step] : "deadline", 0);
	done = 1;
	lws_cancel_service(context);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	char cert[256], key[256], target[64];
	const char *p;
	int n = 0;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	port_front = 7681;
	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_front = atoi(p);
	port_back = port_front + 1;
	port_capture = port_front + 2;
	port_nat = port_front + 3;
	port_nat2 = port_front + 4;
	if ((p = lws_cmdline_option(argc, argv, "--certs")))
		certs = p;

	lwsl_user("LWS API selftest: tls passthrough and PROXY v2\n");

	lws_snprintf(cert, sizeof(cert), "%s/localhost-100y.cert", certs);
	lws_snprintf(key, sizeof(key), "%s/localhost-100y.key", certs);
	lws_snprintf(target, sizeof(target), "127.0.0.1:%d", port_back);

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.fd_limit_per_thread = 0;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the backend: terminates its own tls, trusts the front's PROXY v2 */
	info.vhost_name			= "backend";
	info.port			= port_back;
	info.pprotocols			= pp_backend;
	info.mounts			= &mount_backend;
	info.ssl_cert_filepath		= cert;
	info.ssl_private_key_filepath	= key;
	info.proxy_v2_trusted		= "127.0.0.1";
	if (!lws_create_vhost(context, &info))
		goto bail;
	info.proxy_v2_trusted		= NULL;

	/* the front's own tls vhost, made first so it owns the listener */
	info.vhost_name			= "front.test";
	info.port			= port_front;
	info.pprotocols			= pp_front;
	info.mounts			= &mount_front;
	if (!lws_create_vhost(context, &info))
		goto bail;

	/* the passed through vhost, on the same port, with no tls of its own */
	info.vhost_name			= "pass.test";
	info.pprotocols			= NULL;
	info.mounts			= NULL;
	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;
	info.tls_passthrough		= target;
	info.tls_passthrough_proxy_v2	= 1;
	if (!lws_create_vhost(context, &info))
		goto bail;
	info.tls_passthrough		= NULL;
	info.tls_passthrough_proxy_v2	= 0;

	/* records a ClientHello */
	info.vhost_name			= "capture";
	info.port			= port_capture;
	info.pprotocols			= pp_capture;
	info.options			|= LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role		= "raw-skt";
	info.listen_accept_protocol	= "capture";
	if (!lws_create_vhost(context, &info))
		goto bail;
	info.options			&= ~(uint64_t)LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role		= NULL;
	info.listen_accept_protocol	= NULL;

	info.vhost_name			= "cli";
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.pprotocols			= pp_cli;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli)
		goto bail;

#if defined(TPT_QUIC)
	/* the NATs' sides, the clients' at known ports, and the spoofer */
	nat.in = lws_create_adopt_udp(vh_cli, "127.0.0.1", port_nat,
				      LWS_CAUDP_BIND, "nat", NULL, NULL, NULL,
				      NULL, NULL);
	nat2.in = lws_create_adopt_udp(vh_cli, "127.0.0.1", port_nat2,
				       LWS_CAUDP_BIND, "nat", NULL, NULL, NULL,
				       NULL, NULL);
	for (n = 0; n < 2; n++) {
		nat.out[n] = lws_create_adopt_udp(vh_cli, "127.0.0.1", 0,
						  LWS_CAUDP_BIND, "nat", NULL,
						  NULL, NULL, NULL, NULL);
		nat2.out[n] = lws_create_adopt_udp(vh_cli, "127.0.0.1", 0,
						   LWS_CAUDP_BIND, "nat", NULL,
						   NULL, NULL, NULL, NULL);
	}
	spoofer = lws_create_adopt_udp(vh_cli, "127.0.0.1", 0, LWS_CAUDP_BIND,
				       "nat", NULL, NULL, NULL, NULL, NULL);
	n = 0;
	if (!nat.in || !nat.out[0] || !nat.out[1] || !nat2.in ||
	    !nat2.out[0] || !nat2.out[1] || !spoofer)
		goto bail;
#endif

	lws_sul_schedule(context, 0, &sul_deadline, deadline_cb,
			 60 * LWS_US_PER_SEC);

	step = 0;
	step_start();

	while (n >= 0 && !done) {
		lws_usec_t t = lws_now_usecs();

		n = lws_service(context, 0);
		if (lws_now_usecs() - t >= PT_SLEPT_US)
			wakes++;
	}

	expect("every step ran", step == ST_DONE);

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s (tests=%d fail=%d)\n",
		  !tests || fail ? "FAIL" : "PASS", tests, fail);

	return !tests || fail;
}
