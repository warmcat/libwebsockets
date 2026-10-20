/*
 * lws-api-test-quic-accept-gate
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Fences G-361: pausing a server's accepts must not stop its established
 * QUIC connections, and new QUIC connections honour the tls restriction
 * (simultaneous_ssl_[handshake_]restriction), but only once their address
 * is validated.  And G-366: a listener made while accepts are paused starts
 * paused.  And G-367: a listener's back-off after accept() ran out of fds
 * ends in the same decision, not by simply listening again.
 *
 * A server QUIC connection has no socket of its own: every datagram of every
 * connection on a vhost arrives through its udp listener.  Accepts are
 * paused by taking POLLIN off the vhost's listeners, when the tls
 * restriction is reached, or when the fds tables are full.  The udp listener
 * used to be paused with the tcp one, so a few idle tcp connects to the port
 * froze every h3 connection.  And the other way around, QUIC connections
 * never took a slot of the tls restriction, so it bounded nothing over QUIC.
 *
 * Both ends are in this process.  In the first three cases, the client asks
 * for a slow response, that the server holds after its first chunk until
 * plain tcp connects (from this test, which never speaks tls on them) have
 * made the server pause its accepts.  Then the rest, CGA_BULK bytes, comes,
 * which the server can only send while it hears the client's ACKs and flow
 * control: the request must complete, within CGA_FLOW_MS.
 *
 *  --case handshakes: simultaneous_ssl_handshake_restriction is CGA_HS, and
 *    CGA_HS idle tcp connects fill it.  After the slow response, they go,
 *    and a new connection must complete a request: the slots came back.
 *
 *  --case sessions: simultaneous_ssl_restriction is CGA_SESS.  While the
 *    slow response is held, one idle tcp connect is accepted, and a new QUIC
 *    connection started: the slow connection's two ends, the tcp connect and
 *    the new connection's client end reach the limit, so it must be refused
 *    (CONNECTION_REFUSED, when its address is validated), and not served.
 *    This only holds if the server's end of a QUIC connection takes a slot,
 *    like a tcp one's does.  Then the tcp connect goes, another new
 *    connection must complete a request, and after it the slow response,
 *    with the restriction reached again.
 *
 *  --case fds: no tls restriction, but fd_limit_per_thread is small, and
 *    CGA_FDS_CONNECTS tcp connects fill the fds table.
 *
 *  --case flood: simultaneous_ssl_handshake_restriction is CGA_HS, and
 *    CGA_FLOOD QUIC connections that never validate their address are
 *    started: a udp relay keeps each client's first Initial instead of
 *    passing it on, and the client is closed (so it holds no slot of its
 *    own).  The relay then sends the server those Initials, which it
 *    answers, but nothing more.  They must not take the server's handshake
 *    slots: a tcp connect after them must still be accepted.  Otherwise
 *    anyone able to send Initials, from any source address they like, could
 *    pause the server's tls accepts.
 *
 *  --case late: simultaneous_ssl_handshake_restriction is CGA_HS, and CGA_HS
 *    idle tcp connects fill it.  Then a second tls vhost is made, listening
 *    on the --relay-port, and one tcp connect made to it.  Its listener must
 *    start paused: one that is readable while every accept on it is
 *    declined spins the service loop until the restriction lifts.  So over
 *    CGA_LATE_HOLD_MS, the time spent in service turns shorter than 1ms (a
 *    spin is made of nothing else) must stay under CGA_LATE_MAX_SPIN_US, and
 *    nothing is accepted.  Then the first connects go, and the new vhost's
 *    connect must be accepted: lifting the pause reopens its listener too.
 *
 *  --case emfile: simultaneous_ssl_handshake_restriction is 1, and a second
 *    tls vhost listens on the --relay-port.  The process' fd limit is lowered
 *    to CGA_NOFILE.  A tcp connect is made to the server, then every fd left
 *    is taken: the server's accept() fails with EMFILE, and the listener
 *    backs off for 100ms.  Inside that, the fds are given back and a tcp
 *    connect made to the second vhost, which is accepted and takes the one
 *    tls slot: the restriction is reached, the server's listener is already
 *    off.  (If the loop ran us too late, or too soon, for that, the server's
 *    listener was not backing off when the fds came back, and it accepted
 *    its connect and took the slot itself.  Nothing is wrong, but the case
 *    wasn't set up: everything is closed, and it is tried again, up to
 *    CGA_EMFILE_TRIES times.)  When the back-off ends, the listener must stay paused: readable,
 *    with its connect declined at accept, it spins the service loop.  So over
 *    CGA_LATE_HOLD_MS, the cpu time the process uses must stay under
 *    CGA_EMFILE_MAX_CPU_US (with an event library the loop's turns can't be
 *    timed from here), and the server accepts nothing.  Then the second
 *    vhost's connect goes, and the server's must be accepted.  ctest runs
 *    it on the default poll loop, and with --uv, on libuv.
 *
 * (The client's tls connections count in the same context's restriction as
 * the server's, which is why the handshake limit is 2: one QUIC handshake
 * holds a slot at each end.  For the same reason a new connection can't be
 * refused here for the handshake limit: the client's end has given its slot
 * back by the time the server validates the address, and while tcp connects
 * hold them all, the client's end can't start.)
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/resource.h>

#define CGA_TIMEOUT_S		20
#define CGA_HS			2
#define CGA_SESS		4
#define CGA_FLOOD		6
#define CGA_FDS_CONNECTS	24
#define CGA_TICK_US		(50 * LWS_US_PER_MS)
#define CGA_STABLE_TICKS	6	/* fds case: accepts stopped coming */
#define CGA_FLOW_MS		5000
#define CGA_ACCEPT_MS		2000
#define CGA_FIRST		"first chunk|"
#define CGA_BULK		(256 * 1024)
#define CGA_CHUNK		4096
#define CGA_PAT(_n)		((char)('a' + ((_n) % 26)))
#define CGA_SMALL		"small response"
#define CGA_INITIAL_MAX		1500
#define CGA_LATE_HOLD_MS	500
#define CGA_LATE_MAX_SPIN_US	(50 * LWS_US_PER_MS)
#define CGA_NOFILE		256
#define CGA_EMFILE_MAX_CPU_US	(100 * LWS_US_PER_MS)
#define CGA_EMFILE_TRIES	3

enum {
	CGA_HANDSHAKES,
	CGA_SESSIONS,
	CGA_FDS,
	CGA_FLOOD_CASE,
	CGA_LATE,
	CGA_EMFILE
};

static const char * const case_names[] = {
	"handshakes", "sessions", "fds", "flood", "late", "emfile"
};

/* the client connections, told apart by their opaque user data */
enum {
	CGA_CONN_SLOW,		/* the established one */
	CGA_CONN_REFUSED,	/* new, at the limit: must be refused */
	CGA_CONN_ADMITTED,	/* new, with room: must complete */
	CGA_CONN_FLOOD,		/* only there for its first Initial */

	CGA_CONN_COUNT
};

static int conn_tags[CGA_CONN_COUNT] = { 0, 1, 2, 3 };

enum {
	CGA_ST_SLOW,		/* the slow response's first chunk is coming */
	CGA_ST_FILL,		/* tcp connects are filling what pauses accepts */
	CGA_ST_FLOW,		/* the rest of the slow response must come */
	CGA_ST_REFUSE,		/* the new QUIC connection must be refused */
	CGA_ST_TCP_GONE,	/* the server must have closed the tcp connect */
	CGA_ST_ADMIT,		/* and now a new one must complete */
	CGA_ST_CAPTURE,		/* flood: collecting Initials */
	CGA_ST_FLOOD,		/* flood: the server has them */
	CGA_ST_ACCEPT,		/* flood: a tcp connect must be accepted */
	CGA_ST_LATE_FILL,	/* late: tcp connects fill the restriction */
	CGA_ST_LATE_HOLD,	/* late: the new listener must not spin us */
	CGA_ST_LATE_ACCEPT,	/* late: its connect must now be accepted */
	CGA_ST_EMFILE_SETTLE,	/* emfile: the context's first pass is done */
	CGA_ST_EMFILE_FILL,	/* emfile: connect, then use up the fds */
	CGA_ST_EMFILE_RELEASE,	/* emfile: fds back, connect the second vhost */
	CGA_ST_EMFILE_GATE,	/* emfile: which takes the one tls slot */
	CGA_ST_EMFILE_RESET,	/* emfile: the server took it, try again */
	CGA_ST_EMFILE_HOLD,	/* emfile: the listener must not spin us */
	CGA_ST_EMFILE_ACCEPT,	/* emfile: its connect must now be accepted */
	CGA_ST_DONE
};

static struct lws_context *context;
static struct lws_vhost *vh_cli, *vh_late;
static const char *cert, *key;
static lws_sorted_usec_list_t sul_watchdog, sul_tick;
static struct lws *srv_slow, *relay_in, *relay_out, *flood_wsi,
		  *accepted_wsi[CGA_FDS_CONNECTS];
/* time spent in service turns shorter than 1ms, see --case late */
static lws_usec_t deadline, spin_us, spin_us_base, cpu_us_base;
/* emfile: the fds taken to make the server's accept() fail */
static int fill[CGA_NOFILE], fill_count;
/* emfile: the tries, and the accept counts when this one started */
static int emfile_tries, emfile_acc, emfile_acc_late;
static uint8_t initials[CGA_FLOOD][CGA_INITIAL_MAX];
static size_t initial_len[CGA_FLOOD], body_len[CGA_CONN_COUNT];
static int port = 7700, port_relay, tcase = -1, state, accepted,
	   accepted_last, stable, tcp[CGA_FDS_CONNECTS], tcp_count,
	   accepted_late, tcp_late = -1,
	   accepting, accepted_wsis, tcp_gone, tcp_held,
	   released,
	   served_small, completed[CGA_CONN_COUNT], refused, captured,
	   flood_gone, srv_replies, timed_out, failed, body_bad;

static int
conn_tag(struct lws *wsi)
{
	int *t = (int *)lws_get_opaque_user_data(wsi);

	return t ? *t : CGA_CONN_SLOW;
}

static void
fail(const char *why)
{
	lwsl_err("FAIL: %s\n", why);
	failed = 1;
	lws_default_loop_exit(context);
}

/* ------------------------------------------------------------- server */

struct pss_srv {
	size_t			sent;
	char			small;	/* the small response */
	char			first_sent;
};

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t buf[LWS_PRE + CGA_CHUNK], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	size_t n, total;
	int m;

	switch (reason) {
	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
		/* a tcp connect is being accepted: its wsi is made next */
		accepting = 1;
		accepted++;
		if (vh_late && lws_get_vhost(wsi) == vh_late)
			accepted_late++;
		return 0;

	case LWS_CALLBACK_WSI_CREATE:
		if (accepting && accepted_wsis < (int)LWS_ARRAY_SIZE(accepted_wsi))
			accepted_wsi[accepted_wsis++] = wsi;
		accepting = 0;
		return 0;

	case LWS_CALLBACK_WSI_DESTROY:
		/* one of the tcp connects is closed on the server side */
		for (m = 0; m < accepted_wsis; m++)
			if (accepted_wsi[m] == wsi) {
				accepted_wsi[m] = NULL;
				tcp_gone++;
			}
		return 0;

	case LWS_CALLBACK_HTTP:
		pss->small = !!strcmp((const char *)in, "/slow");
		if (pss->small) {
			served_small++;
			total = strlen(CGA_SMALL);
		} else {
			srv_slow = wsi;
			total = strlen(CGA_FIRST) + CGA_BULK;
		}
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
				"text/plain", (lws_filepos_t)total, &p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return -1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss)
			break;
		if (pss->small) {
			n = strlen(CGA_SMALL);
			memcpy(start, CGA_SMALL, n);
			if (lws_write(wsi, start, n, LWS_WRITE_HTTP_FINAL) < 0)
				return -1;
			pss->small = 0;
			if (lws_http_transaction_completed(wsi))
				return -1;
			break;
		}
		if (wsi != srv_slow)
			break;
		if (!pss->first_sent) {
			n = strlen(CGA_FIRST);
			memcpy(start, CGA_FIRST, n);
			if (lws_write(wsi, start, n, LWS_WRITE_HTTP) < 0)
				return -1;
			pss->first_sent = 1;
			break;
		}
		/* h3 asks for WRITEABLE for its own reasons as well */
		if (!released || pss->sent >= CGA_BULK)
			break;

		for (n = 0; n < CGA_CHUNK; n++)
			start[n] = (uint8_t)CGA_PAT(pss->sent + n);
		pss->sent += CGA_CHUNK;
		if (lws_write(wsi, start, CGA_CHUNK, pss->sent == CGA_BULK ?
				LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP) < 0)
			return -1;
		if (pss->sent < CGA_BULK) {
			lws_callback_on_writable(wsi);
			break;
		}
		srv_slow = NULL;
		if (lws_http_transaction_completed(wsi))
			return -1;
		break;

	case LWS_CALLBACK_CLOSED_HTTP:
		if (wsi == srv_slow)
			srv_slow = NULL;
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
	const char *d = (const char *)in;
	int lenx = (int)sizeof(buf) - LWS_PRE, tag;
	size_t n, o;

	switch (reason) {
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		tag = conn_tag(wsi);
		if (tag != CGA_CONN_SLOW) {
			body_len[tag] += len;
			return 0;
		}
		/* the first chunk, then the pattern */
		for (n = 0; n < len; n++) {
			o = body_len[tag] + n;
			if (o < strlen(CGA_FIRST)) {
				if (d[n] != CGA_FIRST[o])
					body_bad = 1;
			} else if (d[n] != CGA_PAT(o - strlen(CGA_FIRST)))
				body_bad = 1;
		}
		body_len[tag] += len;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		tag = conn_tag(wsi);
		lwsl_user("%s: connection %d completed, %u bytes\n", __func__,
			  tag, (unsigned int)body_len[tag]);
		completed[tag] = 1;
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		tag = conn_tag(wsi);
		if (tag == CGA_CONN_FLOOD)
			/* we closed it ourselves */
			break;
		lwsl_user("%s: connection %d: connection error: %s\n",
			  __func__, tag, in ? d : "(null)");
		if (tag != CGA_CONN_REFUSED)
			fail("connection error");
		break;

	case LWS_CALLBACK_WSI_DESTROY:
		if (wsi == flood_wsi) {
			flood_wsi = NULL;
			flood_gone++;
		}
		/*
		 * Refused once its handshake is done, it hears
		 * CONNECTION_REFUSED and closes, whatever stage its request
		 * reached
		 */
		if (conn_tag(wsi) == CGA_CONN_REFUSED)
			refused = 1;
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * flood: the relay the flood's clients dial.  It keeps each one's first
 * Initial, and closes the client: the relay alone sends the Initials on, and
 * hears the server's answers, which it only counts
 */

static int
callback_relay(struct lws *wsi, enum lws_callback_reasons reason,
	       void *user, void *in, size_t len)
{
	const uint8_t *d = (const uint8_t *)in;

	(void)user;

	if (reason != LWS_CALLBACK_RAW_RX || !lws_get_udp(wsi))
		return 0;

	if (wsi == relay_out) {
		srv_replies++;
		return 0;
	}

	/* a QUIC v1 long header Initial (RFC 9000 17.2.2), from a client */
	if (state != CGA_ST_CAPTURE || !flood_wsi || captured == CGA_FLOOD ||
	    len < 1200 || len > CGA_INITIAL_MAX || (d[0] & 0xb0) != 0x80)
		return 0;

	memcpy(initials[captured], in, len);
	initial_len[captured++] = len;

	lws_wsi_close(flood_wsi, LWS_TO_KILL_ASYNC);

	return 0;
}

static const struct lws_protocols protocols_srv[] = {
	{ "cga", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "cga", callback_cli, 0, 0, 0, NULL, 0 },
	{ "cga-relay", callback_relay, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static struct lws *
connect_h3(int tag)
{
	struct lws_client_connect_info i;
	struct lws *wsi = NULL;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= "127.0.0.1";
	i.host			= "localhost";
	i.origin		= "localhost";
	i.port			= tag == CGA_CONN_FLOOD ? port_relay : port;
	i.path			= tag == CGA_CONN_SLOW ? "/slow" : "/small";
	i.method		= "GET";
	i.protocol		= "cga";
	i.alpn			= "h3";
	/* not LCCSCF_PIPELINE: each is a new connection */
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	/* it must be decided on QUIC, not by a fallback to tcp */
	i.disable_h3_fallback	= 1;
	i.opaque_user_data	= &conn_tags[tag];
	i.pwsi			= &wsi;

	if (!lws_client_connect_via_info(&i))
		return NULL;

	return wsi;
}

/* a tcp connect to the server, that never says anything */

static int
tcp_connect(int to_port)
{
	struct sockaddr_in sin;
	int fd;

	if (tcp_count == (int)LWS_ARRAY_SIZE(tcp))
		return 1;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return 1;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons((uint16_t)to_port);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	/* to loopback, it completes in the kernel, accepted or not */
	if (connect(fd, (struct sockaddr *)&sin, sizeof(sin))) {
		close(fd);
		return 1;
	}

	tcp[tcp_count++] = fd;

	return 0;
}

static void
tcp_close_all(void)
{
	while (tcp_count)
		close(tcp[--tcp_count]);
}

/* late, emfile: a second tls vhost, listening on the --relay-port */
static int
make_vh_late(void)
{
	struct lws_context_creation_info info;

	lws_context_info_defaults(&info, NULL);
	info.port			= port_relay;
	info.protocols			= protocols_srv;
	info.ssl_cert_filepath		= cert;
	info.ssl_private_key_filepath	= key;
	info.alpn			= "http/1.1";
	info.vhost_name			= "late";
	vh_late = lws_create_vhost(context, &info);
	if (!vh_late) {
		fail("the second vhost could not be made");
		return 1;
	}

	return 0;
}

/* a tcp connect to the second vhost, kept apart from the others */
static int
tcp_connect_late(void)
{
	if (tcp_connect(port_relay)) {
		fail("tcp connect to the late vhost");
		return 1;
	}
	tcp_late = tcp[--tcp_count];

	return 0;
}

/* late: the second vhost is made while the restriction is reached */
static int
start_late(void)
{
	if (make_vh_late())
		return 1;

	/* it must outlast the ones holding the restriction */
	return tcp_connect_late();
}

/* emfile: take every fd the process has left */
static int
fill_fds(void)
{
	int fd;

	while (fill_count < (int)LWS_ARRAY_SIZE(fill)) {
		fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			return errno != EMFILE;
		fill[fill_count++] = fd;
	}

	/* the limit is CGA_NOFILE: the fds lws and stdio hold leave fewer */
	return 1;
}

static void
fill_release(void)
{
	while (fill_count)
		close(fill[--fill_count]);
}

/* the cpu time this process used so far, user and system */
static lws_usec_t
cpu_us(void)
{
	struct rusage ru;

	if (getrusage(RUSAGE_SELF, &ru))
		return 0;

	return ((lws_usec_t)ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) *
							LWS_US_PER_SEC +
	       ru.ru_utime.tv_usec + ru.ru_stime.tv_usec;
}

static void
set_deadline(int ms)
{
	deadline = lws_now_usecs() + (lws_usec_t)ms * LWS_US_PER_MS;
}

/* the tcp connects go: the server must close them, and give their slots back */
static void
tcp_release(void)
{
	tcp_held = tcp_count;
	tcp_gone = 0;
	tcp_close_all();
	set_deadline(CGA_FLOW_MS);
	state = CGA_ST_TCP_GONE;
}

static void
release_slow(void)
{
	lwsl_user("accepts paused (%d tcp connects accepted so far), the "
		  "slow response goes on\n", accepted);
	released = 1;
	if (srv_slow)
		lws_callback_on_writable(srv_slow);
	set_deadline(CGA_FLOW_MS);
	state = CGA_ST_FLOW;
}

static int
start_refused(void)
{
	lwsl_user("starting a new QUIC connection at the limit\n");
	if (!connect_h3(CGA_CONN_REFUSED)) {
		fail("new connection could not start");
		return 1;
	}
	set_deadline(CGA_FLOW_MS);
	state = CGA_ST_REFUSE;

	return 0;
}

static int
start_flood_client(void)
{
	flood_wsi = connect_h3(CGA_CONN_FLOOD);
	if (!flood_wsi) {
		fail("flood connection could not start");
		return 1;
	}

	return 0;
}

static void
tick_cb(lws_sorted_usec_list_t *sul)
{
	lws_sockaddr46 srv;
	int n;

	switch (state) {
	case CGA_ST_SLOW:
		if (!body_len[CGA_CONN_SLOW])
			break;
		n = tcase == CGA_FDS ? CGA_FDS_CONNECTS :
		    (tcase == CGA_HANDSHAKES ? CGA_HS : 1);
		while (n--)
			if (tcp_connect(port)) {
				fail("tcp connect");
				return;
			}
		state = CGA_ST_FILL;
		break;

	case CGA_ST_FILL:
		if (tcase == CGA_HANDSHAKES) {
			if (accepted >= CGA_HS)
				release_slow();
			break;
		}
		if (tcase == CGA_SESSIONS) {
			if (accepted && start_refused())
				return;
			break;
		}
		/* the fds table is full when the accepts stop coming */
		if (accepted != accepted_last) {
			accepted_last = accepted;
			stable = 0;
			break;
		}
		if (accepted && ++stable == CGA_STABLE_TICKS) {
			if (accepted >= CGA_FDS_CONNECTS) {
				fail("the fds table never filled");
				return;
			}
			release_slow();
		}
		break;

	case CGA_ST_FLOW:
		if (!completed[CGA_CONN_SLOW]) {
			if (lws_now_usecs() > deadline) {
				fail("the established QUIC connection stalled "
				     "while accepts were paused");
				return;
			}
			break;
		}
		if (body_len[CGA_CONN_SLOW] != strlen(CGA_FIRST) + CGA_BULK ||
		    body_bad) {
			fail("the slow response arrived wrong");
			return;
		}
		if (tcase != CGA_HANDSHAKES) {
			state = CGA_ST_DONE;
			lws_default_loop_exit(context);
			return;
		}
		tcp_release();
		break;

	case CGA_ST_REFUSE:
		if (served_small || completed[CGA_CONN_REFUSED]) {
			fail("a new QUIC connection was served with the tls "
			     "restriction reached");
			return;
		}
		if (!refused) {
			if (lws_now_usecs() > deadline) {
				fail("the new QUIC connection at the limit "
				     "was not refused");
				return;
			}
			break;
		}
		lwsl_user("refused at the limit; the held tcp connect goes\n");
		tcp_release();
		break;

	case CGA_ST_TCP_GONE:
		if (tcp_gone < tcp_held) {
			if (lws_now_usecs() > deadline) {
				fail("the server never closed the tcp "
				     "connect");
				return;
			}
			break;
		}
		lwsl_user("starting a new QUIC connection with room\n");
		if (!connect_h3(CGA_CONN_ADMITTED)) {
			fail("new connection could not start");
			return;
		}
		state = CGA_ST_ADMIT;
		break;

	case CGA_ST_ADMIT:
		if (!completed[CGA_CONN_ADMITTED])
			break;
		if (body_len[CGA_CONN_ADMITTED] != strlen(CGA_SMALL)) {
			fail("the small response arrived wrong");
			return;
		}
		if (tcase == CGA_SESSIONS) {
			/* the restriction is reached again, by the two */
			release_slow();
			break;
		}
		state = CGA_ST_DONE;
		lws_default_loop_exit(context);
		return;

	case CGA_ST_CAPTURE:
		/* one at a time: each closed before the next starts */
		if (flood_wsi || flood_gone != captured)
			break;
		if (captured < CGA_FLOOD) {
			if (start_flood_client())
				return;
			break;
		}

		memset(&srv, 0, sizeof(srv));
		if (lws_sa46_parse_numeric_address("127.0.0.1", &srv)) {
			fail("server address");
			return;
		}
		sa46_sockport(&srv, htons((uint16_t)port));
		for (n = 0; n < CGA_FLOOD; n++)
			(void)sendto(lws_get_socket_fd(relay_out),
				     (const char *)initials[n],
				     LWS_POSIX_LENGTH_CAST(initial_len[n]), 0,
				     sa46_sockaddr(&srv), sa46_socklen(&srv));
		lwsl_user("%d unvalidated Initials sent to the server\n",
			  CGA_FLOOD);
		set_deadline(CGA_FLOW_MS);
		state = CGA_ST_FLOOD;
		break;

	case CGA_ST_FLOOD:
		/* it answers every one: they are all handshakes in progress */
		if (srv_replies < CGA_FLOOD) {
			if (lws_now_usecs() > deadline) {
				fail("the server did not answer the Initials");
				return;
			}
			break;
		}
		accepted_last = accepted;
		if (tcp_connect(port)) {
			fail("tcp connect");
			return;
		}
		set_deadline(CGA_ACCEPT_MS);
		state = CGA_ST_ACCEPT;
		break;

	case CGA_ST_LATE_FILL:
		if (!tcp_count)
			for (n = 0; n < CGA_HS; n++)
				if (tcp_connect(port)) {
					fail("tcp connect");
					return;
				}
		if (accepted < CGA_HS)
			break;
		if (start_late())
			return;
		lwsl_user("late vhost made with the restriction reached, and "
			  "connected to\n");
		spin_us_base = spin_us;
		set_deadline(CGA_LATE_HOLD_MS);
		state = CGA_ST_LATE_HOLD;
		break;

	case CGA_ST_LATE_HOLD:
		if (spin_us - spin_us_base > CGA_LATE_MAX_SPIN_US) {
			lwsl_err("%dms in service turns under 1ms\n",
				 (int)((spin_us - spin_us_base) / LWS_US_PER_MS));
			fail("the service loop spun on the late listener");
			return;
		}
		if (lws_now_usecs() < deadline)
			break;
		if (accepted_late) {
			fail("the late vhost accepted with the restriction "
			     "reached");
			return;
		}
		lwsl_user("late listener quiet, %dus in turns under 1ms over "
			  "%dms; the first connects go\n",
			  (int)(spin_us - spin_us_base), CGA_LATE_HOLD_MS);
		tcp_close_all();
		set_deadline(CGA_FLOW_MS);
		state = CGA_ST_LATE_ACCEPT;
		break;

	case CGA_ST_LATE_ACCEPT:
		if (!accepted_late) {
			if (lws_now_usecs() > deadline) {
				fail("the late vhost never accepted once the "
				     "restriction lifted");
				return;
			}
			break;
		}
		lwsl_user("the late vhost accepted once the restriction "
			  "lifted\n");
		state = CGA_ST_DONE;
		lws_default_loop_exit(context);
		return;

	case CGA_ST_EMFILE_SETTLE:
		/*
		 * The first service pass is behind us: the async dns' first
		 * nameserver reload, which reads resolv.conf, and can close a
		 * socket, is not going to happen while the fds are used up
		 */
		state = CGA_ST_EMFILE_FILL;
		break;

	case CGA_ST_EMFILE_FILL:
		/*
		 * The connect completes in the kernel, then there is no fd
		 * for the server to accept it on
		 */
		emfile_acc = accepted;
		emfile_acc_late = accepted_late;
		emfile_tries++;
		if (tcp_connect(port)) {
			fail("tcp connect");
			return;
		}
		if (fill_fds()) {
			fill_release();
			fail("could not use up the fds");
			return;
		}
		lwsl_user("%d fds taken, the server's accept() must fail\n",
			  fill_count);
		state = CGA_ST_EMFILE_RELEASE;
		break;

	case CGA_ST_EMFILE_RELEASE:
		/* well inside the server listener's 100ms back-off */
		fill_release();
		if (accepted != emfile_acc) {
			fail("the server accepted with no fds left");
			return;
		}
		/* accepted by the second vhost, it takes the one tls slot */
		if (tcp_connect_late())
			return;
		set_deadline(CGA_ACCEPT_MS);
		state = CGA_ST_EMFILE_GATE;
		break;

	case CGA_ST_EMFILE_GATE:
		if (accepted_late == emfile_acc_late) {
			if (accepted - accepted_late !=
					emfile_acc - emfile_acc_late) {
				/* the server's listener got there first */
				if (emfile_tries == CGA_EMFILE_TRIES) {
					fail("the server's listener was never "
					     "still backing off when the fds "
					     "came back");
					return;
				}
				lwsl_user("the server's listener wasn't backing "
					  "off when the fds came back, it took "
					  "the slot: again\n");
				close(tcp_late);
				tcp_late = -1;
				tcp_close_all();
				stable = 0;
				accepted_last = accepted;
				set_deadline(CGA_FLOW_MS);
				state = CGA_ST_EMFILE_RESET;
				break;
			}
			if (lws_now_usecs() > deadline) {
				fail("the second vhost did not accept");
				return;
			}
			break;
		}
		lwsl_user("the restriction is reached, the server's listener "
			  "must stay paused\n");
		cpu_us_base = cpu_us();
		set_deadline(CGA_LATE_HOLD_MS);
		state = CGA_ST_EMFILE_HOLD;
		break;

	case CGA_ST_EMFILE_RESET:
		/*
		 * Each end closed its connect: the server closes what it
		 * accepted of them, giving the slot back, then the second
		 * vhost may accept its own, and close that too
		 */
		if (accepted != tcp_gone || accepted != accepted_last) {
			if (lws_now_usecs() > deadline) {
				fail("the connects of the last try were not "
				     "all closed");
				return;
			}
			accepted_last = accepted;
			stable = 0;
			break;
		}
		if (++stable < CGA_STABLE_TICKS)
			break;
		state = CGA_ST_EMFILE_FILL;
		break;

	case CGA_ST_EMFILE_HOLD:
		if (cpu_us() - cpu_us_base > CGA_EMFILE_MAX_CPU_US) {
			lwsl_err("%dms cpu\n",
				 (int)((cpu_us() - cpu_us_base) / LWS_US_PER_MS));
			fail("the service loop spun on the server's listener "
			     "after its EMFILE back-off");
			return;
		}
		if (lws_now_usecs() < deadline)
			break;
		if (accepted - accepted_late != emfile_acc - emfile_acc_late) {
			fail("the server accepted with the restriction "
			     "reached");
			return;
		}
		lwsl_user("listener quiet, %dus cpu over %dms; the second "
			  "vhost's connect goes\n",
			  (int)(cpu_us() - cpu_us_base), CGA_LATE_HOLD_MS);
		close(tcp_late);
		tcp_late = -1;
		set_deadline(CGA_FLOW_MS);
		state = CGA_ST_EMFILE_ACCEPT;
		break;

	case CGA_ST_EMFILE_ACCEPT:
		if (accepted - accepted_late == emfile_acc - emfile_acc_late) {
			if (lws_now_usecs() > deadline) {
				fail("the server never accepted once the "
				     "restriction lifted");
				return;
			}
			break;
		}
		lwsl_user("the server accepted once the restriction lifted\n");
		state = CGA_ST_DONE;
		lws_default_loop_exit(context);
		return;

	case CGA_ST_ACCEPT:
		if (accepted == accepted_last) {
			if (lws_now_usecs() > deadline) {
				fail("unvalidated Initials paused the tls "
				     "accepts");
				return;
			}
			break;
		}
		lwsl_user("tcp accepted with %d unvalidated QUIC handshakes "
			  "in progress\n", CGA_FLOOD);
		state = CGA_ST_DONE;
		lws_default_loop_exit(context);
		return;

	default:
		return;
	}

	lws_sul_schedule(context, 0, &sul_tick, tick_cb, CGA_TICK_US);
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	timed_out = 1;
	lws_default_loop_exit(context);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	const char *p, *mode = NULL;
	struct lws_context_creation_info info;
	int n, result = 1;
	struct rlimit rl;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	port_relay = port + 1;
	if ((p = lws_cmdline_option(argc, argv, "--relay-port")))
		port_relay = atoi(p);
	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");
	mode = lws_cmdline_option(argc, argv, "--case");

	for (n = 0; mode && n < (int)LWS_ARRAY_SIZE(case_names); n++)
		if (!strcmp(mode, case_names[n]))
			tcase = n;

	if (!cert || !key || tcase < 0) {
		lwsl_err("--cert, --key and --case handshakes|sessions|fds|"
			 "flood|late|emfile are required\n");
		return 1;
	}

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: QUIC and paused accepts, %s\n", mode);

	/*
	 * |=, keeping an event library chosen on the commandline, eg --uv.
	 * No captive portal detection: its tls client would take a slot of
	 * the restriction, and its sockets fds, while the test counts them
	 */
	info.options |= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
			LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
			LWS_SERVER_OPTION_CPD_BYPASS;
	/* the idle tcp connects must outlast the test */
	info.timeout_secs = CGA_TIMEOUT_S * 2;

	info.fd_limit_per_thread = 0;
	switch (tcase) {
	case CGA_HANDSHAKES:
	case CGA_FLOOD_CASE:
	case CGA_LATE:
		info.simultaneous_ssl_handshake_restriction = CGA_HS;
		break;
	case CGA_EMFILE:
		/* the second vhost's connect alone reaches it */
		info.simultaneous_ssl_handshake_restriction = 1;
		/* few enough fds to use them all up */
		if (getrlimit(RLIMIT_NOFILE, &rl)) {
			lwsl_err("getrlimit failed\n");
			return 1;
		}
		if (rl.rlim_cur > CGA_NOFILE) {
			rl.rlim_cur = CGA_NOFILE;
			if (setrlimit(RLIMIT_NOFILE, &rl)) {
				lwsl_err("setrlimit failed\n");
				return 1;
			}
		}
		break;
	case CGA_SESSIONS:
		info.simultaneous_ssl_restriction = CGA_SESS;
		break;
	default:
		/*
		 * Room for what lws holds, the listeners and the client's
		 * QUIC socket, and a few tcp connects
		 */
		info.fd_limit_per_thread = LWS_FD_LIMIT_PER_THREAD_MIN;
		break;
	}

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the server: an alpn naming h3 brings up a quic listener too */

	info.port			= port;
	info.protocols			= protocols_srv;
	info.ssl_cert_filepath		= cert;
	info.ssl_private_key_filepath	= key;
	info.alpn			= "h2,http/1.1,h3";
	info.vhost_name			= "localhost";
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create the server vhost\n");
		goto bail;
	}

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.protocols			= protocols_cli;
	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;
	info.alpn			= NULL;
	info.vhost_name			= "cli";
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create the client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 CGA_TIMEOUT_S * LWS_US_PER_SEC);
	lws_sul_schedule(context, 0, &sul_tick, tick_cb, CGA_TICK_US);

	if (tcase == CGA_FLOOD_CASE) {
		relay_in = lws_create_adopt_udp(vh_cli, "127.0.0.1", port_relay,
						LWS_CAUDP_BIND, "cga-relay",
						NULL, NULL, NULL, NULL, NULL);
		relay_out = lws_create_adopt_udp(vh_cli, "127.0.0.1", 0,
						 LWS_CAUDP_BIND, "cga-relay",
						 NULL, NULL, NULL, NULL, NULL);
		if (!relay_in || !relay_out) {
			lwsl_err("Failed to create the relay\n");
			goto bail;
		}
		state = CGA_ST_CAPTURE;
	} else if (tcase == CGA_LATE)
		state = CGA_ST_LATE_FILL;
	else if (tcase == CGA_EMFILE) {
		if (make_vh_late())
			goto bail;
		state = CGA_ST_EMFILE_SETTLE;
	}
	else if (!connect_h3(CGA_CONN_SLOW)) {
		lwsl_err("The connection could not be started\n");
		goto bail;
	}

	n = 0;
	while (n >= 0) {
		lws_usec_t t = lws_now_usecs();

		n = lws_service(context, 0);
		t = lws_now_usecs() - t;
		if (t < LWS_US_PER_MS)
			spin_us += t;
	}

	if (timed_out)
		lwsl_err("FAIL: timed out in state %d (slow: %u bytes, "
			 "accepted %d)\n", state,
			 (unsigned int)body_len[CGA_CONN_SLOW], accepted);
	else if (!failed && state == CGA_ST_DONE)
		result = 0;

bail:
	lws_sul_cancel(&sul_tick);
	lws_sul_cancel(&sul_watchdog);
	fill_release();
	tcp_close_all();
	if (tcp_late >= 0)
		close(tcp_late);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
