/*
 * lws-api-test-ws-server-examples
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The ws-server minimal examples are copied into real servers, so their
 * protocols must stay safe whatever a peer sends them.  Each example's
 * protocol is built exactly as the example builds it, and served on its own
 * vhost (chosen by Host:) on one port, with ws clients in the same process.
 *
 * minimal-ws-server-pmd-corner sends the corner case chosen by the URL
 *
 *  - "/1" gets the first corner case, one BINARY message of 1012 bytes
 *  - URLs that don't name a corner case, "/-1", "/0", "/6", a huge number,
 *    or one followed by junk, get nothing, and the server carries on
 *
 * minimal-ws-server, -pmd, -ring and minimal-ws-broker pass on what one
 * client sends to the others, so it must reach them as whole, valid messages
 *
 *  - a TEXT message sent in two fragments, split inside a UTF-8 character,
 *    a TEXT message of multibyte characters too big for one rx buffer, a
 *    BINARY message that isn't UTF-8, and a TEXT message of the largest size
 *    the example passes on, each reach the receiver as one message, intact,
 *    as the type it was sent as
 *  - a message one byte bigger than that is refused (close 1009), and an
 *    invalid UTF-8 TEXT message is refused (close 1007), with nothing passed
 *    on from either
 *
 * minimal-ws-server-ring passes on every message to every client, through
 * a ringbuffer that frees a message once everybody has been sent it
 *
 *  - a client sending 20 messages at once, more than the ring holds, gets
 *    them all to two readers, in order, with nobody closed
 *  - a client that stops reading is closed after the example's lag limit,
 *    so it can't hold up the others: while it is stuck, 3000 messages of
 *    4000 bytes get through to a reader, in order, and nothing is lost
 *
 * minimal-ws-broker passes on what publishers send to every subscriber,
 * through a ringbuffer that drops new messages while it is full
 *
 *  - a publisher sending 20 messages at once, more than the ring holds, gets
 *    the ones that fit to two subscribers, in order, with nobody closed
 *  - a subscriber that stops reading is closed after the example's lag
 *    limit, so it can't make the broker drop everything for the others
 *    forever: after 3000 messages of 4000 bytes, and the lag limit, a last
 *    message gets through to a subscriber
 *
 * minimal-ws-raw-proxy passes bytes both ways between a ws client and an
 * onward raw connection to a backend
 *
 *  - what the backend sends reaches the ws client as BINARY messages, a
 *    UTF-8 character split between two of them
 *  - while the backend doesn't read, the ws client can't send without limit
 *    into the proxy's memory: it is held back once buffers fill.  When the
 *    backend reads again, all 64MiB the client sends get to it intact
 *  - when the ws client goes, the proxy closes the backend connection
 *  - when the backend can't be reached, the proxy closes the ws client
 *    instead of keeping it open with nothing behind it, and frees what it
 *    queued (run under ASan to see leaks)
 *
 * The test fails if any of that doesn't happen, or it doesn't all complete
 * in time.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#include "examples.h"

#define WSE_MSG_MAX		8192

/* the URLs the pmd-corner example must ignore, after its one good one */
static const char * const corner_paths[] = {
	"/1", "/-1", "/0", "/6", "/-2147483648", "/4294967297", "/1x", "/",
};

/* the examples that pass on what one client sends to the others */
static const struct wse_relay {
	const char		*vhost_name;
	const char		*protocol_name;
	const char		*tx_path;	/* where senders connect */
	const size_t		*max_message;
} relays[] = {
	{ "chat",	"lws-minimal",		"/",	&wse_max_message_chat },
	{ "pmd",	"lws-minimal",		"/",	&wse_max_message_pmd },
	{ "ring",	"lws-minimal",		"/",	&wse_max_message_ring },
	{ "broker",	"lws-minimal-broker",	"/publisher",
						&wse_max_message_broker },
};

/* each relay case's connections, by offset from its first in conns[] */
enum {
	WSE_R_RX,		/* receives what is passed on */
	WSE_R_TX,		/* sends good messages one at a time */
	WSE_R_BIG,		/* sends a message one byte too big */
	WSE_R_BAD,		/* sends a TEXT message that is not UTF-8 */

	WSE_R_COUNT
};

/* the connections, by index in conns[] */
enum {
	WSE_C_CORNER,
	WSE_C_RELAY = WSE_C_CORNER + LWS_ARRAY_SIZE(corner_paths),
	WSE_C_COUNT = WSE_C_RELAY + (LWS_ARRAY_SIZE(relays) * WSE_R_COUNT)
};

/*
 * The examples that fan out every message to many clients through a ring,
 * where one client that stops reading could hold up all the others
 */
static const struct wse_fanout {
	const char		*vhost_name;
	const char		*protocol_name;
	const char		*tx_path;	/* where the sender connects */
	const int		*lag_secs;	/* stuck client is closed after */
	char			lossless;	/* slows senders, else drops */
} fanouts[] = {
	{ "ring",	"lws-minimal",		"/",	&wse_lag_secs_ring, 1 },
	{ "broker",	"lws-minimal-broker",	"/publisher",
						&wse_lag_secs_broker, 0 },
};

/* each fan-out case's connections, in fanout_conns[case][] */
enum {
	WSE_F_R1,		/* readers */
	WSE_F_R2,
	WSE_F_S,		/* sends */
	WSE_F_K,		/* stops reading */

	WSE_F_COUNT
};

#define WSE_F_BURST		20	/* messages sent at once */
#define WSE_F_LAG_MSGS		3000	/* messages sent while K is stuck */
#define WSE_F_LAG_LEN		4000	/* ...each this big */

#define WSE_PX_TOTAL		(64 * 1024 * 1024) /* client sends this */
#define WSE_PX_FRAME		WSE_MSG_MAX	   /* ...in frames this big */
#define WSE_PX_HELD		(16 * 1024 * 1024) /* must be held back by */

/* sent by the backend in two pieces, split inside the "€" */
static const char px_hello1[] = "hello \xe2\x82", px_hello2[] = "\xac!",
		  px_hello[] = "hello \xe2\x82\xac!";

struct wse_proxy {
	struct lws		*wsi_ws;	/* our ws client to the proxy */
	struct lws		*wsi_be;	/* the backend's raw connection */
	struct lws_vhost	*vh_be;
	int			be_port;
	size_t			sent;		/* by the ws client */
	size_t			be_rx;		/* by the backend */
	uint8_t			hello[16];	/* what the ws client got */
	size_t			hello_len;
	int			be_tx;		/* hello pieces sent */
	char			ws_est;
	char			ws_closed;
	char			be_closed;
	char			not_binary;
	char			corrupt;
};

static struct wse_proxy px;

enum {
	WSE_P_CORNER,
	WSE_P_CORNER_CHECK,
	WSE_P_RELAY,		/* for each relays[] in turn */
	WSE_P_RELAY_BIG,
	WSE_P_RELAY_BAD,
	WSE_P_RELAY_CHECK,
	WSE_P_FANOUT,		/* for each fanouts[] in turn */
	WSE_P_FANOUT_BURST,
	WSE_P_FANOUT_LAG,
	WSE_P_FANOUT_END,	/* lossy: a last message after the lag limit */
	WSE_P_FANOUT_RELEASE,
	WSE_P_FANOUT_CHECK,
	WSE_P_PROXY,
	WSE_P_PROXY_HELD,	/* backend not reading for a while */
	WSE_P_PROXY_DRAIN,	/* backend reading again */
	WSE_P_PROXY_CLOSE,	/* ws client goes: so must the backend conn */
	WSE_P_PROXY_NO_BACKEND,
	WSE_P_PROXY_NO_BACKEND_CHECK,

	WSE_P_DONE
};

struct wse_conn {
	struct lws		*wsi;
	char			path[48];
	uint8_t			msg[WSE_MSG_MAX];
	size_t			msg_len;
	size_t			last_len;	/* length of last whole message */
	int			msgs;		/* complete messages received */
	int			tx_msg;		/* next message to send */
	int			tx_frag;	/* next fragment of it */
	uint16_t		close_code;	/* from the server's close */
	char			est;
	char			closed;
	char			msg_binary;
	char			last_binary;
	char			msg_overflow;
};

struct wse_fconn {
	struct lws		*wsi;
	char			msg[WSE_F_LAG_LEN + 1];	/* reassembly */
	size_t			msg_len;
	int			burst;		/* burst messages received */
	int			lag;		/* lag messages received */
	int			tx;		/* lag messages sent */
	char			est;
	char			closed;
	char			tx_burst;	/* burst sent */
	char			tx_end;		/* last message sent */
	char			rx_end;		/* last message received */
	char			killed;		/* we closed it */
	int			fo;		/* index in fanouts[] */
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_phase, sul_timeout;
static struct wse_conn conns[WSE_C_COUNT];
static struct wse_fconn fanout_conns[LWS_ARRAY_SIZE(fanouts)][WSE_F_COUNT];
static const char *server_address = "localhost";
static int port = 7681, phase, relay, fanout, result = 1, failed, interrupted;
static uint8_t txbuf[LWS_PRE + WSE_MSG_MAX];

/*
 * The messages TX sends, one at a time, and RX must receive, whole and
 * nothing else.  Each is sent as up to two fragments.
 */

static const char split1[] = "split \xe2\x82", split2[] = "\xac fragment",
		  split_whole[] = "split \xe2\x82\xac fragment",
		  binary[] = "\xff\xfe binary";

enum {
	WSE_M_SPLIT,		/* TEXT, two fragments, split inside a char */
	WSE_M_EUROS,		/* TEXT, 100 x "€", bigger than one rx buffer */
	WSE_M_BINARY,		/* BINARY, not UTF-8 */
	WSE_M_LARGEST,		/* TEXT, the largest the example passes on */

	WSE_M_COUNT
};

static uint8_t euros[300];

static void
wse_fail(const char *why)
{
	lwsl_err("FAIL: phase %d, relay %d: %s\n", phase, relay, why);
	failed = 1;
	interrupted = 1;
	lws_cancel_service(context);
}

static int
wse_connect(int idx, const char *vhost_name, const char *proto,
	    const char *path)
{
	struct wse_conn *c = &conns[idx];
	struct lws_client_connect_info i;

	lws_strncpy(c->path, path, sizeof(c->path));

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_address;
	i.port			= port;
	i.path			= c->path;
	i.host			= vhost_name; /* selects the example's vhost */
	i.origin		= vhost_name;
	i.protocol		= proto;
	i.local_protocol_name	= "wse-client";
	i.opaque_user_data	= c;
	i.pwsi			= &c->wsi;

	if (!lws_client_connect_via_info(&i)) {
		wse_fail("connect failed");
		return 1;
	}

	return 0;
}

static int
wse_relay_connect(int r)
{
	const struct wse_relay *rl = &relays[relay];
	const char *path = r == WSE_R_RX ? "/" : rl->tx_path;

	return wse_connect(WSE_C_RELAY + (relay * WSE_R_COUNT) + r,
			   rl->vhost_name, rl->protocol_name, path);
}

static int
wse_fanout_connect(int r)
{
	const struct wse_fanout *fo = &fanouts[fanout];
	struct wse_fconn *fconns = fanout_conns[fanout];
	struct lws_client_connect_info i;

	fconns[r].fo = fanout;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_address;
	i.port			= port;
	i.path			= r == WSE_F_S ? fo->tx_path : "/";
	i.host			= fo->vhost_name;
	i.origin		= fo->vhost_name;
	i.protocol		= fo->protocol_name;
	i.local_protocol_name	= "wse-fanout-client";
	i.opaque_user_data	= &fconns[r];
	i.pwsi			= &fconns[r].wsi;

	if (!lws_client_connect_via_info(&i)) {
		wse_fail("connect failed");
		return 1;
	}

	return 0;
}

static int
wse_proxy_connect(void)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_address;
	i.port			= port;
	i.path			= "/";
	i.host			= "proxy";
	i.origin		= "proxy";
	i.protocol		= "lws-ws-raw-ws";
	i.local_protocol_name	= "wse-proxy-client";
	i.opaque_user_data	= &px;
	i.pwsi			= &px.wsi_ws;

	px.ws_est = px.ws_closed = 0;

	if (!lws_client_connect_via_info(&i)) {
		wse_fail("connect failed");
		return 1;
	}

	return 0;
}

static uint8_t
wse_proxy_byte(size_t o)
{
	return (uint8_t)(o ^ (o >> 8) ^ (o >> 16) ^ (o >> 24));
}

static struct wse_conn *
wse_relay_conn(int r)
{
	return &conns[WSE_C_RELAY + (relay * WSE_R_COUNT) + r];
}

/* which relay case and role is this connection? -1 if not a relay one */

static int
wse_relay_role(struct wse_conn *c)
{
	int idx = (int)(c - conns) - WSE_C_RELAY;

	if (idx < 0 || idx / WSE_R_COUNT != relay)
		return -1;

	return idx % WSE_R_COUNT;
}

static void
wse_phase_cb(lws_sorted_usec_list_t *sul);

static void
wse_schedule(lws_usec_t us)
{
	lws_sul_schedule(context, 0, &sul_phase, wse_phase_cb, us);
}

/*
 * Each phase starts by being called here, then waits for its connections
 * and checks, and schedules the next phase
 */

static void
wse_phase_cb(lws_sorted_usec_list_t *sul)
{
	struct wse_fconn *fconns = fanout < (int)LWS_ARRAY_SIZE(fanouts) ?
					fanout_conns[fanout] : NULL;
	struct wse_conn *c;
	size_t n;

	switch (phase) {
	case WSE_P_CORNER:
		for (n = 0; n < LWS_ARRAY_SIZE(corner_paths); n++)
			if (wse_connect(WSE_C_CORNER + (int)n, "corner",
					"lws-minimal", corner_paths[n]))
				return;
		/* give them all time to get whatever they will get */
		phase++;
		wse_schedule(LWS_US_PER_SEC);
		break;

	case WSE_P_CORNER_CHECK:
		for (n = 0; n < LWS_ARRAY_SIZE(corner_paths); n++) {
			c = &conns[WSE_C_CORNER + n];

			lwsl_user("corner %s: est %d, closed %d, msgs %d, "
				  "len %d\n", c->path, c->est, c->closed,
				  c->msgs, (int)c->last_len);

			if (!c->est || c->closed) {
				wse_fail("corner connection didn't stay up");
				return;
			}
			if (!n) {
				/* "/1": the first corner case only */
				if (c->msgs != 1 || !c->last_binary ||
				    c->last_len != 1012) {
					wse_fail("/1 didn't get its corner case");
					return;
				}
				continue;
			}
			if (c->msgs) {
				wse_fail("corner case sent for a bad URL");
				return;
			}
		}
		phase++;
		wse_schedule(1);
		break;

	case WSE_P_RELAY:
		lwsl_user("relay case %s\n", relays[relay].vhost_name);
		/* RX first, TX joins when RX is established */
		wse_relay_connect(WSE_R_RX);
		break;

	case WSE_P_RELAY_BIG:
		/* RX had all TX's messages a while ago: nothing else came */
		if (wse_relay_conn(WSE_R_RX)->msgs != WSE_M_COUNT) {
			wse_fail("something else was passed on");
			return;
		}
		wse_relay_connect(WSE_R_BIG);
		/* it moves us on when the server closes it */
		break;

	case WSE_P_RELAY_BAD:
		c = wse_relay_conn(WSE_R_BIG);
		if (c->close_code != LWS_CLOSE_STATUS_MESSAGE_TOO_LARGE) {
			lwsl_err("close code %d\n", c->close_code);
			wse_fail("too large message not refused");
			return;
		}
		wse_relay_connect(WSE_R_BAD);
		/* it moves us on when the server closes it */
		break;

	case WSE_P_RELAY_CHECK:
		c = wse_relay_conn(WSE_R_BAD);
		if (c->close_code != LWS_CLOSE_STATUS_INVALID_PAYLOAD) {
			lwsl_err("close code %d\n", c->close_code);
			wse_fail("invalid UTF-8 not refused");
			return;
		}
		c = wse_relay_conn(WSE_R_RX);
		if (c->msgs != WSE_M_COUNT || c->closed) {
			wse_fail("refused messages were passed on");
			return;
		}
		/* close this case's survivors, and on to the next case */
		if (c->wsi)
			lws_set_timeout(c->wsi, PENDING_TIMEOUT_USER_OK,
					LWS_TO_KILL_ASYNC);
		c = wse_relay_conn(WSE_R_TX);
		if (c->wsi)
			lws_set_timeout(c->wsi, PENDING_TIMEOUT_USER_OK,
					LWS_TO_KILL_ASYNC);
		if (++relay < (int)LWS_ARRAY_SIZE(relays))
			phase = WSE_P_RELAY;
		else
			phase++;
		wse_schedule(1);
		break;

	case WSE_P_FANOUT:
		lwsl_user("fan-out case %s\n", fanouts[fanout].vhost_name);
		/* the readers first, S joins when they are established */
		if (wse_fanout_connect(WSE_F_R1) ||
		    wse_fanout_connect(WSE_F_R2))
			return;
		phase++;
		break;

	case WSE_P_FANOUT_BURST:
		/* S's burst went to both readers, and K joins */
		if (!fconns[WSE_F_R1].burst || !fconns[WSE_F_R2].burst) {
			wse_fail("burst didn't reach the readers");
			return;
		}
		if (wse_fanout_connect(WSE_F_K))
			return;
		/* K stops reading when established, then S sends */
		phase++;
		break;

	case WSE_P_FANOUT_END:
		/* the stuck client should be gone by now: S sends the last */
		if (fconns[WSE_F_S].wsi)
			lws_callback_on_writable(fconns[WSE_F_S].wsi);
		break;

	case WSE_P_FANOUT_RELEASE:
		/* let K read again, so it sees it was closed */
		if (fconns[WSE_F_K].wsi)
			lws_rx_flow_control(fconns[WSE_F_K].wsi, 1);
		phase++;
		wse_schedule(LWS_US_PER_SEC);
		break;

	case WSE_P_FANOUT_CHECK:
		lwsl_user("fan-out %s: R1 %d / %d, R2 %d / %d, K closed %d\n",
			  fanouts[fanout].vhost_name, fconns[WSE_F_R1].burst,
			  fconns[WSE_F_R1].lag, fconns[WSE_F_R2].burst,
			  fconns[WSE_F_R2].lag, fconns[WSE_F_K].closed);
		if (!fconns[WSE_F_K].closed) {
			wse_fail("stuck client was not closed");
			return;
		}
		if (fconns[WSE_F_R1].closed || fconns[WSE_F_R2].closed ||
		    fconns[WSE_F_S].closed) {
			wse_fail("a client that kept up was closed");
			return;
		}
		for (n = 0; n < (size_t)WSE_F_COUNT; n++)
			if (fconns[n].wsi) {
				fconns[n].killed = 1;
				lws_set_timeout(fconns[n].wsi,
						PENDING_TIMEOUT_USER_OK,
						LWS_TO_KILL_ASYNC);
			}
		if (++fanout < (int)LWS_ARRAY_SIZE(fanouts))
			phase = WSE_P_FANOUT;
		else
			phase = WSE_P_PROXY;
		wse_schedule(200 * LWS_US_PER_MS);
		break;

	case WSE_P_PROXY:
		lwsl_user("raw proxy\n");
		wse_raw_proxy_backend(server_address, px.be_port);
		/* the backend says hello when both sides are up */
		if (wse_proxy_connect())
			return;
		break;

	case WSE_P_PROXY_HELD:
		lwsl_user("raw proxy: client sent %llu while backend not "
			  "reading\n", (unsigned long long)px.sent);
		if (px.sent >= WSE_PX_HELD) {
			wse_fail("proxy took the client's data without limit");
			return;
		}
		/* the backend reads again: everything must get through */
		phase++;
		lws_rx_flow_control(px.wsi_be, 1);
		break;

	case WSE_P_PROXY_CLOSE:
		if (!px.be_closed) {
			wse_fail("backend conn not closed after ws client");
			return;
		}
		/*
		 * Now nothing listens on the backend port: the next ws client
		 * finds no backend
		 */
		lws_vhost_destroy(px.vh_be);
		px.vh_be = NULL;
		phase++;
		wse_schedule(500 * LWS_US_PER_MS);
		break;

	case WSE_P_PROXY_NO_BACKEND:
		if (wse_proxy_connect())
			return;
		phase++;
		wse_schedule(3 * LWS_US_PER_SEC);
		break;

	case WSE_P_PROXY_NO_BACKEND_CHECK:
		if (!px.ws_est || !px.ws_closed) {
			wse_fail("ws client left open with no backend");
			return;
		}
		phase++;
		wse_schedule(1);
		break;

	case WSE_P_DONE:
		result = 0;
		interrupted = 1;
		lws_cancel_service(context);
		break;
	}
}

static void
wse_timeout_cb(lws_sorted_usec_list_t *sul)
{
	wse_fail("timed out");
}

/* the n'th message TX sends, as up to two fragments */

static int
wse_tx_msg(int n, int frag, const uint8_t **p, size_t *len,
	   enum lws_write_protocol *wp)
{
	size_t largest = *relays[relay].max_message;

	switch (n) {
	case WSE_M_SPLIT:
		if (!frag) {
			*p = (const uint8_t *)split1;
			*len = sizeof(split1) - 1;
			*wp = (enum lws_write_protocol)(LWS_WRITE_TEXT |
						    LWS_WRITE_NO_FIN);
			return 1; /* more to come */
		}
		*p = (const uint8_t *)split2;
		*len = sizeof(split2) - 1;
		*wp = LWS_WRITE_CONTINUATION;
		return 0;
	case WSE_M_EUROS:
		*p = euros;
		*len = sizeof(euros);
		*wp = LWS_WRITE_TEXT;
		return 0;
	case WSE_M_BINARY:
		*p = (const uint8_t *)binary;
		*len = sizeof(binary) - 1;
		*wp = LWS_WRITE_BINARY;
		return 0;
	case WSE_M_LARGEST:
		*p = NULL; /* 'a' * largest */
		*len = largest;
		*wp = LWS_WRITE_TEXT;
		return 0;
	}

	return -1;
}

/* does RX's latest whole message match what TX sent? */

static int
wse_rx_matches(struct wse_conn *c)
{
	size_t largest = *relays[relay].max_message;
	const uint8_t *p = NULL;
	size_t n;

	switch (c->msgs - 1) {
	case WSE_M_SPLIT:
		p = (const uint8_t *)split_whole;
		n = sizeof(split_whole) - 1;
		break;
	case WSE_M_EUROS:
		p = euros;
		n = sizeof(euros);
		break;
	case WSE_M_BINARY:
		if (!c->msg_binary)
			return 0;
		p = (const uint8_t *)binary;
		n = sizeof(binary) - 1;
		break;
	case WSE_M_LARGEST:
		if (c->msg_len != largest)
			return 0;
		for (n = 0; n < largest; n++)
			if (c->msg[n] != 'a')
				return 0;
		return !c->msg_binary;
	default:
		return 0;
	}

	if (c->msg_binary != (c->msgs - 1 == WSE_M_BINARY))
		return 0;

	return c->msg_len == n && !memcmp(c->msg, p, n);
}

static int
wse_tx_writeable(struct lws *wsi, struct wse_conn *c, int role)
{
	struct wse_conn *rx = wse_relay_conn(WSE_R_RX);
	enum lws_write_protocol wp;
	const uint8_t *p;
	size_t len;
	int more;

	switch (role) {
	case WSE_R_TX:
		/* one message at a time: wait for RX to have the last */
		if (c->tx_msg >= WSE_M_COUNT || c->tx_msg != rx->msgs)
			return 0;
		more = wse_tx_msg(c->tx_msg, c->tx_frag, &p, &len, &wp);
		break;

	case WSE_R_BIG:
		if (c->tx_msg++)
			return 0;
		p = NULL;
		len = *relays[relay].max_message + 1;
		wp = LWS_WRITE_TEXT;
		more = 0;
		break;

	case WSE_R_BAD:
		if (c->tx_msg++)
			return 0;
		p = (const uint8_t *)binary;
		len = sizeof(binary) - 1;
		wp = LWS_WRITE_TEXT;
		more = 0;
		break;

	default:
		return 0;
	}

	if (more < 0 || len > WSE_MSG_MAX)
		return -1;

	/* the client masks in place: refill txbuf every time */
	if (p)
		memcpy(txbuf + LWS_PRE, p, len);
	else
		memset(txbuf + LWS_PRE, 'a', len);

	if (lws_write(wsi, txbuf + LWS_PRE, len, wp) < (int)len)
		return -1;

	if (role != WSE_R_TX)
		return 0;

	if (more) {
		c->tx_frag++;
		lws_callback_on_writable(wsi);
	} else {
		c->tx_frag = 0;
		c->tx_msg++;
	}

	return 0;
}

static int
callback_wse_client(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct wse_conn *c = (struct wse_conn *)lws_get_opaque_user_data(wsi);
	int role;

	if (!c)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	role = wse_relay_role(c);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		c->est = 1;
		if (role == WSE_R_RX)
			/* TX joins now RX is there to hear him */
			wse_relay_connect(WSE_R_TX);
		else if (role > WSE_R_RX)
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		if (role > WSE_R_RX)
			return wse_tx_writeable(wsi, c, role);
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		if (lws_is_first_fragment(wsi)) {
			c->msg_len = 0;
			c->msg_binary = (char)lws_frame_is_binary(wsi);
			c->msg_overflow = 0;
		}
		if (len > sizeof(c->msg) - c->msg_len)
			c->msg_overflow = 1;
		else {
			memcpy(c->msg + c->msg_len, in, len);
			c->msg_len += len;
		}
		if (!lws_is_final_fragment(wsi))
			break;

		c->msgs++;
		c->last_len = c->msg_len;
		c->last_binary = c->msg_binary;
		if (c->msg_overflow) {
			wse_fail("message too large");
			break;
		}

		if (role != WSE_R_RX)
			break;

		if (!wse_rx_matches(c)) {
			lwsl_err("rx msg %d: len %d, binary %d\n", c->msgs,
				 (int)c->msg_len, c->msg_binary);
			lwsl_hexdump_err(c->msg, c->msg_len > 64 ? 64 :
							c->msg_len);
			wse_fail("RX got something other than TX sent");
			break;
		}

		if (c->msgs == WSE_M_COUNT) {
			/* give anything else passed on time to reach RX */
			phase = WSE_P_RELAY_BIG;
			wse_schedule(300 * LWS_US_PER_MS);
			break;
		}

		/* let TX send the next one */
		if (wse_relay_conn(WSE_R_TX)->wsi)
			lws_callback_on_writable(wse_relay_conn(WSE_R_TX)->wsi);
		break;

	case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
		if (len >= 2)
			c->close_code = (uint16_t)((((uint8_t *)in)[0] << 8) |
						    ((uint8_t *)in)[1]);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLIENT_CLOSED:
		c->closed = 1;
		c->wsi = NULL;
		/* after its message, the server hung up on BIG or BAD */
		if ((role == WSE_R_BIG && phase == WSE_P_RELAY_BIG) ||
		    (role == WSE_R_BAD && phase == WSE_P_RELAY_BAD)) {
			/* let anything passed on reach RX before we check */
			phase++;
			wse_schedule(300 * LWS_US_PER_MS);
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * Messages must arrive in order, and, from an example that slows senders down
 * instead of dropping, all of them.  burst and lag are the next we expect.
 */

static int
wse_fanout_seq(int *next, int n)
{
	if (n < *next || (fanouts[fanout].lossless && n != *next)) {
		lwsl_err("msg %d, expected %d\n", n, *next);
		return 1;
	}
	*next = n + 1;

	return 0;
}

static int
wse_fanout_rx(struct wse_fconn *c, int r, const char *in, size_t len)
{
	struct wse_fconn *fconns = fanout_conns[c->fo];

	if (len == 3 && in[0] == 'b') {
		if (wse_fanout_seq(&c->burst,
				   ((in[1] - '0') * 10) + (in[2] - '0')))
			return 1;
		if (fanouts[fanout].lossless && r == WSE_F_R2 &&
		    c->burst == WSE_F_BURST &&
		    fconns[WSE_F_R1].burst == WSE_F_BURST)
			wse_schedule(1);
		return 0;
	}

	if (len == WSE_F_LAG_LEN) {
		if (wse_fanout_seq(&c->lag, atoi(in)))
			return 1;
		if (fanouts[fanout].lossless && r == WSE_F_R1 &&
		    c->lag == WSE_F_LAG_MSGS) {
			/* everything got past the stuck client */
			phase = WSE_P_FANOUT_RELEASE;
			wse_schedule(1);
		}
		return 0;
	}

	if (len == 3 && !memcmp(in, "end", 3)) {
		c->rx_end = 1;
		if (r == WSE_F_R1 && phase == WSE_P_FANOUT_END) {
			/* the last message got past the stuck client */
			phase = WSE_P_FANOUT_RELEASE;
			wse_schedule(1);
		}
		return 0;
	}

	lwsl_err("unexpected message len %d\n", (int)len);

	return 1;
}

static int
callback_wse_fanout(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct wse_fconn *c = (struct wse_fconn *)lws_get_opaque_user_data(wsi),
			*fconns;
	int r, n;

	if (!c)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	fconns = fanout_conns[c->fo];
	r = (int)(c - fconns);

	if (c->fo != fanout) {
		/* a connection from a case that is over, being closed */
		if (reason == LWS_CALLBACK_CLIENT_CLOSED ||
		    reason == LWS_CALLBACK_CLIENT_CONNECTION_ERROR) {
			c->closed = 1;
			c->wsi = NULL;
		}
		return lws_callback_http_dummy(wsi, reason, user, in, len);
	}

	switch (reason) {
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		c->est = 1;
		switch (r) {
		case WSE_F_R1:
		case WSE_F_R2:
			/* S joins when both readers are there */
			if (fconns[WSE_F_R1].est && fconns[WSE_F_R2].est)
				wse_fanout_connect(WSE_F_S);
			break;
		case WSE_F_S:
			lws_callback_on_writable(wsi);
			break;
		case WSE_F_K:
			/* K never reads again, until we release it */
			lws_rx_flow_control(wsi, 0);
			lws_callback_on_writable(fconns[WSE_F_S].wsi);
			break;
		}
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		if (r != WSE_F_S)
			break;

		if (!c->tx_burst) {
			/*
			 * All the burst at once: the server is serviced by
			 * this same thread, so they all arrive before it
			 * gets to read any of them
			 */
			c->tx_burst = 1;
			for (n = 0; n < WSE_F_BURST; n++) {
				lws_snprintf((char *)txbuf + LWS_PRE, 4,
					     "b%02d", n);
				if (lws_write(wsi, txbuf + LWS_PRE, 3,
					      LWS_WRITE_TEXT) < 3)
					return -1;
			}
			if (!fanouts[fanout].lossless)
				/* what fitted has reached them by then */
				wse_schedule(500 * LWS_US_PER_MS);
			break;
		}

		if (phase == WSE_P_FANOUT_END) {
			if (c->tx_end)
				break;
			c->tx_end = 1;
			memcpy(txbuf + LWS_PRE, "end", 3);
			if (lws_write(wsi, txbuf + LWS_PRE, 3,
				      LWS_WRITE_TEXT) < 3)
				return -1;
			break;
		}

		if (phase != WSE_P_FANOUT_LAG || !fconns[WSE_F_K].est)
			break;

		if (c->tx == WSE_F_LAG_MSGS) {
			if (!fanouts[fanout].lossless) {
				/*
				 * The broker drops while K holds its ring
				 * full: after the lag limit, K must be gone
				 * and the last message get through
				 */
				phase = WSE_P_FANOUT_END;
				wse_schedule((*fanouts[fanout].lag_secs + 2) *
					     LWS_US_PER_SEC);
			}
			break;
		}

		memset(txbuf + LWS_PRE, 'x', WSE_F_LAG_LEN);
		n = lws_snprintf((char *)txbuf + LWS_PRE, 8, "%06d", c->tx);
		txbuf[LWS_PRE + n] = 'x';
		if (lws_write(wsi, txbuf + LWS_PRE, WSE_F_LAG_LEN,
			      LWS_WRITE_TEXT) < WSE_F_LAG_LEN)
			return -1;
		c->tx++;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		if (lws_is_first_fragment(wsi))
			c->msg_len = 0;
		if (len > sizeof(c->msg) - 1 - c->msg_len) {
			wse_fail("fan-out message too big");
			break;
		}
		memcpy(c->msg + c->msg_len, in, len);
		c->msg_len += len;
		if (!lws_is_final_fragment(wsi))
			break;
		c->msg[c->msg_len] = '\0';
		if (r != WSE_F_K && wse_fanout_rx(c, r, c->msg, c->msg_len))
			wse_fail("fan-out messages lost or out of order");
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLIENT_CLOSED:
		c->closed = 1;
		c->wsi = NULL;
		if (r != WSE_F_K && !c->killed)
			wse_fail("a client that kept up was closed");
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
callback_wse_proxy_client(struct lws *wsi, enum lws_callback_reasons reason,
			  void *user, void *in, size_t len)
{
	size_t n;

	if (!lws_get_opaque_user_data(wsi))
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		px.ws_est = 1;
		if (phase == WSE_P_PROXY_NO_BACKEND_CHECK) {
			/* something for the proxy to queue for nobody */
			lws_callback_on_writable(wsi);
			break;
		}
		if (px.wsi_be)
			lws_callback_on_writable(px.wsi_be);
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		if (!lws_frame_is_binary(wsi))
			px.not_binary = 1;
		if (len > sizeof(px.hello) - px.hello_len) {
			wse_fail("proxy client got too much");
			break;
		}
		memcpy(px.hello + px.hello_len, in, len);
		px.hello_len += len;
		if (px.hello_len < sizeof(px_hello) - 1)
			break;
		if (px.not_binary || memcmp(px.hello, px_hello,
					    sizeof(px_hello) - 1)) {
			wse_fail("backend's data didn't arrive as sent, BINARY");
			break;
		}
		/* now we flood it, while the backend isn't reading */
		phase = WSE_P_PROXY_HELD;
		lws_callback_on_writable(wsi);
		wse_schedule(2 * LWS_US_PER_SEC);
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		if (phase == WSE_P_PROXY_NO_BACKEND_CHECK) {
			memset(txbuf + LWS_PRE, 'x', 100);
			if (lws_write(wsi, txbuf + LWS_PRE, 100,
				      LWS_WRITE_BINARY) < 100)
				return -1;
			break;
		}
		if ((phase != WSE_P_PROXY_HELD && phase != WSE_P_PROXY_DRAIN) ||
		    px.sent == WSE_PX_TOTAL)
			break;
		/* the client masks in place: refill txbuf every time */
		for (n = 0; n < WSE_PX_FRAME; n++)
			txbuf[LWS_PRE + n] = wse_proxy_byte(px.sent + n);
		if (lws_write(wsi, txbuf + LWS_PRE, WSE_PX_FRAME,
			      LWS_WRITE_BINARY) < WSE_PX_FRAME)
			return -1;
		px.sent += WSE_PX_FRAME;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLIENT_CLOSED:
		px.ws_closed = 1;
		px.wsi_ws = NULL;
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* the raw server the proxy connects on to */

static int
callback_wse_backend(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	const uint8_t *p = (const uint8_t *)in;
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		if (px.wsi_be) {
			wse_fail("unexpected second backend connection");
			return -1;
		}
		px.wsi_be = wsi;
		px.be_closed = 0;
		/* we don't read until the flood has been held back */
		lws_rx_flow_control(wsi, 0);
		if (px.ws_est)
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		/* say hello in two pieces, split inside a character */
		if (px.be_tx == 2)
			break;
		if (!px.be_tx++) {
			memcpy(txbuf + LWS_PRE, px_hello1, sizeof(px_hello1) - 1);
			n = sizeof(px_hello1) - 1;
		} else {
			memcpy(txbuf + LWS_PRE, px_hello2, sizeof(px_hello2) - 1);
			n = sizeof(px_hello2) - 1;
		}
		if (lws_write(wsi, txbuf + LWS_PRE, n, LWS_WRITE_RAW) < (int)n)
			return -1;
		if (px.be_tx < 2)
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_RX:
		for (n = 0; n < len; n++)
			if (p[n] != wse_proxy_byte(px.be_rx + n)) {
				px.corrupt = 1;
				wse_fail("backend got corrupted data");
				return -1;
			}
		px.be_rx += len;
		if (px.be_rx == WSE_PX_TOTAL) {
			lwsl_user("raw proxy: backend got all %llu\n",
				  (unsigned long long)px.be_rx);
			/* the ws client goes, and so should we */
			phase = WSE_P_PROXY_CLOSE;
			if (px.wsi_ws)
				lws_set_timeout(px.wsi_ws,
						PENDING_TIMEOUT_USER_OK,
						LWS_TO_KILL_ASYNC);
			wse_schedule(LWS_US_PER_SEC);
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		px.be_closed = 1;
		px.wsi_be = NULL;
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_backend[] = {
	{ "wse-backend", callback_wse_backend, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "wse-client", callback_wse_client, 0, 0, 0, NULL, 0 },
	{ "wse-fanout-client", callback_wse_fanout, 0, 0, 0, NULL, 0 },
	{ "wse-proxy-client", callback_wse_proxy_client, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* one vhost per example, all on one port, chosen by Host: */

static const struct {
	const char			*vhost_name;
	const struct lws_protocols	*protocol;
} examples[] = {
	{ "corner",	&wse_protocol_pmd_corner },
	{ "chat",	&wse_protocol_chat },
	{ "pmd",	&wse_protocol_pmd },
	{ "ring",	&wse_protocol_ring },
	{ "broker",	&wse_protocol_broker },
};

static struct lws_protocols protocols_srv[LWS_ARRAY_SIZE(examples)][3];

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	uint64_t opts;
	size_t m;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_address = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: ws-server example protocols\n");

	/* 100 x "€" (e2 82 ac) */
	for (m = 0; m < sizeof(euros); m += 3) {
		euros[m] = 0xe2;
		euros[m + 1] = 0x82;
		euros[m + 2] = 0xac;
	}

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* there are no pvos to instantiate the protocols one by one */
	opts = info.options;
	info.options |= LWS_SERVER_OPTION_VH_INSTANTIATE_ALL_PROTOCOLS;
	info.port = port;

	for (m = 0; m < LWS_ARRAY_SIZE(examples); m++) {
		protocols_srv[m][0] = (struct lws_protocols){ "http",
				lws_callback_http_dummy, 0, 0, 0, NULL, 0 };
		protocols_srv[m][1] = *examples[m].protocol;
		protocols_srv[m][2] = (struct lws_protocols)
							LWS_PROTOCOL_LIST_TERM;

		info.vhost_name = examples[m].vhost_name;
		info.protocols = protocols_srv[m];
		if (!lws_create_vhost(context, &info)) {
			lwsl_err("Failed to create vhost %s\n",
				 examples[m].vhost_name);
			goto bail;
		}
	}

	/* the raw proxy example has two protocols */
	info.vhost_name = "proxy";
	info.protocols = wse_protocols_raw_proxy;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create proxy vhost\n");
		goto bail;
	}

	/* the raw server it proxies to, on a port of its own */
	info.options = opts | LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.port = 0;
	info.vhost_name = "backend";
	info.protocols = protocols_backend;
	info.listen_accept_role = "raw-skt";
	info.listen_accept_protocol = "wse-backend";
	px.vh_be = lws_create_vhost(context, &info);
	if (!px.vh_be) {
		lwsl_err("Failed to create backend vhost\n");
		goto bail;
	}
	px.be_port = lws_get_vhost_listen_port(px.vh_be);
	info.listen_accept_role = NULL;
	info.listen_accept_protocol = NULL;

	info.options = opts;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	wse_schedule(1);
	lws_sul_schedule(context, 0, &sul_timeout, wse_timeout_cb,
			 100 * LWS_US_PER_SEC);

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

bail:
	lws_context_destroy(context);

	if (failed)
		result = 1;

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
