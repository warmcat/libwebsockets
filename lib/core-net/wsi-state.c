/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * wsi role / state transition tables, trace and check.
 *
 * Only built with LWS_WITH_STATE_TRACE and / or LWS_WITH_STATE_CHECK, both
 * off by default.  Neither changes what any transition does; they observe
 * the setters in wsi.c, the only places wsistate and role_ops are written.
 *
 * The LRS states are the states of four machines, each in its own bits of
 * wsistate (see READMEs/README.wsi-state-machines.md):
 *
 *   transport   : getting a socket to the peer (dns, connect, proxy, socks,
 *                 tls handshake)
 *   carrier     : the protocol handshake on top of it (h1 request / reply,
 *                 h2 preface + settings, mqtt connack, the h1 upgrade
 *                 decision)
 *   transaction : the http request / response cycle and its file / body
 *                 phases
 *   close       : polite ws close, flush, staged shutdown, dead
 *
 * The tables are the observed transition set from the whole ctest suite and
 * the fuzz seed corpus (LWS_WITH_STATE_TRACE) plus the statically present
 * edges no test reaches, marked as such.  They are the specification of the
 * machines; LWS_WITH_STATE_CHECK aborts on any edge not listed, so an
 * unknown edge is either an omission here or a bug there.
 */

#include "private-lib-core.h"

const char * const lws_lrs_names[] = {
	[0] = "UNCONNECTED",
	[1] = "WAITING_DNS",
	[2] = "WAITING_CONNECT",
	[3] = "WAITING_PROXY_REPLY",
	[4] = "WAITING_SSL",
	[5] = "WAITING_SOCKS_GREETING_REPLY",
	[6] = "WAITING_SOCKS_CONNECT_REPLY",
	[7] = "WAITING_SOCKS_AUTH_REPLY",
	[8] = "SSL_INIT",
	[9] = "SSL_ACK_PENDING",
	[10] = "H1_UPGRADE",
	[11] = "WAITING_SERVER_REPLY",
	[12] = "H2_AWAIT_PREFACE",
	[13] = "H2_AWAIT_SETTINGS",
	[15] = "H2_WAITING_TO_SEND_HEADERS",
	[14] = "TXN_COMPLETED",
	[16] = "DEFERRING_ACTION",
	[17] = "IDLING",
	[18] = "H1C_ISSUE_HANDSHAKE",
	[19] = "H1C_ISSUE_HANDSHAKE2",
	[20] = "ISSUE_HTTP_BODY",
	[21] = "ISSUING_FILE",
	[22] = "HEADERS",
	[23] = "BODY",
	[24] = "DISCARD_BODY",
	[25] = "ESTABLISHED",
	[26] = "DOING_TRANSACTION",
	[27] = "WAITING_TO_SEND_CLOSE",
	[28] = "RETURNED_CLOSE",
	[29] = "AWAITING_CLOSE_ACK",
	[30] = "FLUSHING_BEFORE_CLOSE",
	[31] = "SHUTDOWN",
	[32] = "DEAD_SOCKET",
	[33] = "MQTTC_IDLE",
	[34] = "MQTTC_AWAIT_CONNACK",
	[35] = "AWAITING_FILE_READ",
	[36] = "AWAITING_SSL_ACCEPT",
};

/*
 * The state as lwsi_state() reports it, from a raw wsistate word: the close
 * machine's state if one is set, else the live state, with the role flags
 */

static lws_wsi_state_t
lws_wsi_state_of(lws_wsi_state_t w)
{
	return (w & (unsigned int)LWSI_ROLE_MASK) |
	       (lws_wsi_state_t)lwsi_state_of_word(w);
}

/* format a (role, wsistate) pair as role/side[e]:STATE */

void
lws_wsi_state_fmt(const struct lws_role_ops *ops, lws_wsi_state_t s,
		  char *buf, size_t len)
{
	lws_wsi_state_t w = s;
	unsigned int i;

	s = lws_wsi_state_of(s);
	i = s & 0xff;
	const char *name = "?";
	char tmp[16];

	if (!s)
		name = "(zero)";
	else if (i < LWS_ARRAY_SIZE(lws_lrs_names) && lws_lrs_names[i])
		name = lws_lrs_names[i];
	else {
		lws_snprintf(tmp, sizeof(tmp), "0x%x", (unsigned int)(s & LRS_MASK));
		name = tmp;
	}

	lws_snprintf(buf, len, "%s/%c%s:%s%s%s%s%s%s", ops ? ops->name : "(none)",
		     (s & LWSIFR_CLIENT) ? 'C' : ((s & LWSIFR_SERVER) ? 'S' : '-'),
		     (s & LWSI_ROLE_ENCAP_MASK) ? "e" : "", name,
		     ((w & LWSI_TRANSPORT_MASK) >> LWSI_TRANSPORT_SHIFT) ==
						LTS_FAILED ? "+failed" : "",
		     ((w & LWSI_TRANSPORT_MASK) >> LWSI_TRANSPORT_SHIFT) ==
						LTS_RESTARTING ? "+restarting" : "",
		     ((w & LWSI_CLOSE_MASK) >> LWSI_CLOSE_SHIFT) ==
						LCS_USER_TOLD ? "+told" : "",
		     (w & LWSIFS_TXN_COMPLETING) ? "+completing" : "",
		     (w & LWSIFS_SKT_UNUSABLE) ? "+unusable" : "");
}

#if defined(LWS_WITH_STATE_TRACE)

/*
 * Record every distinct (role, wsistate) -> (role, wsistate) edge this
 * process performs, one line per edge, appended to the file named by
 * $LWS_STATE_TRACE_FILE (stderr if unset).  Edges are written the first time
 * they are seen, so a run that is killed rather than destroyed still leaves
 * its edges behind.  Dedup is per-process and best-effort under threads.
 */

#define LWS_STATE_TRACE_MAX 4096

struct lws_state_trace_edge {
	const struct lws_role_ops	*from_ops;
	const struct lws_role_ops	*to_ops;
	lws_wsi_state_t			from;
	lws_wsi_state_t			to;
};

static struct lws_state_trace_edge lws_state_trace_edges[LWS_STATE_TRACE_MAX];
static unsigned int lws_state_trace_count;

static void
lws_wsi_state_trace(struct lws *wsi, const struct lws_role_ops *from_ops,
		    lws_wsi_state_t from, const struct lws_role_ops *to_ops,
		    lws_wsi_state_t to, const char *how)
{
	struct lws_state_trace_edge *e = lws_state_trace_edges;
	char a[64], b[64];
	const char *path;
	unsigned int n;
	FILE *f;

	for (n = 0; n < lws_state_trace_count; n++, e++)
		if (e->from == from && e->to == to &&
		    e->from_ops == from_ops && e->to_ops == to_ops)
			return;

	if (lws_state_trace_count >= LWS_STATE_TRACE_MAX)
		return;

	e->from_ops = from_ops;
	e->to_ops = to_ops;
	e->from = from;
	e->to = to;
	lws_state_trace_count++;

	lws_wsi_state_fmt(from_ops, from, a, sizeof(a));
	lws_wsi_state_fmt(to_ops, to, b, sizeof(b));

	path = getenv("LWS_STATE_TRACE_FILE");
	f = path ? fopen(path, "a") : stderr;
	if (!f)
		return;

	fprintf(f, "LRS %s -> %s %s %s\n", a, b, how, lws_wsi_tag(wsi));
	if (path)
		fclose(f);
	else
		fflush(f);
}
#endif

#if defined(LWS_WITH_STATE_CHECK)

enum lws_state_machine {
	LWSM_TRANSPORT,
	LWSM_CARRIER,
	LWSM_TRANSACTION,
	LWSM_CLOSE
};

static const uint8_t lws_lrs_machine[] = {
	[0] = LWSM_TRANSPORT,
	[1] = LWSM_TRANSPORT,
	[2] = LWSM_TRANSPORT,
	[3] = LWSM_TRANSPORT,
	[4] = LWSM_TRANSPORT,
	[5] = LWSM_TRANSPORT,
	[6] = LWSM_TRANSPORT,
	[7] = LWSM_TRANSPORT,
	[8] = LWSM_TRANSPORT,
	[9] = LWSM_TRANSPORT,
	[10] = LWSM_CARRIER,
	[11] = LWSM_CARRIER,
	[12] = LWSM_CARRIER,
	[13] = LWSM_CARRIER,
	[15] = LWSM_CARRIER,
	[14] = LWSM_TRANSACTION,
	[16] = LWSM_TRANSACTION,
	[17] = LWSM_TRANSACTION,
	[18] = LWSM_CARRIER,
	[19] = LWSM_CARRIER,
	[20] = LWSM_TRANSACTION,
	[21] = LWSM_TRANSACTION,
	[22] = LWSM_TRANSACTION,
	[23] = LWSM_TRANSACTION,
	[24] = LWSM_TRANSACTION,
	[25] = LWSM_TRANSACTION,
	[26] = LWSM_TRANSACTION,
	[27] = LWSM_CLOSE,
	[28] = LWSM_CLOSE,
	[29] = LWSM_CLOSE,
	[30] = LWSM_CLOSE,
	[31] = LWSM_CLOSE,
	[32] = LWSM_CLOSE,
	[33] = LWSM_CARRIER,
	[34] = LWSM_CARRIER,
	[35] = LWSM_TRANSACTION,
	[36] = LWSM_TRANSPORT,
};

static const char * const lws_state_machine_names[] = {
	"transport", "carrier", "transaction", "close"
};

static const char *
lws_state_machine_name(lws_wsi_state_t s)
{
	unsigned int i = lws_wsi_state_of(s) & 0xff;

	if (!s || i >= LWS_ARRAY_SIZE(lws_lrs_machine) || !lws_lrs_names[i])
		return "?";

	return lws_state_machine_names[lws_lrs_machine[i]];
}

#define ANY 0xffff

/*
 * Allowed edges where the role ops do not change.  role and side are the
 * role_ops name and C / S / - with a trailing e for h2-encapsulated, or "*".
 * from is an LRS state or ANY.
 *
 * The close machine can be entered from anywhere: a connection can die, be
 * flushed or be staged for shutdown from any state.  Within it, and for the
 * polite ws close, the edges are specific.
 */

struct lws_state_edge {
	const char		*role;
	const char		*side;
	uint16_t		from;
	uint16_t		to;
};

static const struct lws_state_edge lws_state_edges[] = {
	/* ---- edges into the transport machine ---- */

	{ "*", "C", LRS_UNCONNECTED, LRS_WAITING_CONNECT },
	{ "*", "C", LRS_UNCONNECTED, LRS_WAITING_DNS },
	{ "*", "C", LRS_WAITING_CONNECT, LRS_WAITING_PROXY_REPLY },
	{ "*", "C", LRS_WAITING_CONNECT, LRS_WAITING_SOCKS_GREETING_REPLY },
	{ "*", "C", LRS_WAITING_CONNECT, LRS_WAITING_SSL },
	{ "*", "C", LRS_WAITING_DNS, LRS_WAITING_CONNECT },
	{ "*", "C", LRS_WAITING_PROXY_REPLY, LRS_WAITING_SSL },
	{ "*", "C", LRS_WAITING_SOCKS_AUTH_REPLY, LRS_WAITING_SOCKS_CONNECT_REPLY },
	{ "*", "C", LRS_WAITING_SOCKS_CONNECT_REPLY, LRS_WAITING_SSL },
	{ "*", "C", LRS_WAITING_SOCKS_GREETING_REPLY, LRS_WAITING_SOCKS_AUTH_REPLY },
	{ "*", "C", LRS_WAITING_SOCKS_GREETING_REPLY, LRS_WAITING_SOCKS_CONNECT_REPLY },
	{ "*", "C", LRS_WAITING_SSL, LRS_WAITING_CONNECT },
	{ "*", "S", LRS_AWAITING_SSL_ACCEPT, LRS_SSL_ACK_PENDING },
	{ "*", "S", LRS_SSL_ACK_PENDING, LRS_AWAITING_SSL_ACCEPT },
	{ "*", "S", LRS_SSL_INIT, LRS_SSL_ACK_PENDING },
	{ "h1", "C", LRS_H1C_ISSUE_HANDSHAKE, LRS_WAITING_SSL },	/* carrier -> transport */

	/* ---- edges into the carrier machine ---- */

	{ "h1", "C", LRS_UNCONNECTED, LRS_H1C_ISSUE_HANDSHAKE2 },	/* transport -> carrier */
	{ "h1", "C", LRS_WAITING_CONNECT, LRS_H1C_ISSUE_HANDSHAKE },	/* transport -> carrier */
	{ "h1", "C", LRS_WAITING_SSL, LRS_WAITING_SERVER_REPLY },	/* transport -> carrier */
	{ "h1", "C", LRS_H1C_ISSUE_HANDSHAKE, LRS_WAITING_SERVER_REPLY },
	{ "h1", "C", LRS_H1C_ISSUE_HANDSHAKE2, LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "h1", "C", LRS_H1C_ISSUE_HANDSHAKE2, LRS_WAITING_SERVER_REPLY },
	{ "h1", "C", LRS_H2_WAITING_TO_SEND_HEADERS, LRS_H1C_ISSUE_HANDSHAKE2 },
	{ "h1", "C", LRS_ESTABLISHED, LRS_WAITING_SERVER_REPLY },	/* txn -> carrier */
	{ "h1", "C", LRS_ISSUE_HTTP_BODY, LRS_WAITING_SERVER_REPLY },	/* txn -> carrier */
	{ "h1", "S", LRS_ESTABLISHED, LRS_H1_UPGRADE },	/* txn -> carrier */
	{ "h1", "S", LRS_HEADERS, LRS_H1_UPGRADE },	/* txn -> carrier */
	{ "h2", "C", LRS_ISSUE_HTTP_BODY, LRS_WAITING_SERVER_REPLY },	/* txn -> carrier */
	{ "h2", "C", LRS_H2_WAITING_TO_SEND_HEADERS, LRS_WAITING_SERVER_REPLY }, /* bodyless request sent */
	{ "h2", "S", LRS_H2_AWAIT_PREFACE, LRS_H2_AWAIT_SETTINGS },
	{ "h3", "C", LRS_ESTABLISHED, LRS_WAITING_SERVER_REPLY },	/* txn -> carrier */
	{ "h3", "C", LRS_ISSUE_HTTP_BODY, LRS_WAITING_SERVER_REPLY },	/* txn -> carrier */
	{ "mqtt", "C", LRS_WAITING_CONNECT, LRS_MQTTC_IDLE },	/* transport -> carrier */
	{ "mqtt", "C", LRS_MQTTC_IDLE, LRS_MQTTC_AWAIT_CONNACK },

	/* ---- edges into the txn machine ---- */

	{ "h1", "C", LRS_WAITING_SSL, LRS_ISSUE_HTTP_BODY },	/* transport -> txn */
	{ "h1", "C", LRS_H1C_ISSUE_HANDSHAKE, LRS_ISSUE_HTTP_BODY },	/* carrier -> txn */
	{ "h1", "C", LRS_H1C_ISSUE_HANDSHAKE2, LRS_ISSUE_HTTP_BODY },	/* carrier -> txn */
	{ "h1", "C", LRS_ESTABLISHED, LRS_IDLING },
	{ "h1", "S", LRS_AWAITING_SSL_ACCEPT, LRS_HEADERS },	/* transport -> txn */
	{ "h1", "S", LRS_SSL_ACK_PENDING, LRS_HEADERS },	/* transport -> txn */
	{ "h1", "S", LRS_H1_UPGRADE, LRS_ESTABLISHED },	/* carrier -> txn */
	{ "h1", "S", LRS_AWAITING_FILE_READ, LRS_ISSUING_FILE },
	{ "h1", "S", LRS_BODY, LRS_TXN_COMPLETED },
	{ "h1", "S", LRS_BODY, LRS_DISCARD_BODY },
	{ "h1", "S", LRS_TXN_COMPLETED, LRS_HEADERS },
	{ "h1", "S", LRS_DISCARD_BODY, LRS_TXN_COMPLETED },
	{ "h1", "S", LRS_DOING_TRANSACTION, LRS_BODY },
	{ "h1", "S", LRS_DOING_TRANSACTION, LRS_TXN_COMPLETED },	/* keep-alive GET answered inside the HTTP callback */
	{ "h1", "S", LRS_ESTABLISHED, LRS_BODY },
	{ "h1", "S", LRS_ESTABLISHED, LRS_TXN_COMPLETED },
	{ "h1", "S", LRS_ESTABLISHED, LRS_DOING_TRANSACTION },
	{ "h1", "S", LRS_ESTABLISHED, LRS_ISSUING_FILE },
	{ "h1", "S", LRS_ISSUING_FILE, LRS_AWAITING_FILE_READ },
	{ "h1", "S", LRS_ISSUING_FILE, LRS_ESTABLISHED },
	{ "h2", "*", LRS_ESTABLISHED, LRS_BODY },
	{ "h2", "C", LRS_UNCONNECTED, LRS_ESTABLISHED },	/* client mux child born */
	{ "h2", "C", LRS_H2_WAITING_TO_SEND_HEADERS, LRS_ISSUE_HTTP_BODY },	/* carrier -> txn */
	{ "h2", "S", LRS_UNCONNECTED, LRS_HEADERS },
	{ "h2", "S", LRS_HEADERS, LRS_DEFERRING_ACTION },
	{ "h2", "S", LRS_HEADERS, LRS_DOING_TRANSACTION },	/* action run without deferring */	/* transport -> txn */
	{ "h2", "S", LRS_H2_AWAIT_SETTINGS, LRS_ESTABLISHED },	/* carrier -> txn */
	{ "h2", "S", LRS_AWAITING_FILE_READ, LRS_ISSUING_FILE },
	{ "h2", "S", LRS_BODY, LRS_ESTABLISHED },
	{ "h2", "S", LRS_DEFERRING_ACTION, LRS_ESTABLISHED },
	{ "h2", "S", LRS_ESTABLISHED, LRS_DEFERRING_ACTION },
	{ "h2", "S", LRS_ESTABLISHED, LRS_DOING_TRANSACTION },
	{ "h2", "S", LRS_ESTABLISHED, LRS_ISSUING_FILE },
	{ "h2", "S", LRS_ISSUING_FILE, LRS_AWAITING_FILE_READ },
	{ "h2", "S", LRS_ISSUING_FILE, LRS_ESTABLISHED },
	{ "h3", "C", LRS_ESTABLISHED, LRS_ISSUE_HTTP_BODY },
	{ "h3", "S", LRS_AWAITING_FILE_READ, LRS_ISSUING_FILE },
	{ "h3", "S", LRS_BODY, LRS_ESTABLISHED },
	{ "h3", "S", LRS_DEFERRING_ACTION, LRS_ESTABLISHED },
	{ "h3", "S", LRS_ESTABLISHED, LRS_BODY },
	{ "h3", "S", LRS_ESTABLISHED, LRS_DEFERRING_ACTION },
	{ "h3", "S", LRS_HEADERS, LRS_DEFERRING_ACTION },
	{ "h3", "S", LRS_ESTABLISHED, LRS_DOING_TRANSACTION },
	{ "h3", "S", LRS_ESTABLISHED, LRS_ISSUING_FILE },
	{ "h3", "S", LRS_ISSUING_FILE, LRS_AWAITING_FILE_READ },
	{ "h3", "S", LRS_ISSUING_FILE, LRS_ESTABLISHED },
	{ "mqtt", "C", LRS_MQTTC_AWAIT_CONNACK, LRS_ESTABLISHED },	/* carrier -> txn */
	{ "mqtt", "S", LRS_UNCONNECTED, LRS_ESTABLISHED },	/* transport -> txn */
	{ "quic", "C", LRS_WAITING_CONNECT, LRS_ESTABLISHED },	/* transport -> txn */
	{ "quic", "C", LRS_WAITING_SSL, LRS_ESTABLISHED },	/* transport -> txn */
	{ "quic", "S", LRS_SSL_INIT, LRS_ESTABLISHED },	/* transport -> txn */
	{ "raw-skt", "C", LRS_WAITING_CONNECT, LRS_ESTABLISHED },	/* transport -> txn */

	/* ---- edges into the close machine ---- */

	{ "*", "*", ANY, LRS_DEAD_SOCKET },
	{ "*", "*", ANY, LRS_FLUSHING_BEFORE_CLOSE },
	{ "*", "*", ANY, LRS_SHUTDOWN },
	{ "h1", "S", LRS_SHUTDOWN, LRS_DEAD_SOCKET },
	{ "h2", "S", LRS_SHUTDOWN, LRS_DEAD_SOCKET },
	{ "h3", "S", LRS_FLUSHING_BEFORE_CLOSE, LRS_DEAD_SOCKET },
	{ "ws", "*", LRS_RETURNED_CLOSE, LRS_FLUSHING_BEFORE_CLOSE },
	{ "ws", "C", LRS_ESTABLISHED, LRS_WAITING_TO_SEND_CLOSE },	/* txn -> close */
	{ "ws", "C", LRS_AWAITING_CLOSE_ACK, LRS_DEAD_SOCKET },
	{ "ws", "C", LRS_FLUSHING_BEFORE_CLOSE, LRS_DEAD_SOCKET },
	{ "ws", "C", LRS_WAITING_TO_SEND_CLOSE, LRS_AWAITING_CLOSE_ACK },
	{ "ws", "Ce", LRS_ESTABLISHED, LRS_WAITING_TO_SEND_CLOSE },	/* txn -> close */
	{ "ws", "Ce", LRS_AWAITING_CLOSE_ACK, LRS_DEAD_SOCKET },
	{ "ws", "Ce", LRS_RETURNED_CLOSE, LRS_DEAD_SOCKET },
	{ "ws", "Ce", LRS_WAITING_TO_SEND_CLOSE, LRS_AWAITING_CLOSE_ACK },
	{ "ws", "Ce", LRS_WAITING_TO_SEND_CLOSE, LRS_DEAD_SOCKET },
	{ "ws", "*", LRS_ESTABLISHED, LRS_RETURNED_CLOSE },	/* peer's CLOSE, we answer */	/* txn -> close */
	{ "ws", "S", LRS_ESTABLISHED, LRS_WAITING_TO_SEND_CLOSE },	/* txn -> close */
	{ "ws", "S", LRS_AWAITING_CLOSE_ACK, LRS_SHUTDOWN },
	{ "ws", "S", LRS_FLUSHING_BEFORE_CLOSE, LRS_SHUTDOWN },
	{ "ws", "S", LRS_SHUTDOWN, LRS_DEAD_SOCKET },
	{ "ws", "S", LRS_WAITING_TO_SEND_CLOSE, LRS_AWAITING_CLOSE_ACK },
	{ "ws", "S", LRS_WAITING_TO_SEND_CLOSE, LRS_DEAD_SOCKET },
	{ "ws", "Se", LRS_ESTABLISHED, LRS_WAITING_TO_SEND_CLOSE },	/* txn -> close */
	{ "ws", "Se", LRS_AWAITING_CLOSE_ACK, LRS_DEAD_SOCKET },
	{ "ws", "Se", LRS_RETURNED_CLOSE, LRS_DEAD_SOCKET },
	{ "ws", "Se", LRS_WAITING_TO_SEND_CLOSE, LRS_AWAITING_CLOSE_ACK },


	/*
	 * Present in the code but not reached by ctest or the fuzz seeds; each
	 * cites the site.  Confirm and move into the observed groups above when
	 * a test reaches them.
	 */
	{ "*",    "C", LRS_WAITING_DNS, LRS_UNCONNECTED },		/* connect3.c dns retry */
	{ "h1",   "C", LRS_WAITING_CONNECT, LRS_H1C_ISSUE_HANDSHAKE2 },	/* connect4.c sync tls */
	{ "h1",   "C", LRS_WAITING_SSL, LRS_H1C_ISSUE_HANDSHAKE2 },	/* connect4.c sync tls */
	{ "h1",   "C", LRS_ESTABLISHED, LRS_H1C_ISSUE_HANDSHAKE2 },	/* pipeline restart, digest retry */
	{ "h1",   "C", LRS_IDLING, LRS_H1C_ISSUE_HANDSHAKE2 },		/* pipeline restart from idle */
	{ "h1",   "C", LRS_WAITING_SERVER_REPLY, LRS_H1C_ISSUE_HANDSHAKE2 }, /* client-http.c digest retry */
	{ "h1",   "S", LRS_SSL_INIT, LRS_HEADERS },			/* tls-server.c notls_accepted */
	{ "h2",   "C", LRS_IDLING, LRS_ESTABLISHED },			/* vhost.c revive idle mux conn */
	{ "h3",   "C", LRS_IDLING, LRS_ESTABLISHED },			/* vhost.c revive idle mux conn */
	{ "mqtt", "C", LRS_WAITING_SSL, LRS_MQTTC_IDLE },		/* client-mqtt.c mqtts */
	{ "raw-skt", "C", LRS_WAITING_SOCKS_CONNECT_REPLY, LRS_ESTABLISHED }, /* ops-raw-skt.c socks5 */
};

/*
 * Allowed edges where the role ops or the side changes: adoption, client
 * connect, h1 -> h2 / ws upgrade, quic -> h3, the client's sid-1 migration,
 * and the redirect / fallback restart from DEAD_SOCKET.
 */

struct lws_role_edge {
	const char		*from_role;
	const char		*from_side;
	uint16_t		from;
	const char		*to_role;
	const char		*to_side;
	uint16_t		to;
};

static const struct lws_role_edge lws_role_edges[] = {
	{ "(none)", "-", 0, "(none)", "-", LRS_UNCONNECTED },
	{ "(none)", "-", 0, "h3", "-", LRS_UNCONNECTED },
	{ "(none)", "-", 0, "listen", "-", LRS_UNCONNECTED },
	{ "(none)", "-", 0, "netlink", "-", LRS_UNCONNECTED },
	{ "(none)", "-", 0, "pipe", "-", LRS_UNCONNECTED },
	{ "(none)", "-", 0, "raw-file", "-", LRS_UNCONNECTED },
	{ "(none)", "-", LRS_UNCONNECTED, "h1", "C", LRS_UNCONNECTED },
	{ "(none)", "-", LRS_UNCONNECTED, "mqtt", "C", LRS_UNCONNECTED },
	{ "(none)", "-", LRS_UNCONNECTED, "quic", "C", LRS_UNCONNECTED },
	{ "(none)", "-", LRS_UNCONNECTED, "raw-skt", "C", LRS_UNCONNECTED },
	{ "(none)", "S", LRS_UNCONNECTED, "h1", "S", LRS_HEADERS },
	{ "(none)", "S", LRS_UNCONNECTED, "h1", "S", LRS_SSL_INIT },
	{ "(none)", "S", LRS_UNCONNECTED, "h2", "S", LRS_H2_AWAIT_PREFACE },
	{ "(none)", "S", LRS_UNCONNECTED, "h2", "S", LRS_UNCONNECTED },
	{ "(none)", "S", LRS_UNCONNECTED, "h3", "C", LRS_ESTABLISHED },
	{ "(none)", "S", LRS_UNCONNECTED, "h3", "S", LRS_HEADERS },	/* request stream */
	{ "(none)", "S", LRS_UNCONNECTED, "h3", "S", LRS_ESTABLISHED },	/* our unidi control streams */
	{ "(none)", "S", LRS_UNCONNECTED, "mqtt", "S", LRS_UNCONNECTED },
	{ "(none)", "S", LRS_UNCONNECTED, "quic", "C", LRS_ESTABLISHED },
	{ "(none)", "S", LRS_UNCONNECTED, "quic", "S", LRS_ESTABLISHED },
	{ "(none)", "S", LRS_UNCONNECTED, "quic", "S", LRS_SSL_INIT },
	{ "(none)", "S", LRS_UNCONNECTED, "quic", "S", LRS_UNCONNECTED },
	{ "(none)", "S", LRS_UNCONNECTED, "raw-skt", "-", LRS_ESTABLISHED },
	{ "h1", "C", LRS_H1C_ISSUE_HANDSHAKE, "h2", "C", LRS_H2_AWAIT_PREFACE },
	{ "h1", "C", LRS_H1C_ISSUE_HANDSHAKE2, "h2", "C", LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "h1", "C", LRS_UNCONNECTED, "h2", "C", LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "h1", "C", LRS_UNCONNECTED, "quic", "C", LRS_UNCONNECTED },
	{ "h1", "C", LRS_WAITING_SERVER_REPLY, "h1", "C", LRS_ESTABLISHED },
	{ "h1", "C", LRS_WAITING_SERVER_REPLY, "ws", "C", LRS_ESTABLISHED },
	{ "h1", "C", LRS_WAITING_SSL, "h2", "C", LRS_H2_AWAIT_PREFACE },
	{ "h1", "S", LRS_HEADERS, "h2", "S", LRS_H2_AWAIT_PREFACE },	/* tls accept, alpn h2 */
	{ "h1", "S", LRS_H1_UPGRADE, "h2", "S", LRS_H2_AWAIT_PREFACE },
	{ "h1", "S", LRS_H1_UPGRADE, "ws", "S", LRS_ESTABLISHED },
	{ "h2", "C", LRS_ESTABLISHED, "h2", "C", LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "h2", "C", LRS_WAITING_SERVER_REPLY, "ws", "Ce", LRS_ESTABLISHED },
	{ "h2", "C", LRS_H2_AWAIT_PREFACE, "h2", "C", LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "h2", "C", LRS_WAITING_SERVER_REPLY, "h2", "C", LRS_ESTABLISHED },
	{ "h2", "S", LRS_UNCONNECTED, "h2", "C", LRS_UNCONNECTED },	/* client mux child takes its side before its state */
	{ "h2", "S", LRS_ESTABLISHED, "ws", "Se", LRS_ESTABLISHED },
	{ "h3", "C", LRS_H2_WAITING_TO_SEND_HEADERS, "h3", "C", LRS_ESTABLISHED },
	{ "h3", "C", LRS_WAITING_SERVER_REPLY, "h3", "C", LRS_ESTABLISHED },
	{ "mqtt", "S", LRS_ESTABLISHED, "mqtt", "C", LRS_ESTABLISHED },
	{ "quic", "C", LRS_ESTABLISHED, "h3", "C", LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "quic", "C", LRS_UNCONNECTED, "h3", "C", LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "quic", "S", LRS_ESTABLISHED, "h3", "S", LRS_HEADERS },	/* alpn h3: this wsi is request stream 0 */
	{ "quic", "S", LRS_UNCONNECTED, "h3", "C", LRS_ESTABLISHED },
	{ "quic", "S", LRS_UNCONNECTED, "h3", "S", LRS_HEADERS },
	{ "raw-file", "-", LRS_UNCONNECTED, "raw-file", "-", LRS_ESTABLISHED },
	{ "raw-skt", "S", LRS_ESTABLISHED, "raw-skt", "-", LRS_ESTABLISHED },

	/* present in the code but not reached by ctest or the fuzz seeds */
	{ "*",  "C", LRS_DEAD_SOCKET, "h1", "C", LRS_UNCONNECTED },	/* close.c redirect / fallback restart */
	{ "(none)", "*", LRS_UNCONNECTED, "raw-file", "-", LRS_ESTABLISHED }, /* ops-raw-file.c adoption bind: dir-notify, stdin */
	{ "h1", "C", LRS_UNCONNECTED, "h3", "C", LRS_H2_WAITING_TO_SEND_HEADERS }, /* lws_wsi_h3_adopt() */
	{ "h3", "*", LRS_ESTABLISHED, "wt", "*", LRS_ESTABLISHED },	/* ops-h3.c webtransport session */
};

static void
lws_state_side(lws_wsi_state_t s, char *side)
{
	side[0] = (s & LWSIFR_CLIENT) ? 'C' : ((s & LWSIFR_SERVER) ? 'S' : '-');
	side[1] = (s & LWSI_ROLE_ENCAP_MASK) ? 'e' : '\0';
	side[2] = '\0';
}

static int
lws_state_match(const char *want, const char *have)
{
	return !strcmp(want, "*") || !strcmp(want, have);
}

static int
lws_state_edge_allowed(const struct lws_role_ops *ops, lws_wsi_state_t from,
		       lws_wsi_state_t to)
{
	const char *role = ops ? ops->name : "(none)";
	const struct lws_state_edge *e = lws_state_edges;
	char side[3];
	unsigned int n;

	from = lws_wsi_state_of(from);
	to = lws_wsi_state_of(to);
	lws_state_side(to, side);

	for (n = 0; n < LWS_ARRAY_SIZE(lws_state_edges); n++, e++)
		if (e->to == (to & LRS_MASK) &&
		    (e->from == ANY || e->from == (from & LRS_MASK)) &&
		    lws_state_match(e->role, role) &&
		    lws_state_match(e->side, side))
			return 1;

	return 0;
}

static int
lws_role_edge_allowed(const struct lws_role_ops *from_ops, lws_wsi_state_t from,
		      const struct lws_role_ops *to_ops, lws_wsi_state_t to)
{
	const char *fr = from_ops ? from_ops->name : "(none)",
		   *tr = to_ops ? to_ops->name : "(none)";
	const struct lws_role_edge *e = lws_role_edges;
	char fside[3], tside[3];
	unsigned int n;

	from = lws_wsi_state_of(from);
	to = lws_wsi_state_of(to);
	lws_state_side(from, fside);
	lws_state_side(to, tside);

	for (n = 0; n < LWS_ARRAY_SIZE(lws_role_edges); n++, e++)
		if (e->to == (to & LRS_MASK) &&
		    (e->from == ANY || e->from == (from & LRS_MASK)) &&
		    lws_state_match(e->from_role, fr) &&
		    lws_state_match(e->to_role, tr) &&
		    lws_state_match(e->from_side, fside) &&
		    lws_state_match(e->to_side, tside))
			return 1;

	return 0;
}

/*
 * Invariants on entry to close states, from the close machine review.
 * Returns a description of the violated one, or NULL.
 */

static const char *
lws_state_invariant(struct lws *wsi, lws_wsi_state_t to)
{
	/*
	 * An unusable socket takes the abortive path: it may be flushed or
	 * declared dead, but never enters the polite close states
	 */
	if (to & LWSIFS_SKT_UNUSABLE)
		switch (lws_wsi_state_of(to) & LRS_MASK) {
		case LRS_WAITING_TO_SEND_CLOSE:
		case LRS_RETURNED_CLOSE:
		case LRS_AWAITING_CLOSE_ACK:
		case LRS_SHUTDOWN:
			return "polite close state entered with the socket unusable";
		default:
			break;
		}

	if (((to & LWSI_TRANSPORT_MASK) >> LWSI_TRANSPORT_SHIFT) ==
							LTS_RESTARTING &&
	    !(to & LWSIFR_CLIENT))
		return "RESTARTING on a non-client wsi";

	switch (lws_wsi_state_of(to) & LRS_MASK) {
	case LRS_RETURNED_CLOSE:
		if (!lwsi_role_ws(wsi))
			return "RETURNED_CLOSE on a non-ws role";
		break;
	case LRS_SHUTDOWN:
		if (to & LWSIFR_CLIENT)
			return "SHUTDOWN staging on a client wsi";
		if (wsi->role_ops == &role_ops_raw_skt)
			return "SHUTDOWN staging on a raw socket";
		if (!lws_socket_is_valid(wsi->desc.sockfd))
			return "SHUTDOWN staging without a socket";
		break;
	default:
		break;
	}

	return NULL;
}

static void
lws_wsi_state_check(struct lws *wsi, const struct lws_role_ops *from_ops,
		    lws_wsi_state_t from, const struct lws_role_ops *to_ops,
		    lws_wsi_state_t to, const char *how)
{
	const char *why = NULL;
	char a[64], b[64];
	int ok;

	/*
	 * lwsi_set_state() edges live in the state table; lws_role_transition()
	 * and lwsi_set_role() edges in the role table, even when the ops or
	 * side turn out unchanged, since the tables were derived that way
	 */
	if (!strcmp(how, "set_transport") &&
	    (((to & LWSI_TRANSPORT_MASK) >> LWSI_TRANSPORT_SHIFT) == LTS_FAILED ||
	     ((to & LWSI_TRANSPORT_MASK) >> LWSI_TRANSPORT_SHIFT) == LTS_RESTARTING))
		/*
		 * a connect can be reported failed from any phase, and a client
		 * can be retargeted (redirect, auth retry, fallback) from any
		 */
		ok = 1;
	else if (!strcmp(how, "set_state") || !strcmp(how, "set_close") ||
		 !strcmp(how, "set_transport"))
		ok = lws_state_edge_allowed(to_ops, from, to);
	else
		ok = lws_role_edge_allowed(from_ops, from, to_ops, to);

	if (ok)
		why = lws_state_invariant(wsi, to);

	if (ok && !why)
		return;

	lws_wsi_state_fmt(from_ops, from, a, sizeof(a));
	lws_wsi_state_fmt(to_ops, to, b, sizeof(b));

	lwsl_wsi_err(wsi, "%s wsi state edge %s -> %s (%s, %s -> %s)%s%s",
		     ok ? "invariant broken on" : "unlisted", a, b, how,
		     lws_state_machine_name(from), lws_state_machine_name(to),
		     why ? ": " : "", why ? why : "");

	abort();
}
#endif

/*
 * Called from the three setters in wsi.c after the new state is in place
 */

void
lws_wsi_state_changed(struct lws *wsi, const struct lws_role_ops *from_ops,
		      lws_wsi_state_t from, const struct lws_role_ops *to_ops,
		      lws_wsi_state_t to, const char *how)
{
	int attr_only = lws_wsi_state_of(from) == lws_wsi_state_of(to) &&
			from_ops == to_ops;

	/*
	 * the terminal sub-phases FAILED and USER_TOLD report the same state
	 * as what they follow, so they show in the trace as attributes
	 */
	if (attr_only && !((from ^ to) & (LWSIFS_ATTR_MASK | LWSI_CLOSE_MASK |
					   LWSI_TRANSPORT_MASK)))
		return;

#if defined(LWS_WITH_STATE_TRACE)
	lws_wsi_state_trace(wsi, from_ops, from, to_ops, to, how);
#endif
#if defined(LWS_WITH_STATE_CHECK)
	/* only an attribute changed: no edge to check */
	if (!attr_only)
		lws_wsi_state_check(wsi, from_ops, from, to_ops, to, how);
#endif
}
