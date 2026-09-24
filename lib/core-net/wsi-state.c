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
 * wsi state machines: the event table that drives the carrier and
 * transaction machines, and (with LWS_WITH_STATE_TRACE / LWS_WITH_STATE_CHECK,
 * both off by default) the trace and the check of every transition against
 * the per-machine tables.  The trace and check observe the setters in wsi.c,
 * the only places wsistate and role_ops are written, and change nothing.
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
	const char *name;
	unsigned int i;
	char tmp[16];

	s = lws_wsi_state_of(s);
	i = s & 0xff;

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

const char * const lws_wsi_event_names[LWS_WSIEV_COUNT] = {
	[LWS_WSIEV_TRANSPORT_UP]	= "TRANSPORT_UP",
	[LWS_WSIEV_H2_PREFACE_RX]	= "H2_PREFACE_RX",
	[LWS_WSIEV_H2_SETTINGS_ACKED]	= "H2_SETTINGS_ACKED",
	[LWS_WSIEV_REQ_HDRS_COMPLETE]	= "REQ_HDRS_COMPLETE",
	[LWS_WSIEV_REQ_PLAIN_HTTP]	= "REQ_PLAIN_HTTP",
	[LWS_WSIEV_ACTION_DEFERRED_RUN]	= "ACTION_DEFERRED_RUN",
	[LWS_WSIEV_ACTION_BEGIN]	= "ACTION_BEGIN",
	[LWS_WSIEV_BODY_BEGIN]		= "BODY_BEGIN",
	[LWS_WSIEV_BODY_COMPLETE]	= "BODY_COMPLETE",
	[LWS_WSIEV_BODY_DISCARD]	= "BODY_DISCARD",
	[LWS_WSIEV_TXN_COMPLETED]	= "TXN_COMPLETED",
	[LWS_WSIEV_TXN_DRAINED]		= "TXN_DRAINED",
	[LWS_WSIEV_FILE_BEGIN]		= "FILE_BEGIN",
	[LWS_WSIEV_FILE_READ_QUEUED]	= "FILE_READ_QUEUED",
	[LWS_WSIEV_FILE_READ_DONE]	= "FILE_READ_DONE",
	[LWS_WSIEV_FILE_COMPLETE]	= "FILE_COMPLETE",
	[LWS_WSIEV_SOCKET_CONNECTED]	= "SOCKET_CONNECTED",
	[LWS_WSIEV_QUEUED]		= "QUEUED",
	[LWS_WSIEV_REQ_ISSUE]		= "REQ_ISSUE",
	[LWS_WSIEV_REQ_HDRS_SENT]	= "REQ_HDRS_SENT",
	[LWS_WSIEV_REQ_HDRS_SENT_BODY]	= "REQ_HDRS_SENT_BODY",
	[LWS_WSIEV_REQ_BODY_SENT]	= "REQ_BODY_SENT",
	[LWS_WSIEV_RESP_INTERIM]	= "RESP_INTERIM",
	[LWS_WSIEV_CONN_REUSED]		= "CONN_REUSED",
	[LWS_WSIEV_LAST_STREAM_CLOSED]	= "LAST_STREAM_CLOSED",
	[LWS_WSIEV_MQTT_CONNECT_SENT]	= "MQTT_CONNECT_SENT",
	[LWS_WSIEV_MQTT_CONNACK]	= "MQTT_CONNACK",
	[LWS_WSIEV_SERVER_SIDE]		= "SERVER_SIDE",
	[LWS_WSIEV_ADOPTED]		= "ADOPTED",
	[LWS_WSIEV_ADOPTED_TLS]		= "ADOPTED_TLS",
	[LWS_WSIEV_CLIENT_BIND]		= "CLIENT_BIND",
	[LWS_WSIEV_RESTART]		= "RESTART",
	[LWS_WSIEV_MUX_INSERTED]	= "MUX_INSERTED",
	[LWS_WSIEV_STREAM_OPENED]	= "STREAM_OPENED",
	[LWS_WSIEV_MUX_STREAM_ADOPTED]	= "MUX_STREAM_ADOPTED",
	[LWS_WSIEV_CONTROL_STREAM_OPENED] = "CONTROL_STREAM_OPENED",
	[LWS_WSIEV_CONN_TAKEOVER]	= "CONN_TAKEOVER",
	[LWS_WSIEV_ALPN_DONE]		= "ALPN_DONE",
	[LWS_WSIEV_H2_SELECTED]		= "H2_SELECTED",
	[LWS_WSIEV_H2_PREFACE_SENT]	= "H2_PREFACE_SENT",
	[LWS_WSIEV_WS_UPGRADED]		= "WS_UPGRADED",
	[LWS_WSIEV_RESP_HDRS]		= "RESP_HDRS",
	[LWS_WSIEV_WT_SESSION]		= "WT_SESSION",
	[LWS_WSIEV_WT_STREAM]		= "WT_STREAM",
	[LWS_WSIEV_RAW_UPGRADED]	= "RAW_UPGRADED",
	[LWS_WSIEV_MUX_MIGRATED]	= "MUX_MIGRATED",
	[LWS_WSIEV_DNS_START]		= "DNS_START",
	[LWS_WSIEV_DNS_RETRY]		= "DNS_RETRY",
	[LWS_WSIEV_CONNECT_START]	= "CONNECT_START",
	[LWS_WSIEV_PROXY_CONNECT_SENT]	= "PROXY_CONNECT_SENT",
	[LWS_WSIEV_SOCKS_GREETING_SENT]	= "SOCKS_GREETING_SENT",
	[LWS_WSIEV_SOCKS_AUTH_SENT]	= "SOCKS_AUTH_SENT",
	[LWS_WSIEV_SOCKS_CONNECT_SENT]	= "SOCKS_CONNECT_SENT",
	[LWS_WSIEV_TLS_START]		= "TLS_START",
	[LWS_WSIEV_TLS_ACCEPT_PENDING]	= "TLS_ACCEPT_PENDING",
	[LWS_WSIEV_TLS_ACCEPT_QUEUED]	= "TLS_ACCEPT_QUEUED",
	[LWS_WSIEV_CONN_FAILED]		= "CONN_FAILED",
	[LWS_WSIEV_RETARGET]		= "RETARGET",
	[LWS_WSIEV_WS_CLOSE_INITIATED]	= "WS_CLOSE_INITIATED",
	[LWS_WSIEV_WS_CLOSE_SENT]	= "WS_CLOSE_SENT",
	[LWS_WSIEV_WS_PEER_CLOSE]	= "WS_PEER_CLOSE",
	[LWS_WSIEV_CLOSE_FLUSH]		= "CLOSE_FLUSH",
	[LWS_WSIEV_CLOSE_STAGED]	= "CLOSE_STAGED",
	[LWS_WSIEV_SOCKET_GONE]		= "SOCKET_GONE",
	[LWS_WSIEV_USER_TOLD]		= "USER_TOLD",
};

#define ANY 0xffff

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

/*
 * The transition function of the carrier and transaction machines, and of
 * every role change after a wsi's birth: what state, role and side an event
 * lands a connection in, by role, side and current state.  role and side
 * are the role_ops name and C / S / - with a trailing e for h2-encapsulated,
 * or "*"; from is the state lwsi_state() reports or ANY.  to_role is NULL
 * for no role change, "?" for the ops the site passed, "P" for the mux
 * parent's, else a role name; to_side is NULL for no change, "P" for the
 * mux parent's, "L" for that of the wsi the site passed as like, else
 * C / S / - / Ce / Se.  A site that passes ops only matches rows that take
 * them ("?" or their name).  The first matching row wins, so a role's own
 * row goes before a "*" one.  A to of XT(phase) or XC(phase) sets the
 * transport or close machine's phase instead of the live state: those two
 * machines run in their own bits, over whatever the others were doing.
 *
 * A (role, side, state, event) with no row is a bug at the site that
 * raised it: lws_wsi_event() leaves the state alone and returns -1, and
 * aborts with LWS_WITH_STATE_CHECK.
 */

struct lws_wsi_event_edge {
	const char		*role;
	const char		*side;
	uint16_t		from;
	uint8_t			ev;
	const char		*to_role;
	const char		*to_side;
	uint16_t		to;
};

#define XT(lts) (0x8000 | (lts))	/* to: a transport phase */
#define XC(lcs) (0x4000 | (lcs))	/* to: a close phase */

static const struct lws_wsi_event_edge lws_wsi_event_edges[] = {
	/*
	 * the transport finished: a server starts on the request, an h1 client
	 * on sending one, an mqtt client on its CONNECT, the rest are up
	 */
	{ "h1", "C", LRS_UNCONNECTED,		LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_H1C_ISSUE_HANDSHAKE2 }, /* inherited from an idle leader */
	{ "h1", "C", LRS_WAITING_SSL,		LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_H1C_ISSUE_HANDSHAKE2 },
	{ "h1", "C", LRS_WAITING_CONNECT,	LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_H1C_ISSUE_HANDSHAKE2 },
	{ "h1", "C", LRS_H1C_ISSUE_HANDSHAKE,	LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_H1C_ISSUE_HANDSHAKE2 },
	{ "h1", "C", LRS_H1C_ISSUE_HANDSHAKE2,	LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_H1C_ISSUE_HANDSHAKE2 },
	{ "h1", "C", LRS_H2_WAITING_TO_SEND_HEADERS, LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "h2", "C", LRS_H2_WAITING_TO_SEND_HEADERS, LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "mqtt", "C", LRS_UNCONNECTED,		LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_MQTTC_IDLE },
	{ "mqtt", "C", LRS_WAITING_CONNECT,	LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_MQTTC_IDLE },
	{ "mqtt", "C", LRS_WAITING_SSL,		LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_MQTTC_IDLE },
	{ "mqtt", "C", LRS_WAITING_SOCKS_CONNECT_REPLY, LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_MQTTC_IDLE },
	{ "raw-skt", "C", LRS_WAITING_CONNECT,	LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_ESTABLISHED },
	{ "raw-skt", "C", LRS_WAITING_SSL,	LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_ESTABLISHED },
	{ "raw-skt", "C", LRS_WAITING_SOCKS_CONNECT_REPLY, LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_ESTABLISHED },
	/* the raw proxy's onward connections are raw clients too */
	{ "raw-proxy", "C", LRS_WAITING_CONNECT,	LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_ESTABLISHED },
	{ "raw-proxy", "C", LRS_WAITING_SSL,	LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_ESTABLISHED },
	{ "raw-proxy", "C", LRS_WAITING_SOCKS_CONNECT_REPLY, LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_ESTABLISHED },
	{ "quic", "C", LRS_WAITING_SSL,		LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_ESTABLISHED },
	{ "quic", "C", LRS_WAITING_CONNECT,	LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_ESTABLISHED },
	{ "quic", "S", LRS_SSL_INIT,		LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_ESTABLISHED },
	{ "h1", "S", LRS_SSL_ACK_PENDING,	LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_HEADERS },
	{ "h1", "S", LRS_AWAITING_SSL_ACCEPT,	LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_HEADERS },
	{ "h1", "S", LRS_SSL_INIT,		LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_HEADERS },
	{ "*",  "S", LRS_SSL_ACK_PENDING,	LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_ESTABLISHED },
	{ "*",  "S", LRS_AWAITING_SSL_ACCEPT,	LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_ESTABLISHED },
	{ "*",  "S", LRS_SSL_INIT,		LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_ESTABLISHED },
	/* the non-tls fallback already established the wsi before the accept path reports the transport up */
	{ "*", "S", LRS_ESTABLISHED,		LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_ESTABLISHED },
	/* 0-RTT: the ALPN migration ran inside the handshake, so handshake-done finds the new nwsi established */
	{ "quic", "*", LRS_ESTABLISHED,		LWS_WSIEV_TRANSPORT_UP, NULL, NULL, LRS_ESTABLISHED },

	/* an h1 client's tcp is up before its tls */
	{ "h1", "C", LRS_WAITING_CONNECT,	LWS_WSIEV_SOCKET_CONNECTED, NULL, NULL, LRS_H1C_ISSUE_HANDSHAKE },
	/* the socks tunnel coming up is the socket connecting, for the protocol */
	{ "h1", "C", LRS_WAITING_SOCKS_CONNECT_REPLY, LWS_WSIEV_SOCKET_CONNECTED, NULL, NULL, LRS_H1C_ISSUE_HANDSHAKE },
	{ "h1", "C", LRS_H1C_ISSUE_HANDSHAKE2,	LWS_WSIEV_SOCKET_CONNECTED, NULL, NULL, LRS_H1C_ISSUE_HANDSHAKE2 },

	/* a client request queued on, or issued by, a connection */
	/* any client role may queue behind a leader: raw-skt and mqtt do too */
	{ "*", "C", LRS_UNCONNECTED,		LWS_WSIEV_QUEUED, NULL, NULL, LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "*", "C", LRS_H1C_ISSUE_HANDSHAKE2,	LWS_WSIEV_QUEUED, NULL, NULL, LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "h1", "C", LRS_H2_WAITING_TO_SEND_HEADERS, LWS_WSIEV_REQ_ISSUE, NULL, NULL, LRS_H1C_ISSUE_HANDSHAKE2 },
	{ "quic", "C", LRS_H2_WAITING_TO_SEND_HEADERS, LWS_WSIEV_REQ_ISSUE, NULL, NULL, LRS_H1C_ISSUE_HANDSHAKE2 }, /* h3 queue pickup */
	{ "h1", "C", LRS_ESTABLISHED,		LWS_WSIEV_REQ_ISSUE, NULL, NULL, LRS_H1C_ISSUE_HANDSHAKE2 },
	{ "h1", "C", LRS_IDLING,		LWS_WSIEV_REQ_ISSUE, NULL, NULL, LRS_H1C_ISSUE_HANDSHAKE2 },
	{ "h1", "C", LRS_WAITING_SERVER_REPLY,	LWS_WSIEV_REQ_ISSUE, NULL, NULL, LRS_H1C_ISSUE_HANDSHAKE2 },

	/* the request goes out, then its response is pending */
	{ "h1", "C", LRS_WAITING_SSL,		LWS_WSIEV_REQ_HDRS_SENT, NULL, NULL, LRS_WAITING_SERVER_REPLY },
	{ "h1", "C", LRS_WAITING_CONNECT,	LWS_WSIEV_REQ_HDRS_SENT, NULL, NULL, LRS_WAITING_SERVER_REPLY },
	{ "h1", "C", LRS_WAITING_PROXY_REPLY,	LWS_WSIEV_REQ_HDRS_SENT, NULL, NULL, LRS_WAITING_SERVER_REPLY },
	{ "h1", "C", LRS_H1C_ISSUE_HANDSHAKE,	LWS_WSIEV_REQ_HDRS_SENT, NULL, NULL, LRS_WAITING_SERVER_REPLY },
	{ "h1", "C", LRS_H1C_ISSUE_HANDSHAKE2,	LWS_WSIEV_REQ_HDRS_SENT, NULL, NULL, LRS_WAITING_SERVER_REPLY },
	{ "h2", "C", LRS_H2_WAITING_TO_SEND_HEADERS, LWS_WSIEV_REQ_HDRS_SENT, NULL, NULL, LRS_WAITING_SERVER_REPLY },
	{ "h3", "C", LRS_H2_WAITING_TO_SEND_HEADERS, LWS_WSIEV_REQ_HDRS_SENT, NULL, NULL, LRS_WAITING_SERVER_REPLY },
	{ "h1", "C", LRS_WAITING_SSL,		LWS_WSIEV_REQ_HDRS_SENT_BODY, NULL, NULL, LRS_ISSUE_HTTP_BODY },
	{ "h1", "C", LRS_WAITING_CONNECT,	LWS_WSIEV_REQ_HDRS_SENT_BODY, NULL, NULL, LRS_ISSUE_HTTP_BODY },
	{ "h1", "C", LRS_WAITING_PROXY_REPLY,	LWS_WSIEV_REQ_HDRS_SENT_BODY, NULL, NULL, LRS_ISSUE_HTTP_BODY },
	{ "h1", "C", LRS_H1C_ISSUE_HANDSHAKE,	LWS_WSIEV_REQ_HDRS_SENT_BODY, NULL, NULL, LRS_ISSUE_HTTP_BODY },
	{ "h1", "C", LRS_H1C_ISSUE_HANDSHAKE2,	LWS_WSIEV_REQ_HDRS_SENT_BODY, NULL, NULL, LRS_ISSUE_HTTP_BODY },
	{ "h2", "C", LRS_H2_WAITING_TO_SEND_HEADERS, LWS_WSIEV_REQ_HDRS_SENT_BODY, NULL, NULL, LRS_ISSUE_HTTP_BODY },
	{ "h3", "C", LRS_H2_WAITING_TO_SEND_HEADERS, LWS_WSIEV_REQ_HDRS_SENT_BODY, NULL, NULL, LRS_ISSUE_HTTP_BODY },
	{ "*",  "C", LRS_ISSUE_HTTP_BODY,	LWS_WSIEV_REQ_BODY_SENT, NULL, NULL, LRS_WAITING_SERVER_REPLY },
	{ "h1", "C", LRS_ESTABLISHED,		LWS_WSIEV_RESP_INTERIM, NULL, NULL, LRS_WAITING_SERVER_REPLY },

	/* the response is done: idle, or an idle connection is picked up */
	{ "h1", "C", LRS_ESTABLISHED,		LWS_WSIEV_TXN_COMPLETED, NULL, NULL, LRS_IDLING },
	{ "*",  "C", LRS_IDLING,		LWS_WSIEV_TXN_COMPLETED, NULL, NULL, LRS_IDLING },
	{ "h2", "C", LRS_ESTABLISHED,		LWS_WSIEV_LAST_STREAM_CLOSED, NULL, NULL, LRS_IDLING },
	{ "quic", "C", LRS_ESTABLISHED,		LWS_WSIEV_LAST_STREAM_CLOSED, NULL, NULL, LRS_IDLING },
	{ "h2", "C", LRS_IDLING,		LWS_WSIEV_CONN_REUSED, NULL, NULL, LRS_ESTABLISHED },
	{ "quic", "C", LRS_IDLING,		LWS_WSIEV_CONN_REUSED, NULL, NULL, LRS_ESTABLISHED },

	/* mqtt client handshake */
	{ "mqtt", "C", LRS_MQTTC_IDLE,		LWS_WSIEV_MQTT_CONNECT_SENT, NULL, NULL, LRS_MQTTC_AWAIT_CONNACK },
	{ "mqtt", "C", LRS_MQTTC_AWAIT_CONNACK,	LWS_WSIEV_MQTT_CONNACK, NULL, NULL, LRS_ESTABLISHED },

	/* h2 connection preface */
	{ "h2", "S", LRS_H2_AWAIT_PREFACE,	LWS_WSIEV_H2_PREFACE_RX, NULL, NULL, LRS_H2_AWAIT_SETTINGS },
	{ "h2", "S", LRS_H2_AWAIT_SETTINGS,	LWS_WSIEV_H2_SETTINGS_ACKED, NULL, NULL, LRS_ESTABLISHED },

	/* request headers: h1 decides on the upgrade, mux streams defer the action */
	{ "h1", "S", LRS_HEADERS,		LWS_WSIEV_REQ_HDRS_COMPLETE, NULL, NULL, LRS_H1_UPGRADE },
	{ "h1", "S", LRS_ESTABLISHED,		LWS_WSIEV_REQ_HDRS_COMPLETE, NULL, NULL, LRS_H1_UPGRADE },
	{ "h2", "S", LRS_HEADERS,		LWS_WSIEV_REQ_HDRS_COMPLETE, NULL, NULL, LRS_DEFERRING_ACTION },
	{ "h2", "S", LRS_ESTABLISHED,		LWS_WSIEV_REQ_HDRS_COMPLETE, NULL, NULL, LRS_DEFERRING_ACTION },
	{ "h3", "S", LRS_HEADERS,		LWS_WSIEV_REQ_HDRS_COMPLETE, NULL, NULL, LRS_DEFERRING_ACTION },
	{ "h3", "S", LRS_ESTABLISHED,		LWS_WSIEV_REQ_HDRS_COMPLETE, NULL, NULL, LRS_DEFERRING_ACTION },
	{ "h1", "S", LRS_H1_UPGRADE,		LWS_WSIEV_REQ_PLAIN_HTTP, NULL, NULL, LRS_ESTABLISHED },
	{ "h2", "S", LRS_DEFERRING_ACTION,	LWS_WSIEV_ACTION_DEFERRED_RUN, NULL, NULL, LRS_ESTABLISHED },
	{ "h3", "S", LRS_DEFERRING_ACTION,	LWS_WSIEV_ACTION_DEFERRED_RUN, NULL, NULL, LRS_ESTABLISHED },

	/* acting on the request */
	{ "h1", "S", LRS_ESTABLISHED,		LWS_WSIEV_ACTION_BEGIN, NULL, NULL, LRS_DOING_TRANSACTION },
	{ "h2", "S", LRS_HEADERS,		LWS_WSIEV_ACTION_BEGIN, NULL, NULL, LRS_DOING_TRANSACTION },
	{ "h2", "S", LRS_ESTABLISHED,		LWS_WSIEV_ACTION_BEGIN, NULL, NULL, LRS_DOING_TRANSACTION },
	{ "h3", "S", LRS_HEADERS,		LWS_WSIEV_ACTION_BEGIN, NULL, NULL, LRS_DOING_TRANSACTION },
	{ "h3", "S", LRS_ESTABLISHED,		LWS_WSIEV_ACTION_BEGIN, NULL, NULL, LRS_DOING_TRANSACTION },

	/* request body */
	{ "h1", "S", LRS_ESTABLISHED,		LWS_WSIEV_BODY_BEGIN, NULL, NULL, LRS_BODY },
	{ "h1", "S", LRS_DOING_TRANSACTION,	LWS_WSIEV_BODY_BEGIN, NULL, NULL, LRS_BODY },
	{ "h2", "*", LRS_ESTABLISHED,		LWS_WSIEV_BODY_BEGIN, NULL, NULL, LRS_BODY },
	{ "h2", "*", LRS_HEADERS,		LWS_WSIEV_BODY_BEGIN, NULL, NULL, LRS_BODY },
	{ "h3", "*", LRS_ESTABLISHED,		LWS_WSIEV_BODY_BEGIN, NULL, NULL, LRS_BODY },
	{ "h3", "S", LRS_DOING_TRANSACTION,	LWS_WSIEV_BODY_BEGIN, NULL, NULL, LRS_BODY }, /* action ran, body follows: as h1 */
	{ "h2", "S", LRS_DOING_TRANSACTION,	LWS_WSIEV_BODY_BEGIN, NULL, NULL, LRS_BODY }, /* same on h2 */
	{ "h2", "S", LRS_BODY,			LWS_WSIEV_BODY_COMPLETE, NULL, NULL, LRS_ESTABLISHED },
	{ "h3", "S", LRS_BODY,			LWS_WSIEV_BODY_COMPLETE, NULL, NULL, LRS_ESTABLISHED },
	/* the body completion callback may itself have started serving a file (C-522) */
	{ "h2", "S", LRS_ISSUING_FILE,		LWS_WSIEV_BODY_COMPLETE, NULL, NULL, LRS_ISSUING_FILE },
	{ "h3", "S", LRS_ISSUING_FILE,		LWS_WSIEV_BODY_COMPLETE, NULL, NULL, LRS_ISSUING_FILE },
	{ "h2", "S", LRS_AWAITING_FILE_READ,	LWS_WSIEV_BODY_COMPLETE, NULL, NULL, LRS_AWAITING_FILE_READ },
	{ "h3", "S", LRS_AWAITING_FILE_READ,	LWS_WSIEV_BODY_COMPLETE, NULL, NULL, LRS_AWAITING_FILE_READ },
	{ "h1", "S", LRS_BODY,			LWS_WSIEV_BODY_DISCARD, NULL, NULL, LRS_DISCARD_BODY },
	/* the user may complete the transaction before the body was ever delivered */
	{ "h1", "S", LRS_ESTABLISHED,		LWS_WSIEV_BODY_DISCARD, NULL, NULL, LRS_DISCARD_BODY },
	{ "h1", "S", LRS_DOING_TRANSACTION,	LWS_WSIEV_BODY_DISCARD, NULL, NULL, LRS_DISCARD_BODY },
	{ "h1", "S", LRS_H1_UPGRADE,		LWS_WSIEV_BODY_DISCARD, NULL, NULL, LRS_DISCARD_BODY },
	{ "h1", "S", LRS_ISSUING_FILE,		LWS_WSIEV_BODY_DISCARD, NULL, NULL, LRS_DISCARD_BODY },
	/* the completion runs for mux streams too: there DISCARD_BODY drops the stash and closes the stream */
	{ "h2", "S", LRS_ESTABLISHED,		LWS_WSIEV_BODY_DISCARD, NULL, NULL, LRS_DISCARD_BODY },
	{ "h2", "S", LRS_DOING_TRANSACTION,	LWS_WSIEV_BODY_DISCARD, NULL, NULL, LRS_DISCARD_BODY },
	{ "h2", "S", LRS_DEFERRING_ACTION,	LWS_WSIEV_BODY_DISCARD, NULL, NULL, LRS_DISCARD_BODY },
	{ "h3", "S", LRS_ESTABLISHED,		LWS_WSIEV_BODY_DISCARD, NULL, NULL, LRS_DISCARD_BODY },
	{ "h3", "S", LRS_DOING_TRANSACTION,	LWS_WSIEV_BODY_DISCARD, NULL, NULL, LRS_DISCARD_BODY },
	{ "h3", "S", LRS_DEFERRING_ACTION,	LWS_WSIEV_BODY_DISCARD, NULL, NULL, LRS_DISCARD_BODY },
	{ "h2", "S", LRS_HEADERS,		LWS_WSIEV_BODY_DISCARD, NULL, NULL, LRS_DISCARD_BODY },
	{ "h3", "S", LRS_HEADERS,		LWS_WSIEV_BODY_DISCARD, NULL, NULL, LRS_DISCARD_BODY },
	{ "h2", "S", LRS_BODY,			LWS_WSIEV_BODY_DISCARD, NULL, NULL, LRS_DISCARD_BODY },
	{ "h3", "S", LRS_BODY,			LWS_WSIEV_BODY_DISCARD, NULL, NULL, LRS_DISCARD_BODY },
	{ "h2", "S", LRS_ISSUING_FILE,		LWS_WSIEV_BODY_DISCARD, NULL, NULL, LRS_DISCARD_BODY },
	{ "h3", "S", LRS_ISSUING_FILE,		LWS_WSIEV_BODY_DISCARD, NULL, NULL, LRS_DISCARD_BODY },

	/* the h1 transaction ends and the connection is reused */
	{ "h1", "S", LRS_ESTABLISHED,		LWS_WSIEV_TXN_COMPLETED, NULL, NULL, LRS_TXN_COMPLETED },
	{ "h1", "S", LRS_BODY,			LWS_WSIEV_TXN_COMPLETED, NULL, NULL, LRS_TXN_COMPLETED },
	{ "h1", "S", LRS_DISCARD_BODY,		LWS_WSIEV_TXN_COMPLETED, NULL, NULL, LRS_TXN_COMPLETED },
	{ "h1", "S", LRS_DOING_TRANSACTION,	LWS_WSIEV_TXN_COMPLETED, NULL, NULL, LRS_TXN_COMPLETED },
	{ "h1", "S", LRS_H1_UPGRADE,		LWS_WSIEV_TXN_COMPLETED, NULL, NULL, LRS_TXN_COMPLETED }, /* upgrade refused */
	{ "h1", "S", LRS_TXN_COMPLETED,		LWS_WSIEV_TXN_COMPLETED, NULL, NULL, LRS_TXN_COMPLETED },
	{ "h1", "S", LRS_ISSUING_FILE,		LWS_WSIEV_TXN_COMPLETED, NULL, NULL, LRS_TXN_COMPLETED }, /* completed from the file-complete callback */
	{ "h1", "S", LRS_TXN_COMPLETED,		LWS_WSIEV_TXN_DRAINED, NULL, NULL, LRS_HEADERS },

	/* serving a file */
	{ "*",  "S", LRS_ESTABLISHED,		LWS_WSIEV_FILE_BEGIN, NULL, NULL, LRS_ISSUING_FILE },
	{ "h2", "S", LRS_HEADERS,		LWS_WSIEV_FILE_BEGIN, NULL, NULL, LRS_ISSUING_FILE },	/* h2c upgrade stream 1 */
	{ "*",  "S", LRS_DOING_TRANSACTION,	LWS_WSIEV_FILE_BEGIN, NULL, NULL, LRS_ISSUING_FILE },
	{ "*",  "S", LRS_BODY,			LWS_WSIEV_FILE_BEGIN, NULL, NULL, LRS_ISSUING_FILE },	/* served from HTTP_BODY_COMPLETION */
	{ "h1", "S", LRS_H1_UPGRADE,		LWS_WSIEV_FILE_BEGIN, NULL, NULL, LRS_ISSUING_FILE },	/* served from HTTP_CONFIRM_UPGRADE */
	{ "*",  "S", LRS_ISSUING_FILE,		LWS_WSIEV_FILE_READ_QUEUED, NULL, NULL, LRS_AWAITING_FILE_READ },
	{ "*",  "S", LRS_AWAITING_FILE_READ,	LWS_WSIEV_FILE_READ_DONE, NULL, NULL, LRS_ISSUING_FILE },
	{ "*",  "S", LRS_ISSUING_FILE,		LWS_WSIEV_FILE_COMPLETE, NULL, NULL, LRS_ESTABLISHED },

	/* ---- role changes ---- */

	/* birth on a server, adoption, the client bind, a restart */
	{ "(none)", "-", LRS_UNCONNECTED,	LWS_WSIEV_SERVER_SIDE, NULL, "S", LRS_UNCONNECTED },
	{ "*", "*", LRS_UNCONNECTED,		LWS_WSIEV_ADOPTED_TLS, "?", NULL, LRS_SSL_INIT },
	{ "*", "*", LRS_UNCONNECTED,		LWS_WSIEV_ADOPTED, "h1", NULL, LRS_HEADERS },
	{ "*", "*", LRS_UNCONNECTED,		LWS_WSIEV_ADOPTED, "?", NULL, LRS_ESTABLISHED },
	{ "*", "*", LRS_UNCONNECTED,		LWS_WSIEV_CLIENT_BIND, "?", "C", LRS_UNCONNECTED },
	{ "*", "C", ANY,			LWS_WSIEV_RESTART, "?", "C", LRS_UNCONNECTED },

	/* mux children: a fresh child is its parent's; a server's opened stream reads its request */
	{ "(none)", "*", LRS_UNCONNECTED,	LWS_WSIEV_MUX_INSERTED, "P", "P", LRS_UNCONNECTED },
	{ "h2", "S", LRS_UNCONNECTED,		LWS_WSIEV_STREAM_OPENED, NULL, NULL, LRS_HEADERS },
	{ "h2", "C", LRS_UNCONNECTED,		LWS_WSIEV_STREAM_OPENED, NULL, NULL, LRS_UNCONNECTED },
	{ "quic", "S", LRS_UNCONNECTED,		LWS_WSIEV_STREAM_OPENED, "h3", NULL, LRS_HEADERS },
	{ "quic", "C", LRS_UNCONNECTED,		LWS_WSIEV_STREAM_OPENED, "h3", NULL, LRS_ESTABLISHED },
	{ "quic", "*", LRS_UNCONNECTED,		LWS_WSIEV_STREAM_OPENED, "quic", NULL, LRS_ESTABLISHED },

	/* a client stream is let onto its connection: h2 / h3 send a request, mqtt is up */
	{ "*", "*", LRS_UNCONNECTED,		LWS_WSIEV_MUX_STREAM_ADOPTED, "h2", "P", LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "*", "*", LRS_H1C_ISSUE_HANDSHAKE2,	LWS_WSIEV_MUX_STREAM_ADOPTED, "h2", "P", LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "*", "*", LRS_H2_WAITING_TO_SEND_HEADERS, LWS_WSIEV_MUX_STREAM_ADOPTED, "h2", "P", LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "*", "*", LRS_UNCONNECTED,		LWS_WSIEV_MUX_STREAM_ADOPTED, "h3", "P", LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "*", "*", LRS_H1C_ISSUE_HANDSHAKE2,	LWS_WSIEV_MUX_STREAM_ADOPTED, "h3", "P", LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "*", "*", LRS_WAITING_CONNECT,	LWS_WSIEV_MUX_STREAM_ADOPTED, "h3", "P", LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "*", "*", LRS_WAITING_SSL,		LWS_WSIEV_MUX_STREAM_ADOPTED, "h3", "P", LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "*", "*", LRS_H2_WAITING_TO_SEND_HEADERS, LWS_WSIEV_MUX_STREAM_ADOPTED, "h3", "P", LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "*", "*", LRS_UNCONNECTED,		LWS_WSIEV_MUX_STREAM_ADOPTED, "mqtt", "P", LRS_ESTABLISHED },
	{ "*", "*", LRS_H2_WAITING_TO_SEND_HEADERS, LWS_WSIEV_MUX_STREAM_ADOPTED, "mqtt", "P", LRS_ESTABLISHED },
	{ "*", "*", LRS_ESTABLISHED,		LWS_WSIEV_MUX_STREAM_ADOPTED, "mqtt", "P", LRS_ESTABLISHED },

	/* our own h3 unidirectional streams, and a wsi taking over a quic connection */
	{ "(none)", "*", LRS_UNCONNECTED,	LWS_WSIEV_CONTROL_STREAM_OPENED, "h3", "L", LRS_ESTABLISHED },
	{ "(none)", "*", LRS_UNCONNECTED,	LWS_WSIEV_CONN_TAKEOVER, "?", "L", LRS_ESTABLISHED },

	/* the quic handshake chose h3 (a client stream sends, a server stream reads) or not */
	{ "*", "C", LRS_UNCONNECTED,		LWS_WSIEV_ALPN_DONE, "h3", NULL, LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "*", "C", LRS_WAITING_CONNECT,	LWS_WSIEV_ALPN_DONE, "h3", NULL, LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "quic", "C", ANY,			LWS_WSIEV_ALPN_DONE, "h3", NULL, LRS_H2_WAITING_TO_SEND_HEADERS },
	{ "quic", "S", ANY,			LWS_WSIEV_ALPN_DONE, "h3", NULL, LRS_HEADERS },
	{ "quic", "*", ANY,			LWS_WSIEV_ALPN_DONE, "quic", NULL, LRS_ESTABLISHED },

	/*
	 * the h2 client nwsi hands its own request to the sid-1 child and is
	 * from then on the carrier of streams only: established
	 */
	{ "h2", "C", LRS_H2_WAITING_TO_SEND_HEADERS, LWS_WSIEV_MUX_MIGRATED, NULL, NULL, LRS_ESTABLISHED },

	/* h2: chosen by alpn, h2c upgrade or prior knowledge; the client preface */
	{ "h1", "S", LRS_HEADERS,		LWS_WSIEV_H2_SELECTED, "h2", NULL, LRS_H2_AWAIT_PREFACE },
	{ "h1", "S", LRS_H1_UPGRADE,		LWS_WSIEV_H2_SELECTED, "h2", NULL, LRS_H2_AWAIT_PREFACE },
	{ "(none)", "S", LRS_UNCONNECTED,	LWS_WSIEV_H2_SELECTED, "h2", NULL, LRS_H2_AWAIT_PREFACE },
	{ "h1", "C", LRS_H1C_ISSUE_HANDSHAKE,	LWS_WSIEV_H2_SELECTED, "h2", NULL, LRS_H2_AWAIT_PREFACE },
	{ "h1", "C", LRS_WAITING_SSL,		LWS_WSIEV_H2_SELECTED, "h2", NULL, LRS_H2_AWAIT_PREFACE },
	{ "h1", "C", LRS_UNCONNECTED,		LWS_WSIEV_H2_SELECTED, "h2", NULL, LRS_H2_AWAIT_PREFACE },
	{ "h2", "C", LRS_H2_AWAIT_PREFACE,	LWS_WSIEV_H2_PREFACE_SENT, NULL, NULL, LRS_H2_WAITING_TO_SEND_HEADERS },

	/* ws upgrade, on a server from the upgrade decision, on a client from the 101 */
	{ "h1", "S", LRS_H1_UPGRADE,		LWS_WSIEV_WS_UPGRADED, "ws", NULL, LRS_ESTABLISHED },
	{ "h2", "S", LRS_ESTABLISHED,		LWS_WSIEV_WS_UPGRADED, "ws", "Se", LRS_ESTABLISHED },
	{ "h3", "S", LRS_ESTABLISHED,		LWS_WSIEV_WS_UPGRADED, "ws", "Se", LRS_ESTABLISHED }, /* RFC 9220 */
	{ "h1", "C", LRS_WAITING_SERVER_REPLY,	LWS_WSIEV_WS_UPGRADED, "ws", NULL, LRS_ESTABLISHED },
	{ "h2", "C", LRS_WAITING_SERVER_REPLY,	LWS_WSIEV_WS_UPGRADED, "ws", "Ce", LRS_ESTABLISHED },

	/* the client's response headers; webtransport; raw */
	{ "*", "C", LRS_WAITING_SERVER_REPLY,	LWS_WSIEV_RESP_HDRS, NULL, NULL, LRS_ESTABLISHED },
	/* a server may answer before the request body is finished (401, 413...) */
	{ "*", "C", LRS_ISSUE_HTTP_BODY,	LWS_WSIEV_RESP_HDRS, NULL, NULL, LRS_ESTABLISHED },
	{ "h3", "C", LRS_WAITING_SERVER_REPLY,	LWS_WSIEV_WT_SESSION, "wt", NULL, LRS_ESTABLISHED },
	{ "h3", "S", ANY,			LWS_WSIEV_WT_SESSION, "wt", NULL, LRS_ESTABLISHED },
	{ "h3", "*", ANY,			LWS_WSIEV_WT_STREAM, "wt", NULL, LRS_ESTABLISHED },
	{ "(none)", "*", LRS_UNCONNECTED,	LWS_WSIEV_WT_STREAM, "wt", "L", LRS_ESTABLISHED },
	{ "*", "S", LRS_HEADERS,		LWS_WSIEV_RAW_UPGRADED, "?", NULL, LRS_ESTABLISHED },
	{ "*", "S", LRS_H1_UPGRADE,		LWS_WSIEV_RAW_UPGRADED, "?", NULL, LRS_ESTABLISHED },
	/* the non-tls fallback on a tls listener, from the first byte peek in the accept */
	{ "*", "S", LRS_SSL_INIT,		LWS_WSIEV_RAW_UPGRADED, "?", NULL, LRS_ESTABLISHED },
	{ "*", "S", LRS_SSL_ACK_PENDING,	LWS_WSIEV_RAW_UPGRADED, "?", NULL, LRS_ESTABLISHED },
	/* a later request on a kept-alive connection, and a listener already in the raw role */
	{ "*", "S", LRS_ESTABLISHED,		LWS_WSIEV_RAW_UPGRADED, "?", NULL, LRS_ESTABLISHED },
	{ "h1", "C", LRS_ESTABLISHED,		LWS_WSIEV_RAW_UPGRADED, "raw-skt", NULL, LRS_ESTABLISHED },
	{ "h1", "C", LRS_WAITING_SERVER_REPLY,	LWS_WSIEV_RAW_UPGRADED, "raw-skt", NULL, LRS_ESTABLISHED },
	/* ---- transport machine ---- */

	{ "*", "C", LRS_UNCONNECTED,		LWS_WSIEV_DNS_START, NULL, NULL, XT(LTS_WAITING_DNS) },
	{ "*", "C", LRS_WAITING_DNS,		LWS_WSIEV_DNS_RETRY, NULL, NULL, XT(LTS_NONE) },
	{ "*", "C", LRS_UNCONNECTED,		LWS_WSIEV_CONNECT_START, NULL, NULL, XT(LTS_WAITING_CONNECT) },
	{ "*", "C", LRS_WAITING_DNS,		LWS_WSIEV_CONNECT_START, NULL, NULL, XT(LTS_WAITING_CONNECT) },
	{ "*", "C", LRS_WAITING_CONNECT,	LWS_WSIEV_CONNECT_START, NULL, NULL, XT(LTS_WAITING_CONNECT) },	/* next address */
	{ "*", "C", LRS_WAITING_SSL,		LWS_WSIEV_CONNECT_START, NULL, NULL, XT(LTS_WAITING_CONNECT) },	/* quic to tcp */
	{ "*", "C", LRS_WAITING_CONNECT,	LWS_WSIEV_PROXY_CONNECT_SENT, NULL, NULL, XT(LTS_WAITING_PROXY_REPLY) },
	{ "*", "C", LRS_WAITING_CONNECT,	LWS_WSIEV_SOCKS_GREETING_SENT, NULL, NULL, XT(LTS_WAITING_SOCKS_GREETING_REPLY) },
	{ "*", "C", LRS_WAITING_SOCKS_GREETING_REPLY, LWS_WSIEV_SOCKS_AUTH_SENT, NULL, NULL, XT(LTS_WAITING_SOCKS_AUTH_REPLY) },
	{ "*", "C", LRS_WAITING_SOCKS_GREETING_REPLY, LWS_WSIEV_SOCKS_CONNECT_SENT, NULL, NULL, XT(LTS_WAITING_SOCKS_CONNECT_REPLY) },
	{ "*", "C", LRS_WAITING_SOCKS_AUTH_REPLY, LWS_WSIEV_SOCKS_CONNECT_SENT, NULL, NULL, XT(LTS_WAITING_SOCKS_CONNECT_REPLY) },
	{ "*", "C", LRS_WAITING_CONNECT,	LWS_WSIEV_TLS_START, NULL, NULL, XT(LTS_WAITING_SSL) },
	{ "*", "C", LRS_WAITING_PROXY_REPLY,	LWS_WSIEV_TLS_START, NULL, NULL, XT(LTS_WAITING_SSL) },
	{ "*", "C", LRS_WAITING_SOCKS_CONNECT_REPLY, LWS_WSIEV_TLS_START, NULL, NULL, XT(LTS_WAITING_SSL) },
	{ "*", "C", LRS_H1C_ISSUE_HANDSHAKE,	LWS_WSIEV_TLS_START, NULL, NULL, XT(LTS_WAITING_SSL) },
	{ "*", "C", LRS_WAITING_SSL,		LWS_WSIEV_TLS_START, NULL, NULL, XT(LTS_WAITING_SSL) },	/* more service */
	{ "*", "S", LRS_SSL_INIT,		LWS_WSIEV_TLS_ACCEPT_PENDING, NULL, NULL, XT(LTS_SSL_ACK_PENDING) },
	{ "*", "S", LRS_SSL_ACK_PENDING,	LWS_WSIEV_TLS_ACCEPT_PENDING, NULL, NULL, XT(LTS_SSL_ACK_PENDING) },
	{ "*", "S", LRS_AWAITING_SSL_ACCEPT,	LWS_WSIEV_TLS_ACCEPT_PENDING, NULL, NULL, XT(LTS_SSL_ACK_PENDING) },
	{ "*", "S", LRS_SSL_INIT,		LWS_WSIEV_TLS_ACCEPT_QUEUED, NULL, NULL, XT(LTS_AWAITING_SSL_ACCEPT) },
	{ "*", "S", LRS_SSL_ACK_PENDING,	LWS_WSIEV_TLS_ACCEPT_QUEUED, NULL, NULL, XT(LTS_AWAITING_SSL_ACCEPT) },
	{ "*", "C", ANY,			LWS_WSIEV_CONN_FAILED, NULL, NULL, XT(LTS_FAILED) },
	{ "*", "C", ANY,			LWS_WSIEV_RETARGET, NULL, NULL, XT(LTS_RESTARTING) },

	/* ---- close machine: the polite ws close is specific, the rest can come from anywhere ---- */

	{ "ws", "*", LRS_ESTABLISHED,		LWS_WSIEV_WS_CLOSE_INITIATED, NULL, NULL, XC(LCS_WAITING_TO_SEND_CLOSE) },
	{ "ws", "*", LRS_WAITING_TO_SEND_CLOSE,	LWS_WSIEV_WS_CLOSE_SENT, NULL, NULL, XC(LCS_AWAITING_CLOSE_ACK) },
	{ "ws", "*", LRS_ESTABLISHED,		LWS_WSIEV_WS_PEER_CLOSE, NULL, NULL, XC(LCS_RETURNED_CLOSE) },
	/* his CLOSE beat the one we were about to send: answer his and drop ours */
	{ "ws", "*", LRS_WAITING_TO_SEND_CLOSE,	LWS_WSIEV_WS_PEER_CLOSE, NULL, NULL, XC(LCS_RETURNED_CLOSE) },
	{ "*", "*", ANY,			LWS_WSIEV_CLOSE_FLUSH, NULL, NULL, XC(LCS_FLUSHING_BEFORE_CLOSE) },
	{ "*", "S", ANY,			LWS_WSIEV_CLOSE_STAGED, NULL, NULL, XC(LCS_SHUTDOWN) },
	{ "*", "*", ANY,			LWS_WSIEV_SOCKET_GONE, NULL, NULL, XC(LCS_DEAD_SOCKET) },
	{ "*", "*", LRS_DEAD_SOCKET,		LWS_WSIEV_USER_TOLD, NULL, NULL, XC(LCS_USER_TOLD) },

};

/* the side flags a to_side spec stands for */

static lws_wsi_state_t
lws_state_side_flags(const char *spec)
{
	lws_wsi_state_t f = 0;

	if (spec[0] == 'C')
		f = LWSIFR_CLIENT;
	if (spec[0] == 'S')
		f = LWSIFR_SERVER;
	if (spec[1] == 'e')
		f |= LWSIFR_P_ENCAP_H2;

	return f;
}

int
lws_wsi_event_x(struct lws *wsi, enum lws_wsi_event ev,
		const struct lws_role_ops *ops, struct lws *like)
{
	const char *role = wsi->role_ops ? wsi->role_ops->name : "(none)";
	const struct lws_wsi_event_edge *e = lws_wsi_event_edges;
	lws_wsi_state_t from = lws_wsi_state_of(wsi->wsistate), rf;
#if defined(LWS_ROLE_H2) || defined(LWS_ROLE_MQTT) || defined(LWS_ROLE_QUIC)
	struct lws *parent = wsi->mux.parent_wsi;
#else
	struct lws *parent = NULL;
#endif
	const struct lws_role_ops *nops;
	char side[3], a[64];
	unsigned int n;

	lws_state_side(from, side);

	for (n = 0; n < LWS_ARRAY_SIZE(lws_wsi_event_edges); n++, e++) {
		if (e->ev != ev ||
		    (e->from != ANY && e->from != (from & LRS_MASK)) ||
		    !lws_state_match(e->role, role) ||
		    !lws_state_match(e->side, side))
			continue;

		/* an ops argument must be what the row takes */
		if (e->to_role && !strcmp(e->to_role, "?")) {
			if (!ops)
				continue;
		} else if (ops && (!e->to_role || !strcmp(e->to_role, "P") ||
				   strcmp(e->to_role, ops->name)))
			continue;

		if (e->to & 0x8000) {
			lws_wsi_set_transport_ev(wsi, (enum lws_transport_phase)
						 (e->to & 0xff),
						 lws_wsi_event_names[ev]);

			return 0;
		}

		if (e->to & 0x4000) {
			lws_wsi_set_close_ev(wsi, (enum lws_close_phase)
					     (e->to & 0xff),
					     lws_wsi_event_names[ev]);

			return 0;
		}

		if (!e->to_role && !e->to_side) {
			lws_wsi_set_state_ev(wsi, e->to, lws_wsi_event_names[ev]);

			return 0;
		}

		nops = wsi->role_ops;
		if (e->to_role) {
			if (!strcmp(e->to_role, "?"))
				nops = ops;
			else if (!strcmp(e->to_role, "P"))
				nops = parent ? parent->role_ops : wsi->role_ops;
			else
				nops = lws_role_by_name(e->to_role);
			if (!nops) {
				lwsl_wsi_err(wsi, "event %s: no role %s",
					     lws_wsi_event_names[ev], e->to_role);
				goto bad;
			}
		}

		rf = lwsi_role(wsi);
		if (e->to_side) {
			if (!strcmp(e->to_side, "P")) {
				if (parent)
					rf = lwsi_role(parent);
			} else if (!strcmp(e->to_side, "L")) {
				if (like)
					rf = lwsi_role(like);
			} else
				rf = lws_state_side_flags(e->to_side);
		}

		lws_wsi_role_transition_ev(wsi, (enum lwsi_role)rf,
					   (enum lwsi_state)e->to, nops,
					   lws_wsi_event_names[ev]);

		return 0;
	}

	lws_wsi_state_fmt(wsi->role_ops, wsi->wsistate, a, sizeof(a));
	lwsl_wsi_err(wsi, "no state for event %s%s%s in %s",
		     lws_wsi_event_names[ev], ops ? " with role " : "",
		     ops ? ops->name : "", a);
bad:
#if defined(LWS_WITH_STATE_CHECK)
	abort();
#endif

	return -1;
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
		    lws_wsi_state_t to, const char *how, const char *ev)
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

	fprintf(f, "LRS %s -> %s %s %s%s%s\n", a, b, how, lws_wsi_tag(wsi),
		ev ? " ev=" : "", ev ? ev : "");
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

/*
 * A wsi's birth: the creator hands in the ops, so there is no event row for
 * it.  Every other role or side change comes from an event row and is
 * checked as that; here are the births.
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
};

/* a live-state edge must be one some event row produces */

static int
lws_event_edge_allowed(const struct lws_role_ops *ops, lws_wsi_state_t from,
		       lws_wsi_state_t to)
{
	const char *role = ops ? ops->name : "(none)";
	const struct lws_wsi_event_edge *e = lws_wsi_event_edges;
	char side[3];
	unsigned int n;

	from = lws_wsi_state_of(from);
	to = lws_wsi_state_of(to);
	lws_state_side(to, side);

	for (n = 0; n < LWS_ARRAY_SIZE(lws_wsi_event_edges); n++, e++)
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
		    lws_wsi_state_t to, const char *how, const char *ev)
{
	const char *why = NULL;
	char a[64], b[64];
	int ok;

	/*
	 * A live-state edge must come from the event table; a transport or
	 * close phase edge or a role change must carry an event's name (the
	 * engine made it from a row), else be a birth
	 */
	if (!strcmp(how, "set_state"))
		ok = lws_event_edge_allowed(to_ops, from, to);
	else if (ev)
		ok = 1;
	else if (!strcmp(how, "role_transition"))
		ok = lws_role_edge_allowed(from_ops, from, to_ops, to);
	else
		ok = 0;

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

#if defined(LWS_WITH_STATE_TRACE) || defined(LWS_WITH_STATE_CHECK)
/*
 * Called from the setters in wsi.c after the new state is in place; ev is
 * the event name when the change came through lws_wsi_event(), else NULL
 */

void
lws_wsi_state_changed(struct lws *wsi, const struct lws_role_ops *from_ops,
		      lws_wsi_state_t from, const struct lws_role_ops *to_ops,
		      lws_wsi_state_t to, const char *how, const char *ev)
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
	lws_wsi_state_trace(wsi, from_ops, from, to_ops, to, how, ev);
#endif
#if defined(LWS_WITH_STATE_CHECK)
	/* only an attribute changed: no edge to check */
	if (!attr_only)
		lws_wsi_state_check(wsi, from_ops, from, to_ops, to, how, ev);
#endif
}
#endif
