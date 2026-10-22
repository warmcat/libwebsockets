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

enum {
	WSE_P_CORNER,
	WSE_P_CORNER_CHECK,
	WSE_P_RELAY,		/* for each relays[] in turn */
	WSE_P_RELAY_BIG,
	WSE_P_RELAY_BAD,
	WSE_P_RELAY_CHECK,

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

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_phase, sul_timeout;
static struct wse_conn conns[WSE_C_COUNT];
static const char *server_address = "localhost";
static int port = 7681, phase, relay, result = 1, failed, interrupted;
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

static const struct lws_protocols protocols_cli[] = {
	{ "wse-client", callback_wse_client, 0, 0, 0, NULL, 0 },
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
			 30 * LWS_US_PER_SEC);

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

bail:
	lws_context_destroy(context);

	if (failed)
		result = 1;

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
