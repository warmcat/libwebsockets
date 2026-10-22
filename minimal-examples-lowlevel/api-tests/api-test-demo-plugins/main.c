/*
 * lws-api-test-demo-plugins
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The demo protocol plugins that ship with lwsws and the test server serve
 * anybody who connects, so they must keep what they send to other people's
 * browsers valid, however the peer behaves.  A ws server with the plugins
 * built in and ws clients run in one process.
 *
 * lws-mirror relays whole messages to everyone on its instance
 *
 *  - a TEXT message sent in two fragments, split inside a UTF-8 character,
 *    reaches the other member as one TEXT message, intact
 *  - a BINARY message that isn't UTF-8 reaches it as one BINARY message (lws
 *    doesn't validate BINARY, and a browser must fail on invalid TEXT)
 *  - a message bigger than the mirror reassembles is refused (close 1009)
 *    and nothing is relayed
 *  - idle connections holding every named instance there may be can't keep
 *    anyone out of the default instance
 *
 * lws-status shows every connection's User-Agent to every viewer
 *
 *  - with one peer's UA invalid UTF-8 and another's 200 '"' (escaping to
 *    1200 chars), every status message is valid UTF-8 and parses as JSON
 *
 * dumb-increment sends each connection a number every 50ms
 *
 *  - with connections whose timers are spread over the period, each one
 *    gets about 20 numbers a second, not 20 times the number of
 *    connections
 *
 * The test fails if any of that doesn't happen, or it doesn't all complete
 * in time.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define LWS_PLUGIN_STATIC
#include "../../../plugins/protocol_lws_mirror/protocol_lws_mirror.c"
#include "../../../plugins/protocol_lws_status/protocol_lws_status.c"
#include "../../../plugins/protocol_dumb_increment/protocol_dumb_increment.c"

/* every named instance there may be, plus one more that is refused */
#define DPT_NAMED		(MIRROR_MAX_NAMED_INSTANCES + 1)
#define DPT_STATUS		3
#define DPT_DUMB		10
/* dumb-increment sends one number per 50ms: 20 a second */
#define DPT_DUMB_STAGGER_US	(5 * LWS_US_PER_MS)
#define DPT_DUMB_MIN		5
#define DPT_DUMB_MAX		35
#define DPT_BIG_LEN		(MIRROR_MAX_MESSAGE + 1000)

/* the connections, by index in conns[] */
enum {
	DPT_C_RX,			/* mirror: default instance, receives */
	DPT_C_TX,			/* mirror: default instance, sends */
	DPT_C_BIG,			/* mirror: sends a too-large message */
	DPT_C_DEFAULT,			/* mirror: default instance, idle */
	DPT_C_NAMED,			/* mirror: named instances, idle */
	DPT_C_STATUS = DPT_C_NAMED + DPT_NAMED,
	DPT_C_DUMB = DPT_C_STATUS + DPT_STATUS,

	DPT_C_COUNT = DPT_C_DUMB + DPT_DUMB
};

enum {
	DPT_P_MIRROR_NAMED,
	DPT_P_MIRROR_DEFAULT,
	DPT_P_MIRROR_SPLIT,
	DPT_P_MIRROR_BIG,
	DPT_P_MIRROR_CHECK,
	DPT_P_STATUS,
	DPT_P_STATUS_CHECK,
	DPT_P_DUMB,
	DPT_P_DUMB_COUNT,
	DPT_P_DUMB_CHECK,

	DPT_P_DONE
};

struct dpt_conn {
	struct lws		*wsi;
	const char		*ua;
	char			path[48];
	uint8_t			msg[8192];	/* message being reassembled */
	size_t			msg_len;
	int			msgs;		/* complete messages received */
	int			bad;		/* ...of which were invalid */
	int			tx_step;
	uint16_t		close_code;	/* from the server's close */
	char			est;
	char			closed;
	char			msg_binary;
	char			msg_overflow;
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_phase, sul_timeout, sul_dumb[DPT_DUMB];
static struct dpt_conn conns[DPT_C_COUNT];
static const char *server_address = "localhost";
static int port = 7681, phase, result = 1, failed, interrupted;
static char ua_quotes[201];

/* sent as two fragments, split inside the "€" (e2 82 ac) */
static const char split1[] = "d #000 1 2 3 4;\xe2\x82",
		  split2[] = "\xac;",
		  split_whole[] = "d #000 1 2 3 4;\xe2\x82\xac;",
		  binary[] = "\xff\xfe binary";

/* what RX must receive from TX, in order, and nothing else */
static const struct {
	const char	*data;
	size_t		len;
	char		binary;
} rx_expect[] = {
	{ split_whole,	sizeof(split_whole) - 1,	0 },
	{ binary,	sizeof(binary) - 1,		1 },
};
static uint8_t txbuf[LWS_PRE + DPT_BIG_LEN];

static void
dpt_fail(const char *why)
{
	lwsl_err("FAIL: phase %d: %s\n", phase, why);
	failed = 1;
	interrupted = 1;
	lws_cancel_service(context);
}

static int
dpt_connect(int idx, const char *proto, const char *path)
{
	struct dpt_conn *c = &conns[idx];
	struct lws_client_connect_info i;

	lws_strncpy(c->path, path, sizeof(c->path));

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_address;
	i.port			= port;
	i.path			= c->path;
	i.host			= i.address;
	i.origin		= i.address;
	i.protocol		= proto;
	i.local_protocol_name	= "dpt-client";
	i.opaque_user_data	= c;
	i.pwsi			= &c->wsi;

	if (!lws_client_connect_via_info(&i)) {
		dpt_fail("connect failed");
		return 1;
	}

	return 0;
}

static int
dpt_count_est(int from, int count)
{
	int n, t = 0;

	for (n = from; n < from + count; n++)
		t += conns[n].est;

	return t;
}

static int
dpt_count_closed(int from, int count)
{
	int n, t = 0;

	for (n = from; n < from + count; n++)
		t += conns[n].closed;

	return t;
}

static void
dpt_phase_cb(lws_sorted_usec_list_t *sul);

static void
dpt_schedule(lws_usec_t us)
{
	lws_sul_schedule(context, 0, &sul_phase, dpt_phase_cb, us);
}

static void
dpt_dumb_connect_cb(lws_sorted_usec_list_t *sul)
{
	int n = (int)(sul - sul_dumb);

	dpt_connect(DPT_C_DUMB + n, "dumb-increment-protocol", "/");
}

/*
 * Each phase starts by being called here, then waits for its connections
 * and checks, and schedules the next phase
 */

static void
dpt_phase_cb(lws_sorted_usec_list_t *sul)
{
	char path[48];
	int n;

	switch (phase) {
	case DPT_P_MIRROR_NAMED:
		/* fill every named instance with an idle connection, +1 */
		for (n = 0; n < DPT_NAMED; n++) {
			lws_snprintf(path, sizeof(path), "/?mirror=n%d", n);
			if (dpt_connect(DPT_C_NAMED + n, "lws-mirror-protocol",
					path))
				return;
		}
		/* we check after a second */
		phase++;
		dpt_schedule(LWS_US_PER_SEC);
		break;

	case DPT_P_MIRROR_DEFAULT:
		/* the named instances that may exist are all taken... */
		if (dpt_count_est(DPT_C_NAMED, DPT_NAMED - 1) != DPT_NAMED - 1 ||
		    dpt_count_closed(DPT_C_NAMED, DPT_NAMED - 1)) {
			dpt_fail("allowed named instances not all joined");
			return;
		}
		/* ...and the one past the limit was refused */
		if (!conns[DPT_C_NAMED + DPT_NAMED - 1].closed) {
			dpt_fail("named instance past the limit not refused");
			return;
		}
		/* but somebody can still use the default instance */
		phase++;
		if (dpt_connect(DPT_C_DEFAULT, "lws-mirror-protocol", "/"))
			return;
		dpt_schedule(LWS_US_PER_SEC);
		break;

	case DPT_P_MIRROR_SPLIT:
		if (!conns[DPT_C_DEFAULT].est || conns[DPT_C_DEFAULT].closed) {
			dpt_fail("could not join the default instance");
			return;
		}
		/* RX and TX join the default instance; TX goes on its est */
		if (dpt_connect(DPT_C_RX, "lws-mirror-protocol", "/") ||
		    dpt_connect(DPT_C_TX, "lws-mirror-protocol", "/"))
			return;
		break;

	case DPT_P_MIRROR_BIG:
		/* RX had both TX's messages a while ago: nothing else came */
		if (conns[DPT_C_RX].msgs != (int)LWS_ARRAY_SIZE(rx_expect) ||
		    conns[DPT_C_RX].bad || conns[DPT_C_TX].closed) {
			lwsl_err("rx msgs %d, bad %d\n", conns[DPT_C_RX].msgs,
				 conns[DPT_C_RX].bad);
			dpt_fail("mirror relayed something other than TX's "
				 "messages, whole");
			return;
		}
		if (dpt_connect(DPT_C_BIG, "lws-mirror-protocol", "/"))
			return;
		break;

	case DPT_P_MIRROR_CHECK:
		if (conns[DPT_C_BIG].close_code !=
					LWS_CLOSE_STATUS_MESSAGE_TOO_LARGE) {
			lwsl_err("close code %d\n", conns[DPT_C_BIG].close_code);
			dpt_fail("too large message not refused");
			return;
		}
		if (conns[DPT_C_RX].msgs != (int)LWS_ARRAY_SIZE(rx_expect) ||
		    conns[DPT_C_RX].bad) {
			dpt_fail("mirror relayed some of the too large message");
			return;
		}
		phase++;
		dpt_schedule(1);
		break;

	case DPT_P_STATUS:
		conns[DPT_C_STATUS].ua = "\xff\xfe";
		conns[DPT_C_STATUS + 1].ua = ua_quotes;
		/* DPT_C_STATUS + 2 sends no UA */
		for (n = 0; n < DPT_STATUS; n++)
			if (dpt_connect(DPT_C_STATUS + n, "lws-status", "/"))
				return;
		/* the last viewer moves us on when it sees all three */
		break;

	case DPT_P_STATUS_CHECK:
		for (n = 0; n < DPT_STATUS; n++)
			if (conns[DPT_C_STATUS + n].bad ||
			    conns[DPT_C_STATUS + n].closed) {
				lwsl_err("status conn %d: msgs %d, bad %d, "
					 "closed %d\n", n,
					 conns[DPT_C_STATUS + n].msgs,
					 conns[DPT_C_STATUS + n].bad,
					 conns[DPT_C_STATUS + n].closed);
				dpt_fail("invalid status message");
				return;
			}
		phase++;
		dpt_schedule(1);
		break;

	case DPT_P_DUMB:
		/*
		 * Open the connections one at a time across the 50ms
		 * period, so their timers are spread over it
		 */
		for (n = 0; n < DPT_DUMB; n++)
			lws_sul_schedule(context, 0, &sul_dumb[n],
					 dpt_dumb_connect_cb,
					 n * DPT_DUMB_STAGGER_US);
		/* the last to connect moves us on */
		break;

	case DPT_P_DUMB_COUNT:
		/* they have all been connected a while: count for 1s */
		for (n = 0; n < DPT_DUMB; n++)
			conns[DPT_C_DUMB + n].msgs = 0;
		phase++;
		dpt_schedule(LWS_US_PER_SEC);
		break;

	case DPT_P_DUMB_CHECK:
		for (n = 0; n < DPT_DUMB; n++) {
			lwsl_user("dumb-increment conn %d: %d numbers in 1s\n",
				  n, conns[DPT_C_DUMB + n].msgs);
			if (conns[DPT_C_DUMB + n].msgs < DPT_DUMB_MIN ||
			    conns[DPT_C_DUMB + n].msgs > DPT_DUMB_MAX) {
				dpt_fail("dumb-increment sent the wrong amount");
				return;
			}
		}
		phase++;
		dpt_schedule(1);
		break;

	case DPT_P_DONE:
		result = 0;
		interrupted = 1;
		lws_cancel_service(context);
		break;
	}
}

static void
dpt_timeout_cb(lws_sorted_usec_list_t *sul)
{
	dpt_fail("timed out");
}

#if defined(LWS_WITH_LEJP)
static signed char
dpt_lejp_cb(struct lejp_ctx *ctx, char reason)
{
	return 0;
}
#endif

/* is a complete message received on c acceptable? */

static int
dpt_msg_bad(struct dpt_conn *c)
{
	int idx = (int)(c - conns);
	unsigned char st = 0;

	if (c->msg_overflow)
		return 1;

	if (c->msg_binary)
		/* BINARY may hold anything, but no status message is BINARY */
		return idx >= DPT_C_STATUS && idx < DPT_C_STATUS + DPT_STATUS;

	if (lws_check_utf8(&st, c->msg, c->msg_len) || st) {
		lwsl_err("%s: invalid UTF-8\n", __func__);
		return 1;
	}

	if (idx >= DPT_C_STATUS && idx < DPT_C_STATUS + DPT_STATUS) {
#if defined(LWS_WITH_LEJP)
		struct lejp_ctx ctx;
		int m;

		lejp_construct(&ctx, dpt_lejp_cb, NULL, NULL, 0);
		m = lejp_parse(&ctx, c->msg, (int)c->msg_len);
		lejp_destruct(&ctx);
		if (m < 0) {
			lwsl_err("%s: status JSON doesn't parse: %d\n",
				 __func__, m);
			return 1;
		}
#else
		if (memchr(c->msg, '\0', c->msg_len) || c->msg_len < 2 ||
		    memcmp(c->msg + c->msg_len - 2, "]}", 2)) {
			lwsl_err("%s: status JSON not closed\n", __func__);
			return 1;
		}
#endif
	}

	return 0;
}

static int
callback_dpt_client(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct dpt_conn *c = (struct dpt_conn *)lws_get_opaque_user_data(wsi);
	int idx, n;

	if (!c)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	idx = (int)(c - conns);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		if (c->ua) {
			unsigned char **p = (unsigned char **)in;

			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_USER_AGENT,
					(const unsigned char *)c->ua,
					(int)strlen(c->ua), p, (*p) + len))
				return -1;
		}
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		c->est = 1;
		if (idx == DPT_C_TX || idx == DPT_C_BIG) {
			/* TX starts sending when RX has also joined */
			if (idx == DPT_C_BIG || conns[DPT_C_RX].est)
				lws_callback_on_writable(conns[idx].wsi);
		}
		if (idx == DPT_C_RX && conns[DPT_C_TX].est)
			lws_callback_on_writable(conns[DPT_C_TX].wsi);
		if (idx == DPT_C_DUMB + DPT_DUMB - 1) {
			/* let the last one's timer get going too */
			phase++;
			dpt_schedule(200 * LWS_US_PER_MS);
		}
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		if (idx == DPT_C_BIG) {
			if (c->tx_step++)
				break;
			memset(txbuf + LWS_PRE, 'a', DPT_BIG_LEN);
			if (lws_write(wsi, txbuf + LWS_PRE, DPT_BIG_LEN,
				      LWS_WRITE_TEXT) < DPT_BIG_LEN)
				return -1;
			break;
		}
		if (idx != DPT_C_TX)
			break;

		/* the client masks in place: refill txbuf every time */
		switch (c->tx_step++) {
		case 0:
			memcpy(txbuf + LWS_PRE, split1, sizeof(split1) - 1);
			n = lws_write(wsi, txbuf + LWS_PRE, sizeof(split1) - 1,
				      LWS_WRITE_TEXT | LWS_WRITE_NO_FIN);
			break;
		case 1:
			memcpy(txbuf + LWS_PRE, split2, sizeof(split2) - 1);
			n = lws_write(wsi, txbuf + LWS_PRE, sizeof(split2) - 1,
				      LWS_WRITE_CONTINUATION);
			break;
		case 2:
			memcpy(txbuf + LWS_PRE, binary, sizeof(binary) - 1);
			n = lws_write(wsi, txbuf + LWS_PRE, sizeof(binary) - 1,
				      LWS_WRITE_BINARY);
			break;
		default:
			return 0;
		}
		if (n < 0)
			return -1;
		lws_callback_on_writable(wsi);
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
		if (dpt_msg_bad(c) ||
		    /* RX should only see TX's messages, whole, as sent */
		    (idx == DPT_C_RX &&
		     (c->msgs > (int)LWS_ARRAY_SIZE(rx_expect) ||
		      c->msg_binary != rx_expect[c->msgs - 1].binary ||
		      c->msg_len != rx_expect[c->msgs - 1].len ||
		      memcmp(c->msg, rx_expect[c->msgs - 1].data,
			     c->msg_len)))) {
			c->bad++;
			lwsl_err("conn %d: bad message\n", idx);
			lwsl_hexdump_err(c->msg, c->msg_len > 128 ? 128 :
							c->msg_len);
			dpt_fail("invalid message");
			break;
		}

		if (idx == DPT_C_RX &&
		    c->msgs == (int)LWS_ARRAY_SIZE(rx_expect)) {
			/* give anything else relayed time to reach RX */
			phase++;
			dpt_schedule(300 * LWS_US_PER_MS);
		}

		if (idx == DPT_C_STATUS + DPT_STATUS - 1 &&
		    phase == DPT_P_STATUS &&
		    c->msg_len < sizeof(c->msg) - 1) {
			c->msg[c->msg_len] = '\0';
			if (strstr((const char *)c->msg, "\"wsi\":\"3\"")) {
				/* let the others finish theirs too */
				phase++;
				dpt_schedule(300 * LWS_US_PER_MS);
			}
		}
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
		/* after BIG's message, the server hung up */
		if (idx == DPT_C_BIG && phase == DPT_P_MIRROR_BIG) {
			/* let anything relayed reach RX before we check */
			phase++;
			dpt_schedule(300 * LWS_US_PER_MS);
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	LWS_PLUGIN_PROTOCOL_MIRROR,
	LWS_PLUGIN_PROTOCOL_LWS_STATUS,
	LWS_PLUGIN_PROTOCOL_DUMB_INCREMENT,
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "dpt-client", callback_dpt_client, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

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
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_address = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: demo protocol plugins\n");

	memset(ua_quotes, '\"', sizeof(ua_quotes) - 1);

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.port = port;
	info.vhost_name = "srv";
	info.protocols = protocols_srv;
	/* there are no pvos to instantiate the protocols one by one */
	info.options |= LWS_SERVER_OPTION_VH_INSTANTIATE_ALL_PROTOCOLS;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create server vhost\n");
		goto bail;
	}

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	dpt_schedule(1);
	lws_sul_schedule(context, 0, &sul_timeout, dpt_timeout_cb,
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
