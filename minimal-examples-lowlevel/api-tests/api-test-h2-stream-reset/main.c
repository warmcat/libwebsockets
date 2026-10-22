/*
 * lws-api-test-h2-stream-reset
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Streams of an h2 server connection being reset, by the server and by the
 * peer.  A raw h2 client (cleartext, prior knowledge) in the same process
 * writes the frames itself, so it controls exactly what the server has read
 * when.
 *
 * The server resets a stream outside its frame parser when the stream
 * closes, eg, a GET whose HEADERS had no END_STREAM answered in full: it
 * sends RST_STREAM NO_ERROR then, at POLLOUT.  That must not disturb a frame
 * of another stream, or of the connection, that the server is part way
 * through reading, nor be skipped because the last frame read was one the
 * server ignored:
 *
 * --case ping: a PING is half sent when stream 1 is answered and reset; its
 *   second half goes after the RST_STREAM.  It must be answered.
 *
 * --case hpack: half of stream 5's header block is sent when stream 3 is
 *   answered and reset; the second half, after the RST_STREAM, adds a
 *   user-agent to the hpack dynamic table.  Stream 5 must be served with
 *   it, and stream 7, which refers to the dynamic table entry, too.
 *
 * --case ignored: stream 1's HEADERS is followed by a frame of an unknown
 *   type, which the server ignores.  When stream 1 is answered, its
 *   RST_STREAM must still be sent.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#define RR_DEADLINE_S		10

/* h2 framing */
#define RR_DATA			0
#define RR_HEADERS		1
#define RR_RST_STREAM		3
#define RR_SETTINGS		4
#define RR_PING			6
#define RR_GOAWAY		7
#define RR_UNKNOWN_TYPE		0x77
#define RR_FL_END_STREAM	0x01
#define RR_FL_ACK		0x01
#define RR_FL_END_HEADERS	0x04
#define RR_FL_PADDED		0x08
#define RR_FL_PRIORITY		0x20

#define RR_MAX_SID		1024

/* user-agent the hpack case puts in the dynamic table */
#define RR_UA			"rr-ua"

enum rr_case {
	RR_CASE_PING,
	RR_CASE_HPACK,
	RR_CASE_IGNORED,
};

struct pss_srv {
	char			path[32];
	char			respond;
};

struct rr_conn {
	struct lws		*wsi;
	uint8_t			tx[LWS_PRE + 4096];
	size_t			tx_len;
	/* frames are reassembled here */
	uint8_t			rxf[16384 + 9];
	size_t			rxf_len;
	/* what came back on each stream */
	char			answered[RR_MAX_SID];
	char			ended[RR_MAX_SID];
	char			rst[RR_MAX_SID];
	int			step;
	char			started;
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_deadline;
static const char *server_addr = "127.0.0.1";
static int port = 7681, fails, done;
static enum rr_case rr_case = RR_CASE_PING;
static struct rr_conn conn;

/* what the server saw: /dyn requests carrying RR_UA */
static int srv_dyn_ua;

/* ---- server ---- */

static int
srv_respond(struct lws *wsi)
{
	uint8_t hbuf[LWS_PRE + 256], *start = &hbuf[LWS_PRE], *p = start,
		*end = &hbuf[sizeof(hbuf) - 1];

	if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/plain", 2,
					&p, end) ||
	    lws_finalize_write_http_header(wsi, start, &p, end))
		return 1;

	memcpy(start, "ok", 2);
	if (lws_write(wsi, start, 2, LWS_WRITE_HTTP_FINAL) != 2)
		return 1;

	return lws_http_transaction_completed(wsi) ? -1 : 0;
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	char ua[16];

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		lws_strncpy(pss->path, in ? (const char *)in : "",
			    sizeof(pss->path));
		lwsl_info("%s: server: %s\n", __func__, pss->path);

		if (!strcmp(pss->path, "/dyn") &&
		    lws_hdr_copy(wsi, ua, sizeof(ua),
				 WSI_TOKEN_HTTP_USER_AGENT) > 0 &&
		    !strcmp(ua, RR_UA))
			srv_dyn_ua++;

		pss->respond = 1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss->respond)
			return 0;
		pss->respond = 0;
		return srv_respond(wsi);

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* ---- client: raw h2 ---- */

static void
rr_finish(const char *why, int failed)
{
	if (done)
		return;
	done = 1;
	if (failed) {
		lwsl_err("%s: FAILED: %s\n", __func__, why);
		fails++;
	} else
		lwsl_user("%s: %s\n", __func__, why);

	lws_sul_cancel(&sul_deadline);
	lws_cancel_service(context);
}

static void
rr_add(struct rr_conn *c, const void *p, size_t len)
{
	if (c->tx_len + len > sizeof(c->tx) - LWS_PRE) {
		rr_finish("tx overflow", 1);
		return;
	}
	memcpy(c->tx + LWS_PRE + c->tx_len, p, len);
	c->tx_len += len;
	if (c->wsi)
		lws_callback_on_writable(c->wsi);
}

static void
rr_frame_hdr(struct rr_conn *c, uint8_t type, uint8_t flags, uint32_t sid,
	     size_t len)
{
	uint8_t h[9];

	h[0] = (uint8_t)(len >> 16);
	h[1] = (uint8_t)(len >> 8);
	h[2] = (uint8_t)len;
	h[3] = type;
	h[4] = flags;
	h[5] = (uint8_t)(sid >> 24);
	h[6] = (uint8_t)(sid >> 16);
	h[7] = (uint8_t)(sid >> 8);
	h[8] = (uint8_t)sid;

	rr_add(c, h, sizeof(h));
}

static void
rr_frame(struct rr_conn *c, uint8_t type, uint8_t flags, uint32_t sid,
	 const void *pl, size_t len)
{
	rr_frame_hdr(c, type, flags, sid, len);
	if (len)
		rr_add(c, pl, len);
}

/* hpack literal without indexing, indexed name (< 15) */
static size_t
rr_lit(uint8_t *p, int name_idx, const char *v)
{
	size_t vl = strlen(v), n = 0;

	p[n++] = (uint8_t)name_idx;
	p[n++] = (uint8_t)vl; /* values here are < 127 */
	memcpy(p + n, v, vl);

	return n + vl;
}

/* the fields of a GET for path, without END_STREAM's frame */
static size_t
rr_get_block(uint8_t *b, const char *path)
{
	size_t n = 0;

	b[n++] = 0x82;	/* :method GET */
	b[n++] = 0x86;	/* :scheme http */
	n += rr_lit(b + n, 4, path);		/* :path */
	n += rr_lit(b + n, 1, "localhost");	/* :authority */

	return n;
}

static void
rr_get(struct rr_conn *c, uint32_t sid, const char *path, int end_stream)
{
	uint8_t b[64];
	size_t n = rr_get_block(b, path);

	rr_frame(c, RR_HEADERS, (uint8_t)(RR_FL_END_HEADERS |
		 (end_stream ? RR_FL_END_STREAM : 0)), sid, b, n);
}

static void
rr_preface(struct rr_conn *c)
{
	static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

	rr_add(c, preface, sizeof(preface) - 1);
	rr_frame(c, RR_SETTINGS, 0, 0, NULL, 0);
}

static void
rr_deadline_cb(lws_sorted_usec_list_t *sul)
{
	rr_finish("deadline", 1);
}

static const uint8_t ping1[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h' },
		     ping2[] = { 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p' };

/* the user-agent field, literal with incremental indexing, indexed name */
static const uint8_t ua_incr[] = { 0x40 | 58, 5, 'r', 'r', '-', 'u', 'a' };

/*
 * After the server's SETTINGS, which we ACK first: nothing else we send may
 * land in the middle of a frame we leave half sent
 */
static void
rr_start(struct rr_conn *c)
{
	uint8_t b[64];
	size_t n;

	switch (rr_case) {
	case RR_CASE_PING:
		/* answered and reset while the PING is half here */
		rr_get(c, 1, "/early", 0);
		rr_frame_hdr(c, RR_PING, 0, 0, sizeof(ping1));
		rr_add(c, ping1, 4);
		break;

	case RR_CASE_HPACK:
		rr_get(c, 3, "/early", 0);
		/* stream 5's block, without its last field */
		n = rr_get_block(b, "/dyn");
		rr_frame_hdr(c, RR_HEADERS, RR_FL_END_HEADERS |
			     RR_FL_END_STREAM, 5, n + sizeof(ua_incr));
		rr_add(c, b, n);
		break;

	case RR_CASE_IGNORED:
		rr_get(c, 1, "/early", 0);
		/* a frame the server must ignore, read last before the reset */
		rr_frame(c, RR_UNKNOWN_TYPE, 0, 0, NULL, 0);
		break;
	}
}

/* a frame came: what next */
static void
rr_progress(struct rr_conn *c, uint8_t type, uint32_t sid,
	    const uint8_t *pl, size_t len)
{
	static const uint8_t get_dyn_idx[] = {
		0x82,	/* :method GET */
		0x86,	/* :scheme http */
		0x04, 4, '/', 'd', 'y', 'n',
		0x01, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
		0xbe	/* user-agent, dynamic table entry 62 */
	};

	switch (rr_case) {
	case RR_CASE_PING:
		if (c->step == 0 && type == RR_RST_STREAM && sid == 1) {
			/* the reset went: the rest of the PING */
			c->step = 1;
			rr_add(c, ping1 + 4, 4);
			break;
		}
		if (c->step == 1 && type == RR_PING) {
			if (len != sizeof(ping1) || memcmp(pl, ping1, len))
				rr_finish("PING answered with the wrong payload",
					  1);
			else
				rr_finish("split PING answered across a "
					  "stream reset", 0);
		}
		break;

	case RR_CASE_HPACK:
		if (c->step == 0 && type == RR_RST_STREAM && sid == 3) {
			/* the reset went: the rest of stream 5's block */
			c->step = 1;
			rr_add(c, ua_incr, sizeof(ua_incr));
			break;
		}
		if (c->step == 1 && c->ended[5]) {
			/* refer to the entry the second half added */
			c->step = 2;
			rr_frame(c, RR_HEADERS, RR_FL_END_HEADERS |
				 RR_FL_END_STREAM, 7, get_dyn_idx,
				 sizeof(get_dyn_idx));
			break;
		}
		if (c->step == 2 && c->ended[7]) {
			if (srv_dyn_ua != 2) {
				lwsl_err("%s: server saw %s on %d of 2 "
					 "streams\n", __func__, RR_UA,
					 srv_dyn_ua);
				rr_finish("hpack state lost across a reset", 1);
			} else
				rr_finish("split header block decoded across "
					  "a stream reset", 0);
		}
		break;

	case RR_CASE_IGNORED:
		if (c->step == 0 && c->ended[1]) {
			/* the RST_STREAM goes before the PING's answer */
			c->step = 1;
			rr_frame(c, RR_PING, 0, 0, ping2, sizeof(ping2));
			break;
		}
		if (c->step == 1 && type == RR_PING) {
			if (!c->rst[1])
				rr_finish("no RST_STREAM after an ignored "
					  "frame", 1);
			else
				rr_finish("RST_STREAM sent after an ignored "
					  "frame", 0);
		}
		break;
	}
}

/* the start of a HEADERS frame's header block */
static int
rr_hdrs_block(uint8_t flags, const uint8_t **pl, size_t *len)
{
	if (flags & RR_FL_PADDED) {
		if (!*len)
			return 1;
		(*pl)++;
		(*len)--;
	}
	if (flags & RR_FL_PRIORITY) {
		if (*len < 5)
			return 1;
		*pl += 5;
		*len -= 5;
	}

	return 0;
}

/*
 * Does the response header block start with :status 200?  lws sends it as a
 * literal without indexing, with a literal name; take the indexed form too
 */
static int
rr_status_200(const uint8_t *pl, size_t len)
{
	static const uint8_t lit[] = {
		0x00, 7, ':', 's', 't', 'a', 't', 'u', 's', 3, '2', '0', '0'
	};

	return (len && pl[0] == 0x88) ||
	       (len >= sizeof(lit) && !memcmp(pl, lit, sizeof(lit)));
}

static int
rr_rx_frame(struct rr_conn *c, const uint8_t *f, size_t len)
{
	uint32_t sid = ((uint32_t)(f[5] & 0x7f) << 24) | ((uint32_t)f[6] << 16) |
		       ((uint32_t)f[7] << 8) | f[8];
	const uint8_t *pl = f + 9;
	uint8_t type = f[3], flags = f[4];
	uint32_t err;

	if (sid >= RR_MAX_SID)
		return 1;

	switch (type) {
	case RR_SETTINGS:
		if (flags & RR_FL_ACK)
			return 0;
		rr_frame(c, RR_SETTINGS, RR_FL_ACK, 0, NULL, 0);
		if (!c->started) {
			c->started = 1;
			rr_start(c);
		}
		return 0;

	case RR_PING:
		if (!(flags & RR_FL_ACK))
			return 0;
		break;

	case RR_HEADERS:
		if (rr_hdrs_block(flags, &pl, &len) ||
		    !rr_status_200(pl, len)) {
			lwsl_err("%s: unexpected HEADERS on sid %u\n",
				 __func__, (unsigned int)sid);
			return 1;
		}
		c->answered[sid] = 1;
		if (flags & RR_FL_END_STREAM)
			c->ended[sid] = 1;
		break;

	case RR_DATA:
		if (flags & RR_FL_END_STREAM)
			c->ended[sid] = 1;
		break;

	case RR_RST_STREAM:
		if (len != 4)
			return 1;
		err = ((uint32_t)pl[0] << 24) | ((uint32_t)pl[1] << 16) |
		      ((uint32_t)pl[2] << 8) | pl[3];
		lwsl_user("%s: RST_STREAM sid %u err %u\n", __func__,
			  (unsigned int)sid, (unsigned int)err);
		/* the server finished with a stream it answered */
		if (err || !c->ended[sid])
			return 1;
		c->rst[sid] = 1;
		break;

	case RR_GOAWAY:
		err = len >= 8 ? ((uint32_t)pl[4] << 24) |
				 ((uint32_t)pl[5] << 16) |
				 ((uint32_t)pl[6] << 8) | pl[7] : 0;
		lwsl_err("%s: GOAWAY err 0x%x\n", __func__, (unsigned int)err);
		return 1;

	default:
		return 0;
	}

	rr_progress(c, type, sid, pl, len);

	return 0;
}

static int
rr_rx(struct rr_conn *c, const uint8_t *in, size_t len)
{
	while (len && !done) {
		size_t need = 9, flen, n;

		if (c->rxf_len >= 9)
			need = 9 + (((size_t)c->rxf[0] << 16) |
				    ((size_t)c->rxf[1] << 8) | c->rxf[2]);
		if (need > sizeof(c->rxf))
			return 1;

		n = need - c->rxf_len;
		if (n > len)
			n = len;
		memcpy(c->rxf + c->rxf_len, in, n);
		c->rxf_len += n;
		in += n;
		len -= n;

		if (c->rxf_len < 9)
			continue;
		flen = ((size_t)c->rxf[0] << 16) | ((size_t)c->rxf[1] << 8) |
		       c->rxf[2];
		if (c->rxf_len < 9 + flen)
			continue;

		if (rr_rx_frame(c, c->rxf, flen))
			return 1;
		c->rxf_len = 0;
	}

	return 0;
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct rr_conn *c = (struct rr_conn *)lws_get_opaque_user_data(wsi);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		rr_finish("could not connect", 1);
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		if (!c)
			return -1;
		c->wsi = wsi;
		rr_preface(c);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!c || !c->tx_len)
			break;
		if (lws_write(wsi, c->tx + LWS_PRE, c->tx_len, LWS_WRITE_RAW) !=
							(int)c->tx_len)
			return -1;
		c->tx_len = 0;
		break;

	case LWS_CALLBACK_RAW_RX:
		if (!c || rr_rx(c, (const uint8_t *)in, len)) {
			rr_finish("unexpected frame from the server", 1);
			return -1;
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		if (c)
			c->wsi = NULL;
		rr_finish("the server closed the connection", 1);
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "raw-h2", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static int
rr_connect(struct rr_conn *c)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.port			= port;
	i.method		= "RAW";
	i.local_protocol_name	= "raw-h2";
	i.opaque_user_data	= c;

	return !lws_client_connect_via_info(&i);
}

static void
sigint_handler(int sig)
{
	rr_finish("interrupted", 1);
}

int
main(int argc, const char **argv)
{
	static const char * const case_names[] = { "ping", "hpack", "ignored" };
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* a server: size the fds tables to the process limit */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;
	if ((p = lws_cmdline_option(argc, argv, "--case"))) {
		for (n = 0; n < (int)LWS_ARRAY_SIZE(case_names); n++)
			if (!strcmp(p, case_names[n]))
				break;
		if (n == (int)LWS_ARRAY_SIZE(case_names)) {
			lwsl_err("--case ping (default) | hpack | ignored\n");
			return 1;
		}
		rr_case = (enum rr_case)n;
		n = 0;
	}

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: h2 stream reset, case %s\n",
		  case_names[rr_case]);

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_CPD_BYPASS;
	info.count_threads = 1;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.port = port;
	info.vhost_name = "srv-h2";
	info.protocols = protocols_srv;
	info.options |= LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("server vhost failed\n");
		goto bail;
	}

	info.options &= ~(uint64_t)LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("client vhost failed\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_deadline, rr_deadline_cb,
			 RR_DEADLINE_S * LWS_US_PER_SEC);

	if (rr_connect(&conn))
		rr_finish("connect failed", 1);

	while (!done && n >= 0)
		n = lws_service(context, 0);

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
