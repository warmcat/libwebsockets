/*
 * lws-api-test-h2-ah-refuse
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Every h2 request needs a header table (ah) from the server's pool while
 * its headers are decoded, and a POST keeps it until its body completes.
 * When the pool is in use, a new stream can't be served: that stream must
 * be refused with RST_STREAM REFUSED_STREAM, which tells the client it is
 * safe to retry, and the connection and its other streams must go on.
 * Trailers on a stream that already gave its ah back must not need one
 * from the pool again either.
 *
 * The server has a pool with room for two streams' ahs.  It has no captive
 * portal check, whose client would take one too.  One raw h2 client connection
 * (cleartext, prior knowledge) does, in order:
 *
 *  - POST /hold-a, body still to come: holds an ah
 *  - POST /trailers, with its whole content-length of body but no
 *    END_STREAM: its body completes and its ah goes back
 *  - POST /hold-b, body still to come: takes that ah, the pool is full
 *  - the trailers for /trailers, with END_STREAM: there is no ah for them,
 *    they must still end the request, which is answered
 *  - POST /later: refused with REFUSED_STREAM.  Its header block puts
 *    ":path: /later" (literal value, indexed name) and "user-agent: ahr-ua"
 *    (literal value and name) in the hpack dynamic table
 *  - the bodies of /hold-a and /hold-b end, both are answered
 *  - GET with its :path and user-agent as dynamic table entries: only a
 *    server that kept the refused block's entries, values and all, sees
 *    "/later" with "ahr-ua", so the connection's hpack state stayed in step
 *    through the refusal, as a client retrying it on the connection needs
 *
 * Without the fix, the full pool closed the whole connection at the
 * trailers, and again at the refused stream's HEADERS.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

/*
 * The server's ah pool: two for streams, and one the network connection
 * itself holds (prior knowledge h2 starts out parsing as h1 does)
 */
#define AHR_POOL		(2 + 1)
/* the body /trailers declares and sends before its trailers */
#define AHR_TR_BODY		"abcd"
#define AHR_TR_CL		"4"
/* the server answers /trailers this long after its body completed */
#define AHR_TR_ANSWER_MS	300
/* the client sends the rest this long after the first part */
#define AHR_PHASE1_MS		200
#define AHR_DEADLINE_S		10

/* h2 framing */
#define AHR_DATA		0
#define AHR_HEADERS		1
#define AHR_RST_STREAM		3
#define AHR_SETTINGS		4
#define AHR_GOAWAY		7
#define AHR_FL_END_STREAM	0x01
#define AHR_FL_ACK		0x01
#define AHR_FL_END_HEADERS	0x04
#define AHR_FL_PADDED		0x08
#define AHR_FL_PRIORITY		0x20
#define AHR_ERR_REFUSED		7

/* the client's streams */
#define AHR_SID_HOLD_A		1
#define AHR_SID_TRAILERS	3
#define AHR_SID_HOLD_B		5
#define AHR_SID_REFUSED		7
#define AHR_SID_LATER		9

struct pss_srv {
	lws_sorted_usec_list_t	sul;	/* /trailers' late answer */
	struct lws		*wsi;
	char			path[32];
	char			respond;
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_phase1, sul_deadline;
static const char *server_addr = "127.0.0.1";
static int port = 7681, fails, done, phase1;

/* what the server saw */
static int srv_later_seen, srv_tr_completed_early, srv_refused_seen;

/* what the client saw */
static int cli_refused, cli_answered[AHR_SID_LATER + 1], cli_later_sent;

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

static void
srv_tr_answer_cb(lws_sorted_usec_list_t *sul)
{
	struct pss_srv *pss = lws_container_of(sul, struct pss_srv, sul);

	pss->respond = 1;
	lws_callback_on_writable(pss->wsi);
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	char *uri, ua[16];
	int n, post;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		pss->wsi = wsi;
		lws_strncpy(pss->path, in ? (const char *)in : "",
			    sizeof(pss->path));
		lwsl_user("%s: server: %s\n", __func__, pss->path);
		post = lws_http_get_uri_and_method(wsi, &uri, &n) ==
							LWSHUMETH_POST;

		if (!strcmp(pss->path, "/later")) {
			if (post)
				/* the refused stream must never get here */
				srv_refused_seen = 1;
			else if (lws_hdr_copy(wsi, ua, sizeof(ua),
					      WSI_TOKEN_HTTP_USER_AGENT) > 0 &&
				 !strcmp(ua, "ahr-ua"))
				srv_later_seen = 1;
		}

		if (post)
			return 0; /* answered at its body completion */

		pss->respond = 1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_BODY:
		return 0;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		if (!strcmp(pss->path, "/trailers")) {
			/*
			 * The ah goes back now, before the trailers come:
			 * answer once they are in
			 */
			srv_tr_completed_early = !phase1;
			lws_sul_schedule(context, 0, &pss->sul,
					 srv_tr_answer_cb,
					 AHR_TR_ANSWER_MS * LWS_US_PER_MS);
			return 0;
		}
		pss->respond = 1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss->respond)
			return 0;
		pss->respond = 0;
		return srv_respond(wsi);

	case LWS_CALLBACK_CLOSED_HTTP:
		if (pss) /* not the network connection's */
			lws_sul_cancel(&pss->sul);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* ---- client: raw h2 ---- */

struct ahr_tx {
	uint8_t		buf[LWS_PRE + 1024];
	size_t		len;
};

static struct ahr_tx tx;
static struct lws *cli_wsi;

/* frames are reassembled here */
static uint8_t rxf[16384 + 9];
static size_t rxf_len;

static void
ahr_finish(const char *why, int failed)
{
	if (done)
		return;
	done = 1;
	if (failed) {
		lwsl_err("%s: FAILED: %s\n", __func__, why);
		fails++;
	} else
		lwsl_user("%s: %s\n", __func__, why);

	lws_sul_cancel(&sul_phase1);
	lws_sul_cancel(&sul_deadline);
	lws_cancel_service(context);
}

static void
ahr_add(const void *p, size_t len)
{
	if (tx.len + len > sizeof(tx.buf) - LWS_PRE) {
		ahr_finish("tx overflow", 1);
		return;
	}
	memcpy(tx.buf + LWS_PRE + tx.len, p, len);
	tx.len += len;
	if (cli_wsi)
		lws_callback_on_writable(cli_wsi);
}

static void
ahr_frame(uint8_t type, uint8_t flags, uint32_t sid, const void *pl,
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

	ahr_add(h, sizeof(h));
	if (len)
		ahr_add(pl, len);
}

/* hpack literal, without indexing (or with, if incr), indexed name */
static size_t
ahr_lit(uint8_t *p, int name_idx, int incr, const char *v)
{
	size_t vl = strlen(v), n = 0;

	if (incr)
		p[n++] = (uint8_t)(0x40 | name_idx); /* names here are < 63 */
	else if (name_idx < 15)
		p[n++] = (uint8_t)name_idx;
	else {
		p[n++] = 0x0f;
		p[n++] = (uint8_t)(name_idx - 15);
	}
	p[n++] = (uint8_t)vl; /* values here are < 127 */
	memcpy(p + n, v, vl);

	return n + vl;
}

/* POST path, content-length cl, body to follow */
static void
ahr_post(uint32_t sid, const char *path, int incr, const char *cl)
{
	/* literal with incremental indexing, literal name */
	static const uint8_t ua[] = {
		0x40, 10, 'u', 's', 'e', 'r', '-', 'a', 'g', 'e', 'n', 't',
		6, 'a', 'h', 'r', '-', 'u', 'a'
	};
	uint8_t b[128];
	size_t n = 0;

	b[n++] = 0x83;	/* :method POST */
	b[n++] = 0x86;	/* :scheme http */
	n += ahr_lit(b + n, 4, incr, path);		/* :path */
	n += ahr_lit(b + n, 1, 0, "localhost");		/* :authority */
	n += ahr_lit(b + n, 28, 0, cl);			/* content-length */
	if (incr) {
		memcpy(b + n, ua, sizeof(ua));
		n += sizeof(ua);
	}

	ahr_frame(AHR_HEADERS, AHR_FL_END_HEADERS, sid, b, n);
}

static void
ahr_phase0(void)
{
	static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

	ahr_add(preface, sizeof(preface) - 1);
	ahr_frame(AHR_SETTINGS, 0, 0, NULL, 0);

	ahr_post(AHR_SID_HOLD_A, "/hold-a", 0, "1");
	ahr_post(AHR_SID_TRAILERS, "/trailers", 0, AHR_TR_CL);
	ahr_frame(AHR_DATA, 0, AHR_SID_TRAILERS, AHR_TR_BODY,
		  sizeof(AHR_TR_BODY) - 1);
}

static void
ahr_phase1_cb(lws_sorted_usec_list_t *sul)
{
	/* literal without indexing, new name: x-trailer: 1 */
	static const uint8_t trailers[] = {
		0x00, 9, 'x', '-', 't', 'r', 'a', 'i', 'l', 'e', 'r', 1, '1'
	};

	phase1 = 1;

	ahr_post(AHR_SID_HOLD_B, "/hold-b", 0, "1");
	ahr_frame(AHR_HEADERS, AHR_FL_END_HEADERS | AHR_FL_END_STREAM,
		  AHR_SID_TRAILERS, trailers, sizeof(trailers));
	/*
	 * Its :path and user-agent go in the dynamic table, as entries 63
	 * and 62
	 */
	ahr_post(AHR_SID_REFUSED, "/later", 1, "1");
}

static void
ahr_deadline_cb(lws_sorted_usec_list_t *sul)
{
	ahr_finish("deadline", 1);
}

static void
ahr_check_progress(void)
{
	static const uint8_t get_later[] = {
		0x82,	/* :method GET */
		0x86,	/* :scheme http */
		0xbf,	/* :path, dynamic table entry 63: "/later" */
		0x01, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
		0xbe	/* user-agent, dynamic table entry 62: "ahr-ua" */
	};

	if (cli_refused && !cli_later_sent &&
	    cli_answered[AHR_SID_HOLD_A] && cli_answered[AHR_SID_HOLD_B] &&
	    cli_answered[AHR_SID_TRAILERS]) {
		cli_later_sent = 1;
		ahr_frame(AHR_HEADERS, AHR_FL_END_HEADERS | AHR_FL_END_STREAM,
			  AHR_SID_LATER, get_later, sizeof(get_later));
	}

	if (cli_answered[AHR_SID_LATER])
		ahr_finish("all streams answered, refused one refused", 0);
}

/*
 * Does the response header block start with :status 200?  lws sends it as a
 * literal without indexing, with a literal name; take the indexed form too
 */
static int
ahr_status_200(const uint8_t *pl, size_t len)
{
	static const uint8_t lit[] = {
		0x00, 7, ':', 's', 't', 'a', 't', 'u', 's', 3, '2', '0', '0'
	};

	return (len && pl[0] == 0x88) ||
	       (len >= sizeof(lit) && !memcmp(pl, lit, sizeof(lit)));
}

static int
ahr_rx_frame(const uint8_t *f, size_t len)
{
	uint32_t sid = ((uint32_t)(f[5] & 0x7f) << 24) | ((uint32_t)f[6] << 16) |
		       ((uint32_t)f[7] << 8) | f[8];
	const uint8_t *pl = f + 9;
	uint8_t type = f[3], flags = f[4];
	uint32_t err;

	switch (type) {
	case AHR_SETTINGS:
		if (!(flags & AHR_FL_ACK))
			ahr_frame(AHR_SETTINGS, AHR_FL_ACK, 0, NULL, 0);
		break;

	case AHR_HEADERS:
		if (flags & AHR_FL_PADDED) {
			if (!len)
				return 1;
			pl++;
			len--;
		}
		if (flags & AHR_FL_PRIORITY) {
			if (len < 5)
				return 1;
			pl += 5;
			len -= 5;
		}
		if (!ahr_status_200(pl, len) || sid > AHR_SID_LATER ||
		    sid == AHR_SID_REFUSED) {
			lwsl_err("%s: unexpected HEADERS on sid %u (0x%02x)\n",
				 __func__, (unsigned int)sid, len ? pl[0] : 0);
			return 1;
		}
		lwsl_user("%s: sid %u answered 200\n", __func__,
			  (unsigned int)sid);
		cli_answered[sid] = 1;
		ahr_check_progress();
		break;

	case AHR_RST_STREAM:
		if (len != 4)
			return 1;
		err = ((uint32_t)pl[0] << 24) | ((uint32_t)pl[1] << 16) |
		      ((uint32_t)pl[2] << 8) | pl[3];
		lwsl_user("%s: RST_STREAM sid %u err %u\n", __func__,
			  (unsigned int)sid, (unsigned int)err);
		if (sid != AHR_SID_REFUSED || err != AHR_ERR_REFUSED) {
			/* the server finished with a stream we were done with */
			if (sid < AHR_SID_LATER + 1 && cli_answered[sid] &&
			    !err)
				break;
			return 1;
		}
		cli_refused = 1;
		/* the held streams' bodies end now */
		ahr_frame(AHR_DATA, AHR_FL_END_STREAM, AHR_SID_HOLD_A, "x", 1);
		ahr_frame(AHR_DATA, AHR_FL_END_STREAM, AHR_SID_HOLD_B, "x", 1);
		ahr_check_progress();
		break;

	case AHR_GOAWAY:
		lwsl_err("%s: GOAWAY\n", __func__);
		return 1;

	default:
		break;
	}

	return 0;
}

static int
ahr_rx(const uint8_t *in, size_t len)
{
	while (len) {
		size_t need = 9, flen, n;

		if (rxf_len >= 9)
			need = 9 + (((size_t)rxf[0] << 16) |
				    ((size_t)rxf[1] << 8) | rxf[2]);
		if (need > sizeof(rxf))
			return 1;

		n = need - rxf_len;
		if (n > len)
			n = len;
		memcpy(rxf + rxf_len, in, n);
		rxf_len += n;
		in += n;
		len -= n;

		if (rxf_len < 9)
			continue;
		flen = ((size_t)rxf[0] << 16) | ((size_t)rxf[1] << 8) | rxf[2];
		if (rxf_len < 9 + flen)
			continue;

		if (ahr_rx_frame(rxf, flen))
			return 1;
		rxf_len = 0;
	}

	return 0;
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		ahr_finish("could not connect", 1);
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		cli_wsi = wsi;
		ahr_phase0();
		lws_sul_schedule(context, 0, &sul_phase1, ahr_phase1_cb,
				 AHR_PHASE1_MS * LWS_US_PER_MS);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!tx.len)
			break;
		if (lws_write(wsi, tx.buf + LWS_PRE, tx.len, LWS_WRITE_RAW) !=
							(int)tx.len)
			return -1;
		tx.len = 0;
		break;

	case LWS_CALLBACK_RAW_RX:
		if (ahr_rx((const uint8_t *)in, len)) {
			ahr_finish("unexpected frame from the server", 1);
			return -1;
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		cli_wsi = NULL;
		ahr_finish("the server closed the connection", 1);
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

static void
sigint_handler(int sig)
{
	ahr_finish("interrupted", 1);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
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

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: h2 stream refused when no ah is free\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_CPD_BYPASS;
	info.count_threads = 1;
	info.max_http_header_pool = AHR_POOL;

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

	lws_sul_schedule(context, 0, &sul_deadline, ahr_deadline_cb,
			 AHR_DEADLINE_S * LWS_US_PER_SEC);

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.port			= port;
	i.method		= "RAW";
	i.local_protocol_name	= "raw-h2";

	if (!lws_client_connect_via_info(&i))
		ahr_finish("connect failed", 1);

	while (!done && n >= 0)
		n = lws_service(context, 0);

	if (!srv_tr_completed_early) {
		lwsl_err("FAILED: /trailers' body didn't complete before its "
			 "trailers came\n");
		fails++;
	}
	if (srv_refused_seen) {
		lwsl_err("FAILED: the refused stream was served\n");
		fails++;
	}
	if (!srv_later_seen) {
		lwsl_err("FAILED: the server didn't decode the GET's fields "
			 "from the refused block's dynamic table entries\n");
		fails++;
	}

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
