/*
 * lws-api-test-http-pss-lifecycle
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Checks that LWS_CALLBACK_HTTP_BIND_PROTOCOL and
 * LWS_CALLBACK_HTTP_DROP_PROTOCOL bracket every per-transaction allocation
 * (pss) an http server protocol is given, over several transactions riding
 * one connection (G-556).
 *
 * The server protocols allocate a resource in the pss at LWS_CALLBACK_HTTP
 * and free it at LWS_CALLBACK_HTTP_DROP_PROTOCOL, the way an app keeps an
 * lws_spa, an fd or an lwsac for the transaction.  That is only safe if
 *
 *  - BIND reaches the protocol before any other callback carrying the pss,
 *  - DROP follows every BIND exactly once, before the pss is freed: at the
 *    end of a keepalive transaction, when another protocol is bound, or when
 *    the connection closes.
 *
 * The requests the vhost's protocols[0] answers itself are the ones that used
 * to miss out: a path in a file mount with no such file falls through to
 * protocols[0]'s LWS_CALLBACK_HTTP (as the form examples' /form1 does), and
 * the first transaction of an h1 connection, or any h2 stream, reached it
 * with a pss that was never bound, so no DROP ever came for it and the
 * resource leaked.  A protocol bound by a callback mount always got its
 * BIND / DROP pair; that must not change.
 *
 * Legs, each a series of GET and POST requests from an lws client in the
 * same process, all riding one kept-warm connection:
 *
 *  - h1 to a path in the file mount answered by protocols[0]
 *  - h1 to a callback mount bound to its own protocol
 *  - the same two over h2 (cleartext, prior knowledge), each request a stream
 *
 * After each leg's connection has closed, the protocol under test must have
 * seen LWS_CALLBACK_HTTP for every request, each on a pss that had been bound
 * and was then dropped exactly once, with every resource freed, and no
 * callback on a pss that had not been bound.  The leg also checks every
 * request rode the same server connection.
 *
 * Then h2 streams that close before their request reaches the gates (G-690),
 * from a raw h2 client (cleartext, prior knowledge) writing the frames
 * itself:
 *
 *  - stream 1 a complete GET; once it is answered, stream 3's HEADERS
 *    without END_HEADERS, and the client disconnects
 *  - a request whose HEADERS has no :path
 *  - HEADERS without END_HEADERS, then RST_STREAM for it
 *
 * Such a stream never has a pss: protocols[0] must not be given any callback
 * on a pss it had no BIND for, nor an HTTP_WRITEABLE for a stream with no
 * request, and binds, drops and resources must still balance.  The stream's
 * CLOSED_HTTP comes with user NULL, as for an h1 connection closed before
 * its request.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#define BODY_LEN	16
#define LEG_TIMEOUT_S	20
#define KEEP_WARM_S	1

enum {
	PSS_UNBOUND,		/* zeroed by lws: no BIND seen yet */
	PSS_BOUND,
	PSS_DROPPED,
};

struct pss_srv {
	char		*res;		/* the transaction's resource */
	uint8_t		state;
	uint8_t		had_http;	/* this pss carried a request */
	uint8_t		respond;	/* we asked for WRITEABLE to answer */
};

/* what one server protocol saw during the leg in flight */

struct pstats {
	const char	*name;
	int		bind, drop, http;
	int		drop_of_txn;	/* DROPs of a pss that carried a request */
	int		unbound_use;	/* callback on a pss that had no BIND */
	int		nopss_writeable; /* HTTP_WRITEABLE with no request */
	int		nopss_closed;	/* CLOSED_HTTP of a wsi with no request */
	int		bad_bind;	/* BIND on a pss already bound */
	int		bad_drop;	/* DROP on a pss that was not bound */
	int		reused;		/* request on a pss that had one before */
	int		live;		/* resources allocated and not freed */
};

static struct pstats st_pcol0 = { .name = "pcol0" }, st_mnt = { .name = "mnt" };

static struct lws_context *context;
static struct lws_vhost *vh_cli;

static int port_h1 = 7681;
static int port_h2 = 7682;
static const char *server_addr = "127.0.0.1";

static int result = 1, failures, cur_leg = -1, eval_tries;
static int conn_next_id, conn_first_id, conns_gone, reqs_done, cli_failed;

static lws_sorted_usec_list_t sul_next, sul_req, sul_watchdog, sul_eval;

/* the raw h2 client's legs: streams closed before their request */
enum raw_case {
	RAW_NONE,		/* the leg uses the lws http client */
	RAW_PARTIAL_HDRS,	/* HEADERS without END_HEADERS, disconnect */
	RAW_NO_PATH,		/* HEADERS with no :path */
	RAW_RST_IN_HDRS,	/* HEADERS without END_HEADERS, RST_STREAM */
};

static const struct leg {
	const char	*name;
	const char	*path;
	struct pstats	*st;		/* the protocol taking the requests */
	int		h2;
	int		nreq;
	enum raw_case	raw;
} legs[] = {
	{ "h1 keepalive, protocols[0] via file mount", "/form1", &st_pcol0, 0, 4,
	  RAW_NONE },
	{ "h1 keepalive, callback mount",	 "/mnt/x", &st_mnt,   0, 3,
	  RAW_NONE },
#if defined(LWS_ROLE_H2)
	{ "h2 streams, protocols[0] via file mount",   "/form1", &st_pcol0, 1, 4,
	  RAW_NONE },
	{ "h2 streams, callback mount",		 "/mnt/x", &st_mnt,   1, 3,
	  RAW_NONE },
	{ "h2 stream abandoned in its HEADERS",	 "/form1", &st_pcol0, 1, 1,
	  RAW_PARTIAL_HDRS },
	{ "h2 stream with no :path",		 NULL,	   &st_pcol0, 1, 0,
	  RAW_NO_PATH },
	{ "h2 stream reset in its HEADERS",	 NULL,	   &st_pcol0, 1, 0,
	  RAW_RST_IN_HDRS },
#endif
};

static const char *
req_method(int n)
{
	/* alternate, so each leg has both bodyless and body transactions */
	return (n & 1) ? "POST" : "GET";
}

/* ---- server side ---- */

/*
 * Stamp the network connection when it is accepted, or the first time it
 * brings us a request: for h1 that is the connection wsi itself, for h2 the
 * parent of the stream
 */
static void
stamp_conn(struct lws *wsi)
{
	struct lws *nwsi = lws_get_network_wsi(wsi);

	if (!lws_get_opaque_user_data(nwsi))
		lws_set_opaque_user_data(nwsi,
					 (void *)(intptr_t)++conn_next_id);
}

static int
respond(struct lws *wsi)
{
	static const char body[] = "ok\n";
	uint8_t hbuf[LWS_PRE + 256], *start = &hbuf[LWS_PRE], *p = start,
		*end = &hbuf[sizeof(hbuf) - 1];

	if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/plain",
					(lws_filepos_t)sizeof(body) - 1,
					&p, end) ||
	    lws_finalize_write_http_header(wsi, start, &p, end))
		return 1;

	memcpy(start, body, sizeof(body) - 1);

	if (lws_write(wsi, start, sizeof(body) - 1,
		      LWS_WRITE_HTTP_FINAL) != (int)(sizeof(body) - 1))
		return 1;

	if (lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	const struct lws_protocols *pcol = lws_get_protocol(wsi);
	struct pstats *s = pcol ? (struct pstats *)pcol->user : NULL;
	struct pss_srv *pss = (struct pss_srv *)user;
	char *uri;
	int n;

	switch (reason) {

	case LWS_CALLBACK_HTTP_BIND_PROTOCOL:
		if (!s || !pss)
			break;
		s->bind++;
		if (pss->state != PSS_UNBOUND)
			s->bad_bind++;
		pss->state = PSS_BOUND;
		break;

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		if (!s || !pss)
			break;
		s->drop++;
		if (pss->state != PSS_BOUND)
			s->bad_drop++;
		if (pss->had_http)
			s->drop_of_txn++;
		if (pss->res) {
			free(pss->res);
			pss->res = NULL;
			s->live--;
		}
		pss->state = PSS_DROPPED;
		break;

	case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
		/* a connection accepted on one of our listeners */
		stamp_conn(wsi);
		break;

	case LWS_CALLBACK_WSI_DESTROY:
		/*
		 * A stamped network connection going away: a mux stream's
		 * network wsi is its parent, so streams are not counted
		 */
		if (lws_get_network_wsi(wsi) == wsi &&
		    lws_get_opaque_user_data(wsi))
			conns_gone++;
		break;

	/* the callbacks given a request's pss as user */
	case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
	case LWS_CALLBACK_HTTP_CONFIRM_UPGRADE:
	case LWS_CALLBACK_VERIFY_BASIC_AUTHORIZATION:
	case LWS_CALLBACK_CHECK_ACCESS_RIGHTS:
	case LWS_CALLBACK_ADD_HEADERS:
	case LWS_CALLBACK_HTTP_BODY:
	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
	case LWS_CALLBACK_HTTP_FILE_COMPLETION:
	case LWS_CALLBACK_HTTP_WRITEABLE:
	case LWS_CALLBACK_CLOSED_HTTP:
		if (!s)
			break;

		if (!pss) {
			/*
			 * Our protocols have a pss, so a request on them has
			 * one: until a wsi's request binds the protocol, it
			 * has nothing to write, and closes with user NULL
			 */
			if (reason == LWS_CALLBACK_HTTP_WRITEABLE) {
				lwsl_wsi_err(wsi, "%s: HTTP_WRITEABLE with no "
					     "request", s->name);
				s->nopss_writeable++;
			}
			if (reason == LWS_CALLBACK_CLOSED_HTTP)
				s->nopss_closed++;
			break;
		}

		/* any callback given a pss must come after its BIND */
		if (pss->state == PSS_UNBOUND) {
			lwsl_wsi_err(wsi, "%s: reason %d on an unbound pss",
				     s->name, (int)reason);
			s->unbound_use++;
		}
		break;

	default:
		break;
	}

	switch (reason) {

	case LWS_CALLBACK_HTTP:
		if (!s || !pss) {
			lwsl_wsi_err(wsi, "request with no protocol or pss");
			cli_failed = 1;
			return -1;
		}
		s->http++;
		if (pss->state != PSS_BOUND) {
			lwsl_wsi_err(wsi, "%s: LWS_CALLBACK_HTTP on a pss with "
				     "no BIND", s->name);
			s->unbound_use++;
		}
		if (pss->had_http)
			s->reused++;
		pss->had_http = 1;
		stamp_conn(wsi);

		/* the per-transaction resource DROP is responsible for */
		pss->res = malloc(64);
		if (!pss->res)
			return -1;
		s->live++;

		lwsl_user("%s: %s: HTTP %s\n", __func__, s->name,
			  in ? (const char *)in : "");

		if (lws_http_get_uri_and_method(wsi, &uri, &n) == LWSHUMETH_POST)
			/* answer once the body is in */
			return 0;

		pss->respond = 1;
		lws_callback_on_writable(wsi);
		return 0;

	default:
		break;
	}

	switch (reason) {
	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		if (pss) {
			pss->respond = 1;
			lws_callback_on_writable(wsi);
		}
		return 0;

	case LWS_CALLBACK_HTTP_BODY:
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss || !pss->respond)
			/* not one we asked for: nothing to answer yet */
			return 0;
		pss->respond = 0;
		return respond(wsi);

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	/* protocols[0]: takes whatever the mounts don't bind elsewhere */
	{ "pcol0", callback_srv, sizeof(struct pss_srv), 0, 0, &st_pcol0, 0 },
	{ "mnt", callback_srv, sizeof(struct pss_srv), 0, 0, &st_mnt, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_http_mount mount_mnt = {
	.mountpoint		= "/mnt",
	.origin			= "mnt",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 4,
};

/*
 * Files from the test's own directory: the requests name a file that is not
 * there, so the file mount hands them to protocols[0]'s LWS_CALLBACK_HTTP
 */
static const struct lws_http_mount mount_files = {
	.mount_next		= &mount_mnt,
	.mountpoint		= "/",
	.origin			= ".",
	.def			= "index.html",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 1,
};

/* ---- client side ---- */

static void req_cb(lws_sorted_usec_list_t *sul);
static void leg_eval_cb(lws_sorted_usec_list_t *sul);

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	uint8_t sbuf[LWS_PRE + BODY_LEN], **pp, *end;
	char rbuf[LWS_PRE + 512], *px = &rbuf[LWS_PRE];
	int lenx = sizeof(rbuf) - LWS_PRE, n, post;

	post = !strcmp(req_method(reqs_done), "POST");

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: client: connection error: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		cli_failed = 1;
		lws_sul_schedule(context, 0, &sul_eval, leg_eval_cb, 1);
		break;

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		if (!post)
			break;
		pp = (uint8_t **)in;
		end = (*pp) + len;
		if (lws_add_http_header_content_length(wsi,
						(lws_filepos_t)BODY_LEN,
						pp, end))
			return -1;
		lws_client_http_body_pending(wsi, 1);
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (!post)
			break;
		for (n = 0; n < BODY_LEN; n++)
			sbuf[LWS_PRE + n] = (uint8_t)('a' + n);
		lws_client_http_body_pending(wsi, 0);
		if (lws_write(wsi, &sbuf[LWS_PRE], BODY_LEN,
			      LWS_WRITE_HTTP_FINAL) != BODY_LEN)
			return -1;
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		n = (int)lws_http_client_http_response(wsi);
		/* joining a warm h2 connection is ESTABLISHED with no status */
		if (n && n != HTTP_STATUS_OK) {
			lwsl_err("%s: client: status %d\n", __func__, n);
			cli_failed = 1;
		}
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		reqs_done++;
		if (reqs_done < legs[cur_leg].nreq)
			/* the next request rides the kept-warm connection */
			lws_sul_schedule(context, 0, &sul_req, req_cb, 1);
		else
			/*
			 * The connection idles out of its keep-warm and
			 * closes: the server then drops the pss it bound
			 * for a next request that never came
			 */
			lws_sul_schedule(context, 0, &sul_eval, leg_eval_cb,
					 50 * LWS_US_PER_MS);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

#if defined(LWS_ROLE_H2)

/*
 * ---- client side: raw h2 ----
 *
 * The lws client can't leave a request unfinished, so these legs write the
 * h2 frames themselves
 */

#define H2_HEADERS		1
#define H2_RST_STREAM		3
#define H2_SETTINGS		4
#define H2_GOAWAY		7
#define H2_FL_END_STREAM	0x01
#define H2_FL_ACK		0x01
#define H2_FL_END_HEADERS	0x04
#define H2_ERR_CANCEL		8

/* how long the server is given to read the last frames before we go */
#define RAW_LINGER_MS		200

static struct raw_conn {
	struct lws		*wsi;
	uint8_t			tx[LWS_PRE + 512];
	size_t			tx_len;
	uint8_t			rxf[16384 + 9]; /* a frame is reassembled here */
	size_t			rxf_len;
	char			hangup;	/* close at the next writeable */
} rc;

static lws_sorted_usec_list_t sul_raw_hangup;

static void
raw_add(const void *p, size_t len)
{
	if (rc.tx_len + len > sizeof(rc.tx) - LWS_PRE) {
		lwsl_err("%s: tx overflow\n", __func__);
		cli_failed = 1;
		return;
	}
	memcpy(rc.tx + LWS_PRE + rc.tx_len, p, len);
	rc.tx_len += len;
	if (rc.wsi)
		lws_callback_on_writable(rc.wsi);
}

static void
raw_frame(uint8_t type, uint8_t flags, uint32_t sid, const void *pl,
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

	raw_add(h, sizeof(h));
	if (len)
		raw_add(pl, len);
}

/* hpack literal without indexing, indexed name (< 15), short value */
static size_t
raw_lit(uint8_t *p, int name_idx, const char *v)
{
	size_t vl = strlen(v), n = 0;

	p[n++] = (uint8_t)name_idx;
	p[n++] = (uint8_t)vl;
	memcpy(p + n, v, vl);

	return n + vl;
}

/* the header block of a GET, or of one with no :path if path is NULL */
static void
raw_headers(uint32_t sid, uint8_t flags, const char *path)
{
	uint8_t b[64];
	size_t n = 0;

	b[n++] = 0x82;	/* :method GET */
	b[n++] = 0x86;	/* :scheme http */
	if (path)
		n += raw_lit(b + n, 4, path);		/* :path */
	n += raw_lit(b + n, 1, "localhost");		/* :authority */

	raw_frame(H2_HEADERS, flags, sid, b, n);
}

static void
raw_hangup_cb(lws_sorted_usec_list_t *sul)
{
	if (!rc.wsi)
		return;
	rc.hangup = 1;
	lws_callback_on_writable(rc.wsi);
}

/* the case's frames are all sent: let the server read them, then go */
static void
raw_linger_then_hangup(void)
{
	lws_sul_schedule(context, 0, &sul_raw_hangup, raw_hangup_cb,
			 RAW_LINGER_MS * LWS_US_PER_MS);
}

static void
raw_start(void)
{
	static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
	static const uint8_t cancel[] = { 0, 0, 0, H2_ERR_CANCEL };

	raw_add(preface, sizeof(preface) - 1);
	raw_frame(H2_SETTINGS, 0, 0, NULL, 0);

	switch (legs[cur_leg].raw) {
	case RAW_PARTIAL_HDRS:
		/* stream 3 follows once this is answered */
		raw_headers(1, H2_FL_END_HEADERS | H2_FL_END_STREAM,
			    legs[cur_leg].path);
		break;

	case RAW_NO_PATH:
		raw_headers(1, H2_FL_END_HEADERS | H2_FL_END_STREAM, NULL);
		raw_linger_then_hangup();
		break;

	case RAW_RST_IN_HDRS:
		/* a connection error: only CONTINUATION may follow it */
		raw_headers(1, H2_FL_END_STREAM, "/form1");
		raw_frame(H2_RST_STREAM, 0, 1, cancel, sizeof(cancel));
		raw_linger_then_hangup();
		break;

	default:
		break;
	}
}

static void
raw_rx_frame(const uint8_t *f, size_t flen)
{
	uint32_t sid = ((uint32_t)(f[5] & 0x7f) << 24) |
		       ((uint32_t)f[6] << 16) | ((uint32_t)f[7] << 8) | f[8];
	uint8_t type = f[3], flags = f[4];

	lwsl_info("%s: type %u, flags 0x%x, sid %u, len %u\n", __func__,
		  type, flags, (unsigned int)sid, (unsigned int)flen);

	if (type == H2_SETTINGS && !(flags & H2_FL_ACK)) {
		raw_frame(H2_SETTINGS, H2_FL_ACK, 0, NULL, 0);
		return;
	}

	if (type == H2_GOAWAY) {
		lwsl_user("%s: GOAWAY from the server\n", __func__);
		return;
	}

	if (type == H2_RST_STREAM) {
		lwsl_user("%s: RST_STREAM on stream %u\n", __func__,
			  (unsigned int)sid);
		return;
	}

	if (sid != 1 || !(flags & H2_FL_END_STREAM) ||
	    (legs[cur_leg].raw != RAW_PARTIAL_HDRS) || reqs_done)
		return;

	/*
	 * Stream 1 is answered: stream 3's HEADERS, its block never ended,
	 * and then we go without its CONTINUATION
	 */
	reqs_done++;
	raw_headers(3, H2_FL_END_STREAM, legs[cur_leg].path);
	raw_linger_then_hangup();
}

static void
raw_rx(const uint8_t *in, size_t len)
{
	size_t n, flen;

	while (len) {
		/* the frame header first, then as much payload as it says */
		n = rc.rxf_len < 9 ? 9 - rc.rxf_len : 0;
		if (!n) {
			flen = ((size_t)rc.rxf[0] << 16) |
			       ((size_t)rc.rxf[1] << 8) | rc.rxf[2];
			if (flen > sizeof(rc.rxf) - 9) {
				lwsl_err("%s: frame too big\n", __func__);
				cli_failed = 1;
				return;
			}
			n = 9 + flen - rc.rxf_len;
		}
		if (n > len)
			n = len;
		memcpy(rc.rxf + rc.rxf_len, in, n);
		rc.rxf_len += n;
		in += n;
		len -= n;

		if (rc.rxf_len < 9)
			continue;
		flen = ((size_t)rc.rxf[0] << 16) | ((size_t)rc.rxf[1] << 8) |
		       rc.rxf[2];
		if (rc.rxf_len < 9 + flen)
			continue;

		raw_rx_frame(rc.rxf, flen);
		rc.rxf_len = 0;
	}
}

static int
callback_raw(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: raw client: connection error: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		cli_failed = 1;
		lws_sul_schedule(context, 0, &sul_eval, leg_eval_cb, 1);
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		rc.wsi = wsi;
		raw_start();
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (rc.hangup)
			return -1;
		if (!rc.tx_len)
			break;
		if (lws_write(wsi, rc.tx + LWS_PRE, rc.tx_len, LWS_WRITE_RAW) !=
							(int)rc.tx_len)
			return -1;
		rc.tx_len = 0;
		break;

	case LWS_CALLBACK_RAW_RX:
		raw_rx((const uint8_t *)in, len);
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		/* the server closes its side once it has read our close */
		rc.wsi = NULL;
		lws_sul_cancel(&sul_raw_hangup);
		lws_sul_schedule(context, 0, &sul_eval, leg_eval_cb,
				 50 * LWS_US_PER_MS);
		break;

	default:
		break;
	}

	return 0;
}

static void
raw_connect(void)
{
	struct lws_client_connect_info i;

	memset(&rc, 0, sizeof(rc));

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.port			= port_h2;
	i.method		= "RAW";
	i.local_protocol_name	= "raw-h2";

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		cli_failed = 1;
		lws_sul_schedule(context, 0, &sul_eval, leg_eval_cb, 1);
	}
}

#endif

static const struct lws_protocols protocols_cli[] = {
	{ "cli", callback_cli, 0, 0, 0, NULL, 0 },
#if defined(LWS_ROLE_H2)
	{ "raw-h2", callback_raw, 0, 0, 0, NULL, 0 },
#endif
	LWS_PROTOCOL_LIST_TERM
};

/* ---- leg sequencing ---- */

static void next_leg(lws_sorted_usec_list_t *sul);

static void
req_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

#if defined(LWS_ROLE_H2)
	if (legs[cur_leg].raw != RAW_NONE) {
		lwsl_user("%s: raw h2 client\n", __func__);
		raw_connect();
		return;
	}
#endif

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.port			= legs[cur_leg].h2 ? port_h2 : port_h1;
	i.path			= legs[cur_leg].path;
	i.method		= req_method(reqs_done);
	i.protocol		= "cli";
	i.keep_warm_secs	= KEEP_WARM_S;
	i.ssl_connection	= LCCSCF_PIPELINE;
#if defined(LWS_ROLE_H2)
	if (legs[cur_leg].h2)
		i.ssl_connection |= LCCSCF_H2_PRIOR_KNOWLEDGE;
#endif

	lwsl_user("%s: request %d: %s %s\n", __func__, reqs_done, i.method,
		  i.path);

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		cli_failed = 1;
		lws_sul_schedule(context, 0, &sul_eval, leg_eval_cb, 1);
	}
}

static int
check(const char *leg, const struct pstats *s, const char *what, int got,
      int want)
{
	if (got == want)
		return 0;

	lwsl_err("%s: %s: %s: %s %d, expected %d\n", __func__, leg, s->name,
		 what, got, want);

	return 1;
}

static int
check_protocol(const char *leg, const struct pstats *s, int nreq)
{
	int f = 0;

	lwsl_user("%s: %s: bind %d, drop %d, http %d, drops of a request's "
		  "pss %d\n", leg, s->name, s->bind, s->drop, s->http,
		  s->drop_of_txn);

	f |= check(leg, s, "requests", s->http, nreq);
	f |= check(leg, s, "drops of a transaction's pss", s->drop_of_txn,
		   nreq);
	f |= check(leg, s, "drops minus binds", s->drop - s->bind, 0);
	f |= check(leg, s, "callbacks on an unbound pss", s->unbound_use, 0);
	f |= check(leg, s, "writeables with no request", s->nopss_writeable,
		   0);
	f |= check(leg, s, "binds of a bound pss", s->bad_bind, 0);
	f |= check(leg, s, "drops of an unbound pss", s->bad_drop, 0);
	f |= check(leg, s, "requests on a reused pss", s->reused, 0);
	f |= check(leg, s, "resources leaked", s->live, 0);

	return f;
}

static void
leg_evaluate(void)
{
	const struct leg *l = &legs[cur_leg];
	int ok = !cli_failed;

	lws_sul_cancel(&sul_watchdog);

	if (reqs_done != l->nreq) {
		lwsl_err("%s: %s: %d of %d requests completed\n", __func__,
			 l->name, reqs_done, l->nreq);
		ok = 0;
	}

	/* every request rode the one connection */
	if (conn_next_id - conn_first_id != 1) {
		lwsl_err("%s: %s: requests came on %d server connections, "
			 "expected 1\n", __func__, l->name,
			 conn_next_id - conn_first_id);
		ok = 0;
	}

	if (check_protocol(l->name, l->st, l->nreq))
		ok = 0;

	/* a raw leg's stream with no request did close, through the callback */
	if (l->raw != RAW_NONE && !l->st->nopss_closed) {
		lwsl_err("%s: %s: no CLOSED_HTTP for a stream with no request\n",
			 __func__, l->name);
		ok = 0;
	}

	/*
	 * On a callback mount, protocols[0] still holds the pss between
	 * transactions, and the gates' callbacks for each request: whatever
	 * it was bound for, it must be dropped
	 */
	if (l->st == &st_mnt &&
	    check_protocol(l->name, &st_pcol0, 0))
		ok = 0;

	lwsl_user("--- %s: %s ---\n", l->name, ok ? "PASS" : "FAIL");
	if (!ok)
		failures++;

	lws_sul_schedule(context, 0, &sul_next, next_leg, 1);
}

static void
leg_eval_cb(lws_sorted_usec_list_t *sul)
{
	int conns = conn_next_id - conn_first_id;

	/*
	 * Wait for the leg's connection to be closed on the server side, its
	 * last pss dropped with it, before judging
	 */
	if (!cli_failed && (!conns || conns_gone < conns)) {
		if (eval_tries++ < (KEEP_WARM_S + 5) * 20) {
			lws_sul_schedule(context, 0, &sul_eval, leg_eval_cb,
					 50 * LWS_US_PER_MS);
			return;
		}
		lwsl_err("%s: server connection did not close\n", __func__);
		cli_failed = 1;
	}

	leg_evaluate();
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: leg did not complete\n", __func__);
	failures++;
	result = 1;
	lws_default_loop_exit(context);
}

static void
next_leg(lws_sorted_usec_list_t *sul)
{
	struct pstats *s[] = { &st_pcol0, &st_mnt };
	size_t n;

	cur_leg++;

	if (cur_leg == (int)LWS_ARRAY_SIZE(legs)) {
		result = failures ? 1 : 0;
		lws_default_loop_exit(context);

		return;
	}

	lwsl_user("=== leg %d: %s ===\n", cur_leg, legs[cur_leg].name);

	/* each leg is judged on what it alone did */
	for (n = 0; n < LWS_ARRAY_SIZE(s); n++) {
		const char *name = s[n]->name;

		memset(s[n], 0, sizeof(*s[n]));
		s[n]->name = name;
	}

	reqs_done = 0;
	cli_failed = 0;
	eval_tries = 0;
	conn_first_id = conn_next_id;
	conns_gone = 0;

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 LEG_TIMEOUT_S * LWS_US_PER_SEC);
	lws_sul_schedule(context, 0, &sul_req, req_cb, 1);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* listeners (h1 + h2, v4 + v6) and both ends of the connections */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_h1 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--h2-port")))
		port_h2 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: http pss BIND / DROP lifecycle\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.protocols = protocols_srv;
	info.mounts = &mount_files;

	info.port = port_h1;
	info.vhost_name = "srv-h1";

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create h1 server vhost\n");
		goto bail;
	}

#if defined(LWS_ROLE_H2)
	info.port = port_h2;
	info.vhost_name = "srv-h2";
	info.options |= LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create h2 server vhost\n");
		goto bail;
	}
	info.options &= ~(uint64_t)LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
#endif

	/* client vhost, no listener */

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	info.mounts = NULL;

	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	result = 1;
	lws_sul_schedule(context, 0, &sul_next, next_leg, 1);

	while (n >= 0)
		n = lws_service(context, 0);

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s (%d of %d legs failed)\n",
		  result ? "FAIL" : "PASS", failures,
		  (int)LWS_ARRAY_SIZE(legs));

	return result;
}
