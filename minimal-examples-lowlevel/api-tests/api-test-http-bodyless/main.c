/*
 * lws-api-test-http-bodyless
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Answers that have no body must not send one, and must end where the peer
 * expects them to.  On a kept-alive h1 connection anything else desyncs it:
 * the peer reads the next answer from the stray bytes, or waits for an end
 * that never comes.  The server's handlers are written as an app writes
 * them, unaware of either:
 *
 *  - /body answers 200 text/plain with lws_add_http_common_headers() and
 *    its Content-Length, then writes its body with LWS_WRITE_HTTP_FINAL from
 *    the writeable.  It does not look at the method: for a HEAD, lws must
 *    drop the body it writes (RFC 9110 9.3.2), on h1 sending nothing of it,
 *    on h2 just the end of the stream.
 *
 *  - /redir answers a headers-only 302 text/html, Content-Length 0, as the
 *    lws-login and auth-server redirects do.  With
 *    LWS_WITH_HTTP_STREAM_COMPRESSION lws must not code it: a coded answer
 *    goes chunked on h1, and a headers-only one never sends the last-chunk.
 *
 *  - /nofinal answers like /body, but writes its body as LWS_WRITE_HTTP
 *    and then completes the transaction, relying on its Content-Length.
 *    When lws has chosen to code it, the chunked framing is lws' own, and
 *    lws must end it at the completion.
 *
 *  - /optout answers like /body after lws_http_compression_opt_out(): it
 *    must not be coded, and the opt-out must be for that answer only, the
 *    next /body on the connection is coded again.
 *
 * --role h1 (default): a raw client sends a sequence of requests on one
 * connection, each after the previous answer is whole, and parses the
 * answers byte-exactly: framing (Content-Length or chunked), status, and
 * nothing more than the answer before the next request goes.  Requests say
 * "accept-encoding: deflate", so a build with stream compression codes the
 * text/plain bodies.
 *
 * --role h2: an lws client (prior knowledge) sends HEAD /body and
 * HEAD /redir, which must complete with no body, then GET /body, which
 * must have one.
 *
 * lws is both ends here, in one process.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#define BL_DEADLINE_S		20

/* the most of a response head the raw client keeps */
#define BL_HEAD_MAX		1024
/* the most body it keeps of one answer, coded or not */
#define BL_BODY_MAX		4096

static const char body[] =
	"The quick brown fox jumps over the lazy dog, "
	"the quick brown fox jumps over the lazy dog again, "
	"and then the quick brown fox has a rest.\n";

#define BL_BODY_LEN		(sizeof(body) - 1)

enum bl_role {
	BL_H1,
	BL_H2,
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_watchdog;
static enum bl_role role;
static const char *server_addr = "127.0.0.1";
static int port = 7681, result = 1, finished;

static void
finish(int ok, const char *why)
{
	if (finished)
		return;

	finished = 1;
	result = !ok;
	if (ok)
		lwsl_user("%s: %s\n", __func__, why);
	else
		lwsl_err("%s: FAIL: %s\n", __func__, why);

	lws_cancel_service(context);
}

/*
 * The server
 */

enum bl_answer {
	BL_ANS_NONE,
	BL_ANS_FINAL,		/* /body: the body as LWS_WRITE_HTTP_FINAL */
	BL_ANS_NOFINAL,		/* /nofinal: as LWS_WRITE_HTTP, then complete */
};

struct pss_srv {
	enum bl_answer	ans;
};

static int
answer_redirect(struct lws *wsi)
{
	uint8_t hdr[LWS_PRE + 256], *start = &hdr[LWS_PRE], *p = start,
		*end = &hdr[sizeof(hdr) - 1];

	if (lws_add_http_common_headers(wsi, HTTP_STATUS_FOUND, "text/html",
					0, &p, end) ||
	    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION,
					 (unsigned char *)"/body", 5, &p, end) ||
	    lws_finalize_http_header(wsi, &p, end))
		return -1;

	if (lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
		      LWS_WRITE_HTTP_HEADERS | LWS_WRITE_H2_STREAM_END) !=
						lws_ptr_diff(p, start))
		return -1;

	return lws_http_transaction_completed(wsi) ? -1 : 0;
}

/* the headers now, the body from the writeable */
static int
answer_body(struct lws *wsi, struct pss_srv *pss, enum bl_answer ans)
{
	uint8_t hdr[LWS_PRE + 256], *start = &hdr[LWS_PRE], *p = start,
		*end = &hdr[sizeof(hdr) - 1];

	if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/plain",
					BL_BODY_LEN, &p, end) ||
	    lws_finalize_write_http_header(wsi, start, &p, end))
		return -1;

	pss->ans = ans;
	lws_callback_on_writable(wsi);

	return 0;
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	const char *path = (const char *)in;
	uint8_t buf[LWS_PRE + BL_BODY_LEN];
	enum bl_answer ans;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		pss->ans = BL_ANS_NONE;

		if (path && !strcmp(path, "/body"))
			return answer_body(wsi, pss, BL_ANS_FINAL);
		if (path && !strcmp(path, "/nofinal"))
			return answer_body(wsi, pss, BL_ANS_NOFINAL);
		if (path && !strcmp(path, "/redir"))
			return answer_redirect(wsi);
		if (path && !strcmp(path, "/optout")) {
			if (lws_http_compression_opt_out(wsi))
				return -1;
			return answer_body(wsi, pss, BL_ANS_FINAL);
		}

		if (lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL) ||
		    lws_http_transaction_completed(wsi))
			return -1;
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss || pss->ans == BL_ANS_NONE)
			break;
		ans = pss->ans;
		pss->ans = BL_ANS_NONE;

		memcpy(&buf[LWS_PRE], body, BL_BODY_LEN);
		if (lws_write(wsi, &buf[LWS_PRE], BL_BODY_LEN,
			      ans == BL_ANS_FINAL ? LWS_WRITE_HTTP_FINAL :
						    LWS_WRITE_HTTP) !=
							(int)BL_BODY_LEN)
			return -1;

		return lws_http_transaction_completed(wsi) ? -1 : 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * The raw h1 client: one request at a time on one connection, each answer
 * parsed exactly before the next request goes
 */

enum bl_coding {
	BL_COD_ANY,
	BL_COD_IDENTITY,	/* must not be coded */
	BL_COD_CODED,		/* must be coded, when lws can code */
};

struct step {
	const char	*method;
	const char	*path;
	int		status;
	char		head;		/* a HEAD: the answer has no body */
	char		has_body;	/* a body is expected */
	enum bl_coding	coding;
};

static const struct step steps[] = {
	{ "HEAD",	"/body",	200, 1, 0, BL_COD_ANY },
	{ "GET",	"/redir",	302, 0, 0, BL_COD_ANY },
	{ "GET",	"/body",	200, 0, 1, BL_COD_ANY },
	{ "HEAD",	"/redir",	302, 1, 0, BL_COD_ANY },
	{ "HEAD",	"/nofinal",	200, 1, 0, BL_COD_ANY },
	{ "GET",	"/nofinal",	200, 0, 1, BL_COD_ANY },
	{ "GET",	"/optout",	200, 0, 1, BL_COD_IDENTITY },
	{ "GET",	"/body",	200, 0, 1, BL_COD_CODED },
};

enum rx_state {
	RXS_HEAD,
	RXS_CL,			/* a Content-Length body */
	RXS_CHUNK_SIZE,		/* a chunk-size line */
	RXS_CHUNK_DATA,
	RXS_CHUNK_CRLF,		/* the CRLF after a chunk's data */
	RXS_TRAILER,		/* after the last-chunk: the empty line */
	RXS_DONE,		/* the answer is whole */
};

static struct {
	uint8_t		head[BL_HEAD_MAX];
	uint8_t		body[BL_BODY_MAX];
	char		line[24];
	size_t		head_len;
	size_t		body_len;
	size_t		line_len;
	size_t		remain;
	enum rx_state	state;
	long		cl;		/* the Content-Length, or -1 */
	int		status;
	int		step;		/* the step being answered */
	char		chunked;
	char		coded;		/* a content-encoding */
} raw;

/* case-insensitive match of a header name at p */
static int
raw_hdr_is(const uint8_t *p, const uint8_t *end, const char *name)
{
	size_t n = strlen(name), i;

	if ((size_t)(end - p) < n)
		return 0;

	for (i = 0; i < n; i++) {
		uint8_t c = p[i];

		if (c >= 'A' && c <= 'Z')
			c = (uint8_t)(c + ('a' - 'A'));
		if (c != (uint8_t)name[i])
			return 0;
	}

	return 1;
}

/* the value of a header line starting at p, after its name */
static const uint8_t *
raw_hdr_val(const uint8_t *p, const uint8_t *end)
{
	while (p < end && *p == ' ')
		p++;

	return p;
}

/* raw.head holds a whole head: take its status and framing */
static int
raw_parse_head(void)
{
	const uint8_t *h, *e = raw.head + raw.head_len;
	int n;

	if (raw.head_len < 12 || memcmp(raw.head, "HTTP/1.1 ", 9)) {
		lwsl_err("%s: not a status line: '%.*s'\n", __func__,
			 (int)(raw.head_len < 40 ? raw.head_len : 40),
			 (const char *)raw.head);
		return -1;
	}

	raw.status = 0;
	for (n = 9; n < 12; n++) {
		if (raw.head[n] < '0' || raw.head[n] > '9')
			return -1;
		raw.status = (raw.status * 10) + (raw.head[n] - '0');
	}

	raw.cl = -1;
	raw.chunked = 0;
	raw.coded = 0;

	for (h = raw.head; h < e; h++) {
		if (h[0] != '\n')
			continue;

		if (raw_hdr_is(h + 1, e, "content-length:")) {
			const uint8_t *v = raw_hdr_val(h + 16, e);

			raw.cl = 0;
			while (v < e && *v >= '0' && *v <= '9') {
				raw.cl = (raw.cl * 10) + (*v++ - '0');
				if (raw.cl > BL_BODY_MAX)
					return -1;
			}
		}
		if (raw_hdr_is(h + 1, e, "transfer-encoding:")) {
			const uint8_t *v = raw_hdr_val(h + 19, e);

			if (!raw_hdr_is(v, e, "chunked\r\n"))
				return -1;
			raw.chunked = 1;
		}
		if (raw_hdr_is(h + 1, e, "content-encoding:"))
			raw.coded = 1;
	}

	if (raw.chunked && raw.cl >= 0) {
		lwsl_err("%s: both chunked and a content-length\n", __func__);
		return -1;
	}

	return 0;
}

/* the answer to the current step is whole: is it what was expected? */
static int
raw_answer_ok(void)
{
	const struct step *s = &steps[raw.step];

	lwsl_user("%s: %s %s: %d, %s, %s, %u body bytes\n", __func__,
		  s->method, s->path, raw.status,
		  raw.chunked ? "chunked" : "content-length",
		  raw.coded ? "coded" : "identity",
		  (unsigned int)raw.body_len);

	if (raw.status != s->status) {
		lwsl_err("%s: status %d, expected %d\n", __func__, raw.status,
			 s->status);
		return 0;
	}

	if (!s->has_body) {
		/*
		 * Nothing is coded that has no body: a coded answer would be
		 * chunked on h1, and need an end nothing would send.  A HEAD
		 * may say what the GET would have, framing and coding and all
		 */
		if (!s->head && (raw.coded || raw.chunked || raw.cl != 0)) {
			lwsl_err("%s: a headers-only answer with a coding, "
				 "chunked, or no content-length: 0\n", __func__);
			return 0;
		}

		return 1;
	}

	if ((s->coding == BL_COD_IDENTITY && raw.coded)
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	    || (s->coding == BL_COD_CODED && !raw.coded)
#endif
	   ) {
		lwsl_err("%s: %s, expected %s\n", __func__,
			 raw.coded ? "coded" : "identity",
			 raw.coded ? "identity" : "coded");
		return 0;
	}

	if (raw.coded)
		/* coded: on h1 it can only go chunked */
		return raw.chunked && raw.body_len;

	return raw.body_len == BL_BODY_LEN &&
	       !memcmp(raw.body, body, BL_BODY_LEN);
}

static int
raw_body(const uint8_t *p, size_t n)
{
	if (raw.body_len + n > sizeof(raw.body))
		return -1;

	memcpy(raw.body + raw.body_len, p, n);
	raw.body_len += n;

	return 0;
}

/* a line of the chunked framing, CRLF-ended: 1 when it is whole */
static int
raw_line(uint8_t c)
{
	if (raw.line_len == sizeof(raw.line) - 1)
		return -1;

	raw.line[raw.line_len++] = (char)c;
	raw.line[raw.line_len] = '\0';

	return raw.line_len >= 2 && raw.line[raw.line_len - 2] == '\r' &&
	       raw.line[raw.line_len - 1] == '\n';
}

/* the size of the chunk on the line, or -1 */
static long
raw_chunk_size(void)
{
	long sz = 0;
	size_t n;

	if (raw.line_len < 3)
		return -1;

	for (n = 0; n < raw.line_len - 2; n++) {
		char c = raw.line[n];
		int v;

		if (c >= '0' && c <= '9')
			v = c - '0';
		else if (c >= 'a' && c <= 'f')
			v = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			v = c - 'A' + 10;
		else
			return -1;

		sz = (sz * 16) + v;
		if (sz > BL_BODY_MAX)
			return -1;
	}

	return sz;
}

/*
 * Takes received bytes.  Returns 1 when the current step's answer is whole,
 * 0 when more is needed, -1 if the bytes are wrong
 */
static int
raw_rx(const uint8_t *p, size_t len)
{
	long sz;
	size_t n;
	int r;

	while (len) {
		switch (raw.state) {
		case RXS_HEAD:
			if (raw.head_len == sizeof(raw.head))
				return -1;
			raw.head[raw.head_len++] = *p++;
			len--;
			if (raw.head_len < 4 ||
			    memcmp(raw.head + raw.head_len - 4, "\r\n\r\n", 4))
				break;

			if (raw_parse_head())
				return -1;

			if (steps[raw.step].head) {
				/* whatever the head says, a HEAD's ends here */
				raw.state = RXS_DONE;
				break;
			}
			if (raw.chunked) {
				raw.state = RXS_CHUNK_SIZE;
				break;
			}
			if (raw.cl < 0) {
				lwsl_err("%s: no framing\n", __func__);
				return -1;
			}
			raw.remain = (size_t)raw.cl;
			raw.state = raw.cl ? RXS_CL : RXS_DONE;
			break;

		case RXS_CL:
		case RXS_CHUNK_DATA:
			n = len < raw.remain ? len : raw.remain;
			if (raw_body(p, n))
				return -1;
			raw.remain -= n;
			p += n;
			len -= n;
			if (!raw.remain)
				raw.state = raw.state == RXS_CL ? RXS_DONE :
								  RXS_CHUNK_CRLF;
			break;

		case RXS_CHUNK_SIZE:
			r = raw_line(*p++);
			len--;
			if (r < 0)
				return -1;
			if (!r)
				break;
			sz = raw_chunk_size();
			raw.line_len = 0;
			if (sz < 0) {
				lwsl_err("%s: bad chunk size line\n", __func__);
				return -1;
			}
			raw.remain = (size_t)sz;
			raw.state = sz ? RXS_CHUNK_DATA : RXS_TRAILER;
			break;

		case RXS_CHUNK_CRLF:
		case RXS_TRAILER:
			r = raw_line(*p++);
			len--;
			if (r < 0)
				return -1;
			if (!r)
				break;
			if (raw.line_len != 2) {
				/* lws sends no trailers */
				lwsl_err("%s: junk after chunk data\n", __func__);
				return -1;
			}
			raw.line_len = 0;
			raw.state = raw.state == RXS_TRAILER ? RXS_DONE :
							       RXS_CHUNK_SIZE;
			break;

		case RXS_DONE:
			/*
			 * More than the answer arrived before the next request
			 * went: what a kept-alive peer would read as the start
			 * of the next answer
			 */
			lwsl_err("%s: %u bytes after the answer to %s %s\n",
				 __func__, (unsigned int)len,
				 steps[raw.step].method, steps[raw.step].path);
			lwsl_hexdump_err(p, len < 64 ? len : 64);
			return -1;
		}
	}

	return raw.state == RXS_DONE;
}

static int
raw_send_step(struct lws *wsi)
{
	const struct step *s = &steps[raw.step];
	uint8_t buf[LWS_PRE + 256];
	int n;

	memset(&raw.head, 0, sizeof(raw.head));
	raw.head_len = raw.body_len = raw.line_len = raw.remain = 0;
	raw.state = RXS_HEAD;

	n = lws_snprintf((char *)&buf[LWS_PRE], sizeof(buf) - LWS_PRE,
			 "%s %s HTTP/1.1\r\nHost: bodyless\r\n"
			 "Accept-Encoding: deflate\r\n\r\n",
			 s->method, s->path);

	lwsl_user("%s: %s %s\n", __func__, s->method, s->path);

	return lws_write(wsi, &buf[LWS_PRE], (size_t)n, LWS_WRITE_RAW) != n;
}

static int
callback_raw(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		finish(0, in ? (const char *)in : "raw connection error");
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		raw.step = 0;
		return raw_send_step(wsi) ? -1 : 0;

	case LWS_CALLBACK_RAW_RX:
		switch (raw_rx((const uint8_t *)in, len)) {
		case 0:
			return 0;
		case 1:
			if (!raw_answer_ok()) {
				finish(0, "unexpected answer");
				return -1;
			}
			if (raw.step + 1 == (int)LWS_ARRAY_SIZE(steps)) {
				finish(1, "every answer was framed exactly");
				return -1;
			}
			/* the next request goes once this rx is done with */
			lws_callback_on_writable(wsi);
			return 0;
		default:
			finish(0, "the answers are out of step");
			return -1;
		}

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (finished || raw.state != RXS_DONE)
			break;
		raw.step++;
		return raw_send_step(wsi) ? -1 : 0;

	case LWS_CALLBACK_RAW_CLOSE:
		finish(0, "the connection closed before every answer");
		break;

	default:
		break;
	}

	return 0;
}

/*
 * The h2 client: one stream at a time, each counting its body
 */

static const struct step h2_steps[] = {
	{ "HEAD",	"/body",	200, 1, 0, BL_COD_ANY },
	{ "HEAD",	"/redir",	302, 1, 0, BL_COD_ANY },
	{ "GET",	"/body",	200, 0, 1, BL_COD_ANY },
};

static struct {
	size_t		body_len;
	int		step;
	int		status;
	char		completed;
} h2c;

static int h2_connect(void);

static int
callback_h2c(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	const struct step *s = &h2_steps[h2c.step];
	char buf[LWS_PRE + 1024], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	if (!wsi)
		return 0;

	/*
	 * Only the current step's stream counts: the last one's close may
	 * come after the next one started
	 */
	if (reason != LWS_CALLBACK_CLIENT_CONNECTION_ERROR &&
	    (intptr_t)lws_get_opaque_user_data(wsi) != h2c.step + 1)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in, *end = (*p) + len;

		if (lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_ACCEPT_ENCODING,
				(unsigned char *)"deflate", 7, p, end))
			return -1;
		break;
	}

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		finish(0, in ? (const char *)in : "h2 connection error");
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		h2c.status = (int)lws_http_client_http_response(wsi);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		h2c.body_len += len;
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (h2c.completed)
			break;
		h2c.completed = 1;
		lwsl_user("%s: %s %s: %d, %u body bytes\n", __func__,
			  s->method, s->path, h2c.status,
			  (unsigned int)h2c.body_len);
		if (h2c.status != s->status ||
		    !!h2c.body_len != !!s->has_body) {
			finish(0, "unexpected h2 answer");
			break;
		}
		if (++h2c.step == (int)LWS_ARRAY_SIZE(h2_steps)) {
			finish(1, "every h2 answer was as expected");
			break;
		}
		if (h2_connect())
			finish(0, "the next h2 stream could not be started");
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!h2c.completed)
			finish(0, "the h2 stream closed before completing");
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
h2_connect(void)
{
	struct lws_client_connect_info i;

	h2c.body_len = 0;
	h2c.status = 0;
	h2c.completed = 0;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.port			= port;
	i.path			= h2_steps[h2c.step].path;
	i.method		= h2_steps[h2c.step].method;
	/* the 302 is the answer being checked, not where it leads */
	i.ssl_connection	= LCCSCF_H2_PRIOR_KNOWLEDGE |
				  LCCSCF_HTTP_NO_FOLLOW_REDIRECT;
	i.protocol		= "bl-h2c";
	i.opaque_user_data	= (void *)(intptr_t)(h2c.step + 1);

	lwsl_user("%s: %s %s\n", __func__, i.method, i.path);

	return !lws_client_connect_via_info(&i);
}

static int
raw_connect(void)
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
	i.protocol		= "bl-raw";
	i.local_protocol_name	= "bl-raw";

	return !lws_client_connect_via_info(&i);
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "bl-raw", callback_raw, 0, 0, 0, NULL, 0 },
	{ "bl-h2c", callback_h2c, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	finish(0, "timed out");
}

static void
sigint_handler(int sig)
{
	finished = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* a server and its client */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;
	if ((p = lws_cmdline_option(argc, argv, "--role"))) {
		if (!strcmp(p, "h2"))
			role = BL_H2;
		else if (strcmp(p, "h1")) {
			lwsl_err("--role h1 | h2\n");
			return 1;
		}
	}

#if !defined(LWS_ROLE_H2)
	if (role == BL_H2) {
		lwsl_err("this build has no h2\n");
		return 1;
	}
#endif

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: http answers without a body, %s\n",
		  role == BL_H2 ? "h2" : "h1");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.port = port;
	info.vhost_name = "srv";
	info.protocols = protocols_srv;
	if (role == BL_H2)
		info.options |= LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create the server vhost\n");
		goto bail;
	}

	info.options &= ~(uint64_t)LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create the client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 BL_DEADLINE_S * LWS_US_PER_SEC);

	if (role == BL_H2 ? h2_connect() : raw_connect()) {
		lwsl_err("The connection could not be started\n");
		goto bail;
	}

	while (!finished && lws_service(context, 0) >= 0)
		;

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
