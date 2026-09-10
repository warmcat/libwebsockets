/*
 * lws-api-test-http-transfer
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Exercises the http body transfer framings lws is expected to handle, in
 * both directions, with an lws server and an lws client in one context.
 *
 * Request bodies (client -> server) on h1:
 *
 *  - Content-Length, in one write and in many
 *  - Transfer-Encoding: chunked, chunks of assorted sizes, in one write, in
 *    many, and with the framing itself split across writes
 *  - chunked with chunk extensions and trailer fields
 *  - chunked on a GET, where the server answers before the body has been
 *    read, followed by a pipelined request on the same connection
 *  - refusals: an unsupported Transfer-Encoding (501), Transfer-Encoding
 *    together with Content-Length (400), a chunked body over the mount's
 *    body limit (connection dropped), a Content-Length over it (413)
 *
 * Request bodies on h2 (cleartext, prior knowledge): Content-Length, no
 * Content-Length (END_STREAM delimited), and no body at all.
 *
 * Response bodies (server -> client): Content-Length; hand-framed chunked
 * with extensions and trailers; unknown length (h1: delimited by the
 * close, h2: by END_STREAM)... each also split across many writes.
 *
 * Mount interceptors (LWS_WITH_JOSE): a mount with an interceptor_path hands
 * every request to the interceptor protocol first, which either lets it
 * through to the mount or takes it over.  That decision must be identical
 * for every method and every role -- a POST that the interceptor blocks must
 * not reach the app on h2 any more than it does on h1, and a blocked
 * body-bearing request must leave the h1 connection resynchronized (the body
 * is discarded) rather than desynced.  The gated legs check both outcomes,
 * for GET and for POST, over h1 and h2.
 *
 * The server echoes what it decoded: a summary line "len=<n> sum=<x>\n"
 * followed by n bytes of the same deterministic pattern the client sent,
 * so the client can confirm the server saw exactly the payload it sent, and
 * that it received exactly what the server sent.
 *
 * The test fails if any case does not complete as expected inside the
 * watchdog period.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#define CASE_TIMEOUT_S	30

/* how the client frames the request body */

enum xf_req {
	XR_NONE,	/* no body, no framing headers */
	XR_NOLEN,	/* POST with neither Content-Length nor Transfer-Encoding */
	XR_CL,		/* Content-Length */
	XR_BODY_NOHDR,	/* body but no framing header (h2: END_STREAM delimits) */
	XR_CHUNKED,	/* Transfer-Encoding: chunked */
	XR_CHUNKED_EXT,	/* chunked with chunk extensions and trailer fields */
	XR_TE_BAD,	/* Transfer-Encoding: gzip, no body */
	XR_TE_AND_CL,	/* Transfer-Encoding: chunked with a Content-Length */
};

/* what the mount interceptor is expected to do with the request */

enum xf_gate {
	XG_NONE,	/* the case does not involve an interceptor */
	XG_BLOCK,	/* the interceptor must take the request: the app
			 * protocol must see no request and no body at all */
	XG_PASS,	/* the interceptor must let it through to the app */
};

struct xcase {
	const char	*name;
	const char	*method;
	const char	*path;
	enum xf_req	req;
	size_t		body_len;	/* payload bytes actually sent */
	size_t		claim_len;	/* Content-Length header value if != body_len */
	size_t		write_sz;	/* bytes per client write, framing included */
	int		h2;
	int		pipeline;	/* issue two pipelined requests */
	int		expect_status;	/* 0: expect no completed 200 response */
	long		expect_server_rx; /* -1: don't check; else payload bytes the server saw */
	enum xf_gate	gate;
};

static const struct xcase cases[] = {
	{ "h1 POST Content-Length 100KB, 8KB writes, CL response",
	  "POST", "/echo-cl", XR_CL, 100000, 0, 8192, 0, 0, 200, 100000, XG_NONE },
	{ "h1 POST Content-Length 5KB, one write, chunked response",
	  "POST", "/echo-chunked", XR_CL, 5000, 0, 8192, 0, 0, 200, 5000, XG_NONE },
	{ "h1 POST Content-Length 30KB, 4KB writes, close-delimited response",
	  "POST", "/echo-nolen", XR_CL, 30000, 0, 4096, 0, 0, 200, 30000, XG_NONE },
	{ "h1 POST Content-Length 60KB, chunked response in many chunks",
	  "POST", "/echo-chunked", XR_CL, 60000, 0, 8192, 0, 0, 200, 60000, XG_NONE },
	{ "h1 POST chunked 100KB, 8KB writes, CL response",
	  "POST", "/echo-cl", XR_CHUNKED, 100000, 0, 8192, 0, 0, 200, 100000, XG_NONE },
	{ "h1 POST chunked 5KB, one write, chunked response",
	  "POST", "/echo-chunked", XR_CHUNKED, 5000, 0, 8192, 0, 0, 200, 5000, XG_NONE },
	{ "h1 POST chunked 300B, framing split into 3-byte writes",
	  "POST", "/echo-cl", XR_CHUNKED, 300, 0, 3, 0, 0, 200, 300, XG_NONE },
	{ "h1 POST chunked 2KB with extensions and trailers, 7-byte writes",
	  "POST", "/echo-cl", XR_CHUNKED_EXT, 2000, 0, 7, 0, 0, 200, 2000, XG_NONE },
	{ "h1 POST chunked 5KB, 1KB writes, close-delimited response",
	  "POST", "/echo-nolen", XR_CHUNKED, 5000, 0, 1000, 0, 0, 200, 5000, XG_NONE },
	{ "h1 POST chunked 3KB, two requests pipelined on one connection",
	  "POST", "/echo-cl", XR_CHUNKED, 3000, 0, 8192, 0, 1, 200, -1, XG_NONE },
	{ "h1 GET with a chunked body, two requests pipelined on one connection",
	  "GET", "/echo-cl", XR_CHUNKED, 1000, 0, 8192, 0, 1, 200, -1, XG_NONE },
	{ "h1 GET with a Content-Length body, two requests pipelined",
	  "GET", "/echo-cl", XR_CL, 1000, 0, 8192, 0, 1, 200, -1, XG_NONE },
	/*
	 * No h1 "POST with neither header" case: by lws convention such a body
	 * is delimited by the multipart closing boundary (lws_spa) or the
	 * close, not treated as empty, so it would only wait here.  The h2
	 * variant below is END_STREAM delimited and does complete.
	 */
	{ "h1 GET, no body",
	  "GET", "/echo-cl", XR_NONE, 0, 0, 8192, 0, 0, 200, 0, XG_NONE },
	{ "h1 POST Transfer-Encoding: gzip is refused with 501",
	  "POST", "/echo-cl", XR_TE_BAD, 0, 0, 8192, 0, 0, 501, -1, XG_NONE },
	{ "h1 POST Transfer-Encoding with Content-Length is refused with 400",
	  "POST", "/echo-cl", XR_TE_AND_CL, 0, 5, 8192, 0, 0, 400, -1, XG_NONE },
	{ "h1 POST chunked body over the mount limit is dropped",
	  "POST", "/small/echo-cl", XR_CHUNKED, 200, 0, 8192, 0, 0, 0, -1, XG_NONE },
	{ "h1 POST Content-Length over the mount limit gets 413",
	  "POST", "/small/echo-cl", XR_CL, 0, 200, 8192, 0, 0, 413, -1, XG_NONE },
#if defined(LWS_WITH_JOSE)
	/*
	 * Mount interceptor gating.  "/gated" is guarded by the "/bouncer"
	 * mount's protocol, which lets a request through only if it carries
	 * ?auth=1 and otherwise answers it itself with 403.
	 */
	{ "h1 GET to an interceptor-gated mount is blocked",
	  "GET", "/gated/echo-cl", XR_NONE, 0, 0, 8192, 0, 0, 403, 0, XG_BLOCK },
	{ "h1 GET the interceptor passes reaches the app",
	  "GET", "/gated/echo-cl?auth=1", XR_NONE, 0, 0, 8192, 0, 0, 200, 0,
	  XG_PASS },
	{ "h1 POST to an interceptor-gated mount is blocked",
	  "POST", "/gated/echo-cl", XR_CL, 4000, 0, 8192, 0, 0, 403, 0,
	  XG_BLOCK },
	{ "h1 POST the interceptor passes reaches the app with its body",
	  "POST", "/gated/echo-cl?auth=1", XR_CL, 4000, 0, 8192, 0, 0, 200,
	  4000, XG_PASS },
	{ "h1 POST chunked to an interceptor-gated mount is blocked",
	  "POST", "/gated/echo-cl", XR_CHUNKED, 2000, 0, 512, 0, 0, 403, 0,
	  XG_BLOCK },
	/*
	 * Blocking a request whose body is still arriving must leave the h1
	 * connection resynchronized: the body of the refused request is
	 * discarded, so the second, pipelined request on the same connection
	 * is parsed as a request and not as the tail of the first one's body
	 */
	{ "h1 POST blocked by the interceptor, second request pipelined on the "
	  "same connection",
	  "POST", "/gated/echo-cl", XR_CL, 4000, 0, 8192, 0, 1, 403, 0,
	  XG_BLOCK },
#endif
#if defined(LWS_WITH_HTTP2)
	{ "h2 POST Content-Length 50KB, 8KB writes, CL response",
	  "POST", "/echo-cl", XR_CL, 50000, 0, 8192, 1, 0, 200, 50000, XG_NONE },
	{ "h2 POST no Content-Length 20KB (END_STREAM delimited)",
	  "POST", "/echo-cl", XR_BODY_NOHDR, 20000, 0, 4096, 1, 0, 200, 20000, XG_NONE },
	{ "h2 POST Content-Length 20KB, no-length response (END_STREAM)",
	  "POST", "/echo-nolen", XR_CL, 20000, 0, 8192, 1, 0, 200, 20000, XG_NONE },
	{ "h2 GET, no body",
	  "GET", "/echo-cl", XR_NONE, 0, 0, 8192, 1, 0, 200, 0, XG_NONE },
	{ "h2 POST with neither header: zero-length body",
	  "POST", "/echo-cl", XR_NOLEN, 0, 0, 8192, 1, 0, 200, 0, XG_NONE },
	/*
	 * No h2 Transfer-Encoding refusal case: the lws h2 client does not
	 * forward a Transfer-Encoding header, so it cannot provoke one
	 */
#if defined(LWS_WITH_JOSE)
	/*
	 * The same gating on h2.  h2 dispatches a POST to a callback mount
	 * from its own path (it must bind the protocol before the body can
	 * arrive), which used to be a way past the mount's interceptor that
	 * did not exist on h1.  Both the bodyless and the body-bearing shapes
	 * of that path are covered.
	 */
	{ "h2 GET to an interceptor-gated mount is blocked",
	  "GET", "/gated/echo-cl", XR_NONE, 0, 0, 8192, 1, 0, 403, 0,
	  XG_BLOCK },
	{ "h2 POST to an interceptor-gated mount is blocked",
	  "POST", "/gated/echo-cl", XR_CL, 4000, 0, 8192, 1, 0, 403, 0,
	  XG_BLOCK },
	{ "h2 POST with no body to an interceptor-gated mount is blocked",
	  "POST", "/gated/echo-cl", XR_NOLEN, 0, 0, 8192, 1, 0, 403, 0,
	  XG_BLOCK },
	{ "h2 POST with no Content-Length to a gated mount is blocked",
	  "POST", "/gated/echo-cl", XR_BODY_NOHDR, 2000, 0, 512, 1, 0, 403, 0,
	  XG_BLOCK },
	{ "h2 POST the interceptor passes reaches the app with its body",
	  "POST", "/gated/echo-cl?auth=1", XR_CL, 4000, 0, 8192, 1, 0, 200,
	  4000, XG_PASS },
#endif
#endif
};

/* per client connection */

struct conn {
	struct conn		*next;
	const struct xcase	*c;
	int			case_idx;
	uint8_t			*framed;	/* framed request body */
	size_t			framed_len;
	size_t			sent;
	size_t			rx_len;		/* response payload bytes */
	uint32_t		rx_sum;
	char			line[64];	/* response summary line */
	size_t			line_len;
	int			line_done;
	int			status;
	int			completed;
	int			closed;
	int			error;
};

/* server side, per connection */

enum resp_mode {
	RM_CL,
	RM_CHUNKED,	/* hand-framed, h1 only */
	RM_NOLEN,	/* h1: close-delimited; h2: END_STREAM */
};

struct pss_srv {
	enum resp_mode		mode;
	size_t			rx_len;
	uint32_t		rx_sum;
	char			line[64];
	size_t			line_len;
	size_t			tx_total;
	size_t			tx_pos;
	int			chunk_idx;
	int			responding;
};

/* server-side view of the current case */

static struct {
	long		body_len;	/* decoded payload bytes, all requests */
	int		http_cbs;	/* LWS_CALLBACK_HTTP count */
	int		conns;		/* accepted connections */
	int		gate_blocks;	/* requests the mount interceptor took */
} srv;

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static struct conn *conn_list, *conns[2];
static int interrupted, result, cur = -1, failures, port_h1 = 7681,
	   port_h2 = 7682, only_case = -1, case_done;

static const char *server_addr = "127.0.0.1";

/* deterministic payload and checksum, shared by both sides */

static uint8_t
pat(size_t i)
{
	return (uint8_t)(0x30 + ((i * 7) % 61));
}

static uint32_t
sum_add(uint32_t s, const uint8_t *b, size_t len)
{
	while (len--)
		s = (s * 31u) + *b++;

	return s;
}

static uint32_t
sum_pat(size_t len)
{
	uint32_t s = 0;
	size_t i;

	for (i = 0; i < len; i++)
		s = (s * 31u) + pat(i);

	return s;
}

/* chunk sizes cycle through these, so the framing lands everywhere */

static const size_t chunk_sizes[] = { 1, 7, 100, 1000, 4095, 17, 300, 2 };

/*
 * Frame len bytes of pattern as a chunked body into out.  With ext, every
 * other chunk carries a chunk extension and the last-chunk is followed by
 * trailer fields.
 */

static size_t
frame_chunked(uint8_t *out, size_t out_max, size_t len, int ext)
{
	size_t o = 0, done = 0, i, n = 0;

	while (done < len) {
		size_t cl = chunk_sizes[n++ % LWS_ARRAY_SIZE(chunk_sizes)];

		if (cl > len - done)
			cl = len - done;

		o += (size_t)lws_snprintf((char *)out + o, out_max - o,
				  ext && (n & 1) ? "%x;lws=test\x0d\x0a" :
						   "%x\x0d\x0a", (unsigned int)cl);
		for (i = 0; i < cl; i++)
			out[o++] = pat(done + i);
		done += cl;
		out[o++] = '\x0d';
		out[o++] = '\x0a';
	}

	o += (size_t)lws_snprintf((char *)out + o, out_max - o, ext ?
			"0\x0d\x0ax-trailer: yes\x0d\x0aanother: one\x0d\x0a\x0d\x0a" :
			"0\x0d\x0a\x0d\x0a");

	return o;
}

/* ---- server side ---- */

static int
srv_start_response(struct lws *wsi, struct pss_srv *pss)
{
	uint8_t hbuf[LWS_PRE + 512], *start = &hbuf[LWS_PRE], *p = start,
		*end = &hbuf[sizeof(hbuf) - 1];

	pss->line_len = (size_t)lws_snprintf(pss->line, sizeof(pss->line),
					     "len=%u sum=%08x\n",
					     (unsigned int)pss->rx_len,
					     (unsigned int)pss->rx_sum);
	pss->tx_total = pss->line_len + pss->rx_len;
	pss->tx_pos = 0;
	pss->chunk_idx = 0;
	pss->responding = 1;

	switch (pss->mode) {
	case RM_CL:
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain",
						(lws_filepos_t)pss->tx_total,
						&p, end))
			return 1;
		break;
	case RM_NOLEN:
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain",
						LWS_ILLEGAL_HTTP_CONTENT_LEN,
						&p, end))
			return 1;
		break;
	case RM_CHUNKED:
		/* h1 only: we frame the chunks ourselves */
		if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end) ||
		    lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_TYPE,
					(const uint8_t *)"text/plain", 10,
					&p, end) ||
		    lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_TRANSFER_ENCODING,
					(const uint8_t *)"chunked", 7,
					&p, end))
			return 1;
		break;
	}

	if (lws_finalize_write_http_header(wsi, start, &p, end))
		return 1;

	lws_callback_on_writable(wsi);

	return 0;
}

/* the response body byte at position pos */

static uint8_t
srv_tx_byte(struct pss_srv *pss, size_t pos)
{
	if (pos < pss->line_len)
		return (uint8_t)pss->line[pos];

	return pat(pos - pss->line_len);
}

static int
srv_writeable(struct lws *wsi, struct pss_srv *pss)
{
	static uint8_t wbuf[LWS_PRE + 8192];
	uint8_t *p = &wbuf[LWS_PRE];
	size_t rem = pss->tx_total - pss->tx_pos, n, i, o = 0;
	int final;

	if (!pss->responding)
		return 0;

	if (pss->mode == RM_CHUNKED) {
		n = chunk_sizes[(size_t)pss->chunk_idx++ %
					LWS_ARRAY_SIZE(chunk_sizes)];
		if (n > rem)
			n = rem;
		final = n == rem;

		/*
		 * A chunk extension on the odd chunks, trailer fields after
		 * the last-chunk: the client must skip both
		 */
		o = (size_t)lws_snprintf((char *)p, 64, (pss->chunk_idx & 1) ?
					 "%x;srv=ext\x0d\x0a" : "%x\x0d\x0a",
					 (unsigned int)n);
		for (i = 0; i < n; i++)
			p[o++] = srv_tx_byte(pss, pss->tx_pos + i);
		p[o++] = '\x0d';
		p[o++] = '\x0a';
		if (final)
			o += (size_t)lws_snprintf((char *)p + o, 64,
				"0\x0d\x0ax-srv-trailer: yes\x0d\x0a\x0d\x0a");
	} else {
		n = rem > 1400 ? 1400 : rem;
		final = n == rem;
		for (i = 0; i < n; i++)
			p[o++] = srv_tx_byte(pss, pss->tx_pos + i);
	}

	if (lws_write(wsi, p, o, final ? LWS_WRITE_HTTP_FINAL :
				 LWS_WRITE_HTTP) != (int)o)
		return -1;

	pss->tx_pos += n;

	if (!final) {
		lws_callback_on_writable(wsi);

		return 0;
	}

	pss->responding = 0;

	if (lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	const char *path = (const char *)in;
	char *uri;
	int n;

	switch (reason) {

	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
		srv.conns++;
		break;

	case LWS_CALLBACK_HTTP:
		srv.http_cbs++;
		memset(pss, 0, sizeof(*pss));

		pss->mode = RM_CL;
		if (path && strstr(path, "echo-chunked"))
			pss->mode = RM_CHUNKED;
		if (path && strstr(path, "echo-nolen"))
			pss->mode = RM_NOLEN;

		lwsl_user("%s: server: HTTP %s\n", __func__, path ? path : "");

		if (lws_http_get_uri_and_method(wsi, &uri, &n) == LWSHUMETH_POST)
			/* the body decides the response, wait for it */
			return 0;

		/* answer now, whether or not a body is on its way */
		return srv_start_response(wsi, pss);

	case LWS_CALLBACK_HTTP_BODY:
		/* in only ever holds decoded payload */
		pss->rx_sum = sum_add(pss->rx_sum, (const uint8_t *)in, len);
		pss->rx_len += len;
		srv.body_len += (long)len;
		return 0;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		lwsl_user("%s: server: body complete, %u bytes\n", __func__,
			  (unsigned int)pss->rx_len);
		if (pss->responding)
			/*
			 * A GET with a body: we already answered from
			 * LWS_CALLBACK_HTTP.  Do not fall through to the dummy
			 * handler, which would answer a second time.
			 */
			return 0;
		return srv_start_response(wsi, pss);

	case LWS_CALLBACK_HTTP_WRITEABLE:
		return srv_writeable(wsi, pss);

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

#if defined(LWS_WITH_JOSE)

/*
 * The interceptor protocol, mounted at /bouncer, which guards /gated.
 *
 * This is the contract the real interceptor plugins (lws-login, the captcha
 * rate limiter) implement: LWS_CALLBACK_HTTP_INTERCEPTOR_CHECK returns 0 to
 * let the request continue to the mount it asked for, or nonzero to take it
 * over, in which case lws diverts the request to this mount and delivers
 * LWS_CALLBACK_HTTP here -- before the guarded mount's protocol is bound, so
 * the app sees nothing of the request at all.
 *
 * "Authorized" is just ?auth=1 on the request: what a real interceptor checks
 * is not what is under test here, only that every method and every role goes
 * through this decision and honours it.
 */

static int
callback_gate(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	uint8_t hbuf[LWS_PRE + 256], *start = &hbuf[LWS_PRE], *p = start,
		*end = &hbuf[sizeof(hbuf) - 1];
	const char *blocked = "blocked\n";
	char arg[16];

	switch (reason) {

	case LWS_CALLBACK_HTTP_INTERCEPTOR_CHECK:
		/*
		 * user_space belongs to whichever protocol the wsi is bound to
		 * at this point, which is not us: only the wsi is ours to look
		 * at
		 */
		if (lws_get_urlarg_by_name_safe(wsi, "auth=", arg,
						sizeof(arg)) >= 0 &&
		    !strcmp(arg, "1"))
			return 0;	/* let it through to the mount */

		return 1;		/* we take the request */

	case LWS_CALLBACK_HTTP:
		/*
		 * We only ever see this for a request we took.  Answer it
		 * ourselves: any request body still on its way is discarded
		 * (h1, leaving the connection in sync for the next request on
		 * it) or the stream reset (h2) by the transaction completion.
		 */
		srv.gate_blocks++;

		lwsl_user("%s: interceptor blocking %s\n", __func__,
			  in ? (const char *)in : "");

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_FORBIDDEN,
						"text/plain",
						(lws_filepos_t)strlen(blocked),
						&p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		memcpy(start, blocked, strlen(blocked));
		if (lws_write(wsi, start, strlen(blocked),
			      LWS_WRITE_HTTP_FINAL) < 0)
			return 1;

		if (lws_http_transaction_completed(wsi))
			return -1;

		return 0;

	case LWS_CALLBACK_HTTP_BODY:
	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		/*
		 * A blocked request that had already been answered can still
		 * see the tail of its body: it is not ours to act on
		 */
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

#endif

/* ---- client side ---- */

static void
case_finish(int ok, const char *why)
{
	lwsl_user("--- case %d: %s: %s%s%s ---\n", cur, cases[cur].name,
		  ok ? "PASS" : "FAIL", why ? ": " : "", why ? why : "");
	if (!ok)
		failures++;
}

static void
next_case(lws_sorted_usec_list_t *sul);

static void
case_evaluate(void)
{
	const struct xcase *c = &cases[cur];
	size_t expect_len;
	int n;

	lws_sul_cancel(&sul_watchdog);
	case_done = 1;

	/* a GET is answered before its body is read */
	expect_len = !strcmp(c->method, "POST") ? c->body_len : 0;

	for (n = 0; n < 1 + c->pipeline; n++) {
		struct conn *cn = conns[n];
		unsigned int rlen = 0, rsum = 0;

		if (!c->expect_status) {
			if (cn->completed && cn->status == 200) {
				case_finish(0, "expected a failure, got 200");
				goto next;
			}
			continue;
		}

		if (!cn->completed || cn->status != c->expect_status) {
			lwsl_err("conn %d: completed %d status %d, expected %d\n",
				 n, cn->completed, cn->status, c->expect_status);
			case_finish(0, "unexpected status / completion");
			goto next;
		}

		if (c->expect_status != 200)
			continue;

		if (!cn->line_done ||
		    sscanf(cn->line, "len=%u sum=%x", &rlen, &rsum) != 2) {
			lwsl_err("conn %d: line_done %d, line '%s', %u payload bytes\n",
				 n, cn->line_done, cn->line,
				 (unsigned int)cn->rx_len);
			case_finish(0, "no summary line in response");
			goto next;
		}

		if (rlen != expect_len || rsum != sum_pat(expect_len)) {
			lwsl_err("server saw len %u sum %08x, expected len %u sum %08x\n",
				 rlen, rsum, (unsigned int)expect_len,
				 (unsigned int)sum_pat(expect_len));
			case_finish(0, "server did not see the payload we sent");
			goto next;
		}

		if (cn->rx_len != rlen || cn->rx_sum != sum_pat(rlen)) {
			lwsl_err("received %u bytes sum %08x, expected %u bytes sum %08x\n",
				 (unsigned int)cn->rx_len, cn->rx_sum, rlen,
				 sum_pat(rlen));
			case_finish(0, "response payload mismatch");
			goto next;
		}
	}

	switch (c->gate) {
	case XG_NONE:
		break;
	case XG_BLOCK:
		/*
		 * The interceptor answered it, and the app protocol on the
		 * guarded mount was never dispatched: no LWS_CALLBACK_HTTP,
		 * and (checked by expect_server_rx below) no body either
		 */
		if (srv.gate_blocks != 1 + c->pipeline) {
			lwsl_err("interceptor took %d requests, expected %d\n",
				 srv.gate_blocks, 1 + c->pipeline);
			case_finish(0, "interceptor did not take the request");
			goto next;
		}
		if (srv.http_cbs) {
			lwsl_err("app saw %d requests, expected none\n",
				 srv.http_cbs);
			case_finish(0, "blocked request reached the app");
			goto next;
		}
		break;
	case XG_PASS:
		if (srv.gate_blocks) {
			lwsl_err("interceptor took %d requests, expected none\n",
				 srv.gate_blocks);
			case_finish(0, "interceptor took an authorized request");
			goto next;
		}
		if (srv.http_cbs != 1) {
			lwsl_err("app saw %d requests, expected 1\n",
				 srv.http_cbs);
			case_finish(0, "authorized request did not reach the app");
			goto next;
		}
		break;
	}

	if (c->expect_server_rx >= 0 && srv.body_len != c->expect_server_rx) {
		lwsl_err("server decoded %ld body bytes, expected %ld\n",
			 srv.body_len, c->expect_server_rx);
		case_finish(0, "server body byte count");
		goto next;
	}

	if (c->pipeline) {
		if (c->gate != XG_BLOCK && srv.http_cbs != 2) {
			lwsl_err("server saw %d requests, expected 2\n",
				 srv.http_cbs);
			case_finish(0, "pipelined request count");
			goto next;
		}
		if (srv.conns > 1) {
			lwsl_err("pipelined requests used %d connections\n",
				 srv.conns);
			case_finish(0, "pipelined requests did not share a connection");
			goto next;
		}
	}

	case_finish(1, NULL);

next:
	lws_sul_schedule(context, 0, &sul_next, next_case,
			 100 * LWS_US_PER_MS);
}

/* every connection of the case reached a terminal state? */

static void
case_check(void)
{
	const struct xcase *c = &cases[cur];
	int n;

	if (case_done)
		return;

	for (n = 0; n < 1 + c->pipeline; n++) {
		struct conn *cn = conns[n];

		if (c->expect_status) {
			if (!cn->completed && !cn->closed && !cn->error)
				return;
		} else
			if (!cn->closed && !cn->error)
				return;
	}

	case_evaluate();
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct conn *cn = (struct conn *)lws_get_opaque_user_data(wsi);
	static uint8_t sbuf[LWS_PRE + 8192];
	char rbuf[LWS_PRE + 2048], *px = &rbuf[LWS_PRE];
	int lenx = sizeof(rbuf) - LWS_PRE, n;
	const struct xcase *c;
	uint8_t **pp, *end;
	size_t o;

	if (!cn)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	c = cn->c;

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: client: connection error: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		cn->error = 1;
		if (cn->case_idx == cur)
			case_check();
		break;

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		pp = (uint8_t **)in;
		end = (*pp) + len;

		switch (c->req) {
		case XR_CL:
			if (lws_add_http_header_content_length(wsi,
					(lws_filepos_t)(c->claim_len ?
						c->claim_len : c->body_len),
					pp, end))
				return -1;
			break;
		case XR_CHUNKED:
		case XR_CHUNKED_EXT:
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_TRANSFER_ENCODING,
					(const uint8_t *)"chunked", 7, pp, end))
				return -1;
			break;
		case XR_TE_BAD:
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_TRANSFER_ENCODING,
					(const uint8_t *)"gzip", 4, pp, end))
				return -1;
			break;
		case XR_TE_AND_CL:
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_TRANSFER_ENCODING,
					(const uint8_t *)"chunked", 7, pp, end) ||
			    lws_add_http_header_content_length(wsi,
					(lws_filepos_t)c->claim_len, pp, end))
				return -1;
			break;
		default:
			break;
		}

		if (cn->framed_len) {
			lws_client_http_body_pending(wsi, 1);
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (!cn->framed || cn->sent >= cn->framed_len)
			break;

		o = cn->framed_len - cn->sent;
		if (o > c->write_sz)
			o = c->write_sz;
		if (o > sizeof(sbuf) - LWS_PRE)
			o = sizeof(sbuf) - LWS_PRE;
		memcpy(&sbuf[LWS_PRE], cn->framed + cn->sent, o);

		n = LWS_WRITE_HTTP;
		if (cn->sent + o == cn->framed_len) {
			lws_client_http_body_pending(wsi, 0);
			n = LWS_WRITE_HTTP_FINAL;
		}

		if (lws_write(wsi, &sbuf[LWS_PRE], o,
			      (enum lws_write_protocol)n) != (int)o)
			return -1;

		cn->sent += o;
		if (n != LWS_WRITE_HTTP_FINAL)
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		cn->status = (int)lws_http_client_http_response(wsi);
		lwsl_user("%s: client: response status %d\n", __func__,
			  cn->status);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		/* in only ever holds decoded payload */
		lwsl_hexdump_info(in, len);
		for (o = 0; o < len; o++) {
			uint8_t b = ((const uint8_t *)in)[o];

			if (cn->line_done) {
				cn->rx_sum = (cn->rx_sum * 31u) + b;
				cn->rx_len++;
				continue;
			}
			if (cn->line_len < sizeof(cn->line) - 1)
				cn->line[cn->line_len++] = (char)b;
			cn->line[cn->line_len] = '\0';
			if (b == '\n')
				cn->line_done = 1;
		}
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		lwsl_user("%s: client: completed, status %d, %u payload bytes\n",
			  __func__, cn->status, (unsigned int)cn->rx_len);
		cn->completed = 1;
		if (cn->case_idx == cur)
			case_check();
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		cn->closed = 1;
		if (cn->case_idx == cur)
			case_check();
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * Connection records live on a list until we know lws has finished with the
 * wsi (closed or errored), or until exit: a keepalive connection left over
 * from a finished case can be handed to a later pipelined request, so we
 * never assume anything about wsi lifetimes and never keep wsi pointers.
 */

static void
conn_free(struct conn *cn)
{
	struct conn **pp = &conn_list;

	while (*pp && *pp != cn)
		pp = &(*pp)->next;
	if (*pp)
		*pp = cn->next;

	if (cn->framed)
		free(cn->framed);
	free(cn);
}

static void
conn_reap(int all)
{
	struct conn *cn = conn_list, *nx;

	while (cn) {
		nx = cn->next;
		if (all || (cn->case_idx < cur && (cn->closed || cn->error)))
			conn_free(cn);
		cn = nx;
	}
}

static struct conn *
conn_start(const struct xcase *c)
{
	struct lws_client_connect_info i;
	struct conn *cn;
	size_t max;

	cn = calloc(1, sizeof(*cn));
	if (!cn)
		return NULL;

	cn->c = c;
	cn->case_idx = cur;
	cn->next = conn_list;
	conn_list = cn;

	/* build the framed request body */

	switch (c->req) {
	case XR_CL:
	case XR_BODY_NOHDR:
		if (c->body_len) {
			size_t n;

			cn->framed = malloc(c->body_len);
			if (!cn->framed)
				goto bail;
			for (n = 0; n < c->body_len; n++)
				cn->framed[n] = pat(n);
			cn->framed_len = c->body_len;
		}
		break;
	case XR_CHUNKED:
	case XR_CHUNKED_EXT:
		/* the smallest chunks cost 5 framing bytes per payload byte */
		max = (c->body_len * 6) + 256;
		cn->framed = malloc(max);
		if (!cn->framed)
			goto bail;
		cn->framed_len = frame_chunked(cn->framed, max, c->body_len,
					       c->req == XR_CHUNKED_EXT);
		break;
	default:
		break;
	}

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.vhost = vh_cli;
	i.address = server_addr;
	i.host = server_addr;
	i.origin = server_addr;
	i.port = c->h2 ? port_h2 : port_h1;
	i.path = c->path;
	i.method = c->method;
	i.protocol = "http-xfer";
	i.opaque_user_data = cn;
	if (c->pipeline)
		i.ssl_connection |= LCCSCF_PIPELINE;
#if defined(LWS_WITH_HTTP2)
	if (c->h2)
		i.ssl_connection |= LCCSCF_H2_PRIOR_KNOWLEDGE;
#endif

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		goto bail;
	}

	return cn;

bail:
	conn_free(cn);

	return NULL;
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	case_finish(0, "watchdog: case did not complete");
	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
}

static void
next_case(lws_sorted_usec_list_t *sul)
{
	const struct xcase *c;
	int n;

	if (only_case >= 0 && cur >= 0)
		cur = (int)LWS_ARRAY_SIZE(cases) - 1;
	cur++;
	if (only_case >= 0 && cur < (int)LWS_ARRAY_SIZE(cases))
		cur = only_case;
	conn_reap(0);
	memset(conns, 0, sizeof(conns));
	case_done = 0;
	if (cur == (int)LWS_ARRAY_SIZE(cases)) {
		result = failures ? 1 : 0;
		interrupted = 1;
		return;
	}

	c = &cases[cur];
	lwsl_user("=== case %d: %s ===\n", cur, c->name);

	memset(&srv, 0, sizeof(srv));

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 CASE_TIMEOUT_S * LWS_US_PER_SEC);

	for (n = 0; n < 1 + c->pipeline; n++) {
		conns[n] = conn_start(c);
		if (!conns[n]) {
			case_finish(0, "could not start connection");
			lws_sul_schedule(context, 0, &sul_next, next_case, 1);
			return;
		}
	}
}

static const struct lws_protocols protocols_srv[] = {
	{ "http-xfer", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
#if defined(LWS_WITH_JOSE)
	{ "xfer-gate", callback_gate, 0, 0, 0, NULL, 0 },
#endif
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "http-xfer", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/*
 * /small is served by the same protocol, but with a 64-byte body limit, to
 * check what happens to bodies over the limit
 */

static const struct lws_http_mount mount_small = {
	.mountpoint		= "/small",
	.protocol		= "http-xfer",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 6,
	.max_http_body_size	= 64,
};

#if defined(LWS_WITH_JOSE)

/*
 * /gated is an ordinary callback mount served by the same protocol, except
 * that every request to it must get past the interceptor protocol on
 * /bouncer first
 */

static const struct lws_http_mount mount_bouncer = {
	.mount_next		= &mount_small,
	.mountpoint		= "/bouncer",
	.protocol		= "xfer-gate",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 8,
};

static const struct lws_http_mount mount_gated = {
	.mount_next		= &mount_bouncer,
	.mountpoint		= "/gated",
	.protocol		= "http-xfer",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 6,
	.interceptor_path	= "/bouncer",
};

#define MOUNT_LIST (&mount_gated)
#else
#define MOUNT_LIST (&mount_small)
#endif

void sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/*
	 * The defaults budget 8 fds per thread, sized for a lone client.
	 * We have four listen sockets (h1 + h2, v4 + v6) plus the system
	 * fds, and a case can have both ends of an h2 connection, two
	 * pipelined clients and a keepalive connection left over from the
	 * previous case all open at once.  Past the budget lws stops
	 * servicing the listeners until something closes, which here is
	 * the previous case's idle keepalive timing out 5s later.
	 */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_h1 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--h2-port")))
		port_h2 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;
	if ((p = lws_cmdline_option(argc, argv, "--case")))
		only_case = atoi(p);
	/* --serve-only: just run the server vhosts, for poking at by hand */

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: http body transfer framings\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* h1 server vhost */

	info.port = port_h1;
	info.vhost_name = "srv-h1";
	info.protocols = protocols_srv;
	info.mounts = MOUNT_LIST;

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create h1 server vhost\n");
		goto bail;
	}

#if defined(LWS_WITH_HTTP2)
	/* h2 server vhost, cleartext with prior knowledge */

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
	if (!lws_cmdline_option(argc, argv, "--serve-only"))
		lws_sul_schedule(context, 0, &sul_next, next_case, 1);

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

bail:
	lws_context_destroy(context);
	conn_reap(1);

	lwsl_user("Completed: %s (%d of %d cases failed)\n",
		  result ? "FAIL" : "PASS", failures,
		  (int)LWS_ARRAY_SIZE(cases));

	return result;
}
