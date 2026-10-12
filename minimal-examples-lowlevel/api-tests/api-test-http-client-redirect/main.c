/*
 * lws-api-test-http-client-redirect
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * How the lws http client follows redirects, and the parts of RFC 9110 /
 * 9112 that decide what it sends where afterwards.
 *
 *  - a Location is resolved against the request it answers (RFC 3986 5.2):
 *    a relative path is merged with the request's path, dot segments are
 *    removed, an empty path with a query keeps the path, a fragment is
 *    dropped, and "//host:port/path" names another authority rather than
 *    being a path.  A relative reference keeps the request's Host:
 *
 *  - the method it is followed with (RFC 9110 15.4): a 301 or 302 turns
 *    only a POST into a GET, a 303 turns anything but a HEAD into a GET,
 *    307 and 308 keep the method.  A request that stays a POST or a PUT
 *    sends its body again; one turned into a GET sends none
 *
 *  - Locations that are refused rather than guessed at: two of them, one
 *    carrying userinfo, a port outside 1 - 65535, a scheme that is not
 *    http(s), and bytes that are not a URI reference
 *
 *  - a response saying "Connection: close" (RFC 9112 9.6) leaves its
 *    connection for no further request, even one that asked to pipeline
 *    on it; without it, the next request rides the same connection
 *
 *  - a request body is timed per piece: an upload that keeps moving
 *    completes, however much longer than the context's timeout it takes
 *
 *  - a digest auth challenge that closes its connection is answered on a
 *    new one, to the same authority, so the request's Host: is kept
 *
 * The server is a raw socket in the same process speaking http by hand, so
 * it can send exactly the redirects above, and see exactly the request line,
 * Host: and body the client sent, and on which of the case's connections.
 * Each case checks the last request the server saw, and how many it saw.
 *
 * The test fails if any case does not end as expected inside the watchdog
 * period.
 */

#include <libwebsockets.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>

#define HCR_CASE_TIMEOUT_S	10
/* the context's timeout, which the slow upload takes longer than */
#define HCR_TIMEOUT_S		2

#define HCR_BODY		"hello"
#define HCR_SLOW_PIECES		5
#define HCR_SLOW_PIECE		200
#define HCR_SLOW_GAP_MS		800

/* the Host: the redirect cases ask for, which is not the address dialled */
#define HCR_VHOST		"vhost.example"

enum {
	HCK_REDIR,	/* one request, maybe redirected */
	HCK_TWO,	/* a second request, pipelining, once the first is done */
	HCK_SLOW,	/* a POST whose body goes in slow pieces */
	HCK_DIGEST,	/* a GET with credentials, challenged for them */
};

static const struct hcr_case {
	const char	*name;
	const char	*vhost;		/* client vhost: its own active conns */
	const char	*method;
	const char	*target;
	const char	*target2;	/* HCK_TWO: the second request's */
	const char	*want;		/* a format taking the server port: the
					 * last request the server must see, or
					 * NULL: the client must refuse */
	const char	*why;		/* refused: in the connection error */
	int		requests;	/* the server must see this many */
	char		kind;
} cases[] = {

	/* relative references */

	{ "relative path is merged with the request's",
	  "cli", "GET", "/a/b/start?redir=rel", NULL,
	  "GET /a/b/c?x=1 host=" HCR_VHOST " len=0 conn=2", NULL, 2, HCK_REDIR },
	{ "dot segments are removed",
	  "cli", "GET", "/a/b/start?redir=dots", NULL,
	  "GET /a/d/f host=" HCR_VHOST " len=0 conn=2", NULL, 2, HCK_REDIR },
	{ "a query alone keeps the path",
	  "cli", "GET", "/a/b/start?redir=query", NULL,
	  "GET /a/b/start?z=3 host=" HCR_VHOST " len=0 conn=2", NULL, 2,
	  HCK_REDIR },
	{ "//host:port/path names an authority, not a path",
	  "cli", "GET", "/a/b/start?redir=netpath", NULL,
	  "GET /n/p host=localhost:%d len=0 conn=2", NULL, 2, HCK_REDIR },
	{ "absolute URI",
	  "cli", "GET", "/a/b/start?redir=abs", NULL,
	  "GET /abs host=localhost:%d len=0 conn=2", NULL, 2, HCK_REDIR },
	{ "absolute URI with no path goes to /",
	  "cli", "GET", "/a/b/start?redir=abs-root", NULL,
	  "GET / host=localhost:%d len=0 conn=2", NULL, 2, HCK_REDIR },

	/* methods */

	{ "POST 301 is followed with a GET",
	  "cli", "POST", "/start?redir=301", NULL,
	  "GET /done host=" HCR_VHOST " len=0 conn=2", NULL, 2, HCK_REDIR },
	{ "POST 302 is followed with a GET",
	  "cli", "POST", "/start?redir=302", NULL,
	  "GET /done host=" HCR_VHOST " len=0 conn=2", NULL, 2, HCK_REDIR },
	{ "PUT 302 stays a PUT, with its body",
	  "cli", "PUT", "/start?redir=302", NULL,
	  "PUT /done host=" HCR_VHOST " len=5 conn=2", NULL, 2, HCK_REDIR },
	{ "DELETE 301 stays a DELETE",
	  "cli", "DELETE", "/start?redir=301", NULL,
	  "DELETE /done host=" HCR_VHOST " len=0 conn=2", NULL, 2, HCK_REDIR },
	{ "POST 303 is followed with a GET",
	  "cli", "POST", "/start?redir=303", NULL,
	  "GET /done host=" HCR_VHOST " len=0 conn=2", NULL, 2, HCK_REDIR },
	{ "DELETE 303 is followed with a GET",
	  "cli", "DELETE", "/start?redir=303", NULL,
	  "GET /done host=" HCR_VHOST " len=0 conn=2", NULL, 2, HCK_REDIR },
	{ "HEAD 303 stays a HEAD",
	  "cli", "HEAD", "/start?redir=303", NULL,
	  "HEAD /done host=" HCR_VHOST " len=0 conn=2", NULL, 2, HCK_REDIR },
	{ "POST 307 stays a POST, with its body",
	  "cli", "POST", "/start?redir=307", NULL,
	  "POST /done host=" HCR_VHOST " len=5 conn=2", NULL, 2, HCK_REDIR },
	{ "PUT 308 stays a PUT, with its body",
	  "cli", "PUT", "/start?redir=308", NULL,
	  "PUT /done host=" HCR_VHOST " len=5 conn=2", NULL, 2, HCK_REDIR },

	/* Locations refused */

	{ "two Locations are refused",
	  "cli", "GET", "/start?redir=two", NULL, NULL,
	  "more than one Location", 1, HCK_REDIR },
	{ "userinfo is refused",
	  "cli", "GET", "/start?redir=userinfo", NULL, NULL,
	  "Location refused", 1, HCK_REDIR },
	{ "port 0 is refused",
	  "cli", "GET", "/start?redir=port0", NULL, NULL,
	  "Location refused", 1, HCK_REDIR },
	{ "port 65536 is refused",
	  "cli", "GET", "/start?redir=port-big", NULL, NULL,
	  "Location refused", 1, HCK_REDIR },
	{ "a space is refused",
	  "cli", "GET", "/start?redir=space", NULL, NULL,
	  "Location refused", 1, HCK_REDIR },
	{ "a broken percent-escape is refused",
	  "cli", "GET", "/start?redir=pct", NULL, NULL,
	  "Location refused", 1, HCK_REDIR },
	{ "a scheme other than http(s) is refused",
	  "cli", "GET", "/start?redir=scheme", NULL, NULL,
	  "Location refused", 1, HCK_REDIR },

	/* Connection: close */

	{ "without Connection: close, the next request rides the connection",
	  "cli-keep", "GET", "/first", "/second",
	  "GET /second host=localhost len=0 conn=1", NULL, 2, HCK_TWO },
	{ "after Connection: close, the next request has its own connection",
	  "cli-close", "GET", "/first?close=1", "/second",
	  "GET /second host=localhost len=0 conn=2", NULL, 2, HCK_TWO },

	/* upload timeout */

	{ "an upload longer than the timeout completes while it moves",
	  "cli", "POST", "/slow", NULL,
	  "POST /slow host=localhost len=1000 conn=1", NULL, 1, HCK_SLOW },

#if defined(LWS_WITH_HTTP_DIGEST_AUTH) && defined(LWS_WITH_TLS)
	/* digest auth, whose hashes come from the tls library */

	{ "a digest retry on a new connection keeps the Host:",
	  "cli", "GET", "/auth", NULL,
	  "GET /auth host=" HCR_VHOST " len=0 conn=2 auth=digest", NULL, 2,
	  HCK_DIGEST },
#endif
};

/* what the server answers "?redir=<name>" with */

static const struct hcr_redir {
	const char	*name;
	int		status;
	const char	*loc;		/* a format taking the server port */
	const char	*loc2;		/* a second Location, or NULL */
} redirs[] = {
	{ "rel",	302, "c?x=1#frag",			NULL },
	{ "dots",	302, "../d/./e/../f",			NULL },
	{ "query",	302, "?z=3",				NULL },
	{ "netpath",	302, "//localhost:%d/n/p",		NULL },
	{ "abs",	302, "http://localhost:%d/abs",		NULL },
	{ "abs-root",	302, "http://localhost:%d",		NULL },
	{ "301",	301, "/done",				NULL },
	{ "302",	302, "/done",				NULL },
	{ "303",	303, "/done",				NULL },
	{ "307",	307, "/done",				NULL },
	{ "308",	308, "/done",				NULL },
	{ "two",	302, "/done",				"/other" },
	{ "userinfo",	302, "http://u:p@localhost:%d/done",	NULL },
	{ "port0",	302, "http://localhost:0/done",		NULL },
	{ "port-big",	302, "http://localhost:65536/done",	NULL },
	{ "space",	302, "/do ne",				NULL },
	{ "pct",	302, "/do%%zzne",			NULL },
	{ "scheme",	302, "ftp://localhost:%d/done",		NULL },
};

static struct lws_context *context;
static lws_sorted_usec_list_t sul_next, sul_watchdog, sul_second, sul_piece;
static struct lws *cwsi;
static int cur = -1, failures, port = 7730, status, done, phase, conns,
	   conn_base, nseen, pieces_sent, piece_due;
static char seen[160];

/* ---- the server: http by hand on a raw socket ---- */

struct pss_srv {
	char		in[4096];
	char		out[512];
	size_t		in_len;
	size_t		out_len;
	int		conn;		/* the case's nth connection */
};

/* the offset of "\r\n\r\n" in in[0, len), or -1 */

static int
hcr_head_end(const char *in, size_t len)
{
	size_t n;

	for (n = 0; n + 4 <= len; n++)
		if (!memcmp(in + n, "\r\n\r\n", 4))
			return (int)n;

	return -1;
}

/*
 * Header names are case-insensitive.  strncasecmp() is not portable (windows
 * has _strnicmp()), and name is lower-case ascii, so compare by hand
 */

static int
hcr_name_is(const char *h, const char *name, size_t nl)
{
	while (nl--)
		if (tolower((int)(unsigned char)*h++) != *name++)
			return 0;

	return 1;
}

/* the value of header "name:" in the head [h, end), copied to dst */

static int
hcr_header(const char *h, const char *end, const char *name, char *dst,
	   size_t dlen)
{
	size_t nl = strlen(name);

	while (h < end) {
		const char *e = h;

		while (e < end && *e != '\r')
			e++;

		if ((size_t)(e - h) > nl && hcr_name_is(h, name, nl)) {
			h += nl;
			while (h < e && *h == ' ')
				h++;
			lws_strnncpy(dst, h, lws_ptr_diff_size_t(e, h), dlen);

			return 0;
		}

		h = e + 2;
	}

	return 1;
}

/* compose the answer to one complete request, and note what we saw */

static void
hcr_answer(struct pss_srv *pss, const char *head, size_t hlen, size_t body)
{
	const char *sp1, *sp2, *end = head + hlen, *r;
	char method[16], target[256], host[64], loc[128], auth[16];
	size_t n;
	char *o = pss->out, *oe = pss->out + sizeof(pss->out);

	sp1 = memchr(head, ' ', hlen);
	sp2 = sp1 ? memchr(sp1 + 1, ' ', lws_ptr_diff_size_t(end, sp1 + 1)) :
		    NULL;
	if (!sp2) {
		lws_strncpy(seen, "bad request line", sizeof(seen));
		nseen++;
		return;
	}
	lws_strnncpy(method, head, lws_ptr_diff_size_t(sp1, head),
		     sizeof(method));
	lws_strnncpy(target, sp1 + 1, lws_ptr_diff_size_t(sp2, sp1 + 1),
		     sizeof(target));
	if (hcr_header(head, end, "host:", host, sizeof(host)))
		host[0] = '\0';
	if (hcr_header(head, end, "authorization:", auth, sizeof(auth)))
		auth[0] = '\0';

	n = (size_t)lws_snprintf(seen, sizeof(seen),
				 "%s %s host=%s len=%u conn=%d", method, target,
				 host, (unsigned int)body, pss->conn);
	if (!strncmp(auth, "Digest ", 7))
		lws_snprintf(seen + n, sizeof(seen) - n, " auth=digest");
	nseen++;
	lwsl_user("%s: server saw: %s\n", __func__, seen);

	r = strstr(target, "?redir=");
	if (r) {
		for (n = 0; n < LWS_ARRAY_SIZE(redirs); n++)
			if (!strcmp(r + 7, redirs[n].name))
				break;
		if (n == LWS_ARRAY_SIZE(redirs))
			return;

		lws_snprintf(loc, sizeof(loc), redirs[n].loc, port);
		o += lws_snprintf(o, lws_ptr_diff_size_t(oe, o),
				  "HTTP/1.1 %d Redirect\r\nLocation: %s\r\n",
				  redirs[n].status, loc);
		if (redirs[n].loc2)
			o += lws_snprintf(o, lws_ptr_diff_size_t(oe, o),
					  "Location: %s\r\n", redirs[n].loc2);
		o += lws_snprintf(o, lws_ptr_diff_size_t(oe, o),
				  "Content-Length: 0\r\n\r\n");
	} else if (!strcmp(target, "/auth") && !auth[0])
		/*
		 * Closing after the challenge, the retry can't go on this
		 * connection: the client must make another
		 */
		o += lws_snprintf(o, lws_ptr_diff_size_t(oe, o),
			"HTTP/1.1 401 Unauthorized\r\n"
			"WWW-Authenticate: Digest realm=\"hcr\", "
			"nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", "
			"qop=\"auth\"\r\n"
			"Content-Length: 0\r\nConnection: close\r\n\r\n");
	else
		/*
		 * Saying "Connection: close", the connection is still left
		 * open, so only the client's honouring it keeps another
		 * request off it
		 */
		o += lws_snprintf(o, lws_ptr_diff_size_t(oe, o),
				  "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n%s"
				  "\r\n%s", strstr(target, "close=1") ?
					"Connection: close\r\n" : "",
				  strcmp(method, "HEAD") ? "ok" : "");

	pss->out_len = lws_ptr_diff_size_t(o, pss->out);
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t buf[LWS_PRE + sizeof(pss->out)];
	char cl[16];
	size_t body;
	int he;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		pss->conn = ++conns - conn_base;
		break;

	case LWS_CALLBACK_RAW_RX:
		if (len > sizeof(pss->in) - pss->in_len)
			return -1;
		memcpy(pss->in + pss->in_len, in, len);
		pss->in_len += len;

		/* one request at a time: the client does not pipeline heads */
		he = hcr_head_end(pss->in, pss->in_len);
		if (he < 0 || pss->out_len)
			break;

		body = 0;
		if (!hcr_header(pss->in, pss->in + he + 2, "content-length:",
				cl, sizeof(cl)))
			body = (size_t)atoi(cl);
		if (pss->in_len < (size_t)he + 4 + body)
			break;

		hcr_answer(pss, pss->in, (size_t)he + 2, body);

		pss->in_len -= (size_t)he + 4 + body;
		memmove(pss->in, pss->in + he + 4 + body, pss->in_len);
		if (pss->out_len)
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!pss->out_len)
			break;
		memcpy(buf + LWS_PRE, pss->out, pss->out_len);
		if (lws_write(wsi, buf + LWS_PRE, pss->out_len, LWS_WRITE_RAW) !=
							(int)pss->out_len)
			return -1;
		pss->out_len = 0;
		break;

	default:
		break;
	}

	return 0;
}

/* ---- the client ---- */

static void
next_case(lws_sorted_usec_list_t *sul);

static void
case_end(const char *why)
{
	if (done)
		return;
	done = 1;
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_second);
	lws_sul_cancel(&sul_piece);

	lwsl_user("--- case %d: %s: %s%s%s ---\n", cur, cases[cur].name,
		  why ? "FAIL" : "PASS", why ? ": " : "", why ? why : "");
	if (why)
		failures++;

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
}

static void
case_check(void)
{
	const struct hcr_case *c = &cases[cur];
	char want[160];

	if (!c->want) {
		case_end("the redirect should have been refused");
		return;
	}

	if (status != HTTP_STATUS_OK) {
		case_end("no 200 at the end");
		return;
	}

	lws_snprintf(want, sizeof(want), c->want, port);
	lwsl_user("%s: server saw \"%s\" (%d), want \"%s\" (%d)\n", __func__,
		  seen, nseen, want, c->requests);

	if (strcmp(seen, want) || nseen != c->requests)
		case_end("the server did not see the request it should have");
	else
		case_end(NULL);
}

static void
client_connect(const char *target)
{
	const struct hcr_case *c = &cases[cur];
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context	= context;
	i.vhost		= lws_get_vhost_by_name(context, c->vhost);
	i.address	= "localhost";
	/*
	 * The redirect cases ask for another Host: than the address, which a
	 * relative reference must keep.  A request that pipelines must name
	 * the address it dials, to be one others can join.
	 */
	i.host		= c->kind == HCK_REDIR || c->kind == HCK_DIGEST ?
						HCR_VHOST : i.address;
	i.origin	= i.host;
	i.port		= port;
	i.path		= target;
	i.method	= c->method;
	i.protocol	= "cli";
	i.pwsi		= &cwsi;
	i.opaque_user_data = (void *)(intptr_t)(cur + 1);
	if (c->kind == HCK_TWO)
		i.ssl_connection = LCCSCF_PIPELINE;
	if (c->kind == HCK_DIGEST) {
		i.auth_username	= "user";
		i.auth_password	= "pass";
	}

	if (!i.vhost || !lws_client_connect_via_info(&i))
		case_end("connect failed");
}

static void
second_cb(lws_sorted_usec_list_t *sul)
{
	client_connect(cases[cur].target2);
}

static void
piece_cb(lws_sorted_usec_list_t *sul)
{
	piece_due = 1;
	if (cwsi)
		lws_callback_on_writable(cwsi);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	const struct hcr_case *c = &cases[cur];
	char buf[LWS_PRE + 1024], *px = &buf[LWS_PRE];
	int lenx = sizeof(buf) - LWS_PRE, n;
	uint8_t **pp, *end;
	size_t body;

	/* a connection from an earlier case going away is not this case's */
	if (lws_get_opaque_user_data(wsi) != (void *)(intptr_t)(cur + 1))
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: client: connection error: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		cwsi = NULL;
		if (c->want) {
			case_end("connection error");
			break;
		}
		if (!in || !strstr((const char *)in, c->why))
			case_end("refused, but not for the right reason");
		else if (nseen != c->requests)
			case_end("refused, but the server saw a request after");
		else
			case_end(NULL);
		break;

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		/* a request reissued after a redirect sends its body again */
		pieces_sent = 0;
		piece_due = 1;

		if (c->kind == HCK_SLOW)
			body = HCR_SLOW_PIECES * HCR_SLOW_PIECE;
		else if ((!strcmp(c->method, "POST") ||
			  !strcmp(c->method, "PUT")) &&
			 !lws_http_is_redirected_to_get(wsi))
			body = strlen(HCR_BODY);
		else
			break;

		pp = (uint8_t **)in;
		end = (*pp) + len;
		if (lws_add_http_header_content_length(wsi,
						(lws_filepos_t)body, pp, end))
			return -1;
		lws_client_http_body_pending(wsi, 1);
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (lws_http_is_redirected_to_get(wsi) || !piece_due)
			break;

		if (c->kind != HCK_SLOW) {
			if (pieces_sent)
				break;
			n = (int)strlen(HCR_BODY);
			memcpy(px, HCR_BODY, (size_t)n);
			pieces_sent = HCR_SLOW_PIECES;
		} else {
			n = HCR_SLOW_PIECE;
			memset(px, 'a' + pieces_sent, (size_t)n);
			pieces_sent++;
		}

		if (pieces_sent == HCR_SLOW_PIECES)
			lws_client_http_body_pending(wsi, 0);
		if (lws_write(wsi, (uint8_t *)px, (size_t)n,
			      pieces_sent == HCR_SLOW_PIECES ?
				LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP) != n)
			return -1;

		/* the slow body's next piece goes after a gap */
		if (pieces_sent < HCR_SLOW_PIECES) {
			piece_due = 0;
			lws_sul_schedule(context, 0, &sul_piece, piece_cb,
					 HCR_SLOW_GAP_MS * LWS_US_PER_MS);
		}
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		status = (int)lws_http_client_http_response(wsi);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (wsi != cwsi)
			break;
		cwsi = NULL;
		if (c->kind == HCK_TWO && !phase++) {
			/* the first is done: the second goes once it idles */
			lws_sul_schedule(context, 0, &sul_second, second_cb,
					 100 * LWS_US_PER_MS);
			break;
		}
		case_check();
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		/* the first of two closing after it completed is not news */
		if (wsi != cwsi)
			break;
		cwsi = NULL;
		case_end("closed before completing");
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "srv", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	case_end("watchdog: case did not complete");
}

static void
next_case(lws_sorted_usec_list_t *sul)
{
	if (++cur == (int)LWS_ARRAY_SIZE(cases)) {
		lws_default_loop_exit(context);
		return;
	}

	lwsl_user("=== case %d: %s ===\n", cur, cases[cur].name);
	done = 0;
	status = 0;
	phase = 0;
	nseen = 0;
	seen[0] = '\0';
	conn_base = conns;

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 HCR_CASE_TIMEOUT_S * LWS_US_PER_SEC);

	client_connect(cases[cur].target);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* a server and a client in one process: don't budget fds */
	info.fd_limit_per_thread = 0;
	info.timeout_secs = HCR_TIMEOUT_S;

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);

	lwsl_user("LWS API selftest: http client redirects\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the server, http by hand on a raw socket */

	info.protocols = protocols_srv;
	info.options |= LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = "raw-skt";
	info.listen_accept_protocol = "srv";
	info.port = port;
	info.vhost_name = "srv";
	if (!lws_create_vhost(context, &info))
		goto bail;
	info.options &= ~(uint64_t)LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = NULL;
	info.listen_accept_protocol = NULL;

	/*
	 * The clients: the cases that pipeline have a vhost each, so neither
	 * finds the other's connection kept warm to join
	 */

	info.protocols = protocols_cli;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	if (!lws_create_vhost(context, &info))
		goto bail;
	info.vhost_name = "cli-keep";
	if (!lws_create_vhost(context, &info))
		goto bail;
	info.vhost_name = "cli-close";
	if (!lws_create_vhost(context, &info))
		goto bail;

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);

	while (n >= 0 && cur < (int)LWS_ARRAY_SIZE(cases))
		n = lws_service(context, 0);

	lws_context_destroy(context);

	lwsl_user("Completed: %s (%d of %d cases failed)\n",
		  failures ? "FAIL" : "PASS", failures,
		  (int)LWS_ARRAY_SIZE(cases));

	return !!failures;

bail:
	lwsl_err("vhost creation failed\n");
	lws_context_destroy(context);

	return 1;
}
