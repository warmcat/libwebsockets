/*
 * lws-api-test-html-process
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * lws_chunked_html_process() substitutes variables in a file being
 * interpreted, one lump of it at a time, in place, and frames each lump
 * as an h1 chunk if asked.  How the file is cut into lumps is not up to
 * the interpreter: on h2 the peer's flow control window decides it.
 *
 * So here a small page is fed through it cut into lumps of every size from
 * one byte to all of it, the way lws_http_file_tx() calls it: the lump at
 * the start of a buffer with 10 bytes in front of it for the chunk size
 * line, and 128 bytes after it to grow into.  Whatever the cut, the output,
 * with the chunk framing taken off, must be the page with its variables
 * replaced, and nothing may be written outside the buffer.
 *
 * Then the same through a server: a file mount interprets the .html files
 * in ./docroot with a protocol using lws_chunked_html_process(), and the
 * lws client gets a page of variables over h1 (chunked) and h2 (prior
 * knowledge), in lumps a small serv_buf cuts wherever it falls, and an
 * empty page, which on h1 must still be a whole chunked body.
 *
 * /hm is a file mount that interprets the same way, but also names a
 * protocol of its own, with its own per-session data, that adds headers.
 * The interpreter must still run with its own per-session data: it used to
 * be given the mount protocol's, which binding that protocol had swapped in
 * for the interpreter's after it was allocated (G-513).
 *
 * Last, on one h1 keep-alive connection, an interpreted page and then a POST
 * to /raw, a callback mount whose protocol has no per-session data, which
 * answers with the same file through lws_serve_http_file().  That file is
 * nothing to do with the interpreter: it must come back untransformed, with
 * the Content-Length of the file, and without the page mount's caching
 * policy.  The interpreter, and the caching, of the first transaction used
 * to carry over to the second, which had the interpreter's callback run with
 * the other protocol's (NULL) user_space (G-493).
 *
 * Run it with the test directory as the cwd.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#define HEADROOM	10	/* lws_http_file_tx() leaves this for the size */
#define GROWTH		128	/* ... and this for the content to grow into */
#define GUARD		32
#define GUARD_BYTE	0xa5

#define TEN		"0123456789"
#define HUNDRED		TEN TEN TEN TEN TEN TEN TEN TEN TEN TEN

static const char * const vars[] = {
	"$name", "$v", "$empty", "$longest_var14"
};

static const char * const vals[] = {
	"Alice", HUNDRED, "", "L"
};

static const char page[] =
	"<p>$name, $v; [$empty] $longest_var14 $$name $nam $ "
	"$longest_var14x $name$name$</p>$na";

static const char expected[] =
	"<p>Alice, " HUNDRED "; [] L $Alice $nam $ "
	"Lx AliceAlice$</p>$na";

static const char *
replace(void *data, int index)
{
	(void)data;

	return vals[index];
}

static int
guard_ok(const uint8_t *g, size_t len)
{
	while (len--)
		if (*g++ != GUARD_BYTE)
			return 0;

	return 1;
}

/*
 * Take the chunk framing off one lump's output, checking it as we go
 */

static int
dechunk(const char *p, int len, int final, char *out, size_t *olen,
	size_t omax)
{
	const char *e = p + len;
	char *q;
	long cl;

	if (!len)
		return !final; /* only a lump that is not the last may be empty */

	cl = strtol(p, &q, 16);
	if (cl) {
		if (q + 2 > e || q[0] != '\r' || q[1] != '\n')
			return 0;
		q += 2;
		if (cl < 0 || q + cl + 2 > e || q[cl] != '\r' ||
		    q[cl + 1] != '\n' || *olen + (size_t)cl > omax)
			return 0;
		memcpy(out + *olen, q, (size_t)cl);
		*olen += (size_t)cl;
		q += cl + 2;
	} else
		q = (char *)p;

	if (final) {
		if (e - q != 5 || memcmp(q, "0\r\n\r\n", 5))
			return 0;
		q += 5;
	}

	return q == e;
}

/*
 * Run the page through in lumps of ls bytes.  Returns 0 if the output was
 * right.
 */

static int
run(size_t ls, int chunked)
{
	uint8_t buf[HEADROOM + sizeof(page) + GROWTH + GUARD];
	struct lws_process_html_state s;
	struct lws_process_html_args a;
	size_t done = 0, olen = 0, l;
	char out[512];

	memset(&s, 0, sizeof(s));
	s.vars = vars;
	s.count_vars = (int)LWS_ARRAY_SIZE(vars);
	s.replace = replace;

	while (done < sizeof(page) - 1) {
		l = sizeof(page) - 1 - done;
		if (l > ls)
			l = ls;

		memset(buf, GUARD_BYTE, sizeof(buf));
		memcpy(buf + HEADROOM, page + done, l);
		done += l;

		a.p = (char *)buf + HEADROOM;
		a.len = (int)l;
		a.max_len = (int)(l + GROWTH);
		a.final = done == sizeof(page) - 1;
		a.chunked = chunked;

		if (lws_chunked_html_process(&a, &s)) {
			lwsl_err("%s: lump %d: refused\n", __func__, (int)ls);
			return 1;
		}

		if (!guard_ok(buf + HEADROOM + l + GROWTH, GUARD) ||
		    a.p < (char *)buf ||
		    a.p + a.len > (char *)buf + HEADROOM + l + GROWTH) {
			lwsl_err("%s: lump %d: wrote outside the buffer\n",
				 __func__, (int)ls);
			return 1;
		}

		if (!chunked) {
			if (olen + (size_t)a.len > sizeof(out))
				return 1;
			memcpy(out + olen, a.p, (size_t)a.len);
			olen += (size_t)a.len;
			continue;
		}

		if (!dechunk(a.p, a.len, a.final, out, &olen, sizeof(out))) {
			lwsl_err("%s: lump %d: bad chunk framing\n", __func__,
				 (int)ls);
			return 1;
		}
	}

	if (s.pos) {
		lwsl_err("%s: lump %d: %d bytes left held back\n", __func__,
			 (int)ls, s.pos);
		return 1;
	}

	if (olen != sizeof(expected) - 1 || memcmp(out, expected, olen)) {
		lwsl_err("%s: lump %d, chunked %d: got '%.*s'\n", __func__,
			 (int)ls, chunked, (int)olen, out);
		return 1;
	}

	return 0;
}

#if defined(LWS_WITH_CLIENT) && defined(LWS_WITH_FILE_OPS)

/*
 * ./docroot/page.html is PAGE_UNIT PAGE_UNITS times
 */

#define PAGE_UNIT	"<b>$name</b> $longest_var14|"
#define PAGE_OUT	"<b>Alice</b> L|"
#define PAGE_UNITS	150

enum {
	XP_H1,
	XP_H2C,
};

static const char * const xport_names[] = { "h1", "h2c" };

struct xcase {
	int		xport;
	const char	*path;
	int		empty;
	int		hm;	/* the mount protocol must add its headers */
};

static const struct xcase cases[] = {
	{ XP_H1, "/page.html", 0, 0 },
	{ XP_H1, "/empty.html", 1, 0 },
	{ XP_H1, "/hm/page.html", 0, 1 },
#if defined(LWS_WITH_HTTP2)
	{ XP_H2C, "/page.html", 0, 0 },
	{ XP_H2C, "/empty.html", 1, 0 },
	{ XP_H2C, "/hm/page.html", 0, 1 },
#endif
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static int result = 1, cur = -1, port_h1 = 7681, port_h2c = 7682,
	   hm_add_headers, hm_add_headers_before;
static const char *server_addr = "127.0.0.1";

static struct {
	char		body[PAGE_UNITS * sizeof(PAGE_UNIT)];
	size_t		body_len;
	int		status;
	int		done;
} cli;

/*
 * The interpreter: the state is the interpreted request's own.  It is
 * marked as the interpreter's the first time it is used, so being handed
 * per-session data of another protocol shows
 */

#define PSS_INTERP_MAGIC	0x1a7e5c01u
#define PSS_HM_MAGIC		0x4d0c4a11u

struct pss_interp {
	uint32_t			magic;
	struct lws_process_html_state	s;
};

struct pss_hm {
	uint32_t			magic;
};

static int
callback_interp(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	struct pss_interp *pss = (struct pss_interp *)user;

	switch (reason) {
	case LWS_CALLBACK_PROCESS_HTML:
		if (!pss) {
			lwsl_err("%s: interpreting with no state\n", __func__);
			return -1;
		}
		if (!pss->magic)
			pss->magic = PSS_INTERP_MAGIC;
		if (pss->magic != PSS_INTERP_MAGIC) {
			lwsl_err("%s: interpreting with another protocol's "
				 "state (0x%x)\n", __func__,
				 (unsigned int)pss->magic);
			return -1;
		}
		if (!pss->s.vars) {
			pss->s.vars = vars;
			pss->s.count_vars = (int)LWS_ARRAY_SIZE(vars);
			pss->s.replace = replace;
		}

		return lws_chunked_html_process(
				(struct lws_process_html_args *)in, &pss->s) ?
									-1 : 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocol_vhost_options interpret = {
	NULL, NULL, ".html", "interp"
};

/*
 * /hm's own protocol: it adds a header to the files the mount serves, and
 * has per-session data of its own
 */

static int
callback_hm(struct lws *wsi, enum lws_callback_reasons reason,
	    void *user, void *in, size_t len)
{
	struct lws_process_html_args *args = (struct lws_process_html_args *)in;
	struct pss_hm *pss = (struct pss_hm *)user;
	unsigned char *p, *end;

	if (reason != LWS_CALLBACK_ADD_HEADERS)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	if (!pss)
		return -1;
	pss->magic = PSS_HM_MAGIC;

	p = (unsigned char *)args->p;
	end = p + args->max_len;
	if (lws_add_http_header_by_name(wsi, (const unsigned char *)"x-hm:",
					(const unsigned char *)"1", 1, &p, end))
		return -1;
	args->p = (char *)p;
	hm_add_headers++;

	return 0;
}

/*
 * /raw: answers with ./docroot/page.html as it is, from its callback.  It
 * has no per-session data, so its user_space is NULL.
 */
static int
callback_raw_file(struct lws *wsi, enum lws_callback_reasons reason,
		  void *user, void *in, size_t len)
{
	int n;

	if (reason != LWS_CALLBACK_HTTP)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	n = lws_serve_http_file(wsi, "./docroot/page.html", "text/html",
				NULL, 0);
	if (n < 0 || (n > 0 && lws_http_transaction_completed(wsi)))
		return -1;

	return 0;
}

static const struct lws_http_mount mount_raw = {
	.mountpoint		= "/raw",
	.origin			= "rawfile",
	.protocol		= "rawfile",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 4,
};

/* the pages may be cached, the file /raw sends is nothing to do with that */
#define PAGE_MAX_AGE	"max-age=600"

static const struct lws_http_mount mount_hm = {
	.mount_next		= &mount_raw,
	.mountpoint		= "/hm",
	.origin			= "./docroot",
	.def			= "page.html",
	.protocol		= "hdrmount",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 3,
	.interpret		= &interpret,
};

static const struct lws_http_mount mount = {
	.mount_next		= &mount_hm,
	.mountpoint		= "/",
	.origin			= "./docroot",
	.def			= "page.html",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 1,
	.interpret		= &interpret,
	.cache_max_age		= 600,
	.cache_reusable		= 1,
};

static void
next_case(lws_sorted_usec_list_t *sul);

static void
case_done(const char *why)
{
	const struct xcase *c = &cases[cur];

	if (why) {
		lwsl_err("--- %s %s: FAIL: %s ---\n", xport_names[c->xport],
			 c->path, why);
		lws_default_loop_exit(context);
		return;
	}

	lwsl_user("--- %s %s: PASS ---\n", xport_names[c->xport], c->path);
	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
}

static void
case_evaluate(void)
{
	const struct xcase *c = &cases[cur];
	size_t n;

	if (cli.status != HTTP_STATUS_OK) {
		case_done("not served");
		return;
	}

	if (c->hm && hm_add_headers == hm_add_headers_before) {
		case_done("the mount protocol added no headers");
		return;
	}

	if (c->empty) {
		case_done(cli.body_len ? "an empty page came with a body" :
					 NULL);
		return;
	}

	if (cli.body_len != PAGE_UNITS * (sizeof(PAGE_OUT) - 1)) {
		lwsl_err("%s: %u bytes\n", __func__,
			 (unsigned int)cli.body_len);
		case_done("the page came out the wrong length");
		return;
	}

	for (n = 0; n < PAGE_UNITS; n++)
		if (memcmp(cli.body + n * (sizeof(PAGE_OUT) - 1), PAGE_OUT,
			   sizeof(PAGE_OUT) - 1)) {
			lwsl_err("%s: unit %u: '%.*s'\n", __func__,
				 (unsigned int)n, (int)sizeof(PAGE_OUT) - 1,
				 cli.body + n * (sizeof(PAGE_OUT) - 1));
			case_done("the page came out wrong");
			return;
		}

	case_done(NULL);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 1024], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		/* an earlier case's connection finishing is not news */
		if (cur < 0 || lws_get_opaque_user_data(wsi) != &cases[cur])
			return lws_callback_http_dummy(wsi, reason, user, in,
						       len);
		break;
	default:
		break;
	}

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		cli.status = (int)lws_http_client_http_response(wsi);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (cli.body_len + len > sizeof(cli.body))
			return -1;
		memcpy(cli.body + cli.body_len, in, len);
		cli.body_len += len;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (!cli.done) {
			cli.done = 1;
			case_evaluate();
		}
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (!cli.done) {
			cli.done = 1;
			case_done(in ? (const char *)in : "connection error");
		}
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!cli.done) {
			cli.done = 1;
			case_done("closed without completing");
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * The keep-alive sequence, by a raw client so it is two transactions on one
 * connection, whose answers it frames itself from the bytes it receives
 */

static struct {
	char		rx[2 * PAGE_UNITS * sizeof(PAGE_UNIT) + 2048];
	char		body[PAGE_UNITS * sizeof(PAGE_UNIT)];
	size_t		rx_len;
	size_t		body_len;
	int		step;
	int		done;
} ka;

static void
ka_finish(const char *why)
{
	if (ka.done)
		return;
	ka.done = 1;

	if (why) {
		lwsl_err("--- h1 keep-alive, interpreted page then /raw: "
			 "FAIL: %s ---\n", why);
		lws_default_loop_exit(context);
		return;
	}

	lwsl_user("--- h1 keep-alive, interpreted page then /raw: PASS ---\n");
	result = 0;
	lws_default_loop_exit(context);
}

/* a header name or token, ignoring case, portably */
static int
ka_caseeq(const char *a, const char *b, size_t n)
{
	while (n--) {
		char x = *a++, y = *b++;

		if (x >= 'A' && x <= 'Z')
			x = (char)(x + ('a' - 'A'));
		if (y >= 'A' && y <= 'Z')
			y = (char)(y + ('a' - 'A'));
		if (x != y)
			return 0;
	}

	return 1;
}

/* the value of a header in a response head, or NULL */
static const char *
ka_hdr(const char *head, size_t head_len, const char *name, size_t *vlen)
{
	size_t nl = strlen(name), n;

	for (n = 0; n + 2 + nl < head_len; n++)
		if (head[n] == '\n' && ka_caseeq(head + n + 1, name, nl)) {
			const char *v = head + n + 1 + nl, *e;

			while (*v == ' ')
				v++;
			e = v;
			while (e < head + head_len && *e != '\r')
				e++;
			*vlen = (size_t)(e - v);

			return v;
		}

	return NULL;
}

/*
 * Is there a whole response at the start of ka.rx?  0 if not yet, -1 if it
 * is broken, else the length of it, with its body in ka.body and its head
 * left at the start of ka.rx
 */
static int
ka_response(size_t *head_len, int *status)
{
	const char *p = ka.rx, *end = ka.rx + ka.rx_len, *hd, *v;
	size_t vlen, cl = 0;

	hd = NULL;
	for (v = p; v + 4 <= end; v++)
		if (!memcmp(v, "\r\n\r\n", 4)) {
			hd = v + 4;
			break;
		}
	if (!hd)
		return 0;

	*head_len = (size_t)(hd - p);
	if (*head_len < 12 || strncmp(p, "HTTP/1.1 ", 9))
		return -1;
	*status = atoi(p + 9);
	ka.body_len = 0;

	v = ka_hdr(p, *head_len, "transfer-encoding:", &vlen);
	if (v && vlen == 7 && ka_caseeq(v, "chunked", 7)) {
		p = hd;
		while (1) {
			char *ep;
			long sz = strtol(p, &ep, 16);

			if (ep == p || sz < 0)
				return p < end ? -1 : 0;
			if (ep + 2 > end)
				return 0;
			if (memcmp(ep, "\r\n", 2))
				return -1;
			p = ep + 2;
			if ((size_t)(end - p) < (size_t)sz + 2)
				return 0;
			if (ka.body_len + (size_t)sz > sizeof(ka.body))
				return -1;
			memcpy(ka.body + ka.body_len, p, (size_t)sz);
			ka.body_len += (size_t)sz;
			p += sz;
			if (memcmp(p, "\r\n", 2))
				return -1;
			p += 2;
			if (!sz)
				return (int)(p - ka.rx);
		}
	}

	v = ka_hdr(p, *head_len, "content-length:", &vlen);
	if (!v)
		return -1;
	cl = (size_t)atol(v);
	if (cl > sizeof(ka.body))
		return -1;
	if ((size_t)(end - hd) < cl)
		return 0;
	memcpy(ka.body, hd, cl);
	ka.body_len = cl;

	return (int)(hd + cl - ka.rx);
}

static int
ka_send(struct lws *wsi)
{
	uint8_t buf[LWS_PRE + 256];
	int n;

	n = lws_snprintf((char *)&buf[LWS_PRE], sizeof(buf) - LWS_PRE,
			 ka.step ? "POST /raw HTTP/1.1\r\nHost: ka\r\n"
				   "Content-Length: 0\r\n"
				   "Connection: close\r\n\r\n" :
				   "GET /page.html HTTP/1.1\r\nHost: ka\r\n\r\n");

	return lws_write(wsi, &buf[LWS_PRE], (size_t)n, LWS_WRITE_RAW) != n;
}

/* the whole answer to the current step is at the start of ka.rx */
static const char *
ka_check(size_t head_len, int status)
{
	const char *cc;
	char ccv[64];
	size_t n, vlen;

	if (status != HTTP_STATUS_OK)
		return "not served";

	if (!ka.step) {
		/* the page, interpreted */
		if (ka.body_len != PAGE_UNITS * (sizeof(PAGE_OUT) - 1))
			return "the page came out the wrong length";
		for (n = 0; n < PAGE_UNITS; n++)
			if (memcmp(ka.body + n * (sizeof(PAGE_OUT) - 1),
				   PAGE_OUT, sizeof(PAGE_OUT) - 1))
				return "the page came out wrong";

		return NULL;
	}

	/* the file /raw sent, as it is */
	if (ka.body_len != PAGE_UNITS * (sizeof(PAGE_UNIT) - 1))
		return "/raw's file came out the wrong length";
	for (n = 0; n < PAGE_UNITS; n++)
		if (memcmp(ka.body + n * (sizeof(PAGE_UNIT) - 1), PAGE_UNIT,
			   sizeof(PAGE_UNIT) - 1))
			return "/raw's file was interpreted";

	cc = ka_hdr(ka.rx, head_len, "cache-control:", &vlen);
	if (cc) {
		lws_strnncpy(ccv, cc, vlen, sizeof(ccv));
		if (strstr(ccv, PAGE_MAX_AGE))
			return "/raw's file went with the page mount's caching";
	}

	return NULL;
}

static int
callback_ka(struct lws *wsi, enum lws_callback_reasons reason,
	    void *user, void *in, size_t len)
{
	const char *why;
	size_t head_len;
	int status, n;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		ka_finish(in ? (const char *)in : "raw connection error");
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		return ka_send(wsi) ? -1 : 0;

	case LWS_CALLBACK_RAW_RX:
		if (ka.rx_len + len >= sizeof(ka.rx)) {
			ka_finish("too much came back");
			return -1;
		}
		memcpy(ka.rx + ka.rx_len, in, len);
		ka.rx_len += len;
		ka.rx[ka.rx_len] = '\0';

		n = ka_response(&head_len, &status);
		if (!n)
			return 0;
		if (n < 0) {
			ka_finish("broken response");
			return -1;
		}

		why = ka_check(head_len, status);
		if (why) {
			ka_finish(why);
			return -1;
		}
		if (ka.step++) {
			ka_finish(NULL);
			return -1;
		}

		/* the next request goes on the same connection */
		if ((size_t)n != ka.rx_len) {
			ka_finish("more came back than the answer");
			return -1;
		}
		ka.rx_len = 0;

		return ka_send(wsi) ? -1 : 0;

	case LWS_CALLBACK_RAW_CLOSE:
		ka_finish("connection closed before both were answered");
		break;

	default:
		break;
	}

	return 0;
}

static void
ka_start(void)
{
	struct lws_client_connect_info i;

	memset(&ka, 0, sizeof(ka));
	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.port			= port_h1;
	i.method		= "RAW";
	i.local_protocol_name	= "ka";

	if (!lws_client_connect_via_info(&i))
		ka_finish("connect failed");
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	{ "interp", callback_interp, sizeof(struct pss_interp),
	  0, 0, NULL, 0 },
	{ "hdrmount", callback_hm, sizeof(struct pss_hm), 0, 0, NULL, 0 },
	{ "rawfile", callback_raw_file, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "cli", callback_cli, 0, 0, 0, NULL, 0 },
	{ "ka", callback_ka, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	const struct xcase *c;

	if (++cur == (int)LWS_ARRAY_SIZE(cases)) {
		/* the keep-alive sequence decides the result */
		ka_start();
		return;
	}
	c = &cases[cur];
	memset(&cli, 0, sizeof(cli));
	hm_add_headers_before = hm_add_headers;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.path			= c->path;
	i.method		= "GET";
	i.protocol		= "cli";
	i.local_protocol_name	= "cli";
	i.port			= port_h1;
	i.opaque_user_data	= (void *)c;
#if defined(LWS_WITH_HTTP2)
	if (c->xport == XP_H2C) {
		i.port = port_h2c;
		i.ssl_connection = LCCSCF_H2_PRIOR_KNOWLEDGE;
	}
#endif

	if (!lws_client_connect_via_info(&i))
		case_done("connect failed");
}

static void
sul_watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("--- timed out in case %d ---\n", cur);
	lws_default_loop_exit(context);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

static int
served(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_h1 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--h2c-port")))
		port_h2c = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;

	signal(SIGINT, sigint_handler);

	/* small, so the page is interpreted in several lumps */
	info.pt_serv_buf_size = 2048;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.protocols = protocols_srv;
	info.mounts = &mount;

	info.port = port_h1;
	info.vhost_name = "srv-h1";
	if (!lws_create_vhost(context, &info))
		goto bail;

#if defined(LWS_WITH_HTTP2)
	info.port = port_h2c;
	info.vhost_name = "srv-h2c";
	info.options |= LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
	if (!lws_create_vhost(context, &info))
		goto bail;
	info.options &= ~(uint64_t)LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
#endif

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	info.mounts = NULL;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli)
		goto bail;

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
	lws_sul_schedule(context, 0, &sul_watchdog, sul_watchdog_cb,
			 20 * LWS_US_PER_SEC);

	while (n >= 0)
		n = lws_service(context, 0);

bail:
	if (cur < 0)
		lwsl_err("--- setup failed ---\n");
	lws_sul_cancel(&sul_watchdog);
	lws_context_destroy(context);

	return result;
}
#endif

int
main(int argc, const char **argv)
{
	struct lws_process_html_state s;
	struct lws_process_html_args a;
	uint8_t buf[HEADROOM + 16 + GUARD];
	int e = 0, chunked;
	size_t ls;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);
	lwsl_user("LWS API selftest: html process\n");

	for (chunked = 0; chunked < 2; chunked++)
		for (ls = 1; ls <= sizeof(page) - 1; ls++)
			e |= run(ls, chunked);

	/*
	 * A substitution with no room to grow into is refused, and writes
	 * nothing past what it was given
	 */

	memset(&s, 0, sizeof(s));
	s.vars = vars;
	s.count_vars = (int)LWS_ARRAY_SIZE(vars);
	s.replace = replace;

	memset(buf, GUARD_BYTE, sizeof(buf));
	memcpy(buf + HEADROOM, "a $v b", 6);
	a.p = (char *)buf + HEADROOM;
	a.len = 6;
	a.max_len = 16;
	a.final = 1;
	a.chunked = 1;
	if (!lws_chunked_html_process(&a, &s)) {
		lwsl_err("an outgrown buffer was not refused\n");
		e = 1;
	}
	if (!guard_ok(buf + HEADROOM + 16, GUARD)) {
		lwsl_err("an outgrown buffer was written past\n");
		e = 1;
	}

	/* a last lump that comes to nothing is just the last-chunk */

	memset(&s, 0, sizeof(s));
	s.vars = vars;
	s.count_vars = (int)LWS_ARRAY_SIZE(vars);
	s.replace = replace;

	memset(buf, GUARD_BYTE, sizeof(buf));
	memcpy(buf + HEADROOM, "$empty", 6);
	a.p = (char *)buf + HEADROOM;
	a.len = 6;
	a.max_len = 16;
	a.final = 1;
	a.chunked = 1;
	if (lws_chunked_html_process(&a, &s) || a.len != 5 ||
	    memcmp(a.p, "0\r\n\r\n", 5)) {
		lwsl_err("an empty last lump is not just the last-chunk\n");
		e = 1;
	}

#if defined(LWS_WITH_CLIENT) && defined(LWS_WITH_FILE_OPS)
	if (!e)
		e = served(argc, argv);
#endif

	lwsl_user("Completed: %s\n", e ? "FAIL" : "PASS");

	return e;
}
