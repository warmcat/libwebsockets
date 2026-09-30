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
 * empty page, which on h1 must still be a whole chunked body.  Run it with
 * the test directory as the cwd.
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
};

static const struct xcase cases[] = {
	{ XP_H1, "/page.html", 0 },
	{ XP_H1, "/empty.html", 1 },
#if defined(LWS_WITH_HTTP2)
	{ XP_H2C, "/page.html", 0 },
	{ XP_H2C, "/empty.html", 1 },
#endif
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static int result = 1, cur = -1, port_h1 = 7681, port_h2c = 7682;
static const char *server_addr = "127.0.0.1";

static struct {
	char		body[PAGE_UNITS * sizeof(PAGE_UNIT)];
	size_t		body_len;
	int		status;
	int		done;
} cli;

/* the interpreter: the state is the interpreted request's own */

static int
callback_interp(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	struct lws_process_html_state *s =
				(struct lws_process_html_state *)user;

	switch (reason) {
	case LWS_CALLBACK_PROCESS_HTML:
		if (!s->vars) {
			s->vars = vars;
			s->count_vars = (int)LWS_ARRAY_SIZE(vars);
			s->replace = replace;
		}

		return lws_chunked_html_process(
				(struct lws_process_html_args *)in, s) ? -1 : 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocol_vhost_options interpret = {
	NULL, NULL, ".html", "interp"
};

static const struct lws_http_mount mount = {
	.mountpoint		= "/",
	.origin			= "./docroot",
	.def			= "page.html",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 1,
	.interpret		= &interpret,
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

static const struct lws_protocols protocols_srv[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	{ "interp", callback_interp, sizeof(struct lws_process_html_state),
	  0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	const struct xcase *c;

	if (++cur == (int)LWS_ARRAY_SIZE(cases)) {
		result = 0;
		lws_default_loop_exit(context);
		return;
	}
	c = &cases[cur];
	memset(&cli, 0, sizeof(cli));

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
