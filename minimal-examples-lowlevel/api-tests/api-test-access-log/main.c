/*
 * lws-api-test-access-log
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The access log is one line per request, whatever the peer sends.  A raw
 * client sends GETs to an http vhost writing an access log, each on its own
 * connection, with Referer and User-Agent headers of many lengths (every
 * length around where the line fills up), much too long ones, ones with a
 * quote and control characters in them, ones ending in a backslash, ones
 * with bytes above 0x7f (UTF-8 and a raw C1 CSI), and a much too long URI.
 * After the context is gone, every line of the log must:
 *
 *  - end with a newline, with nothing but printable ASCII in it, so that it
 *    can never run into the next line or reach a terminal as a control,
 *
 *  - have exactly the six quotes of the request, referrer and user agent
 *    fields, with a host field that has no spaces, and in those fields
 *    every backslash starting an escape, \\ or \xhh, so that a reader
 *    honouring escapes (as Apache's format has them) finds the same fields,
 *
 *  - have the request, referrer and user agent the client sent, with any
 *    quote or C0 control in them replaced, any backslash, DEL or byte above
 *    it escaped, and cut short, never inside an escape, only when the line
 *    could not hold them.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>

#define AL_SWEEP_REF		400	/* referrer while the UA length sweeps */
#define AL_SWEEP_MAX		700	/* the UA lengths swept, from 1 */
#define AL_LONG			1500	/* referrer and UA both too long */
#define AL_LONG_URI		300	/* a URI too long to log whole */
#define AL_FITS			800	/* referrer + UA always logged whole */
#define AL_FAIR			200	/* what each keeps when both are cut */
#define AL_TX			(AL_LONG * 2 + AL_LONG_URI + 256)

typedef struct al_case {
	const char	*what;
	char		*uri;
	char		*ref;
	char		*ua;
} al_case_t;

static struct lws_context *cx;
static struct lws_vhost *vh_cli, *vh_srv;
static lws_sorted_usec_list_t sul_next;
static const char *server = "localhost", *alog;
static al_case_t *cases;
static int case_count, case_idx = -1, fails, finished, answered;

static void
al_next(lws_sorted_usec_list_t *sul);

static void
check(int ok, int idx, const char *what)
{
	if (ok)
		return;

	lwsl_err("  FAIL: case %d (%s): %s\n", idx,
		 idx >= 0 && idx < case_count ? cases[idx].what : "-", what);
	fails++;
}

/* a string of len bytes of pattern, repeated */
static char *
al_str(size_t len, const char *pattern)
{
	size_t pl = strlen(pattern), n;
	char *s = malloc(len + 1);

	if (!s)
		return NULL;

	for (n = 0; n < len; n++)
		s[n] = pattern[n % pl];
	s[len] = '\0';

	return s;
}

static int
al_case_add(const char *what, const char *uri, char *ref, char *ua)
{
	al_case_t *c = &cases[case_count];

	c->what	= what;
	c->uri	= al_str(strlen(uri), uri);
	c->ref	= ref;
	c->ua	= ua;
	if (!c->uri || !c->ref || !c->ua) {
		free(c->uri);
		free(c->ref);
		free(c->ua);
		return 1;
	}

	case_count++;

	return 0;
}

static int
al_cases(void)
{
	char *uri;
	int n;

	cases = calloc(AL_SWEEP_MAX + 16, sizeof(*cases));
	if (!cases)
		return 1;

	/* every length from short to past where the line fills up */
	for (n = 1; n <= AL_SWEEP_MAX; n++)
		if (al_case_add("sweep", "/", al_str(AL_SWEEP_REF, "r"),
				al_str((size_t)n, "u")))
			return 1;

	if (al_case_add("both too long", "/", al_str(AL_LONG, "r"),
			al_str(AL_LONG, "u")) ||
	    al_case_add("referrer too long", "/", al_str(AL_LONG * 2, "r"),
			al_str(20, "u")) ||
	    al_case_add("user agent too long", "/", al_str(20, "r"),
			al_str(AL_LONG * 2, "u")) ||
	    al_case_add("empty", "/", al_str(0, "r"), al_str(0, "u")) ||
	    /* a quote, a tab and DEL may be in a header value */
	    al_case_add("quotes and controls", "/",
			al_str(16, "a\"b\tc\x7f"), al_str(16, "x\"y\t\x7fz")) ||
	    /* a reader honouring escapes must still find the closing quotes */
	    al_case_add("trailing backslash", "/b\\", al_str(2, "x\\"),
			al_str(1, "\\")) ||
	    /* UTF-8 U+009B (CSI), and a raw 8-bit CSI */
	    al_case_add("high bytes", "/\xc3\xa9\x9b",
			al_str(5, "\xc2\x9b" "31m"), al_str(5, "\x9b[2J\x7f")) ||
	    /* escaped, both are much too long: the cut is between escapes */
	    al_case_add("escapes too long", "/", al_str(AL_LONG, "\x9b"),
			al_str(AL_LONG, "a\\")))
		return 1;

	uri = al_str(AL_LONG_URI, "/\xe9");
	if (!uri)
		return 1;
	n = al_case_add("long escaped uri", uri, al_str(40, "r"),
			al_str(40, "u"));
	free(uri);
	if (n)
		return 1;

	uri = al_str(AL_LONG_URI, "/abcdefgh");
	if (!uri)
		return 1;
	n = al_case_add("long uri", uri, al_str(40, "r"), al_str(40, "u"));
	free(uri);

	return n;
}

/*
 * What the log has for a peer's text, as much of it as fits in max bytes,
 * never part of an escape: quotes and C0 controls replaced, a backslash
 * doubled and DEL and above as \xhh
 */
static char *
al_escaped(const char *s, size_t max)
{
	static const char hex[] = "0123456789abcdef";
	char *e = malloc(strlen(s) * 4 + 1);
	size_t n = 0, el;
	unsigned char c;

	if (!e)
		return NULL;

	for (; *s; s++) {
		c = (unsigned char)*s;
		el = c == '\\' ? 2 : (c >= 0x7f ? 4 : 1);
		if (n + el > max)
			break;
		if (el == 1)
			e[n] = c == '\"' ? '\'' : (c < 0x20 ? '_' : (char)c);
		else if (el == 2) {
			e[n] = '\\';
			e[n + 1] = '\\';
		} else {
			e[n] = '\\';
			e[n + 1] = 'x';
			e[n + 2] = hex[c >> 4];
			e[n + 3] = hex[c & 15];
		}
		n += el;
	}
	e[n] = '\0';

	return e;
}

static int
al_is_hex(char c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

static int
al_srv_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	  void *in, size_t len)
{
	uint8_t hb[LWS_PRE + 256], *start = &hb[LWS_PRE], *p = start,
		*end = &hb[sizeof(hb) - 1];

	if (reason == LWS_CALLBACK_HTTP) {
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain", 0, &p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		return lws_http_transaction_completed(wsi) ? -1 : 0;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
al_case_end(void)
{
	lws_sul_schedule(cx, 0, &sul_next, al_next, 1);
}

/* the client: a raw connection sending one GET */

static int
al_cli_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	  void *in, size_t len)
{
	int idx = (int)(intptr_t)lws_get_opaque_user_data(wsi) - 1;
	al_case_t *c;
	uint8_t *tx;
	int n;

	(void)user;

	if (idx != case_idx)
		return 0;
	c = &cases[idx];

	switch (reason) {
	case LWS_CALLBACK_RAW_CONNECTED:
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		tx = malloc(LWS_PRE + AL_TX);
		if (!tx)
			return -1;
		n = lws_snprintf((char *)tx + LWS_PRE, AL_TX,
				 "GET %s HTTP/1.1\x0d\x0aHost: al\x0d\x0a"
				 "Referer: %s\x0d\x0aUser-Agent: %s\x0d\x0a"
				 "\x0d\x0a", c->uri, c->ref, c->ua);
		n = lws_write(wsi, tx + LWS_PRE, (size_t)n, LWS_WRITE_RAW) != n;
		free(tx);
		if (n)
			return -1;
		break;

	case LWS_CALLBACK_RAW_RX:
		check(len >= 12 && !strncmp((const char *)in, "HTTP/1.1 200", 12),
		      idx, "answered 200");
		answered++;
		/* the next case starts from the close */
		return -1;

	case LWS_CALLBACK_RAW_CLOSE:
		al_case_end();
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		check(0, idx, in ? (const char *)in : "connection error");
		al_case_end();
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols al_srv_protocols[] = {
	{ "http", al_srv_cb, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols al_cli_protocols[] = {
	{ "al-cli", al_cli_cb, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
al_next(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	(void)sul;

	if (++case_idx == case_count) {
		finished = 1;
		lws_cancel_service(cx);
		return;
	}

	memset(&i, 0, sizeof(i));
	i.context		= cx;
	i.vhost			= vh_cli;
	i.address		= server;
	i.host			= server;
	i.port			= lws_get_vhost_listen_port(vh_srv);
	i.method		= "RAW";
	i.protocol		= al_cli_protocols[0].name;
	i.local_protocol_name	= al_cli_protocols[0].name;
	i.opaque_user_data	= (void *)(intptr_t)(case_idx + 1);

	if (!lws_client_connect_via_info(&i)) {
		check(0, case_idx, "connect failed");
		al_case_end();
	}
}

/*
 * Field f ("..." from p) is a prefix of the sanitized exp, or all of it when
 * whole is set.  Returns the end of the field (its closing quote), or NULL.
 */
static const char *
al_field(const char *p, const char *eol, const char *exp, int whole,
	  size_t *got, int idx, const char *what)
{
	const char *q;

	if (*p != '\"') {
		check(0, idx, what);
		return NULL;
	}
	p++;
	q = memchr(p, '\"', lws_ptr_diff_size_t(eol, p));
	if (!q) {
		check(0, idx, what);
		return NULL;
	}

	*got = lws_ptr_diff_size_t(q, p);
	check(*got <= strlen(exp) && !strncmp(p, exp, *got) &&
	      (!whole || *got == strlen(exp)), idx, what);

	/* as a reader honouring escapes sees it: whole escapes only */
	while (p < q) {
		if (*p++ != '\\')
			continue;
		if (p < q && *p == '\\')
			p++;
		else if (q - p >= 3 && p[0] == 'x' && al_is_hex(p[1]) &&
			 al_is_hex(p[2]))
			p += 3;
		else {
			check(0, idx, "a backslash that starts no escape");
			return NULL;
		}
	}

	return q + 1;
}

static void
al_check_line(int idx, const char *p, const char *eol)
{
	al_case_t *c = &cases[idx];
	char req[AL_LONG_URI * 4 + 32], *uri, *ref = NULL, *ua = NULL;
	size_t rl, ul, got_r = 0, got_u = 0;
	const char *sp;
	int quotes = 0, whole;

	for (sp = p; sp < eol; sp++) {
		if ((unsigned char)*sp < 0x20 || (unsigned char)*sp >= 0x7f) {
			check(0, idx, "nothing but printable ASCII in the line");
			return;
		}
		if (*sp == '\"')
			quotes++;
	}
	check(quotes == 6, idx, "six quotes");
	if (quotes != 6)
		return;

	/* the host field: one token, then the rest of the usual prefix */
	sp = memchr(p, ' ', lws_ptr_diff_size_t(eol, p));
	check(sp && sp != p && !strncmp(sp, " - - [", 6), idx,
	      "the host field is one token");
	if (!sp)
		return;
	sp = memchr(sp, ']', lws_ptr_diff_size_t(eol, sp));
	if (!sp || sp[1] != ' ') {
		check(0, idx, "the date field");
		return;
	}
	sp += 2;

	/* the request, the uri as much of it as the log keeps */
	uri = al_escaped(c->uri, 255);
	if (!uri) {
		check(0, idx, "OOM");
		return;
	}
	lws_snprintf(req, sizeof(req), "GET %s HTTP/1.1", uri);
	free(uri);
	sp = al_field(sp, eol, req, 1, &got_r, idx, "the request, whole");
	if (!sp)
		return;

	/* the status, and the size of what was sent, the headers */
	if (strncmp(sp, " 200 ", 5) || sp[5] < '0' || sp[5] > '9') {
		check(0, idx, "status and size");
		return;
	}
	sp += 5;
	while (sp < eol && *sp >= '0' && *sp <= '9')
		sp++;
	if (*sp != ' ') {
		check(0, idx, "status and size");
		return;
	}
	sp++;

	ref = al_escaped(c->ref, (size_t)-1);
	ua = al_escaped(c->ua, (size_t)-1);
	if (!ref || !ua) {
		check(0, idx, "OOM");
		goto bail;
	}
	rl = strlen(ref);
	ul = strlen(ua);
	whole = rl + ul <= AL_FITS;

	sp = al_field(sp, eol, ref, whole, &got_r, idx, "the referrer");
	if (!sp)
		goto bail;
	if (*sp != ' ') {
		check(0, idx, "space after the referrer");
		goto bail;
	}
	sp = al_field(sp + 1, eol, ua, whole, &got_u, idx, "the user agent");
	if (!sp)
		goto bail;
	check(sp == eol, idx, "the user agent ends the line");

	/* when both are cut, each keeps a fair share */
	if (!whole)
		check((got_r == rl || got_r >= AL_FAIR) &&
		      (got_u == ul || got_u >= AL_FAIR), idx,
		      "both kept a fair share");

bail:
	free(ref);
	free(ua);
}

static void
al_check_log(void)
{
	size_t max = (size_t)case_count * 2048 + 1;
	char *log = malloc(max), *p, *eol;
	int n, lines = 0;

	if (!log) {
		check(0, -1, "OOM");
		return;
	}

	n = lws_plat_read_file(alog, log, max - 1);
	if (n <= 0) {
		check(0, -1, "the access log was written");
		free(log);
		return;
	}

	check(log[n - 1] == '\n', -1, "the log ends with a newline");
	check(!memchr(log, '\0', (size_t)n), -1, "no NUL in the log");
	log[n] = '\0';

	p = log;
	while (p < log + n) {
		eol = memchr(p, '\n', lws_ptr_diff_size_t(log + n, p));
		if (!eol)
			eol = log + n;
		if (lines < case_count)
			al_check_line(lines, p, eol);
		lines++;
		p = eol + 1;
	}

	if (lines != case_count) {
		lwsl_err("  FAIL: %d lines for %d requests\n", lines,
			 case_count);
		fails++;
	}

	free(log);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int m = 0, n;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server = p;
	alog = lws_cmdline_option(argc, argv, "--access-log");
	if (!alog) {
		lwsl_err("--access-log FILE is required\n");
		return 1;
	}
	/* only this run's lines in it */
	if (lws_plat_write_file(alog, (void *)"", 0)) {
		lwsl_err("can't truncate %s\n", alog);
		return 1;
	}

	lwsl_user("LWS API selftest: access log lines\n");

	if (al_cases()) {
		lwsl_err("OOM\n");
		fails++;
		goto out;
	}

	/* a server and a client in one process: don't budget fds */
	info.fd_limit_per_thread	= 0;
	info.options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	/* room for the longest headers we send */
	info.max_http_header_data	= 8192;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		fails++;
		goto out;
	}

	info.port		= 0;
	info.protocols		= al_srv_protocols;
	info.vhost_name		= "al-srv";
	info.log_filepath	= alog;
	vh_srv = lws_create_vhost(cx, &info);

	info.log_filepath	= NULL;
	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.protocols		= al_cli_protocols;
	info.vhost_name		= "al-cli";
	vh_cli = lws_create_vhost(cx, &info);

	if (!vh_srv || !vh_cli) {
		lwsl_err("vhost creation failed\n");
		fails++;
	} else {
		lws_sul_schedule(cx, 0, &sul_next, al_next, 1);

		while (m >= 0 && !finished)
			m = lws_service(cx, 0);

		if (!finished) {
			lwsl_err("service loop ended early\n");
			fails++;
		}
	}

	lws_sul_cancel(&sul_next);
	lws_context_destroy(cx);

	if (!fails) {
		if (answered != case_count) {
			lwsl_err("  FAIL: %d of %d requests answered\n",
				 answered, case_count);
			fails++;
		}
		/* the vhost flushed and closed it */
		al_check_log();
	}

out:
	for (n = 0; n < case_count; n++) {
		free(cases[n].uri);
		free(cases[n].ref);
		free(cases[n].ua);
	}
	free(cases);

	lwsl_user("Completed: %s (%d requests)\n", fails ? "FAIL" : "PASS",
		  case_count);

	return !!fails;
}
