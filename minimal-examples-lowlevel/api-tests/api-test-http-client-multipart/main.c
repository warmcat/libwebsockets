/*
 * lws-api-test-http-client-multipart
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Exercises the client multipart form helpers, lws_http_mp_sm_*() and
 * lws_client_http_multipart(), against a raw socket server in the same
 * context that records exactly what arrives on the connection.
 *
 * For a POST that should go out, the body that arrives after the request
 * headers must be exactly the Content-Length the headers declared: not one
 * byte more, which an h1 server would read as the start of the next request
 * on the connection, and not one byte less.  The forms include values longer
 * than the client's write buffer, and a file part.
 *
 * Forms the helper can't send as declared must fail, without sending more
 * than was declared and without hanging: an element too long for the
 * element buffer, an element with no '=', a file that is truncated or grows
 * between the Content-Length being computed and the file being sent.
 *
 * The test fails if a case does not complete inside the watchdog period.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#if defined(WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

#define CASE_TIMEOUT_S	20
#define SETTLE_MS	250
#define SRV_RX_MAX	(64 * 1024)

enum {
	EXP_SENT,		/* the whole body goes, exactly as declared */
	EXP_REFUSED,		/* lws_http_mp_sm_init() refuses the form */
	EXP_FILL_FAILS,		/* lws_http_mp_sm_fill() fails partway */
};

enum {
	MUT_NONE,
	MUT_TRUNCATE_EARLY,	/* the file shrinks before it is opened */
	MUT_GROW_EARLY,		/* the file grows before it is opened */
	MUT_TRUNCATE_LATE,	/* the file shrinks while it is being sent */
	MUT_GROW_LATE,		/* the file grows while it is being sent */
};

#define MAX_ELEMS 6

struct mcase {
	const char	*name;
	const char	*elems[MAX_ELEMS]; /* form elements, NULL terminated */
	int		mutate;
	int		expect;
};

/* runtime strings the cases refer to */

static char v300[2 + 300 + 1], v4092[2 + 4092 + 1], v5000[2 + 5000 + 1],
	    el_file[512], el_file_mut[512], path_file[480], path_file_mut[480];

#define V300		((const char *)1)
#define V4092		((const char *)2)
#define V5000		((const char *)3)
#define EL_FILE		((const char *)4)
#define EL_FILE_MUT	((const char *)5)

static const struct mcase cases[] = {
	{ "short fields and a file",
		{ "a=1", "b=two", EL_FILE, NULL },		MUT_NONE, EXP_SENT },
	{ "file truncated while it is being sent",
		{ "a=1", EL_FILE_MUT, NULL },	MUT_TRUNCATE_LATE, EXP_FILL_FAILS },
	{ "file grown while it is being sent",
		{ "a=1", EL_FILE_MUT, NULL },	MUT_GROW_LATE, EXP_SENT },
	{ "values longer than the write buffer, the longest element that fits",
		{ "s=x", V300, V4092, EL_FILE, "e=", NULL },	MUT_NONE, EXP_SENT },
	{ "element too long for the element buffer",
		{ "a=1", V5000, NULL },			MUT_NONE, EXP_REFUSED },
	{ "element without '='",
		{ "a=1", "noeq", NULL },		MUT_NONE, EXP_REFUSED },
	{ "file truncated after it was sized, before it is opened",
		{ "a=1", EL_FILE_MUT, "b=2", NULL },
						MUT_TRUNCATE_EARLY, EXP_FILL_FAILS },
	{ "file grown after it was sized, before it is opened",
		{ "a=1", EL_FILE_MUT, "b=2", NULL },
						MUT_GROW_EARLY, EXP_FILL_FAILS },
};

static const char *
resolve(const char *e)
{
	switch ((uintptr_t)e) {
	case 1: return v300;
	case 2: return v4092;
	case 3: return v5000;
	case 4: return el_file;
	case 5: return el_file_mut;
	}

	return e;
}

/* client side view of the current case */

static struct {
	struct lws	*wsi;
	uint64_t	body_sent;
	int		refused;	/* lws_http_mp_sm_init() said NULL */
	int		fill_failed;	/* lws_http_mp_sm_fill() said < 0 */
	int		fill_done;	/* lws_http_mp_sm_fill() said 0 */
	int		pass;		/* times the form cb was restarted */
	int		elem;		/* next element for the form cb */
	int		fills;		/* lws_http_mp_sm_fill() calls */
} cli;

struct pss_cli {
	struct lws_http_mp_sm	*hmp;
	int			case_idx;
};

/* server side view of the current case */

static struct {
	char		rx[SRV_RX_MAX + 1];
	size_t		rx_len;
	int		overflow;
} srv;

struct pss_srv {
	int		case_idx;
};

static struct lws_context *context;
static lws_sorted_usec_list_t sul_next, sul_watchdog, sul_settle;
static int result, cur = -1, failures, port = 7690, case_done, settling;
static const char *server = "localhost";

static void next_case(lws_sorted_usec_list_t *sul);

static int
write_file(const char *path, size_t len, int append)
{
	char buf[256];
	size_t n, w;
	int fd;

	fd = lws_open(path, LWS_O_WRONLY | LWS_O_CREAT |
			    (append ? O_APPEND : LWS_O_TRUNC), 0600);
	if (fd < 0) {
		lwsl_err("%s: can't open %s\n", __func__, path);
		return 1;
	}

	memset(buf, 'F', sizeof(buf));
	while (len) {
		w = len > sizeof(buf) ? sizeof(buf) : len;
		n = (size_t)write(fd, buf, LWS_POSIX_LENGTH_CAST(w));
		if (n != w) {
			close(fd);
			return 1;
		}
		len -= w;
	}

	close(fd);

	return 0;
}

static int
mutate(int early)
{
	switch (cases[cur].mutate) {
	case MUT_TRUNCATE_EARLY:
		return early ? write_file(path_file_mut, 10, 0) : 0;
	case MUT_GROW_EARLY:
		return early ? write_file(path_file_mut, 1000, 1) : 0;
	case MUT_TRUNCATE_LATE:
		return early ? 0 : write_file(path_file_mut, 10, 0);
	case MUT_GROW_LATE:
		return early ? 0 : write_file(path_file_mut, 1000, 1);
	}

	return 0;
}

static void
case_finish(int pass, const char *why)
{
	if (case_done)
		return;
	case_done = 1;
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_settle);

	lwsl_user("--- case %d: %s: %s%s%s ---\n", cur, cases[cur].name,
		  pass ? "PASS" : "FAIL", why ? ": " : "", why ? why : "");
	if (!pass)
		failures++;

	/* a client still waiting for a response is no further use */
	if (cli.wsi)
		lws_set_timeout(cli.wsi, PENDING_TIMEOUT_USER_OK,
				LWS_TO_KILL_ASYNC);

	lws_sul_schedule(context, 0, &sul_next, next_case,
			 100 * LWS_US_PER_MS);
}

/*
 * The request head is up to the first CRLFCRLF: find where the body starts
 * and what Content-Length the head declared
 */

static int
parse_head(size_t *body_ofs, uint64_t *cl)
{
	const char *p = srv.rx, *end, *eol;
	static const char cl_name[] = "content-length:";
	int have = 0;

	srv.rx[srv.rx_len] = '\0';
	end = strstr(srv.rx, "\r\n\r\n");
	if (!end)
		return 1;
	*body_ofs = lws_ptr_diff_size_t(end, srv.rx) + 4;

	while (p < end) {
		eol = strstr(p, "\r\n");
		if (!eol)
			break;
		if (lws_ptr_diff_size_t(eol, p) > sizeof(cl_name) - 1 &&
		    !strncasecmp(p, cl_name, sizeof(cl_name) - 1)) {
			p += sizeof(cl_name) - 1;
			while (*p == ' ')
				p++;
			*cl = 0;
			while (p < eol && *p >= '0' && *p <= '9' &&
			       *cl < 0xffffffffffull)
				*cl = (*cl * 10) + (uint64_t)(*p++ - '0');
			have = p == eol;
		}
		p = eol + 2;
	}

	return !have;
}

static void
settle_cb(lws_sorted_usec_list_t *sul)
{
	const struct mcase *c = &cases[cur];
	size_t body_ofs, body_rx;
	uint64_t cl = 0;

	if (srv.overflow) {
		case_finish(0, "server rx buffer overflowed");
		return;
	}

	switch (c->expect) {
	case EXP_REFUSED:
		if (!cli.refused) {
			case_finish(0, "the form was not refused");
			return;
		}
		if (srv.rx_len) {
			case_finish(0, "a refused form sent something");
			return;
		}
		case_finish(1, NULL);
		return;

	case EXP_FILL_FAILS:
	case EXP_SENT:
		if (cli.refused) {
			case_finish(0, "the form was refused");
			return;
		}
		if (parse_head(&body_ofs, &cl)) {
			case_finish(0, "no request head with a Content-Length");
			return;
		}
		body_rx = srv.rx_len - body_ofs;
		lwsl_user("%s: declared %llu, client sent %llu, server got %llu\n",
			  __func__, (unsigned long long)cl,
			  (unsigned long long)cli.body_sent,
			  (unsigned long long)body_rx);

		if (body_rx > cl) {
			/* the server reads these as the next request */
			case_finish(0, "more body than Content-Length declared");
			return;
		}

		if (c->expect == EXP_FILL_FAILS) {
			if (!cli.fill_failed) {
				case_finish(0, "the fill did not fail");
				return;
			}
			case_finish(1, NULL);
			return;
		}

		if (!cli.fill_done) {
			case_finish(0, "the fill did not complete");
			return;
		}
		if (body_rx != cl || cli.body_sent != cl) {
			case_finish(0, "body length is not Content-Length");
			return;
		}
		break;
	}

	case_finish(1, NULL);
}

/* the client is done one way or another: let the server see the rest */

static void
settle(void)
{
	if (settling || case_done)
		return;
	settling = 1;
	lws_sul_schedule(context, 0, &sul_settle, settle_cb,
			 SETTLE_MS * LWS_US_PER_MS);
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("case %d: watchdog: sent %llu, server got %u\n", cur,
		 (unsigned long long)cli.body_sent, (unsigned int)srv.rx_len);
	case_finish(0, "timed out");
}

/* ---- server side: keep everything that arrives ---- */

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		pss->case_idx = cur;
		break;

	case LWS_CALLBACK_RAW_RX:
		if (pss->case_idx != cur || case_done)
			break;
		if (len > SRV_RX_MAX - srv.rx_len) {
			srv.overflow = 1;
			break;
		}
		memcpy(srv.rx + srv.rx_len, in, len);
		srv.rx_len += len;
		break;

	default:
		break;
	}

	return 0;
}

/* ---- client side ---- */

/*
 * The form callback, the way apps write it: copy the next element into ft,
 * truncating it if it doesn't fit
 */

static int
form_cb(struct lws_context *cx, char *ft, size_t ft_len, const char **last)
{
	const struct mcase *c = &cases[cur];
	const char *e;

	if (!*last) {
		/* starting the form again: the init pass, then the fill */
		cli.pass++;
		cli.elem = 0;
	}

	if (cli.elem >= MAX_ELEMS || !c->elems[cli.elem])
		return 1; /* no more */

	e = resolve(c->elems[cli.elem++]);
	*last = e;

	/* the file changes after the init pass sized it, before it's opened */
	if (cli.pass == 2 && e == el_file_mut && mutate(1))
		return -1;

	lws_strnncpy(ft, e, strlen(e), ft_len);

	return 0;
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_cli *pss = (struct pss_cli *)user;
	uint8_t buf[LWS_PRE + 1024], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	int n;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: connection error: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		if (cli.wsi == wsi)
			cli.wsi = NULL;
		settle();
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (pss)
			lws_http_mp_sm_destroy(&pss->hmp);
		if (cli.wsi == wsi) {
			cli.wsi = NULL;
			settle();
		}
		break;

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
	{
		uint8_t **pin = (uint8_t **)in, *endin = (*pin) + len;

		pss->case_idx = cur;
		pss->hmp = lws_http_mp_sm_init(wsi, form_cb, pin, endin);
		if (!pss->hmp) {
			cli.refused = 1;
			settle();
			return -1;
		}

		lws_client_http_body_pending(wsi, 1);
		lws_callback_on_writable(wsi);
		break;
	}

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (!pss->hmp || pss->case_idx != cur)
			return 0;

		/*
		 * The first fill opened the file and sent the start of it:
		 * the file changes under the open fd
		 */
		if (cli.fills++ == 1 && mutate(0))
			return -1;

		n = lws_http_mp_sm_fill(pss->hmp, &p, end);
		if (n < 0) {
			lwsl_user("%s: fill failed\n", __func__);
			cli.fill_failed = 1;
			settle();
			return -1;
		}

		if (!n) {
			lws_client_http_body_pending(wsi, 0);
			lws_http_mp_sm_destroy(&pss->hmp);
		}

		if (lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
			      n ? LWS_WRITE_HTTP : LWS_WRITE_HTTP_FINAL) !=
						(int)lws_ptr_diff_size_t(p, start))
			return -1;

		cli.body_sent += lws_ptr_diff_size_t(p, start);

		if (n)
			lws_callback_on_writable(wsi);
		else {
			cli.fill_done = 1;
			settle();
		}

		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	const struct mcase *c;

	cur++;
	if (cur >= (int)LWS_ARRAY_SIZE(cases)) {
		result = !!failures;
		lwsl_user("Completed: %s (%d of %d cases failed)\n",
			  failures ? "FAIL" : "PASS", failures,
			  (int)LWS_ARRAY_SIZE(cases));
		lws_default_loop_exit(context);
		return;
	}

	c = &cases[cur];
	case_done = 0;
	settling = 0;
	memset(&cli, 0, sizeof(cli));
	srv.rx_len = 0;
	srv.overflow = 0;

	lwsl_user("=== case %d: %s ===\n", cur, c->name);

	if (c->mutate != MUT_NONE && write_file(path_file_mut, 3000, 0)) {
		case_finish(0, "could not create the file");
		return;
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 CASE_TIMEOUT_S * LWS_US_PER_SEC);

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.address		= server;
	i.host			= i.address;
	i.port			= port;
	i.path			= "/form";
	i.method		= "POST";
	i.protocol		= "mp-cli";
	i.pwsi			= &cli.wsi;

	if (!lws_client_connect_via_info(&i))
		case_finish(0, "could not start connection");
}

static const struct lws_protocols protocols[] = {
	{ "mp-srv", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	{ "mp-cli", callback_cli, sizeof(struct pss_cli), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p, *tmpdir = ".";

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server = p;
	if ((p = lws_cmdline_option(argc, argv, "--tmpdir")))
		tmpdir = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: client multipart form helpers\n");

	/* "x=" and a value of the length in the name */
	memcpy(v300, "l=", 2);
	memset(v300 + 2, 'L', sizeof(v300) - 3);
	memcpy(v4092, "m=", 2);
	memset(v4092 + 2, 'M', sizeof(v4092) - 3);
	memcpy(v5000, "t=", 2);
	memset(v5000 + 2, 'T', sizeof(v5000) - 3);

	lws_snprintf(path_file, sizeof(path_file), "%s/lws-mp-leaf.txt",
		     tmpdir);
	lws_snprintf(el_file, sizeof(el_file), "f=@%s", path_file);
	lws_snprintf(path_file_mut, sizeof(path_file_mut),
		     "%s/lws-mp-mutable.txt", tmpdir);
	lws_snprintf(el_file_mut, sizeof(el_file_mut), "f=@%s", path_file_mut);

	if (write_file(path_file, 2000, 0))
		return 1;

	info.port = port;
	info.protocols = protocols;
	info.options = LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = "raw-skt";
	info.listen_accept_protocol = "mp-srv";

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	result = 1;
	lws_sul_schedule(context, 0, &sul_next, next_case, 1);

	lws_context_default_loop_run_destroy(context);

	unlink(path_file);
	unlink(path_file_mut);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
