/*
 * lws-api-test-http-cookie-jar
 *
 * The client cookie jar (info->http_nsc_filepath + LCCSCF_CACHE_COOKIES) end
 * to end: a server vhost in the same context sets a batch of cookies on
 * /set, and echoes back the Cookie: header each later request arrived with.
 * The client connects to 127.0.0.1 every time, but names a different host
 * in its connect info, so the jar sees requests to several sites.
 *
 * What is being fenced is the RFC 6265 scoping the jar applies to what a
 * server may set:
 *
 *  - a Domain= that does not domain-match the request host is ignored
 *  - a Domain= that does (with or without a leading dot, in any case) makes
 *    the cookie go to that domain and its subdomains
 *  - a Domain= that is a single label (a TLD) is ignored
 *  - a cookie with no Domain= is host-only: not sent to sibling hosts
 *  - a cookie name that is not an RFC 6265 token is ignored
 *  - a Secure cookie is not accepted over plaintext
 *  - a cookie with no Path= gets the default-path of the request that set it
 *    ("/" for "/set"), and a Path= scopes the cookie to that path and below
 *
 * This file is made available under the Creative Commons CC0 1.0 Universal
 * Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_timeout, sul_next;
static int port = 7700, cur = -1, done, fail;

/*
 * What the server sets on /set, whoever asks.  The request doing it is to
 * a.example.com over plaintext.
 */
static const char * const set_cookies[] = {
	"host1=a; Path=/",				/* host-only */
	"dom1=b; Domain=example.com; Path=/",		/* parent domain */
	"dotdom=c; Domain=.example.com; Path=/",	/* leading dot */
	"upper=d; Domain=Example.COM; Path=/",		/* case */
	"other=e; Domain=other.example; Path=/",	/* not ours: ignored */
	"tld=f; Domain=com; Path=/",			/* TLD: ignored */
	"st*r=g; Path=/",				/* not a token: ignored */
	"sec=h; Secure; Path=/",			/* plaintext: ignored */
	"deep=i; Path=/deeper",				/* path scoped */
	"defpath=j",					/* default-path "/" */
};

static const struct step {
	const char	*host;
	const char	*path;
	const char	*want; /* space-separated cookies, NULL for /set */
} steps[] = {
	{ "a.example.com",	"/set",		NULL },
	{ "a.example.com",	"/get",
		"host1=a dom1=b dotdom=c upper=d defpath=j" },
	/* the host-only cookies stay with a.example.com */
	{ "b.example.com",	"/get",		"dom1=b dotdom=c upper=d" },
	/* and so do the Domain= ones: example.com is not other.example */
	{ "other.example",	"/get",		"" },
	/* the Domain= cookies go to the domain itself too */
	{ "example.com",	"/get",		"dom1=b dotdom=c upper=d" },
	/* the Path=/deeper one joins in at and below /deeper */
	{ "a.example.com",	"/deeper/get",
		"host1=a dom1=b dotdom=c upper=d defpath=j deep=i" },
	{ "b.example.com",	"/deeper/get",
		"dom1=b dotdom=c upper=d" },
};

/* ------------------------------------------------------------- server */

struct pss_srv {
	char	body[512];
	size_t	body_len;
};

static int
callback_jar_srv(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t buf[LWS_PRE + 1024], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	int n, is_set;
	size_t m;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		is_set = !strcmp((const char *)in, "/set");

		/* the body is the Cookie: header the request came with */
		m = (size_t)lws_snprintf(pss->body, sizeof(pss->body),
					 "cookies:");
		n = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COOKIE);
		if (n > 0 && lws_hdr_copy(wsi, pss->body + m,
					  (int)(sizeof(pss->body) - m),
					  WSI_TOKEN_HTTP_COOKIE) < 0)
			return 1;
		pss->body_len = strlen(pss->body);

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain", pss->body_len,
						&p, end))
			return 1;

		if (is_set)
			for (m = 0; m < LWS_ARRAY_SIZE(set_cookies); m++)
				if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_SET_COOKIE,
					(const uint8_t *)set_cookies[m],
					(int)strlen(set_cookies[m]), &p, end))
					return 1;

		if (lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		lws_callback_on_writable(wsi);

		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss || !pss->body_len)
			return 0;

		memcpy(start, pss->body, pss->body_len);
		if (lws_write(wsi, start, pss->body_len,
			      LWS_WRITE_HTTP_FINAL) != (int)pss->body_len)
			return 1;
		pss->body_len = 0;

		if (lws_http_transaction_completed(wsi))
			return -1;

		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* ------------------------------------------------------------- client */

static char rx[512];
static size_t rx_len;
static int step_finished;

/* is the cookie "want" (want_len bytes) one of the "; "-separated in got? */
static int
has_cookie(const char *got, const char *want, size_t want_len)
{
	const char *e;
	size_t l;

	while (*got) {
		while (*got == ' ' || *got == ';')
			got++;
		e = strchr(got, ';');
		l = e ? (size_t)(e - got) : strlen(got);
		if (l == want_len && !strncmp(got, want, l))
			return 1;
		got += l;
	}

	return 0;
}

static int
count_cookies(const char *s)
{
	int n = 0;

	while (*s) {
		while (*s == ' ' || *s == ';')
			s++;
		if (!*s)
			break;
		n++;
		while (*s && *s != ';')
			s++;
	}

	return n;
}

static void
next_step(lws_sorted_usec_list_t *sul);

static void
step_finish(int completed)
{
	const struct step *s = &steps[cur];
	const char *got, *w, *e;
	int ok = 1, n = 0;
	size_t l;

	if (step_finished)
		return;
	step_finished = 1;

	rx[rx_len] = '\0';
	got = rx;

	if (!completed || strncmp(got, "cookies:", 8)) {
		lwsl_err("%s: step %d: no proper response\n", __func__, cur);
		ok = 0;
	} else if (s->want) {
		got += 8;

		for (w = s->want; *w; w = e) {
			while (*w == ' ')
				w++;
			if (!*w)
				break;
			e = strchr(w, ' ');
			if (!e)
				e = w + strlen(w);
			l = (size_t)(e - w);
			n++;
			if (!has_cookie(got, w, l)) {
				lwsl_err("%s: step %d: missing %.*s\n",
					 __func__, cur, (int)l, w);
				ok = 0;
			}
		}

		if (count_cookies(got) != n) {
			lwsl_err("%s: step %d: sent %d cookies, want %d\n",
				 __func__, cur, count_cookies(got), n);
			ok = 0;
		}
	}

	lwsl_user("%s: step %d: %s%s: '%s': %s\n", __func__, cur, s->host,
		  s->path, got, ok ? "PASS" : "FAIL");
	if (!ok)
		fail++;

	lws_sul_schedule(context, 0, &sul_next, next_step, LWS_US_PER_MS);
}

/* only the connection of the current step may conclude it */
static int
is_current(struct lws *wsi)
{
	return wsi && (intptr_t)lws_get_opaque_user_data(wsi) == cur + 1;
}

static int
callback_jar_cli(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP: {
		char b[1024 + LWS_PRE], *px = b + LWS_PRE;
		int lenx = (int)sizeof(b) - LWS_PRE;

		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (!is_current(wsi))
			break;
		if (len > sizeof(rx) - 1 - rx_len) {
			lwsl_err("%s: response too large\n", __func__);
			return -1;
		}
		memcpy(rx + rx_len, in, len);
		rx_len += len;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (!is_current(wsi))
			break;
		step_finish(lws_http_client_http_response(wsi) ==
							HTTP_STATUS_OK);
		/* one request per connection */
		return -1;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (is_current(wsi))
			step_finish(0);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{ "jar-srv", callback_jar_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	{ "jar-cli", callback_jar_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_http_mount mount = {
	.mountpoint		= "/",
	.origin			= "jar-srv",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 1,
};

static void
next_step(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	if (++cur >= (int)LWS_ARRAY_SIZE(steps)) {
		done = 1;
		lws_cancel_service(context);
		return;
	}

	rx_len = 0;
	step_finished = 0;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= "127.0.0.1";
	i.port			= port;
	i.path			= steps[cur].path;
	/* the site the jar thinks it is talking to */
	i.host			= steps[cur].host;
	i.origin		= steps[cur].host;
	i.method		= "GET";
	i.protocol		= "jar-cli";
	i.local_protocol_name	= "jar-cli";
	i.alpn			= "http/1.1";
	i.ssl_connection	= LCCSCF_CACHE_COOKIES;
	i.opaque_user_data	= (void *)(intptr_t)(cur + 1);

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		fail++;
		done = 1;
		lws_cancel_service(context);
	}
}

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out at step %d\n", __func__, cur);
	fail++;
	done = 1;
	lws_cancel_service(context);
}

static void
sigint_handler(int sig)
{
	done = 1;
	fail++;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p, *jar = "./cookie-jar-test.txt";
	int n = 0;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--jar")))
		jar = p;

	lwsl_user("LWS API selftest: http cookie jar scoping\n");

	/* start from an empty jar */
	unlink(jar);

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	/* the server and client wsi, plus lws' own */
	info.fd_limit_per_thread = 0;
	info.http_nsc_filepath = jar;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.vhost_name		= "srv";
	info.port		= port;
	info.protocols		= protocols;
	info.mounts		= &mount;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("server vhost creation failed\n");
		fail++;
		goto bail;
	}

	info.vhost_name		= "cli";
	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.mounts		= NULL;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("client vhost creation failed\n");
		fail++;
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 20 * LWS_US_PER_SEC);
	lws_sul_schedule(context, 0, &sul_next, next_step, 1);

	while (n >= 0 && !done)
		n = lws_service(context, 0);

	lws_sul_cancel(&sul_timeout);
	lws_sul_cancel(&sul_next);

	if (!fail && cur != (int)LWS_ARRAY_SIZE(steps)) {
		lwsl_err("stopped at step %d\n", cur);
		fail++;
	}

bail:
	lws_context_destroy(context);
	unlink(jar);

	lwsl_user("Completed: %s\n", fail ? "FAIL" : "PASS");

	return !!fail;
}
