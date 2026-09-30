/*
 * lws-api-test-http-cgi-stdin
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests the CGI stdin proxying path end-to-end at its boundary condition.
 *
 * A server vhost mounts a CGI script (cgi.sh next to this file, a small
 * POSIX sh script that counts the bytes arriving on its stdin and answers
 * with that count).  An h1 client POSTs a body sized in exact multiples of
 * the server's largest possible single h1 body read on the direct-read
 * path (pt_serv_buf_size - LWS_PRE bytes), so that body chunks are handed
 * to LWS_CALLBACK_CGI_STDIN_DATA ending exactly at the end of pt->serv_buf.
 *
 * This is the exact shaping of security audit finding F-001: the CGI stdin
 * handling in lws_callback_http_dummy() historically NUL-terminated
 * args->data[args->len] there, writing one byte past pt->serv_buf into the
 * same pt's fakewsi.  The regression guard here is that the CGI process
 * receives the complete body intact (exact byte count reported back) and
 * the http transaction completes normally with 200.
 *
 * With --chunked, the client sends the same body with Transfer-Encoding:
 * chunked instead of a Content-Length, one chunk per write: the server must
 * decode it, hand the CGI only the payload, and close the CGI's stdin at the
 * last-chunk so the script's read sees EOF.
 *
 * With --put, the same body goes as an h1 PUT; with --h2-post as an h2 POST,
 * and with --h2-post-stream as an h2 POST with no Content-Length, ended by
 * the stream: whatever the method or http version, the script must get the
 * whole body, see its end, and be told its Content-Length if it had one.
 *
 * With --no-headers, the script exits without writing anything: the
 * transaction must fail at once, not after the cgi timeout, and without the
 * service loop spinning on the hangup of the script's stdout meanwhile.
 *
 * With --h2-starve, an h2 client GETs a 32KB answer from the script, but
 * opens its stream window only 1KB wide, and only opens it the rest of the
 * way a second after the answer started.  The script has long finished and
 * gone by then, its answer waiting in the stdout pipe: that wait must be
 * spent sleeping in poll(), not spinning, and all of the answer must arrive
 * once the window opens.
 *
 * With --query, the client GETs the script with URI arguments holding a UTF-8
 * character and a space, percent-encoded: the script must see them in its
 * QUERY_STRING percent-encoded again, byte for byte, the space as '+'.
 *
 * With --fd-budget, the client GETs the script over and over, each time in a
 * new context with one less place in its fds table, starting from a budget
 * with room for everything.  The cgi's three stdio pipes each need a place
 * as well as the connection: the first budget that does not answer 200 must
 * be one that still took the connection but had no room for all the pipes,
 * and it must answer 500, with nothing left behind by the failed spawn.
 *
 * With JOSE in the build, the CGI mount is also gated by a tiny mount
 * interceptor that lets every request through but stamps an onward header
 * on it, the way lws-login stamps its login state; the client sends its
 * own copy of the same header.  The script reports the header as it
 * reached its env, and it must be the interceptor's value: stamped headers
 * go to CGI scripts as they go to a reverse-proxied backend, and the
 * peer's own copy never does.
 *
 * The test fails if
 *  - the client connection or transaction errors out (except where it is
 *    what is expected),
 *  - the response status is not the one expected,
 *  - the CGI does not report receiving every byte of the POST body,
 *  - (JOSE) the CGI did not see the interceptor's stamped header value,
 *  - no completion is seen inside the watchdog period,
 *  - the service loop went around more than MAX_PASSES times, ie, it spun.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

/*
 * This must match info.pt_serv_buf_size set in main(): the biggest body
 * chunk the server can deliver in one go from the direct read path fills
 * pt->serv_buf from LWS_PRE to the end, exactly.
 */
#define SERV_BUF_SIZE	4096
#define CHUNK		(SERV_BUF_SIZE - LWS_PRE)
#define CHUNKS		4

/* the fds budget --fd-budget starts from, with room for everything */
#define FD_BUDGET_START	16

/* what the script answers /big with, and the h2 window we open at first */
#define BIG_BODY	32768
#define STARVE_WINDOW	1024

/*
 * A transaction here takes some tens of trips around the service loop, or
 * some hundreds when a timer comes due inside the millisecond granularity of
 * the poll() wait.  One whose wait spins instead of sleeping takes tens of
 * thousands a second.
 */
#define MAX_PASSES	5000

enum body_type {
	BODY_NONE,
	BODY_CONTENT_LENGTH,
	BODY_CHUNKED,
	BODY_STREAM,		/* h2: no length, the stream ends it */
};

enum expect {
	EXPECT_BODY_COUNT,	/* 200, and the script counted our body */
	EXPECT_FD_BUDGET,	/* 200s, then a 500 as the budget shrinks */
	EXPECT_NO_ANSWER,	/* the connection goes, with no response */
	EXPECT_BIG_BODY,	/* 200 and all of the script's /big answer */
	EXPECT_QUERY,		/* 200 and the QUERY_STRING the script saw */
};

struct tcase {
	const char	*name;
	const char	*method;
	const char	*path;
	enum body_type	body;
	enum expect	expect;
	int		h2;		/* h2 with prior knowledge */
	int		starve;		/* hold the h2 stream window shut */
};

static const struct tcase cases[] = {
	{ "post", "POST", "/", BODY_CONTENT_LENGTH, EXPECT_BODY_COUNT, 0, 0 },
	{ "chunked", "POST", "/", BODY_CHUNKED, EXPECT_BODY_COUNT, 0, 0 },
#if defined(LWS_WITH_HTTP_UNCOMMON_HEADERS)
	{ "put", "PUT", "/", BODY_CONTENT_LENGTH, EXPECT_BODY_COUNT, 0, 0 },
#endif
	{ "fd-budget", "GET", "/", BODY_NONE, EXPECT_FD_BUDGET, 0, 0 },
	{ "no-headers", "GET", "/nohdr", BODY_NONE, EXPECT_NO_ANSWER, 0, 0 },
	{ "query", "GET", "/?x=%C3%A9&y=a%20b", BODY_NONE, EXPECT_QUERY, 0, 0 },
#if defined(LWS_ROLE_H2)
	{ "h2-starve", "GET", "/big", BODY_NONE, EXPECT_BIG_BODY, 1, 1 },
	{ "h2-post", "POST", "/", BODY_CONTENT_LENGTH, EXPECT_BODY_COUNT, 1, 0 },
	{ "h2-post-stream", "POST", "/", BODY_STREAM, EXPECT_BODY_COUNT, 1, 0 },
#endif
};

/* what one client transaction came to */

struct run {
	char		rx[128];
	size_t		rx_len;
	size_t		rx_total;
	lws_usec_t	us_start;
	lws_usec_t	us_end;
	struct lws	*cli;
	int		passes;
	int		status;
	int		completed;
	int		not_x;
	int		done;
};

static const struct tcase *tc;
static struct lws_context *context;
static struct run run;
static int port_tcp = 7681;
static const char *server = "127.0.0.1";
static lws_sorted_usec_list_t sul_timeout, sul_grant;

static uint8_t body[LWS_PRE + CHUNK];

static const char cgi_script_path[] = CGI_SCRIPT_PATH;

/* what --query's URI arguments must come to in the script's QUERY_STRING */
#define QUERY_SEEN	"qs=x=%C3%A9&y=a+b\n"

#define STAMP_HDR	"x-test-stamp"
#define STAMP_VAL	"42"

#if defined(LWS_WITH_JOSE)
static const struct lws_http_mount mount_stamp = {
	.mountpoint		= "/stamp",
	.protocol		= "stamp",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 6,
};
#endif

static const struct lws_http_mount mount = {
#if defined(LWS_WITH_JOSE)
	.mount_next		= &mount_stamp,
	.interceptor_path	= "/stamp",
#endif
	.mountpoint		= "/",			/* mountpoint URL */
	.origin			= cgi_script_path,	/* cgi script */
	.def			= "/",
	.origin_protocol	= LWSMPRO_CGI,
	.mountpoint_len		= 1,			/* char count */
};

struct pss {
	int chunks_done;
};

static void
run_done(void)
{
	if (!run.done)
		run.us_end = lws_now_usecs();
	run.done = 1;
	lws_cancel_service(context);
}

#if defined(LWS_ROLE_H2)
/* --h2-starve: open the stream window the rest of the way */

static void
sul_grant_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_user("%s: opening the window after %d service passes\n",
		  __func__, run.passes);

	if (run.cli && lws_wsi_tx_credit(run.cli, LWSTXCR_PEER_TO_US, BIG_BODY))
		lwsl_err("%s: unable to open the window\n", __func__);
}
#endif

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("--- watchdog: cgi transaction did not complete ---\n");
	run_done();
}

/*
 * The script's answer to a request with a body: did it get all of it, and
 * was it told its length if it had one?
 */

static int
check_body_count(void)
{
	const char *p = strstr(run.rx, "bytes=");
	unsigned long expect = (unsigned long)CHUNKS * CHUNK, seen = 0;
	char clen[32];

	if (!p) {
		lwsl_err("--- no byte count in response, rx '%s' ---\n", run.rx);
		return 1;
	}

	for (p += 6; *p >= '0' && *p <= '9'; p++)
		seen = (seen * 10) + (unsigned long)(*p - '0');

	if (seen != expect) {
		lwsl_err("--- cgi received %lu bytes, expected %lu ---\n",
			 seen, expect);
		return 1;
	}

	if (tc->body == BODY_CONTENT_LENGTH)
		lws_snprintf(clen, sizeof(clen), "clen=%lu\n", expect);
	else
		lws_strncpy(clen, "clen=\n", sizeof(clen));

	if (!strstr(run.rx, clen)) {
		lwsl_err("--- cgi env CONTENT_LENGTH wrong, rx '%s' ---\n",
			 run.rx);
		return 1;
	}

#if defined(LWS_WITH_JOSE)
	p = strstr(run.rx, "stamp=");
	if (!p || strncmp(p + 6, STAMP_VAL "\n", strlen(STAMP_VAL) + 1)) {
		lwsl_err("--- cgi env lacks the stamped header, rx '%s' ---\n",
			 run.rx);
		return 1;
	}
#endif

	lwsl_user("--- cgi stdin received all %lu bytes ---\n", seen);

	return 0;
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	char buf[LWS_PRE + 1024], *start = &buf[LWS_PRE];
	uint8_t **pp, *end;
	int n;

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: client: connection error: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		run_done();
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		run.status = (int)lws_http_client_http_response(wsi);
		lwsl_user("%s: client established, response status %d\n",
			  __func__, run.status);
#if defined(LWS_ROLE_H2)
		if (tc->starve) {
			run.cli = wsi;
			lws_sul_schedule(context, 0, &sul_grant, sul_grant_cb,
					 LWS_US_PER_SEC);
		}
#endif
		break;

	/* ...callbacks related to generating the POST body... */

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		pp = (uint8_t **)in;
		end = (*pp) + len;

		/*
		 * our own copy of the header the interceptor stamps: it must
		 * not be what the script sees
		 */
		if (lws_add_http_header_by_name(wsi,
				(const uint8_t *)STAMP_HDR ":",
				(const uint8_t *)"evil", 4, pp, end))
			return -1;

		switch (tc->body) {
		case BODY_NONE:
			return 0;
		case BODY_CHUNKED:
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_TRANSFER_ENCODING,
					(const uint8_t *)"chunked", 7, pp, end))
				return -1;
			break;
		case BODY_CONTENT_LENGTH:
			/*
			 * Give the exact body size, so the server side takes
			 * the bounded content-length path through LRS_BODY
			 */
			if (lws_add_http_header_content_length(wsi,
						(lws_filepos_t)CHUNKS * CHUNK,
						pp, end))
				return -1;
			break;
		case BODY_STREAM:
			/* nothing: the END_STREAM on the last DATA ends it */
			break;
		}

		/* ... we are going to send the body next ... */
		lws_client_http_body_pending(wsi, 1);
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (tc->body == BODY_NONE || pss->chunks_done >= CHUNKS)
			return 0;

		/*
		 * Send the body one serv_buf-sized chunk per trip around
		 * the event loop, so the server meets body reads that fill
		 * its read buffer exactly
		 */
		n = LWS_WRITE_HTTP;
		if (pss->chunks_done == CHUNKS - 1) {
			/* this is the last piece */
			lws_client_http_body_pending(wsi, 0);
			n = LWS_WRITE_HTTP_FINAL;
		}

		if (tc->body == BODY_CHUNKED) {
			/*
			 * Frame this piece as one chunk, with the last-chunk
			 * and trailer terminator after the final piece
			 */
			static uint8_t fbuf[LWS_PRE + 16 + CHUNK + 8];
			size_t o;

			o = (size_t)lws_snprintf((char *)&fbuf[LWS_PRE], 16,
						 "%x\x0d\x0a", (unsigned int)CHUNK);
			memcpy(&fbuf[LWS_PRE + o], &body[LWS_PRE], CHUNK);
			o += CHUNK;
			fbuf[LWS_PRE + o++] = '\x0d';
			fbuf[LWS_PRE + o++] = '\x0a';
			if (n == LWS_WRITE_HTTP_FINAL) {
				memcpy(&fbuf[LWS_PRE + o], "0\x0d\x0a\x0d\x0a", 5);
				o += 5;
			}

			if (lws_write(wsi, &fbuf[LWS_PRE], o,
				      (enum lws_write_protocol)n) != (int)o)
				return -1;
		} else
			if (lws_write(wsi, &body[LWS_PRE], CHUNK,
				      (enum lws_write_protocol)n) != CHUNK)
				return -1;

		pss->chunks_done++;

		if (n != LWS_WRITE_HTTP_FINAL)
			lws_callback_on_writable(wsi);
		break;

	/* ...callbacks related to receiving the result... */

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ: {
		size_t o = 0;

		/* accumulate the start of the cgi response body */
		while (o < len && run.rx_len + 1 < sizeof(run.rx))
			run.rx[run.rx_len++] = ((const char *)in)[o++];
		run.rx[run.rx_len] = '\0';

		/* ... and count all of it, and what is not 'x' in it */
		for (o = 0; o < len; o++)
			if (((const char *)in)[o] != 'x')
				run.not_x++;
		run.rx_total += len;

		lwsl_user("%s: read %d\n", __func__, (int)len);

		return 0; /* don't passthru */
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		n = (int)(sizeof(buf) - LWS_PRE);
		if (lws_http_client_read(wsi, &start, &n) < 0)
			return -1;

		return 0; /* don't passthru */

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		run.completed = 1;
		run_done();
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		run_done();
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

#if defined(LWS_WITH_JOSE)
/*
 * The interceptor on the CGI mount: passes everything, stamping the
 * header the script reports
 */
static int
callback_stamp(struct lws *wsi, enum lws_callback_reasons reason,
	       void *user, void *in, size_t len)
{
	if (reason == LWS_CALLBACK_HTTP_INTERCEPTOR_CHECK) {
		if (lws_http_add_onward_header(wsi, STAMP_HDR, STAMP_VAL))
			return 1;

		return 0;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}
#endif

static const struct lws_protocols protocols_srv[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
#if defined(LWS_WITH_JOSE)
	{ "stamp", callback_stamp, 0, 0, 0, NULL, 0 },
#endif
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "http", callback_cli, sizeof(struct pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

void sigint_handler(int sig)
{
	run_done();
}

/*
 * One client transaction against the cgi mount, in a context of its own
 * whose fds table has fd_limit places (0 = the process limit).  Returns
 * nonzero if the context or its vhosts could not be created.
 */

static int
run_one(struct lws_context_creation_info *info, unsigned int fd_limit)
{
	struct lws_client_connect_info i;
	struct lws_vhost *vh;
	int ret = 1;

	memset(&run, 0, sizeof(run));

	info->port = CONTEXT_PORT_NO_LISTEN;
	info->vhost_name = NULL;
	info->protocols = NULL;
	info->mounts = NULL;
	info->fd_limit_per_thread = fd_limit;

	context = lws_create_context(info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* server vhost serving the cgi script at / */

	info->port = port_tcp;
	info->vhost_name = "srv";
	info->protocols = protocols_srv;
	info->mounts = &mount;
#if defined(LWS_ROLE_H2)
	if (tc->h2)
		info->options |= LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
#endif

	vh = lws_create_vhost(context, info);
#if defined(LWS_ROLE_H2)
	info->options &= ~(uint64_t)LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
#endif
	if (!vh) {
		lwsl_err("Failed to create server vhost\n");
		goto bail;
	}

	/* client vhost, no listener */

	info->port = CONTEXT_PORT_NO_LISTEN;
	info->vhost_name = "cli";
	info->protocols = protocols_cli;
	info->mounts = NULL;

	vh = lws_create_vhost(context, info);
	if (!vh) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.vhost = vh;
	i.address = server;
	i.port = port_tcp;
	i.path = tc->path;
	i.host = server;
	i.origin = server;
	i.method = tc->method;
	i.protocol = protocols_cli[0].name;
#if defined(LWS_ROLE_H2)
	if (tc->h2)
		i.ssl_connection |= LCCSCF_H2_PRIOR_KNOWLEDGE;
	if (tc->starve) {
		i.ssl_connection |= LCCSCF_H2_MANUAL_RXFLOW;
		i.manual_initial_tx_credit = STARVE_WINDOW;
	}
#endif

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 20 * LWS_US_PER_SEC);

	run.us_start = lws_now_usecs();

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("client connect failed\n");
		goto bail;
	}

	while (!run.done && lws_service(context, 0) >= 0)
		run.passes++;

	lwsl_user("--- %d service passes in %dms ---\n", run.passes,
		  (int)((run.us_end - run.us_start) / LWS_US_PER_MS));

	ret = run.passes > MAX_PASSES;
	if (ret)
		lwsl_err("--- the service loop spun ---\n");

bail:
	lws_sul_cancel(&sul_timeout);
	lws_sul_cancel(&sul_grant);
	lws_context_destroy(context);
	context = NULL;

	return ret;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	unsigned int budget;
	int result = 1, a;
	const char *p;
	size_t n;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_tcp = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server = p;

	/* the case is named by a --<name> switch, the whole of it */

	tc = &cases[0];
	for (a = 1; a < argc; a++)
		for (n = 1; n < LWS_ARRAY_SIZE(cases); n++)
			if (!strncmp(argv[a], "--", 2) &&
			    !strcmp(argv[a] + 2, cases[n].name))
				tc = &cases[n];

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: CGI (%s)\n", tc->name);

	/* deterministic body content */
	for (n = 0; n < CHUNK; n++)
		body[LWS_PRE + n] = (uint8_t)('A' + (n % 26));

	/*
	 * Pin the server read buffer size, so the body chunk boundary math
	 * above stays valid
	 */
	info.pt_serv_buf_size = SERV_BUF_SIZE;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	switch (tc->expect) {
	case EXPECT_BODY_COUNT:
	case EXPECT_BIG_BODY:
	case EXPECT_QUERY:
		if (run_one(&info, info.fd_limit_per_thread) || !run.completed)
			goto done;

		if (run.status != 200) {
			lwsl_err("--- response status %d ---\n", run.status);
			goto done;
		}

		switch (tc->expect) {
		case EXPECT_BODY_COUNT:
			if (check_body_count())
				goto done;
			break;
		case EXPECT_BIG_BODY:
			if (run.rx_total != BIG_BODY || run.not_x) {
				lwsl_err("--- got %u bytes (%d wrong), "
					 "expected %u ---\n",
					 (unsigned int)run.rx_total, run.not_x,
					 (unsigned int)BIG_BODY);
				goto done;
			}
			break;
		default:
			if (!strstr(run.rx, QUERY_SEEN)) {
				lwsl_err("--- script saw the wrong QUERY_STRING,"
					 " rx '%s' ---\n", run.rx);
				goto done;
			}
			break;
		}

		result = 0;
		goto done;

	case EXPECT_NO_ANSWER:
		/*
		 * The script is gone at once: so must the transaction be,
		 * well inside the mount's cgi timeout (5s), with no response
		 */
		if (run_one(&info, info.fd_limit_per_thread))
			goto done;

		if (run.completed || run.status) {
			lwsl_err("--- a response (%d) with no cgi headers ---\n",
				 run.status);
			goto done;
		}

		if (run.us_end - run.us_start > 3 * LWS_US_PER_SEC) {
			lwsl_err("--- the transaction outlived its script ---\n");
			goto done;
		}

		result = 0;
		goto done;

	case EXPECT_FD_BUDGET:
		break;
	}

	/*
	 * Take one place away from the fds table each time, until the cgi
	 * no longer gets its 200: that budget has room for the connection
	 * but not for all three of the cgi's stdio pipes, and must be told
	 * so with a 500
	 */

	for (budget = FD_BUDGET_START; budget > 1; budget--) {
		if (run_one(&info, budget) || !run.completed) {
			lwsl_err("--- budget %u: no answer ---\n", budget);
			goto done;
		}

		lwsl_user("--- budget %u: status %d ---\n", budget, run.status);

		if (run.status == 200)
			continue;

		if (budget == FD_BUDGET_START)
			lwsl_err("--- no room for the cgi at the start ---\n");
		else if (run.status != 500)
			lwsl_err("--- failed spawn answered %d, not 500 ---\n",
				 run.status);
		else
			result = 0;

		break;
	}

done:
	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
