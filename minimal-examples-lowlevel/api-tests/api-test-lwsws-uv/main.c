/*
 * lws-api-test-lwsws-uv
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * PURPOSE
 *
 * Client side of the api-test-lwsws-uv ctest fixture: it drives a real lwsws,
 * running on libuv with its protocol plugins dlopened out of the build tree,
 * over the flows that broke in production but that the in-process ctests never
 * touch, because those only ever run the poll loop with no plugins and no
 * mounts.
 *
 * The cases (-t <case>) are:
 *
 *  captcha    the lws_captcha_ratelimit interceptor's whole challenge /
 *             submit / pass handshake against a gated file mount, as h1.
 *             "captcha-h2" is the same sequence as h2 (the interceptor
 *             decision is made per request, on whatever http role the peer
 *             arrived as).  The challenge form posts to the
 *             gated url itself (captcha.js sets form.action =
 *             window.location.pathname), which is exactly what C-468 took
 *             for a state confusion and answered with a 303 back to the
 *             challenge: warmcat.com then looped on the captcha forever
 *             (reverted in 6b004539e).  So this case asserts the POST to the
 *             gated url IS the form's POST and does mint the pass cookie.
 *             It also fetches an interceptor asset with no cookies at all,
 *             the path a browser takes for the challenge page's own js/css.
 *             NOTE: captcha-h2 fails at the time of writing, and not on the
 *             interceptor: the lws h2 CLIENT does not deliver a POST with a
 *             request body at all.  See the README.
 *
 *  pipeline   h1 keepalive pipelining across a large transfer, on the
 *             cleartext listener.  Two phases: first the two requests in one
 *             write the C-460 report describes, then the same thing with the
 *             second request deliberately arriving as its own POLLIN while
 *             the big response is still in flight (we stop reading to hold
 *             the server in LRS_ISSUING_FILE).  That second shape is the one
 *             the reverted C-460 release broke: the mid-transaction POLLIN
 *             re-attached an ah, cleared hdr_parsing_completed and made
 *             lws_http_transaction_completed() silently no-op, so the
 *             connection was never returned to keepalive.  The case
 *             therefore asserts both responses are complete and correct AND
 *             that further transactions still work on the same connection,
 *             and finally that the server does idle-close it once we go
 *             quiet (the keepalive path still being armed at all).
 *
 *  proxy      a request through the tls vhost's http proxy mount, whose
 *             origin is this same lwsws's cleartext listener, so the onward
 *             request headers are really composed and consumed.
 *
 *  h3race     C-473.  An h3 client with the TCP fallback ENABLED (so the
 *             happy-eyeballs racer really starts) fetches over QUIC; QUIC
 *             wins the race on loopback and the TCP racer is parked.  The
 *             client then stays alive well past the server's idle timeout,
 *             so the server closes that parked, unused TCP connection.  If
 *             the racer's event-lib watcher outlived the wsi it points at,
 *             that close is the POLLIN that dereferences freed memory: the
 *             production SIGSEGV.  Run under libuv (where it crashed) and on
 *             the poll loop as a control.  The client must survive and still
 *             serve a further h3 request.
 *
 *  quicabort  C-471.  A QUIC client that goes away during, or immediately
 *             after, its handshake -- lws_context_destroy() sends the
 *             CONNECTION_CLOSE -- at a spread of delays, after which lwsws
 *             must still answer ordinary h1 requests.
 *
 * Everything here is legitimate client behaviour: no crafted inputs, no
 * malformed frames.  Failures are reported by the process exit code.
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <signal.h>

/* ---------------------------------------------------------- cmdline state */

static const char	*g_server = "localhost";
static int		g_port_tls, g_port_plain;
static int		g_uv;			/* run our loop on libuv */
/*
 * The interceptor's cookies carry the peer's IP as their "sub" claim and are
 * refused from any other address, quite deliberately.  So a case that carries
 * a cookie across separate connections has to keep using one address family:
 * "localhost" resolves to both, and lws is free to pick either per connect.
 */
static int		g_pin_family;

static struct lws_context *cx;
static int		interrupted, result = 1;

/* ------------------------------------------------------------- http jobs */

enum job_scheme {
	JS_PLAIN,	/* cleartext listener */
	JS_TLS,		/* tls listener, h1 or h2 by alpn */
	JS_QUIC		/* tls listener port, over QUIC / h3 */
};

enum job_cookie {
	JC_NONE,
	JC_VISIT,	/* the interceptor's visit cookie */
	JC_PASS		/* the interceptor's pass cookie */
};

struct job {
	const char	*name;
	const char	*method;	/* NULL means GET */
	const char	*path;
	enum job_scheme	scheme;
	enum job_cookie	send_cookie;
	enum job_cookie	capture_cookie;
	const char	*body;		/* urlencoded POST body, or NULL */
	unsigned int	expect_status;
	const char	*expect_substr;	/* must appear in the body */
	const char	*expect_location; /* must equal Location:, or NULL */
	unsigned int	pre_delay_ms;	/* idle this long before starting */
};

/* what the interceptor names its two cookies (the lws_captcha_ratelimit
 * PVOs in the fixture config pick the second one) */
#define COOKIE_VISIT_NAME	"lws_interceptor_v"
#define COOKIE_PASS_NAME	"lws_apitest_captcha"

#define BODY_MAX	(16 * 1024)

static char		cookie_visit[1024], cookie_pass[1024];
static const char	*g_alpn = "http/1.1";

static const struct job	*jobs;
static int		njobs, jidx, jdone, job_delay_done = -1;
/*
 * Set while a job list is being driven.  The quicabort case uses the same
 * client callback for a connection it deliberately abandons, and must not have
 * the job driver advance or assert on it.
 */
static int		jobs_active;

static unsigned int	r_status;
static char		r_location[512];
static char		r_body[BODY_MAX];
static size_t		r_body_len;
static int		r_trunc;

static struct lws	*current_wsi;
static lws_sorted_usec_list_t sul_next, sul_watchdog;

static void run_next_job(lws_sorted_usec_list_t *sul);

/*
 * Stop this phase's loop.
 *
 * On the poll loop lws_service() returns each time round, so setting the flag
 * and kicking it is enough.
 *
 * On libuv, lws_service() IS uv_run(): it does not return until the loop has
 * nothing left to do.  And lws_context_destroy() from in here would only set
 * pt->destroy_self and defer (lib/core/context.c, "if (pt->inside_lws_service)
 * ... deferred_pt = 1"), which under libuv is picked up only by the next fd
 * event in lws_io_cb() -- if the last connection just went away there may be
 * no such event ever again.  So stop the loop instead, and let the caller
 * destroy the context from outside the service, where it can complete.
 */

static void
stop_loop(void)
{
	interrupted = 1;

#if defined(LWS_WITH_LIBUV)
	if (g_uv && cx) {
		uv_loop_t *l = lws_uv_getloop(cx, 0);

		if (l) {
			uv_stop(l);

			return;
		}
	}
#endif

	lws_cancel_service(cx);
}

static void
finish(int res)
{
	result = res;
	stop_loop();
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;
	lwsl_err("%s: watchdog: case did not complete\n", __func__);
	finish(1);
}

/*
 * Pull "name=value" out of the Set-Cookie fragments of the response that just
 * completed, for the cookie whose name contains needle (the interceptor
 * prefixes its cookie names with __Host- when it can).
 */

static int
capture_cookie(struct lws *wsi, const char *needle, char *dest, size_t dest_len)
{
	char frag[1024];
	int n = 0;

	while (lws_hdr_copy_fragment(wsi, frag, (int)sizeof(frag),
				     WSI_TOKEN_HTTP_SET_COOKIE, n++) >= 0) {
		char *semi;

		if (!strstr(frag, needle))
			continue;

		semi = strchr(frag, ';');
		if (semi)
			*semi = '\0';

		lws_strncpy(dest, frag, dest_len);

		return 0;
	}

	return 1;
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	const struct job *j = &jobs[jidx];

	/*
	 * No wsi filter here: on h2 (and h3) the request moves to a mux child
	 * wsi that is not the one lws_client_connect_via_info() handed back,
	 * so comparing against that pointer silently drops the whole
	 * response.  Only one job is ever in flight per context.
	 */

	switch (reason) {

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in, *end = (*p) + len;
		const char *ck = NULL;

		if (j->send_cookie == JC_VISIT)
			ck = cookie_visit;
		if (j->send_cookie == JC_PASS)
			ck = cookie_pass;

		if (ck && ck[0] &&
		    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_COOKIE,
						 (const unsigned char *)ck,
						 (int)strlen(ck), p, end))
			return -1;

		if (j->body) {
			char cl[16];

			lws_snprintf(cl, sizeof(cl), "%d",
				     (int)strlen(j->body));

			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_TYPE,
					(const unsigned char *)
					"application/x-www-form-urlencoded",
					33, p, end) ||
			    lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_LENGTH,
					(const unsigned char *)cl,
					(int)strlen(cl), p, end))
				return -1;

			lws_client_http_body_pending(wsi, 1);
			lws_callback_on_writable(wsi);
		}
		break;
	}

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE: {
		uint8_t buf[LWS_PRE + 512], *start = &buf[LWS_PRE];
		size_t blen;

		if (!j->body)
			break;

		blen = strlen(j->body);
		if (blen > sizeof(buf) - LWS_PRE)
			return -1;

		memcpy(start, j->body, blen);
		lws_client_http_body_pending(wsi, 0);

		if (lws_write(wsi, start, blen, LWS_WRITE_HTTP_FINAL) < 0)
			return -1;
		break;
	}

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		r_status = (unsigned int)lws_http_client_http_response(wsi);

		r_location[0] = '\0';
		if (lws_hdr_copy(wsi, r_location, (int)sizeof(r_location),
				 WSI_TOKEN_HTTP_LOCATION) < 0)
			r_location[0] = '\0';

		if (j->capture_cookie == JC_VISIT &&
		    capture_cookie(wsi, COOKIE_VISIT_NAME, cookie_visit,
				   sizeof(cookie_visit))) {
			lwsl_err("%s: '%s': no " COOKIE_VISIT_NAME " cookie\n",
				 __func__, j->name);
			jdone = -1;
		}

		if (j->capture_cookie == JC_PASS &&
		    capture_cookie(wsi, COOKIE_PASS_NAME, cookie_pass,
				   sizeof(cookie_pass))) {
			lwsl_err("%s: '%s': no " COOKIE_PASS_NAME " cookie\n",
				 __func__, j->name);
			jdone = -1;
		}
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP: {
		char abuf[LWS_PRE + 2048], *px = abuf + LWS_PRE;
		int alen = (int)sizeof(abuf) - LWS_PRE;

		/* h1 wants the body pulled by the callback */
		if (lws_http_client_read(wsi, &px, &alen) < 0)
			return -1;

		return 0;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (r_body_len + len < sizeof(r_body)) {
			memcpy(r_body + r_body_len, in, len);
			r_body_len += len;
		} else
			r_trunc = 1;

		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!jdone)
			jdone = 1;
		if (jobs_active)
			lws_sul_schedule(cx, 0, &sul_next, run_next_job, 1);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: '%s': connect error: %s\n", __func__, j->name,
			 in ? (const char *)in : "(null)");
		jdone = -1;
		if (jobs_active)
			lws_sul_schedule(cx, 0, &sul_next, run_next_job, 1);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * Check the response the job just got, then start the next one.  Called on a
 * sul so we are never inside the completing wsi's callback.
 */

static void
run_next_job(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	static char host_hdr[128];
	const struct job *j;

	(void)sul;

	if (jidx >= 0 && jidx < njobs && jdone) {
		j = &jobs[jidx];

		if (jdone < 0) {
			lwsl_err("%s: '%s' failed\n", __func__, j->name);
			finish(1);

			return;
		}

		if (j->expect_status && r_status != j->expect_status) {
			lwsl_err("%s: '%s': status %u, expected %u\n",
				 __func__, j->name, r_status,
				 j->expect_status);
			finish(1);

			return;
		}

		if (j->expect_location &&
		    strcmp(r_location, j->expect_location)) {
			lwsl_err("%s: '%s': Location '%s', expected '%s'\n",
				 __func__, j->name, r_location,
				 j->expect_location);
			finish(1);

			return;
		}

		if (j->expect_substr &&
		    !lws_nstrstr(r_body, r_body_len, j->expect_substr,
				 strlen(j->expect_substr))) {
			lwsl_err("%s: '%s': body (%u bytes%s) lacks '%s'\n",
				 __func__, j->name, (unsigned int)r_body_len,
				 r_trunc ? ", truncated" : "",
				 j->expect_substr);
			finish(1);

			return;
		}

		lwsl_user("%s: '%s': OK (status %u, %u bytes)\n", __func__,
			  j->name, r_status, (unsigned int)r_body_len);

		jidx++;
	}

	if (jidx >= njobs) {
		finish(0);

		return;
	}

	j = &jobs[jidx];

	if (j->pre_delay_ms && job_delay_done != jidx) {
		/*
		 * An intentional idle gap: come back here once it has passed,
		 * with the delay marked consumed for this job.
		 */
		job_delay_done = jidx;
		jdone = 0;
		lwsl_user("%s: '%s': idling %ums first\n", __func__, j->name,
			  j->pre_delay_ms);
		lws_sul_schedule(cx, 0, &sul_next, run_next_job,
				 (lws_usec_t)j->pre_delay_ms * LWS_US_PER_MS);

		return;
	}

	jdone = 0;
	r_status = 0;
	r_body_len = 0;
	r_trunc = 0;
	r_location[0] = '\0';

	memset(&i, 0, sizeof(i));
	i.context		= cx;
	i.address		= g_server;
	i.port			= j->scheme == JS_PLAIN ? g_port_plain :
							  g_port_tls;
	i.path			= j->path;
	i.method		= j->method ? j->method : "GET";

	lws_snprintf(host_hdr, sizeof(host_hdr), "%s:%d", g_server, i.port);
	i.host			= host_hdr;
	i.origin		= host_hdr;

	/* we assert the redirects ourselves rather than following them */
	i.ssl_connection	= LCCSCF_HTTP_NO_FOLLOW_REDIRECT;

	if (j->scheme != JS_PLAIN)
		i.ssl_connection |= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED;

	if (j->scheme == JS_QUIC) {
		i.method	= "QUIC";
		i.alpn		= "h3";
		/*
		 * C-473 is about the TCP fallback racer, so it must be left
		 * enabled: that is what creates the parallel connection the
		 * ALPN migration has to tear down.
		 */
		i.disable_h3_fallback = 0;
	} else
		if (j->scheme == JS_TLS)
			i.alpn = g_alpn;

	i.protocol		= "defprot";
	i.local_protocol_name	= "lws-api-test-lwsws-uv-cli";
	i.pwsi			= &current_wsi;

	current_wsi = NULL;
	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: '%s': client connect failed\n", __func__,
			 j->name);
		finish(1);
	}
}

/* ------------------------------------------------- raw h1 pipelining case */

/*
 * A minimal incremental HTTP/1.1 response reader.  The mounts we ask for are
 * plain files, so every response is Content-Length delimited.
 */

struct h1_resp {
	unsigned int	status;
	long long	content_length;
	long long	body_got;
	int		in_body;
	int		complete;
	size_t		hdr_len;
	char		hdr[2048];
	/* offset of this response's body within the pattern, for checking */
	int		check_pattern;
	int		pattern_bad;
	char		first[64];	/* first bytes of body, for text */
	size_t		first_len;
};

static const char pat[] = "0123456789abcdef";

static void
h1_resp_reset(struct h1_resp *r, int check_pattern)
{
	memset(r, 0, sizeof(*r));
	r->content_length = -1;
	r->check_pattern = check_pattern;
}

/*
 * Consume up to *len bytes; returns the number consumed, and sets
 * r->complete when the response's body is fully in.
 */
static size_t
h1_resp_consume(struct h1_resp *r, const uint8_t *p, size_t len)
{
	size_t used = 0;

	while (used < len && !r->complete) {

		if (!r->in_body) {
			char *eoh;

			if (r->hdr_len >= sizeof(r->hdr) - 1) {
				lwsl_err("%s: response headers too big\n",
					 __func__);
				r->pattern_bad = 1;

				return len;
			}

			r->hdr[r->hdr_len++] = (char)p[used++];
			r->hdr[r->hdr_len] = '\0';

			eoh = strstr(r->hdr, "\x0d\x0a\x0d\x0a");
			if (!eoh)
				continue;

			r->in_body = 1;

			if (r->hdr_len > 12 &&
			    !strncmp(r->hdr, "HTTP/1.1 ", 9))
				r->status = (unsigned int)atoi(r->hdr + 9);

			{
				const char *cl = r->hdr;

				while ((cl = strstr(cl, "\x0d\x0a"))) {
					cl += 2;
					if (!strncasecmp(cl, "content-length:",
							 15)) {
						r->content_length =
							atoll(cl + 15);
						break;
					}
				}
			}

			if (r->content_length <= 0)
				r->complete = 1;

			continue;
		}

		{
			size_t chunk = len - used;

			if (r->content_length >= 0 &&
			    (long long)chunk > r->content_length - r->body_got)
				chunk = (size_t)(r->content_length -
						 r->body_got);

			if (r->check_pattern) {
				size_t n;

				for (n = 0; n < chunk; n++)
					if (p[used + n] !=
					    (uint8_t)pat[(r->body_got + (long long)n) % 16]) {
						r->pattern_bad = 1;
						break;
					}
			} else
				if (r->first_len < sizeof(r->first) - 1) {
					size_t n = sizeof(r->first) - 1 -
							r->first_len;

					if (n > chunk)
						n = chunk;
					memcpy(r->first + r->first_len,
					       p + used, n);
					r->first_len += n;
					r->first[r->first_len] = '\0';
				}

			r->body_got += (long long)chunk;
			used += chunk;

			if (r->content_length >= 0 &&
			    r->body_got >= r->content_length)
				r->complete = 1;
		}
	}

	return used;
}

/*
 * The pipelining case's own little state machine.
 *
 *  PL_PIPE1   both requests written in one write, both responses drained
 *  PL_PIPE2   big request written, we stop reading to hold the server in
 *             LRS_ISSUING_FILE, and the second request goes out as its own
 *             POLLIN mid-transfer; then we resume and drain both
 *  PL_REUSE   one more ordinary transaction, to prove the connection came
 *             back to keepalive properly after all that
 *  PL_IDLE    stay quiet and require the server to idle-close us
 */

enum pl_state {
	PL_PIPE1,
	PL_PIPE2_BIG,
	PL_PIPE2_SMALL,
	PL_REUSE,
	PL_IDLE
};

static enum pl_state	pl_state;
static struct h1_resp	pl_r[2];
static int		pl_ridx, pl_nresp;
static int		pl_write_what;	/* 1 = both, 2 = big, 3 = small */
static lws_usec_t	pl_idle_from;
static lws_sorted_usec_list_t sul_pl;
static struct lws	*pl_wsi;

static char		req_big[256], req_small[256];

#define BIG_LEN		(4 * 1024 * 1024)
#define SMALL_BODY	"LWSWS-APITEST-SMALL-FILE-CONTENT\n"

static void
pl_start_resp(int n, int check_pattern)
{
	int i;

	pl_ridx = 0;
	pl_nresp = n;
	for (i = 0; i < n; i++)
		h1_resp_reset(&pl_r[i], i == 0 ? check_pattern : 0);
}

static int
pl_check(const struct h1_resp *r, long long explen, const char *expbody,
	 const char *what)
{
	if (r->status != 200) {
		lwsl_err("%s: %s: status %u\n", __func__, what, r->status);

		return 1;
	}

	if (r->content_length != explen) {
		lwsl_err("%s: %s: Content-Length %lld, expected %lld\n",
			 __func__, what, r->content_length, explen);

		return 1;
	}

	if (r->body_got != explen) {
		lwsl_err("%s: %s: got %lld body bytes of %lld\n", __func__,
			 what, r->body_got, explen);

		return 1;
	}

	if (r->pattern_bad) {
		lwsl_err("%s: %s: body content mismatch\n", __func__, what);

		return 1;
	}

	if (expbody && strcmp(r->first, expbody)) {
		lwsl_err("%s: %s: body '%s', expected '%s'\n", __func__, what,
			 r->first, expbody);

		return 1;
	}

	lwsl_user("%s: %s: OK (%lld bytes)\n", __func__, what, r->body_got);

	return 0;
}

/* mid-transfer: let the big response resume, having sent the small request
 * into the middle of it */
static void
pl_resume_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;

	lwsl_user("%s: resuming rx, %lld of %d big bytes in so far\n", __func__,
		  pl_r[0].body_got, BIG_LEN);

	/*
	 * We deliberately did not read while the second request went out, so
	 * the server was still in its file transfer when that POLLIN landed.
	 */
	lws_rx_flow_control(pl_wsi, 1);
}

/* the second request of phase 2, written while the big one is still coming */
static void
pl_midreq_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;

	pl_state = PL_PIPE2_SMALL;
	pl_write_what = 3;
	lws_callback_on_writable(pl_wsi);

	/* give the server a moment with the request while we are still quiet */
	lws_sul_schedule(cx, 0, &sul_pl, pl_resume_cb, 300 * LWS_US_PER_MS);
}

static void
pl_idle_done_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;

	lwsl_err("%s: server did not idle-close the keepalive connection\n",
		 __func__);
	finish(1);
}

static int
callback_pl(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	    void *in, size_t len)
{
	(void)user;

	switch (reason) {

	case LWS_CALLBACK_RAW_CONNECTED:
		lwsl_user("%s: connected to the cleartext listener\n",
			  __func__);
		pl_wsi = wsi;
		pl_state = PL_PIPE1;
		pl_write_what = 1;
		pl_start_resp(2, 1);
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE: {
		uint8_t buf[LWS_PRE + 1024], *p = &buf[LWS_PRE];
		size_t l = 0;

		switch (pl_write_what) {
		case 1:
			/*
			 * Both requests in ONE write: the shape the C-460
			 * report describes, and what a browser does for a page
			 * and its subresources on one keepalive connection.
			 */
			l = (size_t)lws_snprintf((char *)p, sizeof(buf) -
						 LWS_PRE, "%s%s", req_big,
						 req_small);
			break;
		case 2:
			l = (size_t)lws_snprintf((char *)p, sizeof(buf) -
						 LWS_PRE, "%s", req_big);
			break;
		case 3:
			l = (size_t)lws_snprintf((char *)p, sizeof(buf) -
						 LWS_PRE, "%s", req_small);
			break;
		default:
			return 0;
		}

		pl_write_what = 0;

		if (lws_write(wsi, p, l, LWS_WRITE_RAW) < (int)l) {
			lwsl_err("%s: short write\n", __func__);
			finish(1);

			return -1;
		}
		break;
	}

	case LWS_CALLBACK_RAW_RX: {
		const uint8_t *p = (const uint8_t *)in;
		size_t rem = len;

		while (rem && pl_ridx < pl_nresp) {
			size_t used = h1_resp_consume(&pl_r[pl_ridx], p, rem);

			p += used;
			rem -= used;

			if (!pl_r[pl_ridx].complete)
				break;

			pl_ridx++;
		}

		if (pl_ridx < pl_nresp)
			break;

		/* both (or the one) expected responses are complete */

		switch (pl_state) {
		case PL_PIPE1:
			if (pl_check(&pl_r[0], BIG_LEN, NULL,
				     "phase 1 big (pipelined)") ||
			    pl_check(&pl_r[1], (long long)strlen(SMALL_BODY),
				     SMALL_BODY, "phase 1 small (pipelined)")) {
				finish(1);

				return -1;
			}

			/*
			 * Phase 2: ask for the big file again, then stop
			 * reading so the server is still inside
			 * lws_serve_http_file_fragment() when the next
			 * request's POLLIN arrives.
			 */
			lwsl_user("%s: phase 2: request during transfer\n",
				  __func__);
			pl_state = PL_PIPE2_BIG;
			pl_start_resp(2, 1);
			pl_write_what = 2;
			lws_callback_on_writable(wsi);
			lws_rx_flow_control(wsi, 0);
			lws_sul_schedule(cx, 0, &sul_pl, pl_midreq_cb,
					 700 * LWS_US_PER_MS);
			break;

		case PL_PIPE2_BIG:
		case PL_PIPE2_SMALL:
			if (pl_check(&pl_r[0], BIG_LEN, NULL,
				     "phase 2 big (interrupted)") ||
			    pl_check(&pl_r[1], (long long)strlen(SMALL_BODY),
				     SMALL_BODY, "phase 2 small (mid-transfer)")) {
				finish(1);

				return -1;
			}

			/* is the connection still usable as a keepalive one? */
			lwsl_user("%s: phase 3: reuse after the transfers\n",
				  __func__);
			pl_state = PL_REUSE;
			pl_start_resp(1, 0);
			pl_write_what = 3;
			lws_callback_on_writable(wsi);
			break;

		case PL_REUSE:
			if (pl_check(&pl_r[0],
				     (long long)strlen(SMALL_BODY), SMALL_BODY,
				     "phase 3 reuse")) {
				finish(1);

				return -1;
			}

			/*
			 * Now go quiet: the server's keepalive timeout must
			 * eventually close us, ie, the keepalive path really
			 * was re-armed by the completed transactions.
			 */
			lwsl_user("%s: phase 4: waiting for the server's "
				  "idle close\n", __func__);
			pl_state = PL_IDLE;
			pl_idle_from = lws_now_usecs();
			lws_sul_schedule(cx, 0, &sul_pl, pl_idle_done_cb,
					 30 * LWS_USEC_PER_SEC);
			break;

		case PL_IDLE:
			lwsl_err("%s: unexpected rx while idle\n", __func__);
			finish(1);

			return -1;
		}
		break;
	}

	case LWS_CALLBACK_RAW_CLOSE:
		if (pl_state != PL_IDLE) {
			lwsl_err("%s: server closed us in state %d\n",
				 __func__, (int)pl_state);
			finish(1);
			break;
		}

		lwsl_user("%s: server idle-closed after %ums\n", __func__,
			  (unsigned int)((lws_now_usecs() - pl_idle_from) /
					 LWS_US_PER_MS));
		lws_sul_cancel(&sul_pl);
		finish(0);
		break;

	case LWS_CALLBACK_RAW_ADOPT:
	default:
		break;
	}

	return 0;
}

/* -------------------------------------------------------------- protocols */

static const struct lws_protocols
	defprot = { "defprot", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	prot_cli = { "lws-api-test-lwsws-uv-cli", callback_cli, 0, 0, 0,
		     NULL, 0 },
	prot_pl = { "lws-api-test-lwsws-uv-pl", callback_pl, 0, 0, 0,
		    NULL, 0 };

static const struct lws_protocols *pprotocols[] = {
	&defprot, &prot_cli, &prot_pl, NULL
};

/* ------------------------------------------------------------- the cases */

static const struct job jobs_captcha[] = {
	/*
	 * The gated mount is protected by the interceptor: an unproven peer
	 * gets the challenge page in place of the page he asked for, plus the
	 * visit cookie the challenge is measured against.
	 */
	{ "gated GET -> challenge", NULL, "/gated/", JS_TLS, JC_NONE, JC_VISIT,
	  NULL, 200, "captcha", NULL, 0 },

	/*
	 * The challenge page's own assets come off the interceptor's
	 * mountpoint with no cookies attached at all.
	 */
	{ "interceptor asset, no cookies", NULL, "/captcha/captcha.js",
	  JS_TLS, JC_NONE, JC_NONE, NULL, 200, "captcha-btn", NULL, 0 },

	/*
	 * C-468: the challenge form posts to the gated url itself.  That POST
	 * must be taken as the form submission and mint the pass cookie, with
	 * the redirect back to the url the peer originally wanted.
	 */
	{ "form POST to the gated url", "POST", "/gated/", JS_TLS, JC_VISIT,
	  JC_PASS, "captcha=1", 303, NULL, "/gated/?lws_interceptor_ok=1",
	  600 },

	/* the reload the 303 sends the browser to */
	{ "reload with lws_interceptor_ok", NULL,
	  "/gated/?lws_interceptor_ok=1", JS_TLS, JC_PASS, JC_NONE, NULL, 303,
	  NULL, "/gated/", 0 },

	/* ...and now the real page is visible */
	{ "gated GET -> real content", NULL, "/gated/", JS_TLS, JC_PASS,
	  JC_NONE, NULL, 200, "LWSWS-APITEST-GATED-CONTENT", NULL, 0 },
};

static const struct job jobs_proxy[] = {
	/*
	 * The proxy mount's origin is this same lwsws's cleartext listener,
	 * so this really composes and consumes onward request headers.
	 */
	{ "proxy mount", NULL, "/proxy/files/small.txt", JS_TLS, JC_NONE,
	  JC_NONE, NULL, 200, SMALL_BODY, NULL, 0 },
	{ "origin direct", NULL, "/files/small.txt", JS_PLAIN, JC_NONE,
	  JC_NONE, NULL, 200, SMALL_BODY, NULL, 0 },
};

static const struct job jobs_h3race[] = {
	/*
	 * QUIC wins the race on loopback; the TCP racer that was started
	 * alongside it is parked and must be torn down by the ALPN migration
	 * while it is still reachable from the wsi that owns its event-lib
	 * watcher (C-473).
	 */
	{ "h3 fetch (races TCP)", NULL, "/files/small.txt", JS_QUIC, JC_NONE,
	  JC_NONE, NULL, 200, SMALL_BODY, NULL, 0 },

	/*
	 * Outlive the server's idle close of anything it is still holding for
	 * us -- that close is the POLLIN that used to land on a freed wsi.
	 * The fixture's timeouts are a few seconds, this is comfortably past
	 * them.
	 */
	{ "h3 fetch after the server's idle close", NULL, "/files/small.txt",
	  JS_QUIC, JC_NONE, JC_NONE, NULL, 200, SMALL_BODY, NULL, 16000 },

	/* and ordinary h1 still works from the same client */
	{ "h1 fetch afterwards", NULL, "/files/small.txt", JS_PLAIN, JC_NONE,
	  JC_NONE, NULL, 200, SMALL_BODY, NULL, 0 },
};

static const struct job jobs_alive[] = {
	{ "h1 cleartext still served", NULL, "/files/small.txt", JS_PLAIN,
	  JC_NONE, JC_NONE, NULL, 200, SMALL_BODY, NULL, 0 },
	{ "h1 tls still served", NULL, "/files/small.txt", JS_TLS, JC_NONE,
	  JC_NONE, NULL, 200, SMALL_BODY, NULL, 0 },
};

static const struct job jobs_quic_hit[] = {
	{ "quic connect we then abandon", NULL, "/files/big.bin", JS_QUIC,
	  JC_NONE, JC_NONE, NULL, 0, NULL, NULL, 0 },
};

/* ------------------------------------------------------------------ main */

static int
make_context(void)
{
	struct lws_context_creation_info info;

	memset(&info, 0, sizeof(info));
	lws_context_info_defaults(&info, NULL);

	/*
	 * The default budget is sized for a lone client; this test runs
	 * several connections and would otherwise silently stall.
	 */
	info.fd_limit_per_thread	= 0;
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.pprotocols			= pprotocols;
	/* so we are told when a destroy started from a callback finalizes */
	info.pcontext			= &cx;
	info.options			= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.connect_timeout_secs	= 20;

	/*
	 * Set the event lib here rather than through the builtin cmdline
	 * handler, so this test does not depend on that option existing.
	 */
	if (g_uv)
		info.options |= LWS_SERVER_OPTION_LIBUV;

#if defined(LWS_WITH_IPV4)
	if (g_pin_family)
		info.options |= LWS_SERVER_OPTION_DISABLE_IPV6;
#endif

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("%s: lws_create_context failed\n", __func__);

		return 1;
	}

	return 0;
}

static int
service_until_done(void)
{
	while (!interrupted && cx)
		if (lws_service(cx, 0) < 0)
			break;

	return 0;
}

/*
 * Run a job list to completion.
 *
 * fresh == 1 gives each job its own context.  That matters wherever we care
 * which http role the request uses: lws remembers the Alt-Svc h3 endpoint and
 * the negotiated ALPN per context, so within one context the second request to
 * the same origin would be upgraded to h3 whatever this job asked for.  The
 * cases that need one long-lived client (h3race) pass 0.
 */
static int
run_jobs(const struct job *j, int n, const char *alpn, int fresh)
{
	if (fresh && n > 1) {
		int k;

		for (k = 0; k < n; k++)
			if (run_jobs(&j[k], 1, alpn, 1))
				return 1;

		return 0;
	}

	if (make_context())
		return 1;

	g_alpn		= alpn ? alpn : "http/1.1";
	jobs		= j;
	njobs		= n;
	jidx		= 0;
	jdone		= 0;
	job_delay_done	= -1;
	jobs_active	= 1;
	interrupted	= 0;
	result		= 1;

	lws_sul_schedule(cx, 0, &sul_watchdog, watchdog_cb,
			 55 * LWS_USEC_PER_SEC);
	lws_sul_schedule(cx, 0, &sul_next, run_next_job, 1);

	service_until_done();

	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_next);
	jobs_active = 0;
	if (cx)
		lws_context_destroy(cx);
	cx = NULL;

	return result;
}

/*
 * C-471: bring a QUIC connection up and take our whole context away at a
 * spread of moments around the handshake, so the server sees the
 * CONNECTION_CLOSE at each of them.
 */

static void
abort_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;

	/* C-471: this is the abandonment the server has to survive */
	stop_loop();
}

static int
run_quicabort(void)
{
	static const unsigned int delays_ms[] = { 1, 3, 8, 20, 50, 120 };
	struct lws_client_connect_info i;
	static char host_hdr[128];
	size_t k;

	for (k = 0; k < LWS_ARRAY_SIZE(delays_ms); k++) {

		if (make_context())
			return 1;

		jobs		= jobs_quic_hit;
		njobs		= 1;
		jidx		= 0;
		jdone		= 0;
		jobs_active	= 0;
		interrupted	= 0;

		memset(&i, 0, sizeof(i));
		i.context		= cx;
		i.address		= g_server;
		i.port			= g_port_tls;
		i.path			= "/files/big.bin";
		i.method		= "QUIC";
		i.alpn			= "h3";
		i.ssl_connection	= LCCSCF_USE_SSL |
					  LCCSCF_ALLOW_SELFSIGNED |
					  LCCSCF_HTTP_NO_FOLLOW_REDIRECT;
		lws_snprintf(host_hdr, sizeof(host_hdr), "%s:%d", g_server,
			     g_port_tls);
		i.host			= host_hdr;
		i.origin		= host_hdr;
		i.protocol		= "defprot";
		i.local_protocol_name	= "lws-api-test-lwsws-uv-cli";
		i.pwsi			= &current_wsi;

		current_wsi = NULL;
		if (!lws_client_connect_via_info(&i)) {
			lwsl_err("%s: connect failed\n", __func__);
			lws_context_destroy(cx);
			cx = NULL;

			return 1;
		}

		lwsl_user("%s: destroying the context %ums in\n", __func__,
			  delays_ms[k]);

		lws_sul_schedule(cx, 0, &sul_next, abort_cb,
				 (lws_usec_t)delays_ms[k] * LWS_US_PER_MS);

		service_until_done();

		lws_sul_cancel(&sul_next);
		if (cx)
			lws_context_destroy(cx);
		cx = NULL;
	}

	/* ...and the server must still be there, serving ordinary http */

	return run_jobs(jobs_alive, (int)LWS_ARRAY_SIZE(jobs_alive),
			"http/1.1", 1);
}

static int
run_pipeline(void)
{
	struct lws_client_connect_info i;

	if (make_context())
		return 1;

	interrupted	= 0;
	result		= 1;

	lws_snprintf(req_big, sizeof(req_big),
		     "GET /files/big.bin HTTP/1.1\x0d\x0a"
		     "Host: %s:%d\x0d\x0a"
		     "Connection: keep-alive\x0d\x0a"
		     "Accept: */*\x0d\x0a\x0d\x0a", g_server, g_port_plain);

	lws_snprintf(req_small, sizeof(req_small),
		     "GET /files/small.txt HTTP/1.1\x0d\x0a"
		     "Host: %s:%d\x0d\x0a"
		     "Connection: keep-alive\x0d\x0a"
		     "Accept: */*\x0d\x0a\x0d\x0a", g_server, g_port_plain);

	memset(&i, 0, sizeof(i));
	i.context		= cx;
	i.address		= g_server;
	i.port			= g_port_plain;
	i.method		= "RAW";
	i.protocol		= "defprot";
	i.local_protocol_name	= "lws-api-test-lwsws-uv-pl";

	lws_sul_schedule(cx, 0, &sul_watchdog, watchdog_cb,
			 55 * LWS_USEC_PER_SEC);

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: raw client connect failed\n", __func__);
		lws_context_destroy(cx);
		cx = NULL;

		return 1;
	}

	service_until_done();

	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_pl);
	if (cx)
		lws_context_destroy(cx);
	cx = NULL;

	return result;
}

static void
sigint_handler(int sig)
{
	(void)sig;
	interrupted = 1;
}

int
main(int argc, const char **argv)
{
	const char *p;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, r = 1;

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);

	if ((p = lws_cmdline_option(argc, argv, "--server")))
		g_server = p;
	if ((p = lws_cmdline_option(argc, argv, "-p")))
		g_port_tls = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--plain-port")))
		g_port_plain = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--evlib")))
		g_uv = !strcmp(p, "uv");

	p = lws_cmdline_option(argc, argv, "-t");
	if (!p || !g_port_tls || !g_port_plain) {
		lwsl_err("Usage: lws-api-test-lwsws-uv -t "
			 "<captcha|captcha-h2|pipeline|proxy|h3race|"
			 "quicabort> "
			 "--server <host> -p <tls port> "
			 "--plain-port <port> [--evlib uv|poll] [-d <level>]\n");

		return 1;
	}

	lwsl_user("LWS lwsws-uv api test: case '%s', %s loop, %s:%d (+%d)\n",
		  p, g_uv ? "libuv" : "poll", g_server, g_port_tls,
		  g_port_plain);

	/*
	 * The interceptor decision runs before the mount's protocol is bound,
	 * on whatever http role the peer arrived as, so the same sequence is
	 * run per role from its own ctest.
	 */
	if (!strcmp(p, "captcha")) {
		g_pin_family = 1;
		r = run_jobs(jobs_captcha, (int)LWS_ARRAY_SIZE(jobs_captcha),
			     "http/1.1", 1);
	} else
		if (!strcmp(p, "captcha-h2")) {
			g_pin_family = 1;
			r = run_jobs(jobs_captcha,
				     (int)LWS_ARRAY_SIZE(jobs_captcha), "h2",
				     1);
		}
	else
		if (!strcmp(p, "proxy"))
			r = run_jobs(jobs_proxy,
				     (int)LWS_ARRAY_SIZE(jobs_proxy),
				     "http/1.1", 1);
	else
		if (!strcmp(p, "h3race"))
			r = run_jobs(jobs_h3race,
				     (int)LWS_ARRAY_SIZE(jobs_h3race),
				     "http/1.1", 0);
	else
		if (!strcmp(p, "quicabort"))
			r = run_quicabort();
	else
		if (!strcmp(p, "pipeline"))
			r = run_pipeline();
	else {
		lwsl_err("%s: unknown case '%s'\n", __func__, p);

		return 1;
	}

	lwsl_user("Completed: %s\n", r ? "FAIL" : "PASS");

	return r;
}
