/*
 * lws api test: reverse-proxy forwarding of oversized headers
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * PURPOSE
 *
 * The h3 QPACK dynamic-table fixes let large browser headers that were
 * previously dropped during decode actually reach the ah intact.  That
 * exposed a second, latent limitation: the http / ws reverse-proxy header
 * forwarding copied each header through a fixed 1KB temp, so a legit
 * 1KB+ header (a browser's SSO cookie jar) was silently dropped on the
 * floor, failing proxied apps that depend on it with eg
 *
 *   proxy_header: unable to copy par hdr idx 26 (len 1070)
 *
 * (idx 26 = WSI_TOKEN_HTTP_COOKIE with the full header set enabled).
 *
 * proxy_header() now falls back to a right-sized heap temp when the
 * caller's stack temp is too small.  This test runs the real proxy
 * machinery in-process against a backend vhost through a proxying mount:
 *
 *  - "http-req": an http GET through the proxy carries a 1070-byte cookie;
 *    the backend must receive it whole and echoes it back as the body
 *    (request-side forwarding; the body must also come back exactly, with
 *    no stray bytes after it, which fences the proxy transaction end: it
 *    used to append a chunked terminator after complete content-length
 *    responses)
 *
 *  - "http-rsp": the same transaction's response carries a 1070-byte
 *    set-cookie header back through the proxy; the client must receive it
 *    intact (response-side forwarding, the second fixed 1KB temp)
 *
 *  - "ws-proxy": a ws upgrade through the proxying mount carries a
 *    1070-byte cookie; the backend ws server must see the whole cookie
 *    and echoes it back over the established ws (the production failure
 *    path through the lws-ws-proxy stack temp)
 *
 *  - "http-post0": a POST with "Content-Length: 0" and no body (what a
 *    browser's fetch(url, {method: 'POST'}) sends) through the proxying
 *    mount must reach the backend as a POST and get its 200 back.  The
 *    proxy used to try to stash the empty body notification on the onward
 *    connection's buflist, which refuses a NULL buffer, and so closed the
 *    browser side without ever sending the request on.
 *
 *  - "http-path": the http request's path and query carry percent-encoded
 *    spaces, a '&' and a '=' inside a value, and a '+'.  The proxy holds
 *    the DECODED uri, and used to splice it into the onward request line
 *    as it was, so "/echo/The Something" reached the backend as
 *    "/echo/The" and a decoded '&' split its value in two.  The backend
 *    must see the same decoded path and urlargs the proxy saw.
 *
 * Both the proxied parent wsi and the http onward client connection bind
 * to vhost protocols[0]; that protocol must pass everything through to
 * lws_callback_http_dummy(), where the actual proxying lives.  lwsws
 * plugin protocols do that implicitly; here "hdr-proxy-pass" exists to be
 * protocols[0] on the test vhosts.
 */

#include <libwebsockets.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* deliberately just over the 1KB fixed temps proxy_header() used to use */
#define BIG_HDR_LEN 1070

#define COOKIE_NAME   "ctest_session="
#define SETCOOKIE_VAL "ctest_setcookie="

/* what the client sends, and what the backend must decode it to */
#define REQ_PATH_ENC	"/echo/The%20Something%20Something%2Bx" \
			"?v=a%20b&w=x%26y%3Dz&p=1+2"
#define REQ_PATH_DEC	"echo/The Something Something+x"

enum test_state {
	ST_HTTP_CONN,		/* http transaction through the proxy */
	ST_WS_CONN,		/* ws upgrade through the proxy */
	ST_POST0,		/* empty-body POST through the proxy */
	ST_DONE,
};

struct pss {
	int echoed;		/* backend: ws cookie echo sent */
};

static struct lws_context *context;
static enum test_state state = ST_HTTP_CONN;
static int test_failures, watchdog_secs;

static char big_cookie[BIG_HDR_LEN + 1];	/* request side */
static char big_setcookie[BIG_HDR_LEN + 1];	/* response side */

static char rx_body[2 * BIG_HDR_LEN + 1];
static size_t rx_body_len;
static char rx_setcookie[BIG_HDR_LEN + 1];
static int rx_setcookie_len = -1;

static char ws_rx[BIG_HDR_LEN + 1];
static size_t ws_rx_len;

static char backend_ws_seen[BIG_HDR_LEN + 1];
static int backend_ws_seen_len = -1;

static struct lws_vhost *vh_proxy;
static int port_backend, port_proxy;
static int ws_stage_started;

static int
start_ws_connection(void);

static int
start_post0_connection(void);

static void
sul_watchdog_cb(lws_sorted_usec_list_t *sul)
{
	if (++watchdog_secs > 25) {
		lwsl_err("%s: timed out in state %d\n", __func__, state);
		test_failures++;
		state = ST_DONE;

		return;
	}

	lws_sul_schedule(context, 0, sul, sul_watchdog_cb, LWS_US_PER_SEC);
}

/*
 * This stands in for the browser side of the proxy: it is the client
 * protocol for the http GET and the ws upgrade through the proxying mount,
 * and adds the oversize cookie to its requests exactly like a browser with
 * a big cookie jar would.
 */

static int
callback_hdr_proxy_client(struct lws *wsi, enum lws_callback_reasons reason,
			  void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in, *end = (*p) + len;

		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_COOKIE,
						 (const unsigned char *)big_cookie,
						 (int)strlen(big_cookie),
						 p, end))
			return -1;
		break;
	}

	/* http response side: the headers the proxy sent us */

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		rx_setcookie_len = lws_hdr_copy(wsi, rx_setcookie,
						sizeof(rx_setcookie),
						WSI_TOKEN_HTTP_SET_COOKIE);
		if (rx_setcookie_len < 0)
			lwsl_err("%s: client: no set-cookie in response\n",
				 __func__);
		lws_client_http_body_pending(wsi, 1);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP: {
		static char buffer[4096 + LWS_PRE];
		char *px = buffer + LWS_PRE;
		int lenx = (int)sizeof(buffer) - LWS_PRE;

		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		break;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (rx_body_len + len > sizeof(rx_body) - 1) {
			lwsl_err("%s: http body too big\n", __func__);
			return -1;
		}
		memcpy(rx_body + rx_body_len, in, len);
		rx_body_len += len;
		rx_body[rx_body_len] = '\0';
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:

		/* "http-req": the backend saw the whole oversize cookie */

		if (rx_body_len != strlen(big_cookie) ||
		    strcmp(rx_body, big_cookie)) {
			lwsl_err("%s: http-req: backend received %zu bytes of "
				 "cookie, sent %zu\n", __func__, rx_body_len,
				 strlen(big_cookie));
			test_failures++;
		}

		/*
		 * "http-rsp": the oversize set-cookie survived the proxy
		 * response serialization
		 */

		if (rx_setcookie_len != (int)strlen(big_setcookie) ||
		    strcmp(rx_setcookie, big_setcookie)) {
			lwsl_err("%s: http-rsp: client received %d bytes of "
				 "set-cookie, sent %zu\n", __func__,
				 rx_setcookie_len, strlen(big_setcookie));
			test_failures++;
		}

		/*
		 * Move on to the ws upgrade scenario.  Only ever start it
		 * once: COMPLETED_CLIENT_HTTP can be delivered more than
		 * once for the same transaction (eg, again when the
		 * connection closes).
		 */

		if (!ws_stage_started) {
			ws_stage_started = 1;
			if (start_ws_connection()) {
				test_failures++;
				state = ST_DONE;
			}
		}
		break;

	/* ws side */

	case LWS_CALLBACK_CLIENT_RECEIVE:
		if (ws_rx_len + len > sizeof(ws_rx) - 1) {
			lwsl_err("%s: ws echo too big\n", __func__);
			test_failures++;
			state = ST_DONE;
			break;
		}
		memcpy(ws_rx + ws_rx_len, in, len);
		ws_rx_len += len;
		ws_rx[ws_rx_len] = '\0';

		if (!lws_is_final_fragment(wsi))
			break;

		/*
		 * "ws-proxy": the backend saw the whole oversize cookie
		 * through the ws proxy
		 */

		if (ws_rx_len != strlen(big_cookie) ||
		    strcmp(ws_rx, big_cookie)) {
			lwsl_err("%s: ws-proxy: backend received %zu bytes of "
				 "cookie, sent %zu\n", __func__, ws_rx_len,
				 strlen(big_cookie));
			test_failures++;
		}

		/* on to the empty-body POST */

		if (start_post0_connection()) {
			test_failures++;
			state = ST_DONE;
		}
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: client connection error: %s\n", __func__,
			 in ? (const char *)in : "(none)");
		test_failures++;
		state = ST_DONE;
		break;

	default:
		break;
	}

	return 0;
}

/*
 * "http-post0": the browser side of an empty POST, as fetch() sends it:
 * "Content-Length: 0" and nothing after the headers.
 */

static int post0_status;

static int
callback_hdr_proxy_post0(struct lws *wsi, enum lws_callback_reasons reason,
			 void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in, *end = (*p) + len;

		if (lws_add_http_header_content_length(wsi, 0, p, end))
			return -1;
		break;
	}

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		post0_status = (int)lws_http_client_http_response(wsi);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP: {
		static char buffer[1024 + LWS_PRE];
		char *px = buffer + LWS_PRE;
		int lenx = (int)sizeof(buffer) - LWS_PRE;

		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		break;
	}

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (state != ST_POST0)
			break;
		if (post0_status != HTTP_STATUS_OK) {
			lwsl_err("%s: http-post0: response status %d\n",
				 __func__, post0_status);
			test_failures++;
		}
		state = ST_DONE;
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: http-post0: connection error: %s\n", __func__,
			 in ? (const char *)in : "(none)");
		test_failures++;
		state = ST_DONE;
		break;

	default:
		break;
	}

	return 0;
}

/*
 * The far side of the proxy: an http endpoint that echoes the request
 * cookie back in the body while returning an oversize set-cookie header,
 * and a ws endpoint that captures the upgrade request's cookie while the
 * ah is still attached and echoes it back over the ws.
 */

static int
callback_hdr_echo_backend(struct lws *wsi, enum lws_callback_reasons reason,
			  void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	unsigned char buf[LWS_PRE + sizeof(big_setcookie) + 512],
		      *p = buf + LWS_PRE,
		      *end = p + sizeof(buf) - LWS_PRE;
	char seen[BIG_HDR_LEN + 1];
	int n;

	switch (reason) {

	case LWS_CALLBACK_HTTP:

		if (in && !strcmp((const char *)in, "post0")) {
			/* http-post0: it must have arrived as a POST */
			if (!lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI)) {
				lwsl_err("%s: backend: post0 not a POST\n",
					 __func__);
				test_failures++;
			}
			if (lws_return_http_status(wsi, HTTP_STATUS_OK, NULL))
				return 1;
			/* the body callbacks for the empty body follow */
			return 0;
		}

		/*
		 * http-path: the proxy must have re-encoded the decoded path
		 * and query for its onward request line, so we decode to
		 * exactly what the client encoded
		 */
		if (!in || strcmp((const char *)in, REQ_PATH_DEC)) {
			lwsl_err("%s: backend: path '%s', expected '%s'\n",
				 __func__, in ? (const char *)in : "(null)",
				 REQ_PATH_DEC);
			test_failures++;
		}

		{
			static const char * const exp[][2] = {
				{ "v", "a b" }, { "w", "x&y=z" }, { "p", "1 2" },
			};
			char v[64];
			size_t m;

			for (m = 0; m < LWS_ARRAY_SIZE(exp); m++) {
				v[0] = '\0';
				if (lws_get_urlarg_by_name_safe(wsi, exp[m][0],
								v, sizeof(v)) < 0 ||
				    strcmp(v, exp[m][1])) {
					lwsl_err("%s: backend: urlarg %s "
						 "'%s', expected '%s'\n",
						 __func__, exp[m][0], v,
						 exp[m][1]);
					test_failures++;
				}
			}
		}

		n = lws_hdr_copy(wsi, seen, sizeof(seen),
				 WSI_TOKEN_HTTP_COOKIE);
		if (n < 0) {
			lwsl_err("%s: backend: oversize cookie did not "
				 "survive to the backend ah\n", __func__);
			n = 0;
		}
		seen[n] = '\0';

		if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end))
			return 1;

		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_SET_COOKIE,
						 (const unsigned char *)big_setcookie,
						 (int)strlen(big_setcookie),
						 &p, end))
			return 1;

		if (lws_add_http_header_content_length(wsi, (lws_filepos_t)n,
						       &p, end))
			return 1;

		if (lws_finalize_http_header(wsi, &p, end))
			return 1;

		if (lws_write(wsi, buf + LWS_PRE,
			      lws_ptr_diff_size_t(p, buf + LWS_PRE),
			      LWS_WRITE_HTTP_HEADERS) < 0)
			return 1;

		/* the body is the cookie we received, verbatim */

		if (n) {
			memcpy(buf + LWS_PRE, seen, (size_t)n);
			if (lws_write(wsi, buf + LWS_PRE, (size_t)n,
				      LWS_WRITE_HTTP) < 0)
				return 1;
		}

		if (lws_http_transaction_completed(wsi))
			return -1;

		return 0;

	case LWS_CALLBACK_HTTP_BODY:
	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		/* http-post0: already answered at LWS_CALLBACK_HTTP */
		return 0;

	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:

		/* the upgrade request headers are in the ah right now */

		backend_ws_seen_len = lws_hdr_copy(wsi, backend_ws_seen,
						   sizeof(backend_ws_seen),
						   WSI_TOKEN_HTTP_COOKIE);
		return 0;	/* accept the subprotocol */

	case LWS_CALLBACK_ESTABLISHED:
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE: {
		const char *echo = backend_ws_seen_len > 0 ?
					 backend_ws_seen : "-";
		size_t el = backend_ws_seen_len > 0 ?
				 (size_t)backend_ws_seen_len : 1;

		if (pss->echoed)
			break;

		/*
		 * Echo what we got even when the cookie did not make it,
		 * so the client can mismatch immediately instead of waiting
		 * for timeouts
		 */

		memcpy(buf + LWS_PRE, echo, el);
		if (lws_write(wsi, buf + LWS_PRE, el, LWS_WRITE_TEXT) < 0)
			return -1;

		pss->echoed = 1;
		break;
	}

	default:
		break;
	}

	return 0;
}

/*
 * This is vhost protocols[0] on the test vhosts.  The proxied parent wsi
 * and the http proxy's onward client connection both bind here, so it has
 * to hand everything to lws_callback_http_dummy() where the proxying is
 * implemented, exactly like the protocol tables lwsws builds from plugin
 * protocols that chain their unhandled reasons to the dummy callback.
 */

static int
callback_hdr_proxy_pass(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{ "hdr-proxy-pass", callback_hdr_proxy_pass, 0, 0, 0, NULL, 0 },
	{ "hdr-echo", callback_hdr_echo_backend, sizeof(struct pss), 0, 0, NULL, 0 },
	{ "hdr-proxy-client", callback_hdr_proxy_client, 0, 0, 0, NULL, 0 },
	{ "hdr-proxy-post0", callback_hdr_proxy_post0, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static int
start_post0_connection(void)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_proxy;
	i.address		= "127.0.0.1";
	i.port			= port_proxy;
	i.path			= "/post0";
	i.host			= "127.0.0.1";
	i.method		= "POST";
	i.local_protocol_name	= "hdr-proxy-post0";

	state = ST_POST0;

	return lws_client_connect_via_info(&i) ? 0 : -1;
}

static int
start_ws_connection(void)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_proxy;
	i.address		= "127.0.0.1";
	i.port			= port_proxy;
	i.path			= "/ws";
	i.host			= "127.0.0.1";
	i.protocol		= "hdr-echo"; /* ws subprotocol, forwarded */
	i.local_protocol_name	= "hdr-proxy-client";

	state = ST_WS_CONN;

	return lws_client_connect_via_info(&i) ? 0 : -1;
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info, vi;
	struct lws_http_mount mount_backend, mount_proxy;
	struct lws_client_connect_info i;
	lws_sorted_usec_list_t sul;
	char origin[64];
	int n = 1;

	memset(&sul, 0, sizeof(sul));

	if (argc > 2 && !strcmp(argv[1], "-p"))
		/* adjacent block from the CI port allocator */
		port_backend = (int)atoi(argv[2]);

	port_proxy = port_backend + 1;

	if (port_backend < 2 || port_backend > 65534) {
		fprintf(stderr, "Usage: %s -p <base port>\n", argv[0]);

		return 1;
	}

	signal(SIGINT, sigint_handler);

	/* deterministic oversize header payloads, exactly BIG_HDR_LEN long */

	n = (int)strlen(COOKIE_NAME);
	memcpy(big_cookie, COOKIE_NAME, (size_t)n);
	memset(big_cookie + n, 'a', (size_t)(BIG_HDR_LEN - n));
	big_cookie[BIG_HDR_LEN] = '\0';

	n = (int)strlen(SETCOOKIE_VAL);
	memcpy(big_setcookie, SETCOOKIE_VAL, (size_t)n);
	memset(big_setcookie + n, 'b', (size_t)(BIG_HDR_LEN - n));
	big_setcookie[BIG_HDR_LEN] = '\0';

	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_USER, NULL);

	memset(&info, 0, sizeof(info));
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.protocols = protocols;
	/* the ahs on both sides must be able to hold the oversize headers */
	info.max_http_header_data = 4096;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");

		return 1;
	}

	/* the backend vhost serving /echo http and hdr-echo ws */

	memset(&mount_backend, 0, sizeof(mount_backend));
	mount_backend.mountpoint	= "/";
	mount_backend.mountpoint_len	= 1;
	mount_backend.protocol		= "hdr-echo";
	mount_backend.origin_protocol	= LWSMPRO_CALLBACK;

	memset(&vi, 0, sizeof(vi));
	vi.port		= port_backend;
	vi.protocols	= protocols;
	vi.mounts	= &mount_backend;
	if (!lws_create_vhost(context, &vi)) {
		lwsl_err("backend vhost init failed\n");
		goto bail;
	}

	/* the proxying vhost in front of it */

	lws_snprintf(origin, sizeof(origin), "127.0.0.1:%u/",
		     (unsigned int)port_backend);

	memset(&mount_proxy, 0, sizeof(mount_proxy));
	mount_proxy.mountpoint		= "/";
	mount_proxy.mountpoint_len	= 1;
	mount_proxy.origin		= origin;
	mount_proxy.origin_protocol	= LWSMPRO_HTTP;

	memset(&vi, 0, sizeof(vi));
	vi.port		= port_proxy;
	vi.protocols	= protocols;
	vi.mounts	= &mount_proxy;
	vh_proxy = lws_create_vhost(context, &vi);
	if (!vh_proxy) {
		lwsl_err("proxy vhost init failed\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul, sul_watchdog_cb, LWS_US_PER_SEC);

	/* stage 1: the http transaction through the proxy */

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_proxy;
	i.address		= "127.0.0.1";
	i.port			= port_proxy;
	i.path			= REQ_PATH_ENC;
	i.host			= "127.0.0.1";
	i.method		= "GET";
	i.local_protocol_name	= "hdr-proxy-client";

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("http client connect failed\n");
		goto bail;
	}

	while (state != ST_DONE && lws_service(context, 0) >= 0)
		;

	if (state != ST_DONE) /* loop exit requested before we finished */
		test_failures++;

	n = test_failures ? 1 : 0;

bail:
	lws_context_destroy(context);

	if (n)
		lwsl_user("api-test-proxy-hdr: FAILED\n");
	else
		lwsl_user("api-test-proxy-hdr: PASS\n");

	return n;
}
