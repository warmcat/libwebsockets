/*
 * lws-api-test-http-origin
 *
 * This file is made available under the Creative Commons CC0 1.0 Universal
 * Public Domain Dedication.
 *
 * Fences lws_http_origin_check(), the check a ws upgrade or POST authorized
 * by an ambient credential (a session cookie) uses to refuse requests caused
 * by another site's page, against real request headers: a server vhost and a
 * client in this process, the client sending each case's Host and Origin
 * header(s) and the server deciding the case from them.
 *
 * The contracts fenced:
 *
 *  - the Origin must be https://<Host>, or http://<Host> since this server is
 *    not itself TLS, compared whole and case-insensitively: another host, a
 *    sibling or a lookalike suffix, another port, another scheme, a path, or
 *    "null" is refused;
 *
 *  - origins in the allow list are accepted, matched whole;
 *
 *  - no Origin is accepted unless LWS_HOC_REQUIRE_ORIGIN, but an Origin that
 *    is too long to copy, or repeated, is refused, never taken for "none".
 */

#include <libwebsockets.h>
#include <string.h>

#define HOG_TIMEOUT_S		5

struct hog_case {
	const char		*label;
	const char		*host;
	const char		*origin[2];	/* each non-NULL one is sent */
	const char		*allow;
	unsigned int		flags;
	int			want_refused;
};

/* longer than any real origin: must be refused, not taken for absent */
#define HOG_LONG_HOST \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

static const struct hog_case hog_cases[] = {
	{ .label = "no Origin", .host = "example.com" },
	{ .label = "no Origin, required", .host = "example.com",
	  .flags = LWS_HOC_REQUIRE_ORIGIN, .want_refused = 1 },
	{ .label = "https own host", .host = "example.com",
	  .origin = { "https://example.com" } },
	{ .label = "http own host, not TLS here", .host = "example.com",
	  .origin = { "http://example.com" } },
	{ .label = "own host, other case", .host = "example.com",
	  .origin = { "https://Example.COM" } },
	{ .label = "own host and port", .host = "example.com:7681",
	  .origin = { "https://example.com:7681" } },
	{ .label = "other host", .host = "example.com",
	  .origin = { "https://evil.example" }, .want_refused = 1 },
	{ .label = "sibling host", .host = "example.com",
	  .origin = { "https://user.example.com" }, .want_refused = 1 },
	{ .label = "lookalike suffix", .host = "example.com",
	  .origin = { "https://example.com.evil.example" },
	  .want_refused = 1 },
	{ .label = "truncated host", .host = "example.com",
	  .origin = { "https://example.co" }, .want_refused = 1 },
	{ .label = "other port", .host = "example.com",
	  .origin = { "https://example.com:8443" }, .want_refused = 1 },
	{ .label = "path after host", .host = "example.com",
	  .origin = { "https://example.com/" }, .want_refused = 1 },
	{ .label = "other scheme", .host = "example.com",
	  .origin = { "ftp://example.com" }, .want_refused = 1 },
	{ .label = "null", .host = "example.com", .origin = { "null" },
	  .want_refused = 1 },
	{ .label = "allow list", .host = "example.com",
	  .origin = { "https://b.example:8443" },
	  .allow = "https://a.example, https://b.example:8443" },
	{ .label = "allow list, other case", .host = "example.com",
	  .origin = { "https://A.example" },
	  .allow = "https://a.example,https://b.example:8443" },
	{ .label = "allow list matches whole", .host = "example.com",
	  .origin = { "https://b.example" },
	  .allow = "https://a.example, https://b.example:8443",
	  .want_refused = 1 },
	{ .label = "allow list does not drop own host", .host = "example.com",
	  .origin = { "https://example.com" }, .allow = "https://a.example" },
	{ .label = "too long is not absent", .host = "example.com",
	  .origin = { "https://" HOG_LONG_HOST }, .want_refused = 1 },
	{ .label = "repeated Origin", .host = "example.com",
	  .origin = { "https://example.com", "https://example.com" },
	  .want_refused = 1 },
};

static struct lws_context *hog_cx;
static lws_sorted_usec_list_t hog_sul_next, hog_sul_watchdog;
static const char *hog_server = "localhost";
static int hog_cur = -1, hog_port, hog_fails, hog_finished, hog_answered,
	   hog_case_done;

static void
hog_fail(const char *why)
{
	lwsl_err("case %d (%s): FAIL: %s\n", hog_cur, hog_cases[hog_cur].label,
		 why);
	hog_fails++;
}

/* the server half: decide the case from the request's headers */

static int
hog_srv_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	   void *in, size_t len)
{
	uint8_t hb[LWS_PRE + 256], *start = &hb[LWS_PRE], *p = start,
		*end = &hb[sizeof(hb) - 1];
	const struct hog_case *c;
	int refused;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		if (hog_cur >= 0 && hog_cur < (int)LWS_ARRAY_SIZE(hog_cases)) {
			c = &hog_cases[hog_cur];
			refused = !!lws_http_origin_check(wsi, c->allow,
							  c->flags);
			if (refused != c->want_refused)
				hog_fail(refused ? "refused" : "accepted");
			hog_answered++;
		}

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain", 0, &p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		return lws_http_transaction_completed(wsi) ? -1 : 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
hog_next(lws_sorted_usec_list_t *sul);

static void
hog_case_end(struct lws *wsi, const char *why)
{
	if (lws_get_opaque_user_data(wsi) != (void *)(intptr_t)(hog_cur + 1) ||
	    hog_case_done)
		return; /* a late event from an earlier case */

	hog_case_done = 1;
	if (why)
		hog_fail(why);
	else if (hog_answered != 1)
		hog_fail("server did not see the request");

	lws_sul_cancel(&hog_sul_watchdog);
	lws_sul_schedule(hog_cx, 0, &hog_sul_next, hog_next, 1);
}

static int
hog_cli_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	   void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in, *end = (*p) + len;
		const struct hog_case *c;
		size_t n;

		if (lws_get_opaque_user_data(wsi) !=
					(void *)(intptr_t)(hog_cur + 1))
			return -1;
		c = &hog_cases[hog_cur];

		for (n = 0; n < LWS_ARRAY_SIZE(c->origin); n++)
			if (c->origin[n] &&
			    lws_add_http_header_by_token(wsi, WSI_TOKEN_ORIGIN,
					(const unsigned char *)c->origin[n],
					(int)strlen(c->origin[n]), p, end))
				return -1;
		break;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP: {
		char buf[LWS_PRE + 256], *px = buf + LWS_PRE;
		int lenx = sizeof(buf) - LWS_PRE;

		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;

		return 0;
	}

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		hog_case_end(wsi, NULL);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		hog_case_end(wsi, in ? (const char *)in : "connection error");
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		hog_case_end(wsi, "closed before completion");
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols hog_protocols_srv[] = {
	{ "hog-srv", hog_srv_cb, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols hog_protocols_cli[] = {
	{ "hog-cli", hog_cli_cb, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
hog_watchdog(lws_sorted_usec_list_t *sul)
{
	hog_fail("timed out");
	hog_case_done = 1;
	lws_sul_schedule(hog_cx, 0, &hog_sul_next, hog_next, 1);
}

static void
hog_next(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	if (++hog_cur == (int)LWS_ARRAY_SIZE(hog_cases)) {
		hog_finished = 1;
		lws_cancel_service(hog_cx);
		return;
	}

	hog_answered = 0;
	hog_case_done = 0;

	memset(&i, 0, sizeof(i));
	i.context		= hog_cx;
	i.vhost			= lws_get_vhost_by_name(hog_cx, "hog-cli");
	i.address		= hog_server;
	i.host			= hog_cases[hog_cur].host;
	i.port			= hog_port;
	i.path			= "/";
	i.method		= "GET";
	i.protocol		= hog_protocols_cli[0].name;
	i.local_protocol_name	= hog_protocols_cli[0].name;
	i.opaque_user_data	= (void *)(intptr_t)(hog_cur + 1);

	lws_sul_schedule(hog_cx, 0, &hog_sul_watchdog, hog_watchdog,
			 HOG_TIMEOUT_S * LWS_US_PER_SEC);

	if (!lws_client_connect_via_info(&i)) {
		hog_fail("connect failed");
		hog_case_done = 1;
		lws_sul_cancel(&hog_sul_watchdog);
		lws_sul_schedule(hog_cx, 0, &hog_sul_next, hog_next, 1);
	}
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* a server and a client in one process: don't budget fds */
	info.fd_limit_per_thread = 0;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	p = lws_cmdline_option(argc, argv, "--server");
	if (p)
		hog_server = p;

	lwsl_user("LWS API selftest: lws_http_origin_check()\n");

	hog_cx = lws_create_context(&info);
	if (!hog_cx) {
		lwsl_err("%s: context creation failed\n", __func__);
		return 1;
	}

	info.port = 0;
	info.protocols = hog_protocols_srv;
	info.vhost_name = "hog-srv";
	vh = lws_create_vhost(hog_cx, &info);
	if (!vh)
		goto bail;
	hog_port = lws_get_vhost_listen_port(vh);

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = hog_protocols_cli;
	info.vhost_name = "hog-cli";
	if (!lws_create_vhost(hog_cx, &info))
		goto bail;

	lws_sul_schedule(hog_cx, 0, &hog_sul_next, hog_next, 1);

	while (n >= 0 && !hog_finished)
		n = lws_service(hog_cx, 0);

	lws_sul_cancel(&hog_sul_watchdog);
	lws_sul_cancel(&hog_sul_next);
	lws_context_destroy(hog_cx);

	if (!hog_finished) {
		lwsl_err("%s: service loop ended early\n", __func__);
		return 1;
	}

	lwsl_user("Completed: %s (%d of %d cases failed)\n",
		  hog_fails ? "FAIL" : "PASS", hog_fails,
		  (int)LWS_ARRAY_SIZE(hog_cases));

	return !!hog_fails;

bail:
	lwsl_err("%s: setup failed\n", __func__);
	lws_context_destroy(hog_cx);

	return 1;
}
