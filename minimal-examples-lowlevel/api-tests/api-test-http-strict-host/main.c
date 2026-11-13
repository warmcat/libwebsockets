/*
 * lws-api-test-http-strict-host
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Fences LWS_SERVER_OPTION_VHOST_UPG_STRICT_HOST_CHECK: a vhost with it only
 * upgrades a connection whose Host names it, and its port.  A server vhost
 * called "strict.example.com" and clients in this process; each case is one
 * ws upgrade, accepted if the server answers 101.
 *
 * Over h1, from a raw client sending the request bytes itself:
 *
 *  - the vhost name and its port is accepted, in any case (RFC 3986 3.2.2)
 *
 *  - a prefix of the name (G-492), a longer name, another name, the name
 *    with a trailing dot, an IPv6 literal, or userinfo, is refused
 *
 *  - the right name with another port, no port (so 80), an empty port, port
 *    0, a port too big for 16 bits, even one that is the right port plus
 *    2^32, or a port with junk after it, is refused
 *
 *  - no Host, a Host too long for any host name, or two Host headers, is
 *    refused
 *
 * None of them may crash the server, eg, a sanitizer build (G-686).
 *
 * With --cert / --key, a TLS vhost called "localhost" with the option takes
 * ws over h2 and h3 streams, whose :authority is checked the same way (G-492),
 * and WebTransport sessions over h3, whose CONNECT's :authority is too
 * (G-693):
 *
 *  - "localhost" and its port is accepted, "localhos" and its port, or
 *    "localhost" with no port (so 443) or another port, is refused
 *
 * The h3 clients may not fall back to tcp, so an h3 case is decided on h3.  A
 * refused WebTransport CONNECT must be refused with the strict check's 421,
 * not for some other reason.
 */

#include <libwebsockets.h>
#include <string.h>

#if defined(LWS_WITH_TLS) && defined(LWS_ROLE_H2)
#define SHC_H2		/* we can test ws over h2 */
#if defined(LWS_ROLE_H3)
#define SHC_H3		/* ... and over h3 */
#if defined(LWS_ROLE_WT)
#define SHC_WT		/* ... and WebTransport over h3 */
#include <libwebsockets/lws-webtransport.h>
#endif
#endif
#endif

#define SHC_TIMEOUT_S		5
#define SHC_NAME		"strict.example.com"
#define SHC_H2_NAME		"localhost"

/* how the case's upgrade travels */
enum shc_via {
	SHC_V_H1,		/* ws upgrade from a raw h1 client */
	SHC_V_H2,		/* ws over an h2 stream */
	SHC_V_H3,		/* ws over an h3 stream */
	SHC_V_WT,		/* a WebTransport session over h3 */
};

/* what goes after the host name in the Host header */
enum shc_port {
	SHC_P_OWN,		/* ":" and the vhost's port */
	SHC_P_OTHER,		/* ":" and another port */
	SHC_P_WRAP,		/* ":" and the vhost's port + 2^32 */
	SHC_P_NONE,		/* nothing */
	SHC_P_LIT,		/* the literal .lit */
};

struct shc_case {
	const char		*label;
	const char		*name;	/* NULL: no Host header */
	const char		*lit;
	enum shc_port		port;
	char			hosts;	/* Host headers sent, if name */
	char			oversize;
	enum shc_via		via;
	char			want_ok;
};

static const struct shc_case shc_cases[] = {
	{ .label = "exact", .name = SHC_NAME, .hosts = 1, .want_ok = 1 },
	/* G-492: first, so it is seen even where a mismatch kills the server */
	{ .label = "prefix", .name = "strict.example.co", .hosts = 1 },
	{ .label = "other case", .name = "STRICT.Example.COM", .hosts = 1,
	  .want_ok = 1 },
	{ .label = "port + 2^32", .name = SHC_NAME, .port = SHC_P_WRAP,
	  .hosts = 1 },
	{ .label = "other name", .name = "evil.example", .hosts = 1 },
	{ .label = "longer name", .name = SHC_NAME ".evil.example",
	  .hosts = 1 },
	{ .label = "short prefix", .name = "s", .hosts = 1 },
	{ .label = "trailing dot", .name = SHC_NAME ".", .hosts = 1 },
	{ .label = "IPv6 literal", .name = "[::1]", .hosts = 1 },
	{ .label = "userinfo", .name = "x@" SHC_NAME, .hosts = 1 },
	{ .label = "other port", .name = SHC_NAME, .port = SHC_P_OTHER,
	  .hosts = 1 },
	{ .label = "no port", .name = SHC_NAME, .port = SHC_P_NONE,
	  .hosts = 1 },
	{ .label = "empty port", .name = SHC_NAME, .port = SHC_P_LIT,
	  .lit = ":", .hosts = 1 },
	{ .label = "port 0", .name = SHC_NAME, .port = SHC_P_LIT, .lit = ":0",
	  .hosts = 1 },
	{ .label = "port 65536", .name = SHC_NAME, .port = SHC_P_LIT,
	  .lit = ":65536", .hosts = 1 },
	{ .label = "port junk", .name = SHC_NAME, .port = SHC_P_LIT,
	  .lit = ":80x", .hosts = 1 },
	{ .label = "two ports", .name = SHC_NAME, .port = SHC_P_LIT,
	  .lit = ":80:80", .hosts = 1 },
	{ .label = "no Host" },
	{ .label = "oversize", .name = SHC_NAME, .hosts = 1, .oversize = 1 },
	{ .label = "two Hosts", .name = SHC_NAME, .hosts = 2 },
	{ .label = "exact, last", .name = SHC_NAME, .hosts = 1, .want_ok = 1 },
#if defined(SHC_H2)
	{ .label = "h2 exact", .name = SHC_H2_NAME, .via = SHC_V_H2,
	  .want_ok = 1 },
	{ .label = "h2 prefix", .name = "localhos", .via = SHC_V_H2 },
	{ .label = "h2 other port", .name = SHC_H2_NAME, .port = SHC_P_OTHER,
	  .via = SHC_V_H2 },
	{ .label = "h2 no port", .name = SHC_H2_NAME, .port = SHC_P_NONE,
	  .via = SHC_V_H2 },
	{ .label = "h2 exact, last", .name = SHC_H2_NAME, .via = SHC_V_H2,
	  .want_ok = 1 },
#endif
#if defined(SHC_H3)
	{ .label = "h3 exact", .name = SHC_H2_NAME, .via = SHC_V_H3,
	  .want_ok = 1 },
	{ .label = "h3 prefix", .name = "localhos", .via = SHC_V_H3 },
	{ .label = "h3 other port", .name = SHC_H2_NAME, .port = SHC_P_OTHER,
	  .via = SHC_V_H3 },
	{ .label = "h3 no port", .name = SHC_H2_NAME, .port = SHC_P_NONE,
	  .via = SHC_V_H3 },
	{ .label = "h3 exact, last", .name = SHC_H2_NAME, .via = SHC_V_H3,
	  .want_ok = 1 },
#endif
#if defined(SHC_WT)
	{ .label = "wt exact", .name = SHC_H2_NAME, .via = SHC_V_WT,
	  .want_ok = 1 },
	{ .label = "wt prefix", .name = "localhos", .via = SHC_V_WT },
	{ .label = "wt other port", .name = SHC_H2_NAME, .port = SHC_P_OTHER,
	  .via = SHC_V_WT },
	{ .label = "wt no port", .name = SHC_H2_NAME, .port = SHC_P_NONE,
	  .via = SHC_V_WT },
	{ .label = "wt exact, last", .name = SHC_H2_NAME, .via = SHC_V_WT,
	  .want_ok = 1 },
#endif
};

static struct lws_context *shc_cx;
static struct lws_vhost *shc_vh_cli;
static lws_sorted_usec_list_t shc_sul_next, shc_sul_watchdog;
static const char *shc_server = "localhost";
#if defined(SHC_H3)
/* the current h3 / wt case's client, while it exists, to dump if it stalls */
static struct lws *shc_cli_wsi;
#endif
static int shc_cur = -1, shc_port, shc_h2_port, shc_fails, shc_finished,
	   shc_case_done, shc_rx_len;
static char shc_rx[16];

static void
shc_next(lws_sorted_usec_list_t *sul);

static void
shc_fail(const char *why)
{
	lwsl_err("case %d (%s): FAIL: %s\n", shc_cur, shc_cases[shc_cur].label,
		 why);
	shc_fails++;
}

static int
shc_is_cur(struct lws *wsi)
{
	return lws_get_opaque_user_data(wsi) ==
					(void *)(intptr_t)(shc_cur + 1) &&
	       !shc_case_done;
}

/* the case ended: upgraded, or not */

static void
shc_case_end(int upgraded)
{
	const struct shc_case *c = &shc_cases[shc_cur];

	shc_case_done = 1;
	lwsl_user("case %d (%s): %s\n", shc_cur, c->label,
		  upgraded ? "upgraded" : "refused");
	if (upgraded != c->want_ok)
		shc_fail(upgraded ? "upgraded, should be refused" :
				    "refused, should be upgraded");

	lws_sul_cancel(&shc_sul_watchdog);
	lws_sul_schedule(shc_cx, 0, &shc_sul_next, shc_next, 1);
}

/* the authority the case sends, for the vhost listening on port */

static void
shc_authority(const struct shc_case *c, int port, char *buf, size_t len)
{
	switch (c->port) {
	case SHC_P_OWN:
		lws_snprintf(buf, len, "%s:%d", c->name, port);
		break;
	case SHC_P_OTHER:
		lws_snprintf(buf, len, "%s:%d", c->name,
			     port == 65535 ? port - 1 : port + 1);
		break;
	case SHC_P_WRAP:
		lws_snprintf(buf, len, "%s:%llu", c->name,
			     (unsigned long long)port + (1ull << 32));
		break;
	case SHC_P_NONE:
		lws_strncpy(buf, c->name, len);
		break;
	case SHC_P_LIT:
		lws_snprintf(buf, len, "%s%s", c->name, c->lit);
		break;
	}
}

/* the h1 client: a raw connection writing the upgrade request itself */

static int
shc_raw_send(struct lws *wsi)
{
	const struct shc_case *c = &shc_cases[shc_cur];
	char buf[LWS_PRE + 1024], *start = buf + LWS_PRE, *p = start,
	     *end = buf + sizeof(buf), host[384];
	int n;

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  "GET / HTTP/1.1\r\n");

	if (c->oversize) {
		/* longer than the 253 any DNS name can be */
		memset(host, 'a', 300);
		lws_strncpy(host + 300, "." SHC_NAME, sizeof(host) - 300);
	} else if (c->name)
		shc_authority(c, shc_port, host, sizeof(host));

	for (n = 0; c->name && n < c->hosts; n++)
		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
				  "Host: %s\r\n", host);

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  "Upgrade: websocket\r\n"
			  "Connection: Upgrade\r\n"
			  "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
			  "Sec-WebSocket-Version: 13\r\n"
			  "Sec-WebSocket-Protocol: shc-ws\r\n\r\n");

	n = lws_ptr_diff(p, start);

	return lws_write(wsi, (unsigned char *)start, (size_t)n,
			 LWS_WRITE_RAW) != n;
}

static int
shc_raw_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	   void *in, size_t len)
{
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_RAW_CONNECTED:
		if (shc_is_cur(wsi))
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!shc_is_cur(wsi))
			return -1;
		if (shc_raw_send(wsi))
			return -1;
		break;

	case LWS_CALLBACK_RAW_RX:
		if (!shc_is_cur(wsi))
			return -1;
		n = sizeof(shc_rx) - 1 - (size_t)shc_rx_len;
		if (n > len)
			n = len;
		memcpy(shc_rx + shc_rx_len, in, n);
		shc_rx_len += (int)n;
		shc_rx[shc_rx_len] = '\0';

		if (shc_rx_len < 12)
			break;

		/* we have the status line's status: that decides it */
		shc_case_end(!strncmp(shc_rx, "HTTP/1.1 101", 12));

		return -1;

	case LWS_CALLBACK_RAW_CLOSE:
		if (shc_is_cur(wsi))
			/* closed without telling us it upgraded */
			shc_case_end(0);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (shc_is_cur(wsi)) {
			shc_fail(in ? (const char *)in : "connection error");
			shc_case_end(0);
		}
		break;

#if defined(SHC_H3)
	case LWS_CALLBACK_WSI_DESTROY:
		/* every wsi of the client vhost comes here, its protocols[0] */
		if (wsi == shc_cli_wsi)
			shc_cli_wsi = NULL;
		break;
#endif

	default:
		break;
	}

	return 0;
}

#if defined(SHC_H2)

/* the h2 / h3 client: a ws client whose connection is a stream */

static int
shc_h2_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	  void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		if (!shc_is_cur(wsi))
			return -1;
		if (lws_get_network_wsi(wsi) == wsi)
			shc_fail("ws connection not on a stream");
		shc_case_end(1);
		/* done with it: close it once we have returned */
		lws_set_timeout(wsi, PENDING_TIMEOUT_USER_OK, LWS_TO_KILL_ASYNC);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLIENT_CLOSED:
		if (shc_is_cur(wsi))
			shc_case_end(0);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

#endif

#if defined(SHC_WT)

/* the wt client: its CONNECT's 200 makes the stream a session */

static int
shc_wt_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	  void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (!lws_wt_is_session(wsi) || !shc_is_cur(wsi))
			break;
		shc_case_end(1);
		/* done with it: close it once we have returned */
		lws_set_timeout(wsi, PENDING_TIMEOUT_USER_OK, LWS_TO_KILL_ASYNC);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (!shc_is_cur(wsi))
			break;
		/* refused, and by the strict check, not for another reason */
		if (!shc_cases[shc_cur].want_ok &&
		    (!in || !strstr((const char *)in, "refused 421")))
			shc_fail("not refused with 421");
		shc_case_end(0);
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (shc_is_cur(wsi))
			shc_case_end(0);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* a WebTransport CONNECT to /wt on the TLS vhost gets a "shc-wt" session */

static const struct lws_protocol_vhost_options shc_pvo_wt_opt = {
	NULL, NULL, "webtransport", ""
};

static const struct lws_protocol_vhost_options shc_pvo_wt = {
	NULL, &shc_pvo_wt_opt, "shc-wt", ""
};

static const struct lws_http_mount shc_mount_wt = {
	.mountpoint		= "/wt",
	.origin			= "shc-wt",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 3,
};

#endif

static const struct lws_protocols shc_protocols_srv[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	/* whether it upgrades is all we look at */
	{ "shc-ws", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
#if defined(SHC_WT)
	{ "shc-wt", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
#endif
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols shc_protocols_cli[] = {
	{ "shc-raw", shc_raw_cb, 0, 0, 0, NULL, 0 },
#if defined(SHC_H2)
	{ "shc-h2", shc_h2_cb, 0, 0, 0, NULL, 0 },
#endif
#if defined(SHC_WT)
	/* lws asks for a wt session for a client of a protocol so named */
	{ "webtransport", shc_wt_cb, 0, 0, 0, NULL, 0 },
#endif
	LWS_PROTOCOL_LIST_TERM
};

static void
shc_watchdog(lws_sorted_usec_list_t *sul)
{
	shc_fail("timed out");
#if defined(SHC_H3)
	/* our deadline comes before lws' own: say where the client got to */
	if (shc_cli_wsi)
		lws_quic_dump(shc_cli_wsi);
#endif
	shc_case_done = 1;
	lws_sul_schedule(shc_cx, 0, &shc_sul_next, shc_next, 1);
}

static void
shc_next(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	const struct shc_case *c;
#if defined(SHC_H2)
	char auth[128];
#endif

	do {
		if (++shc_cur == (int)LWS_ARRAY_SIZE(shc_cases)) {
			shc_finished = 1;
			lws_cancel_service(shc_cx);
			return;
		}
		c = &shc_cases[shc_cur];
		/* no TLS vhost unless we were given its cert */
	} while (c->via != SHC_V_H1 && !shc_h2_port);

	shc_case_done = 0;
	shc_rx_len = 0;

	memset(&i, 0, sizeof(i));
	i.context		= shc_cx;
	i.vhost			= shc_vh_cli;
	i.address		= shc_server;
	i.opaque_user_data	= (void *)(intptr_t)(shc_cur + 1);

	if (c->via == SHC_V_H1) {
		i.host		= shc_server;
		i.port		= shc_port;
		i.method	= "RAW";
		i.protocol	= "shc-raw";
		i.local_protocol_name = "shc-raw";
	}
#if defined(SHC_H2)
	else {
		shc_authority(c, shc_h2_port, auth, sizeof(auth));
		i.host		= auth;
		i.origin	= auth;
		i.port		= shc_h2_port;
		i.path		= "/";
		i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
		i.alpn		= "h2";
		i.protocol	= "shc-ws";
		i.local_protocol_name = "shc-h2";
		if (c->via != SHC_V_H2) {
			i.alpn	= "h3";
			/* decided on h3, not by a fallback to tcp */
			i.disable_h3_fallback = 1;
		}
#if defined(SHC_WT)
		if (c->via == SHC_V_WT) {
			i.path	= "/wt";
			i.protocol = "webtransport";
			i.local_protocol_name = NULL;
		}
#endif
	}
#endif

	lws_sul_schedule(shc_cx, 0, &shc_sul_watchdog, shc_watchdog,
			 SHC_TIMEOUT_S * LWS_US_PER_SEC);

#if defined(SHC_H3)
	shc_cli_wsi = NULL;
	if (c->via == SHC_V_H3 || c->via == SHC_V_WT)
		i.pwsi = &shc_cli_wsi;
#endif

	if (!lws_client_connect_via_info(&i)) {
		shc_fail("connect failed");
		shc_case_done = 1;
		lws_sul_cancel(&shc_sul_watchdog);
		lws_sul_schedule(shc_cx, 0, &shc_sul_next, shc_next, 1);
	}
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p, *cert, *key;
	struct lws_vhost *vh;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* servers and clients in one process: don't budget fds */
	info.fd_limit_per_thread = 0;
	info.options |= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
			LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	p = lws_cmdline_option(argc, argv, "--server");
	if (p)
		shc_server = p;
	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");

	lwsl_user("LWS API selftest: strict Host check on ws upgrade\n");

	shc_cx = lws_create_context(&info);
	if (!shc_cx) {
		lwsl_err("%s: context creation failed\n", __func__);
		return 1;
	}

	info.port = 0;
	info.protocols = shc_protocols_srv;
	info.vhost_name = SHC_NAME;
	info.options |= LWS_SERVER_OPTION_VHOST_UPG_STRICT_HOST_CHECK;
	vh = lws_create_vhost(shc_cx, &info);
	if (!vh)
		goto bail;
	shc_port = lws_get_vhost_listen_port(vh);

#if defined(SHC_H2)
	if (cert && key) {
		info.vhost_name = SHC_H2_NAME;
		info.ssl_cert_filepath = cert;
		info.ssl_private_key_filepath = key;
#if defined(SHC_H3)
		/* offer h3 as well: a tls vhost serves it on the same port */
		info.alpn = "h2,http/1.1,h3";
#endif
#if defined(SHC_WT)
		info.pvo = &shc_pvo_wt;
		info.mounts = &shc_mount_wt;
#endif
		vh = lws_create_vhost(shc_cx, &info);
		if (!vh)
			goto bail;
		shc_h2_port = lws_get_vhost_listen_port(vh);
		info.ssl_cert_filepath = NULL;
		info.ssl_private_key_filepath = NULL;
		info.alpn = NULL;
		info.pvo = NULL;
		info.mounts = NULL;
	} else
		lwsl_user("no --cert / --key: skipping the h2, h3 and wt "
			  "cases\n");
#else
	(void)cert;
	(void)key;
#endif

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = shc_protocols_cli;
	info.vhost_name = "shc-cli";
	info.options &= ~(uint64_t)LWS_SERVER_OPTION_VHOST_UPG_STRICT_HOST_CHECK;
	shc_vh_cli = lws_create_vhost(shc_cx, &info);
	if (!shc_vh_cli)
		goto bail;

	lws_sul_schedule(shc_cx, 0, &shc_sul_next, shc_next, 1);

	while (n >= 0 && !shc_finished)
		n = lws_service(shc_cx, 0);

	lws_sul_cancel(&shc_sul_watchdog);
	lws_sul_cancel(&shc_sul_next);
	lws_context_destroy(shc_cx);

	if (!shc_finished) {
		lwsl_err("%s: service loop ended early\n", __func__);
		return 1;
	}

	lwsl_user("Completed: %s (%d failed)\n", shc_fails ? "FAIL" : "PASS",
		  shc_fails);

	return !!shc_fails;

bail:
	lwsl_err("%s: setup failed\n", __func__);
	lws_context_destroy(shc_cx);

	return 1;
}
