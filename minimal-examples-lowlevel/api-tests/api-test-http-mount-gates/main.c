/*
 * lws-api-test-http-mount-gates
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A mount's gates, its interceptors, basic auth and access rights, are met by
 * every request for a path in it, whatever else the request says about
 * itself, and whatever routing choice is made about who serves it.  And a
 * mount whose gates would not be applied as configured is refused when the
 * vhost is created, rather than being served open.
 *
 * A raw client in the same process makes h1 requests and ws upgrades, and
 * checks the status each is answered with.  The gate is a test interceptor,
 * "gk", that lets a request through only if it has the cookie "gk=ok", and
 * answers 403 itself otherwise (an upgrade it would not let through is
 * refused 401 by lws).
 *
 *  - a ws upgrade to a no_ws_upgrades mount's path meets that mount's gates,
 *    though the mount around it serves it
 *
 *  - a ws protocol that a gated mount serves its path with is not bound by an
 *    upgrade whose path meets no gates; it is through a gated path, and a
 *    protocol that declares it vets its own sessions
 *    (lws_vhost_protocol_self_gated()) is bound anywhere
 *
 *  - a mountpoint ending in '/' covers the paths below it
 *
 *  - a "gzip://" mount listed before a more specific one inside it does not
 *    hide it
 *
 *  - LWSAUTHM_BASIC_AUTH_CALLBACK credentials are verified by the mount's own
 *    protocol, not whatever the connection is bound to (the vhost's first
 *    protocol here, which would accept anything)
 *
 *  - a callback mount's access rights (auth_mask) are asked for a ws upgrade
 *    to its path too
 *
 * and lws_create_vhost() refuses, and lws_vhost_set_mounts() too:
 *
 *  - an interceptor_path that is no mount's mountpoint
 *  - an interceptor chain that loops
 *  - basic auth on a CONNECT mount, and an interceptor on a "gzip://" mount
 *  - access rights on a mount that is not a callback mount
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define GK_OK		"Cookie: gk=ok\r\n"
#define AR_OK		"Cookie: ar=ok\r\n"
#define BA_GOOD		"Authorization: Basic dTpw\r\n"	/* u:p */
#define BA_BAD		"Authorization: Basic eDp5\r\n"	/* x:y */

static const struct gcase {
	const char	*name;
	const char	*path;
	const char	*ws;		/* NULL, or the subprotocol to ask for */
	const char	*extra;		/* more request headers */
	int		status;		/* expected */
	int		basic_auth;	/* needs LWS_WITH_HTTP_BASIC_AUTH */
} cases[] = {
	{ "ws to a no_ws_upgrades mount's path, no cookie",
	  "/nows/x", "app-ws", "", 401, 0 },
	{ "ws to a no_ws_upgrades mount's path, cookie",
	  "/nows/x", "app-ws", GK_OK, 101, 0 },
	{ "ws for a gated mount's protocol, ungated path",
	  "/", "admin-ws", "", 400, 0 },
	{ "ws for a gated mount's protocol, its own path",
	  "/admin", "admin-ws", GK_OK, 101, 0 },
	{ "ws for a gated mount's protocol, another gated path",
	  "/nows/x", "admin-ws", GK_OK, 101, 0 },
	{ "ws for a self-gated protocol of a gated mount, ungated path",
	  "/", "self-ws", "", 101, 0 },
	{ "http below a mountpoint ending in /, no cookie",
	  "/slash/x", NULL, "", 403, 0 },
	{ "http below a mountpoint ending in /, cookie",
	  "/slash/x", NULL, GK_OK, 200, 0 },
	{ "http to a mount listed after a gzip:// one, no cookie",
	  "/nm/deep/x", NULL, "", 403, 0 },
	{ "http to a mount's basic auth callback, wrong credentials",
	  "/ba", NULL, BA_BAD, 401, 1 },
	{ "http to a mount's basic auth callback, right credentials",
	  "/ba", NULL, BA_GOOD, 200, 1 },
	{ "ws to a mount with access rights, without them",
	  "/ar", "app-ws", "", 401, 0 },
	{ "ws to a mount with access rights, with them",
	  "/ar", "app-ws", AR_OK, 101, 0 },
	{ "http to a mount with access rights, without them",
	  "/ar", NULL, "", 401, 0 },
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_timeout;
static const char *server_addr = "127.0.0.1";
static int port, cur = -1, failed;

/* what the client heard for the current case */
static struct {
	char		rx[512];
	size_t		rx_len;
	int		done;
} cli;

static int
has_cookie(struct lws *wsi, const char *want)
{
	char buf[128];

	return lws_hdr_copy(wsi, buf, sizeof(buf), WSI_TOKEN_HTTP_COOKIE) > 0 &&
	       strstr(buf, want);
}

static int
answer(struct lws *wsi, unsigned int status)
{
	if (lws_return_http_status(wsi, status, NULL))
		return -1;

	return lws_http_transaction_completed(wsi) ? -1 : 0;
}

/*
 * The vhost's first protocol, serving what no mount does.  If asked, it would
 * accept any basic auth credentials.
 */

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	      void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_VERIFY_BASIC_AUTHORIZATION:
		return 1;
	case LWS_CALLBACK_HTTP:
		return answer(wsi, HTTP_STATUS_NOT_FOUND);
	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* the gate: diverts the request to itself unless it has "gk=ok" */

static int
callback_gk(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	    void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_HTTP_INTERCEPTOR_CHECK:
		return !has_cookie(wsi, "gk=ok");
	case LWS_CALLBACK_HTTP:
		return answer(wsi, HTTP_STATUS_FORBIDDEN);
	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* the apps behind the gates: http answered 200, ws upgrades accepted */

static int
callback_app(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		/* "self-ws" vets its own sessions, and says so */
		if (!strcmp(lws_get_protocol(wsi)->name, "self-ws") &&
		    lws_vhost_protocol_self_gated(lws_get_vhost(wsi),
						  lws_get_protocol(wsi)))
			return -1;
		break;
	case LWS_CALLBACK_VERIFY_BASIC_AUTHORIZATION:
		return len == 3 && !memcmp(in, "u:p", 3);
	case LWS_CALLBACK_HTTP:
		return answer(wsi, HTTP_STATUS_OK);
	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * "ar" decides its mount's access rights.  For an upgrade, it is asked before
 * any protocol is bound for it, with no pss.
 */

static int
callback_ar(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	    void *in, size_t len)
{
	if (reason == LWS_CALLBACK_CHECK_ACCESS_RIGHTS)
		return !has_cookie(wsi, "ar=ok");

	return callback_app(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "http",	callback_http, 0, 0, 0, NULL, 0 },
	{ "gk",		callback_gk,   0, 0, 0, NULL, 0 },
	{ "app-ws",	callback_app,  0, 0, 0, NULL, 0 },
	{ "admin-ws",	callback_app,  0, 0, 0, NULL, 0 },
	{ "self-ws",	callback_app,  0, 0, 0, NULL, 0 },
	{ "ba",		callback_app,  0, 0, 0, NULL, 0 },
	{ "ar",		callback_ar,   0, 0, 0, NULL, 0 },
	{ "page",	callback_app,  0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

#define CB_MOUNT(_name, _next, _mp, _prot) \
	static struct lws_http_mount _name = { \
		.mount_next		= _next, \
		.mountpoint		= _mp, \
		.protocol		= _prot, \
		.origin_protocol	= LWSMPRO_CALLBACK, \
		.mountpoint_len		= sizeof(_mp) - 1, \
	}

CB_MOUNT(m_ar,		NULL,		"/ar",		"ar");
CB_MOUNT(m_ba,		&m_ar,		"/ba",		"ba");
CB_MOUNT(m_slash,	&m_ba,		"/slash/",	"page");
CB_MOUNT(m_self,	&m_slash,	"/self",	"self-ws");
CB_MOUNT(m_admin,	&m_self,	"/admin",	"admin-ws");
CB_MOUNT(m_nows,	&m_admin,	"/nows",	"page");
CB_MOUNT(m_gk,		&m_nows,	"/gk",		"gk");
CB_MOUNT(m_deep,	&m_gk,		"/nm/deep",	"page");

/* listed first, so the old matching stopped at it for "/nm/deep/x" */
static struct lws_http_mount m_nomount = {
	.mount_next		= &m_deep,
	.mountpoint		= "/nm",
	.origin			= "gzip",
	.origin_protocol	= LWSMPRO_NO_MOUNT,
	.mountpoint_len		= 3,
};

/* mounts the vhost must be refused for */

CB_MOUNT(b_gk,		NULL,		"/gk",		"gk");
CB_MOUNT(b_nonesuch,	&b_gk,		"/a",		"page");
CB_MOUNT(b_loop2,	&b_gk,		"/l2",		"gk");
CB_MOUNT(b_loop1,	&b_loop2,	"/l1",		"gk");
CB_MOUNT(b_ar_file,	NULL,		"/f",		"ar");

static struct lws_http_mount b_connect = {
	.mountpoint		= "example.com:443",
	.protocol		= "http",
	.origin_protocol	= LWSMPRO_CONNECT,
	.mountpoint_len		= 15,
};

static struct lws_http_mount b_nomount = {
	.mount_next		= &b_gk,
	.mountpoint		= "/z",
	.origin			= "gzip",
	.origin_protocol	= LWSMPRO_NO_MOUNT,
	.mountpoint_len		= 2,
};

static void
next_case(lws_sorted_usec_list_t *sul);

static void
case_judge(void)
{
	const struct gcase *c = &cases[cur];
	int status = 0;

	if (cli.done)
		return;
	cli.done = 1;

	cli.rx[cli.rx_len] = '\0';
	if (!strncmp(cli.rx, "HTTP/1.1 ", 9))
		status = atoi(cli.rx + 9);

	lwsl_user("--- case %d \"%s\": %s (status %d, expected %d) ---\n",
		  cur, c->name, status == c->status ? "PASS" : "FAIL", status,
		  c->status);
	if (status != c->status)
		failed = 1;

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	const struct gcase *c = &cases[cur];
	uint8_t buf[LWS_PRE + 1024];
	char *start = (char *)buf + LWS_PRE, ws[256];
	int n;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error\n", __func__);
		case_judge();
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		ws[0] = '\0';
		if (c->ws)
			lws_snprintf(ws, sizeof(ws),
				     "Upgrade: websocket\r\n"
				     "Connection: Upgrade\r\n"
				     "Sec-WebSocket-Key: "
						"dGhlIHNhbXBsZSBub25jZQ==\r\n"
				     "Sec-WebSocket-Version: 13\r\n"
				     "Sec-WebSocket-Protocol: %s\r\n", c->ws);

		n = lws_snprintf(start, sizeof(buf) - LWS_PRE,
				 "GET %s HTTP/1.1\r\n"
				 "Host: localhost\r\n"
				 "%s%s\r\n", c->path, ws, c->extra);
		if (lws_write(wsi, (uint8_t *)start, (size_t)n,
			      LWS_WRITE_RAW) != n)
			return -1;
		break;

	case LWS_CALLBACK_RAW_RX:
		if (cli.done)
			break;
		if (len > sizeof(cli.rx) - 1 - cli.rx_len)
			len = sizeof(cli.rx) - 1 - cli.rx_len;
		memcpy(cli.rx + cli.rx_len, in, len);
		cli.rx_len += len;
		cli.rx[cli.rx_len] = '\0';
		if (strstr(cli.rx, "\r\n")) {
			/* the status line is all we judge */
			case_judge();
			return -1;
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		case_judge();
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_cli[] = {
	{ "mg-cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	do {
		if (++cur == (int)LWS_ARRAY_SIZE(cases)) {
			lws_default_loop_exit(context);
			return;
		}
#if !defined(LWS_WITH_HTTP_BASIC_AUTH)
		if (cases[cur].basic_auth) {
			lwsl_user("--- case %d \"%s\": skipped, no basic "
				  "auth ---\n", cur, cases[cur].name);
			continue;
		}
#endif
		break;
	} while (1);

	memset(&cli, 0, sizeof(cli));

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.port			= port;
	i.method		= "RAW";
	i.local_protocol_name	= "mg-cli";

	if (!lws_client_connect_via_info(&i))
		/* it told us with CLIENT_CONNECTION_ERROR */
		case_judge();
}

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("--- timeout in case %d ---\n", cur);
	failed = 1;
	lws_default_loop_exit(context);
}

static void
sigint_handler(int sig)
{
	failed = 1;
	lws_default_loop_exit(context);
}

/*
 * The vhost must be refused for these mounts, and lws_vhost_set_mounts()
 * must refuse them for a vhost that exists, keeping what it had: the cases
 * afterwards are served by its mounts
 */

static int
refusals(struct lws_context_creation_info *info, struct lws_vhost *vh)
{
	static const struct {
		const char			*name;
		struct lws_http_mount		*mounts;
	} r[] = {
		{ "interceptor_path is no mountpoint",	&b_nonesuch },
		{ "interceptor chain loops",		&b_loop1 },
		{ "basic auth on a CONNECT mount",	&b_connect },
		{ "interceptor on a gzip:// mount",	&b_nomount },
		{ "access rights on a file mount",	&b_ar_file },
	};
	struct lws_vhost *v;
	int n, bad = 0;

	b_nonesuch.interceptor_path	= "/nonesuch";
	b_loop1.interceptor_path	= "/l2";
	b_loop2.interceptor_path	= "/l1";
	b_connect.basic_auth_login_file	= "/dev/null";
	b_nomount.interceptor_path	= "/gk";
	b_ar_file.origin_protocol	= LWSMPRO_FILE;
	b_ar_file.origin		= ".";
	b_ar_file.auth_mask		= 1;

	info->port		= CONTEXT_PORT_NO_LISTEN;
	info->protocols		= protocols_srv;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(r); n++) {
		info->vhost_name	= r[n].name;
		info->mounts		= r[n].mounts;
		v = lws_create_vhost(context, info);
		if (v)
			lws_vhost_destroy(v);
		if (!lws_vhost_set_mounts(vh, r[n].mounts))
			v = vh;

		lwsl_user("--- refusal \"%s\": %s ---\n", r[n].name,
			  v ? "FAIL" : "PASS");
		bad |= !!v;
	}

	return bad;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
	const char *p;

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: mount gates\n");

	m_deep.interceptor_path		= "/gk";
	m_nows.interceptor_path		= "/gk";
	m_nows.no_ws_upgrades		= 1;
	m_admin.interceptor_path	= "/gk";
	m_self.interceptor_path		= "/gk";
	m_slash.interceptor_path	= "/gk";
#if defined(LWS_WITH_HTTP_BASIC_AUTH)
	/* without basic auth, the vhost is refused a mount with it */
	m_ba.auth_mask			= LWSAUTHM_BASIC_AUTH_CALLBACK;
#endif
	m_ar.auth_mask			= 1;

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.port		= 0;
	info.vhost_name		= "srv";
	info.protocols		= protocols_srv;
	info.mounts		= &m_nomount;
	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create the server vhost\n");
		goto bail;
	}
	port = lws_get_vhost_listen_port(vh);

	if (refusals(&info, vh))
		failed = 1;

	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.vhost_name		= "cli";
	info.protocols		= protocols_cli;
	info.mounts		= NULL;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create the client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 20 * LWS_US_PER_SEC);

	lws_context_default_loop_run_destroy(context);

	if (cur != (int)LWS_ARRAY_SIZE(cases))
		failed = 1;

	lwsl_user("Completed: %s\n", failed ? "FAIL" : "PASS");

	return failed;

bail:
	lws_context_destroy(context);
	lwsl_user("Completed: FAIL\n");

	return 1;
}
