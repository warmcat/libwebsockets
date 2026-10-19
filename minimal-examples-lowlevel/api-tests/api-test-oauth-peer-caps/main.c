/*
 * lws-api-test-oauth-peer-caps
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The per-peer admission caps of lws-oauth2-client (/oauth/login pending
 * states) and lws-oauth-preauth (the device waiting room) must count a host
 * as one peer: an IPv4 address, but for IPv6 the whole /64, since one host
 * commands all 2^64 addresses of it (G-234).
 *
 * Both plugins are built in, on a vhost that trusts loopback, where all our
 * connections come from, to send a PROXY v2 header naming the client first.
 * That lets one process be many clients, in one /64 or not.
 *
 * lws-oauth2-client, 8 pending logins on the vhost, 4 per peer:
 *
 *  - a victim from an IPv4 address starts a login;
 *
 *  - 8 addresses of one /64 each start one.  Counted as one peer, they only
 *    displace each other: the /64's oldest is evicted, the victim's is
 *    still pending.  Counted per address, the vhost would fill and the
 *    victim's login would be the oldest one evicted.
 *
 * Whether a login is still pending is told by presenting its state at
 * /oauth/callback with its state cookie: an evicted state is not found, a
 * 400.  A pending one is, and the token exchange starts, but the auth server
 * the vhost is configured with is a port nobody listens on, so that fails
 * at once, a 500.
 *
 * lws-oauth-preauth, 4 devices in the room, 2 per peer:
 *
 *  - 4 devices from 4 addresses of one /64 announce serials.  Counted as
 *    one peer, the third and fourth evict the first and second;
 *
 *  - a device from an IPv4 host then finds room and is admitted (counted
 *    per address, the room is full of announced devices and it is refused);
 *
 *  - two more hosts fill the room.  With every device announced, a device
 *    from a new host evicts the oldest of the host holding the most of the
 *    room, the /64;
 *
 *  - a second device from that new host is refused: the room is now
 *    shared evenly, one device per host.
 */

#include <libwebsockets.h>
#include <string.h>

#define LWS_PLUGIN_STATIC
#include "protocol_lws_oauth2_client.c"
#include "protocol_lws_oauth_preauth.c"

/* a refused connect can take a few seconds on some platforms */
#define OPC_STEP_US		(10 * LWS_US_PER_SEC)
/* how long the server is given to act on what a step sent */
#define OPC_SETTLE_US		(200 * LWS_US_PER_MS)
#define OPC_LOGINS		9
#define OPC_DEVICES		8

enum opc_kind {
	OPC_LOGIN,	/* GET /oauth/login, keep its state and cookie */
	OPC_CALLBACK,	/* GET /oauth/callback with a login's state */
	OPC_DEVICE,	/* a preauth device connects and announces a serial */
	OPC_CHECK,	/* which devices are still in the room */
};

struct opc_step {
	const char	*name;
	enum opc_kind	kind;
	const char	*client;	/* who the PROXY v2 header names */
	int		slot;		/* login or device index */
	const char	*expect;	/* CALLBACK: body text, CHECK: states */
};

#define OPC_PENDING	"HTTP/1.1 500"	/* found, the exchange failed */
#define OPC_GONE	"HTTP/1.1 400"	/* "Invalid or expired state" */

static const struct opc_step opc_steps[] = {
	{ "victim starts a login",		OPC_LOGIN, "192.0.2.10", 0,
	  NULL },
	{ "/64 login 1",	OPC_LOGIN, "2001:db8:1:2::1", 1, NULL },
	{ "/64 login 2",	OPC_LOGIN, "2001:db8:1:2::2", 2, NULL },
	{ "/64 login 3",	OPC_LOGIN, "2001:db8:1:2:8000::3", 3, NULL },
	{ "/64 login 4",	OPC_LOGIN, "2001:db8:1:2:ffff::4", 4, NULL },
	{ "/64 login 5",	OPC_LOGIN, "2001:db8:1:2:1:2:3:5", 5, NULL },
	{ "/64 login 6",	OPC_LOGIN, "2001:db8:1:2::6", 6, NULL },
	{ "/64 login 7",	OPC_LOGIN, "2001:db8:1:2::7", 7, NULL },
	{ "/64 login 8",	OPC_LOGIN, "2001:db8:1:2::8", 8, NULL },
	{ "the victim's login survived the /64's flood",
				OPC_CALLBACK, "192.0.2.10", 0, OPC_PENDING },
	{ "the /64's first login was its own to evict",
				OPC_CALLBACK, "2001:db8:1:2::1", 1, OPC_GONE },
	{ "the /64's last login is pending",
				OPC_CALLBACK, "2001:db8:1:2::8", 8, OPC_PENDING },

	{ "/64 device 0",	OPC_DEVICE, "2001:db8:5:6::1", 0, NULL },
	{ "/64 device 1",	OPC_DEVICE, "2001:db8:5:6::2", 1, NULL },
	{ "/64 device 2",	OPC_DEVICE, "2001:db8:5:6:7::3", 2, NULL },
	{ "/64 device 3",	OPC_DEVICE, "2001:db8:5:6:8::4", 3, NULL },
	{ "IPv4 device 4",	OPC_DEVICE, "192.0.2.20", 4, NULL },
	{ "the /64 holds 2 of the room and device 4 got in",
				OPC_CHECK, NULL, 0, "CCOOO" },
	{ "IPv4 device 5",	OPC_DEVICE, "192.0.2.31", 5, NULL },
	{ "IPv4 device 6",	OPC_DEVICE, "192.0.2.40", 6, NULL },
	{ "device 6 displaced the /64's oldest from the full room",
				OPC_CHECK, NULL, 0, "CCCOOOO" },
	{ "IPv4 device 7, same host as 6",
				OPC_DEVICE, "192.0.2.40", 7, NULL },
	{ "device 7 refused: the room is shared evenly",
				OPC_CHECK, NULL, 0, "CCCOOOOC" },
};

struct opc_conn {
	char		rx[4096];
	size_t		rxlen;
	int		step;
	char		sent;
	char		upgraded;
	char		framed;
	char		closed;
};

struct opc_login {
	char		state[64];
	char		nonce[64];
};

/* the auth server, and the iss it must be called: a port nobody listens on */
static char auth_url[128];

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_step;
static const char *server = "localhost";
static struct opc_conn conns[LWS_ARRAY_SIZE(opc_steps)];
static struct opc_login logins[OPC_LOGINS];
static struct opc_conn *devices[OPC_DEVICES];
static int port, step = -1, fails, finished, judged;

static void
opc_next(lws_sorted_usec_list_t *sul);

static void
opc_judge(const char *why, lws_usec_t delay)
{
	if (judged)
		return;
	judged = 1;
	lws_sul_cancel(&sul_step);

	if (why) {
		lwsl_err("  FAIL: %s: %s\n", opc_steps[step].name, why);
		fails++;
	} else
		lwsl_user("  PASS: %s\n", opc_steps[step].name);

	lws_sul_schedule(context, 0, &sul_step, opc_next, delay);
}

static void
opc_deadline(lws_sorted_usec_list_t *sul)
{
	(void)sul;

	opc_judge("timed out", 1);
}

/* copy what follows the first occurrence of name in s, up to a delimiter */

static int
opc_extract(const char *s, const char *name, const char *delims, char *out,
	    size_t olen)
{
	const char *p = strstr(s, name);
	size_t n = 0;

	if (!p)
		return 1;
	p += strlen(name);
	while (p[n] && !strchr(delims, p[n]) && n < olen - 1) {
		out[n] = p[n];
		n++;
	}
	out[n] = '\0';

	return !n;
}

/* the response to a whole http request on c, the server having closed */

static void
opc_judge_http(struct opc_conn *c)
{
	const struct opc_step *s = &opc_steps[c->step];
	struct opc_login *l = &logins[s->slot];

	if (s->kind == OPC_CALLBACK) {
		if (!strstr(c->rx, s->expect))
			lwsl_warn("  answer: %.300s\n", c->rx);
		opc_judge(strstr(c->rx, s->expect) ? NULL :
			  (strstr(c->rx, OPC_PENDING) ? "login pending" :
			   (strstr(c->rx, OPC_GONE) ? "login evicted" :
						      "unexpected answer")), 1);
		return;
	}

	/* a login: keep the state it was given, and the cookie binding it */

	if (strncmp(c->rx, "HTTP/1.1 302", 12) ||
	    opc_extract(c->rx, "&state=", "&\r\n", l->state,
			sizeof(l->state)) ||
	    opc_extract(c->rx, OAUTH2_STATE_COOKIE "=", ";\r\n", l->nonce,
			sizeof(l->nonce))) {
		opc_judge("no 302 with state and state cookie", 1);
		return;
	}

	opc_judge(NULL, 1);
}

static int
opc_cli_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	   void *in, size_t len)
{
	struct opc_conn *c = (struct opc_conn *)lws_get_opaque_user_data(wsi);
	uint8_t tx[LWS_PRE + LWS_PROXY_V2_MAX + 512], *p = tx + LWS_PRE;
	const struct opc_step *s;
	lws_proxy_v2_t pv;
	int n;

	(void)user;

	if (!c)
		return 0;
	s = &opc_steps[c->step];

	switch (reason) {
	case LWS_CALLBACK_RAW_CONNECTED:
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (c->upgraded && !c->framed) {
			/* the device announces itself, in one masked frame */
			n = lws_snprintf((char *)p + 6, 64,
					 "{\"serial\":\"dev%d\"}", s->slot);
			p[0] = 0x81;
			p[1] = (uint8_t)(0x80 | n);
			memset(p + 2, 0, 4); /* a zero mask leaves it as is */
			c->framed = 1;
			if (lws_write(wsi, p, (size_t)n + 6, LWS_WRITE_RAW) !=
								n + 6)
				return -1;
			if (c->step == step)
				opc_judge(NULL, OPC_SETTLE_US);
			break;
		}
		if (c->sent)
			break;
		c->sent = 1;

		memset(&pv, 0, sizeof(pv));
		if (lws_sa46_parse_numeric_address(s->client, &pv.src) ||
		    lws_sa46_parse_numeric_address(strchr(s->client, ':') ?
						"2001:db8::443" : "192.0.2.1",
						&pv.dst))
			return -1;
		sa46_sockport(&pv.src, htons(40000));
		sa46_sockport(&pv.dst, htons(443));

		n = lws_proxy_v2_render(&pv, p, LWS_PROXY_V2_MAX);
		if (n <= 0)
			return -1;

		switch (s->kind) {
		case OPC_LOGIN:
			n += lws_snprintf((char *)p + n,
				sizeof(tx) - LWS_PRE - (size_t)n,
				"GET /oauth/login HTTP/1.1\r\n"
				"Host: localhost\r\n"
				"Connection: close\r\n\r\n");
			break;
		case OPC_CALLBACK:
			n += lws_snprintf((char *)p + n,
				sizeof(tx) - LWS_PRE - (size_t)n,
				"GET /oauth/callback?state=%s&code=c&iss=%s "
					"HTTP/1.1\r\n"
				"Host: localhost\r\n"
				"Cookie: " OAUTH2_STATE_COOKIE "=%s\r\n"
				"Connection: close\r\n\r\n",
				logins[s->slot].state, auth_url,
				logins[s->slot].nonce);
			break;
		default:
			n += lws_snprintf((char *)p + n,
				sizeof(tx) - LWS_PRE - (size_t)n,
				"GET / HTTP/1.1\r\n"
				"Host: localhost\r\n"
				"Upgrade: websocket\r\n"
				"Connection: Upgrade\r\n"
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
				"Sec-WebSocket-Version: 13\r\n"
				"Sec-WebSocket-Protocol: lws-oauth-preauth\r\n"
				"\r\n");
			break;
		}

		if (lws_write(wsi, p, (size_t)n, LWS_WRITE_RAW) != n)
			return -1;
		break;

	case LWS_CALLBACK_RAW_RX:
		if (c->upgraded && len && *(const uint8_t *)in == 0x88)
			goto ws_closing;
		if (len > sizeof(c->rx) - 1 - c->rxlen)
			len = sizeof(c->rx) - 1 - c->rxlen;
		memcpy(c->rx + c->rxlen, in, len);
		c->rxlen += len;
		c->rx[c->rxlen] = '\0';

		if (s->kind == OPC_DEVICE && !c->upgraded &&
		    strstr(c->rx, "\r\n\r\n")) {
			if (strncmp(c->rx, "HTTP/1.1 101", 12)) {
				if (c->step == step)
					opc_judge("not upgraded", 1);
				return -1;
			}
			c->upgraded = 1;
			p = (uint8_t *)strstr(c->rx, "\r\n\r\n") + 4;
			if (p < (uint8_t *)c->rx + c->rxlen && *p == 0x88)
				goto ws_closing;
			lws_callback_on_writable(wsi);
		}
		break;

ws_closing:
		/*
		 * The server is closing the ws: a refused device is sent a
		 * close frame right after the upgrade.  There's no need to
		 * wait for it to give up on our close reply.
		 */
		c->closed = 1;
		lws_set_opaque_user_data(wsi, NULL);
		if (c->step == step)
			opc_judge(NULL, OPC_SETTLE_US);
		return -1;

	case LWS_CALLBACK_RAW_CLOSE:
		c->closed = 1;
		lws_set_opaque_user_data(wsi, NULL);
		if (c->step != step)
			break;
		if (s->kind == OPC_DEVICE)
			/* refused: the room is checked later */
			opc_judge(NULL, OPC_SETTLE_US);
		else
			opc_judge_http(c);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lws_set_opaque_user_data(wsi, NULL);
		if (c->step == step)
			opc_judge(in ? (const char *)in : "connection error",
				  1);
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols opc_srv_protocols[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	LWS_PLUGIN_PROTOCOL_LWS_OAUTH2_CLIENT,
	LWS_PLUGIN_PROTOCOL_LWS_OAUTH_PREAUTH,
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols opc_cli_protocols[] = {
	{ "opc-cli", opc_cli_cb, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static struct lws_protocol_vhost_options
	pvo_oc_per_peer	= { NULL, NULL, "max-pending-auths-per-peer", "4" },
	pvo_oc_max	= { &pvo_oc_per_peer, NULL, "max-pending-auths", "8" },
	pvo_oc_cid	= { &pvo_oc_max, NULL, "client-id", "api-test" },
	pvo_oc_url	= { &pvo_oc_cid, NULL, "remote-auth-url", auth_url },
	pvo_oc		= { NULL, &pvo_oc_url, "lws-oauth2-client", "" },
	pvo_pa_per_peer	= { NULL, NULL, "max-devices-per-peer", "2" },
	pvo_pa_max	= { &pvo_pa_per_peer, NULL, "max-devices", "4" },
	pvo_pa		= { &pvo_oc, &pvo_pa_max, "lws-oauth-preauth", "" };

static const struct lws_http_mount mount_oauth = {
	.mountpoint		= "/oauth",
	.mountpoint_len		= 6,
	.origin			= "lws-oauth2-client",
	.origin_protocol	= LWSMPRO_CALLBACK,
};

/* which devices are still connected, 'O'pen or 'C'losed, in slot order */

static void
opc_check(const char *expect)
{
	char got[OPC_DEVICES + 1];
	size_t n, e = strlen(expect);

	for (n = 0; n < e && n < OPC_DEVICES; n++)
		got[n] = devices[n] && !devices[n]->closed ? 'O' : 'C';
	got[n] = '\0';

	if (strcmp(got, expect)) {
		char why[64];

		lws_snprintf(why, sizeof(why), "devices %s, expected %s", got,
			     expect);
		opc_judge(why, 1);
	} else
		opc_judge(NULL, 1);
}

static void
opc_next(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	const struct opc_step *s;

	(void)sul;

	if (++step == (int)LWS_ARRAY_SIZE(opc_steps)) {
		finished = 1;
		lws_cancel_service(context);
		return;
	}

	s = &opc_steps[step];
	judged = 0;

	if (s->kind == OPC_CHECK) {
		opc_check(s->expect);
		return;
	}

	memset(&conns[step], 0, sizeof(conns[step]));
	conns[step].step = step;
	if (s->kind == OPC_DEVICE)
		devices[s->slot] = &conns[step];

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server;
	i.host			= server;
	i.port			= port;
	i.method		= "RAW";
	i.protocol		= opc_cli_protocols[0].name;
	i.local_protocol_name	= opc_cli_protocols[0].name;
	i.opaque_user_data	= &conns[step];

	lws_sul_schedule(context, 0, &sul_step, opc_deadline, OPC_STEP_US);

	if (!lws_client_connect_via_info(&i))
		opc_judge("connect failed", 1);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
	const char *p;
	int m = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server = p;
	lws_snprintf(auth_url, sizeof(auth_url), strchr(server, ':') ?
				"http://[%s]:1" : "http://%s:1", server);

	lwsl_user("LWS API selftest: oauth plugin per-peer caps\n");

	/* a server and a client in one process: don't budget fds */
	info.fd_limit_per_thread	= 0;
	info.options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.port		= 0;
	info.protocols		= opc_srv_protocols;
	info.pvo		= &pvo_pa;
	info.mounts		= &mount_oauth;
	info.vhost_name		= "opc-srv";
	/* every connection of ours comes from loopback, our "proxy" */
	info.proxy_v2_trusted	= "127.0.0.1, ::1";
	vh = lws_create_vhost(context, &info);
	if (!vh)
		goto bail;
	port = lws_get_vhost_listen_port(vh);

	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.protocols		= opc_cli_protocols;
	info.pvo		= NULL;
	info.mounts		= NULL;
	info.vhost_name		= "opc-cli";
	info.proxy_v2_trusted	= NULL;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli)
		goto bail;

	lws_sul_schedule(context, 0, &sul_step, opc_next, 1);

	while (m >= 0 && !finished)
		m = lws_service(context, 0);

	lws_sul_cancel(&sul_step);
	lws_context_destroy(context);

	if (!finished) {
		lwsl_err("service loop ended early\n");
		fails++;
	}

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;

bail:
	lwsl_err("setup failed\n");
	lws_context_destroy(context);

	return 1;
}
