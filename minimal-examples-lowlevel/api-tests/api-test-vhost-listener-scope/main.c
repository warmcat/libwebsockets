/*
 * lws-api-test-vhost-listener-scope
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Fences G-329 and G-007: a connection may only be moved, by a name it sends,
 * onto a vhost served by the listener it arrived on.  Vhosts on the same port
 * but different interfaces have listen sockets of their own, and the
 * interface can be all that restricts who reaches a vhost (eg, an admin vhost
 * on lo:443 beside a public one).  TLS SNI, h1 Host: and the choice of a tls
 * passthrough vhost used to look for the name among every vhost with the
 * same port number, on any interface.
 *
 * Both ends are in this process.  The vhosts listen on the same port on
 * 127.0.0.1 and 127.0.0.2, and the client always dials 127.0.0.1.  Every
 * vhost answers with its own name.  "va" and, in some cases, "va2" listen on
 * 127.0.0.1, "vb" on 127.0.0.2:
 *
 *  --case host-other:  plain http, Host: vb, must be served by "va"
 *  --case host-same:   plain http, Host: va2, must be served by "va2"
 *  --case sni-other:   tls, only "va" on 127.0.0.1, so the SNI name and
 *                      Host / :authority "vb" must be served by "va"
 *  --case sni-same:    tls, SNI "va2" must be served by "va2"
 *  --case sni-refused: tls, "va" and "va2" on 127.0.0.1, neither the SNI
 *                      fallback, so SNI "vb" must be refused
 *
 * The tls cases run on the alpn given by --alpn (http/1.1, h2 or h3).
 *
 * With tls passthrough, "pa" on 127.0.0.1 and "pb" on 127.0.0.2 are passed
 * through to "backend", on another port of 127.0.0.1 (where available, over
 * QUIC too):
 *
 *  --case pt-same:     SNI "pa" is passed through, "backend" serves it
 *  --case pt-other:    SNI "pb", passed through only on 127.0.0.2, must not
 *                      be: it is refused on 127.0.0.1
 *
 * Fences G-330: a connection moved onto another vhost must not keep a
 * protocol from the vhost it left.  "ga" and "gb" share a tls listener on
 * 127.0.0.1, with protocols named differently.
 *
 *  --case proto-moved:     a raw tls client with SNI "gb" is moved to "gb"
 *                          at the handshake.  "ga" is then destroyed, and
 *                          only after that does the client send a
 *                          websocket upgrade request: "gb"'s protocol must
 *                          be asked to confirm it, never the freed one of
 *                          "ga" (an ASan use after free when it was).
 *  --case proto-keepalive: a raw tls client with SNI "ga" sends a request
 *                          with Host: ga, then on the same connection one
 *                          with Host: gb: both are served, each by its own
 *                          vhost.
 *
 * Where 127.0.0.2 can't be listened on (it is not a loopback address on
 * every platform), the cases needing it are skipped.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>

#define VLS_TIMEOUT_S		10
#define VLS_SKIP		77
#define VLS_ADS_A		"127.0.0.1"
#define VLS_ADS_B		"127.0.0.2"

enum {
	VLS_L_PLAIN,	/* va, va2 plain on .1, vb on .2 */
	VLS_L_TLS1,	/* va tls on .1, vb on .2 */
	VLS_L_TLS2,	/* va, va2 tls on .1, vb on .2 */
	VLS_L_PT,	/* va + passthrough pa on .1, vb + pb on .2, backend */
	VLS_L_PROTO,	/* ga, gb tls on .1, protocols named differently */
};

enum {
	VLS_K_GET,		/* an lws http client GET */
	VLS_K_UPGRADE_LATE,	/* raw tls, upgrade request after ga is gone */
	VLS_K_KEEPALIVE,	/* raw tls, two requests naming two vhosts */
};

static const struct vls_case {
	const char	*name;
	uint8_t		layout;
	uint8_t		kind;
	const char	*host;	/* SNI and Host / :authority */
	const char	*want;	/* the vhost that must serve it, NULL: refused */
} vls_cases[] = {
	{ "host-other",		VLS_L_PLAIN,	VLS_K_GET,	"vb",	"va" },
	{ "host-same",		VLS_L_PLAIN,	VLS_K_GET,	"va2",	"va2" },
	{ "sni-other",		VLS_L_TLS1,	VLS_K_GET,	"vb",	"va" },
	{ "sni-same",		VLS_L_TLS2,	VLS_K_GET,	"va2",	"va2" },
	{ "sni-refused",	VLS_L_TLS2,	VLS_K_GET,	"vb",	NULL },
	{ "pt-same",		VLS_L_PT,	VLS_K_GET,	"pa",	"backend" },
	{ "pt-other",		VLS_L_PT,	VLS_K_GET,	"pb",	NULL },
	{ "proto-moved",	VLS_L_PROTO,	VLS_K_UPGRADE_LATE, "gb", "gb" },
	{ "proto-keepalive",	VLS_L_PROTO,	VLS_K_KEEPALIVE, "ga",	"gb" },
};

static const struct vls_case *tc;
static struct lws_context *context;
static struct lws_vhost *vh_ga;
static lws_sorted_usec_list_t sul_watchdog, sul_step;
static struct lws *cli_wsi;
static char body[512], confirm_vh[32];
static size_t body_len;
static int port = 7700, completed, timed_out, served, stage;

static const char *upgrade_req =
	"GET / HTTP/1.1\r\n"
	"Host: gb\r\n"
	"Connection: Upgrade\r\n"
	"Upgrade: websocket\r\n"
	"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
	"Sec-WebSocket-Version: 13\r\n"
	"\r\n";

static const char *keepalive_req[] = {
	"GET / HTTP/1.1\r\nHost: ga\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: gb\r\n\r\n",
};

struct pss_srv {
	char		resp[LWS_PRE + 64];
	size_t		resp_len;
};

static void
vls_done(void)
{
	lws_default_loop_exit(context);
}

/* the server: every vhost answers with its own name */

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t hdr[LWS_PRE + 256], *start = &hdr[LWS_PRE], *p = start,
		*end = &hdr[sizeof(hdr) - 1];

	switch (reason) {
	case LWS_CALLBACK_HTTP_CONFIRM_UPGRADE:
		/* who was asked: the protocol's own vhost must be his */
		lws_snprintf(confirm_vh, sizeof(confirm_vh), "%s:%s",
			     lws_get_protocol(wsi)->name,
			     lws_get_vhost_name(lws_get_vhost(wsi)));
		lwsl_user("%s: upgrade confirm asked of %s\n", __func__,
			  confirm_vh);
		/* that is all we wanted to know */
		return -1;

	case LWS_CALLBACK_HTTP:
		pss->resp_len = (size_t)lws_snprintf(&pss->resp[LWS_PRE],
				sizeof(pss->resp) - LWS_PRE, "vh=%s",
				lws_get_vhost_name(lws_get_vhost(wsi)));

		lwsl_user("%s: served by %s\n", __func__, &pss->resp[LWS_PRE]);
		served++;

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain",
						(lws_filepos_t)pss->resp_len,
						&p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return -1;

		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss || !pss->resp_len)
			break;
		if (lws_write(wsi, (uint8_t *)&pss->resp[LWS_PRE],
			      pss->resp_len, LWS_WRITE_HTTP_FINAL) !=
							(int)pss->resp_len)
			return -1;
		pss->resp_len = 0;
		if (lws_http_transaction_completed(wsi))
			return -1;
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* the client */

static void
step_cb(lws_sorted_usec_list_t *sul)
{
	switch (stage) {
	case 0:
		/*
		 * proto-moved: he was moved off ga at the handshake.  Destroy
		 * ga now: nothing is bound to it any more, so it is freed,
		 * protocols and all, and its listen socket goes to gb
		 */
		lwsl_user("%s: destroying ga\n", __func__);
		lws_vhost_destroy(vh_ga);
		vh_ga = NULL;
		stage++;
		lws_sul_schedule(context, 0, &sul_step, step_cb,
				 100 * LWS_US_PER_MS);
		break;
	case 1:
		/* ... and only now does he send his request */
		stage++;
		if (cli_wsi)
			lws_callback_on_writable(cli_wsi);
		break;
	}
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 256], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;
	const char *req = NULL;
	size_t n;

	switch (reason) {
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (len > sizeof(body) - 1 - body_len)
			len = sizeof(body) - 1 - body_len;
		memcpy(body + body_len, in, len);
		body_len += len;
		body[body_len] = '\0';
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		completed = 1;
		vls_done();
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: connection error: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		vls_done();
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		vls_done();
		break;

	/* the raw tls cases */

	case LWS_CALLBACK_RAW_CONNECTED:
		cli_wsi = wsi;
		if (tc->kind == VLS_K_UPGRADE_LATE)
			lws_sul_schedule(context, 0, &sul_step, step_cb,
					 100 * LWS_US_PER_MS);
		else
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (tc->kind == VLS_K_UPGRADE_LATE) {
			if (stage == 2) {
				req = upgrade_req;
				stage = 3;
			}
		} else if (stage < (int)LWS_ARRAY_SIZE(keepalive_req) &&
			   !completed) {
			req = keepalive_req[stage];
			/* sent: now wait for its answer */
			completed = 1;
		}
		if (!req)
			break;
		n = strlen(req);
		memcpy(buf + LWS_PRE, req, n);
		if (lws_write(wsi, (uint8_t *)buf + LWS_PRE, n,
			      LWS_WRITE_RAW) < (int)n)
			return -1;
		break;

	case LWS_CALLBACK_RAW_RX:
		if (len > sizeof(body) - 1 - body_len)
			len = sizeof(body) - 1 - body_len;
		memcpy(body + body_len, in, len);
		body_len += len;
		body[body_len] = '\0';

		if (tc->kind == VLS_K_KEEPALIVE && completed &&
		    strstr(body, stage ? "vh=gb" : "vh=ga")) {
			lwsl_user("%s: answer %d: ...%s\n", __func__, stage,
				  stage ? "vh=gb" : "vh=ga");
			completed = 0;
			if (++stage == (int)LWS_ARRAY_SIZE(keepalive_req)) {
				/* both answered */
				completed = 1;
				return -1;
			}
			/* only what follows matters for the next one */
			body_len = 0;
			body[0] = '\0';
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		cli_wsi = NULL;
		vls_done();
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "vls", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* ga and gb have no protocol of the same name */

static const struct lws_protocols protocols_ga[] = {
	{ "vls-ga", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_gb[] = {
	{ "vls-gb", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "vls-cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	timed_out = 1;
	vls_done();
}

static struct lws_vhost *
vls_vhost(struct lws_context_creation_info *info, const char *name,
	  const char *iface)
{
	struct lws_vhost *vh;

	info->vhost_name	= name;
	info->iface		= iface;

	vh = lws_create_vhost(context, info);
	if (!vh)
		lwsl_err("Failed to create vhost %s on %s\n", name, iface);

	return vh;
}

/* the tls cases are only registered with ctest in builds that have tls */
static void
vls_info_tls(struct lws_context_creation_info *info, const char *cert,
	     const char *key, const char *alpn)
{
#if defined(LWS_WITH_TLS)
	info->ssl_cert_filepath		= cert;
	info->ssl_private_key_filepath	= key;
	info->alpn			= alpn;
#else
	(void)info;
	(void)cert;
	(void)key;
	(void)alpn;
#endif
}

int main(int argc, const char **argv)
{
	const char *p, *cert = NULL, *key = NULL, *mode = NULL,
		   *alpn = "http/1.1";
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	struct lws_vhost *vh_cli;
	char want[64], target[64];
	int result = 1, tls;
	size_t n;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* several listeners, and both ends */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");
	mode = lws_cmdline_option(argc, argv, "--case");
	if ((p = lws_cmdline_option(argc, argv, "--alpn")))
		alpn = p;

	for (n = 0; mode && n < LWS_ARRAY_SIZE(vls_cases); n++)
		if (!strcmp(mode, vls_cases[n].name))
			tc = &vls_cases[n];

	if (!tc || port <= 0 || port > 65534) {
		lwsl_err("--case and -p are required\n");
		return 1;
	}

	tls = tc->layout != VLS_L_PLAIN;
	if (tls && (!cert || !key)) {
		lwsl_err("--cert and --key are required for %s\n", tc->name);
		return 1;
	}

	lwsl_user("LWS API selftest: vhost listener scope, %s (%s)\n",
		  tc->name, tls ? alpn : "plain");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/*
	 * The server vhosts.  The ones on 127.0.0.1 are made first, so they
	 * own its listener.  Each is bound to its own address, ipv4 only.
	 */

	info.port	= port;
	info.protocols	= protocols_srv;
	info.options	|= LWS_SERVER_OPTION_DISABLE_IPV6 |
			   LWS_SERVER_OPTION_FAIL_UPON_UNABLE_TO_BIND;
	if (tls)
		vls_info_tls(&info, cert, key, "h2,http/1.1,h3");

	switch (tc->layout) {
	case VLS_L_PROTO:
		info.protocols = protocols_ga;
		vh_ga = vls_vhost(&info, "ga", VLS_ADS_A);
		if (!vh_ga)
			goto bail;
		info.protocols = protocols_gb;
		if (!vls_vhost(&info, "gb", VLS_ADS_A))
			goto bail;
		break;

	case VLS_L_PT:
		/* the backend, on the next port */
		info.port		= port + 1;
		info.proxy_v2_trusted	= VLS_ADS_A;
		if (!vls_vhost(&info, "backend", VLS_ADS_A))
			goto bail;
		info.proxy_v2_trusted	= NULL;
		info.port		= port;
		/* fallthru */

	default:
		if (!vls_vhost(&info, "va", VLS_ADS_A))
			goto bail;
		if ((tc->layout == VLS_L_PLAIN || tc->layout == VLS_L_TLS2) &&
		    !vls_vhost(&info, "va2", VLS_ADS_A))
			goto bail;

		/*
		 * The first vhost on 127.0.0.2 tells us if the platform can
		 * listen there at all
		 */
		info.vhost_name	= "vb";
		info.iface	= VLS_ADS_B;
		if (!lws_create_vhost(context, &info)) {
			lwsl_user("SKIP: can't listen on %s here\n", VLS_ADS_B);
			result = VLS_SKIP;
			goto bail;
		}

		if (tc->layout != VLS_L_PT)
			break;

		/* the passed through vhosts, after a tls vhost on each */
		lws_snprintf(target, sizeof(target), "%s:%d", VLS_ADS_A,
			     port + 1);
		vls_info_tls(&info, NULL, NULL, NULL);
		info.tls_passthrough		= target;
		info.tls_passthrough_proxy_v2	= 1;
		if (!vls_vhost(&info, "pa", VLS_ADS_A) ||
		    !vls_vhost(&info, "pb", VLS_ADS_B))
			goto bail;
		info.tls_passthrough		= NULL;
		info.tls_passthrough_proxy_v2	= 0;
		break;
	}

	/* the client vhost */

	info.options			&= ~(uint64_t)
				(LWS_SERVER_OPTION_DISABLE_IPV6 |
				 LWS_SERVER_OPTION_FAIL_UPON_UNABLE_TO_BIND);
	vls_info_tls(&info, NULL, NULL, NULL);
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.iface			= NULL;
	info.vhost_name			= "cli";
	info.protocols			= protocols_cli;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create the client vhost\n");
		goto bail;
	}

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= VLS_ADS_A;
	/* the SNI name, and the Host / :authority of an http client */
	i.host			= tc->host;
	i.origin		= tc->host;
	i.port			= port;
	i.path			= "/";
	i.local_protocol_name	= "vls-cli";
	i.protocol		= "vls-cli";
	if (tls) {
		i.alpn		= alpn;
		i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	}
	/* an h3 case must be decided on h3, not by a fallback to tcp */
	i.disable_h3_fallback	= 1;
	i.method		= tc->kind == VLS_K_GET ? "GET" : "RAW";

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 VLS_TIMEOUT_S * LWS_US_PER_SEC);

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("The connection could not be started\n");
		goto bail;
	}

	while (lws_service(context, 0) >= 0)
		;

	want[0] = '\0';
	if (tc->want)
		lws_snprintf(want, sizeof(want), "vh=%s", tc->want);

	if (timed_out)
		lwsl_err("FAIL: timed out\n");
	else if (tc->kind == VLS_K_UPGRADE_LATE) {
		if (strcmp(confirm_vh, "vls-gb:gb"))
			lwsl_err("FAIL: upgrade confirm asked of '%s', want "
				 "vls-gb:gb\n", confirm_vh);
		else
			result = 0;
	} else if (tc->kind == VLS_K_KEEPALIVE) {
		if (!completed || stage != (int)LWS_ARRAY_SIZE(keepalive_req))
			lwsl_err("FAIL: %d of 2 answered as asked, last '%s'\n",
				 stage, body);
		else
			result = 0;
	} else if (!tc->want) {
		if (served || completed)
			lwsl_err("FAIL: served (%d) as '%s', want refused\n",
				 served, body);
		else
			result = 0;
	} else if (!completed)
		lwsl_err("FAIL: the request did not complete\n");
	else if (strcmp(body, want))
		lwsl_err("FAIL: served as '%s', want '%s'\n", body, want);
	else
		result = 0;

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_step);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result == VLS_SKIP ? "SKIP" :
					(result ? "FAIL" : "PASS"));

	return result;
}
