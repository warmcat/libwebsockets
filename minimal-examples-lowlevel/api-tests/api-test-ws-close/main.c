/*
 * lws-api-test-ws-close
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Exercises the clean ws close handshake in both directions, over h1 and
 * over ws-over-h2 (RFC 8441), with a ws server vhost and a ws client in one
 * process, and checks that the close status code and reason reach the peer
 * intact and that both sides see their close callbacks.
 *
 * With --proxy host:port, --socks host:port and --socks-auth host:port it
 * additionally runs h1 legs through an http CONNECT proxy, a SOCKS5 proxy
 * with no auth and a SOCKS5 proxy requiring username/password; ctest runs it
 * that way against proxy-fixture.py in this directory.
 *
 * Before this test, no ctest performed a clean ws close at all: every ws
 * connection in the suite ended by dropping the socket, so the close
 * handshake states (LRS_WAITING_TO_SEND_CLOSE, LRS_RETURNED_CLOSE,
 * LRS_AWAITING_CLOSE_ACK) and the proxy connect states were never reached.
 *
 * With permessage-deflate built in, a leg also has the server close while
 * the inflater still holds output of a compressed message it is partway
 * through, the ordinary case of an app refusing a message it has only seen
 * the start of.
 *
 * Every leg must finish its close promptly and without the service loop
 * spinning meanwhile: a close handshake that only ends at its timeout, or
 * a service loop that goes around without waiting, fails the leg.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

struct leg {
	const char	*name;
	const char	*vhost;		/* client vhost to connect from */
	const char	*alpn;
	uint8_t		h2;
	uint8_t		server_initiates;
	uint8_t		default_reason;	/* close without lws_close_reason() */
	uint8_t		pmd_mid_drain;	/* server closes on a compressed
					 * message it is partway through */
};

static const struct leg legs[] = {
	{ "h1, client-initiated",		"cli",	   "http/1.1", 0, 0, 0, 0 },
	{ "h1, server-initiated",		"cli",	   "http/1.1", 0, 1, 0, 0 },
	{ "h2, client-initiated",		"cli",	   "h2",       1, 0, 0, 0 },
	{ "h2, server-initiated",		"cli",	   "h2",       1, 1, 0, 0 },
	{ "h1, client-initiated, default reason", "cli",  "http/1.1", 0, 0, 1, 0 },
	{ "h1, server-initiated, default reason", "cli",  "http/1.1", 0, 1, 1, 0 },
	{ "h2, client-initiated, default reason", "cli",  "h2",       1, 0, 1, 0 },
	{ "h2, server-initiated, default reason", "cli",  "h2",       1, 1, 1, 0 },
	{ "h1 via http CONNECT proxy",		"cli-hp",  "http/1.1", 0, 0, 0, 0 },
	{ "h1 via socks5, no auth",		"cli-s5",  "http/1.1", 0, 0, 0, 0 },
	{ "h1 via socks5, username/password",	"cli-s5a", "http/1.1", 0, 0, 0, 0 },
	{ "h1, pmd, server closes mid-message",	"cli-pmd", "http/1.1", 0, 1, 0, 1 },
};

#define CLI_CODE	LWS_CLOSE_STATUS_GOINGAWAY	/* 1001 */
#define CLI_REASON	"bye"
#define SRV_CODE	LWS_CLOSE_STATUS_NORMAL		/* 1000 */
#define SRV_REASON	"srv"

/*
 * A close handshake on loopback takes a few ms and a few dozen trips around
 * the service loop.  One that only ends at the 5s close timeout, or a loop
 * that spins meanwhile, is far outside these.
 */
#define LEG_MAX_US	(3 * LWS_US_PER_SEC)
#define LEG_MAX_TURNS	2000

/* the compressible message the pmd leg's client sends */
#define PMD_MSG_LEN	(16 * 1024)

static struct lws_context *context;
static struct lws_vhost *vh_cli[5];
static const char *vh_cli_names[5] = { "cli", "cli-hp", "cli-s5", "cli-s5a",
				       "cli-pmd" };
static lws_sorted_usec_list_t sul_next, sul_timeout;
static const char *server_ads = "127.0.0.1";
static int port_tcp = 7681, cur = -1, result = 1, legs_run;
static unsigned long turns, leg_turns;
static lws_usec_t leg_start;

/* per-leg state */
static int cli_closed, srv_closed, peer_close_seen, peer_close_ok, sent_close,
	   sent_msg;

static void
fail_leg(const char *why)
{
	lwsl_err("--- leg %d (%s): %s ---\n", cur, legs[cur].name, why);
	lws_default_loop_exit(context);
}

static struct lws_vhost *
vhost_for(const char *name)
{
	int n;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(vh_cli_names); n++)
		if (!strcmp(vh_cli_names[n], name))
			return vh_cli[n];

	return NULL;
}

static void
start_leg(lws_sorted_usec_list_t *sul);

static void
leg_done_check(void)
{
	lws_usec_t us;

	if (!cli_closed || !srv_closed)
		return;

	if (!peer_close_seen) {
		fail_leg("peer never saw the close frame");
		return;
	}
	if (!peer_close_ok) {
		fail_leg("close code / reason did not survive");
		return;
	}
	us = lws_now_usecs() - leg_start;
	if (us > LEG_MAX_US || turns - leg_turns > LEG_MAX_TURNS) {
		lwsl_err("%dms, %lu service turns\n", (int)(us / LWS_US_PER_MS),
			 turns - leg_turns);
		fail_leg(us > LEG_MAX_US ? "close took too long" :
					   "service loop spun during the close");
		return;
	}

	lwsl_user("--- leg %d (%s): OK (%dms, %lu service turns) ---\n", cur,
		  legs[cur].name, (int)(us / LWS_US_PER_MS), turns - leg_turns);
	legs_run++;

	/* leave the close path before reconnecting */
	lws_sul_schedule(context, 0, &sul_next, start_leg, 1000);
}

static int
check_encap(struct lws *wsi)
{
	int encap = lws_get_network_wsi(wsi) != wsi;

	if (encap != legs[cur].h2) {
		fail_leg(encap ? "unexpectedly ws-over-h2" :
				 "not ws-over-h2");
		return 1;
	}

	return 0;
}

static void
check_peer_close(void *in, size_t len, int code, const char *reason)
{
	const uint8_t *p = (const uint8_t *)in;
	size_t rl = strlen(reason);

	peer_close_seen = 1;

	if (len != 2 + rl) {
		lwsl_err("close payload len %d, expected %d\n", (int)len,
			 (int)(2 + rl));
		return;
	}
	if (((p[0] << 8) | p[1]) != code) {
		lwsl_err("close code %d, expected %d\n", (p[0] << 8) | p[1],
			 code);
		return;
	}
	if (memcmp(p + 2, reason, rl)) {
		lwsl_err("close reason mismatch\n");
		return;
	}

	peer_close_ok = 1;
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		lwsl_user("%s: server: established\n", __func__);
		if (check_encap(wsi))
			return -1;
		if (legs[cur].server_initiates && !legs[cur].pmd_mid_drain)
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RECEIVE:
		if (!legs[cur].pmd_mid_drain || sent_close)
			break;
		/*
		 * The first inflated chunk of the client's message: the rest
		 * of the compressed frame is still to come, and the inflater
		 * holds more output from what came so far.  We have seen
		 * enough, and close.
		 */
		if (!lws_remaining_packet_payload(wsi)) {
			fail_leg("pmd message not partway through a frame");
			return -1;
		}
		sent_close = 1;
		lwsl_user("%s: server: closing mid-message\n", __func__);
		lws_close_reason(wsi, SRV_CODE, (unsigned char *)SRV_REASON,
				 strlen(SRV_REASON));
		return -1;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (!legs[cur].server_initiates || legs[cur].pmd_mid_drain ||
		    sent_close)
			break;
		sent_close = 1;
		lwsl_user("%s: server: initiating close\n", __func__);
		/*
		 * with no prepared reason, lws must still send a Close frame
		 * and the peer must see 1000 with no reason text
		 */
		if (!legs[cur].default_reason)
			lws_close_reason(wsi, SRV_CODE,
					 (unsigned char *)SRV_REASON,
					 strlen(SRV_REASON));
		return -1;

	case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
		lwsl_user("%s: server: peer-initiated close, %d bytes\n",
			  __func__, (int)len);
		if (legs[cur].server_initiates) {
			fail_leg("server saw a peer close it initiated");
			return -1;
		}
		if (legs[cur].default_reason)
			check_peer_close(in, len, LWS_CLOSE_STATUS_NORMAL, "");
		else
			check_peer_close(in, len, CLI_CODE, CLI_REASON);
		break;

	case LWS_CALLBACK_CLOSED:
		lwsl_user("%s: server: closed\n", __func__);
		srv_closed = 1;
		leg_done_check();
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lwsl_user("%s: client: established\n", __func__);
		if (check_encap(wsi))
			return -1;
		if (!legs[cur].server_initiates || legs[cur].pmd_mid_drain)
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		if (legs[cur].pmd_mid_drain) {
			uint8_t *buf;
			int n;

			if (sent_msg)
				break;
			sent_msg = 1;

			buf = malloc(LWS_PRE + PMD_MSG_LEN);
			if (!buf)
				return -1;
			/* compresses, but not to nothing */
			for (n = 0; n < PMD_MSG_LEN; n++)
				buf[LWS_PRE + n] = (uint8_t)('a' + ((n * 7) % 13) +
							     ((n >> 9) & 7));
			n = lws_write(wsi, buf + LWS_PRE, PMD_MSG_LEN,
				      LWS_WRITE_TEXT);
			free(buf);
			if (n < 0)
				return -1;
			break;
		}
		if (legs[cur].server_initiates || sent_close)
			break;
		sent_close = 1;
		lwsl_user("%s: client: initiating close\n", __func__);
		if (!legs[cur].default_reason)
			lws_close_reason(wsi, CLI_CODE,
					 (unsigned char *)CLI_REASON,
					 strlen(CLI_REASON));
		return -1;

	case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
		lwsl_user("%s: client: peer-initiated close, %d bytes\n",
			  __func__, (int)len);
		if (!legs[cur].server_initiates) {
			fail_leg("client saw a peer close it initiated");
			return -1;
		}
		if (legs[cur].default_reason)
			check_peer_close(in, len, LWS_CLOSE_STATUS_NORMAL, "");
		else
			check_peer_close(in, len, SRV_CODE, SRV_REASON);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("--- client connection error: %s ---\n",
			 in ? (char *)in : "(null)");
		fail_leg("connection error");
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		lwsl_user("%s: client: closed\n", __func__);
		cli_closed = 1;
		leg_done_check();
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	{ "wsclose", callback_srv, 0, 256, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "wsclose", callback_cli, 0, 256, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

#if !defined(LWS_WITHOUT_EXTENSIONS)
/*
 * The pmd client deflates into frames of up to 4KB, so each is larger than
 * the server's 256-byte rx buffer, and one message spans several
 */
static const struct lws_protocols protocols_cli_pmd[] = {
	{ "wsclose", callback_cli, 0, 4096, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_extension extensions[] = {
	{
		"permessage-deflate",
		lws_extension_callback_pm_deflate,
		"permessage-deflate"
		 "; client_no_context_takeover"
		 "; client_max_window_bits"
	},
	{ NULL, NULL, NULL /* terminator */ }
};
#endif

static void
start_leg(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	struct lws_vhost *vh;

	do {
		cur++;
		if (cur == (int)LWS_ARRAY_SIZE(legs)) {
			lwsl_user("--- all %d legs passed ---\n", legs_run);
			result = 0;
			lws_default_loop_exit(context);
			return;
		}
		vh = vhost_for(legs[cur].vhost);
		if (!vh)
			lwsl_user("--- leg %d (%s): skipped, no %s ---\n", cur,
				  legs[cur].name, legs[cur].vhost);
	} while (!vh);

	lwsl_user("--- leg %d (%s): starting ---\n", cur, legs[cur].name);

	cli_closed = srv_closed = peer_close_seen = peer_close_ok =
						sent_close = sent_msg = 0;
	leg_start = lws_now_usecs();
	leg_turns = turns;

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.vhost = vh;
	i.address = server_ads;
	i.port = port_tcp;
	i.path = "/";
	i.host = server_ads;
	i.origin = server_ads;
	i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
			   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	i.alpn = legs[cur].alpn;
	i.protocol = "wsclose";
	i.local_protocol_name = "wsclose";

	if (!lws_client_connect_via_info(&i))
		fail_leg("client connect failed");
}

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("--- timed out in leg %d ---\n", cur);
	lws_default_loop_exit(context);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

static int
split_hostport(const char *hp, char *host, size_t hl, unsigned int *port)
{
	const char *c = strrchr(hp, ':');

	if (!c || (size_t)(c - hp) >= hl)
		return 1;

	memcpy(host, hp, (size_t)(c - hp));
	host[c - hp] = '\0';
	*port = (unsigned int)atoi(c + 1);

	return 0;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	char proxy_host[64], socks[128], socks_auth[128];
	unsigned int proxy_port = 0;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_tcp = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_ads = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: ws close handshake\n");

	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* ws server vhost, offering h2 and h1 */
	info.port = port_tcp;
	info.vhost_name = "srv";
	info.alpn = "h2,http/1.1";
	info.protocols = protocols_srv;
	info.ssl_cert_filepath = "localhost-100y.cert";
	info.ssl_private_key_filepath = "localhost-100y.key";
#if !defined(LWS_WITHOUT_EXTENSIONS)
	/* only a client that asks for it gets pmd */
	info.extensions = extensions;
#endif

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create server vhost\n");
		goto bail;
	}
	info.extensions = NULL;

	/* direct client vhost */
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.alpn = NULL;
	info.protocols = protocols_cli;
	info.ssl_cert_filepath = NULL;
	info.ssl_private_key_filepath = NULL;
	info.vhost_name = vh_cli_names[0];

	vh_cli[0] = lws_create_vhost(context, &info);
	if (!vh_cli[0]) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	/* client vhost via http CONNECT proxy */
	if ((p = lws_cmdline_option(argc, argv, "--proxy"))) {
		if (split_hostport(p, proxy_host, sizeof(proxy_host),
				   &proxy_port)) {
			lwsl_err("--proxy wants host:port\n");
			goto bail;
		}
		info.vhost_name = vh_cli_names[1];
		info.http_proxy_address = proxy_host;
		info.http_proxy_port = proxy_port;
		vh_cli[1] = lws_create_vhost(context, &info);
		info.http_proxy_address = NULL;
		info.http_proxy_port = 0;
		if (!vh_cli[1]) {
			lwsl_err("Failed to create proxy client vhost\n");
			goto bail;
		}
	}

#if defined(LWS_WITH_SOCKS5)
	/* client vhost via socks5, no auth */
	if ((p = lws_cmdline_option(argc, argv, "--socks"))) {
		lws_strncpy(socks, p, sizeof(socks));
		info.vhost_name = vh_cli_names[2];
		info.socks_proxy_address = socks;
		vh_cli[2] = lws_create_vhost(context, &info);
		info.socks_proxy_address = NULL;
		if (!vh_cli[2]) {
			lwsl_err("Failed to create socks client vhost\n");
			goto bail;
		}
	}

	/* client vhost via socks5 requiring username / password */
	if ((p = lws_cmdline_option(argc, argv, "--socks-auth"))) {
		lws_snprintf(socks_auth, sizeof(socks_auth), "user:pass@%s", p);
		info.vhost_name = vh_cli_names[3];
		info.socks_proxy_address = socks_auth;
		vh_cli[3] = lws_create_vhost(context, &info);
		info.socks_proxy_address = NULL;
		if (!vh_cli[3]) {
			lwsl_err("Failed to create socks auth client vhost\n");
			goto bail;
		}
	}
#else
	(void)socks;
	(void)socks_auth;
#endif

#if !defined(LWS_WITHOUT_EXTENSIONS)
	/* client vhost offering permessage-deflate */
	info.vhost_name = vh_cli_names[4];
	info.protocols = protocols_cli_pmd;
	info.extensions = extensions;
	vh_cli[4] = lws_create_vhost(context, &info);
	info.extensions = NULL;
	if (!vh_cli[4]) {
		lwsl_err("Failed to create pmd client vhost\n");
		goto bail;
	}
#endif

	lws_sul_schedule(context, 0, &sul_next, start_leg, 1);
	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 30 * LWS_US_PER_SEC);

	while (n >= 0) {
		n = lws_service(context, 0);
		turns++;
	}

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
