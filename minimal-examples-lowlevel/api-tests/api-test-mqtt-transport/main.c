/*
 * lws-api-test-mqtt-transport
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The mqtt client's transports other than plain tcp: the transport comes up
 * after its tls handshake, after the http CONNECT proxy's 200, or after the
 * SOCKS5 proxy's connect reply, and the client's CONNECT goes on it then.
 * Each leg connects the real lws mqtt client to an in-process fake broker,
 * on a vhost binding what it accepts to raw-skt, and is done when the
 * broker's CONNACK has established it:
 *
 *  - over tls, to the broker's tls vhost (--port-tls, with --cert / --key)
 *  - through an http CONNECT proxy (--proxy host:port)
 *  - through a SOCKS5 proxy (--socks host:port), when built with
 *    LWS_WITH_SOCKS5
 *
 * ctest runs it against api-test-ws-close's proxy-fixture.py, which is
 * both kinds of proxy on one port.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define WATCHDOG_S		20

enum {
	LEG_TLS,
	LEG_HTTP_PROXY,
	LEG_SOCKS5,
	LEG_COUNT
};

static const char * const leg_names[] = {
	"tls", "http CONNECT proxy", "socks5"
};

static int port = 7681, port_tls = 7682, fails, done, leg = -1;
static struct lws_context *cx;
static struct lws_vhost *vh_cli[LEG_COUNT];
static lws_sorted_usec_list_t sul_watchdog, sul_next;
static int established, conn_error;

static const lws_mqtt_client_connect_param_t conn_param = {
	.client_id				= "lws-api-test-mqtt-transport",
	.keep_alive				= 60,
	.clean_start				= 1,
	.client_id_nofree			= 1,
	.username_nofree			= 1,
	.password_nofree			= 1,
};

/*
 * Fake MQTT broker side: CONNACK to CONNECT, PINGRESP to PINGREQ
 */

struct broker_pss {
	uint8_t				rx[1024];
	size_t				rx_len;
	uint8_t				tx[64];
	size_t				tx_len;
};

/* decode an MQTT VBI at buf, returns bytes consumed, or 0 if incomplete */
static size_t
vbi_decode(const uint8_t *buf, size_t len, uint32_t *remlen)
{
	size_t used = 0;
	uint32_t val = 0, mult = 1;

	while (used < len && used < 4) {
		uint8_t b = buf[used++];

		val += (uint32_t)(b & 0x7f) * mult;
		if (!(b & 0x80)) {
			*remlen = val;

			return used;
		}
		mult <<= 7;
	}

	return 0;
}

static int
broker_tx(struct broker_pss *pss, const uint8_t *pkt, size_t len)
{
	if (pss->tx_len + len > sizeof(pss->tx)) {
		lwsl_err("%s: broker tx overflow\n", __func__);

		return 1;
	}

	memcpy(pss->tx + pss->tx_len, pkt, len);
	pss->tx_len += len;

	return 0;
}

static int
callback_fake_broker(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	struct broker_pss *pss = (struct broker_pss *)user;
	size_t pos = 0;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX: {
		static const uint8_t connack[] = { 0x20, 0x02, 0x00, 0x00 },
				     pingresp[] = { 0xd0, 0x00 };

		if (pss->rx_len + len > sizeof(pss->rx)) {
			lwsl_err("%s: broker rx overflow\n", __func__);

			return -1;
		}
		memcpy(pss->rx + pss->rx_len, in, len);
		pss->rx_len += len;

		while (pos + 1 < pss->rx_len) {
			uint32_t remlen;
			size_t hsz, pkt_len;

			hsz = vbi_decode(pss->rx + pos + 1,
					 pss->rx_len - pos - 1, &remlen);
			if (!hsz)
				break; /* need more bytes for the header */

			pkt_len = 1 + hsz + remlen;
			if (pos + pkt_len > pss->rx_len)
				break; /* wait for the rest of the packet */

			switch (pss->rx[pos] >> 4) {
			case LMQCP_CTOS_CONNECT:
				if (broker_tx(pss, connack, sizeof(connack)))
					return -1;
				break;

			case LMQCP_CTOS_PINGREQ:
				if (broker_tx(pss, pingresp, sizeof(pingresp)))
					return -1;
				break;

			default:
				break;
			}

			pos += pkt_len;
		}

		memmove(pss->rx, pss->rx + pos, pss->rx_len - pos);
		pss->rx_len -= pos;

		if (pss->tx_len)
			lws_callback_on_writable(wsi);
		break;
	}

	case LWS_CALLBACK_RAW_WRITEABLE: {
		size_t tx_len = pss->tx_len;

		pss->tx_len = 0;
		if (tx_len &&
		    lws_write(wsi, pss->tx, tx_len, LWS_WRITE_RAW) !=
							(int)tx_len) {
			lwsl_err("%s: broker write failed\n", __func__);

			return -1;
		}
		break;
	}

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * MQTT client side
 */

static void
finish(void)
{
	if (done)
		return;
	done = 1;
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_next);
	lws_default_loop_exit(cx);
}

static void
next_leg(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	/* the next leg we have a client vhost for */
	do {
		leg++;
	} while (leg < LEG_COUNT && !vh_cli[leg]);

	if (leg == LEG_COUNT) {
		finish();
		return;
	}

	lwsl_user("%s: leg %d: %s\n", __func__, leg, leg_names[leg]);
	established = conn_error = 0;

	memset(&i, 0, sizeof i);
	i.mqtt_cp		= &conn_param;
	i.context		= cx;
	i.vhost			= vh_cli[leg];
	i.address		= "127.0.0.1";
	i.host			= "127.0.0.1";
	i.port			= leg == LEG_TLS ? port_tls : port;
	i.protocol		= "mqtt";
	i.method		= "MQTT";
	i.alpn			= "mqtt";
	if (leg == LEG_TLS)
		i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: leg %d: connect failed\n", __func__, leg);
		fails++;
		finish();
	}
}

static int
callback_mqtt(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	      void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: leg %d: connection error: %s\n", __func__, leg,
			 in ? (const char *)in : "(null)");
		conn_error = 1;
		fails++;
		finish();
		break;

	case LWS_CALLBACK_MQTT_CLIENT_ESTABLISHED:
		lwsl_user("%s: leg %d: established\n", __func__, leg);
		established = 1;
		/* done with it: the next leg once it has closed */
		return -1;

	case LWS_CALLBACK_MQTT_CLIENT_CLOSED:
		if (!established && !conn_error) {
			lwsl_err("%s: leg %d: closed unestablished\n", __func__,
				 leg);
			fails++;
			finish();
			break;
		}
		if (!done)
			lws_sul_schedule(cx, 0, &sul_next, next_leg, 1);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{
		.name			= "lws-api-test-mqtt-transport-broker",
		.callback		= callback_fake_broker,
		.per_session_data_size	= sizeof(struct broker_pss),
	},
	{
		.name			= "mqtt",
		.callback		= callback_mqtt,
	},
	LWS_PROTOCOL_LIST_TERM
};

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: leg %d timed out\n", __func__, leg);
	fails++;
	finish();
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

static int
split_hostport(const char *hp, char *host, size_t hl, unsigned int *pport)
{
	const char *c = strrchr(hp, ':');

	if (!c || (size_t)(c - hp) >= hl)
		return 1;

	memcpy(host, hp, (size_t)(c - hp));
	host[c - hp] = '\0';
	*pport = (unsigned int)atoi(c + 1);

	return 0;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p, *cert, *key;
	char proxy_host[64];
	unsigned int proxy_port;
	int n = 0;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* the defaults budget fds for a lone client; we have both ends */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-tls")))
		port_tls = atoi(p);
	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");

	lwsl_user("LWS API selftest: mqtt client over tls and proxies\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");

		return 1;
	}

	/* the fake broker, in the clear and over tls */
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = "raw-skt";
	info.listen_accept_protocol = "lws-api-test-mqtt-transport-broker";
	info.protocols = protocols;
	info.vhost_name = "broker";
	info.port = port;
	if (!lws_create_vhost(cx, &info)) {
		lwsl_err("broker vhost failed\n");
		goto bail;
	}
	if (cert && key) {
		info.vhost_name = "broker-tls";
		info.port = port_tls;
		info.ssl_cert_filepath = cert;
		info.ssl_private_key_filepath = key;
		if (!lws_create_vhost(cx, &info)) {
			lwsl_err("broker tls vhost failed\n");
			goto bail;
		}
		info.ssl_cert_filepath = NULL;
		info.ssl_private_key_filepath = NULL;
	}

	/* the client vhosts, one per leg it has what it needs for */
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.listen_accept_role = NULL;
	info.listen_accept_protocol = NULL;
	info.port = CONTEXT_PORT_NO_LISTEN;
	if (cert && key) {
		info.vhost_name = "cli-tls";
		vh_cli[LEG_TLS] = lws_create_vhost(cx, &info);
		if (!vh_cli[LEG_TLS])
			goto bail;
	}
	if ((p = lws_cmdline_option(argc, argv, "--proxy"))) {
		if (split_hostport(p, proxy_host, sizeof(proxy_host),
				   &proxy_port)) {
			lwsl_err("--proxy wants host:port\n");
			goto bail;
		}
		info.vhost_name = "cli-hp";
		info.http_proxy_address = proxy_host;
		info.http_proxy_port = proxy_port;
		vh_cli[LEG_HTTP_PROXY] = lws_create_vhost(cx, &info);
		info.http_proxy_address = NULL;
		info.http_proxy_port = 0;
		if (!vh_cli[LEG_HTTP_PROXY])
			goto bail;
	}
#if defined(LWS_WITH_SOCKS5)
	if ((p = lws_cmdline_option(argc, argv, "--socks"))) {
		info.vhost_name = "cli-s5";
		info.socks_proxy_address = p;
		vh_cli[LEG_SOCKS5] = lws_create_vhost(cx, &info);
		info.socks_proxy_address = NULL;
		if (!vh_cli[LEG_SOCKS5])
			goto bail;
	}
#endif

	lws_sul_schedule(cx, 0, &sul_watchdog, watchdog_cb,
			 WATCHDOG_S * LWS_USEC_PER_SEC);
	lws_sul_schedule(cx, 0, &sul_next, next_leg, 1);

	while (n >= 0 && !done)
		n = lws_service(cx, 0);

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_next);
	lws_context_destroy(cx);

	if (fails || !done) {
		lwsl_user("Completed: failed\n");

		return 1;
	}

	lwsl_user("Completed: OK\n");

	return 0;
}
