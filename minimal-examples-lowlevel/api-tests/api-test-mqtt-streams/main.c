/*
 * lws-api-test-mqtt-streams
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * MQTT client streams to the same broker, asked to pipeline
 * (LCCSCF_PIPELINE, as Secure Streams does), share one connection: those
 * that arrive while it is still connecting queue on it and are adopted at
 * CONNACK, later ones join it directly.  A connection takes at most
 * LWS_MQTT_MAX_CHILDREN (8) streams, so the rest must wait on its queue
 * until a stream closes, and then take the freed slot.
 *
 * Nine streams are started back to back, so eight are adopted at CONNACK and
 * the ninth has to wait; once those eight are established a tenth is
 * started, which the full connection must queue too.  Both must still be
 * waiting (no ESTABLISHED, no CONNECTION_ERROR) after a settle.  Then two
 * of the established streams are closed, and both waiting streams must be
 * established on the slots they free, on the same broker connection.
 *
 * Before this test the ninth stream was dropped from the queue with its
 * adopt refused and never heard of again, and a stream queued on an
 * established mqtt connection was never adopted however many streams closed.
 *
 * The broker is an in-process fake on an ONLY_RAW vhost, as in
 * api-test-mqtt-unsub: it answers CONNECT with CONNACK and PINGREQ with
 * PINGRESP, and counts the connections it accepts.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define MAX_CHILDREN		8	/* lws' LWS_MQTT_MAX_CHILDREN */
#define N_FIRST			(MAX_CHILDREN + 1)
#define N_STREAMS		(N_FIRST + 1)
#define SETTLE_MS		300
#define WATCHDOG_S		15

static int port = 7681;
static int fails, done;
static struct lws_context *cx;
static lws_sorted_usec_list_t sul_watchdog, sul_step;

struct stream {
	struct lws	*wsi;
	uint8_t		established;
	uint8_t		closed;
	uint8_t		error;
};

static struct stream streams[N_STREAMS];

static struct {
	int		accepted;	/* broker connections adopted */
	int		closed;
} broker;

static const lws_mqtt_client_connect_param_t conn_param = {
	.client_id				= "lws-api-test-mqtt-streams",
	.keep_alive				= 60,
	.clean_start				= 1,
	.client_id_nofree			= 1,
	.username_nofree			= 1,
	.password_nofree			= 1,
};

/*
 * Fake MQTT broker side
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
	case LWS_CALLBACK_RAW_ADOPT:
		broker.accepted++;
		lwsl_user("%s: broker: connection %d\n", __func__,
			  broker.accepted);
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		broker.closed++;
		break;

	case LWS_CALLBACK_RAW_RX: {
		static const uint8_t connack[] = { 0x20, 0x02, 0x00, 0x00 },
				     pingresp[] = { 0xd0, 0x00 };

		if (pss->rx_len + len > sizeof(pss->rx)) {
			lwsl_err("%s: broker rx overflow\n", __func__);

			return -1;
		}
		memcpy(pss->rx + pss->rx_len, in, len);
		pss->rx_len += len;

		while (pos < pss->rx_len) {
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
				/* accept it: flags 0, return code 0 */
				if (broker_tx(pss, connack, sizeof(connack)))
					return -1;
				break;

			case LMQCP_CTOS_PINGREQ:
				if (broker_tx(pss, pingresp, sizeof(pingresp)))
					return -1;
				break;

			default:
				break; /* eg, DISCONNECT: nothing to reply */
			}

			pos += pkt_len;
		}

		/* consume the packets we dealt with */
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

static int
n_established(void)
{
	int n, c = 0;

	for (n = 0; n < N_STREAMS; n++)
		c += streams[n].established;

	return c;
}

static int
n_errors(void)
{
	int n, c = 0;

	for (n = 0; n < N_STREAMS; n++)
		c += streams[n].error;

	return c;
}

static int
stream_start(int n)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof i);
	i.mqtt_cp		= &conn_param;
	i.context		= cx;
	i.address		= "127.0.0.1";
	i.host			= "127.0.0.1";
	i.port			= port;
	i.protocol		= "mqtt";
	i.method		= "MQTT";
	i.alpn			= "mqtt";
	i.opaque_user_data	= &streams[n];
	/* share the connection to the broker */
	i.ssl_connection	= LCCSCF_PIPELINE;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: stream %d: connect failed\n", __func__, n);

		return 1;
	}

	return 0;
}

static void
finish(void)
{
	if (done)
		return;
	done = 1;
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_step);
	lws_default_loop_exit(cx);
}

/*
 * Steps, each after a settle so what should not happen has had time to:
 *
 *  1: eight of the first nine are established, the ninth waits; start the
 *     tenth
 *  2: the ninth and tenth both still wait; close two established streams
 *  3: all ten were established, on the one connection
 */
static void
step_cb(lws_sorted_usec_list_t *sul)
{
	static int step;
	int n, k;

	step++;
	lwsl_user("%s: step %d: %d established, %d errors, %d broker conns\n",
		  __func__, step, n_established(), n_errors(),
		  broker.accepted);

	switch (step) {
	case 1:
		if (n_established() != MAX_CHILDREN) {
			lwsl_err("%s: expected %d established of the first "
				 "%d\n", __func__, MAX_CHILDREN, N_FIRST);
			fails++;
		}
		if (stream_start(N_FIRST))
			fails++;
		break;

	case 2:
		if (n_established() != MAX_CHILDREN || n_errors()) {
			lwsl_err("%s: the waiting streams should still be "
				 "waiting\n", __func__);
			fails++;
		}
		/* close two of the established streams */
		for (n = 0, k = 0; n < N_FIRST && k < 2; n++)
			if (streams[n].established && !streams[n].closed &&
			    streams[n].wsi) {
				lwsl_user("%s: closing stream %d\n", __func__,
					  n);
				lws_set_timeout(streams[n].wsi,
						PENDING_TIMEOUT_USER_OK,
						LWS_TO_KILL_ASYNC);
				k++;
			}
		break;

	default:
		if (n_established() != N_STREAMS) {
			lwsl_err("%s: expected all %d streams established\n",
				 __func__, N_STREAMS);
			fails++;
		}
		if (n_errors()) {
			lwsl_err("%s: %d streams failed\n", __func__,
				 n_errors());
			fails++;
		}
		if (broker.accepted != 1) {
			lwsl_err("%s: expected one broker connection, saw "
				 "%d\n", __func__, broker.accepted);
			fails++;
		}
		finish();
		return;
	}

	if (fails) {
		finish();
		return;
	}

	lws_sul_schedule(cx, 0, &sul_step, step_cb, SETTLE_MS * LWS_US_PER_MS);
}

static int
callback_mqtt(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	      void *in, size_t len)
{
	struct stream *s = (struct stream *)lws_get_opaque_user_data(wsi);
	int n;

	if (!s)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	n = (int)(s - &streams[0]);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: stream %d: connection error: %s\n", __func__, n,
			 in ? (const char *)in : "(null)");
		s->error = 1;
		break;

	case LWS_CALLBACK_MQTT_CLIENT_ESTABLISHED:
		lwsl_user("%s: stream %d: established\n", __func__, n);
		s->established = 1;
		s->wsi = wsi;
		/* the first eight arriving starts the steps */
		if (n_established() == MAX_CHILDREN && !done)
			lws_sul_schedule(cx, 0, &sul_step, step_cb,
					 SETTLE_MS * LWS_US_PER_MS);
		break;

	case LWS_CALLBACK_MQTT_CLIENT_CLOSED:
		lwsl_user("%s: stream %d: closed\n", __func__, n);
		s->closed = 1;
		s->wsi = NULL;
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{
		.name			= "lws-api-test-mqtt-streams-broker",
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
	lwsl_err("%s: timed out: %d established, %d errors, %d broker conns\n",
		 __func__, n_established(), n_errors(), broker.accepted);
	fails++;
	finish();
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n, n2 = 0;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* the defaults budget fds for a lone client; we have both ends */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);

	lwsl_user("LWS API selftest: mqtt streams beyond a connection's "
		  "limit\n");

	/*
	 * The default vhost is the fake broker: it listens in RAW mode, and
	 * accepted connections bind the first protocol above.  The mqtt
	 * client protocol is found by name on the same vhost for the
	 * outbound streams.
	 */

	info.port		= port;
	info.protocols		= protocols;
	info.options		= LWS_SERVER_OPTION_ONLY_RAW;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");

		return 1;
	}

	lws_sul_schedule(cx, 0, &sul_watchdog, watchdog_cb,
			 WATCHDOG_S * LWS_USEC_PER_SEC);

	/*
	 * Back to back: the first makes the connection, the rest find it on
	 * the vhost's active connections and queue on it
	 */
	for (n = 0; n < N_FIRST; n++)
		if (stream_start(n)) {
			fails++;
			goto bail;
		}

	while (n2 >= 0 && !done)
		n2 = lws_service(cx, 0);

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_step);
	lws_context_destroy(cx);

	if (fails || !done) {
		lwsl_user("Completed: failed\n");

		return 1;
	}

	lwsl_user("Completed: OK\n");

	return 0;
}
