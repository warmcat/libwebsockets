/*
 * lws-api-test-mqtt-inflight
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Fence for the operations an mqtt client stream has awaiting the broker's
 * ack.  A stream tracks one, by a single packet id, and LWS_CALLBACK_MQTT_ACK
 * doesn't say which operation it is about, so:
 *
 *  - busy: a second acked operation started while one awaits its ack must be
 *    refused, not silently take over the stream's packet id
 *  - qos2 back to back: MQTT_ACK for a QoS2 PUBLISH comes at its PUBREC, and
 *    the stream may publish again then, before the PUBCOMP of the first has
 *    come: that PUBCOMP must not be taken for unsolicited
 *  - resend: after MQTT_RESEND, a resend with dup set must go with the
 *    packet id the PUBLISH had, even though another stream on the connection
 *    took a new id meanwhile, and a second PUBACK for it must be ignored
 *  - gone: a stream closes with a QoS2 PUBLISH awaiting its PUBREC.  When
 *    that comes, the connection must still release the id with a PUBREL,
 *    ignore the PUBCOMP that answers it, and carry on for the other stream
 *
 * Any of those used to close the connection, with every stream on it, on an
 * ack no stream claimed.
 *
 * Two streams share one connection to an in-process fake broker on an
 * ONLY_RAW vhost, which answers each PUBLISH according to its payload.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int port = 7681;
static int fails, completed;
static struct lws_context *cx;
static lws_sorted_usec_list_t sul_watchdog;

static const char topic[] = "lws/api-test-mqtt-inflight";

static const lws_mqtt_client_connect_param_t conn_param = {
	.client_id				= "lws-api-test-mqtt-inflight",
	.keep_alive				= 60,
	.clean_start				= 1,
	.client_id_nofree			= 1,
	.username_nofree			= 1,
	.password_nofree			= 1,
};

static lws_mqtt_topic_elem_t topics[] = {
	{ .name = topic, .qos = QOS1 },
};

static lws_mqtt_subscribe_param_t sub_param = {
	.topic					= topics,
	.num_topics				= LWS_ARRAY_SIZE(topics),
};

static enum {
	IS_BUSY,
	IS_QOS2_B2B,
	IS_RESEND,
	IS_GONE,
} step;

/* what a client stream does on its next WRITEABLE */
enum {
	IA_NONE,
	IA_BUSY_FIRST,		/* QoS1, then try another, and a SUBSCRIBE */
	IA_BUSY_SECOND,		/* the other QoS1, now the first is acked */
	IA_B2B_FIRST,		/* QoS2 */
	IA_B2B_SECOND,		/* QoS2 again, at the first one's MQTT_ACK */
	IA_RESEND_FIRST,	/* QoS1, whose PUBACK is withheld */
	IA_RESEND_DUP,		/* resend it, at MQTT_RESEND */
	IA_AUX,			/* the other stream takes a packet id */
	IA_GONE,		/* the other stream: QoS2, then close */
	IA_DONE,		/* QoS1 to finish */
};

struct cstream {
	const char			*name;
	struct lws			*wsi;
	int				action;
	unsigned int			acks;	/* MQTT_ACK this step */
	char				closed;
};

static struct cstream sa = { .name = "a" }, sb = { .name = "b" };

/*
 * Fake MQTT broker side
 */

static struct {
	struct lws			*wsi;
	uint8_t				rx[1024];
	size_t				rx_len;
	uint8_t				tx[512];
	size_t				tx_len;
	int				accepted;
	uint16_t			b2b_first;	/* PUBCOMP withheld */
	uint16_t			resend_id;
	uint16_t			aux_id;
	uint16_t			gone_id;
	char				gone_rx;
} broker;

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

static void
fail(const char *why)
{
	lwsl_err("FAIL: %s\n", why);
	fails++;
	lws_default_loop_exit(cx);
	lws_cancel_service(cx);
}

/* PUBACK, PUBREC or PUBCOMP, written on the broker's next WRITEABLE */
static void
broker_tx_ack(uint8_t cmd, uint16_t pkt_id)
{
	if (broker.tx_len + 4 > sizeof(broker.tx)) {
		fail("broker tx overflow");

		return;
	}

	broker.tx[broker.tx_len++] = cmd;
	broker.tx[broker.tx_len++] = 2;
	broker.tx[broker.tx_len++] = (uint8_t)(pkt_id >> 8);
	broker.tx[broker.tx_len++] = (uint8_t)(pkt_id & 0xff);

	if (broker.wsi)
		lws_callback_on_writable(broker.wsi);
}

static void
client_act(struct cstream *s, int action)
{
	s->action = action;
	if (s->wsi)
		lws_callback_on_writable(s->wsi);
}

/*
 * The gone stream's PUBREC is sent once its PUBLISH has arrived and the
 * stream has closed: no stream has that PUBLISH in flight any more
 */
static void
broker_gone_pubrec(void)
{
	if (broker.gone_rx && sb.closed) {
		lwsl_user("%s: PUBREC for the closed stream's PUBLISH\n",
			  __func__);
		broker_tx_ack(0x50, broker.gone_id);
	}
}

/* a PUBLISH from a client stream, answered according to its payload */
static void
broker_rx_publish(const uint8_t *pkt, const uint8_t *pay, uint32_t remlen)
{
	unsigned int qos = (pkt[0] >> 1) & 3, dup = !!(pkt[0] & 8);
	uint16_t tlen, id;
	const char *p;
	size_t plen;

	if (remlen < 2)
		goto bad;
	tlen = (uint16_t)((pay[0] << 8) | pay[1]);
	if (!qos || remlen < 4u + tlen)
		goto bad;

	id = (uint16_t)((pay[2 + tlen] << 8) | pay[3 + tlen]);
	if (!id) {
		fail("PUBLISH with packet id 0");

		return;
	}
	p = (const char *)pay + 4 + tlen;
	plen = remlen - 4u - tlen;

#define IS(s) (plen == strlen(s) && !memcmp(p, s, plen))

	if (IS("b2b-1")) {
		broker_tx_ack(0x50, id);

		return;
	}
	if (IS("b2b-2")) {
		/*
		 * Only now does the first one's PUBCOMP come, when the stream
		 * has started another QoS2 PUBLISH
		 */
		broker_tx_ack(0x70, broker.b2b_first);
		broker.b2b_first = 0;
		broker_tx_ack(0x50, id);

		return;
	}
	if (IS("resend")) {
		if (!dup) {
			/*
			 * Withheld, until the client resends it.  Meanwhile
			 * the other stream takes the connection's next id.
			 */
			broker.resend_id = id;
			client_act(&sb, IA_AUX);

			return;
		}
		if (id != broker.resend_id) {
			lwsl_err("%s: resend went with id %u, not %u\n",
				 __func__, id, broker.resend_id);
			fail("resend with a new packet id");

			return;
		}
		if (!broker.aux_id) {
			fail("the other stream took no id before the resend");

			return;
		}
		/* acked twice: the second must be ignored */
		broker_tx_ack(0x40, id);
		broker_tx_ack(0x40, id);

		return;
	}
	if (IS("aux")) {
		if (!broker.resend_id) {
			fail("the other stream's id came before the resend's");

			return;
		}
		broker.aux_id = id;
		broker_tx_ack(0x40, id);

		return;
	}
	if (IS("gone")) {
		broker.gone_id = id;
		broker.gone_rx = 1;
		broker_gone_pubrec();

		return;
	}

	/* busy-1, busy-2, done */
	if (qos == 1) {
		broker_tx_ack(0x40, id);

		return;
	}

bad:
	lwsl_hexdump_err(pkt, remlen + 2);
	fail("unexpected PUBLISH");
}

static int
callback_fake_broker(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	size_t pos = 0;

	switch (reason) {

	case LWS_CALLBACK_RAW_ADOPT:
		broker.wsi = wsi;
		broker.accepted++;
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		broker.wsi = NULL;
		break;

	case LWS_CALLBACK_RAW_RX:
		if (broker.rx_len + len > sizeof(broker.rx)) {
			fail("broker rx overflow");

			return -1;
		}
		memcpy(broker.rx + broker.rx_len, in, len);
		broker.rx_len += len;

		while (pos < broker.rx_len) {
			const uint8_t *pay;
			uint32_t remlen;
			size_t hsz, pkt_len;
			uint16_t id;

			hsz = vbi_decode(broker.rx + pos + 1,
					 broker.rx_len - pos - 1, &remlen);
			if (!hsz)
				break;
			pkt_len = 1 + hsz + remlen;
			if (pos + pkt_len > broker.rx_len)
				break;
			pay = broker.rx + pos + 1 + hsz;

			switch (broker.rx[pos] >> 4) {
			case LMQCP_CTOS_CONNECT:
				if (broker.tx_len + 4 > sizeof(broker.tx))
					return -1;
				memcpy(broker.tx + broker.tx_len,
				       (const uint8_t[]){ 0x20, 2, 0, 0 }, 4);
				broker.tx_len += 4;
				lws_callback_on_writable(wsi);
				break;

			case LMQCP_PUBLISH:
				broker_rx_publish(broker.rx + pos, pay, remlen);
				break;

			case LMQCP_PUBREL:
				if (remlen != 2)
					return -1;
				id = (uint16_t)((pay[0] << 8) | pay[1]);
				if (step == IS_QOS2_B2B && !broker.b2b_first &&
				    !sa.acks) {
					/* the first one's: hold its PUBCOMP */
					broker.b2b_first = id;
					break;
				}
				broker_tx_ack(0x70, id);
				if (step == IS_GONE && id == broker.gone_id)
					/* released: the other stream goes on */
					client_act(&sa, IA_DONE);
				break;

			case LMQCP_CTOS_PINGREQ:
				if (broker.tx_len + 2 > sizeof(broker.tx))
					return -1;
				broker.tx[broker.tx_len++] = 0xd0;
				broker.tx[broker.tx_len++] = 0;
				lws_callback_on_writable(wsi);
				break;

			case LMQCP_CTOS_SUBSCRIBE:
				/* only ever sent if the refusal failed */
				fail("SUBSCRIBE went out while busy");
				break;

			default:
				break;
			}

			pos += pkt_len;
		}

		memmove(broker.rx, broker.rx + pos, broker.rx_len - pos);
		broker.rx_len -= pos;
		break;

	case LWS_CALLBACK_RAW_WRITEABLE: {
		size_t tx_len = broker.tx_len;

		broker.tx_len = 0;
		if (tx_len &&
		    lws_write(wsi, broker.tx, tx_len, LWS_WRITE_RAW) !=
							(int)tx_len)
			return -1;
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
client_publish(struct lws *wsi, lws_mqtt_qos_levels_t qos, const char *payload,
	       int dup)
{
	uint8_t buf[LWS_PRE + 16];
	lws_mqtt_publish_param_t pub;
	size_t plen = strlen(payload);

	memset(&pub, 0, sizeof(pub));
	pub.topic	= (char *)topic; /* lws only reads it */
	pub.topic_len	= (uint16_t)(sizeof(topic) - 1);
	pub.qos		= qos;
	pub.dup		= !!dup;
	pub.payload_len	= (uint32_t)plen;
	memcpy(buf + LWS_PRE, payload, plen);

	return lws_mqtt_client_send_publish(wsi, &pub, buf + LWS_PRE,
					    (uint32_t)plen, 1);
}

static int
client_connect(struct cstream *s)
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
	i.opaque_user_data	= s;
	/* streams to the same broker share one connection */
	i.ssl_connection	= LCCSCF_PIPELINE;

	return !lws_client_connect_via_info(&i);
}

static int
client_writeable(struct cstream *s)
{
	int action = s->action;

	s->action = IA_NONE;

	switch (action) {
	case IA_BUSY_FIRST:
		if (client_publish(s->wsi, QOS1, "busy-1", 0))
			return 1;
		/* busy-1 awaits its PUBACK: these must be refused */
		if (!client_publish(s->wsi, QOS1, "busy-2", 0)) {
			fail("second QoS1 PUBLISH accepted while busy");

			return 1;
		}
		if (!lws_mqtt_client_send_subcribe(s->wsi, &sub_param)) {
			fail("SUBSCRIBE accepted while busy");

			return 1;
		}
		lwsl_user("%s: busy: second operation refused\n", __func__);
		return 0;

	case IA_BUSY_SECOND:
		return client_publish(s->wsi, QOS1, "busy-2", 0);

	case IA_B2B_FIRST:
		return client_publish(s->wsi, QOS2, "b2b-1", 0);

	case IA_B2B_SECOND:
		return client_publish(s->wsi, QOS2, "b2b-2", 0);

	case IA_RESEND_FIRST:
		return client_publish(s->wsi, QOS1, "resend", 0);

	case IA_RESEND_DUP:
		return client_publish(s->wsi, QOS1, "resend", 1);

	case IA_AUX:
		return client_publish(s->wsi, QOS1, "aux", 0);

	case IA_GONE:
		if (client_publish(s->wsi, QOS2, "gone", 0))
			return 1;
		/* close the stream with its PUBLISH awaiting its PUBREC */
		return -1;

	case IA_DONE:
		return client_publish(s->wsi, QOS1, "done", 0);

	default:
		/* WRITEABLE may come unasked */
		return 0;
	}
}

static void
client_ack(struct cstream *s)
{
	s->acks++;

	if (s != &sa)
		return; /* the other stream's "aux" */

	switch (step) {
	case IS_BUSY:
		if (s->acks == 1) {
			client_act(s, IA_BUSY_SECOND);
			break;
		}
		lwsl_user("%s: step qos2 back to back\n", __func__);
		step = IS_QOS2_B2B;
		s->acks = 0;
		client_act(s, IA_B2B_FIRST);
		break;

	case IS_QOS2_B2B:
		if (s->acks == 1) {
			/* at the PUBREC, before the PUBCOMP */
			client_act(s, IA_B2B_SECOND);
			break;
		}
		lwsl_user("%s: step resend\n", __func__);
		step = IS_RESEND;
		s->acks = 0;
		client_act(s, IA_RESEND_FIRST);
		/* the other stream joins and takes an id meanwhile */
		if (client_connect(&sb))
			fail("second stream connect failed");
		break;

	case IS_RESEND:
		lwsl_user("%s: step gone\n", __func__);
		step = IS_GONE;
		s->acks = 0;
		client_act(&sb, IA_GONE);
		break;

	case IS_GONE:
		completed = 1;
		lws_sul_cancel(&sul_watchdog);
		lws_default_loop_exit(cx);
		lws_cancel_service(cx);
		break;
	}
}

static int
callback_mqtt(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	struct cstream *s = (struct cstream *)lws_get_opaque_user_data(wsi);

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		fail("CLIENT_CONNECTION_ERROR");
		break;

	case LWS_CALLBACK_MQTT_CLIENT_ESTABLISHED:
		if (!s)
			break;
		lwsl_user("%s: stream %s established\n", __func__, s->name);
		s->wsi = wsi;
		if (s == &sa)
			client_act(s, IA_BUSY_FIRST);
		else
			/* the broker may already have given it something to do */
			client_act(s, s->action);
		break;

	case LWS_CALLBACK_MQTT_CLIENT_WRITEABLE:
		if (!s)
			break;
		return client_writeable(s);

	case LWS_CALLBACK_MQTT_ACK:
		if (s)
			client_ack(s);
		break;

	case LWS_CALLBACK_MQTT_RESEND:
		if (s == &sa && step == IS_RESEND) {
			lwsl_user("%s: MQTT_RESEND, resending\n", __func__);
			client_act(s, IA_RESEND_DUP);
		}
		break;

	case LWS_CALLBACK_MQTT_CLIENT_CLOSED:
		if (!s)
			break;
		s->wsi = NULL;
		s->closed = 1;
		if (s == &sb && step == IS_GONE) {
			broker_gone_pubrec();
			break;
		}
		if (!completed)
			fail("stream closed before completion");
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		.name			= "lws-api-test-mqtt-inflight-broker",
		.callback		= callback_fake_broker,
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
	fail("timed out");
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
	int n = 0;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: MQTT client operations in flight\n");

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);

	info.port		= port;
	info.protocols		= protocols;
	info.options		= LWS_SERVER_OPTION_ONLY_RAW;
	info.fd_limit_per_thread = 0;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");

		return 1;
	}

	/* the resend step waits out lws' 3s PUBACK timeout */
	lws_sul_schedule(cx, 0, &sul_watchdog, watchdog_cb,
			 15 * LWS_USEC_PER_SEC);

	if (client_connect(&sa)) {
		lwsl_err("%s: Client Connect Failed\n", __func__);
		fails++;
		goto bail;
	}

	while (n >= 0 && !completed && !fails)
		n = lws_service(cx, 0);

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_context_destroy(cx);

	if (broker.accepted != 1) {
		lwsl_err("%d broker connections, expected 1\n",
			 broker.accepted);
		fails++;
	}

	if (fails || !completed) {
		lwsl_user("Completed: failed\n");

		return 1;
	}

	lwsl_user("Completed: OK\n");

	return 0;
}
