/*
 * lws-api-test-mqtt-qos2
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Fence for the client side of inbound QoS2 (issue #3672).
 *
 * The test runs a fake in-process MQTT broker on an ONLY_RAW vhost and
 * connects the real lws mqtt client to it over loopback.  Once the client
 * has subscribed, the broker walks it through a lock-stepped script of QoS2
 * exchanges, checking the exact bytes of each PUBREC and PUBCOMP the client
 * sends back: their fixed header flags must be 0 [MQTT-3.5.1, 3.7.1], only
 * PUBREL carries 0x2, and a compliant broker drops a client that gets it
 * wrong.
 *
 * The script also checks the QoS2 rx id list: a DUP resend before the PUBREL
 * must not be delivered again, the PUBREL must find and release the id, and
 * an id the application restored with lws_mqtt_client_qos2_rx_add() must
 * suppress the redelivery from the broker.  Those list entries were once
 * allocated without being zeroed, so their list linkage started as heap
 * junk and they could silently fail to join the list.  ctest runs this with
 * glibc's MALLOC_PERTURB_ so the junk is there even without ASan.
 */

#include <libwebsockets.h>
#include <string.h>

#include <signal.h>

static int port = 7681;
static int fails, completed;
static unsigned int rx_count, rx_complete_count;
static struct lws_context *cx;

#define QOS2_PKT_ID		0x1234
#define QOS2_RESTORED_PKT_ID	0x0777

static const char topic[] = "lws/api-test-mqtt-qos2";

static lws_mqtt_topic_elem_t topics[] = {
	{ .name = topic, .qos = QOS2 },
};

static lws_mqtt_subscribe_param_t sub_param = {
	.topic					= topics,
	.num_topics				= LWS_ARRAY_SIZE(topics),
};

static const lws_mqtt_client_connect_param_t conn_param = {
	.client_id				= "lws-api-test-mqtt-qos2",
	.keep_alive				= 60,
	.clean_start				= 1,
	.client_id_nofree			= 1,
	.username_nofree			= 1,
	.password_nofree			= 1,
};

/*
 * Fake MQTT broker side
 */

enum {
	QS_PUBLISH,		/* PUBLISH(id), client is new to it */
	QS_PUBLISH_DUP,		/* DUP resend of it before the PUBREL */
	QS_PUBREL,		/* release it */
	QS_PUBLISH_AGAIN,	/* the id is free again: a new message */
	QS_PUBREL_AGAIN,
	QS_PUBLISH_RESTORED,	/* DUP resend of the restored id */
	QS_PUBREL_RESTORED,

	QS_COUNT
};

/*
 * Each step: what the broker sends, and the exact reply the client must
 * send back to it before the broker moves on to the next step
 */

static const struct qstep {
	const char			*name;
	uint8_t				cmd;	 /* fixed header byte 0 */
	uint16_t			pkt_id;
	const char			*payload; /* NULL: PUBREL */
	uint8_t				reply;	 /* fixed header byte 0 */
	unsigned int			rx_after;
	unsigned int			rx_complete_after;
} qsteps[QS_COUNT] = {
	[QS_PUBLISH] = {
		"publish",		0x34, QOS2_PKT_ID, "first",
		0x50, 1, 0
	},
	[QS_PUBLISH_DUP] = {
		"publish dup",		0x3c, QOS2_PKT_ID, "first",
		0x50, 1, 0
	},
	[QS_PUBREL] = {
		"pubrel",		0x62, QOS2_PKT_ID, NULL,
		0x70, 1, 1
	},
	[QS_PUBLISH_AGAIN] = {
		"publish again",	0x34, QOS2_PKT_ID, "second",
		0x50, 2, 1
	},
	[QS_PUBREL_AGAIN] = {
		"pubrel again",		0x62, QOS2_PKT_ID, NULL,
		0x70, 2, 2
	},
	[QS_PUBLISH_RESTORED] = {
		"publish restored",	0x3c, QOS2_RESTORED_PKT_ID, "old",
		0x50, 2, 2
	},
	[QS_PUBREL_RESTORED] = {
		"pubrel restored",	0x62, QOS2_RESTORED_PKT_ID, NULL,
		0x70, 2, 3
	},
};

struct broker_pss {
	uint8_t				rx[512];
	size_t				rx_len;
	uint8_t				tx[256];
	size_t				tx_len;
	int				step;	/* -1 until subscribed */
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

/* queue the broker side of the current step */
static int
broker_step_tx(struct broker_pss *pss)
{
	const struct qstep *s = &qsteps[pss->step];
	size_t tlen = sizeof(topic) - 1, plen;
	uint8_t hdr[4];

	lwsl_user("%s: step %s\n", __func__, s->name);

	if (!s->payload)
		/* PUBREL */
		return broker_tx(pss, (const uint8_t[]){
				s->cmd, 0x02,
				(uint8_t)(s->pkt_id >> 8),
				(uint8_t)(s->pkt_id & 0xff)
			}, 4);

	/* PUBLISH: topic, packet id, payload, all short enough for 1 VBI */

	plen = strlen(s->payload);
	hdr[0] = s->cmd;
	hdr[1] = (uint8_t)(2 + tlen + 2 + plen);
	hdr[2] = (uint8_t)(tlen >> 8);
	hdr[3] = (uint8_t)(tlen & 0xff);

	return broker_tx(pss, hdr, sizeof(hdr)) ||
	       broker_tx(pss, (const uint8_t *)topic, tlen) ||
	       broker_tx(pss, (const uint8_t[]){
				(uint8_t)(s->pkt_id >> 8),
				(uint8_t)(s->pkt_id & 0xff)
			}, 2) ||
	       broker_tx(pss, (const uint8_t *)s->payload, plen);
}

/* the client's reply to the current step, checked bytewise */
static int
broker_step_rx(struct broker_pss *pss, const uint8_t *pkt, size_t pkt_len)
{
	const struct qstep *s = &qsteps[pss->step];
	const uint8_t want[] = {
		s->reply, 0x02,
		(uint8_t)(s->pkt_id >> 8),
		(uint8_t)(s->pkt_id & 0xff)
	};

	if (pkt_len != sizeof(want) || memcmp(pkt, want, sizeof(want))) {
		lwsl_err("%s: %s: wrong reply\n", __func__, s->name);
		lwsl_hexdump_err(pkt, pkt_len);
		fails++;

		return 1;
	}

	if (rx_count != s->rx_after) {
		lwsl_err("%s: %s: %u deliveries, expected %u\n", __func__,
			 s->name, rx_count, s->rx_after);
		fails++;

		return 1;
	}

	if (rx_complete_count != s->rx_complete_after) {
		lwsl_err("%s: %s: %u QOS2_RX_COMPLETE, expected %u\n",
			 __func__, s->name, rx_complete_count,
			 s->rx_complete_after);
		fails++;

		return 1;
	}

	if (++pss->step == QS_COUNT) {
		completed = 1;
		lws_default_loop_exit(cx);
		lws_cancel_service(cx);

		return 0;
	}

	return broker_step_tx(pss);
}

static int
callback_fake_broker(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	struct broker_pss *pss = (struct broker_pss *)user;
	size_t pos = 0;

	switch (reason) {

	case LWS_CALLBACK_RAW_ADOPT:
		pss->step = -1;
		break;

	case LWS_CALLBACK_RAW_RX: {
		static const uint8_t connack[] = { 0x20, 0x02, 0x00, 0x00 };

		if (pss->rx_len + len > sizeof(pss->rx)) {
			lwsl_err("%s: broker rx overflow\n", __func__);

			return -1;
		}
		memcpy(pss->rx + pss->rx_len, in, len);
		pss->rx_len += len;

		while (pos < pss->rx_len) {
			const uint8_t *pay;
			uint32_t remlen;
			size_t hsz, pkt_len;
			uint16_t pkt_id;

			hsz = vbi_decode(pss->rx + pos + 1,
					 pss->rx_len - pos - 1, &remlen);
			if (!hsz)
				break; /* need more bytes for the header */

			pkt_len = 1 + hsz + remlen;
			if (pos + pkt_len > pss->rx_len)
				break; /* wait for the rest of the packet */

			pay = pss->rx + pos + 1 + hsz;

			switch (pss->rx[pos] >> 4) {
			case LMQCP_CTOS_CONNECT:
				/* accept it: flags 0, return code 0 */
				if (broker_tx(pss, connack, sizeof(connack)))
					return -1;
				break;

			case LMQCP_CTOS_SUBSCRIBE:
				if (remlen < 2 || pss->step != -1)
					return -1;
				pkt_id = (uint16_t)((pay[0] << 8) | pay[1]);
				/* our one topic, granted at QoS2 */
				if (broker_tx(pss, (const uint8_t[]){
						0x90, 0x03,
						(uint8_t)(pkt_id >> 8),
						(uint8_t)(pkt_id & 0xff),
						0x02
					}, 5))
					return -1;
				pss->step = QS_PUBLISH;
				if (broker_step_tx(pss))
					return -1;
				break;

			case LMQCP_PUBREC:
			case LMQCP_PUBCOMP:
				if (pss->step < 0 || pss->step >= QS_COUNT ||
				    broker_step_rx(pss, pss->rx + pos, pkt_len))
					return -1;
				break;

			case LMQCP_CTOS_PINGREQ:
				if (broker_tx(pss, (const uint8_t[]){
						0xd0, 0x00 }, 2))
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
callback_mqtt(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	lws_mqtt_publish_param_t *pub;

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: CLIENT_CONNECTION_ERROR: %s\n", __func__,
			 in ? (const char *)in : "(null)");
		fails++;
		lws_default_loop_exit(cx);
		break;

	case LWS_CALLBACK_MQTT_CLIENT_CLOSED:
		if (!completed) {
			lwsl_err("%s: connection closed before completion\n",
				 __func__);
			fails++;
		}
		lws_default_loop_exit(cx);
		break;

	case LWS_CALLBACK_MQTT_CLIENT_ESTABLISHED:
		lwsl_user("%s: MQTT_CLIENT_ESTABLISHED\n", __func__);

		/*
		 * As if restoring from persistent storage an id we took
		 * delivery of, but did not see the PUBREL for, before the
		 * last connection was lost
		 */
		if (lws_mqtt_client_qos2_rx_add(wsi, QOS2_RESTORED_PKT_ID)) {
			lwsl_err("%s: qos2_rx_add failed\n", __func__);
			fails++;

			return -1;
		}
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_MQTT_CLIENT_WRITEABLE:
		if (lws_mqtt_client_send_subcribe(wsi, &sub_param)) {
			lwsl_err("%s: subscribe failed\n", __func__);
			fails++;

			return -1;
		}
		break;

	case LWS_CALLBACK_MQTT_SUBSCRIBED:
		lwsl_user("%s: MQTT_SUBSCRIBED\n", __func__);
		break;

	case LWS_CALLBACK_MQTT_CLIENT_RX:
		pub = (lws_mqtt_publish_param_t *)in;
		/* count each message once, however it is chunked */
		if (!pub->payload_pos) {
			lwsl_user("%s: MQTT_CLIENT_RX %.*s\n", __func__,
				  (int)len, (const char *)pub->payload);
			rx_count++;
		}
		break;

	case LWS_CALLBACK_MQTT_QOS2_RX_COMPLETE:
		lwsl_user("%s: MQTT_QOS2_RX_COMPLETE 0x%04x\n", __func__,
			  *(uint16_t *)in);
		rx_complete_count++;
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		.name			= "lws-api-test-mqtt-qos2-broker",
		.callback		= callback_fake_broker,
		.per_session_data_size	= sizeof(struct broker_pss),
	},
	{
		.name			= "mqtt",
		.callback		= callback_mqtt,
	},
	LWS_PROTOCOL_LIST_TERM
};

static lws_sorted_usec_list_t sul_watchdog;

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out before completing\n", __func__);
	fails++;
	lws_default_loop_exit(cx);
	lws_cancel_service(cx);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	const char *p;
	int n = 0;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: MQTT client QoS2 rx\n");

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);

	/*
	 * The default vhost is the fake broker: it listens in RAW mode, and
	 * accepted connections bind the first protocol above.  The mqtt
	 * client protocol is found by name on the same vhost for the
	 * outbound connection.
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
			 10 * LWS_USEC_PER_SEC);

	memset(&i, 0, sizeof i);
	i.mqtt_cp	= &conn_param;
	i.context	= cx;
	i.address	= "127.0.0.1";
	i.host		= "127.0.0.1";
	i.port		= port;
	i.protocol	= "mqtt";
	i.method	= "MQTT";
	i.alpn		= "mqtt";

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: Client Connect Failed\n", __func__);

		goto bail;
	}

	while (n >= 0)
		n = lws_service(cx, 0);

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_context_destroy(cx);

	if (fails || !completed) {
		lwsl_user("Completed: failed\n");

		return 1;
	}

	lwsl_user("Completed: OK\n");

	return 0;
}
