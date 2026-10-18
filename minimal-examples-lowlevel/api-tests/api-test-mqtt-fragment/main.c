/*
 * lws-api-test-mqtt-fragment
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Fence for the mqtt client's rx parser being restartable at any byte: what
 * one read hands it is whatever the network delivered, so any field of any
 * packet may be split across reads, and a field longer than one read (a
 * PUBLISH topic may be up to 64KB) can only ever arrive split.
 *
 * The test runs a fake in-process MQTT broker on an ONLY_RAW vhost and
 * connects the real lws mqtt client to it over loopback.  The broker sends
 * everything except the long topic one byte per write, a millisecond apart,
 * so every field of every packet it sends straddles a read.  Each step waits
 * for the client's exact reply, byte for byte, before the next:
 *
 *  - CONNACK, then SUBACK for the client's SUBSCRIBE
 *  - a QoS1 PUBLISH: the client must deliver it and PUBACK its id
 *  - a QoS2 PUBLISH: delivered and PUBREC'd, then its PUBREL: PUBCOMP'd
 *  - a QoS1 PUBLISH whose topic is longer than the client's rx buffer, in
 *    one write: delivered with the whole topic, and PUBACK'd
 *  - the client publishes at QoS2: the broker's PUBREC must get our PUBREL,
 *    and its PUBCOMP complete the publish
 *  - the client unsubscribes: the UNSUBACK must complete it
 *
 * Any failure to parse closes the connection, which fails the test.
 */

#include <libwebsockets.h>
#include <string.h>

#include <signal.h>

#define FRAG_ID_QOS1		0x0101
#define FRAG_ID_QOS2		0x0102
#define FRAG_ID_LONG		0x0103
/* longer than the default pt_serv_buf_size, the most one read can bring */
#define FRAG_LONG_TOPIC_LEN	6000
#define FRAG_PREFIX		"lws/frag/"

static int port = 7681;
static int fails, completed;
static unsigned int rx_count, qos2_rx_complete, ack_count;
static struct lws_context *cx;
static struct lws *client_wsi, *broker_wsi;
static lws_sorted_usec_list_t sul_watchdog, sul_trickle;
static char long_topic[FRAG_LONG_TOPIC_LEN + 1];

static lws_mqtt_topic_elem_t topics[] = {
	{ .name = FRAG_PREFIX "#", .qos = QOS2 },
};

static lws_mqtt_subscribe_param_t sub_param = {
	.topic					= topics,
	.num_topics				= LWS_ARRAY_SIZE(topics),
};

static const lws_mqtt_client_connect_param_t conn_param = {
	.client_id				= "lws-api-test-mqtt-fragment",
	.keep_alive				= 60,
	.clean_start				= 1,
	.client_id_nofree			= 1,
	.username_nofree			= 1,
	.password_nofree			= 1,
};

/* what the client side does next, when it is writeable */

static enum {
	FCS_SUBSCRIBE,
	FCS_IDLE,
	FCS_PUBLISH_QOS2,
	FCS_UNSUBSCRIBE,
} client_action;

/* the broker's steps: each waits for one packet from the client */

enum {
	FBS_CONNECT,
	FBS_SUBSCRIBE,
	FBS_PUBACK_QOS1,
	FBS_PUBREC_QOS2,
	FBS_PUBCOMP_QOS2,
	FBS_PUBACK_LONG,
	FBS_CLIENT_PUBLISH,
	FBS_CLIENT_PUBREL,
	FBS_UNSUBSCRIBE,
	FBS_DONE
};

static const char * const step_names[] = {
	"CONNECT", "SUBSCRIBE", "PUBACK (qos1)", "PUBREC (qos2)",
	"PUBCOMP (qos2)", "PUBACK (long topic)", "client PUBLISH",
	"client PUBREL", "UNSUBSCRIBE", "done"
};

/*
 * Fake MQTT broker side
 */

struct broker_pss {
	uint8_t				rx[2048];
	size_t				rx_len;
	uint8_t				tx[8192];
	size_t				tx_len;
	size_t				tx_pos;
	int				step;
	uint16_t			client_pkt_id;
	char				trickle;
};

static void
fail_test(const char *why)
{
	lwsl_err("%s\n", why);
	fails++;
	lws_default_loop_exit(cx);
	lws_cancel_service(cx);
}

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

static size_t
vbi_encode(uint8_t *buf, uint32_t value)
{
	size_t n = 0;

	do {
		buf[n] = (uint8_t)(value & 0x7f);
		value >>= 7;
		if (value)
			buf[n] |= 0x80;
		n++;
	} while (value);

	return n;
}

static int
broker_tx(struct broker_pss *pss, const void *pkt, size_t len)
{
	if (pss->tx_len + len > sizeof(pss->tx)) {
		lwsl_err("%s: broker tx overflow\n", __func__);

		return 1;
	}

	memcpy(pss->tx + pss->tx_len, pkt, len);
	pss->tx_len += len;

	return 0;
}

/* SUBACK, UNSUBACK, PUBACK, PUBREC, PUBREL or PUBCOMP */
static int
broker_tx_ack(struct broker_pss *pss, uint8_t cmd, uint16_t pkt_id)
{
	return broker_tx(pss, (const uint8_t[]){
			cmd, 0x02, (uint8_t)(pkt_id >> 8),
			(uint8_t)(pkt_id & 0xff)
		}, 4);
}

/* a QoS1 or QoS2 PUBLISH */
static int
broker_tx_publish(struct broker_pss *pss, uint8_t cmd, uint16_t pkt_id,
		  const char *topic, const char *payload)
{
	size_t tlen = strlen(topic), plen = strlen(payload), n;
	uint8_t h[8];

	h[0] = cmd;
	n = 1 + vbi_encode(&h[1], (uint32_t)(2 + tlen + 2 + plen));
	h[n++] = (uint8_t)(tlen >> 8);
	h[n++] = (uint8_t)(tlen & 0xff);

	return broker_tx(pss, h, n) ||
	       broker_tx(pss, topic, tlen) ||
	       broker_tx(pss, (const uint8_t[]){
				(uint8_t)(pkt_id >> 8),
				(uint8_t)(pkt_id & 0xff)
			}, 2) ||
	       broker_tx(pss, payload, plen);
}

/* send what's queued, one byte at a time if trickling */

static void
broker_kick(struct broker_pss *pss, char trickle)
{
	pss->trickle = trickle;
	if (broker_wsi)
		lws_callback_on_writable(broker_wsi);
}

static void
trickle_cb(lws_sorted_usec_list_t *sul)
{
	if (broker_wsi)
		lws_callback_on_writable(broker_wsi);
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	struct broker_pss *pss = broker_wsi ?
			(struct broker_pss *)lws_wsi_user(broker_wsi) : NULL;

	lwsl_err("%s: timed out waiting for %s\n", __func__,
		 pss ? step_names[pss->step] : "the broker connection");
	fail_test("timed out");
}

/* one packet from the client: is it the one this step waits for? */

static int
broker_rx_pkt(struct broker_pss *pss, const uint8_t *pkt, size_t pkt_len,
	      const uint8_t *pay, uint32_t remlen)
{
	uint16_t id, tlen;

	switch (pss->step) {
	case FBS_CONNECT:
		if (pkt[0] >> 4 != LMQCP_CTOS_CONNECT)
			return 1;
		/* accept it: flags 0, return code 0 */
		if (broker_tx(pss, (const uint8_t[]){ 0x20, 0x02, 0, 0 }, 4))
			return 1;
		broker_kick(pss, 1);
		break;

	case FBS_SUBSCRIBE:
		if (pkt[0] >> 4 != LMQCP_CTOS_SUBSCRIBE || remlen < 2)
			return 1;
		id = (uint16_t)((pay[0] << 8) | pay[1]);
		/* granted at QoS2, then the first PUBLISH */
		if (broker_tx(pss, (const uint8_t[]){
				0x90, 0x03, (uint8_t)(id >> 8),
				(uint8_t)(id & 0xff), 0x02 }, 5) ||
		    broker_tx_publish(pss, 0x32, FRAG_ID_QOS1,
				      FRAG_PREFIX "a", "one"))
			return 1;
		broker_kick(pss, 1);
		break;

	case FBS_PUBACK_QOS1:
	case FBS_PUBACK_LONG:
		if (pkt_len != 4 || pkt[0] != 0x40 || pkt[1] != 2 ||
		    pkt[2] != (pss->step == FBS_PUBACK_QOS1 ?
				FRAG_ID_QOS1 : FRAG_ID_LONG) >> 8 ||
		    pkt[3] != ((pss->step == FBS_PUBACK_QOS1 ?
				FRAG_ID_QOS1 : FRAG_ID_LONG) & 0xff))
			return 1;
		if (pss->step == FBS_PUBACK_LONG) {
			/* now the client publishes at QoS2 */
			client_action = FCS_PUBLISH_QOS2;
			if (client_wsi)
				lws_callback_on_writable(client_wsi);
			break;
		}
		if (broker_tx_publish(pss, 0x34, FRAG_ID_QOS2,
				      FRAG_PREFIX "b", "two"))
			return 1;
		broker_kick(pss, 1);
		break;

	case FBS_PUBREC_QOS2:
		if (pkt_len != 4 || pkt[0] != 0x50 || pkt[1] != 2 ||
		    pkt[2] != FRAG_ID_QOS2 >> 8 ||
		    pkt[3] != (FRAG_ID_QOS2 & 0xff) ||
		    broker_tx_ack(pss, 0x62, FRAG_ID_QOS2))
			return 1;
		broker_kick(pss, 1);
		break;

	case FBS_PUBCOMP_QOS2:
		if (pkt_len != 4 || pkt[0] != 0x70 || pkt[1] != 2 ||
		    pkt[2] != FRAG_ID_QOS2 >> 8 ||
		    pkt[3] != (FRAG_ID_QOS2 & 0xff))
			return 1;
		/* the long topic all in one write: it straddles reads */
		if (broker_tx_publish(pss, 0x32, FRAG_ID_LONG, long_topic,
				      "long"))
			return 1;
		broker_kick(pss, 0);
		break;

	case FBS_CLIENT_PUBLISH:
		if ((pkt[0] & 0xf6) != 0x34 || remlen < 2)
			return 1;
		tlen = (uint16_t)((pay[0] << 8) | pay[1]);
		if (remlen < 4u + tlen)
			return 1;
		pss->client_pkt_id = (uint16_t)((pay[2 + tlen] << 8) |
						pay[3 + tlen]);
		if (broker_tx_ack(pss, 0x50, pss->client_pkt_id))
			return 1;
		broker_kick(pss, 1);
		break;

	case FBS_CLIENT_PUBREL:
		if (pkt_len != 4 || pkt[0] != 0x62 || pkt[1] != 2 ||
		    pkt[2] != pss->client_pkt_id >> 8 ||
		    pkt[3] != (pss->client_pkt_id & 0xff) ||
		    broker_tx_ack(pss, 0x70, pss->client_pkt_id))
			return 1;
		broker_kick(pss, 1);
		break;

	case FBS_UNSUBSCRIBE:
		if (pkt[0] >> 4 != LMQCP_CTOS_UNSUBSCRIBE || remlen < 2)
			return 1;
		id = (uint16_t)((pay[0] << 8) | pay[1]);
		if (broker_tx_ack(pss, 0xb0, id))
			return 1;
		broker_kick(pss, 1);
		break;

	default:
		return 1;
	}

	pss->step++;
	lwsl_user("%s: now waiting for %s\n", __func__, step_names[pss->step]);

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
		pss->step = FBS_CONNECT;
		broker_wsi = wsi;
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		broker_wsi = NULL;
		lws_sul_cancel(&sul_trickle);
		break;

	case LWS_CALLBACK_RAW_RX:
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

			if ((pss->rx[pos] >> 4) == LMQCP_CTOS_PINGREQ) {
				if (broker_tx(pss, (const uint8_t[]){
						0xd0, 0x00 }, 2))
					goto fail;
				broker_kick(pss, 0);
			} else if (broker_rx_pkt(pss, pss->rx + pos, pkt_len,
						 pss->rx + pos + 1 + hsz,
						 remlen)) {
				lwsl_err("%s: waiting for %s, got\n", __func__,
					 step_names[pss->step]);
				lwsl_hexdump_err(pss->rx + pos,
						 pkt_len > 32 ? 32 : pkt_len);
				goto fail;
			}

			pos += pkt_len;
		}

		/* consume the packets we dealt with */
		memmove(pss->rx, pss->rx + pos, pss->rx_len - pos);
		pss->rx_len -= pos;
		break;

	case LWS_CALLBACK_RAW_WRITEABLE: {
		size_t n = pss->tx_len - pss->tx_pos;

		if (!n)
			break;
		if (pss->trickle)
			n = 1;

		if (lws_write(wsi, pss->tx + pss->tx_pos, n, LWS_WRITE_RAW) !=
								(int)n) {
			lwsl_err("%s: broker write failed\n", __func__);

			return -1;
		}

		pss->tx_pos += n;
		if (pss->tx_pos == pss->tx_len) {
			pss->tx_pos = pss->tx_len = 0;
			break;
		}

		/*
		 * The next byte a while later, so the client has read this
		 * one by itself
		 */
		lws_sul_schedule(cx, 0, &sul_trickle, trickle_cb,
				 LWS_US_PER_MS);
		break;
	}

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);

fail:
	fail_test("broker saw the wrong thing");

	return -1;
}

/*
 * MQTT client side
 */

static int
client_writeable(struct lws *wsi)
{
	lws_mqtt_publish_param_t pub;

	switch (client_action) {
	case FCS_SUBSCRIBE:
		client_action = FCS_IDLE;

		return lws_mqtt_client_send_subcribe(wsi, &sub_param);

	case FCS_IDLE:
		/* WRITEABLE may come unasked: nothing for us to do */
		return 0;

	case FCS_PUBLISH_QOS2:
		client_action = FCS_IDLE;
		memset(&pub, 0, sizeof(pub));
		pub.topic	= (char *)FRAG_PREFIX "ours"; /* only read */
		pub.topic_len	= (uint16_t)strlen(pub.topic);
		pub.qos		= QOS2;
		pub.payload_len	= 4;

		return lws_mqtt_client_send_publish(wsi, &pub, "ours", 4, 1);

	case FCS_UNSUBSCRIBE:
		client_action = FCS_IDLE;

		return lws_mqtt_client_send_unsubcribe(wsi, &sub_param);
	}

	return 0;
}

/*
 * Each delivery must be the one the broker sent, whole.  The payload comes
 * in as many pieces as it arrived in, each with the whole topic.
 */

static int
client_rx(const lws_mqtt_publish_param_t *pub, size_t len)
{
	static const struct {
		const char	*topic;
		const char	*payload;
	} want[] = {
		{ FRAG_PREFIX "a", "one" },
		{ FRAG_PREFIX "b", "two" },
		{ long_topic, "long" },
	};
	static char payload[8];

	if (rx_count >= LWS_ARRAY_SIZE(want) ||
	    pub->topic_len != strlen(want[rx_count].topic) ||
	    memcmp(pub->topic, want[rx_count].topic, pub->topic_len) ||
	    pub->topic[pub->topic_len] ||
	    pub->payload_len != strlen(want[rx_count].payload) ||
	    pub->payload_pos + len > pub->payload_len) {
		lwsl_err("%s: delivery %u is wrong: topic len %u\n", __func__,
			 rx_count, (unsigned int)pub->topic_len);

		return 1;
	}

	memcpy(payload + pub->payload_pos, pub->payload, len);
	if (pub->payload_pos + len != pub->payload_len)
		return 0; /* more to come */

	if (memcmp(payload, want[rx_count].payload, pub->payload_len)) {
		lwsl_err("%s: delivery %u payload is wrong\n", __func__,
			 rx_count);

		return 1;
	}

	rx_count++;

	return 0;
}

static int
callback_mqtt(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: CLIENT_CONNECTION_ERROR: %s\n", __func__,
			 in ? (const char *)in : "(null)");
		fail_test("connection error");
		break;

	case LWS_CALLBACK_MQTT_CLIENT_CLOSED:
		client_wsi = NULL;
		if (!completed)
			fail_test("connection closed before completion");
		break;

	case LWS_CALLBACK_MQTT_CLIENT_ESTABLISHED:
		lwsl_user("%s: MQTT_CLIENT_ESTABLISHED\n", __func__);
		client_wsi = wsi;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_MQTT_CLIENT_WRITEABLE:
		if (client_writeable(wsi)) {
			fail_test("client send failed");

			return -1;
		}
		break;

	case LWS_CALLBACK_MQTT_SUBSCRIBED:
		lwsl_user("%s: MQTT_SUBSCRIBED\n", __func__);
		break;

	case LWS_CALLBACK_MQTT_ACK:
		/* the broker's PUBCOMP completed our QoS2 publish */
		lwsl_user("%s: MQTT_ACK\n", __func__);
		ack_count++;
		client_action = FCS_UNSUBSCRIBE;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_MQTT_CLIENT_RX:
		if (client_rx((const lws_mqtt_publish_param_t *)in, len)) {
			fail_test("bad delivery");

			return -1;
		}
		break;

	case LWS_CALLBACK_MQTT_QOS2_RX_COMPLETE:
		qos2_rx_complete++;
		break;

	case LWS_CALLBACK_MQTT_UNSUBSCRIBED:
		lwsl_user("%s: MQTT_UNSUBSCRIBED\n", __func__);
		if (rx_count != 3 || qos2_rx_complete != 1 || ack_count != 1) {
			lwsl_err("%s: %u deliveries, %u QOS2_RX_COMPLETE, "
				 "%u ACK\n", __func__, rx_count,
				 qos2_rx_complete, ack_count);
			fail_test("wrong counts");
			break;
		}
		completed = 1;
		lws_sul_cancel(&sul_watchdog);
		lws_default_loop_exit(cx);
		lws_cancel_service(cx);
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		.name			= "lws-api-test-mqtt-fragment-broker",
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

	lwsl_user("LWS API selftest: MQTT client rx split across reads\n");

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);

	memcpy(long_topic, FRAG_PREFIX, strlen(FRAG_PREFIX));
	memset(long_topic + strlen(FRAG_PREFIX), 'x',
	       sizeof(long_topic) - 1 - strlen(FRAG_PREFIX));

	/*
	 * The default vhost is the fake broker: it listens in RAW mode, and
	 * accepted connections bind the first protocol above.  The mqtt
	 * client protocol is found by name on the same vhost for the
	 * outbound connection.
	 */

	info.port		= port;
	info.protocols		= protocols;
	info.options		= LWS_SERVER_OPTION_ONLY_RAW;
	info.fd_limit_per_thread = 0;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");

		return 1;
	}

	lws_sul_schedule(cx, 0, &sul_watchdog, watchdog_cb,
			 20 * LWS_USEC_PER_SEC);

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

	while (n >= 0 && !fails && !completed)
		n = lws_service(cx, 0);

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_trickle);
	lws_context_destroy(cx);

	if (fails || !completed) {
		lwsl_user("Completed: failed\n");

		return 1;
	}

	lwsl_user("Completed: OK\n");

	return 0;
}
