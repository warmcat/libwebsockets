/*
 * lws-api-test-mqtt-unsub
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Fence for the mqtt subscribe / unsubscribe topic count contract
 * (LWS_MQTT_MAX_TOPICS): the tx composition paths index fixed-size stack
 * scratch by the caller-supplied num_topics, so an over-wide topic list
 * must be loudly refused instead of walking off the end of the scratch.
 *
 * The test runs a fake in-process MQTT broker on an ONLY_RAW vhost and
 * connects the real lws mqtt client to it over loopback, so the fence
 * exercises the actual ESTABLISHED-state tx paths rather than a refusal
 * that fires early on connection state.
 */

#include <libwebsockets.h>
#include <string.h>

#include <signal.h>

static int port = 7681;
static int interrupted, fails, completed;
static unsigned int guard_hits;
static struct lws_context *cx;

/*
 * The one topic we really subscribe to, so the unsubscribe legs find an
 * existing subscription and go through the composition path
 */

static const char *const dummy_names[LWS_MQTT_MAX_TOPICS] = {
	"lws/api-test-mqtt-unsub/d0",
	"lws/api-test-mqtt-unsub/d1",
	"lws/api-test-mqtt-unsub/d2",
	"lws/api-test-mqtt-unsub/d3",
	"lws/api-test-mqtt-unsub/d4",
	"lws/api-test-mqtt-unsub/d5",
	"lws/api-test-mqtt-unsub/d6",
	"lws/api-test-mqtt-unsub/d7",
};

static lws_mqtt_topic_elem_t	 topic_real;
static lws_mqtt_topic_elem_t	 topics_overwide[LWS_MQTT_MAX_TOPICS + 1];
static lws_mqtt_topic_elem_t	 topics_boundary[LWS_MQTT_MAX_TOPICS];

static lws_mqtt_subscribe_param_t sub_real = {
	.topic					= &topic_real,
	.num_topics				= 1,
};

static lws_mqtt_subscribe_param_t sub_overwide = {
	.topic					= topics_overwide,
	.num_topics				= LWS_MQTT_MAX_TOPICS + 1,
};

static lws_mqtt_subscribe_param_t unsub_overwide = {
	.topic					= topics_overwide,
	.num_topics				= LWS_MQTT_MAX_TOPICS + 1,
};

static lws_mqtt_subscribe_param_t unsub_zero = {
	.topic					= topics_boundary,
	.num_topics				= 0,
};

static lws_mqtt_subscribe_param_t unsub_boundary = {
	.topic					= topics_boundary,
	.num_topics				= LWS_MQTT_MAX_TOPICS,
};

static const lws_mqtt_client_connect_param_t conn_param = {
	.client_id				= "lws-api-test-mqtt-unsub",
	.keep_alive				= 60,
	.clean_start				= 1,
	.client_id_nofree			= 1,
	.username_nofree			= 1,
	.password_nofree			= 1,
};

/*
 * Capture the library's loud refusals: the guard emits a distinctive
 * lwsl_err, and each fence leg must produce exactly one of them
 */

static void
test_emit(int level, const char *line)
{
	if (strstr(line, "num_topics") && strstr(line, "out of range"))
		guard_hits++;

	/* keep the logs visible so failures can be debugged from ctest output */
	fprintf(stderr, "%s", line);
}

/*
 * Fake MQTT broker side
 */

struct broker_pss {
	uint8_t				rx[1024];
	size_t				rx_len;
	uint8_t				tx[256];
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
			size_t hsz, pkt_len, p;
			uint16_t pkt_id, tlen;
			uint8_t granted[16];
			unsigned int n = 0;

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
				if (remlen < 2)
					return -1;
				pkt_id = (uint16_t)((pay[0] << 8) | pay[1]);
				p = 2;
				/* count the topic filters to ack them all */
				while (p < remlen) {
					if (p + 2 > remlen)
						return -1;
					tlen = (uint16_t)((pay[p] << 8) |
							  pay[p + 1]);
					p += (size_t)tlen + 3; /* len + name + qos */
					if (p > remlen || n >= LWS_ARRAY_SIZE(granted))
						return -1;
					granted[n++] = 0; /* grant at QoS0 */
				}
				if (broker_tx(pss, (const uint8_t[]){
						0x90,
						(uint8_t)(2 + n),
						(uint8_t)(pkt_id >> 8),
						(uint8_t)(pkt_id & 0xff)
					}, 4))
					return -1;
				if (broker_tx(pss, granted, n))
					return -1;
				break;

			case LMQCP_CTOS_UNSUBSCRIBE:
				if (remlen < 2)
					return -1;
				pkt_id = (uint16_t)((pay[0] << 8) | pay[1]);
				if (broker_tx(pss, (const uint8_t[]){
						0xb0, 0x02,
						(uint8_t)(pkt_id >> 8),
						(uint8_t)(pkt_id & 0xff)
					}, 4))
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

enum {
	MQST_SUBSCRIBE,		/* subscribe to the one real topic */
	MQST_SUBACK_WAIT,	/* waiting for the real SUBACK */
	MQST_FENCE,		/* run the fence legs */
	MQST_UNSUBACK_WAIT,	/* boundary unsubscribe awaiting its UNSUBACK */
	MQST_DONE,
};

struct client_pss {
	int				state;
};

/* one leg that must be refused loudly, without any side effects */
static void
expect_refusal(struct lws *wsi, const char *leg, int is_subscribe,
	       lws_mqtt_subscribe_param_t *param)
{
	unsigned int hits = guard_hits;
	int rc = is_subscribe ? lws_mqtt_client_send_subcribe(wsi, param)
			      : lws_mqtt_client_send_unsubcribe(wsi, param);

	if (!rc) {
		lwsl_err("%s: %s: not refused\n", __func__, leg);
		fails++;
	}

	if (guard_hits != hits + 1) {
		lwsl_err("%s: %s: expected one loud rejection, saw %u\n",
			 __func__, leg, guard_hits - hits);
		fails++;
	}
}

static int
callback_mqtt(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	struct client_pss *pss = (struct client_pss *)user;

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: CLIENT_CONNECTION_ERROR: %s\n", __func__,
			 in ? (const char *)in : "(null)");
		fails++;
		interrupted = 1;
		break;

	case LWS_CALLBACK_MQTT_CLIENT_CLOSED:
		if (pss->state != MQST_DONE) {
			lwsl_err("%s: connection closed before completion\n",
				 __func__);
			fails++;
		}
		interrupted = 1;
		break;

	case LWS_CALLBACK_MQTT_CLIENT_ESTABLISHED:
		lwsl_user("%s: MQTT_CLIENT_ESTABLISHED\n", __func__);
		pss->state = MQST_SUBSCRIBE;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_MQTT_SUBSCRIBED:
		lwsl_user("%s: MQTT_SUBSCRIBED\n", __func__);
		pss->state = MQST_FENCE;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_MQTT_UNSUBSCRIBED:
		lwsl_user("%s: MQTT_UNSUBSCRIBED\n", __func__);
		pss->state = MQST_DONE;
		completed = 1;
		interrupted = 1;
		lws_cancel_service(lws_get_context(wsi));
		break;

	case LWS_CALLBACK_MQTT_CLIENT_WRITEABLE:
		switch (pss->state) {

		case MQST_SUBSCRIBE:
			if (lws_mqtt_client_send_subcribe(wsi, &sub_real)) {
				lwsl_err("%s: real subscribe failed\n",
					 __func__);
				fails++;
				return -1;
			}
			pss->state = MQST_SUBACK_WAIT;
			break;

		case MQST_FENCE:
			/*
			 * The fence legs.  The over-wide calls must be
			 * refused cleanly, with the loud rejection logged,
			 * before anything is composed or any subscription
			 * refcount is touched
			 */

			expect_refusal(wsi, "overwide unsubscribe", 0,
				       &unsub_overwide);
			expect_refusal(wsi, "zero unsubscribe", 0, &unsub_zero);
			expect_refusal(wsi, "overwide subscribe", 1,
				       &sub_overwide);

			/*
			 * Boundary leg: the widest legal unsubscribe must
			 * still work end-to-end (it carries the one real
			 * topic, so a real UNSUBSCRIBE goes out and is
			 * UNSUBACKed)
			 */

			{
				unsigned int hits = guard_hits;

				if (lws_mqtt_client_send_unsubcribe(wsi,
							   &unsub_boundary)) {
					lwsl_err("%s: boundary unsubscribe refused\n",
						 __func__);
					fails++;
					break;
				}
				if (guard_hits != hits) {
					lwsl_err("%s: boundary leg tripped the guard\n",
						 __func__);
					fails++;
					break;
				}
				pss->state = MQST_UNSUBACK_WAIT;
			}
			break;

		default:
			break;
		}
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		.name			= "lws-api-test-mqtt-unsub-broker",
		.callback		= callback_fake_broker,
		.per_session_data_size	= sizeof(struct broker_pss),
	},
	{
		.name			= "mqtt",
		.callback		= callback_mqtt,
		.per_session_data_size	= sizeof(struct client_pss),
	},
	LWS_PROTOCOL_LIST_TERM
};

static lws_sorted_usec_list_t sul_watchdog;

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out before completing\n", __func__);
	fails++;
	interrupted = 1;
	lws_cancel_service(cx);
}

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	const char *p;
	unsigned int n;
	int n2 = 0;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	/* install our log catcher after the builtin processing of -d etc */
	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_USER,
			  test_emit);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);

	topic_real.name = "lws/api-test-mqtt-unsub/real";
	topic_real.qos = QOS0;

	/* [0] is the real subscribed topic, the rest are dummies */
	topics_overwide[0] = topic_real;
	for (n = 1; n < LWS_ARRAY_SIZE(topics_overwide); n++) {
		topics_overwide[n].name = dummy_names[n - 1];
		topics_overwide[n].qos = QOS0;
	}
	topics_boundary[0] = topic_real;
	for (n = 1; n < LWS_ARRAY_SIZE(topics_boundary); n++) {
		topics_boundary[n].name = dummy_names[n - 1];
		topics_boundary[n].qos = QOS0;
	}

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

	while (n2 >= 0 && !interrupted)
		n2 = lws_service(cx, 0);

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
