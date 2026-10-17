/*
 * lws-api-test-mqtt-acks
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Fence for the acks the mqtt client owes the broker (issue #3680): every
 * PUBACK, PUBREC, PUBREL and PUBCOMP must go out, promptly, quoting the
 * packet id of what it answers, in the order those packets arrived.
 *
 * The test runs a fake in-process MQTT broker on an ONLY_RAW vhost and
 * connects the real lws mqtt client to it over loopback.  Once the client
 * has subscribed, the broker plays a series of rounds at it.  Most send
 * several packets in one write, so they arrive in one read, and each round
 * waits for exactly the right acks, in order, before the next starts.  A
 * round that doesn't get them in time fails: the client's keepalive is much
 * longer than that, so an ack that only leaves with the next PINGREQ fails.
 *
 *  - qos1 burst: two QoS1 PUBLISH, while the client has nothing to write
 *  - qos2 burst: two QoS2 PUBLISH, then their two PUBRELs
 *  - our qos2: the client publishes at QoS2, and the broker answers its
 *    PUBREC together with a PUBREL of its own: our PUBREL must quote our
 *    id, not the other flow's
 *  - late ack: a QoS1 PUBLISH arrives while the client is in the middle of
 *    sending a chunked PUBLISH: its PUBACK must follow the PUBLISH out, not
 *    wait for something else to write
 *  - held: a flood arrives while the client is in the middle of a chunked
 *    PUBLISH, so more acks come due than it holds before it can write any:
 *    its rx must stop until it finishes the PUBLISH (from a timer, since rx
 *    can't drive it), then every ack and delivery must follow
 *  - flood: many more QoS1 PUBLISH in one write than the client holds acks
 *    for at once: it must hold its rx while it catches up, and lose none
 */

#include <libwebsockets.h>
#include <string.h>

#include <signal.h>

#define ACKS_FLOOD		100 /* several times what lws holds at once */
#define ACKS_PEER_PUBREL_ID	0x0303
#define ACKS_LATE_ID		0x0501
#define ACKS_HELD_ID		0x3000

static int port = 7681;
static int fails, completed;
static unsigned int rx_count, rx_complete_count, ack_count;
static unsigned int rx_held_start, rx_held_finish;
static struct lws_context *cx;
static struct lws *client_wsi, *broker_wsi;
static lws_sorted_usec_list_t sul_watchdog, sul_finish;

static const char topic[] = "lws/api-test-mqtt-acks";
/* the chunked PUBLISH of the late ack and held rounds, sent in two halves */
static const char chunked_payload[] = "first half, second half";
#define ACKS_CHUNK_SPLIT	12

static lws_mqtt_topic_elem_t topics[] = {
	{ .name = topic, .qos = QOS2 },
};

static lws_mqtt_subscribe_param_t sub_param = {
	.topic					= topics,
	.num_topics				= LWS_ARRAY_SIZE(topics),
};

static const lws_mqtt_client_connect_param_t conn_param = {
	.client_id				= "lws-api-test-mqtt-acks",
	.keep_alive				= 60,
	.clean_start				= 1,
	.client_id_nofree			= 1,
	.username_nofree			= 1,
	.password_nofree			= 1,
};

enum {
	AR_QOS1_BURST,
	AR_QOS2_BURST,
	AR_PUBREL_BURST,
	AR_OUR_QOS2,
	AR_LATE_ACK,
	AR_HELD,
	AR_FLOOD,

	AR_COUNT
};

/*
 * Each round: what the broker sends at its start, and the acks the client
 * must send back, in order: count of them, with ids counting up from
 * first_id, unless the round says otherwise below.  A round with no tx_cmd
 * starts with the client doing something.
 */

static const struct around {
	const char			*name;
	uint8_t				tx_cmd;	/* fixed header byte 0 */
	uint16_t			first_id;
	unsigned int			count;
	uint8_t				ack;	/* fixed header byte 0 */
	unsigned int			rx_after;
	unsigned int			rx_complete_after;
} arounds[AR_COUNT] = {
	[AR_QOS1_BURST] = {
		"qos1 burst",	0x32, 0x0101, 2,	   0x40,   2, 0
	},
	[AR_QOS2_BURST] = {
		"qos2 burst",	0x34, 0x0201, 2,	   0x50,   4, 0
	},
	[AR_PUBREL_BURST] = {
		"pubrel burst",	0x62, 0x0201, 2,	   0x70,   4, 2
	},
	[AR_OUR_QOS2] = {
		/* PUBREL for ours, then PUBCOMP for the broker's PUBREL */
		"our qos2",	0,    ACKS_PEER_PUBREL_ID, 2, 0, 4, 2
	},
	[AR_LATE_ACK] = {
		"late ack",	0,    ACKS_LATE_ID, 1,	   0x40,   5, 2
	},
	[AR_HELD] = {
		"held",		0,    ACKS_HELD_ID, ACKS_FLOOD, 0x40,
		5 + ACKS_FLOOD, 2
	},
	[AR_FLOOD] = {
		"flood",	0x32, 0x1000, ACKS_FLOOD,  0x40,
		5 + (2 * ACKS_FLOOD), 2
	},
};

/*
 * Fake MQTT broker side
 */

struct broker_pss {
	uint8_t				rx[2048];
	size_t				rx_len;
	uint8_t				tx[4096];
	size_t				tx_len;
	int				round;	/* -1 until subscribed */
	unsigned int			acked;	/* acks seen this round */
	uint16_t			client_pkt_id; /* of its QoS2 PUBLISH */
	char				client_publish_seen; /* its chunked one */
};

/* the client's side of the rounds where it goes first */
static enum {
	ACS_SUBSCRIBE,
	ACS_IDLE,
	ACS_PUBLISH_QOS2,
	ACS_CHUNK_FIRST,	/* send the first half */
	ACS_CHUNK_WAIT,		/* wait for the broker's PUBLISH, or a timer */
	ACS_CHUNK_SECOND,	/* send the second half */
} client_action;

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

/* PUBACK, PUBREC, PUBREL or PUBCOMP */
static int
broker_tx_ack(struct broker_pss *pss, uint8_t cmd, uint16_t pkt_id)
{
	return broker_tx(pss, (const uint8_t[]){
			cmd, 0x02, (uint8_t)(pkt_id >> 8),
			(uint8_t)(pkt_id & 0xff)
		}, 4);
}

/* a QoS1 or QoS2 PUBLISH on our topic, short enough for a 1-byte VBI */
static int
broker_tx_publish(struct broker_pss *pss, uint8_t cmd, uint16_t pkt_id,
		  const char *payload)
{
	size_t tlen = sizeof(topic) - 1, plen = strlen(payload);

	return broker_tx(pss, (const uint8_t[]){
				cmd, (uint8_t)(2 + tlen + 2 + plen),
				(uint8_t)(tlen >> 8), (uint8_t)(tlen & 0xff)
			}, 4) ||
	       broker_tx(pss, (const uint8_t *)topic, tlen) ||
	       broker_tx(pss, (const uint8_t[]){
				(uint8_t)(pkt_id >> 8),
				(uint8_t)(pkt_id & 0xff)
			}, 2) ||
	       broker_tx(pss, (const uint8_t *)payload, plen);
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out\n", __func__);
	fails++;
	lws_default_loop_exit(cx);
	lws_cancel_service(cx);
}

static int
broker_round_start(struct broker_pss *pss)
{
	const struct around *r = &arounds[pss->round];
	unsigned int n;

	lwsl_user("%s: round %s\n", __func__, r->name);

	pss->acked = 0;
	pss->client_publish_seen = 0;
	/* each round gets its own deadline */
	lws_sul_schedule(cx, 0, &sul_watchdog, watchdog_cb,
			 3 * LWS_USEC_PER_SEC);

	if (!r->tx_cmd) {
		/* the client goes first */
		client_action = pss->round == AR_OUR_QOS2 ? ACS_PUBLISH_QOS2 :
							    ACS_CHUNK_FIRST;
		rx_held_start = rx_count;
		lws_callback_on_writable(client_wsi);

		return 0;
	}

	/* all of the round in one write */
	for (n = 0; n < r->count; n++)
		if (r->tx_cmd == 0x62 ?
			broker_tx_ack(pss, r->tx_cmd,
				      (uint16_t)(r->first_id + n)) :
			broker_tx_publish(pss, r->tx_cmd,
					  (uint16_t)(r->first_id + n), "msg"))
			return 1;

	return 0;
}

/* the client's PUBLISH, in the rounds where it goes first */
static int
broker_rx_publish(struct broker_pss *pss, const uint8_t *pkt,
		  const uint8_t *pay, uint32_t remlen)
{
	uint16_t tlen;

	if (remlen < 2)
		return 1;
	tlen = (uint16_t)((pay[0] << 8) | pay[1]);
	if (remlen < 2u + tlen)
		return 1;

	switch ((pkt[0] >> 1) & 3) {
	case QOS2:
		if (pss->round != AR_OUR_QOS2 || remlen < 4u + tlen)
			break;
		pss->client_pkt_id = (uint16_t)((pay[2 + tlen] << 8) |
						pay[3 + tlen]);
		/*
		 * Our PUBREC for it, and in the same write, a PUBREL for a
		 * flow of our own: two acks for the client to send, with
		 * different ids
		 */
		return broker_tx_ack(pss, 0x50, pss->client_pkt_id) ||
		       broker_tx_ack(pss, 0x62, ACKS_PEER_PUBREL_ID);

	case QOS0:
		if (pss->round != AR_LATE_ACK && pss->round != AR_HELD)
			break;
		if (remlen != 2u + tlen + sizeof(chunked_payload) - 1 ||
		    memcmp(pay + 2 + tlen, chunked_payload,
			   sizeof(chunked_payload) - 1)) {
			lwsl_err("%s: chunked PUBLISH mangled\n", __func__);
			lwsl_hexdump_err(pkt, remlen + 2);

			return 1;
		}
		pss->client_publish_seen = 1;

		return 0;

	default:
		break;
	}

	lwsl_err("%s: unexpected PUBLISH in round %s\n", __func__,
		 arounds[pss->round].name);

	return 1;
}

/* an ack from the client: it must be the next one the round expects */
static int
broker_rx_ack(struct broker_pss *pss, const uint8_t *pkt, size_t pkt_len)
{
	const struct around *r = &arounds[pss->round];
	uint16_t id = (uint16_t)(r->first_id + pss->acked);
	uint8_t cmd = r->ack;

	switch (pss->round) {
	case AR_OUR_QOS2:
		if (!pss->acked) {
			/* our PUBREL, for the client's own PUBLISH */
			cmd = 0x62;
			id = pss->client_pkt_id;
		} else {
			/* the PUBCOMP for the broker's PUBREL */
			cmd = 0x70;
			id = ACKS_PEER_PUBREL_ID;
		}
		break;

	case AR_LATE_ACK:
	case AR_HELD:
		/* it must come after the PUBLISH it waited for, not inside it */
		if (!pss->client_publish_seen) {
			lwsl_err("%s: %s: ack before our PUBLISH\n",
				 __func__, r->name);

			return 1;
		}
		break;

	default:
		break;
	}

	if (pkt_len != 4 || pkt[0] != cmd || pkt[1] != 2 ||
	    pkt[2] != (uint8_t)(id >> 8) || pkt[3] != (uint8_t)(id & 0xff)) {
		lwsl_err("%s: %s: ack %u: wanted %02x 02 %04x, got\n", __func__,
			 r->name, pss->acked, cmd, id);
		lwsl_hexdump_err(pkt, pkt_len);

		return 1;
	}

	if (pss->round == AR_OUR_QOS2 && !pss->acked &&
	    /* finish the client's exchange */
	    broker_tx_ack(pss, 0x70, pss->client_pkt_id))
		return 1;

	if (++pss->acked < r->count)
		return 0;

	/* the round is complete */

	if (rx_count != r->rx_after ||
	    rx_complete_count != r->rx_complete_after) {
		lwsl_err("%s: %s: %u deliveries, %u QOS2_RX_COMPLETE, "
			 "expected %u, %u\n", __func__, r->name, rx_count,
			 rx_complete_count, r->rx_after, r->rx_complete_after);

		return 1;
	}

	if (pss->round == AR_HELD &&
	    rx_held_finish - rx_held_start >= ACKS_FLOOD) {
		/* everything was delivered before the PUBLISH was finished */
		lwsl_err("%s: %s: rx was not held\n", __func__, r->name);

		return 1;
	}

	if (pss->round == AR_OUR_QOS2 && !ack_count) {
		lwsl_err("%s: %s: no MQTT_ACK for our PUBLISH\n", __func__,
			 r->name);

		return 1;
	}

	if (++pss->round == AR_COUNT) {
		completed = 1;
		lws_sul_cancel(&sul_watchdog);
		lws_default_loop_exit(cx);
		lws_cancel_service(cx);

		return 0;
	}

	return broker_round_start(pss);
}

static int
callback_fake_broker(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	struct broker_pss *pss = (struct broker_pss *)user;
	size_t pos = 0;

	switch (reason) {

	case LWS_CALLBACK_RAW_ADOPT:
		pss->round = -1;
		broker_wsi = wsi;
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		broker_wsi = NULL;
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
					goto fail;
				break;

			case LMQCP_CTOS_SUBSCRIBE:
				if (remlen < 2 || pss->round != -1)
					goto fail;
				pkt_id = (uint16_t)((pay[0] << 8) | pay[1]);
				/* our one topic, granted at QoS2 */
				if (broker_tx(pss, (const uint8_t[]){
						0x90, 0x03,
						(uint8_t)(pkt_id >> 8),
						(uint8_t)(pkt_id & 0xff),
						0x02
					}, 5))
					goto fail;
				pss->round = AR_QOS1_BURST;
				if (broker_round_start(pss))
					goto fail;
				break;

			case LMQCP_PUBLISH:
				if (pss->round < 0 ||
				    broker_rx_publish(pss, pss->rx + pos, pay,
						      remlen))
					goto fail;
				break;

			case LMQCP_PUBACK:
			case LMQCP_PUBREC:
			case LMQCP_PUBREL:
			case LMQCP_PUBCOMP:
				if (pss->round < 0 || pss->round >= AR_COUNT ||
				    broker_rx_ack(pss, pss->rx + pos, pkt_len))
					goto fail;
				break;

			case LMQCP_CTOS_PINGREQ:
				if (broker_tx(pss, (const uint8_t[]){
						0xd0, 0x00 }, 2))
					goto fail;
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

fail:
	fails++;
	lws_default_loop_exit(cx);
	lws_cancel_service(cx);

	return -1;
}

/*
 * The held round's client finishes its PUBLISH some time after starting it,
 * not because of anything it received: its rx is held until it does
 */
static void
finish_cb(lws_sorted_usec_list_t *sul)
{
	rx_held_finish = rx_count;
	client_action = ACS_CHUNK_SECOND;
	if (client_wsi)
		lws_callback_on_writable(client_wsi);
}

/*
 * The client is in the middle of its chunked PUBLISH: now the broker sends
 * its own, so the client owes acks it can't send yet.  In the late ack round
 * it is one QoS1 PUBLISH, whose arrival lets the client finish.  In the held
 * round it is a flood, more than the client holds acks for.
 */
static void
broker_mid_publish(void)
{
	struct broker_pss *pss;
	unsigned int n;

	if (!broker_wsi)
		return;

	pss = (struct broker_pss *)lws_wsi_user(broker_wsi);
	if (pss->round == AR_HELD) {
		for (n = 0; n < ACKS_FLOOD; n++)
			if (broker_tx_publish(pss, 0x32,
					      (uint16_t)(ACKS_HELD_ID + n),
					      "held"))
				goto fail;
		lws_sul_schedule(cx, 0, &sul_finish, finish_cb,
				 500 * LWS_US_PER_MS);
	} else
		if (broker_tx_publish(pss, 0x32, ACKS_LATE_ID, "late"))
			goto fail;

	lws_callback_on_writable(broker_wsi);

	return;

fail:
	fails++;
	lws_default_loop_exit(cx);
}

/*
 * MQTT client side
 */

static int
client_writeable(struct lws *wsi)
{
	uint8_t buf[LWS_PRE + sizeof(chunked_payload)];
	lws_mqtt_publish_param_t pub;

	memset(&pub, 0, sizeof(pub));
	pub.topic	= (char *)topic; /* lws only reads it */
	pub.topic_len	= (uint16_t)(sizeof(topic) - 1);

	switch (client_action) {
	case ACS_SUBSCRIBE:
		client_action = ACS_IDLE;

		return lws_mqtt_client_send_subcribe(wsi, &sub_param);

	case ACS_IDLE:
	case ACS_CHUNK_WAIT:
		/* WRITEABLE may come unasked: nothing for us to do */
		return 0;

	case ACS_PUBLISH_QOS2:
		client_action = ACS_IDLE;
		pub.qos		= QOS2;
		pub.payload_len	= 4;

		return lws_mqtt_client_send_publish(wsi, &pub, "ours", 4, 1);

	case ACS_CHUNK_FIRST:
		client_action = ACS_CHUNK_WAIT;
		pub.qos		= QOS0;
		pub.payload_len	= sizeof(chunked_payload) - 1;

		if (lws_mqtt_client_send_publish(wsi, &pub, chunked_payload,
						 ACKS_CHUNK_SPLIT, 0))
			return 1;

		/* the PUBLISH stays open until the broker's, or a timer */
		broker_mid_publish();

		return 0;

	case ACS_CHUNK_SECOND:
		client_action = ACS_IDLE;
		pub.qos		= QOS0;
		pub.payload_len	= sizeof(chunked_payload) - 1;
		memcpy(buf + LWS_PRE, chunked_payload + ACKS_CHUNK_SPLIT,
		       sizeof(chunked_payload) - 1 - ACKS_CHUNK_SPLIT);

		return lws_mqtt_client_send_publish(wsi, &pub, buf + LWS_PRE,
				(uint32_t)(sizeof(chunked_payload) - 1 -
					   ACKS_CHUNK_SPLIT), 1);
	}

	return 0;
}

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
		client_wsi = NULL;
		if (!completed) {
			lwsl_err("%s: connection closed before completion\n",
				 __func__);
			fails++;
		}
		lws_default_loop_exit(cx);
		break;

	case LWS_CALLBACK_MQTT_CLIENT_ESTABLISHED:
		lwsl_user("%s: MQTT_CLIENT_ESTABLISHED\n", __func__);
		client_wsi = wsi;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_MQTT_CLIENT_WRITEABLE:
		if (client_writeable(wsi)) {
			lwsl_err("%s: send failed\n", __func__);
			fails++;

			return -1;
		}
		break;

	case LWS_CALLBACK_MQTT_SUBSCRIBED:
		lwsl_user("%s: MQTT_SUBSCRIBED\n", __func__);
		break;

	case LWS_CALLBACK_MQTT_ACK:
		ack_count++;
		break;

	case LWS_CALLBACK_MQTT_CLIENT_RX:
		pub = (lws_mqtt_publish_param_t *)in;
		/* count each message once, however it is chunked */
		if (pub->payload_pos)
			break;
		rx_count++;
		if (client_action == ACS_CHUNK_WAIT && pub->payload_len == 4 &&
		    !memcmp(pub->payload, "late", 4)) {
			/* now we can finish our PUBLISH */
			client_action = ACS_CHUNK_SECOND;
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_MQTT_QOS2_RX_COMPLETE:
		rx_complete_count++;
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		.name			= "lws-api-test-mqtt-acks-broker",
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

	lwsl_user("LWS API selftest: MQTT client acks\n");

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
	info.fd_limit_per_thread = 0;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");

		return 1;
	}

	/* until the first round starts, which gets its own */
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
	lws_sul_cancel(&sul_finish);
	lws_context_destroy(cx);

	if (fails || !completed) {
		lwsl_user("Completed: failed\n");

		return 1;
	}

	lwsl_user("Completed: OK\n");

	return 0;
}
