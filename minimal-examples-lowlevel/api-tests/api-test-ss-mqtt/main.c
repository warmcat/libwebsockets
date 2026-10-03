/*
 * lws-api-test-ss-mqtt
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Secure Streams over mqtt, against a small in-process broker on a raw
 * vhost, for the things an application is allowed to do from its callbacks
 * on a stream that shares its mqtt connection with others:
 *
 *  - give up on the stream (DESTROY_ME) from the state it hears after it
 *    sent something, when the ack is one lws makes up itself: a QoS0
 *    PUBLISH has no PUBACK, and a SUBSCRIBE to a topic the connection
 *    already has is not sent to the broker at all
 *
 *  - destroy another stream on the same connection while lws is walking
 *    the connection's streams to tell each of them something: adopting the
 *    streams queued on a new connection, delivering a PUBLISH to every
 *    subscriber, giving each stream that asked for it a WRITEABLE
 *
 * The streams must hear each state once, in order, be destroyed once, and
 * nothing must be left using them afterwards (run it under ASan).
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

enum {
	LWS_SW_PORT,
	LWS_SW_SERVER,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_PORT]	= { "-p",	"Port for the test broker "
					"(default 1883)" },
	[LWS_SW_SERVER]	= { "--server",	"Address the streams connect to "
					"(default localhost)" },
	[LWS_SW_HELP]	= { "--help",	"Show this help information" },
};

static struct lws_context *context;
static lws_state_notify_link_t nl;
static lws_sorted_usec_list_t sul_timeout, sul_leg, sul_second;
static const char *server_ads = "localhost";
static int port = 1883, failed;

/* what the broker saw, so a leg can tell what really went on the wire */
static unsigned int broker_subscribes;

/*
 * The in-process broker, just enough mqtt 3.1.1 for the streams: CONNACK,
 * SUBACK, UNSUBACK and PINGRESP, and a PUBLISH to a topic the connection
 * subscribed to is sent back to it at QoS0
 */

#define BROKER_MAX_SUBS 8

struct broker_pss {
	uint8_t			rx[2048];
	size_t			rx_len;
	uint8_t			tx[2048];
	size_t			tx_len;
	char			subs[BROKER_MAX_SUBS][64];
};

/* decode an mqtt VBI at buf, returns bytes consumed, or 0 if incomplete */
static size_t
vbi_decode(const uint8_t *buf, size_t len, uint32_t *remlen)
{
	uint32_t val = 0, mult = 1;
	size_t used = 0;

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
	if (len > sizeof(pss->tx) - pss->tx_len) {
		lwsl_err("%s: broker tx overflow\n", __func__);

		return 1;
	}

	memcpy(pss->tx + pss->tx_len, pkt, len);
	pss->tx_len += len;

	return 0;
}

static int
broker_subscribed(struct broker_pss *pss, const uint8_t *topic, size_t tlen)
{
	unsigned int n;

	for (n = 0; n < BROKER_MAX_SUBS; n++)
		if (strlen(pss->subs[n]) == tlen &&
		    !memcmp(pss->subs[n], topic, tlen))
			return 1;

	return 0;
}

/* one complete control packet from the client */

static int
broker_packet(struct broker_pss *pss, uint8_t type_flags, const uint8_t *pay,
	      uint32_t remlen)
{
	static const uint8_t connack[] = { 0x20, 0x02, 0x00, 0x00 };
	uint8_t hdr[4], granted[BROKER_MAX_SUBS];
	unsigned int n = 0, m;
	uint16_t pkt_id, tlen;
	uint32_t p, plen;

	switch (type_flags >> 4) {
	case LMQCP_CTOS_CONNECT:
		return broker_tx(pss, connack, sizeof(connack));

	case LMQCP_CTOS_SUBSCRIBE:
		if (remlen < 2)
			return 1;
		broker_subscribes++;
		pkt_id = (uint16_t)((pay[0] << 8) | pay[1]);
		for (p = 2; p < remlen; p += (uint32_t)tlen + 3) {
			if (p + 2 > remlen || n == BROKER_MAX_SUBS)
				return 1;
			tlen = (uint16_t)((pay[p] << 8) | pay[p + 1]);
			if (p + 2 + tlen + 1 > remlen)
				return 1;
			for (m = 0; m < BROKER_MAX_SUBS; m++)
				if (!pss->subs[m][0]) {
					lws_strnncpy(pss->subs[m],
						     (const char *)pay + p + 2,
						     tlen, sizeof(pss->subs[m]));
					break;
				}
			granted[n++] = 0; /* granted at QoS0 */
		}
		hdr[0] = 0x90;
		hdr[1] = (uint8_t)(2 + n);
		hdr[2] = (uint8_t)(pkt_id >> 8);
		hdr[3] = (uint8_t)(pkt_id & 0xff);

		return broker_tx(pss, hdr, 4) || broker_tx(pss, granted, n);

	case LMQCP_CTOS_UNSUBSCRIBE:
		if (remlen < 2)
			return 1;
		pkt_id = (uint16_t)((pay[0] << 8) | pay[1]);
		for (p = 2; p < remlen; p += (uint32_t)tlen + 2) {
			if (p + 2 > remlen)
				return 1;
			tlen = (uint16_t)((pay[p] << 8) | pay[p + 1]);
			if (p + 2 + tlen > remlen)
				return 1;
			for (m = 0; m < BROKER_MAX_SUBS; m++)
				if (strlen(pss->subs[m]) == tlen &&
				    !memcmp(pss->subs[m], pay + p + 2, tlen))
					pss->subs[m][0] = '\0';
		}
		hdr[0] = 0xb0;
		hdr[1] = 2;
		hdr[2] = (uint8_t)(pkt_id >> 8);
		hdr[3] = (uint8_t)(pkt_id & 0xff);

		return broker_tx(pss, hdr, 4);

	case LMQCP_PUBLISH:
		if (remlen < 2)
			return 1;
		tlen = (uint16_t)((pay[0] << 8) | pay[1]);
		p = 2u + tlen;
		if (type_flags & 6) { /* QoS1: PUBACK it */
			if (p + 2 > remlen)
				return 1;
			hdr[0] = 0x40;
			hdr[1] = 2;
			hdr[2] = pay[p];
			hdr[3] = pay[p + 1];
			p += 2;
			if (broker_tx(pss, hdr, 4))
				return 1;
		}
		if (p > remlen)
			return 1;
		plen = remlen - p;

		if (!broker_subscribed(pss, pay + 2, tlen))
			return 0;

		/* deliver it back to this connection, at QoS0 */
		if (2u + tlen + plen > 127) {
			lwsl_err("%s: echo too large for the test\n", __func__);
			return 1;
		}
		hdr[0] = 0x30;
		hdr[1] = (uint8_t)(2u + tlen + plen);

		return broker_tx(pss, hdr, 2) ||
		       broker_tx(pss, pay, 2u + tlen) ||
		       broker_tx(pss, pay + p, plen);

	case LMQCP_CTOS_PINGREQ:
		hdr[0] = 0xd0;
		hdr[1] = 0;

		return broker_tx(pss, hdr, 2);

	default:
		return 0; /* eg, DISCONNECT: nothing to reply */
	}
}

static int
callback_broker(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	struct broker_pss *pss = (struct broker_pss *)user;
	size_t pos = 0, hsz, pkt_len, tx_len;
	uint32_t remlen;

	switch (reason) {

	case LWS_CALLBACK_RAW_RX:
		if (len > sizeof(pss->rx) - pss->rx_len) {
			lwsl_err("%s: broker rx overflow\n", __func__);

			return -1;
		}
		memcpy(pss->rx + pss->rx_len, in, len);
		pss->rx_len += len;

		while (pss->rx_len - pos >= 2) {
			hsz = vbi_decode(pss->rx + pos + 1,
					 pss->rx_len - pos - 1, &remlen);
			if (!hsz)
				break; /* need more for the header */

			pkt_len = 1 + hsz + remlen;
			if (pkt_len > pss->rx_len - pos)
				break; /* wait for the rest of the packet */

			if (broker_packet(pss, pss->rx[pos],
					  pss->rx + pos + 1 + hsz, remlen))
				return -1;

			pos += pkt_len;
		}

		/* consume the packets we dealt with */
		memmove(pss->rx, pss->rx + pos, pss->rx_len - pos);
		pss->rx_len -= pos;

		if (pss->tx_len)
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		tx_len = pss->tx_len;
		pss->tx_len = 0;
		if (tx_len &&
		    lws_write(wsi, pss->tx, tx_len, LWS_WRITE_RAW) != (int)tx_len) {
			lwsl_err("%s: broker write failed\n", __func__);

			return -1;
		}
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_broker[] = {
	{ "test-broker", callback_broker, sizeof(struct broker_pss), 0, 0,
	  NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/*
 * The streams.  Each leg uses up to three, in slots[], and the slot keeps what
 * its stream heard after the stream is gone
 */

typedef struct slot {
	struct lws_ss_handle	*h;
	const char		*name;

	unsigned int		connected;
	unsigned int		acked;
	unsigned int		nacked;
	unsigned int		rx;
	unsigned int		destroying;
	unsigned int		destroyed_sibling;
	char			sent;
} slot_t;

typedef struct tst {
	struct lws_ss_handle	*ss;
	void			*opaque_data;
} tst_t;

enum {
	LEG_QUEUE_DESTROY,	/* adopted from the queue, destroys a queued one */
	LEG_QOS0_ACK_DESTROY,	/* DESTROY_ME from the QoS0 local ack */
	LEG_SUBSCRIBED_DESTROY,	/* DESTROY_ME from a local SUBSCRIBED */
	LEG_RX_DESTROY,		/* one subscriber's rx destroys the other */
	LEG_TX_DESTROY,		/* one stream's tx destroys the other */

	LEG_COUNT
};

static const char * const leg_names[] = {
	"queue destroy",
	"qos0 ack destroy",
	"local subscribed destroy",
	"rx destroys sibling",
	"tx destroys sibling",
};

static slot_t slots[3];
static int leg = -1;
static unsigned int subscribes_at_second;

static const char *
leg_name(void)
{
	return leg >= 0 && leg < (int)LWS_ARRAY_SIZE(leg_names) ?
						leg_names[leg] : "?";
}

static void
leg_sul_cb(lws_sorted_usec_list_t *sul);
static void
second_sul_cb(lws_sorted_usec_list_t *sul);

static void
finish(int fail)
{
	if (fail)
		failed = 1;
	lws_default_loop_exit(context);
}

static void
leg_fail(const char *why)
{
	lwsl_err("%s: leg %s: %s\n", __func__,
		 leg_name(), why);
	finish(1);
}

/* the current leg is over, check it and start the next from the event loop */

static void
leg_done(void)
{
	lws_sul_schedule(context, 0, &sul_leg, leg_sul_cb, 1);
}

/*
 * The other stream of a two-stream leg is destroyed from inside this one's
 * callback, while lws is walking the streams of the shared connection to
 * deliver to each of them
 */

static void
destroy_sibling(slot_t *s)
{
	slot_t *o = s == &slots[0] ? &slots[1] : &slots[0];

	if (!o->h)
		return;

	lws_ss_destroy(&o->h);
	s->destroyed_sibling++;
	leg_done();
}

static lws_ss_state_return_t
tst_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	slot_t *s = (slot_t *)((tst_t *)userobj)->opaque_data;

	s->rx++;
	if (leg == LEG_RX_DESTROY)
		destroy_sibling(s);

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
tst_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf, size_t *len,
       int *flags)
{
	slot_t *s = (slot_t *)((tst_t *)userobj)->opaque_data;

	switch (leg) {
	case LEG_QOS0_ACK_DESTROY:
	case LEG_RX_DESTROY:
		/* the first stream just waits for the second's message */
		if ((leg == LEG_RX_DESTROY && s != &slots[1]) || s->sent ||
		    *len < 4)
			break;

		memcpy(buf, "once", 4);
		*len = 4;
		*flags = LWSSS_FLAG_SOM | LWSSS_FLAG_EOM;
		s->sent = 1;

		return LWSSSSRET_OK;

	case LEG_TX_DESTROY:
		/* both streams asked to write, the first to get to destroys */
		if (slots[0].connected && slots[1].connected)
			destroy_sibling(s);
		break;
	}

	return LWSSSSRET_TX_DONT_SEND;
}

static lws_ss_state_return_t
tst_state(void *userobj, void *sh, lws_ss_constate_t state,
	  lws_ss_tx_ordinal_t ack)
{
	tst_t *t = (tst_t *)userobj;
	slot_t *s = (slot_t *)t->opaque_data;
	unsigned int n;

	lwsl_ss_user(t->ss, "%s: %s", s->name, lws_ss_state_name(state));

	switch (state) {
	case LWSSSCS_CREATING:
		return lws_ss_client_connect(t->ss);

	case LWSSSCS_CONNECTED:
		s->connected++;

		switch (leg) {
		case LEG_QUEUE_DESTROY:
			/*
			 * The first stream made the connection, the other two
			 * queued on it and are adopted when it is up.  The
			 * first adopted one destroys the one still queued.
			 */
			if (s != &slots[1])
				break;
			for (n = 0; n < LWS_ARRAY_SIZE(slots); n++)
				if (slots[n].h && !slots[n].connected) {
					lws_ss_destroy(&slots[n].h);
					s->destroyed_sibling++;
				}
			leg_done();
			break;

		case LEG_QOS0_ACK_DESTROY:
			return lws_ss_request_tx(t->ss);

		case LEG_SUBSCRIBED_DESTROY:
		case LEG_RX_DESTROY:
			if (s == &slots[0]) {
				/* the connection has the topic, now join it */
				lws_sul_schedule(context, 0, &sul_second,
						 second_sul_cb, 1);
				break;
			}

			if (leg == LEG_RX_DESTROY)
				/* publish to the topic both subscribed to */
				return lws_ss_request_tx(t->ss);

			/* the second stream gives up as soon as it is up */
			return LWSSSSRET_DESTROY_ME;

		case LEG_TX_DESTROY:
			/*
			 * Once both are up, both ask to write in the same
			 * pass of the event loop
			 */
			if (s == &slots[1] && slots[0].h) {
				if (lws_ss_request_tx(slots[0].h)) {
					leg_fail("request tx failed");
					break;
				}
				return lws_ss_request_tx(t->ss);
			}
			break;
		}
		break;

	case LWSSSCS_QOS_ACK_REMOTE:
		s->acked++;
		if (leg == LEG_QOS0_ACK_DESTROY)
			/* sent the one thing it had to send: done */
			return LWSSSSRET_DESTROY_ME;
		break;

	case LWSSSCS_QOS_NACK_REMOTE:
		s->nacked++;
		leg_fail("unexpected QOS_NACK_REMOTE");
		break;

	case LWSSSCS_UNREACHABLE:
	case LWSSSCS_ALL_RETRIES_FAILED:
		leg_fail("stream could not connect");
		break;

	case LWSSSCS_DESTROYING:
		s->destroying++;
		s->h = NULL;
		if ((leg == LEG_QOS0_ACK_DESTROY && s == &slots[0]) ||
		    (leg == LEG_SUBSCRIBED_DESTROY && s == &slots[1]))
			leg_done();
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

static int
stream_create(slot_t *s, const char *name, const char *streamtype)
{
	lws_ss_info_t ssi;

	memset(&ssi, 0, sizeof(ssi));
	ssi.handle_offset		= offsetof(tst_t, ss);
	ssi.opaque_user_data_offset	= offsetof(tst_t, opaque_data);
	ssi.rx				= tst_rx;
	ssi.tx				= tst_tx;
	ssi.state			= tst_state;
	ssi.user_alloc			= sizeof(tst_t);
	ssi.streamtype			= streamtype;

	s->name = name;

	if (lws_ss_create(context, 0, &ssi, s, &s->h, NULL, NULL)) {
		lwsl_err("%s: failed to create %s\n", __func__, name);

		return 1;
	}

	return 0;
}

static void
second_sul_cb(lws_sorted_usec_list_t *sul)
{
	subscribes_at_second = broker_subscribes;

	if (stream_create(&slots[1], "second",
			  leg == LEG_RX_DESTROY ? "subrx" : "subsh"))
		finish(1);
}

/* each of the two streams lost the other, or heard it, exactly once */

static int
leg_check_pair(void)
{
	unsigned int rx = slots[0].rx + slots[1].rx,
		     by = slots[0].destroyed_sibling +
			  slots[1].destroyed_sibling,
		     gone = slots[0].destroying + slots[1].destroying;

	if (!slots[0].connected || !slots[1].connected || by != 1 ||
	    gone != 1 || (leg == LEG_RX_DESTROY && rx != 1)) {
		lwsl_err("%s: conn %u / %u, rx %u, destroyed by sibling %u, "
			 "destroying %u\n", __func__, slots[0].connected,
			 slots[1].connected, rx, by, gone);
		return 1;
	}

	return 0;
}

static int
leg_check(void)
{
	switch (leg) {
	case LEG_QUEUE_DESTROY:
		if (slots[0].connected != 1 || slots[1].connected != 1 ||
		    slots[2].connected || slots[2].destroying != 1 ||
		    slots[1].destroyed_sibling != 1) {
			lwsl_err("%s: conn %u / %u / %u, destroying %u\n",
				 __func__, slots[0].connected,
				 slots[1].connected, slots[2].connected,
				 slots[2].destroying);
			return 1;
		}
		break;

	case LEG_QOS0_ACK_DESTROY:
		if (slots[0].connected != 1 || slots[0].acked != 1 ||
		    slots[0].nacked || slots[0].destroying != 1) {
			lwsl_err("%s: conn %u, ack %u, nack %u, destroying %u\n",
				 __func__, slots[0].connected, slots[0].acked,
				 slots[0].nacked, slots[0].destroying);
			return 1;
		}
		break;

	case LEG_SUBSCRIBED_DESTROY:
		if (slots[0].connected != 1 || slots[1].connected != 1 ||
		    slots[1].destroying != 1) {
			lwsl_err("%s: conn %u / %u, destroying %u\n", __func__,
				 slots[0].connected, slots[1].connected,
				 slots[1].destroying);
			return 1;
		}
		/* the second stream's subscribe must have been a local one */
		if (broker_subscribes != subscribes_at_second) {
			lwsl_err("%s: second stream subscribed at the broker\n",
				 __func__);
			return 1;
		}
		break;

	case LEG_RX_DESTROY:
	case LEG_TX_DESTROY:
		return leg_check_pair();
	}

	return 0;
}

static void
leg_sul_cb(lws_sorted_usec_list_t *sul)
{
	unsigned int n;

	if (leg >= 0) {
		if (leg_check()) {
			leg_fail("unexpected result");
			return;
		}
		lwsl_user("leg %s: OK\n", leg_name());

		/* whatever streams the leg left are finished with */
		for (n = 0; n < LWS_ARRAY_SIZE(slots); n++)
			if (slots[n].h)
				lws_ss_destroy(&slots[n].h);
	}

	if (++leg == LEG_COUNT) {
		finish(0);
		return;
	}

	lwsl_user("--- leg %s ---\n", leg_name());
	memset(slots, 0, sizeof(slots));

	switch (leg) {
	case LEG_QUEUE_DESTROY:
		/*
		 * Nothing is connected yet: the first makes the connection,
		 * the other two queue on it
		 */
		if (stream_create(&slots[0], "first", "plain") ||
		    stream_create(&slots[1], "second", "plain") ||
		    stream_create(&slots[2], "third", "plain"))
			finish(1);
		break;

	case LEG_QOS0_ACK_DESTROY:
		if (stream_create(&slots[0], "q0", "pubq0"))
			finish(1);
		break;

	case LEG_SUBSCRIBED_DESTROY:
		if (stream_create(&slots[0], "first", "subsh"))
			finish(1);
		break;

	case LEG_RX_DESTROY:
		if (stream_create(&slots[0], "first", "subrx"))
			finish(1);
		break;

	case LEG_TX_DESTROY:
		if (stream_create(&slots[0], "first", "plain") ||
		    stream_create(&slots[1], "second", "plain"))
			finish(1);
		break;
	}
}

static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		    int current, int target)
{
	if (current != LWS_SYSTATE_OPERATIONAL ||
	    target != LWS_SYSTATE_OPERATIONAL)
		return 0;

	/* start the first leg from the event loop */
	leg_done();

	return 0;
}

static lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	leg_fail("timed out");
}

static void
sigint_handler(int sig)
{
	finish(1);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	char policy[2048];
	const char *p;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_PORT].sw)))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_SERVER].sw)))
		server_ads = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: Secure Streams over mqtt\n");

#define ST_COMMON "\"endpoint\":\"%s\",\"port\":%d,\"protocol\":\"mqtt\"," \
		  "\"retry\":\"default\",\"mqtt_keep_alive\":60," \
		  "\"mqtt_clean_start\":true,\"mqtt_qos\":0,\"aws_iot\":false,"

	lws_snprintf(policy, sizeof(policy),
		"{\"release\":\"01234567\",\"product\":\"myproduct\","
		 "\"schema-version\":1,"
		 "\"retry\":[{\"default\":{\"backoff\":[1000,2000,3000],"
			"\"conceal\":3,\"jitterpc\":20,"
			"\"svalidping\":30,\"svalidhup\":35}}],"
		 "\"s\":["
		  "{\"pubq0\":{" ST_COMMON
			"\"mqtt_topic\":\"lws/api-test-ss-mqtt/q0\"}},"
		  "{\"subsh\":{" ST_COMMON
			"\"mqtt_topic\":\"lws/api-test-ss-mqtt/shared\","
			"\"mqtt_subscribe\":\"lws/api-test-ss-mqtt/shared\"}},"
		  "{\"subrx\":{" ST_COMMON
			"\"mqtt_topic\":\"lws/api-test-ss-mqtt/rx\","
			"\"mqtt_subscribe\":\"lws/api-test-ss-mqtt/rx\"}},"
		  "{\"plain\":{" ST_COMMON
			"\"mqtt_topic\":\"lws/api-test-ss-mqtt/plain\"}}"
		 "]}",
		 server_ads, port, server_ads, port, server_ads, port,
		 server_ads, port);

	nl.name				= "app";
	nl.notify_cb			= app_system_state_nf;

	info.options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.pss_policies_json		= policy;
	info.register_notifier_list	= app_notifier_list;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the broker, a raw vhost listening on the test port */

	info.vhost_name			= "broker";
	info.port			= port;
	info.protocols			= protocols_broker;
	info.options			= LWS_SERVER_OPTION_ONLY_RAW;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create broker vhost\n");
		lws_context_destroy(context);
		return 1;
	}

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 20 * LWS_US_PER_SEC);

	lws_context_default_loop_run_destroy(context);

	lwsl_user("Completed: %s\n",
		  failed || leg != LEG_COUNT ? "FAIL" : "PASS");

	return failed || leg != LEG_COUNT;
}
