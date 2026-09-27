/*
 * lws-api-test-compose-in-rx
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The composers (lws_return_http_status(), lws_mqtt_client_send_publish()
 * and friends) may be called from callbacks the parsers deliver in the
 * middle of a read, while the rest of that read is still waiting to be
 * parsed.  What they compose must not land on it.  Each leg arranges for a
 * read to hold the bytes that trigger such a callback with more protocol
 * behind them, has the callback compose, and checks what was behind it
 * still arrives intact:
 *
 *  - h1: a POST's body lands in a read of its own, with a pipelined GET
 *    right behind it.  The server answers the POST from
 *    LWS_CALLBACK_HTTP_BODY_COMPLETION with lws_return_http_status(); both
 *    requests must get their own 200.
 *
 *  - h2 (cleartext, prior knowledge): stream 1's DATA with END_STREAM
 *    lands in a read with stream 3's HEADERS right behind it.  Stream 1 is
 *    answered from HTTP_BODY_COMPLETION the same way; both streams must
 *    get their 200 and END_STREAM, and the connection no GOAWAY.
 *
 *  - mqtt: a fake broker answers the SUBSCRIBE with the SUBACK and two
 *    PUBLISHes in one write.  The client echoes the first PUBLISH's payload
 *    from LWS_CALLBACK_MQTT_CLIENT_RX, straight out of the pointer it was
 *    handed; the broker must see the echo intact, and the client must still
 *    receive the second PUBLISH intact.
 *
 * The h1 and h2 clients are raw, so the test decides exactly what shares a
 * write: the request head goes first, and the rest follows in one write
 * after a pause long enough for the server to have read the head alone.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define SPLIT_PAUSE_MS		200

static struct lws_context *cx;
static int port_h1 = 7681, port_h2 = 7682, port_mqtt = 7683;
static int fails, legs_pending;
static lws_sorted_usec_list_t sul_watchdog;

/* the POST body: short, so the composed response would cover what follows */
static const char post_body[] = "12345678";

static void
leg_done(const char *leg, int ok)
{
	lwsl_user("%s: %s\n", leg, ok ? "OK" : "FAIL");
	if (!ok)
		fails++;
	if (!--legs_pending) {
		lws_default_loop_exit(cx);
		lws_cancel_service(cx);
	}
}

/*
 * Server side, for both the h1 and the h2 vhost: /post is answered from
 * HTTP_BODY_COMPLETION, /ok straight away
 */

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_HTTP:
		if (!strcmp((const char *)in, "/post"))
			return 0; /* answered once the body has come */

		if (lws_return_http_status(wsi, HTTP_STATUS_OK, "ok-done"))
			return -1;

		return lws_http_transaction_completed(wsi) ? -1 : 0;

	case LWS_CALLBACK_HTTP_BODY:
		return 0;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		/*
		 * The pattern under test: composing the response from inside
		 * the read that brought the end of the body
		 */
		if (lws_return_http_status(wsi, HTTP_STATUS_OK, "post-done"))
			return -1;

		return lws_http_transaction_completed(wsi) ? -1 : 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * The raw h1 and h2 clients share this: the first write goes on connect,
 * the second after the pause
 */

struct raw_cli {
	lws_sorted_usec_list_t		sul;
	struct lws			*wsi;
	const char			*leg;
	uint8_t				rx[4096];
	size_t				rx_len;
	int				paused;	/* the pause is over */
	int				phase;	/* 0: head sent, 1: rest sent */
	int				finished;
};

static struct raw_cli cli_h1 = { .leg = "h1" };
#if defined(LWS_WITH_HTTP2)
static struct raw_cli cli_h2 = { .leg = "h2" };
#endif

static void
raw_cli_finish(struct raw_cli *rc, int ok)
{
	if (rc->finished)
		return;
	rc->finished = 1;
	leg_done(rc->leg, ok);
}

static void
raw_cli_pause_cb(lws_sorted_usec_list_t *sul)
{
	struct raw_cli *rc = lws_container_of(sul, struct raw_cli, sul);

	rc->paused = 1;
	if (rc->wsi)
		lws_callback_on_writable(rc->wsi);
}

static int
raw_cli_accumulate(struct raw_cli *rc, const void *in, size_t len)
{
	if (len > sizeof(rc->rx) - rc->rx_len) {
		lwsl_err("%s: %s: rx overflow\n", __func__, rc->leg);

		return 1;
	}
	memcpy(rc->rx + rc->rx_len, in, len);
	rc->rx_len += len;

	return 0;
}

/* how many times s occurs in the first len bytes of b */

static int
count_in(const uint8_t *b, size_t len, const char *s)
{
	size_t sl = strlen(s), o;
	int n = 0;

	for (o = 0; o + sl <= len; o++)
		if (!memcmp(b + o, s, sl))
			n++;

	return n;
}

static int
callback_raw_h1(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	struct raw_cli *rc = &cli_h1;
	uint8_t buf[LWS_PRE + 256];
	int n;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (const char *)in : "(null)");
		rc->wsi = NULL;
		raw_cli_finish(rc, 0);
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		rc->wsi = wsi;
		n = lws_snprintf((char *)buf + LWS_PRE, sizeof(buf) - LWS_PRE,
				 "POST /post HTTP/1.1\r\n"
				 "Host: localhost\r\n"
				 "Content-Length: %u\r\n\r\n",
				 (unsigned int)strlen(post_body));
		if (lws_write(wsi, buf + LWS_PRE, (size_t)n, LWS_WRITE_RAW) != n)
			return -1;
		lws_sul_schedule(cx, 0, &rc->sul, raw_cli_pause_cb,
				 SPLIT_PAUSE_MS * LWS_US_PER_MS);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		/* a raw client is also writeable as soon as it connects */
		if (!rc->paused || rc->phase)
			break;
		rc->phase = 1;
		/* the body, and the next request right behind it */
		n = lws_snprintf((char *)buf + LWS_PRE, sizeof(buf) - LWS_PRE,
				 "%sGET /ok HTTP/1.1\r\n"
				 "Host: localhost\r\n\r\n", post_body);
		if (lws_write(wsi, buf + LWS_PRE, (size_t)n, LWS_WRITE_RAW) != n)
			return -1;
		break;

	case LWS_CALLBACK_RAW_RX:
		if (raw_cli_accumulate(rc, in, len))
			return -1;
		if (count_in(rc->rx, rc->rx_len, "HTTP/1.1 200 ") == 2 &&
		    count_in(rc->rx, rc->rx_len, "</html>") == 2) {
			n = count_in(rc->rx, rc->rx_len, "post-done") == 1 &&
			    count_in(rc->rx, rc->rx_len, "ok-done") == 1;
			if (!n)
				lwsl_err("%s: responses: '%.*s'\n", __func__,
					 (int)rc->rx_len, (const char *)rc->rx);
			raw_cli_finish(rc, n);

			return -1;
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		rc->wsi = NULL;
		lws_sul_cancel(&rc->sul);
		if (!rc->finished)
			lwsl_err("%s: closed with '%.*s'\n", __func__,
				 (int)rc->rx_len, (const char *)rc->rx);
		raw_cli_finish(rc, 0);
		break;

	default:
		break;
	}

	return 0;
}

#if defined(LWS_WITH_HTTP2)

/*
 * Just enough h2 for the leg.  Requests are hpack literals with indexed
 * names or fully indexed fields; responses are read for the :status lws
 * sends first, as a literal name and value without indexing, and for
 * END_STREAM, per stream.
 */

static const uint8_t h2_head[] =
	"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	/* SETTINGS, empty */
	"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
	/* HEADERS, stream 1, END_HEADERS: POST /post, body follows */
	"\x00\x00\x14\x01\x04\x00\x00\x00\x01"
	"\x83"				/* :method POST */
	"\x86"				/* :scheme http */
	"\x04\x05/post"			/* :path */
	"\x01\x09localhost";		/* :authority */

static const uint8_t h2_rest[] =
	/* DATA, stream 1, END_STREAM: the body */
	"\x00\x00\x08\x00\x01\x00\x00\x00\x01"
	"12345678"
	/* HEADERS, stream 3, END_STREAM | END_HEADERS: GET /ok */
	"\x00\x00\x12\x01\x05\x00\x00\x00\x03"
	"\x82"				/* :method GET */
	"\x86"				/* :scheme http */
	"\x04\x03/ok"			/* :path */
	"\x01\x09localhost";		/* :authority */

static int h2_status[2], h2_ended[2];

static int
callback_raw_h2(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	static const uint8_t settings_ack[] =
					 "\x00\x00\x00\x04\x01\x00\x00\x00\x00";
	struct raw_cli *rc = &cli_h2;
	uint8_t buf[LWS_PRE + 128], *p;
	uint32_t sid;
	size_t flen;
	int n;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (const char *)in : "(null)");
		rc->wsi = NULL;
		raw_cli_finish(rc, 0);
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		rc->wsi = wsi;
		memcpy(buf + LWS_PRE, h2_head, sizeof(h2_head) - 1);
		if (lws_write(wsi, buf + LWS_PRE, sizeof(h2_head) - 1,
			      LWS_WRITE_RAW) != (int)sizeof(h2_head) - 1)
			return -1;
		lws_sul_schedule(cx, 0, &rc->sul, raw_cli_pause_cb,
				 SPLIT_PAUSE_MS * LWS_US_PER_MS);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		/* a raw client is also writeable as soon as it connects */
		if (!rc->paused || rc->phase)
			break;
		rc->phase = 1;
		/* stream 1's body, and stream 3's request right behind it */
		memcpy(buf + LWS_PRE, h2_rest, sizeof(h2_rest) - 1);
		if (lws_write(wsi, buf + LWS_PRE, sizeof(h2_rest) - 1,
			      LWS_WRITE_RAW) != (int)sizeof(h2_rest) - 1)
			return -1;
		break;

	case LWS_CALLBACK_RAW_RX:
		if (raw_cli_accumulate(rc, in, len))
			return -1;

		p = rc->rx;
		while (rc->rx_len >= 9) {
			flen = ((size_t)p[0] << 16) | ((size_t)p[1] << 8) | p[2];
			if (flen > sizeof(rc->rx) - 9) {
				lwsl_err("%s: frame len %u too big\n", __func__,
					 (unsigned int)flen);
				return -1;
			}
			if (rc->rx_len < 9 + flen)
				break;

			sid = ((uint32_t)(p[5] & 0x7f) << 24) |
			      ((uint32_t)p[6] << 16) | ((uint32_t)p[7] << 8) |
			      p[8];
			n = sid == 1 ? 0 : (sid == 3 ? 1 : -1);

			switch (p[3]) {
			case 4: /* SETTINGS: ack theirs */
				if (!(p[4] & 1)) {
					memcpy(buf + LWS_PRE, settings_ack, 9);
					if (lws_write(wsi, buf + LWS_PRE, 9,
						      LWS_WRITE_RAW) != 9)
						return -1;
				}
				break;
			case 1: /* HEADERS */
				if (n >= 0 && !(p[4] & 0x28) && flen >= 13 &&
				    !p[9] && p[10] == 7 &&
				    !memcmp(p + 11, ":status", 7) && p[18] == 3)
					h2_status[n] = ((p[19] - '0') * 100) +
						       ((p[20] - '0') * 10) +
							(p[21] - '0');
				if (n >= 0 && (p[4] & 1))
					h2_ended[n] = 1;
				break;
			case 0: /* DATA */
				if (n >= 0 && (p[4] & 1))
					h2_ended[n] = 1;
				break;
			case 3: /* RST_STREAM */
			case 7: /* GOAWAY */
				lwsl_err("%s: server sent frame type %u on "
					 "stream %u\n", __func__, p[3],
					 (unsigned int)sid);
				raw_cli_finish(rc, 0);

				return -1;
			default:
				break;
			}
			p += 9 + flen;
			rc->rx_len -= 9 + flen;
		}
		if (p != rc->rx)
			memmove(rc->rx, p, rc->rx_len);

		if (h2_ended[0] && h2_ended[1]) {
			n = h2_status[0] == 200 && h2_status[1] == 200;
			if (!n)
				lwsl_err("%s: stream statuses %d, %d\n",
					 __func__, h2_status[0], h2_status[1]);
			raw_cli_finish(rc, n);

			return -1;
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		rc->wsi = NULL;
		lws_sul_cancel(&rc->sul);
		if (!rc->finished)
			lwsl_err("%s: closed, streams ended %d %d\n", __func__,
				 h2_ended[0], h2_ended[1]);
		raw_cli_finish(rc, 0);
		break;

	default:
		break;
	}

	return 0;
}
#endif

#if defined(LWS_ROLE_MQTT)

/*
 * A fake broker, on a raw vhost: CONNACK for the CONNECT, then for the
 * SUBSCRIBE, the SUBACK and two PUBLISHes on the subscribed topic in one
 * write.  The client's echo must come back with the first one's payload.
 *
 * The echo topic is longer than the subscribed one, so that an echo composed
 * over the start of the read the broker's write arrived in would run over
 * the second PUBLISH.
 */

#define TOPIC_SUB	"lws/t"
#define TOPIC_ECHO	"lws/api-test-compose-in-rx/echo"

static const char pay1[] = "first publish payload, echoed from the rx cb";
static const char pay2[] = "second publish payload, behind it in the read";

static char topic_echo[] = TOPIC_ECHO;
static int mqtt_echo_ok, mqtt_pay2_ok, mqtt_rx_count, mqtt_subscribed,
	   mqtt_finished;

struct broker_pss {
	uint8_t				rx[512];
	size_t				rx_len;
	uint8_t				tx[512];
	size_t				tx_len;
};

static int
broker_tx(struct broker_pss *pss, const void *pkt, size_t len)
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
broker_tx_publish(struct broker_pss *pss, const char *topic, const char *pay)
{
	size_t tl = strlen(topic), pl = strlen(pay);
	uint8_t h[4];

	if (2 + tl + pl > 127)
		return 1; /* one-byte remaining length only */

	h[0] = 0x30; /* PUBLISH, QoS0 */
	h[1] = (uint8_t)(2 + tl + pl);
	h[2] = 0;
	h[3] = (uint8_t)tl;

	return broker_tx(pss, h, 4) || broker_tx(pss, topic, tl) ||
	       broker_tx(pss, pay, pl);
}

static void
mqtt_finish(int ok)
{
	if (mqtt_finished)
		return;
	mqtt_finished = 1;
	leg_done("mqtt", ok);
}

static void
mqtt_check_done(void)
{
	if (mqtt_echo_ok && mqtt_pay2_ok)
		mqtt_finish(1);
}

static int
callback_broker(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	struct broker_pss *pss = (struct broker_pss *)user;
	size_t pos = 0, pkt_len, tl;
	const uint8_t *pay;
	uint32_t remlen;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		if (len > sizeof(pss->rx) - pss->rx_len) {
			lwsl_err("%s: broker rx overflow\n", __func__);

			return -1;
		}
		memcpy(pss->rx + pss->rx_len, in, len);
		pss->rx_len += len;

		/* everything the client sends us here is < 128 long */
		while (pss->rx_len - pos >= 2) {
			if (pss->rx[pos + 1] & 0x80) {
				lwsl_err("%s: unexpectedly long packet\n",
					 __func__);
				return -1;
			}
			remlen = pss->rx[pos + 1];
			pkt_len = 2 + remlen;
			if (pss->rx_len - pos < pkt_len)
				break;
			pay = pss->rx + pos + 2;

			switch (pss->rx[pos] >> 4) {
			case LMQCP_CTOS_CONNECT:
				if (broker_tx(pss, "\x20\x02\x00\x00", 4))
					return -1;
				break;

			case LMQCP_CTOS_SUBSCRIBE:
				if (remlen < 2)
					return -1;
				/* SUBACK granting QoS0, then both PUBLISHes */
				if (broker_tx(pss, (const uint8_t[]){
						0x90, 0x03, pay[0], pay[1], 0 },
						5) ||
				    broker_tx_publish(pss, TOPIC_SUB, pay1) ||
				    broker_tx_publish(pss, TOPIC_SUB, pay2))
					return -1;
				break;

			case LMQCP_PUBLISH:
				if (remlen < 2)
					return -1;
				tl = ((size_t)pay[0] << 8) | pay[1];
				if (2 + tl > remlen)
					return -1;
				mqtt_echo_ok = tl == strlen(TOPIC_ECHO) &&
					!memcmp(pay + 2, TOPIC_ECHO, tl) &&
					remlen - 2 - tl == strlen(pay1) &&
					!memcmp(pay + 2 + tl, pay1, strlen(pay1));
				if (!mqtt_echo_ok) {
					lwsl_err("%s: echo is not the first "
						 "payload\n", __func__);
					lwsl_hexdump_err(pay, remlen);
					mqtt_finish(0);

					return -1;
				}
				mqtt_check_done();
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

	case LWS_CALLBACK_RAW_WRITEABLE:
		/* everything queued goes in one write */
		if (pss->tx_len &&
		    lws_write(wsi, pss->tx, pss->tx_len, LWS_WRITE_RAW) !=
						(int)pss->tx_len) {
			lwsl_err("%s: broker write failed\n", __func__);

			return -1;
		}
		pss->tx_len = 0;
		break;

	default:
		break;
	}

	return 0;
}

static lws_mqtt_topic_elem_t topic_sub = {
	.name		= TOPIC_SUB,
	.qos		= QOS0,
};

static lws_mqtt_subscribe_param_t sub_param = {
	.topic		= &topic_sub,
	.num_topics	= 1,
};

static const lws_mqtt_client_connect_param_t conn_param = {
	.client_id		= "lws-api-test-compose-in-rx",
	.keep_alive		= 60,
	.clean_start		= 1,
	.client_id_nofree	= 1,
	.username_nofree	= 1,
	.password_nofree	= 1,
};

static int
callback_mqtt(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	lws_mqtt_publish_param_t *pub, echo;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (const char *)in : "(null)");
		mqtt_finish(0);
		break;

	case LWS_CALLBACK_MQTT_CLIENT_ESTABLISHED:
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_MQTT_CLIENT_WRITEABLE:
		if (mqtt_subscribed)
			break;
		mqtt_subscribed = 1;
		if (lws_mqtt_client_send_subcribe(wsi, &sub_param)) {
			lwsl_err("%s: subscribe failed\n", __func__);
			mqtt_finish(0);

			return -1;
		}
		break;

	case LWS_CALLBACK_MQTT_CLIENT_RX:
		pub = (lws_mqtt_publish_param_t *)in;
		if (!pub || pub->payload_pos || len != pub->payload_len) {
			lwsl_err("%s: expected each publish in one chunk\n",
				 __func__);
			mqtt_finish(0);

			return -1;
		}

		switch (mqtt_rx_count++) {
		case 0:
			if (len != strlen(pay1) ||
			    memcmp(pub->payload, pay1, len)) {
				lwsl_err("%s: first payload wrong\n", __func__);
				mqtt_finish(0);

				return -1;
			}
			/*
			 * The pattern under test: publish from inside the
			 * rx, straight out of the pointer we were handed
			 */
			memset(&echo, 0, sizeof(echo));
			echo.topic	= topic_echo;
			echo.topic_len	= (uint16_t)strlen(topic_echo);
			echo.qos	= QOS0;
			echo.payload_len = (uint32_t)len;
			if (lws_mqtt_client_send_publish(wsi, &echo,
							 pub->payload,
							 (uint32_t)len, 1)) {
				lwsl_err("%s: echo publish failed\n", __func__);
				mqtt_finish(0);

				return -1;
			}
			break;

		case 1:
			mqtt_pay2_ok = len == strlen(pay2) &&
				       !memcmp(pub->payload, pay2, len);
			if (!mqtt_pay2_ok) {
				lwsl_err("%s: second payload corrupted\n",
					 __func__);
				lwsl_hexdump_err(pub->payload, len);
				mqtt_finish(0);

				return -1;
			}
			mqtt_check_done();
			break;

		default:
			lwsl_err("%s: unexpected extra publish\n", __func__);
			mqtt_finish(0);

			return -1;
		}
		break;

	default:
		break;
	}

	return 0;
}
#endif

static const struct lws_protocols protocols_srv[] = {
	{ "compose-srv", callback_srv, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

#if defined(LWS_ROLE_MQTT)
static const struct lws_protocols protocols_broker[] = {
	{ "compose-broker", callback_broker, sizeof(struct broker_pss),
	  0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};
#endif

static const struct lws_protocols protocols_cli[] = {
	{ "compose-raw-h1", callback_raw_h1, 0, 0, 0, NULL, 0 },
#if defined(LWS_WITH_HTTP2)
	{ "compose-raw-h2", callback_raw_h2, 0, 0, 0, NULL, 0 },
#endif
#if defined(LWS_ROLE_MQTT)
	{ "mqtt", callback_mqtt, 0, 0, 0, NULL, 0 },
#endif
	LWS_PROTOCOL_LIST_TERM
};

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out with %d legs pending\n", __func__,
		 legs_pending);
	fails++;
	lws_default_loop_exit(cx);
	lws_cancel_service(cx);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

static int
raw_connect(struct lws_vhost *vh, int port, const char *proto)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= cx;
	i.vhost			= vh;
	i.address		= "127.0.0.1";
	i.host			= "127.0.0.1";
	i.origin		= "127.0.0.1";
	i.port			= port;
	i.method		= "RAW";
	i.local_protocol_name	= proto;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: %s connect failed\n", __func__, proto);

		return 1;
	}
	legs_pending++;

	return 0;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh_cli;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/*
	 * The defaults budget 8 fds per thread, sized for a lone client: we
	 * have three listeners on v4 and v6 and both ends of three
	 * connections open at once
	 */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_h1 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--h2-port")))
		port_h2 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--mqtt-port")))
		port_mqtt = atoi(p);

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: composing from inside rx\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.port = port_h1;
	info.vhost_name = "srv-h1";
	info.protocols = protocols_srv;
	if (!lws_create_vhost(cx, &info)) {
		lwsl_err("Failed to create h1 server vhost\n");
		goto bail;
	}

#if defined(LWS_WITH_HTTP2)
	info.port = port_h2;
	info.vhost_name = "srv-h2";
	info.options |= LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
	if (!lws_create_vhost(cx, &info)) {
		lwsl_err("Failed to create h2 server vhost\n");
		goto bail;
	}
	info.options &= ~(uint64_t)LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
#endif

#if defined(LWS_ROLE_MQTT)
	info.port = port_mqtt;
	info.vhost_name = "broker";
	info.protocols = protocols_broker;
	info.options |= LWS_SERVER_OPTION_ONLY_RAW;
	if (!lws_create_vhost(cx, &info)) {
		lwsl_err("Failed to create broker vhost\n");
		goto bail;
	}
	info.options &= ~(uint64_t)LWS_SERVER_OPTION_ONLY_RAW;
#endif

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	vh_cli = lws_create_vhost(cx, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	if (raw_connect(vh_cli, port_h1, "compose-raw-h1"))
		goto bail;
#if defined(LWS_WITH_HTTP2)
	if (raw_connect(vh_cli, port_h2, "compose-raw-h2"))
		goto bail;
#endif
#if defined(LWS_ROLE_MQTT)
	{
		struct lws_client_connect_info i;

		memset(&i, 0, sizeof(i));
		i.mqtt_cp	= &conn_param;
		i.context	= cx;
		i.vhost		= vh_cli;
		i.address	= "127.0.0.1";
		i.host		= "127.0.0.1";
		i.port		= port_mqtt;
		i.protocol	= "mqtt";
		i.method	= "MQTT";
		i.alpn		= "mqtt";

		if (!lws_client_connect_via_info(&i)) {
			lwsl_err("%s: mqtt connect failed\n", __func__);
			goto bail;
		}
		legs_pending++;
	}
#endif

	lws_sul_schedule(cx, 0, &sul_watchdog, watchdog_cb,
			 10 * LWS_USEC_PER_SEC);

	/* every leg runs to its own verdict, the watchdog bounds it */
	while (n >= 0 && legs_pending)
		n = lws_service(cx, 0);

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&cli_h1.sul);
#if defined(LWS_WITH_HTTP2)
	lws_sul_cancel(&cli_h2.sul);
#endif
	lws_context_destroy(cx);

	if (fails || legs_pending) {
		lwsl_user("Completed: FAIL\n");

		return 1;
	}

	lwsl_user("Completed: OK\n");

	return 0;
}
