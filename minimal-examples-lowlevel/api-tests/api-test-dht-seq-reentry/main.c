/*
 * lws-api-test-dht-seq-reentry
 *
 * The DHT's reliable transport calls back into its consumer, and what the
 * consumer does there can make the DHT recycle sequencers: it keeps at most
 * 64 (LWS_DHT_MAX_TS), and making one more destroys the least recently used.
 * This checks the sequencer calling back is never the one destroyed, and
 * nothing uses it after the callback if it could have been (G-181):
 *
 *  - a plain UDP socket Q sends DHT B a chunk with the verb "FAN".  B's
 *    handler for it sends to 64 endpoints B has no sequencer for, so B
 *    makes 64, which is enough to recycle every sequencer it had, including
 *    the one delivering Q's chunk.  B must not free that one under its own
 *    delivery: Q's chunk is acked with Q's tid and its full length
 *
 *  - none of those 64 endpoints answer, so B's sends to them fail.  When
 *    the first one is reported failed, B's event callback sends to 64 more
 *    new endpoints.  The sequencer reporting its failure must survive that,
 *    to be destroyed once, by the DHT, after the callback
 *
 * Run under ASan, the old behaviour shows as a heap use-after-free (or a
 * double free) inside the DHT.
 *
 * The UDP ports are allocated uniquely at build time and passed in on the
 * command line, so parallel ctest instances do not collide.  Nothing
 * listens on the fan-out port, at 127.0.0.2.. and 127.0.1.2..
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define SR_POLL_US	(50 * LWS_US_PER_MS)
#define SR_DEADLINE_US	(15 * LWS_US_PER_SEC)

/* LWS_DHT_MAX_TS: enough new sequencers to recycle every one B has */
#define SR_FANOUT	64
/* polls to let the second fan-out's sequencers fail and be destroyed */
#define SR_SETTLE_POLLS	40

#define SR_Q_TID	"qqqqqqqqqq"

static struct lws_context *cx;
static struct lws_dht_ctx *dht_b;
static struct lws *wsi_q;
static struct sockaddr_in sa_b;
static lws_sorted_usec_list_t sul_poll, sul_deadline;
static int port_fan, retcode = 1;

static const char *fan_msg = "FAN 0102030405 0 0 ";
static const char *sr_verbs[] = { "FAN" };

static struct {
	int		fanned;		/* B's FAN handler sent to this many */
	int		fanned2;	/* ...and its WRITE_FAILED handler */
	int		settle;
	unsigned int	q_sent:1;	/* Q sent B its FAN chunk */
	unsigned int	q_acked:1;	/* ...B acked it, whole, with Q's tid */
	unsigned int	q_bad:1;	/* ...or acked something else */
	unsigned int	failed:1;	/* a fan-out send was reported failed */
} sr;

/* the endpoint of the i-th fan-out target of set s, nobody listens there */

static void
sr_fan_target(struct sockaddr_in *sin, int set, int i)
{
	memset(sin, 0, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_port = htons((uint16_t)port_fan);
	sin->sin_addr.s_addr = htonl((uint32_t)((127u << 24) | ((unsigned int)set << 8) |
				     (2u + (unsigned int)i)));
}

static int
sr_fanout(struct lws_dht_ctx *ctx, int set)
{
	static const char msg[] = "NOP 0102030405 0 0 ";
	struct sockaddr_in sin;
	int i, n = 0;

	for (i = 0; i < SR_FANOUT; i++) {
		sr_fan_target(&sin, set, i);
		if (!lws_dht_send_data(ctx, (const struct sockaddr *)&sin,
				       msg, sizeof(msg) - 1))
			n++;
	}

	return n;
}

/* B's handler for the verbs it registered */

static int
cb_sr_verbs(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	    void *in, size_t len)
{
	struct lws_dht_verb_dispatch_args *args =
				(struct lws_dht_verb_dispatch_args *)in;

	if (reason != LWS_CALLBACK_DHT_VERB_DISPATCH || !args)
		return 0;

	args->out_precedence = LWS_DHT_VERB_RESULT_PROCEED;

	if (!strcmp(args->msg->verb, "FAN"))
		sr.fanned = sr_fanout(args->ctx, 0);

	return 0;
}

/* B's DHT events */

static void
cb_b(void *closure, int event, const lws_dht_hash_t *info_hash,
     const void *data, size_t data_len, const struct sockaddr *from,
     size_t fromlen)
{
	if (event != LWS_DHT_EVENT_WRITE_FAILED || sr.failed)
		return;

	/* the first fan-out send has failed: fan out again from here */
	sr.failed = 1;
	sr.fanned2 = sr_fanout(dht_b, 1);
}

static ssize_t
sr_find(const uint8_t *buf, size_t len, const char *needle)
{
	size_t nl = strlen(needle), n;

	for (n = 0; n + nl <= len; n++)
		if (!memcmp(buf + n, needle, nl))
			return (ssize_t)n;

	return -1;
}

/* the bencode integer following key, eg "6:offseti", or -1 */

static int64_t
sr_int(const uint8_t *buf, size_t len, const char *key)
{
	ssize_t at = sr_find(buf, len, key);
	int64_t v = 0;
	size_t n;

	if (at < 0)
		return -1;

	for (n = (size_t)at + strlen(key); n < len && buf[n] != 'e'; n++) {
		if (buf[n] < '0' || buf[n] > '9' || v > 0x7fffffffffffll / 10)
			return -1;
		v = (v * 10) + (buf[n] - '0');
	}

	return n < len ? v : -1;
}

static void
sr_sendto(const void *buf, size_t len)
{
	lws_sockfd_type fd = lws_get_socket_fd(wsi_q);
	ssize_t n;

	if (fd == LWS_SOCK_INVALID)
		return;

	n = sendto(fd,
#if defined(WIN32)
		   (const char *)
#endif
		   buf,
#if defined(WIN32)
		   (int)
#endif
		   len, 0, (const struct sockaddr *)&sa_b, sizeof(sa_b));
	if (n != (ssize_t)len)
		lwsl_err("%s: sendto returned %d\n", __func__, (int)n);
}

/* Q's data chunk to B: d1:ad4:data..2:id..3:len..6:offset..e1:q4:data1:t.. */

static void
sr_q_send_chunk(uint64_t offset, const char *msg)
{
	char q[256];
	int n;

	n = lws_snprintf(q, sizeof(q), "d1:ad4:data%u:%s2:id20:"
			 "44444444444444444444"
			 "3:leni%ue6:offseti%lluee1:q4:data1:t%u:%s1:y1:qe",
			 (unsigned int)strlen(msg), msg,
			 (unsigned int)strlen(msg), (unsigned long long)offset,
			 (unsigned int)strlen(SR_Q_TID), SR_Q_TID);
	if (n > 0 && (size_t)n < sizeof(q) - 1)
		sr_sendto(q, (size_t)n);
}

static int
cb_q(struct lws *wsi, enum lws_callback_reasons reason, void *user,
     void *in, size_t len)
{
	const struct lws_udp *udp;
	char t[32];

	if (reason != LWS_CALLBACK_RAW_RX)
		return 0;

	udp = lws_get_udp(wsi);
	if (!udp || udp->sa46.sa4.sin_family != AF_INET ||
	    udp->sa46.sa4.sin_port != sa_b.sin_port)
		return 0;

	/* an ack: d1:rd2:id..3:len..6:offset..e1:t<tid>1:y1:re */

	if (sr_find(in, len, "d1:rd") != 0 || sr_find(in, len, "6:offseti") < 0)
		return 0;

	lws_snprintf(t, sizeof(t), "e1:t%u:%s1:y1:re",
		     (unsigned int)strlen(SR_Q_TID), SR_Q_TID);

	if (sr_find(in, len, t) < 0 ||
	    sr_int(in, len, "6:offseti") != (int64_t)strlen(fan_msg)) {
		lwsl_err("%s: B's ack of Q's chunk is wrong\n", __func__);
		lwsl_hexdump_err(in, len);
		sr.q_bad = 1;
		return 0;
	}

	sr.q_acked = 1;

	return 0;
}

static void
poll_cb(lws_sorted_usec_list_t *sul)
{
	if (!sr.q_sent) {
		sr_q_send_chunk(0, fan_msg);
		sr.q_sent = 1;
	}

	if (sr.q_acked && sr.fanned2 && ++sr.settle >= SR_SETTLE_POLLS) {
		retcode = 0;
		lws_default_loop_exit(cx);
		return;
	}

	lws_sul_schedule(cx, 0, &sul_poll, poll_cb, SR_POLL_US);
}

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out\n", __func__);
	lws_default_loop_exit(cx);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	static const struct lws_protocols protocols[] = {
		{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
		{ "sr-q", cb_q, 0, 0, 0, NULL, 0 },
		{ "sr-verbs", cb_sr_verbs, 0, 0, 0, NULL, 0 },
		LWS_PROTOCOL_LIST_TERM
	};
	struct lws_vhost *vh;
	lws_dht_info_t di;
	uint8_t idb[20];
	int port_b = 0, port_q = 0, n = 0;
	const char *p;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "--port-b")))
		port_b = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-q")))
		port_q = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-fan")))
		port_fan = atoi(p);

	if (port_b < 1 || port_b > 65535 || port_q < 1 || port_q > 65535 ||
	    port_fan < 1 || port_fan > 65535 || port_b == port_q ||
	    port_fan == port_b || port_fan == port_q) {
		lwsl_err("usage: --port-b <udp port> --port-q <udp port> "
			 "--port-fan <unused udp port>\n");
		return 1;
	}

	lwsl_user("LWS API selftest: dht sequencer reentry\n");

	signal(SIGINT, sigint_handler);

	memset(&sa_b, 0, sizeof(sa_b));
	sa_b.sin_family = AF_INET;
	sa_b.sin_port = htons((uint16_t)port_b);
	sa_b.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.vhost_name = "dht-sr-b";
	vh = lws_create_vhost(cx, &info);
	if (!vh) {
		lwsl_err("vhost creation failed\n");
		goto bail;
	}

	memset(idb, 0x22, sizeof(idb));
	memset(&di, 0, sizeof(di));
	di.allow_private_ads	= 1; /* everything is on loopback */
	di.vhost		= vh;
	di.cb			= cb_b;
	di.name			= "sr-b";
	di.port			= port_b;
	{
		lws_dht_hash_t *id = lws_dht_hash_create(
				LWS_DHT_HASH_TYPE_SHA1, 20, idb);
		di.id = id;
		dht_b = lws_dht_create(&di);
		lws_dht_hash_destroy(&id);
	}
	if (!dht_b ||
	    lws_dht_register_verbs(dht_b, sr_verbs,
				   (int)LWS_ARRAY_SIZE(sr_verbs),
				   &protocols[2])) {
		lwsl_err("dht creation failed\n");
		goto bail;
	}

	wsi_q = lws_create_adopt_udp(vh, "127.0.0.1", port_q, LWS_CAUDP_BIND,
				     protocols[1].name, NULL, NULL, NULL, NULL,
				     "sr-q");
	if (!wsi_q) {
		lwsl_err("raw udp socket creation failed\n");
		goto bail;
	}

	lws_sul_schedule(cx, 0, &sul_deadline, deadline_cb, SR_DEADLINE_US);
	lws_sul_schedule(cx, 0, &sul_poll, poll_cb, SR_POLL_US);

	while (n >= 0)
		n = lws_service(cx, 0);

	if (sr.fanned != SR_FANOUT) {
		lwsl_err("B's FAN handler sent to %d of %d\n", sr.fanned,
			 SR_FANOUT);
		retcode = 1;
	}
	if (!sr.q_acked || sr.q_bad) {
		lwsl_err("B did not ack Q's FAN chunk properly\n");
		retcode = 1;
	}
	if (sr.fanned2 != SR_FANOUT) {
		lwsl_err("B's WRITE_FAILED handler sent to %d of %d\n",
			 sr.fanned2, SR_FANOUT);
		retcode = 1;
	}

	lwsl_user("Completed: %s\n", retcode ? "FAIL" : "PASS");

bail:
	lws_sul_cancel(&sul_poll);
	lws_sul_cancel(&sul_deadline);
	lws_context_destroy(cx);

	return retcode;
}
