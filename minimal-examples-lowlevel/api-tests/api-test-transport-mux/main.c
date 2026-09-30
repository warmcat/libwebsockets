/*
 * lws-api-test-transport-mux
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Drives the SS transport mux framing layer directly: the test plays the mux
 * peer by feeding mux commands to lws_transport_mux_rx_parse(), collects
 * what lws_transport_mux_pending() wants to send back, and stands in for
 * whatever owns the channels on our side (sspc, or the SS proxy) with the
 * callbacks below.  No transport, sspc or proxy is involved.
 */

#include <libwebsockets.h>
#include <string.h>

static struct {
	int		ch_opens;
	int		ch_opens_failed;
	int		ch_closes;
	int		can_write;
	int		can_write_unbound;
	int		payload;

	int		bind_peer_channels;
	/**< like the proxy, bind channels the peer asks for... the client
	 * has nothing to bind them to */
} t;

/* what we bind a peer-requested channel to in proxy role */
static int bound_obj;
/* stands in for the sspc handle that asks for its own channel; only the
 * mux stores this pointer, nothing dereferences it */
static int own_obj;

static int fails;

/* the channel owner's side of the mux */

static int
cb_payload(lws_transport_mux_ch_t *tmc, const uint8_t *buf, size_t len)
{
	t.payload++;

	return 0;
}

static int
cb_ch_opens(lws_transport_mux_ch_t *tmc, int determination)
{
	t.ch_opens++;

	if (determination) {
		t.ch_opens_failed++;
		return 0;
	}

	if (!tmc->priv) {
		if (!t.bind_peer_channels)
			return -1;
		tmc->priv = &bound_obj;
	}

	return 0;
}

static int
cb_ch_closes(lws_transport_mux_ch_t *tmc)
{
	t.ch_closes++;

	return 0;
}

static void
cb_txp_req_write(lws_transport_mux_t *tm)
{
}

static int
cb_txp_can_write(lws_transport_mux_ch_t *tmc)
{
	t.can_write++;
	if (!tmc->priv)
		t.can_write_unbound++;

	return 0;
}

static const lws_txp_mux_parse_cbs_t cbs = {
	.payload		= cb_payload,
	.ch_opens		= cb_ch_opens,
	.ch_closes		= cb_ch_closes,
	.txp_req_write		= cb_txp_req_write,
	.txp_can_write		= cb_txp_can_write,
};

/* the onward transport under the mux, it only has to take write requests */

static void
onw_req_write(lws_transport_priv_t priv)
{
}

static const lws_transport_client_ops_t onw_ops = {
	.name			= "api-test-onw",
	.req_write		= onw_req_write,
};

static void
feed(lws_transport_mux_t *tm, const char *what, const uint8_t *in, size_t len)
{
	if (lws_transport_mux_rx_parse(tm, in, len, &cbs)) {
		lwsl_err("%s: %s: rx_parse failed\n", __func__, what);
		fails++;
	}
}

/*
 * Take the next write opportunity, and check the mux sends exactly exp, or
 * nothing if exp_len is 0
 */

static void
expect_tx(lws_transport_mux_t *tm, const char *what, const uint8_t *exp,
	  size_t exp_len)
{
	uint8_t buf[64];
	size_t len = sizeof(buf);
	int r;

	memset(buf, 0xaa, sizeof(buf));

	r = lws_transport_mux_pending(tm, buf, &len, &cbs);

	if ((r != 0) != (exp_len != 0) || len != exp_len ||
	    (exp_len && memcmp(buf, exp, exp_len))) {
		lwsl_err("%s: %s: pending %d, len %u, expected len %u\n",
			 __func__, what, r, (unsigned int)len,
			 (unsigned int)exp_len);
		lwsl_hexdump_err(buf, len < sizeof(buf) ? len : sizeof(buf));
		fails++;
	}
}

static void
expect_count(const char *what, int seen, int expected)
{
	if (seen == expected)
		return;

	lwsl_err("%s: %s: %d, expected %d\n", __func__, what, seen, expected);
	fails++;
}

int
main(int argc, const char **argv)
{
	static const uint8_t
		pongack[]	= { LWSSSS_LLM_PONGACK, 0, 0, 0, 0, 0, 0, 0, 1 },
		req_ack_7[]	= { LWSSSS_LLM_CHANNEL_REQ, 7,
				    LWSSSS_LLM_CHANNEL_ACK, 7 },
		nack_7[]	= { LWSSSS_LLM_CHANNEL_NACK, 7 },
		req_nack_9[]	= { LWSSSS_LLM_CHANNEL_REQ, 9,
				    LWSSSS_LLM_CHANNEL_NACK, 9 },
		req_11[]	= { LWSSSS_LLM_CHANNEL_REQ, 11 },
		ack_11[]	= { LWSSSS_LLM_CHANNEL_ACK, 11 },
		req_255[]	= { LWSSSS_LLM_CHANNEL_REQ, 255 },
		ack_255[]	= { LWSSSS_LLM_CHANNEL_ACK, 255 },
		data_255[]	= { LWSSSS_LLM_MUX, 255, 0, 1, 'x' };
	struct lws_context_creation_info info;
	lws_transport_info_t tinfo;
	lws_txp_path_client_t path;
	lws_transport_mux_t *tm;
	struct lws_context *cx;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);
	lwsl_user("LWS API selftest: transport mux\n");

	lws_context_info_defaults(&info, NULL);
	info.port = CONTEXT_PORT_NO_LISTEN;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	memset(&tinfo, 0, sizeof(tinfo));
	tinfo.ping_interval_us		= 10 * LWS_US_PER_SEC;
	tinfo.pong_grace_us		= 2 * LWS_US_PER_SEC;
	tinfo.txp_cpath.ops_onw		= &onw_ops;

	tm = lws_transport_mux_create(cx, &tinfo, NULL);
	if (!tm) {
		lwsl_err("mux create failed\n");
		lws_context_destroy(cx);
		return 1;
	}

	/* the peer brings the link up */

	feed(tm, "pongack", pongack, sizeof(pongack));
	if (tm->link_state != LWSTM_OPERATIONAL) {
		lwsl_err("%s: link not up after PONGACK\n", __func__);
		fails++;
	}
	expect_tx(tm, "idle link", NULL, 0);

	/*
	 * Client role, where there's nothing to bind a channel the peer asks
	 * for to.  The peer asks for channel 7 and ACKs it himself before we
	 * answer: his ACK must be ignored, and the channel refused, rather
	 * than opened and passed up with nothing bound to it.
	 */

	feed(tm, "peer self-ACK", req_ack_7, sizeof(req_ack_7));
	expect_count("ch_opens after self-ACK", t.ch_opens, 0);
	expect_tx(tm, "refuse peer channel", nack_7, sizeof(nack_7));
	expect_tx(tm, "refused peer channel gone", NULL, 0);
	expect_count("can_write on unbound ch", t.can_write_unbound, 0);

	/*
	 * The peer asks for channel 9 and withdraws it with a NACK (a FIN)
	 * before we answer: the placeholder goes and nothing is sent for it
	 */

	feed(tm, "peer withdraws", req_nack_9, sizeof(req_nack_9));
	expect_count("ch_closes after withdraw", t.ch_closes, 2);
	expect_tx(tm, "withdrawn peer channel gone", NULL, 0);

	/*
	 * Proxy role: the channel the peer asks for is bound and ACKed, and
	 * his ACK for it afterwards changes nothing
	 */

	t.bind_peer_channels = 1;
	feed(tm, "peer asks", req_11, sizeof(req_11));
	expect_tx(tm, "accept peer channel", ack_11, sizeof(ack_11));
	expect_count("ch_opens for peer channel", t.ch_opens, 2);
	feed(tm, "peer ACKs open ch", ack_11, sizeof(ack_11));
	expect_count("ch_opens after peer ACK", t.ch_opens, 2);
	expect_tx(tm, "nothing after peer ACK", NULL, 0);

	/*
	 * Our own channel: we send CHANNEL_REQ, the peer's ACK for it opens it
	 * with what we bound to it, and DATA on it reaches the owner
	 */

	memset(&path, 0, sizeof(path));
	path.mux = tm;
	if (lws_transport_mux_client_ops.event_retry_connect(&path,
				(struct lws_sspc_handle *)&own_obj)) {
		lwsl_err("%s: failed to add own channel\n", __func__);
		fails++;
	}
	expect_tx(tm, "own channel req", req_255, sizeof(req_255));
	feed(tm, "peer ACKs own ch", ack_255, sizeof(ack_255));
	expect_count("ch_opens for own channel", t.ch_opens, 3);
	expect_count("ch_opens failed", t.ch_opens_failed, 0);
	feed(tm, "data on own ch", data_255, sizeof(data_255));
	expect_count("payload", t.payload, 1);

	lws_transport_mux_destroy(&tm);
	lws_context_destroy(cx);

	expect_count("can_write on unbound ch", t.can_write_unbound, 0);

	if (fails) {
		lwsl_user("Completed: FAIL (%d)\n", fails);
		return 1;
	}

	lwsl_user("Completed: PASS\n");

	return 0;
}
