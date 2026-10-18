/*
 * lws-api-test-ss-proxy-mux
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Exercises an SS proxy whose clients reach it over the transport mux, the
 * way the serial-link proxy does (minimal-examples/ssproxy/
 * ssproxy-custom-transport-uart), in one process.
 *
 * The proxy is created with lws_transport_mux_proxy_ops, and under the mux,
 * in place of the serial port, there is a "link" transport implemented in
 * this test.  What the proxy writes on the link is parsed here as the mux
 * client would, and what the test sends goes to the mux's proxy_read() as if
 * it had come in on the link.  The test speaks the mux protocol and, inside
 * a mux channel, the serialized SS protocol, the way an sspc client on the
 * other end of the link would.
 *
 * The client's stream is fulfilled by a local sink registered in this
 * process.  Once the proxy has created it, the client sends, all in one
 * read of the link:
 *
 *  - a 1400-byte payload, more than the proxy's 1380-byte chunk, so the
 *    proxy queues it as a 1380-byte and a 20-byte chunk, the first bigger
 *    than the mux's 1300-byte dsh split size
 *  - two small payloads back to back, queued behind it before the sink can
 *    take anything
 *
 * The sink must receive exactly the bytes that were sent, in order.
 */

#include <libwebsockets.h>
#include <string.h>

/* the mux channel the client asks for */
#define PXM_CH			3

static const char * const policy =
	"{"
		"\"release\":\"01234567\","
		"\"product\":\"myproduct\","
		"\"schema-version\":1,"
		"\"retry\":[{\"default\":{"
			"\"backoff\":[1000,2000,3000],"
			"\"conceal\":3,"
			"\"jitterpc\":20,"
			"\"svalidping\":30,"
			"\"svalidhup\":35"
		"}}],"
		"\"s\":["
			/* fulfilled by the sink we register */
			"{\"sink\":{"
				"\"local_sink\":true,"
				"\"protocol\":\"raw\""
			"}}"
		"]"
	"}";

/* the payloads the client sends, all in one link read */

static const size_t pxm_writes[] = { 1400, 10, 20 };

#define PXM_TOTAL		(1400 + 10 + 20)

static struct lws_context *cx;
static lws_sorted_usec_list_t sul_timeout;
static int failed;

/*
 * The link under the mux.  The proxy end of it is the transport ops below,
 * the client end is played by the test.
 */

static struct {
	const lws_transport_proxy_ops_t	*ops_in;	/* the mux */
	lws_transport_priv_t		priv_in;	/* the mux object */
	lws_sorted_usec_list_t		sul_writeable;
	lws_sorted_usec_list_t		sul_deliver;

	/* client -> proxy, waiting to be delivered as one read */
	uint8_t				tx[4096];
	size_t				tx_len;

	/* proxy -> client mux parser */
	uint8_t				hdr[17];
	size_t				hdr_len;
	size_t				need;	/* bytes still due for cmd */
	uint8_t				cmd;
	size_t				data_left;

	/* serialized SS frames from the proxy on our channel */
	uint8_t				ser[2048];
	size_t				ser_len;

	char				link_up;
	char				ch_open;
	char				sent_payload;
} lk;

/* what the sink received */

static uint8_t sink_buf[PXM_TOTAL];
static size_t sink_rx_len;

static void
finish(int fail)
{
	if (fail)
		failed = 1;
	lws_sul_cancel(&sul_timeout);
	lws_sul_cancel(&lk.sul_writeable);
	lws_sul_cancel(&lk.sul_deliver);
	lws_default_loop_exit(cx);
}

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out: link %d, ch %d, payload sent %d, "
		 "sink rx %u / %u\n", __func__, lk.link_up, lk.ch_open,
		 lk.sent_payload, (unsigned int)sink_rx_len,
		 (unsigned int)PXM_TOTAL);
	finish(1);
}

static uint8_t
pxm_pattern(size_t write_idx, size_t ofs)
{
	return (uint8_t)('A' + (write_idx * 7 + ofs) % 26);
}

/*
 * Client -> proxy: queue bytes, and deliver everything queued as one read of
 * the link from the event loop, never from inside the mux's own callbacks
 */

static void
sul_deliver_cb(lws_sorted_usec_list_t *sul)
{
	size_t len = lk.tx_len;

	lk.tx_len = 0;
	if (len && lk.ops_in->proxy_read(lk.priv_in, lk.tx, len)) {
		lwsl_err("%s: proxy_read failed\n", __func__);
		finish(1);
	}
}

static int
client_send(const uint8_t *buf, size_t len)
{
	if (len > sizeof(lk.tx) - lk.tx_len) {
		lwsl_err("%s: tx overflow\n", __func__);
		return 1;
	}

	memcpy(lk.tx + lk.tx_len, buf, len);
	lk.tx_len += len;
	lws_sul_schedule(cx, 0, &lk.sul_deliver, sul_deliver_cb, 1);

	return 0;
}

/* wrap serialized SS bytes in a mux DATA frame on our channel */

static int
client_send_ch(const uint8_t *buf, size_t len)
{
	uint8_t h[4];

	h[0] = LWSSSS_LLM_MUX;
	h[1] = PXM_CH;
	h[2] = (uint8_t)(len >> 8);
	h[3] = (uint8_t)(len & 0xff);

	return client_send(h, sizeof(h)) || client_send(buf, len);
}

static int
client_send_streamtype(void)
{
	static const char st[] = "sink";
	uint8_t b[32];

	/*
	 * STREAMTYPE: protocol version, our pid, the initial tx credit we
	 * allow, and the streamtype name
	 */
	b[0] = LWSSS_SER_TXPRE_STREAMTYPE;
	lws_ser_wu16be(&b[1], (uint16_t)(1 + 4 + 4 + strlen(st)));
	b[3] = LWSSSS_VERSION;
	lws_ser_wu32be(&b[4], 1);
	lws_ser_wu32be(&b[8], 0);
	memcpy(&b[12], st, strlen(st));

	return client_send_ch(b, 12 + strlen(st));
}

static int
client_send_payloads(void)
{
	uint8_t b[(19 * LWS_ARRAY_SIZE(pxm_writes)) + PXM_TOTAL], *p = b;
	size_t n, m;

	/*
	 * Every TX_PAYLOAD back to back in one mux frame: flags, 4-byte and
	 * 8-byte latency information, and the payload
	 */

	for (n = 0; n < LWS_ARRAY_SIZE(pxm_writes); n++) {
		if (lws_ptr_diff_size_t(b + sizeof(b), p) <
						19 + pxm_writes[n]) {
			lwsl_err("%s: payloads too large\n", __func__);
			return 1;
		}
		p[0] = LWSSS_SER_TXPRE_TX_PAYLOAD;
		lws_ser_wu16be(&p[1], (uint16_t)(16 + pxm_writes[n]));
		lws_ser_wu32be(&p[3], LWSSS_FLAG_SOM | LWSSS_FLAG_EOM);
		lws_ser_wu32be(&p[7], 0);
		lws_ser_wu64be(&p[11], (uint64_t)lws_now_usecs());
		for (m = 0; m < pxm_writes[n]; m++)
			p[19 + m] = pxm_pattern(n, m);
		p += 19 + pxm_writes[n];
	}

	lk.sent_payload = 1;

	return client_send_ch(b, lws_ptr_diff_size_t(p, b));
}

/* one serialized SS frame from the proxy on our channel */

static int
client_ser_frame(uint8_t type, const uint8_t *body, size_t len)
{
	switch (type) {
	case LWSSS_SER_RXPRE_CREATE_RESULT:
		if (!len || body[0]) {
			lwsl_err("%s: stream creation failed\n", __func__);
			return 1;
		}
		lwsl_user("%s: CREATE_RESULT OK, sending payloads\n", __func__);
		if (lk.sent_payload)
			return 1;

		return client_send_payloads();

	default:
		break;
	}

	return 0;
}

static int
client_ser_rx(const uint8_t *buf, size_t len)
{
	size_t o = 0, fl;

	if (len > sizeof(lk.ser) - lk.ser_len) {
		lwsl_err("%s: serialized rx too large\n", __func__);
		return 1;
	}
	memcpy(lk.ser + lk.ser_len, buf, len);
	lk.ser_len += len;

	while (lk.ser_len - o >= 3) {
		fl = lws_ser_ru16be(&lk.ser[o + 1]);
		if (lk.ser_len - o < 3 + fl)
			break;
		if (client_ser_frame(lk.ser[o], &lk.ser[o + 3], fl))
			return 1;
		o += 3 + fl;
	}

	memmove(lk.ser, lk.ser + o, lk.ser_len - o);
	lk.ser_len -= o;

	return 0;
}

/* a whole mux command (other than DATA) from the proxy */

static int
client_mux_cmd(void)
{
	uint8_t b[17];

	switch (lk.cmd) {
	case LWSSSS_LLM_PING:
		/* PONG echoes his time, and adds ours */
		b[0] = LWSSSS_LLM_PONG;
		memcpy(&b[1], &lk.hdr[1], 8);
		lws_ser_wu64be(&b[9], (uint64_t)lws_now_usecs());

		return client_send(b, 17);

	case LWSSSS_LLM_PONGACK:
		if (lk.link_up)
			break;
		lwsl_user("%s: link up, asking for channel %d\n", __func__,
			  PXM_CH);
		lk.link_up = 1;
		b[0] = LWSSSS_LLM_CHANNEL_REQ;
		b[1] = PXM_CH;

		return client_send(b, 2);

	case LWSSSS_LLM_CHANNEL_ACK:
		if (lk.hdr[1] != PXM_CH || lk.ch_open)
			return 1;
		lwsl_user("%s: channel open\n", __func__);
		lk.ch_open = 1;

		return client_send_streamtype();

	case LWSSSS_LLM_CHANNEL_NACK:
	case LWSSSS_LLM_CHANNEL_CLOSE:
		if (lk.hdr[1] == PXM_CH) {
			lwsl_err("%s: proxy closed our channel\n", __func__);
			return 1;
		}
		break;

	default:
		break;
	}

	return 0;
}

/* parse the mux byte stream the proxy writes on the link */

static int
client_mux_rx(const uint8_t *buf, size_t len)
{
	size_t n;

	while (len) {
		if (lk.data_left) {
			n = len < lk.data_left ? len : lk.data_left;
			if (client_ser_rx(buf, n))
				return 1;
			buf += n;
			len -= n;
			lk.data_left -= n;
			continue;
		}

		if (!lk.hdr_len) {
			lk.cmd = *buf;
			switch (lk.cmd) {
			case LWSSSS_LLM_CHANNEL_REQ:
			case LWSSSS_LLM_CHANNEL_ACK:
			case LWSSSS_LLM_CHANNEL_NACK:
			case LWSSSS_LLM_CHANNEL_CLOSE:
			case LWSSSS_LLM_CHANNEL_CLOSE_ACK:
				lk.need = 2;
				break;
			case LWSSSS_LLM_MUX:
				lk.need = 4;
				break;
			case LWSSSS_LLM_PING:
			case LWSSSS_LLM_PONGACK:
				lk.need = 9;
				break;
			case LWSSSS_LLM_PONG:
				lk.need = 17;
				break;
			case LWSSSS_LLM_RESET_TRANSPORT:
				lk.need = 1;
				break;
			default:
				lwsl_err("%s: unknown mux cmd 0x%x\n", __func__,
					 lk.cmd);
				return 1;
			}
		}

		lk.hdr[lk.hdr_len++] = *buf++;
		len--;
		if (lk.hdr_len < lk.need)
			continue;

		lk.hdr_len = 0;
		if (lk.cmd == LWSSSS_LLM_MUX) {
			if (lk.hdr[1] != PXM_CH) {
				lwsl_err("%s: DATA on ch %u\n", __func__,
					 lk.hdr[1]);
				return 1;
			}
			lk.data_left = lws_ser_ru16be(&lk.hdr[2]);
			continue;
		}

		if (client_mux_cmd())
			return 1;
	}

	return 0;
}

/* the proxy end of the link, under the mux */

static void
sul_writeable_cb(lws_sorted_usec_list_t *sul)
{
	lk.ops_in->event_proxy_can_write(lk.priv_in
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
					 , NULL
#endif
					);
}

static int
link_init_proxy_server(struct lws_context *context,
		       const struct lws_transport_proxy_ops *txp_ops_inward,
		       lws_transport_priv_t txp_priv_inward,
		       lws_txp_path_proxy_t *txp_ppath, const void *aux,
		       const char *bind, int port)
{
	lk.ops_in		= txp_ops_inward;
	lk.priv_in		= txp_priv_inward;
	txp_ppath->priv_onw	= (lws_transport_priv_t)&lk;

	return 0;
}

static void
link_req_write(lws_transport_priv_t priv)
{
	lws_sul_schedule(cx, 0, &lk.sul_writeable, sul_writeable_cb, 1);
}

static int
link_write(lws_transport_priv_t priv, uint8_t *buf, size_t *len)
{
	/* the whole write is taken, it goes straight to the client */

	if (client_mux_rx(buf, *len))
		finish(1);

	return 0;
}

static void
link_onward_bind(lws_transport_priv_t priv, struct lws_ss_handle *h)
{
}

static void
link_client_up(lws_transport_priv_t priv)
{
}

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
static const lws_fi_ctx_t *
link_fault_context(lws_transport_priv_t priv)
{
	return NULL;
}
#endif

static const lws_transport_proxy_ops_t link_ops = {
	.name			= "api-test-link",
	.init_proxy_server	= link_init_proxy_server,
	.proxy_req_write	= link_req_write,
	.proxy_write		= link_write,
	.event_onward_bind	= link_onward_bind,
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	.fault_context		= link_fault_context,
#endif
	.event_client_up	= link_client_up,
	/* like the serial transport the mux normally runs on */
	.flags			= LWS_DSHFLAG_ENABLE_COALESCE |
				  LWS_DSHFLAG_ENABLE_SPLIT
};

static lws_transport_info_t info_link = {
	.ping_interval_us		= LWS_US_PER_SEC * 10,
	.pong_grace_us			= LWS_US_PER_SEC * 2,
	.flags				= LWSTMINFO_SERVER,
}, info_mux = {
	.ping_interval_us		= LWS_US_PER_SEC * 10,
	.pong_grace_us			= LWS_US_PER_SEC * 2,
	.txp_ppath = {
		.ops_onw		= &link_ops,
		.ops_in			= &lws_transport_mux_proxy_ops,
	},
	.onward_txp_info		= &info_link,
	.flags				= LWSTMINFO_SERVER,
};

/*
 * The local sink, and the accepted sink stream it makes for the proxied
 * stream that binds to it
 */

typedef struct sink {
	struct lws_ss_handle	*ss;
	void			*opaque_data;
} sink_t;

static lws_ss_state_return_t
sink_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	size_t n, w, o, base;

	lwsl_user("%s: %u (total %u)\n", __func__, (unsigned int)len,
		  (unsigned int)(sink_rx_len + len));

	if (len > sizeof(sink_buf) - sink_rx_len) {
		lwsl_err("%s: more than was sent\n", __func__);
		finish(1);
		return LWSSSSRET_OK;
	}
	memcpy(sink_buf + sink_rx_len, buf, len);
	sink_rx_len += len;

	if (sink_rx_len != sizeof(sink_buf))
		return LWSSSSRET_OK;

	/* we have as much as was sent: is it exactly what was sent? */

	base = 0;
	for (w = 0; w < LWS_ARRAY_SIZE(pxm_writes); w++) {
		for (o = 0; o < pxm_writes[w]; o++) {
			n = base + o;
			if (sink_buf[n] != pxm_pattern(w, o)) {
				lwsl_err("%s: write %u differs at +%u\n",
					 __func__, (unsigned int)w,
					 (unsigned int)o);
				finish(1);
				return LWSSSSRET_OK;
			}
		}
		base += pxm_writes[w];
	}

	lwsl_user("%s: all %u bytes arrived intact\n", __func__,
		  (unsigned int)sink_rx_len);
	finish(0);

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
sink_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf, size_t *len,
	int *flags)
{
	sink_t *m = (sink_t *)userobj;
	lws_ss_state_return_t r;

	/*
	 * The source asked to write, and a sink pulls what its source
	 * has by asking to write itself.  We have nothing to send back.
	 */

	r = lws_ss_request_tx(m->ss);
	if (r)
		return r;

	return LWSSSSRET_TX_DONT_SEND;
}

static lws_ss_state_return_t
sink_state(void *userobj, void *sh, lws_ss_constate_t state,
	   lws_ss_tx_ordinal_t ack)
{
	lwsl_user("%s: %s\n", __func__, lws_ss_state_name(state));

	return LWSSSSRET_OK;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	lws_ss_info_t ssi;

	lws_context_info_defaults(&info, policy);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	lwsl_user("LWS API Test - SS proxy over the transport mux\n");

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.txp_ops_ssproxy		= &lws_transport_mux_proxy_ops;
	info.txp_ssproxy_info		= &info_mux;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	memset(&ssi, 0, sizeof(ssi));
	ssi.handle_offset		= offsetof(sink_t, ss);
	ssi.opaque_user_data_offset	= offsetof(sink_t, opaque_data);
	ssi.rx				= sink_rx;
	ssi.tx				= sink_tx;
	ssi.state			= sink_state;
	ssi.user_alloc			= sizeof(sink_t);
	ssi.streamtype			= "sink";
	ssi.flags			= LWSSSINFLAGS_REGISTER_SINK;

	if (lws_ss_create(cx, 0, &ssi, NULL, NULL, NULL, NULL)) {
		lwsl_err("%s: failed to register sink\n", __func__);
		goto bail;
	}

	/* the mux pings the link straight away, and we take it from there */

	if (lws_ss_proxy_create(cx, "api-test-link", 0)) {
		lwsl_err("%s: failed to create ss proxy\n", __func__);
		goto bail;
	}

	lws_sul_schedule(cx, 0, &sul_timeout, sul_timeout_cb,
			 10 * LWS_US_PER_SEC);

	lws_context_default_loop_run_destroy(cx);

	lwsl_user("Completed: %s\n", failed ? "FAIL" : "OK");

	return failed;

bail:
	lws_context_destroy(cx);
	lwsl_user("Completed: FAIL\n");

	return 1;
}
