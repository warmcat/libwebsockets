/*
 * lws-api-test-ss-proxy
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Exercises the proxy side of Secure Streams serialization.  The process is
 * an SS proxy, and it also makes raw client connections to its own proxy
 * Unix Domain Socket, speaking the serialized SS protocol to it the way an
 * sspc client process would, one connection ("leg") at a time:
 *
 *  - "server": the client asks for a streamtype the policy describes as a
 *    server, bound to an existing vhost.  A proxy client can only drive
 *    client streams, so the proxy must refuse to create it, and hang up.
 *
 *  - "create-fail-then-payload": the client asks for a streamtype that
 *    isn't in the policy, and sends payload after the failed result.  The
 *    proxy must hang up, and must not try to queue the payload.
 *
 *  - "sink-full-chunk": the client's stream is fulfilled by a local sink
 *    registered in this process, and it sends a payload of exactly the
 *    1380-byte chunk size the proxy queues client payload in, which is also
 *    the size of the buffer a local sink's source is asked to fill.  The
 *    sink must get all of it.
 *
 *  - "sink-goes-first": the client's stream is fulfilled by a local sink
 *    registered in this process.  The sink takes the client's payload and
 *    then destroys itself, which takes the proxied source stream with it
 *    while the client link is still up.  The proxy must tell the client its
 *    stream is DESTROYING, and not touch the stream after that.
 *
 * Those clients run as the same user as the proxy, which by default may use
 * it.  With --refused, the proxy is told only uid / gid 65534 may use it, and
 * the one leg, "refused", requires the proxy to drop the client without
 * creating anything.  That needs the Linux abstract namespace socket, where
 * the proxy checks client credentials itself, and a test not running as
 * root or 65534: otherwise it's skipped.
 */

#include <libwebsockets.h>
#include <string.h>
#if !defined(WIN32)
#include <unistd.h>
#endif

enum {
	LWS_SW_REFUSED,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_REFUSED]	= { "--refused", "Run the leg where the proxy only "
						 "allows another user" },
	[LWS_SW_HELP]		= { "--help",	 "Show this help information" },
};

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
			/* a server, bound to the existing vhost "srvvh" */
			"{\"srv\":{"
				"\"server\":true,"
				"\"endpoint\":\"!srvvh\","
				"\"protocol\":\"raw\""
			"}},"
			/* fulfilled by the sink we register */
			"{\"sink\":{"
				"\"local_sink\":true,"
				"\"protocol\":\"raw\""
			"}}"
		"]"
	"}";

/* what ends a leg, after the CREATE_RESULT */

enum {
	UNTIL_RESULT,		/* we close as soon as we have the result */
	UNTIL_DESTROYING,	/* we close once the proxy says DESTROYING */
	UNTIL_HANGUP,		/* the proxy must close after the result */
};

typedef struct leg {
	const char		*name;
	const char		*streamtype;
	size_t			payload_len;	/* sent after the result */
	char			expect_create_ok;
	char			until;
	char			sink_destroys;	/* on rx of the EOM */
	char			expect_refused;	/* dropped before the result */

	/* results */
	size_t			sink_rx;
	char			got_result;
	char			seen_destroying;
	uint8_t			result;
} leg_t;

static leg_t legs_main[] = {
	{ .name = "server",		.streamtype = "srv",
	  .until = UNTIL_HANGUP },
	{ .name = "create-fail-then-payload", .streamtype = "nonexistent",
	  .payload_len = 100, .until = UNTIL_HANGUP },
	{ .name = "sink-full-chunk",	.streamtype = "sink",
	  .expect_create_ok = 1, .payload_len = 1380,
	  .sink_destroys = 1, .until = UNTIL_DESTROYING },
	{ .name = "sink-goes-first",	.streamtype = "sink",
	  .expect_create_ok = 1, .payload_len = 100,
	  .sink_destroys = 1, .until = UNTIL_DESTROYING },
}, legs_refused[] = {
	{ .name = "refused",		.streamtype = "sink",
	  .expect_refused = 1 },
};

static leg_t *legs = legs_main;
static unsigned int count_legs = LWS_ARRAY_SIZE(legs_main);

/* the client connection's view of the proxy link */

struct pss {
	uint8_t			rx[2048];	/* partial proxy frames */
	size_t			rx_len;
	char			sent_streamtype;
	char			want_payload;
};

static struct lws_context *cx;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_timeout, sul_next_leg;
static char proxy_bind[64], proxy_ads[66];
static unsigned int cur_leg;
static int failed;
static char we_closed;

static void
finish(int fail)
{
	if (fail)
		failed = 1;
	lws_sul_cancel(&sul_timeout);
	lws_sul_cancel(&sul_next_leg);
	lws_default_loop_exit(cx);
}

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out in leg %s\n", __func__, legs[cur_leg].name);
	finish(1);
}

static void
leg_start(void)
{
	struct lws_client_connect_info i;

	lwsl_user("%s: leg %s\n", __func__, legs[cur_leg].name);

	memset(&i, 0, sizeof(i));
	i.context		= cx;
	i.vhost			= vh_cli;
	i.address		= proxy_ads;
	i.host			= i.address;
	i.origin		= i.address;
	i.method		= "RAW";
	i.local_protocol_name	= "sspx-cli";

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: leg %s: connect failed\n", __func__,
			 legs[cur_leg].name);
		finish(1);
	}
}

static void
sul_next_leg_cb(lws_sorted_usec_list_t *sul)
{
	leg_start();
}

/* the client link closed: judge the leg, and start the next one */

static void
leg_done(void)
{
	leg_t *l = &legs[cur_leg];
	int fail = 0;

	if (l->expect_refused) {
		if (l->got_result) {
			lwsl_err("%s: leg %s: not refused\n", __func__,
				 l->name);
			fail = 1;
		}
	} else if (!l->got_result) {
		lwsl_err("%s: leg %s: no CREATE_RESULT\n", __func__, l->name);
		fail = 1;
	} else
		if ((l->result == 0) != (l->expect_create_ok != 0)) {
			lwsl_err("%s: leg %s: create result %u, expected %s\n",
				 __func__, l->name, l->result,
				 l->expect_create_ok ? "success" : "failure");
			fail = 1;
		}

	if (l->sink_rx != (l->result ? 0 : l->payload_len)) {
		lwsl_err("%s: leg %s: sink rx %u, expected %u\n", __func__,
			 l->name, (unsigned int)l->sink_rx,
			 (unsigned int)l->payload_len);
		fail = 1;
	}

	if (l->until == UNTIL_DESTROYING && !l->seen_destroying) {
		lwsl_err("%s: leg %s: no DESTROYING\n", __func__, l->name);
		fail = 1;
	}

	if (l->until == UNTIL_HANGUP && we_closed) {
		lwsl_err("%s: leg %s: proxy didn't hang up\n", __func__,
			 l->name);
		fail = 1;
	}

	if (fail) {
		finish(1);
		return;
	}

	lwsl_user("%s: leg %s: OK\n", __func__, l->name);

	if (++cur_leg == count_legs) {
		finish(0);
		return;
	}

	lws_sul_schedule(cx, 0, &sul_next_leg, sul_next_leg_cb, 1);
}

/*
 * One frame from the proxy, type, 2-byte length, and len bytes of body.
 * Return nonzero to close the link.
 */

static int
proxy_frame(struct lws *wsi, struct pss *pss, uint8_t type,
	    const uint8_t *body, size_t len)
{
	leg_t *l = &legs[cur_leg];
	uint32_t state;

	switch (type) {
	case LWSSS_SER_RXPRE_CREATE_RESULT:
		if (!len || l->got_result)
			return 1;
		l->got_result = 1;
		l->result = body[0];
		lwsl_user("%s: leg %s: CREATE_RESULT %u\n", __func__,
			  l->name, l->result);

		if (l->until == UNTIL_RESULT ||
		    (l->result && l->until != UNTIL_HANGUP))
			/* we've seen what we wanted, close the link */
			return 1;

		if (l->payload_len) {
			pss->want_payload = 1;
			lws_callback_on_writable(wsi);
		}
		break;

	case LWSSS_SER_RXPRE_CONNSTATE:
		/* 1-byte state and 4-byte ordinal, or 4-byte state */
		if (len == 5)
			state = body[0];
		else if (len == 8)
			state = lws_ser_ru32be(body);
		else
			return 1;

		lwsl_user("%s: leg %s: CONNSTATE %s\n", __func__, l->name,
			  lws_ss_state_name((lws_ss_constate_t)state));

		if (state == LWSSSCS_DESTROYING) {
			l->seen_destroying = 1;
			if (l->until == UNTIL_DESTROYING)
				return 1;
		}
		break;

	default:
		break;
	}

	return 0;
}

static int
callback_sspx_cli(struct lws *wsi, enum lws_callback_reasons reason,
		  void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	uint8_t buf[LWS_PRE + 19 + 1380], *p = buf + LWS_PRE;
	leg_t *l = &legs[cur_leg];
	size_t n, fl;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: leg %s: connection error %s\n", __func__, l->name,
			 in ? (const char *)in : "");
		finish(1);
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		memset(pss, 0, sizeof(*pss));
		we_closed = 0;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (pss->want_payload) {
			/*
			 * TX_PAYLOAD: flags, 4-byte and 8-byte latency
			 * information, and the payload
			 */
			pss->want_payload = 0;
			n = l->payload_len;
			if (n > sizeof(buf) - LWS_PRE - 19)
				return -1;
			p[0] = LWSSS_SER_TXPRE_TX_PAYLOAD;
			lws_ser_wu16be(&p[1], (uint16_t)(16 + n));
			lws_ser_wu32be(&p[3], LWSSS_FLAG_SOM | LWSSS_FLAG_EOM);
			lws_ser_wu32be(&p[7], 0);
			lws_ser_wu64be(&p[11], (uint64_t)lws_now_usecs());
			memset(&p[19], 'x', n);
			if (lws_write(wsi, p, 19 + n, LWS_WRITE_RAW) !=
							(int)(19 + n))
				return -1;
			break;
		}

		if (pss->sent_streamtype)
			break;

		/*
		 * STREAMTYPE: protocol version, our pid, the initial tx
		 * credit we allow, and the streamtype name
		 */
		n = strlen(l->streamtype);
		p[0] = LWSSS_SER_TXPRE_STREAMTYPE;
		lws_ser_wu16be(&p[1], (uint16_t)(1 + 4 + 4 + n));
		p[3] = LWSSSS_VERSION;
		lws_ser_wu32be(&p[4], 1);
		lws_ser_wu32be(&p[8], 0);
		memcpy(&p[12], l->streamtype, n);
		if (lws_write(wsi, p, 12 + n, LWS_WRITE_RAW) != (int)(12 + n))
			return -1;
		pss->sent_streamtype = 1;
		break;

	case LWS_CALLBACK_RAW_RX:
		if (len > sizeof(pss->rx) - pss->rx_len) {
			lwsl_err("%s: leg %s: rx too large\n", __func__, l->name);
			return -1;
		}
		memcpy(pss->rx + pss->rx_len, in, len);
		pss->rx_len += len;

		/* issue each complete frame we have */

		while (pss->rx_len >= 3) {
			fl = lws_ser_ru16be(&pss->rx[1]);
			if (pss->rx_len < 3 + fl)
				break;
			if (proxy_frame(wsi, pss, pss->rx[0], &pss->rx[3], fl)) {
				we_closed = 1;
				return -1;
			}
			pss->rx_len -= 3 + fl;
			memmove(pss->rx, pss->rx + 3 + fl, pss->rx_len);
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		leg_done();
		break;

	default:
		break;
	}

	return 0;
}

/*
 * The local sink, and the accepted sink stream it makes for each stream
 * that binds to it
 */

typedef struct sink {
	struct lws_ss_handle	*ss;
	void			*opaque_data;
} sink_t;

static lws_ss_state_return_t
sink_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	leg_t *l = &legs[cur_leg];

	l->sink_rx += len;
	lwsl_user("%s: leg %s: %u (total %u)\n", __func__, l->name,
		  (unsigned int)len, (unsigned int)l->sink_rx);

	if (l->sink_destroys && (flags & LWSSS_FLAG_EOM))
		/* the sink goes away before the proxied stream does */
		return LWSSSSRET_DESTROY_ME;

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

static const struct lws_protocols protocols_cli[] = {
	{ "sspx-cli", callback_sspx_cli, sizeof(struct pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	lws_ss_info_t ssi;
	uint8_t rnd[4];

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	lws_context_info_defaults(&info, policy);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	lwsl_user("LWS API Test - SS proxy\n");

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_REFUSED].sw)) {
#if defined(__linux__)
		if (!geteuid() || !getegid() ||
		    geteuid() == 65534 || getegid() == 65534) {
			lwsl_user("Completed: skipped, we are root or 65534\n");
			return 0;
		}

		legs			= legs_refused;
		count_legs		= LWS_ARRAY_SIZE(legs_refused);
		info.ss_proxy_perms	= "65534:65534";
#else
		lwsl_user("Completed: skipped, needs an abstract socket\n");
		return 0;
#endif
	}

	info.fd_limit_per_thread	= 0;
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/*
	 * The vhost our client connections come from, and the existing vhost
	 * the "srv" server streamtype binds to
	 */

	info.vhost_name	= "sspx-cli";
	info.protocols	= protocols_cli;
	vh_cli = lws_create_vhost(cx, &info);
	info.vhost_name	= "srvvh";
	info.protocols	= NULL;
	if (!vh_cli || !lws_create_vhost(cx, &info)) {
		lwsl_err("%s: vhost creation failed\n", __func__);
		goto bail;
	}

	/*
	 * A proxy UDS name of our own, so parallel runs can't meet each
	 * other's proxy.  Abstract namespace on Linux, else a socket path.
	 */

	if (lws_get_random(cx, rnd, sizeof(rnd)) != sizeof(rnd))
		goto bail;
	lws_snprintf(proxy_bind, sizeof(proxy_bind),
#if defined(__linux__)
		     "@"
#else
		     "/tmp/" /* NOSONAR */
#endif
		     "lws-api-test-ss-proxy-%02x%02x%02x%02x",
		     rnd[0], rnd[1], rnd[2], rnd[3]);
	/* a client's proxy address starts with + to mean a UDS */
	lws_snprintf(proxy_ads, sizeof(proxy_ads), "+%s", proxy_bind);

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

	if (lws_ss_proxy_create(cx, proxy_bind, 0)) {
		lwsl_err("%s: failed to create ss proxy\n", __func__);
		goto bail;
	}

	lws_sul_schedule(cx, 0, &sul_timeout, sul_timeout_cb,
			 10 * LWS_US_PER_SEC);
	leg_start();

	lws_context_default_loop_run_destroy(cx);

#if !defined(__linux__) && !defined(WIN32)
	unlink(proxy_bind);
#endif

	lwsl_user("Completed: %s\n", failed ? "FAIL" : "OK");

	return failed;

bail:
	lws_context_destroy(cx);
	lwsl_user("Completed: FAIL\n");

	return 1;
}
