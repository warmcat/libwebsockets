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
 *    client streams, so the proxy must refuse to create it.
 */

#include <libwebsockets.h>
#include <string.h>
#if !defined(__linux__) && !defined(WIN32)
#include <unistd.h>
#endif

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
			"}}"
		"]"
	"}";

typedef struct leg {
	const char		*name;
	const char		*streamtype;
	char			expect_create_ok;

	/* results */
	char			got_result;
	uint8_t			result;
} leg_t;

static leg_t legs[] = {
	{ "server",	"srv",		0, 0, 0 },
};

/* the client connection's view of the proxy link */

struct pss {
	uint8_t			rx[2048];	/* partial proxy frames */
	size_t			rx_len;
	char			sent_streamtype;
};

static struct lws_context *cx;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_timeout, sul_next_leg;
static char proxy_bind[64], proxy_ads[66];
static unsigned int cur_leg;
static int failed;

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

	if (!l->got_result) {
		lwsl_err("%s: leg %s: no CREATE_RESULT\n", __func__, l->name);
		fail = 1;
	} else
		if ((l->result == 0) != (l->expect_create_ok != 0)) {
			lwsl_err("%s: leg %s: create result %u, expected %s\n",
				 __func__, l->name, l->result,
				 l->expect_create_ok ? "success" : "failure");
			fail = 1;
		}

	if (fail) {
		finish(1);
		return;
	}

	lwsl_user("%s: leg %s: OK\n", __func__, l->name);

	if (++cur_leg == LWS_ARRAY_SIZE(legs)) {
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
proxy_frame(uint8_t type, const uint8_t *body, size_t len)
{
	leg_t *l = &legs[cur_leg];

	switch (type) {
	case LWSSS_SER_RXPRE_CREATE_RESULT:
		if (!len || l->got_result)
			return 1;
		l->got_result = 1;
		l->result = body[0];
		lwsl_user("%s: leg %s: CREATE_RESULT %u\n", __func__,
			  l->name, l->result);

		/* we've seen what we wanted, close the link ourselves */
		return 1;

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
	uint8_t buf[LWS_PRE + 64], *p = buf + LWS_PRE;
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
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
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
			if (proxy_frame(pss->rx[0], &pss->rx[3], fl))
				return -1;
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

static const struct lws_protocols protocols_cli[] = {
	{ "sspx-cli", callback_sspx_cli, sizeof(struct pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	uint8_t rnd[4];

	lws_context_info_defaults(&info, policy);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	lwsl_user("LWS API Test - SS proxy\n");

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
