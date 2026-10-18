/*
 * lws-api-test-sspc-rx-metadata
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The SS proxy tells an sspc client about rx metadata in METADATA frames,
 * whose value may arrive over several reads of the proxy link, and the link
 * may go down before all of it has come.  The client must only ever show
 * user code a complete value: until a new value has all arrived,
 * lws_sspc_get_metadata() keeps returning the previous complete value with
 * that name.
 *
 * The process is an sspc client, and it also plays the proxy, with a raw
 * Unix Domain Socket listener of its own speaking the serialized SS protocol
 * the way the proxy would.  The proxy:
 *
 *  - on the first link, creates the stream and sends "md" = "old"
 *  - sends the start of a METADATA frame with a new 64-byte value for "md",
 *    stopping after the first few bytes of the value
 *  - drops the link
 *  - on the second link, creates the stream again and sends the whole new
 *    value
 *
 * After each step the client checks what lws_sspc_get_metadata() says about
 * "md": "old" until the second link has delivered all of the new value, and
 * then exactly the new value.
 */

#include <libwebsockets.h>
#include <string.h>
#if !defined(WIN32)
#include <unistd.h>
#endif

#define RXMD_NAME		"md"
#define RXMD_OLD		"old"
#define RXMD_NEW_LEN		64
#define RXMD_PARTIAL		5	/* bytes of the new value before the drop */
/* how long we give each step to reach the other side */
#define RXMD_STEP_US		(200 * LWS_US_PER_MS)

typedef struct myss {
	struct lws_sspc_handle		*ss;
	void				*opaque_data;
} myss_t;

/* the steps, driven from the client side */

enum {
	RXMD_WAIT_OLD,		/* proxy creates the stream and sends "old" */
	RXMD_SENT_PARTIAL,	/* proxy sent part of the new value */
	RXMD_DROPPED,		/* proxy dropped the link mid-value */
	RXMD_WAIT_NEW,		/* proxy sends the whole new value on relink */
};

static struct lws_context *cx;
static struct lws_sspc_handle *hss;
static lws_sorted_usec_list_t sul_step, sul_timeout;
static char proxy_bind[64], proxy_ads[66];
static uint8_t new_value[RXMD_NEW_LEN];
static int step, failed, links;

/* the proxy side of the link */

static struct lws *proxy_wsi;
static char proxy_send_partial, proxy_drop;

struct pss {
	char			created;
};

static void
finish(int fail)
{
	if (fail)
		failed = 1;
	lws_sul_cancel(&sul_step);
	lws_sul_cancel(&sul_timeout);
	lws_cancel_service(cx);
	lws_default_loop_exit(cx);
}

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out at step %d (links %d)\n", __func__, step,
		 links);
	finish(1);
}

/* does "md" have exactly this value for user code? */

static int
check_md(const char *what, const void *exp, size_t exp_len)
{
	const void *v;
	size_t len;

	if (lws_sspc_get_metadata(hss, RXMD_NAME, &v, &len)) {
		lwsl_err("%s: %s: no %s\n", __func__, what, RXMD_NAME);
		return 1;
	}

	if (len != exp_len || memcmp(v, exp, len)) {
		lwsl_err("%s: %s: %s is %u bytes, expected %u\n", __func__,
			 what, RXMD_NAME, (unsigned int)len,
			 (unsigned int)exp_len);
		return 1;
	}

	lwsl_user("%s: %s: OK\n", __func__, what);

	return 0;
}

static void
sul_step_cb(lws_sorted_usec_list_t *sul)
{
	switch (step) {
	case RXMD_WAIT_OLD:
		if (check_md("first value", RXMD_OLD, strlen(RXMD_OLD))) {
			finish(1);
			return;
		}
		/* have the proxy start sending a new value */
		step = RXMD_SENT_PARTIAL;
		proxy_send_partial = 1;
		lws_callback_on_writable(proxy_wsi);
		break;

	case RXMD_SENT_PARTIAL:
		if (check_md("while new value incomplete", RXMD_OLD,
			     strlen(RXMD_OLD))) {
			finish(1);
			return;
		}
		/* have the proxy drop the link with the value incomplete */
		step = RXMD_DROPPED;
		proxy_drop = 1;
		lws_callback_on_writable(proxy_wsi);
		break;

	case RXMD_DROPPED:
		if (check_md("after link lost mid-value", RXMD_OLD,
			     strlen(RXMD_OLD))) {
			finish(1);
			return;
		}
		/* the sspc relinks by itself, and the proxy sends it all */
		step = RXMD_WAIT_NEW;
		return;

	case RXMD_WAIT_NEW:
		if (check_md("complete new value", new_value,
			     sizeof(new_value))) {
			finish(1);
			return;
		}
		finish(0);
		return;
	}

	lws_sul_schedule(cx, 0, &sul_step, sul_step_cb, RXMD_STEP_US);
}

/* append a METADATA frame for "md" with vlen bytes of value to p */

static size_t
proxy_md_frame(uint8_t *p, size_t vlen_frame, const void *v, size_t vlen)
{
	size_t nl = strlen(RXMD_NAME);

	p[0] = LWSSS_SER_RXPRE_METADATA;
	lws_ser_wu16be(&p[1], (uint16_t)(1 + nl + vlen_frame));
	p[3] = (uint8_t)nl;
	memcpy(&p[4], RXMD_NAME, nl);
	memcpy(&p[4 + nl], v, vlen);

	return 4 + nl + vlen;
}

static int
callback_fake_proxy(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	uint8_t buf[LWS_PRE + 256], *start = buf + LWS_PRE, *p = start;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		links++;
		lwsl_user("%s: link %d up\n", __func__, links);
		proxy_wsi = wsi;
		break;

	case LWS_CALLBACK_RAW_RX:
		/*
		 * The first thing the client sends is its STREAMTYPE, what
		 * it sends after that doesn't matter here
		 */
		if (!pss->created) {
			pss->created = 1;
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (proxy_drop) {
			lwsl_user("%s: dropping link\n", __func__);
			proxy_drop = 0;
			return -1;
		}

		if (proxy_send_partial) {
			/* the frame promises all of it, we send the start */
			proxy_send_partial = 0;
			p += proxy_md_frame(p, sizeof(new_value), new_value,
					    RXMD_PARTIAL);
		} else {
			if (pss->created != 1)
				break;
			pss->created = 2;

			/*
			 * CREATE_RESULT: success, and 0 for the dsh size, so
			 * the client uses its default
			 */
			p[0] = LWSSS_SER_RXPRE_CREATE_RESULT;
			lws_ser_wu16be(&p[1], 5);
			p[3] = 0;
			lws_ser_wu32be(&p[4], 0);
			p += 8;

			if (links == 1)
				p += proxy_md_frame(p, strlen(RXMD_OLD),
						    RXMD_OLD, strlen(RXMD_OLD));
			else
				p += proxy_md_frame(p, sizeof(new_value),
						    new_value,
						    sizeof(new_value));

			/* the client checks what it got in a moment */
			lws_sul_schedule(cx, 0, &sul_step, sul_step_cb,
					 RXMD_STEP_US);
		}

		if (lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
			      LWS_WRITE_RAW) != (int)lws_ptr_diff(p, start))
			return -1;
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		if (proxy_wsi == wsi)
			proxy_wsi = NULL;
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "fake-proxy", callback_fake_proxy, sizeof(struct pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* the sspc client */

static lws_ss_state_return_t
myss_state(void *userobj, void *sh, lws_ss_constate_t state,
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
	uint8_t rnd[4];
	size_t n;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	lwsl_user("LWS API selftest: sspc rx metadata\n");

	for (n = 0; n < sizeof(new_value); n++)
		new_value[n] = (uint8_t)('a' + (n % 26));

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.fd_limit_per_thread	= 0;
	info.options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	/*
	 * The context keeps this pointer, and the sspc only reads it when it
	 * connects: we fill in the name below, before creating the sspc
	 */
	info.ss_proxy_bind		= proxy_ads;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/*
	 * A proxy UDS name of our own, so parallel runs can't meet each
	 * other.  Abstract namespace on Linux, else a socket path.
	 */

	if (lws_get_random(cx, rnd, sizeof(rnd)) != sizeof(rnd))
		goto bail;
	lws_snprintf(proxy_bind, sizeof(proxy_bind),
#if defined(__linux__)
		     "@"
#else
		     "/tmp/" /* NOSONAR */
#endif
		     "lws-api-test-sspc-rx-metadata-%02x%02x%02x%02x",
		     rnd[0], rnd[1], rnd[2], rnd[3]);
	/* a client's proxy address starts with + to mean a UDS */
	lws_snprintf(proxy_ads, sizeof(proxy_ads), "+%s", proxy_bind);

	/* we play the proxy on that UDS */

	memset(&info, 0, sizeof(info));
	info.vhost_name			= "fake-proxy";
	info.options			= LWS_SERVER_OPTION_UNIX_SOCK |
				LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.iface			= proxy_bind;
	info.listen_accept_role		= "raw-skt";
	info.listen_accept_protocol	= "fake-proxy";
	info.protocols			= protocols;

	if (!lws_create_vhost(cx, &info)) {
		lwsl_err("%s: failed to create proxy vhost\n", __func__);
		goto bail;
	}

	memset(&ssi, 0, sizeof(ssi));
	ssi.handle_offset		= offsetof(myss_t, ss);
	ssi.opaque_user_data_offset	= offsetof(myss_t, opaque_data);
	ssi.state			= myss_state;
	ssi.user_alloc			= sizeof(myss_t);
	ssi.streamtype			= "api-test";

	if (lws_sspc_create(cx, 0, &ssi, NULL, &hss, NULL, NULL)) {
		lwsl_err("%s: failed to create sspc\n", __func__);
		goto bail;
	}

	lws_sul_schedule(cx, 0, &sul_timeout, sul_timeout_cb,
			 10 * LWS_US_PER_SEC);

	lws_context_default_loop_run_destroy(cx);

#if !defined(__linux__) && !defined(WIN32)
	unlink(proxy_bind);
#endif

	lwsl_user("Completed: %s\n", failed ? "FAIL" : "PASS");

	return failed;

bail:
	lws_context_destroy(cx);
	lwsl_user("Completed: FAIL\n");

	return 1;
}
