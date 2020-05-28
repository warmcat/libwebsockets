/*
 * lws-minimal-secure-streams-tx
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 *
 * This demonstrates tx from secure streams.
 *
 * It opens a stream and fires small 80-byte payloads on it at 50Hz (20ms)
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define PKT_SIZE 80
#define RATE_US 50000

static int interrupted, bad = 1;

typedef struct myss {
	struct lws_sspc_handle 	*ss;
	void			*opaque_data;
	/* ... application specific state ... */
	lws_sorted_usec_list_t	sul;

	int			count;
	char			due;
} myss_t;

/* secure streams payload interface */

static int
myss_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
//	myss_t *m = (myss_t *)userobj;

	//lwsl_user("%s: len %d, flags: %d\n", __func__, (int)len, flags);
	//lwsl_hexdump_info(buf, len);

	return 0;
}

static void
txcb(struct lws_sorted_usec_list *sul)
{
	myss_t *m = lws_container_of(sul, myss_t, sul);

	if (m->count == 1000) {
		interrupted = 1;
		return;
	}

	m->due = 1;
	lws_sspc_request_tx(m->ss);

	lws_sul_schedule(lws_sspc_get_context(m->ss), 0, &m->sul, txcb, RATE_US);


}

static int
myss_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf, size_t *len,
	int *flags)
{
	myss_t *m = (myss_t *)userobj;

	if (!m->due)
		return 0;

	m->due = 0;

	if (lws_get_random(lws_sspc_get_context(m->ss), buf, PKT_SIZE) != PKT_SIZE)
		return 1;

	*len = PKT_SIZE;
	*flags = 0;
	if (!m->count)
		*flags |= LWSSS_FLAG_SOM;
	if (m->count == 999) {
		*flags |= LWSSS_FLAG_EOM;
		lwsl_user("%s: sent final packet\n", __func__);
		bad = 0;
	}

	m->count++;

	lws_sul_schedule(lws_sspc_get_context(m->ss), 0, &m->sul, txcb, RATE_US);

	// lwsl_user("%s: sending pkt %d\n", __func__, m->count);

	return 0;
}

static int
myss_state(void *userobj, void *sh, lws_ss_constate_t state,
		lws_ss_tx_ordinal_t ack)
{
	myss_t *m = (myss_t *)userobj;
	struct lws_context *context = lws_sspc_get_context(m->ss);

	lwsl_user("%s: %s, ord 0x%x\n", __func__, lws_ss_state_name(state),
		  (unsigned int)ack);

	switch (state) {
	case LWSSSCS_CREATING:
		break;
	case LWSSSCS_CONNECTED:
		lws_sul_schedule(context, 0, &m->sul, txcb, RATE_US);
		break;
	case LWSSSCS_DISCONNECTED:
		lws_sul_cancel(&m->sul);
		break;
	case LWSSSCS_ALL_RETRIES_FAILED:
		/* if we're out of retries, we want to close the app and FAIL */
		interrupted = 1;
		break;
	default:
		break;
	}

	return 0;
}

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct lws_context_creation_info info;
	struct lws_context *context;
	lws_ss_info_t ssi;
	const char *p;

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS secure streams client TX [-d<verb>]\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */

	info.options = //LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.fd_limit_per_thread = 1 + 6 + 1;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = lws_sspc_protocols;
#if defined(LWS_WITH_DETAILED_LATENCY)
	info.detailed_latency_cb = lws_det_lat_plot_cb;
	info.detailed_latency_filepath = "/tmp/lws-latency-ssclient";
#endif

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/*
	 * We're requesting a secure stream via proxy... where and how this
	 * connects are details managed by the proxy policy
	 */

	memset(&ssi, 0, sizeof ssi);
	ssi.handle_offset		= offsetof(myss_t, ss);
	ssi.opaque_user_data_offset	= offsetof(myss_t, opaque_data);
	ssi.rx				= myss_rx;
	ssi.tx				= myss_tx;
	ssi.state			= myss_state;
	ssi.user_alloc			= sizeof(myss_t);
	ssi.streamtype			= "spam";

	if (lws_sspc_create(context, 0, &ssi, NULL, NULL, NULL, NULL)) {
		lwsl_err("%s: create secure stream failed\n", __func__);
		goto bail;
	}

	/* the event loop */

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

bail:
	lws_context_destroy(context);
	lwsl_user("Completed: %s\n", bad ? "failed" : "OK");

	return bad;
}
