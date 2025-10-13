/*
 * lws-minimal-secure-streams-hugeurl
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 *
 * This checks huge url operations via libwebsockets.org
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static unsigned int timeout_ms = 6000;
static int interrupted, bad = 1, h1;
static lws_state_notify_link_t nl;
static size_t hugeurl_size = 4000;
static char *hugeurl, *check;

#if !defined(LWS_SS_USE_SSPC)
static const char * const default_ss_policy =
	"{"
	  "\"release\":"			"\"01234567\","
	  "\"product\":"			"\"myproduct\","
	  "\"schema-version\":"			"1,"
#if defined(VIA_LOCALHOST_SOCKS)
	  "\"via-socks5\":"                     "\"127.0.0.1:1080\","
#endif

	  "\"retry\": ["	/* named backoff / retry strategies */
		"{\"default\": {"
			"\"backoff\": ["	 "1000,"
						 "2000,"
						 "3000,"
						 "5000,"
						"10000"
				"],"
			"\"conceal\":"		"5,"
			"\"jitterpc\":"		"20,"
			"\"svalidping\":"	"30,"
			"\"svalidhup\":"	"35"
		"}}"
	  "],"
	  "\"certs\": [" /* named individual certificates in BASE64 DER */
		/*
		 * Let's Encrypt certs for warmcat.com / libwebsockets.org
		 *
		 * We fetch the real policy from there using SS and switch to
		 * using that.
		 */
		"{\"isrg_root_x1\": \""
	"MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw"
	"TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh"
	"cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4"
	"WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu"
	"ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY"
	"MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc"
	"h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+"
	"0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U"
	"A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW"
	"T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH"
	"B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC"
	"B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv"
	"KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn"
	"OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn"
	"jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw"
	"qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI"
	"rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV"
	"HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq"
	"hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL"
	"ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ"
	"3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK"
	"NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5"
	"ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur"
	"TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC"
	"jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc"
	"oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq"
	"4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA"
	"mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d"
	"emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc="
	  "\"}"
	  "],"
	  "\"trust_stores\": [" /* named cert chains */
		"{"
			"\"name\": \"le_via_isrg\","
			"\"stack\": ["
				"\"isrg_root_x1\""
			"]"
		"}"
	  "],"
	  "\"s\": [{"

		"\"lws_anything_h1\": {"
			"\"endpoint\":"			"\"libwebsockets.org\","
			"\"port\":"			"443,"
			"\"protocol\":"			"\"h1\","
			"\"http_method\":"		"\"GET\","
			"\"http_url\":"			"\"urlarg/?x=${hugearg}\","
			"\"metadata\": [{"
				"\"hugearg\":"		"\"\""
			"}],"
			"\"tls\":"			"true,"
			"\"timeout_ms\":"			"4000,"
			"\"retry\":"			"\"default\","
			"\"tls_trust_store\":"		"\"le_via_isrg\""
		"}},{"
		"\"lws_anything_h2\": {"
			"\"endpoint\":"			"\"libwebsockets.org\","
			"\"port\":"			"443,"
			"\"protocol\":"			"\"h2\","
			"\"http_method\":"		"\"GET\","
			"\"http_url\":"			"\"urlarg/?x=${hugearg}\","
			"\"nghttp2_quirk_end_stream\":" "true,"
			"\"h2q_oflow_txcr\":"		"true,"
			"\"metadata\": [{"
				"\"hugearg\":"		"\"\""
			"}],"
			"\"timeout_ms\":"			"4000,"
			"\"tls\":"			"true,"
			"\"retry\":"			"\"default\","
			"\"tls_trust_store\":"		"\"le_via_isrg\""
		"}},{"
			/*
			 * "captive_portal_detect" describes
			 * what to do in order to check if the path to
			 * the Internet is being interrupted by a
			 * captive portal.  If there's a larger policy
			 * fetched from elsewhere, it should also include
			 * this since it needs to be done at least after
			 * every DHCP acquisition
			 */
		    "\"captive_portal_detect\": {"
                        "\"endpoint\": \"connectivitycheck.android.com\","
			"\"http_url\": \"generate_204\","
			"\"port\": 80,"
                        "\"protocol\": \"h1\","
                        "\"http_method\": \"GET\","
                        "\"opportunistic\": true,"
                        "\"http_expect\": 204,"
			"\"http_fail_redirect\": true"
                "}}"
	"]}"
;

#endif

typedef struct myss {
	struct lws_ss_handle 		*ss;
	void				*opaque_data;
	/* ... application specific state ... */
	lws_sorted_usec_list_t		sul;
	struct lejp_ctx			ctx;
	size_t				comp;
	size_t				cr;

	unsigned char			check[16384];
	char				started;

} myss_t;


/* secure streams payload interface */

static lws_ss_state_return_t
myss_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	myss_t *m = (myss_t *)userobj;

	if (m->cr + len > sizeof(m->check)) {
		lwsl_err("%s: oversize receive\n", __func__);
		return LWSSSSRET_DISCONNECT_ME;
	}

	memcpy(m->check + m->cr, buf, len);
	m->cr += len;

	if (flags & LWSSS_FLAG_EOM) {

		interrupted = 1;

		/* confirm that what we collected is the expected size */

		if (m->cr != hugeurl_size) {
			lwsl_err("%s: wrong urlarg size recovered %d %d\n",
				 __func__, (int)m->cr, (int)hugeurl_size);
			return LWSSSSRET_OK;
		}

		/* confirm what we sent is the same as what we collected */

		if (memcmp(hugeurl, m->check, hugeurl_size)) {
			lwsl_err("%s: huge url content mismatch\n", __func__);

			return LWSSSSRET_OK;
		}

		lwsl_user("%s: return hugeurl len %u matches OK\n", __func__,
				(unsigned int)hugeurl_size);

		bad = 0;
	}

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
myss_state(void *userobj, void *sh, lws_ss_constate_t state,
	   lws_ss_tx_ordinal_t ack)
{
	myss_t *m = (myss_t *)userobj;

	lwsl_user("%s: %s (%d), ord 0x%x\n", __func__,
		  lws_ss_state_name(state), (int)state, (unsigned int)ack);

	switch (state) {
	case LWSSSCS_CREATING:
		lws_ss_start_timeout(m->ss, timeout_ms);

		/* let's make the hugeurl part */

		hugeurl = malloc(hugeurl_size + 1);
		if (!hugeurl) {
			lwsl_err("OOM\n");
			return LWSSSSRET_DESTROY_ME;
		}

		check = malloc(hugeurl_size + 1);
		if (!check) {
			lwsl_err("OOM\n");
			free(hugeurl);
			hugeurl = NULL;
			return LWSSSSRET_DESTROY_ME;
		}

		/* Create the big, random, urlarg */

		lws_hex_random(lws_ss_get_context(m->ss), hugeurl,
			       hugeurl_size + 1);
		if (lws_ss_set_metadata(m->ss, "hugearg", hugeurl, hugeurl_size))
			return LWSSSSRET_DISCONNECT_ME;

		return lws_ss_client_connect(m->ss);

	case LWSSSCS_ALL_RETRIES_FAILED:
		/* if we're out of retries, we want to close the app and FAIL */
		interrupted = 1;
		lws_cancel_service(lws_ss_get_context(m->ss));
		break;

	case LWSSSCS_QOS_ACK_REMOTE:
		lwsl_notice("%s: LWSSSCS_QOS_ACK_REMOTE\n", __func__);
		break;

	case LWSSSCS_QOS_NACK_REMOTE:
		lwsl_notice("%s: LWSSSCS_QOS_NACK_REMOTE\n", __func__);
		break;

	case LWSSSCS_TIMEOUT:
		lwsl_notice("%s: LWSSSCS_TIMEOUT\n", __func__);
		interrupted = 1;
		lws_cancel_service(lws_ss_get_context(m->ss));
		break;

	case LWSSSCS_USER_BASE:
		lwsl_notice("%s: LWSSSCS_USER_BASE\n", __func__);
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

static lws_ss_info_t ssi = {
	.handle_offset			= offsetof(myss_t, ss),
	.opaque_user_data_offset	= offsetof(myss_t, opaque_data),
	.rx				= myss_rx,
	.state				= myss_state,
	.user_alloc			= sizeof(myss_t),
	.streamtype			= "lws_anything_h2"
};

static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		    int current, int target)
{
	struct lws_context *context = lws_system_context_from_system_mgr(mgr);

	/*
	 * For the things we care about, let's notice if we are trying to get
	 * past them when we haven't solved them yet, and make the system
	 * state wait while we trigger the dependent action.
	 */
	if (target != LWS_SYSTATE_OPERATIONAL)
		return 0;

	if (current != LWS_SYSTATE_OPERATIONAL)
		return 0;

	if (h1)
		ssi.streamtype = "lws_anything_h1";

	if (!lws_ss_create(context, 0, &ssi, NULL, NULL, NULL, NULL))
		return 0;

	lwsl_err("%s: failed to create secure stream\n", __func__);

	return -1;
}

static lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	const char *p;
	int n = 0;

	signal(SIGINT, sigint_handler);

	memset(&info, 0, sizeof info);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS secure streams hugeurl test client [-d<verb>][-h <urlarg len>]\n");

	info.fd_limit_per_thread = 1 + 6 + 1;
	info.port = CONTEXT_PORT_NO_LISTEN;
#if defined(LWS_SS_USE_SSPC)
	info.protocols = lws_sspc_protocols;

	/* connect to ssproxy via UDS by default, else via
	 * tcp connection to this port */
	if ((p = lws_cmdline_option(argc, argv, "-p")))
		info.ss_proxy_port = (uint16_t)atoi(p);

	/* UDS "proxy.ss.lws" in abstract namespace, else this socket
	 * path; when -p given this can specify the network interface
	 * to bind to */
	if ((p = lws_cmdline_option(argc, argv, "-i")))
		info.ss_proxy_bind = p;

	/* if -p given, -a specifies the proxy address to connect to */
	if ((p = lws_cmdline_option(argc, argv, "-a")))
		info.ss_proxy_address = p;
#else
	info.pss_policies_json = default_ss_policy;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_H2_JUST_FIX_WINDOW_UPDATE_OVERFLOW |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
#endif
	info.connect_timeout_secs = 15;
	info.timeout_secs = 10;

	if (lws_cmdline_option(argc, argv, "--h1"))
		h1 = 1;

	if ((p = lws_cmdline_option(argc, argv, "-h")))
		hugeurl_size = (size_t)atol(p);

	if (hugeurl_size < 1 || hugeurl_size > 16384) {
		lwsl_err("%s: -h should be between 1 and 16384\n", __func__);
		return 1;
	}

	lwsl_user("%s: huge argument size: %u bytes\n", __func__,
			(unsigned int)hugeurl_size);

	info.pt_serv_buf_size = (unsigned int)((hugeurl_size * 2) + 2048);
	info.max_http_header_data = (unsigned short)(hugeurl_size + 2048);

	/* integrate us with lws system state management when context created */

	nl.name = "app";
	nl.notify_cb = app_system_state_nf;
	info.register_notifier_list = app_notifier_list;

	/* create the context */

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the event loop */

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	free(hugeurl);
	free(check);

	lwsl_user("Completed: %s\n", bad ? "failed" : "OK");

	return bad;
}
