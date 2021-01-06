/*
 * lws-minimal-secure-streams-proxy
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 *
 * This is the proxy part for examples built to use it to connect to... it has
 * the policy and the core SS function, but it doesn't contain any of the user
 * code "business logic"... that's in the clients.
 *
 * The proxy side has the policy and performs the onward connection proxying
 * fulfilment.  The clients state the streamtype name they want and ask for the
 * client to do the connection part.
 *
 * Rideshare information is being parsed out at the proxy side; the SSS RX part
 * also brings with it rideshare names.
 *
 * Metadata is passed back over SSS from the client in the TX messages for the
 * proxy to use per the policy.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#if defined(__APPLE__) || defined(__linux__)
#include <execinfo.h>
#include <assert.h>
#endif

static int interrupted, bad = 1, port = 0 /* unix domain socket */;
static const char *ibind = NULL; /* default to unix domain skt "proxy.ss.lws" */
static lws_state_notify_link_t nl;

/*
 * We just define enough policy so it can fetch the latest one securely
 */

static const char * const default_ss_policy =
	"{"
	  "\"release\":"			"\"01234567\","
	  "\"product\":"			"\"myproduct\","
	  "\"schema-version\":"			"1,"
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
		"{\"dst_root_x3\": \""
	"MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/"
	"MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT"
	"DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow"
	"PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD"
	"Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB"
	"AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O"
	"rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq"
	"OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b"
	"xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw"
	"7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD"
	"aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV"
	"HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG"
	"SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69"
	"ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr"
	"AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz"
	"R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5"
	"JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo"
	"Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ"
		"\"}"
	  "],"
	  "\"trust_stores\": [" /* named cert chains */
		"{"
			"\"name\": \"le_via_dst\","
			"\"stack\": ["
				"\"dst_root_x3\""
			"]"
		"}"
	  "],"
	  "\"s\": [{"
		"\"captive_portal_detect\": {"
			"\"endpoint\": \"connectivitycheck.android.com\","
			"\"http_url\": \"generate_204\","
			"\"port\": 80,"
			"\"protocol\": \"h1\","
			"\"http_method\": \"GET\","
			"\"opportunistic\": true,"
			"\"http_expect\": 204,"
			"\"http_fail_redirect\": true"
		"},"
		"\"fetch_policy\": {"
			"\"endpoint\":"		"\"warmcat.com\","
			"\"port\":"		"443,"
			"\"protocol\":"		"\"h1\","
			"\"http_method\":"	"\"GET\","
			"\"http_url\":"		"\"policy/minimal-proxy-v4.2.json\","
			"\"tls\":"		"true,"
			"\"opportunistic\":"	"true,"
			"\"retry\":"		"\"default\","
			"\"tls_trust_store\":"	"\"le_via_dst\""
		"}}"
	"}"
;

static const char *canned_root_token_payload =
	"grant_type=refresh_token"
	"&refresh_token=Atzr|IwEBIJedGXjDqsU_vMxykqOMg"
	"SHfYe3CPcedueWEMWSDMaDnEmiW8RlR1Kns7Cb4B-TOSnqp7ifVsY4BMY2B8tpHfO39XP"
	"zfu9HapGjTR458IyHX44FE71pWJkGZ79uVBpljP4sazJuk8XS3Oe_yLnm_DIO6fU1nU3Y"
	"0flYmsOiOAQE_gRk_pdlmEtHnpMA-9rLw3mkY5L89Ty9kUygBsiFaYatouROhbsTn8-jW"
	"k1zZLUDpT6ICtBXSnrCIg0pUbZevPFhTwdXd6eX-u4rq0W-XaDvPWFO7au-iPb4Zk5eZE"
	"iX6sissYrtNmuEXc2uHu7MnQO1hHCaTdIO2CANVumf-PHSD8xseamyh04sLV5JgFzY45S"
	"KvKMajiUZuLkMokOx86rjC2Hdkx5DO7G-dbG1ufBDG-N79pFMSs7Ck5pc283IdLoJkCQc"
	"AGvTX8o8I29QqkcGou-9TKhOJmpX8As94T61ok0UqqEKPJ7RhfQHHYdCtsdwxgvfVr9qI"
	"xL_hDCcTho8opCVX-6QhJHl6SQFlTw13"
	"&client_id="
		"amzn1.application-oa2-client.4823334c434b4190a2b5a42c07938a2d";

#if defined(LWS_WITH_SECURE_STREAMS_AUTH_SIGV4)
static char *aws_keyid = NULL,
	    *aws_key = NULL;
#endif

static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		    int current, int target)
{
	struct lws_context *context = lws_system_context_from_system_mgr(mgr);
	lws_system_blob_t *ab = lws_system_get_blob(context,
				LWS_SYSBLOB_TYPE_AUTH, 1 /* AUTH_IDX_ROOT */);
	size_t size;

	/*
	 * For the things we care about, let's notice if we are trying to get
	 * past them when we haven't solved them yet, and make the system
	 * state wait while we trigger the dependent action.
	 */
	switch (target) {
	case LWS_SYSTATE_REGISTERED:
		size = lws_system_blob_get_size(ab);
		if (size)
			break;

		/* let's register our canned root token so auth can use it */
		lws_system_blob_direct_set(ab,
				(const uint8_t *)canned_root_token_payload,
				strlen(canned_root_token_payload));
		break;
	case LWS_SYSTATE_OPERATIONAL:
		if (current == LWS_SYSTATE_OPERATIONAL) {
#if defined(LWS_WITH_SECURE_STREAMS_AUTH_SIGV4)

			if (lws_aws_filesystem_credentials_helper(
						  "~/.aws/credentials",
						  "aws_access_key_id",
						  "aws_secret_access_key",
						  &aws_keyid, &aws_key))
				return -1;

			lws_ss_sigv4_set_aws_key(context, 0, aws_keyid, aws_key);
#endif
			/*
			 * At this point we have DHCP, ntp, system auth token
			 * and we can reasonably create the proxy
			 */
			if (lws_ss_proxy_create(context, ibind, port)) {
				lwsl_err("%s: failed to create ss proxy\n",
						__func__);
				return -1;
			}
		}
		break;
	case LWS_SYSTATE_POLICY_INVALID:
		/*
		 * This is a NOP since we used direct set... but in a real
		 * system this could easily change to be done on the heap, then
		 * this would be important
		 */
		lws_system_blob_destroy(lws_system_get_blob(context,
					LWS_SYSBLOB_TYPE_AUTH,
					1 /* AUTH_IDX_ROOT */));
		break;
	}

	return 0;
}

static lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};

#if defined(LWS_WITH_SYS_METRICS)

static int
my_metric_report(lws_metric_pub_t *mp)
{
	char buf[128];

	if (lws_metrics_format(mp, buf, sizeof(buf)))
		lwsl_user("%s: %s\n", __func__, buf);

	return 0;
}

static const lws_system_ops_t system_ops = {
	.metric_report = my_metric_report,
};

#endif

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

static void
assert_bt(int sig)
{
#if defined(__APPLE__) || defined(__linux__)
	  void *array[20];
	  char **strings;
	  int size, i;

	  size = backtrace (array, 10);
	  strings = backtrace_symbols (array, size);
	  if (!strings)
		  return;

	    for (i = 0; i < size; i++)
	      printf("%s\n", strings[i]);

	  free (strings);
#endif
}

int main(int argc, const char **argv)
{
	int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct lws_context_creation_info info;
	struct lws_context *context;
	const char *p;

	signal(SIGINT, sigint_handler);
	signal(SIGABRT, assert_bt);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	/* connect to ssproxy via UDS by default, else via tcp with this port */
	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);

	/* UDS "proxy.ss.lws" in abstract namespace, else this socket path;
	 * when -p given this can specify the network interface to bind to */
	if ((p = lws_cmdline_option(argc, argv, "-i")))
		ibind = p;

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS secure streams Proxy [-d<verb>]\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_H2_JUST_FIX_WINDOW_UPDATE_OVERFLOW |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.fd_limit_per_thread = 1 + 32 + 1;
	info.pss_policies_json = default_ss_policy;
	info.port = CONTEXT_PORT_NO_LISTEN;

	/* integrate us with lws system state management when context created */
	nl.name = "app";
	nl.notify_cb = app_system_state_nf;
	info.register_notifier_list = app_notifier_list;

#if defined(LWS_WITH_SYS_METRICS)
	info.system_ops = &system_ops;
	info.metrics_prefix = "ssproxy";
#endif

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the event loop */

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	bad = 0;

#if defined(LWS_WITH_SECURE_STREAMS_AUTH_SIGV4)
	if (aws_keyid)
		free(aws_keyid);
	if (aws_key)
		free(aws_key);
#endif

	lws_context_destroy(context);
	lwsl_user("Completed: %s\n", bad ? "failed" : "OK");

	return bad;
}
