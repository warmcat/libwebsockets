/*
 * lws-minimal-secure-streams-custom-proxy-transport
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 *
 * This is a version of minimal-secure-streams-proxy that uses a custom
 * transport.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#include "private.h"

static int test_result = 1, port = 0 /* unix domain socket */;
static const char *ibind = "/dev/ttyUSB0";
static lws_state_notify_link_t nl;
static struct lws_context *cx;
int interrupted;

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
			"\"http_url\":"		"\"policy/minimal-proxy-v4.2-v2.json\","
			"\"tls\":"		"true,"
			"\"opportunistic\":"	"true,"
			"\"retry\":"		"\"default\","
			"\"tls_trust_store\":"	"\"le_via_dst\""
		"}}"
	"}"
;

static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		    int current, int target)
{
	struct lws_context *context = lws_system_context_from_system_mgr(mgr);

	switch (target) {
	case LWS_SYSTATE_OPERATIONAL:
		if (current == LWS_SYSTATE_OPERATIONAL) {
			/*
			 * At this point we have DHCP, ntp, system auth token
			 * and we can reasonably create the proxy
			 */
			if (lws_ss_proxy_create(context, ibind, port)) {
				lwsl_err("%s: failed to create ss proxy\n",
						__func__);
				return -1;
			}
			test_result = 0;
		}
		break;
	}

	return 0;
}

static lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};

const struct lws_protocols *ppcols[] = {
	&protocol_sspc_serial_transport,
	NULL
};

lws_transport_info_t info_serial = {
	.ping_interval_us		= LWS_US_PER_SEC * 10,
	.pong_grace_us			= LWS_US_PER_SEC * 2,
	.flags				= LWSTMINFO_SERVER,
}, info_mux = { /* onward transport for mux is serial */
	.ping_interval_us		= LWS_US_PER_SEC * 10,
	.pong_grace_us			= LWS_US_PER_SEC * 2,
	.txp_ppath = {
		.ops_onw		= &lws_transport_ops_serial,
		.ops_in			= &lws_transport_mux_proxy_ops,
	},
	.onward_txp_info		= &info_serial,
	.flags				= LWSTMINFO_SERVER,
};

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;

	lws_context_info_defaults(&info, default_ss_policy);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	signal(SIGINT, sigint_handler);

	/* connect to ssproxy via UDS by default, else via tcp with this port */
	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);

	/* UDS "proxy.ss.lws" in abstract namespace, else this socket path;
	 * when -p given this can specify the network interface to bind to */
	if ((p = lws_cmdline_option(argc, argv, "-i")))
		ibind = p;

	lwsl_user("LWS secure streams Proxy [-d<verb>]\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_H2_JUST_FIX_WINDOW_UPDATE_OVERFLOW |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.fd_limit_per_thread	= 1 + 26 + 1;
	info.pprotocols			= ppcols;

	/* integrate us with lws system state management when context created */
	nl.name				= "app";
	nl.notify_cb			= app_system_state_nf;
	info.register_notifier_list	= app_notifier_list;

	info.pt_serv_buf_size		= (unsigned int)((6144 * 2) + 2048);
	info.max_http_header_data	= (unsigned short)(6144 + 2048);

	info.txp_ops_ssproxy		= &lws_transport_mux_proxy_ops;
	info.txp_ssproxy_info		= &info_mux;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	lws_context_default_loop_run_destroy(cx);

	return lws_cmdline_passfail(argc, argv, test_result);
}
