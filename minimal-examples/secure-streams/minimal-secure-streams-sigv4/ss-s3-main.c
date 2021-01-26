/*
 * S3 Put Object via Secure Streams minimal sigv4 example
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *			   Amit Pachore <apachor@amazon.com>
 *                         securestreams-dev@amazon.com
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "ss-s3-put.h"

int interrupted, bad = 1;
static lws_state_notify_link_t nl;
extern const lws_ss_info_t s3_ssi;

#if !defined(LWS_SS_USE_SSPC)

static const char * const default_ss_policy =
	"{"
	  "\"release\":"			"\"01234567\","
	  "\"product\":"			"\"myproduct\","
	  "\"schema-version\":"			"1,"

	  "\"retry\": ["	/* named backoff / retry strategies */
		"{\"default\": {"
			"\"backoff\": ["	 "100,"
						 "200,"
						 "300,"
						 "500,"
						"1000"
				"],"
			"\"conceal\":"		"5,"
			"\"jitterpc\":"		"20,"
			"\"svalidping\":"	"30,"
			"\"svalidhup\":"	"35"
		"}}"
	  "],"
	  "\"certs\": [" /* named individual certificates in BASE64 DER */
		"{\"baltimore_cybertrust_root\": \"" /* LE X3 signed by ISRG X1 root */
			"MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ"
			"RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD"
			"VQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoX"
			"DTI1MDUxMjIzNTkwMFowWjELMAkGA1UEBhMCSUUxEjAQBgNVBAoTCUJhbHRpbW9y"
			"ZTETMBEGA1UECxMKQ3liZXJUcnVzdDEiMCAGA1UEAxMZQmFsdGltb3JlIEN5YmVy"
			"VHJ1c3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMEuyKr"
			"mD1X6CZymrV51Cni4eiVgLGw41uOKymaZN+hXe2wCQVt2yguzmKiYv60iNoS6zjr"
			"IZ3AQSsBUnuId9Mcj8e6uYi1agnnc+gRQKfRzMpijS3ljwumUNKoUMMo6vWrJYeK"
			"mpYcqWe4PwzV9/lSEy/CG9VwcPCPwBLKBsua4dnKM3p31vjsufFoREJIE9LAwqSu"
			"XmD+tqYF/LTdB1kC1FkYmGP1pWPgkAx9XbIGevOF6uvUA65ehD5f/xXtabz5OTZy"
			"dc93Uk3zyZAsuT3lySNTPx8kmCFcB5kpvcY67Oduhjprl3RjM71oGDHweI12v/ye"
			"jl0qhqdNkNwnGjkCAwEAAaNFMEMwHQYDVR0OBBYEFOWdWTCCR1jMrPoIVDaGezq1"
			"BE3wMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3"
			"DQEBBQUAA4IBAQCFDF2O5G9RaEIFoN27TyclhAO992T9Ldcw46QQF+vaKSm2eT92"
			"9hkTI7gQCvlYpNRhcL0EYWoSihfVCr3FvDB81ukMJY2GQE/szKN+OMY3EU/t3Wgx"
			"jkzSswF07r51XgdIGn9w/xZchMB5hbgF/X++ZRGjD8ACtPhSNzkE1akxehi/oCr0"
			"Epn3o0WC4zxe9Z2etciefC7IpJ5OCBRLbf1wbWsaY71k5h+3zvDyny67G7fyUIhz"
			"ksLi4xaNmjICq44Y3ekQEe5+NauQrz4wlHrQMz2nZQ/1/I6eYs9HRCwBXbsdtTLS"
			"R9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp"
		"\"}"
	  "],"
	  "\"trust_stores\": [" /* named cert chains */
		"{"
			"\"name\": \"s3-root-cert\","
			"\"stack\": ["
						"\"baltimore_cybertrust_root\""
			"]"
		"}"
	  "],"
	  "\"auth\": [" /* named cert chains */
	       "{"
			"\"name\": \"sigv4_br\","
			"\"type\": \"sigv4\","
			"\"blob\": 0"
		"}"

	  "],"
	  "\"s\": ["
		"{\"s3PutObj\": {"
			"\"endpoint\":"	"\"${s3bucket}.s3.amazonaws.com\","
			"\"port\":"	"443,"
			"\"protocol\":"	"\"h1\","
			"\"http_method\":" "\"PUT\","
			"\"http_url\":" "\"${s3Obj}\","
			"\"http_no_content_length\": false,"
			"\"tls\":" "true,"
			"\"tls_trust_store\":"	"\"s3-root-cert\","
			"\"opportunistic\":" "true,"
			"\"retry\":" "\"default\","
			"\"use_auth\":" "\"sigv4_br\","
			"\"aws_region\":" "\"region\","
			"\"aws_service\":" "\"service\","
			"\"metadata\": ["
				"{\"region\": \"\"},"
				"{\"service\": \"\"},"
				"{\"s3bucket\": \"\"},"
				"{\"s3Obj\": \"\"},"
				"{\"ctype\": \"content-type:\"},"
                                "{\"xcsha256\": \"x-amz-content-sha256:\"},"
                                "{\"xdate\": \"x-amz-date:\"},"
				"{\"xacl\": \"x-amz-acl:\"}"
			"]"
		"}}"
	   "]"
	"}"
;

static char *aws_keyid, *aws_key;
#endif

static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		    int current, int target)
{
	struct lws_context *context = lws_system_context_from_system_mgr(mgr);
	struct lws_ss_handle *h;

	switch (target) {
	case LWS_SYSTATE_REGISTERED:
		break;

	case LWS_SYSTATE_OPERATIONAL:
		if (current != LWS_SYSTATE_OPERATIONAL)
			break;

#if !defined(LWS_SS_USE_SSPC)
		if (lws_aws_filesystem_credentials_helper(
					  "~/.aws/credentials",
					  "aws_access_key_id",
					  "aws_secret_access_key",
					  &aws_keyid, &aws_key))
			return -1;
		lws_ss_sigv4_set_aws_key(context, 0, aws_keyid, aws_key);
#endif

		if (lws_ss_create(context, 0, &s3_ssi, NULL, &h,
				  NULL, NULL)) {
			lwsl_err("%s: failed to create secure stream\n",
				 __func__);

			return -1;
		}
		break;
	}

	return 0;
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
	int logs = LLL_USER | LLL_ERR | LLL_WARN /* | LLL_NOTICE */ ;
	struct lws_context_creation_info info;
	struct lws_context *context;
	int n = 0;

	signal(SIGINT, sigint_handler);
	lws_set_log_level(logs, NULL);

	memset(&info, 0, sizeof info);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS minimal secure streams sigv4 \n");

	info.fd_limit_per_thread = 1 + 6 + 1;
	info.port = CONTEXT_PORT_NO_LISTEN;

#if defined(LWS_SS_USE_SSPC)
	info.protocols = lws_sspc_protocols;
	{
		const char *p;

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
	}
#else
	info.pss_policies_json = default_ss_policy;

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
#endif

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

	lws_system_blob_heap_append(lws_system_get_blob(context,
				    LWS_SYSBLOB_TYPE_DEVICE_TYPE, 0),
				    (const uint8_t *)"beerfountain", 12);

	/* the event loop */

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);

#if !defined(LWS_SS_USE_SSPC)
	if (aws_key)
		free(aws_key);
	if (aws_keyid)
		free(aws_keyid);
#endif

	lwsl_user("Completed: %s\n", bad ? "failed" : "OK");

	return bad;
}
