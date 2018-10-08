/*
 * lws-minimal-http-client hugeurl
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates the a minimal http client using lws.
 *
 * It visits https://warmcat.com/?fakeparam=<2KB> and receives the html
 * page there.  You can dump the page data by changing the #if 0 below.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int interrupted, bad = 1, status;
static struct lws *client_wsi;

static const char * const uri =
	"/?fakeparam="
	"00000000000000000000000000000000000000000000000000"
	"00000000000000000000000000000000000000000000000000"
	"00000000000000000000000000000000000000000000000000"
	"00000000000000000000000000000000000000000000000000"
	"00000000000000000000000000000000000000000000000000"
	"00000000000000000000000000000000000000000000000000"
	"00000000000000000000000000000000000000000000000000"
	"00000000000000000000000000000000000000000000000000"
	"00000000000000000000000000000000000000000000000000"
	"00000000000000000000000000000000000000000000000000" /* 500 */
	"11111111111111111111111111111111111111111111111111"
	"11111111111111111111111111111111111111111111111111"
	"11111111111111111111111111111111111111111111111111"
	"11111111111111111111111111111111111111111111111111"
	"11111111111111111111111111111111111111111111111111"
	"11111111111111111111111111111111111111111111111111"
	"11111111111111111111111111111111111111111111111111"
	"11111111111111111111111111111111111111111111111111"
	"11111111111111111111111111111111111111111111111111"
	"11111111111111111111111111111111111111111111111111" /* 1000 */
	"22222222222222222222222222222222222222222222222222"
	"22222222222222222222222222222222222222222222222222"
	"22222222222222222222222222222222222222222222222222"
	"22222222222222222222222222222222222222222222222222"
	"22222222222222222222222222222222222222222222222222"
	"22222222222222222222222222222222222222222222222222"
	"22222222222222222222222222222222222222222222222222"
	"22222222222222222222222222222222222222222222222222"
	"22222222222222222222222222222222222222222222222222"
	"22222222222222222222222222222222222222222222222222" /* 1500 */
	"33333333333333333333333333333333333333333333333333"
	"33333333333333333333333333333333333333333333333333"
	"33333333333333333333333333333333333333333333333333"
	"33333333333333333333333333333333333333333333333333"
	"33333333333333333333333333333333333333333333333333"
	"33333333333333333333333333333333333333333333333333"
	"33333333333333333333333333333333333333333333333333"
	"33333333333333333333333333333333333333333333333333"
	"33333333333333333333333333333333333333333333333333"
	"33333333333333333333333333333333333333333333333333" /* 2000 */
;

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	switch (reason) {

	/* because we are protocols[0] ... */
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		client_wsi = NULL;
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		status = lws_http_client_http_response(wsi);
		lwsl_user("Connected with server response: %d\n", status);
		break;

	/* chunks of chunked content, with header removed */
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		lwsl_user("RECEIVE_CLIENT_HTTP_READ: read %d\n", (int)len);
#if 0  /* enable to dump the html */
		{
			const char *p = in;

			while (len--)
				if (*p < 0x7f)
					putchar(*p++);
				else
					putchar('.');
		}
#endif
		return 0; /* don't passthru */

	/* uninterpreted http content */
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		{
			char buffer[1024 + LWS_PRE];
			char *px = buffer + LWS_PRE;
			int lenx = sizeof(buffer) - LWS_PRE;

			if (lws_http_client_read(wsi, &px, &lenx) < 0)
				return -1;
		}
		return 0; /* don't passthru */

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		client_wsi = NULL;
		bad = status != 200;
		lws_cancel_service(lws_get_context(wsi)); /* abort poll wait */
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		client_wsi = NULL;
		bad = status != 200;
		lws_cancel_service(lws_get_context(wsi)); /* abort poll wait */
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{
		"http",
		callback_http,
		0,
		0,
	},
	{ NULL, NULL, 0, 0 }
};

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	struct lws_context *context;
	const char *p;
	int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
			/* for LLL_ verbosity above NOTICE to be built into lws,
			 * lws must have been configured and built with
			 * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE */
			/* | LLL_INFO */ /* | LLL_PARSER */ /* | LLL_HEADER */
			/* | LLL_EXT */ /* | LLL_CLIENT */ /* | LLL_LATENCY */
			/* | LLL_DEBUG */;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	signal(SIGINT, sigint_handler);
	lws_set_log_level(logs, NULL);
	lwsl_user("LWS minimal http client hugeurl [-d <verbosity>] [-l] [--h1]\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.port = CONTEXT_PORT_NO_LISTEN; /* we do not run any server */
	info.protocols = protocols;

#if defined(LWS_WITH_MBEDTLS)
	/*
	 * OpenSSL uses the system trust store.  mbedTLS has to be told which
	 * CA to trust explicitly.
	 */
	info.client_ssl_ca_filepath = "./warmcat.com.cer";
#endif

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	memset(&i, 0, sizeof i); /* otherwise uninitialized garbage */
	i.context = context;
	i.ssl_connection = LCCSCF_USE_SSL;

	if (lws_cmdline_option(argc, argv, "-l")) {
		i.port = 7681;
		i.address = "localhost";
		i.ssl_connection |= LCCSCF_ALLOW_SELFSIGNED;
	} else {
		i.port = 443;
		i.address = "warmcat.com";
	}

	if (lws_cmdline_option(argc, argv, "--h1"))
		i.alpn = "http/1.1";

	i.path = uri;
	i.host = i.address;
	i.origin = i.address;
	i.method = "GET";
	i.protocol = protocols[0].name;
	i.pwsi = &client_wsi;

	lws_client_connect_via_info(&i);

	while (n >= 0 && client_wsi && !interrupted)
		n = lws_service(context, 1000);

	lws_context_destroy(context);
	lwsl_user("Completed: %s\n", bad? "failed": "OK");

	return bad;
}
