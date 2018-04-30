/*
 * lws-minimal-http-client-multi
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates the a minimal http client using lws, which makes
 * 8 downloads simultaneously from warmcat.com.
 *
 * Currently that takes the form of 8 individual simultaneous tcp and
 * tls connections, which happen concurrently.  Notice that the ordering
 * of the returned payload may be intermingled for the various connections.
 *
 * By default the connections happen all together at the beginning and operate
 * concurrently, which is fast.  However this is resource-intenstive, there are
 * 8 tcp connections, 8 tls tunnels on both the client and server.  You can
 * instead opt to have the connections happen one after the other inside a
 * single tcp connection and tls tunnel, using HTTP/1.1 pipelining.  To be
 * eligible to be pipelined on another existing connection to the same server,
 * the client connection must have the LCCSCF_PIPELINE flag on its
 * info.ssl_connection member (this is independent of whether the connection
 * is in ssl mode or not).
 *
 * HTTP/1.0: Pipelining only possible if Keep-Alive: yes sent by server
 * HTTP/1.1: always possible... serializes requests
 * HTTP/2:   always possible... all requests sent as individual streams in parallel
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <time.h>

#define COUNT 8

struct user {
	int index;
};

static int interrupted, completed, failed;
static struct lws *client_wsi[COUNT];
static struct user user[COUNT];

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	struct user *u = (struct user *)user;

	switch (reason) {

	/* because we are protocols[0] ... */
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		client_wsi[u->index] = NULL;
		failed++;
		if (++completed == COUNT) {
			lwsl_err("Done: failed: %d\n", failed);
			interrupted = 1;
		}
		break;

	/* chunks of chunked content, with header removed */
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		lwsl_user("RECEIVE_CLIENT_HTTP_READ: conn %d: read %d\n",
			u->index, (int)len);
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
		lwsl_user("LWS_CALLBACK_COMPLETED_CLIENT_HTTP %p: idx %d\n",
			  wsi, u->index);
		client_wsi[u->index] = NULL;
		if (++completed == COUNT) {
			if (!failed)
				lwsl_user("Done: all OK\n");
			else
				lwsl_err("Done: failed: %d\n", failed);
			interrupted = 1;
			/* so we exit immediately */
			lws_cancel_service(lws_get_context(wsi));
		}
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (u && client_wsi[u->index]) {
			/*
			 * If it completed normally, it will have been set to
			 * NULL then already.  So we are dealing with an
			 * abnormal, failing, close
			 */
			client_wsi[u->index] = NULL;
			failed++;
			if (++completed == COUNT) {
				lwsl_err("Done: failed: %d\n", failed);
				interrupted = 1;
			}
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{ "http", callback_http, 0, 0, },
	{ NULL, NULL, 0, 0 }
};

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

unsigned long long us(void)
{
	struct timeval t;

	gettimeofday(&t, NULL);

	return (t.tv_sec * 1000000ull) + t.tv_usec;
}

static void
lws_try_client_connection(struct lws_client_connect_info *i, int m)
{
	i->path = "/";

	i->pwsi = &client_wsi[m];
	user[m].index = m;
	i->userdata = &user[m];

	if (!lws_client_connect_via_info(i)) {
		failed++;
		if (++completed == COUNT) {
			lwsl_user("Done: failed: %d\n", failed);
			interrupted = 1;
		}
	} else
		lwsl_user("started connection %p: idx %d\n", client_wsi[m], m);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	struct lws_context *context;
	unsigned long long start, next;
	const char *p;
	int n = 0, m, staggered = 0, logs =
		LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
		/* for LLL_ verbosity above NOTICE to be built into lws,
		 * lws must have been configured and built with
		 * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE */
		/* | LLL_INFO */ /* | LLL_PARSER */ /* | LLL_HEADER */
		/* | LLL_EXT */ /* | LLL_CLIENT */ /* | LLL_LATENCY */
		/* | LLL_DEBUG */;

	signal(SIGINT, sigint_handler);

	memset(&i, 0, sizeof i); /* otherwise uninitialized garbage */

	staggered = !!lws_cmdline_option(argc, argv, "-s");
	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS minimal http client [-s (staggered)] [-p (pipeline)]\n");
	lwsl_user("	[--h1 (http/1 only)] [-l (localhost)] [-d <logs>]\n");

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

	i.context = context;
	i.ssl_connection = LCCSCF_USE_SSL;

	/* enables h1 or h2 connection sharing */
	if (lws_cmdline_option(argc, argv, "-p"))
		i.ssl_connection |= LCCSCF_PIPELINE;

	/* force h1 even if h2 available */
	if (lws_cmdline_option(argc, argv, "--h1"))
		i.alpn = "http/1.1";

	if (lws_cmdline_option(argc, argv, "-l")) {
		i.port = 7681;
		i.address = "localhost";
		i.ssl_connection |= LCCSCF_ALLOW_SELFSIGNED;
	} else {
		i.port = 443;
		i.address = "warmcat.com";
	}

	if ((p = lws_cmdline_option(argc, argv, "--port")))
		i.port = atoi(p);

	i.host = i.address;
	i.origin = i.address;
	i.method = "GET";
	i.protocol = protocols[0].name;

	if (!staggered)
		/*
		 * just pile on all the connections at once, testing the
		 * pipeline queuing before the first is connected
		 */
		for (m = 0; m < (int)LWS_ARRAY_SIZE(client_wsi); m++)
			lws_try_client_connection(&i, m);

	next = start = us();
	m = 0;
	while (n >= 0 && !interrupted) {

		if (staggered) {
			/*
			 * open the connections at 100ms intervals, with the
			 * last one being after 1s, testing both queuing, and
			 * direct H2 stream addition stability
			 */
			if (us() > next && m < (int)LWS_ARRAY_SIZE(client_wsi)) {

				lws_try_client_connection(&i, m++);

				if (m == (int)LWS_ARRAY_SIZE(client_wsi) - 1)
					next = us() + 1000000;
				else
					next = us() + 300000;
			}
		}

		n = lws_service(context, 100);
	}

	lwsl_user("Duration: %lldms\n", (us() - start) / 1000);
	lws_context_destroy(context);

	lwsl_user("Exiting with %d\n", failed || completed != COUNT);

	return failed || completed != COUNT;
}
