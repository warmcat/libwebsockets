/*
 * lws-minimal-http-client-multi
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
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

struct cliuser {
	int index;
};

static int completed, failed, numbered, stagger_idx, posting, count = COUNT;
static lws_sorted_usec_list_t sul_stagger;
static struct lws_client_connect_info i;
static struct lws *client_wsi[COUNT];
static char urlpath[64], intr;
static struct lws_context *context;

/* we only need this for tracking POST emit state */

struct pss {
	char body_part;
};

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 1024], *start = &buf[LWS_PRE], *p = start,
	     *end = &buf[sizeof(buf) - LWS_PRE - 1];
	int n, idx = (int)(intptr_t)lws_get_opaque_user_data(wsi);
	struct pss *pss = (struct pss *)user;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		lwsl_user("LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP: idx: %d, resp %u\n",
				idx, lws_http_client_http_response(wsi));
		break;

	/* because we are protocols[0] ... */
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		client_wsi[idx] = NULL;
		failed++;
		goto finished;

	/* chunks of chunked content, with header removed */
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		lwsl_user("RECEIVE_CLIENT_HTTP_READ: conn %d: read %d\n", idx, (int)len);
		lwsl_hexdump_info(in, len);
		return 0; /* don't passthru */

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		/*
		 * Tell lws we are going to send the body next...
		 */
		if (posting && !lws_http_is_redirected_to_get(wsi)) {
			lwsl_user("%s: doing POST flow\n", __func__);
			lws_client_http_body_pending(wsi, 1);
			lws_callback_on_writable(wsi);
		} else
			lwsl_user("%s: doing GET flow\n", __func__);
		break;

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
			  wsi, idx);
		client_wsi[idx] = NULL;
		goto finished;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		lwsl_info("%s: closed: %p\n", __func__, client_wsi[idx]);
		if (client_wsi[idx]) {
			/*
			 * If it completed normally, it will have been set to
			 * NULL then already.  So we are dealing with an
			 * abnormal, failing, close
			 */
			client_wsi[idx] = NULL;
			failed++;
			goto finished;
		}
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (!posting)
			break;
		if (lws_http_is_redirected_to_get(wsi))
			break;
		lwsl_info("LWS_CALLBACK_CLIENT_HTTP_WRITEABLE: %p, idx %d,"
				" part %d\n", wsi, idx, pss->body_part);

		n = LWS_WRITE_HTTP;

		/*
		 * For a small body like this, we could prepare it in memory and
		 * send it all at once.  But to show how to handle, eg,
		 * arbitrary-sized file payloads, or huge form-data fields, the
		 * sending is done in multiple passes through the event loop.
		 */

		switch (pss->body_part++) {
		case 0:
			if (lws_client_http_multipart(wsi, "text", NULL, NULL,
						      &p, end))
				return -1;
			/* notice every usage of the boundary starts with -- */
			p += lws_snprintf(p, end - p, "my text field\xd\xa");
			break;
		case 1:
			if (lws_client_http_multipart(wsi, "file", "myfile.txt",
						      "text/plain", &p, end))
				return -1;
			p += lws_snprintf(p, end - p,
					"This is the contents of the "
					"uploaded file.\xd\xa"
					"\xd\xa");
			break;
		case 2:
			if (lws_client_http_multipart(wsi, NULL, NULL, NULL,
						      &p, end))
				return -1;
			lws_client_http_body_pending(wsi, 0);
			 /* necessary to support H2, it means we will write no
			  * more on this stream */
			n = LWS_WRITE_HTTP_FINAL;
			break;

		default:
			/*
			 * We can get extra callbacks here, if nothing to do,
			 * then do nothing.
			 */
			return 0;
		}

		if (lws_write(wsi, (uint8_t *)start, lws_ptr_diff(p, start), n)
				!= lws_ptr_diff(p, start))
			return 1;

		if (n != LWS_WRITE_HTTP_FINAL)
			lws_callback_on_writable(wsi);

		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);

finished:
	if (++completed == count) {
		if (!failed)
			lwsl_user("Done: all OK\n");
		else
			lwsl_err("Done: failed: %d\n", failed);
		intr = 1;
		/*
		 * This is how we can exit the event loop even when it's an
		 * event library backing it... it will start and stage the
		 * destroy to happen after we exited this service for each pt
		 */
		lws_context_destroy(lws_get_context(wsi));
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "http", callback_http, sizeof(struct pss), 0, },
	{ NULL, NULL, 0, 0 }
};

static void
signal_cb(void *handle, int signum)
{
	switch (signum) {
	case SIGTERM:
	case SIGINT:
		break;
	default:
		lwsl_err("%s: signal %d\n", __func__, signum);
		break;
	}
	lws_context_destroy(context);
}

static void
sigint_handler(int sig)
{
	signal_cb(NULL, sig);
}

#if defined(WIN32)
int gettimeofday(struct timeval * tp, struct timezone * tzp)
{
    // Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
    // This magic number is the number of 100 nanosecond intervals since January 1, 1601 (UTC)
    // until 00:00:00 January 1, 1970 
    static const uint64_t EPOCH = ((uint64_t) 116444736000000000ULL);

    SYSTEMTIME  system_time;
    FILETIME    file_time;
    uint64_t    time;

    GetSystemTime( &system_time );
    SystemTimeToFileTime( &system_time, &file_time );
    time =  ((uint64_t)file_time.dwLowDateTime )      ;
    time += ((uint64_t)file_time.dwHighDateTime) << 32;

    tp->tv_sec  = (long) ((time - EPOCH) / 10000000L);
    tp->tv_usec = (long) (system_time.wMilliseconds * 1000);
    return 0;
}
#endif

unsigned long long us(void)
{
	struct timeval t;

	gettimeofday(&t, NULL);

	return (t.tv_sec * 1000000ull) + t.tv_usec;
}

static void
lws_try_client_connection(struct lws_client_connect_info *i, int m)
{
	char path[128];

	if (numbered) {
		lws_snprintf(path, sizeof(path), "/%d.png", m + 1);
		i->path = path;
	} else
		i->path = urlpath;

	i->pwsi = &client_wsi[m];
	i->opaque_user_data = (void *)(intptr_t)m;

	if (!lws_client_connect_via_info(i)) {
		failed++;
		if (++completed == count) {
			lwsl_user("Done: failed: %d\n", failed);
			lws_context_destroy(context);
		}
	} else
		lwsl_user("started connection %p: idx %d (%s)\n",
			  client_wsi[m], m, i->path);
}

static void
stagger_cb(lws_sorted_usec_list_t *sul)
{
	lws_usec_t next;

	/*
	 * open the connections at 100ms intervals, with the
	 * last one being after 1s, testing both queuing, and
	 * direct H2 stream addition stability
	 */
	lws_try_client_connection(&i, stagger_idx++);

	if (stagger_idx == count)
		return;

	next = 300 * LWS_US_PER_MS;
	if (stagger_idx == count - 1)
		next += 700 * LWS_US_PER_MS;

	lws_sul_schedule(context, 0, &sul_stagger, stagger_cb, next);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	unsigned long long start;
	int m, staggered = 0;
	const char *p;

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	memset(&i, 0, sizeof i); /* otherwise uninitialized garbage */

	lws_cmdline_option_handle_builtin(argc, argv, &info);

	info.signal_cb = signal_cb;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	if (lws_cmdline_option(argc, argv, "--uv"))
		info.options |= LWS_SERVER_OPTION_LIBUV;
	else
		if (lws_cmdline_option(argc, argv, "--event"))
			info.options |= LWS_SERVER_OPTION_LIBEVENT;
		else
			if (lws_cmdline_option(argc, argv, "--ev"))
				info.options |= LWS_SERVER_OPTION_LIBEV;
			else
				if (lws_cmdline_option(argc, argv, "--glib"))
					info.options |= LWS_SERVER_OPTION_GLIB;
				else
					signal(SIGINT, sigint_handler);

	staggered = !!lws_cmdline_option(argc, argv, "-s");

	lwsl_user("LWS minimal http client [-s (staggered)] [-p (pipeline)]\n");
	lwsl_user("   [--h1 (http/1 only)] [-l (localhost)] [-d <logs>]\n");
	lwsl_user("   [-n (numbered)] [--post]\n");

	info.port = CONTEXT_PORT_NO_LISTEN; /* we do not run any server */
	info.protocols = protocols;
	/*
	 * since we know this lws context is only ever going to be used with
	 * COUNT client wsis / fds / sockets at a time, let lws know it doesn't
	 * have to use the default allocations for fd tables up to ulimit -n.
	 * It will just allocate for 1 internal and COUNT + 1 (allowing for h2
	 * network wsi) that we will use.
	 */
	info.fd_limit_per_thread = 1 + COUNT + 1;

#if defined(LWS_WITH_MBEDTLS) || defined(USE_WOLFSSL)
	/*
	 * OpenSSL uses the system trust store.  mbedTLS has to be told which
	 * CA to trust explicitly.
	 */
	info.client_ssl_ca_filepath = "./warmcat.com.cer";
#endif

	if ((p = lws_cmdline_option(argc, argv, "--limit")))
		info.simultaneous_ssl_restriction = atoi(p);

#if defined(LWS_WITH_DETAILED_LATENCY)
	info.detailed_latency_cb = lws_det_lat_plot_cb;
	info.detailed_latency_filepath = "/tmp/lws-latency-results";
#endif

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	i.context = context;
	i.ssl_connection = LCCSCF_USE_SSL |
			   LCCSCF_H2_QUIRK_OVERFLOWS_TXCR |
			   LCCSCF_H2_QUIRK_NGHTTP2_END_STREAM;

	if (lws_cmdline_option(argc, argv, "--post")) {
		posting = 1;
		i.method = "POST";
		i.ssl_connection |= LCCSCF_HTTP_MULTIPART_MIME;
	} else
		i.method = "GET";

	/* enables h1 or h2 connection sharing */
	if (lws_cmdline_option(argc, argv, "-p"))
		i.ssl_connection |= LCCSCF_PIPELINE;

	/* force h1 even if h2 available */
	if (lws_cmdline_option(argc, argv, "--h1"))
		i.alpn = "http/1.1";

	strcpy(urlpath, "/");

	if (lws_cmdline_option(argc, argv, "-l")) {
		i.port = 7681;
		i.address = "localhost";
		i.ssl_connection |= LCCSCF_ALLOW_SELFSIGNED;
		if (posting)
			strcpy(urlpath, "/formtest");
	} else {
		i.port = 443;
		i.address = "libwebsockets.org";
		if (posting)
			strcpy(urlpath, "/testserver/formtest");
	}

	if (lws_cmdline_option(argc, argv, "--no-tls"))
		i.ssl_connection &= ~(LCCSCF_USE_SSL);

	if (lws_cmdline_option(argc, argv, "-n"))
		numbered = 1;

	if ((p = lws_cmdline_option(argc, argv, "--server")))
		i.address = p;

	if ((p = lws_cmdline_option(argc, argv, "--port")))
		i.port = atoi(p);

	if ((p = lws_cmdline_option(argc, argv, "--path")))
		lws_strncpy(urlpath, p, sizeof(urlpath));

	if ((p = lws_cmdline_option(argc, argv, "-c")))
		if (atoi(p) <= COUNT && atoi(p))
			count = atoi(p);

	i.host = i.address;
	i.origin = i.address;
	i.protocol = protocols[0].name;

	if (!staggered)
		/*
		 * just pile on all the connections at once, testing the
		 * pipeline queuing before the first is connected
		 */
		for (m = 0; m < count; m++)
			lws_try_client_connection(&i, m);
	else
		/*
		 * delay the connections slightly
		 */
		lws_sul_schedule(context, 0, &sul_stagger, stagger_cb,
				 100 * LWS_US_PER_MS);

	start = us();
	while (!intr && !lws_service(context, 0))
		;

	lwsl_user("Duration: %lldms\n", (us() - start) / 1000);
	lws_context_destroy(context);

	lwsl_user("Exiting with %d\n", failed || completed != count);

	return failed || completed != count;
}
