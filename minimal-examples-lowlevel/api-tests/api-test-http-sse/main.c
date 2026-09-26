/*
 * lws-api-test-http-sse
 *
 * An h1 SSE stream must live as long as its server and client want it to.
 *
 * lws_http_mark_sse() gives the stream's header table up, since an SSE
 * transaction never parses another request.  The h1 rx policy, which is
 * asked on every service and not only for rx, handed it a new one in
 * LRS_DOING_TRANSACTION, and attaching one arms the ah idle timeout: every
 * h1 SSE stream was closed timeout_secs_ah_idle (default 10s) after it
 * was first writeable.
 *
 * The server vhost here has a 1s ah idle timeout and sends an event when
 * the stream opens and another EVENT_GAP_SECS later.  The client must get
 * both on the one connection, and the server must still notice the client
 * hanging up once it has them.
 *
 * This file is made available under the Creative Commons CC0 1.0 Universal
 * Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

/* comfortably past the server's timeout_secs_ah_idle of 1s */
#define EVENT_GAP_SECS	3
#define N_EVENTS	2

static struct lws_context *context;
static lws_sorted_usec_list_t sul_timeout, sul_connect;
static int port = 7700, events_seen, srv_closed, done, fail;
static lws_usec_t t_first, t_last;

/* ------------------------------------------------------------- server */

struct pss_srv {
	int sent;
};

static int
callback_sse_srv(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t buf[LWS_PRE + 256], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	int n;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/event-stream",
						LWS_ILLEGAL_HTTP_CONTENT_LEN,
						&p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		lws_http_mark_sse(wsi);
		lws_callback_on_writable(wsi);

		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss || pss->sent == N_EVENTS)
			return 0;

		n = lws_snprintf((char *)start, sizeof(buf) - LWS_PRE,
				 "data: %d\r\n\r\n", pss->sent);
		if (lws_write(wsi, start, (size_t)n, LWS_WRITE_HTTP) != n)
			return -1;

		if (++pss->sent < N_EVENTS)
			lws_set_timer_usecs(wsi,
					    EVENT_GAP_SECS * LWS_USEC_PER_SEC);

		return 0;

	case LWS_CALLBACK_TIMER:
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_CLOSED_HTTP:
		/* the client hung up after the last event: we noticed */
		if (pss && pss->sent == N_EVENTS)
			srv_closed = 1;
		lws_cancel_service(lws_get_context(wsi));
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* ------------------------------------------------------------- client */

static int
callback_sse_cli(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (lws_http_client_http_response(wsi) != HTTP_STATUS_OK) {
			lwsl_err("%s: bad response status\n", __func__);
			fail++;
			done = 1;
			return -1;
		}
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP: {
		char b[1024 + LWS_PRE], *px = b + LWS_PRE;
		int lenx = (int)sizeof(b) - LWS_PRE;

		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ: {
		const char *p = (const char *)in, *e = p + len;

		/* events are small: each arrives whole in one read */
		while ((p = memchr(p, 'd', lws_ptr_diff_size_t(e, p))) &&
		       e - p >= 5) {
			if (!strncmp(p, "data:", 5)) {
				t_last = lws_now_usecs();
				if (!events_seen++)
					t_first = t_last;
				lwsl_user("%s: event %d\n", __func__,
					  events_seen);
			}
			p++;
		}

		if (events_seen == N_EVENTS) {
			/* hang up: the server must notice */
			done = 1;
			return -1;
		}
		return 0;
	}

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (events_seen != N_EVENTS) {
			lwsl_err("%s: stream closed after %d event(s)\n",
				 __func__, events_seen);
			fail++;
		}
		done = 1;
		lws_cancel_service(lws_get_context(wsi));
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{ "sse-srv", callback_sse_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	{ "sse-cli", callback_sse_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_http_mount mount = {
	.mountpoint		= "/sse",
	.origin			= "sse-srv",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 4,
};

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out with %d event(s)\n", __func__, events_seen);
	fail++;
	done = 1;
	lws_cancel_service(context);
}

static void
sul_connect_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= lws_get_vhost_by_name(context, "cli");
	i.address		= "127.0.0.1";
	i.port			= port;
	i.path			= "/sse";
	i.host			= "127.0.0.1";
	i.origin		= "127.0.0.1";
	i.method		= "GET";
	i.protocol		= "sse-cli";
	i.local_protocol_name	= "sse-cli";
	i.alpn			= "http/1.1";

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		fail++;
		done = 1;
	}
}

static void
sigint_handler(int sig)
{
	done = 1;
	fail++;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	lws_usec_t t_wait;
	const char *p;
	int n = 0;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);

	lwsl_user("LWS API selftest: h1 SSE stream lifetime\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	/* the server and client wsi, plus lws' own */
	info.fd_limit_per_thread = 0;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.vhost_name		= "srv";
	info.port		= port;
	info.protocols		= protocols;
	info.mounts		= &mount;
	/* an SSE stream is not "holding a header table" for this long */
	info.timeout_secs_ah_idle = 1;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("server vhost creation failed\n");
		goto bail;
	}

	info.vhost_name		= "cli";
	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.mounts		= NULL;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("client vhost creation failed\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 (EVENT_GAP_SECS + 10) * LWS_US_PER_SEC);
	lws_sul_schedule(context, 0, &sul_connect, sul_connect_cb, 1);

	while (n >= 0 && !done)
		n = lws_service(context, 0);

	/* the server has to hear the client hang up */
	t_wait = lws_now_usecs() + 3 * LWS_US_PER_SEC;
	while (n >= 0 && !srv_closed && !fail && lws_now_usecs() < t_wait)
		n = lws_service(context, 0);

	lws_sul_cancel(&sul_timeout);

	if (!fail && t_last - t_first < (EVENT_GAP_SECS - 1) * LWS_US_PER_SEC) {
		lwsl_err("events came %dms apart, the test proves nothing\n",
			 (int)((t_last - t_first) / 1000));
		fail++;
	}
	if (!fail && !srv_closed) {
		lwsl_err("server did not notice the client hang up\n");
		fail++;
	}

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", fail || events_seen != N_EVENTS ?
					"FAIL" : "PASS");

	return fail || events_seen != N_EVENTS;
}
