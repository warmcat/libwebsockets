/*
 * lws-api-test-netlink-coldplug
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * At init, lws asks netlink for the existing routes, and until the kernel
 * has finished telling it, the routing table can't be used to judge whether
 * a connection still has a route.  A fallback stops the wait if the end of
 * that dump never comes.
 *
 * On a slow or loaded host, lws_create_context() can take seconds, all before
 * the event loop has read anything from netlink.  If the fallback is judged
 * from when it was armed, it has expired by the time the loop first runs, the
 * part of the dump read first is taken as the whole table, and connections to
 * addresses whose routes come later in the dump, eg, ::1 after the ipv4
 * routes, are closed as "dest route gone".  CI saw QUIC and h3 clients to
 * localhost culled this way on aarch64 coverage builds.
 *
 * Here the context's creation is followed by a stall longer than the fallback
 * before the event loop first runs, as if creating the context had been that
 * slow.  Then a connected UDP socket, like QUIC's, to a UDP socket in the
 * same context on ::1 (when lws has ipv6), waits until the whole route dump
 * must have been read, and sends a datagram: it must survive to send it, and
 * the datagram must arrive.
 *
 * Linux only: netlink is where the routing table comes from.
 */

#include <libwebsockets.h>
#include <string.h>
#include <unistd.h>

static int interrupted, port = 7681, passed;
#if defined(LWS_WITH_IPV6)
static const char *server = "::1";
#else
static const char *server = "127.0.0.1";
#endif
static struct lws_context *cx;
static lws_sorted_usec_list_t sul_deadline, sul_send;
static struct lws *wsi_cli;

/* longer than lws waits for the end of the route dump */
#define NLC_STALL_US		(3 * LWS_US_PER_SEC)
/* how long the client waits before it sends */
#define NLC_SEND_US		(1 * LWS_US_PER_SEC)
#define NLC_DEADLINE_US		(10 * LWS_US_PER_SEC)

static const char dgram[] = "still here";

static void
finish(void)
{
	interrupted = 1;
	lws_cancel_service(cx);
}

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: the datagram never arrived\n", __func__);
	finish();
}

static void
send_cb(lws_sorted_usec_list_t *sul)
{
	if (wsi_cli)
		lws_callback_on_writable(wsi_cli);
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		if (len == sizeof(dgram) - 1 && !memcmp(in, dgram, len)) {
			lwsl_user("%s: got the datagram\n", __func__);
			passed = 1;
		}
		finish();
		break;

	default:
		break;
	}

	return 0;
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	uint8_t buf[LWS_PRE + sizeof(dgram)];

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		lwsl_user("%s: connected to %s, waiting before sending\n",
			  __func__, server);
		wsi_cli = wsi;
		lws_sul_schedule(cx, 0, &sul_send, send_cb, NLC_SEND_US);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		memcpy(buf + LWS_PRE, dgram, sizeof(dgram) - 1);
		if (lws_write(wsi, buf + LWS_PRE, sizeof(dgram) - 1,
			      LWS_WRITE_RAW) != (int)sizeof(dgram) - 1) {
			lwsl_err("%s: write failed\n", __func__);
			finish();
		}
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_RAW_CLOSE:
		wsi_cli = NULL;
		lws_sul_cancel(&sul_send);
		if (interrupted)
			/* the context going away */
			break;
		lwsl_err("%s: closed before sending\n", __func__);
		finish();
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "nlc-srv", callback_srv, 0, 0, 0, NULL, 0 },
	{ "nlc-cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
	const char *p;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* the defaults budget fds for a lone client; we have both ends */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server = p;

	lwsl_user("LWS API selftest: netlink coldplug after a slow start\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the udp sockets are made explicitly, nothing listens */
	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.protocols		= protocols;
	info.vhost_name		= "nlc";

	vh = lws_create_vhost(cx, &info);
	if (!vh) {
		lwsl_err("vhost creation failed\n");
		goto bail;
	}

	if (!lws_create_adopt_udp(vh, server, port, LWS_CAUDP_BIND,
				  protocols[0].name, NULL, NULL, NULL, NULL,
				  NULL)) {
		/* eg, the host has no ::1 */
		lwsl_user("%s: can't bind %s, not applicable here\n",
			  __func__, server);
		lws_context_destroy(cx);

		return 0;
	}

	lwsl_user("%s: stalling %dms before the event loop runs\n", __func__,
		  (int)(NLC_STALL_US / LWS_US_PER_MS));
	usleep((useconds_t)NLC_STALL_US);

	if (!lws_create_adopt_udp(vh, server, port, 0, protocols[1].name,
				  NULL, NULL, NULL, NULL, NULL)) {
		lwsl_err("%s: client udp adopt failed\n", __func__);
		goto bail;
	}

	lws_sul_schedule(cx, 0, &sul_deadline, deadline_cb, NLC_DEADLINE_US);

	while (!interrupted)
		if (lws_service(cx, 0) < 0)
			break;

bail:
	lws_sul_cancel(&sul_deadline);
	lws_sul_cancel(&sul_send);
	lws_context_destroy(cx);

	lwsl_user("Completed: %s\n", passed ? "PASS" : "FAIL");

	return !passed;
}
