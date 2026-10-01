/*
 * lws-api-test-udp-unreachable
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A connected UDP socket whose datagram draws an ICMP port unreachable is
 * told of it by the kernel as a bare POLLERR, level-triggered until something
 * takes the error from the socket.  The service loop must take it and fail
 * the wsi's next read with it, so the wsi hears its RAW_CLOSE promptly:
 * before that it was never consumed, and the thread spun on poll() until the
 * next send, the wsi hearing nothing.
 *
 * Two wsi each send one datagram to a loopback UDP port nothing listens on,
 * and both must close within the deadline:
 *
 *  - one made by lws_create_adopt_udp(), which goes through the client
 *    connect machinery and stays in its connect-wait phase, where the client
 *    transport already reads the socket error as a failed connect
 *
 *  - one made from a socket the application created and connected itself,
 *    adopted with lws_adopt_descriptor_vhost(): past any connect phase, which
 *    is where the error was never taken before and the loop spun
 *
 * Linux only: it is the only platform whose poll() reports the datagram
 * error this way, and where lws connect()s the socket (Apple does not), which
 * the error delivery needs.
 */

#include <libwebsockets.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static int result = 1, interrupted, closed;

/* the client-machinery wsi and the adopted-fd wsi */
#define UDPU_WSI_COUNT		2
static lws_sorted_usec_list_t sul_deadline;
static struct lws_context *cx;

/* the error must be reported well inside this */
#define UDPU_DEADLINE_US	(3 * LWS_US_PER_SEC)

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: no close reported for the unreachable datagram\n",
		 __func__);
	interrupted = 1;
	lws_cancel_service(cx);
}

static int
callback_udpu(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	      void *in, size_t len)
{
	uint8_t pkt[LWS_PRE + 8];

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		lwsl_user("%s: adopted, sending one datagram\n", __func__);
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		memset(pkt + LWS_PRE, 0x55, sizeof(pkt) - LWS_PRE);
		if (lws_write(wsi, pkt + LWS_PRE, sizeof(pkt) - LWS_PRE,
			      LWS_WRITE_RAW) != (int)(sizeof(pkt) - LWS_PRE)) {
			lwsl_err("%s: write failed\n", __func__);
			interrupted = 1;
			lws_cancel_service(cx);
		}
		break;

	case LWS_CALLBACK_RAW_RX:
		lwsl_err("%s: unexpected rx %u\n", __func__, (unsigned int)len);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_RAW_CLOSE:
		/*
		 * The error reached us as the socket closing: that is the
		 * test.  Closes after the deadline are the context going away,
		 * not the error being reported, and do not count
		 */
		if (interrupted)
			break;
		lwsl_user("%s: closed after the unreachable datagram (%d)\n",
			  __func__, closed + 1);
		if (++closed == UDPU_WSI_COUNT) {
			result = 0;
			interrupted = 1;
			lws_cancel_service(cx);
		}
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "udp-unreachable", callback_udpu, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/*
 * A loopback UDP port nothing listens on: bind an ephemeral one to learn a
 * number the kernel just handed out, and give it back
 */
static int
unused_udp_port(void)
{
	struct sockaddr_in sin;
	socklen_t sl = sizeof(sin);
	int fd, port;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) ||
	    getsockname(fd, (struct sockaddr *)&sin, &sl)) {
		close(fd);
		return -1;
	}
	port = ntohs(sin.sin_port);
	close(fd);

	return port;
}

/*
 * A UDP socket the application made and connected to the unused port itself,
 * for lws to adopt: it has no connect phase in lws
 */
static int
own_connected_udp(int port)
{
	struct sockaddr_in sin;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = htons((uint16_t)port);
	if (connect(fd, (struct sockaddr *)&sin, sizeof(sin))) {
		close(fd);
		return -1;
	}

	return fd;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	lws_sock_file_fd_type fd;
	struct lws_vhost *vh;
	int port;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: UDP unreachable datagram\n");

	port = unused_udp_port();
	if (port < 0) {
		lwsl_err("%s: cannot find an unused udp port\n", __func__);
		return 1;
	}

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	info.fd_limit_per_thread = LWS_FD_LIMIT_PER_THREAD_MIN + UDPU_WSI_COUNT;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	vh = lws_create_vhost(cx, &info);
	if (!vh) {
		lwsl_err("%s: vhost failed\n", __func__);
		goto bail;
	}

	if (!lws_create_adopt_udp(vh, "127.0.0.1", port, 0, protocols[0].name,
				  NULL, NULL, NULL, NULL, "udpu")) {
		lwsl_err("%s: udp adopt failed\n", __func__);
		goto bail;
	}

	fd.sockfd = own_connected_udp(port);
	if (fd.sockfd < 0) {
		lwsl_err("%s: cannot make the connected udp socket\n", __func__);
		goto bail;
	}
	if (!lws_adopt_descriptor_vhost(vh, LWS_ADOPT_RAW_SOCKET_UDP, fd,
					protocols[0].name, NULL)) {
		lwsl_err("%s: adopting the connected udp socket failed\n",
			 __func__);
		close(fd.sockfd);
		goto bail;
	}

	lws_sul_schedule(cx, 0, &sul_deadline, deadline_cb, UDPU_DEADLINE_US);

	while (!interrupted && lws_service(cx, 0) >= 0)
		;

bail:
	lws_sul_cancel(&sul_deadline);
	lws_context_destroy(cx);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
