/*
 * lws-api-test-client-early-fail
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A client connection that fails before it ever had a socket in the fds
 * table is freed by the connect code itself, not by the usual close.  That
 * free still resets the wsi, giving back its ah and taking it off the pt's
 * timer lists, which are the pt's: it must hold the context lock and then
 * the pt lock, as the close does.  Before G-701 it held only the context
 * lock, so in SMP builds (LWS_MAX_SMP > 1) another thread could be changing
 * the same lists, and debug SMP builds aborted on the pt lock assert.
 *
 * Two clients fail that way:
 *
 *  - one to a name a fake nameserver on loopback, adopted into the event
 *    loop, says does not exist (NXDOMAIN): it fails later, from the
 *    resolver's callback, and
 *
 *  - in builds with unix domain sockets, one to a unix socket path too long
 *    to fit sun_path: it fails at once, inside lws_client_connect_via_info().
 *
 * The first must be told LWS_CALLBACK_CLIENT_CONNECTION_ERROR, saying why.
 * The second is told by lws_client_connect_via_info() returning NULL, and
 * must not also get a CONNECTION_ERROR.  The process must neither abort nor
 * (under ASan) leak or touch freed memory.  A single service thread is enough: the lock asserts are compiled
 * into any debug build with LWS_MAX_SMP > 1, whatever the thread count.
 *
 * The test runs under ctest, which gives the fake nameserver's port in
 * LWS_ASYNCDNS_PORT, the port the resolver asks its nameservers on.  To run
 * it by hand, set that to any free udp port.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#define NX_NAME			"no-such-host.invalid"
#define WATCHDOG_S		10

/* one leg per way to fail before the fds table */

static struct leg {
	const char		*name;
	const char		*expect;	/* in the CONNECTION_ERROR, or
						 * NULL: refused synchronously */
	int			errored;
	int			done;
} legs[] = {
	{ "NXDOMAIN",			"NXDOMAIN",		0, 0 },
#if defined(LWS_WITH_UNIX_SOCK)
	{ "unix path too long",		NULL,			0, 0 },
#endif
};

static struct lws_context *cx;
static lws_sorted_usec_list_t sul_watchdog;
static int fails, queries;

static void
check_done(void)
{
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(legs); n++)
		if (!legs[n].done)
			return;

	lws_default_loop_exit(cx);
}

/*
 * The fake nameserver: whatever it is asked, the name does not exist
 */

static int
callback_fake_ns(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	const uint8_t *q = (const uint8_t *)in;
	uint8_t resp[512];
	lws_sockfd_type fd;
	size_t o = 12;
	ssize_t n;

	if (reason != LWS_CALLBACK_RAW_RX)
		return 0;

	/* walk the query's qname, which has no compression pointers */

	if (len < 12 || len > sizeof(resp))
		return 0;
	while (o < len && q[o]) {
		if (q[o] > 63)
			return 0;
		o += (size_t)q[o] + 1;
	}
	if (o + 5 > len)
		return 0;
	o += 5; /* the question section ends after QTYPE + QCLASS */

	memcpy(resp, q, o);
	resp[2] = 0x81;			/* QR + RD */
	resp[3] = 0x83;			/* RA, rcode NXDOMAIN */
	memset(&resp[6], 0, 6);		/* no answer, authority, additional */

	queries++;

	fd = lws_get_socket_fd(wsi);
	if (fd == LWS_SOCK_INVALID) {
		lwsl_err("%s: no socket to answer on\n", __func__);
		return 0;
	}
	n = sendto(fd,
#if defined(WIN32)
		   (const char *)
#endif
		   resp,
#if defined(WIN32)
		   (int)
#endif
		   o, 0, sa46_sockaddr(&lws_get_udp(wsi)->sa46),
		   sa46_socklen(&lws_get_udp(wsi)->sa46));
	if (n < (ssize_t)o)
		lwsl_err("%s: answer send failed\n", __func__);

	return 0;
}

/*
 * The clients: each must fail, saying why
 */

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct leg *leg = (struct leg *)lws_get_opaque_user_data(wsi);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (!leg || leg->done)
			break;
		leg->done = 1;
		leg->errored = 1;
		if (!leg->expect || !in ||
		    !strstr((const char *)in, leg->expect)) {
			lwsl_err("%s: %s: unexpected error: %s\n", __func__,
				 leg->name, in ? (const char *)in : "(null)");
			fails++;
		} else
			lwsl_user("%s: %s: failed as expected: %s\n", __func__,
				  leg->name, (const char *)in);
		check_done();
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (!leg || leg->done)
			break;
		lwsl_err("%s: %s: connected\n", __func__, leg->name);
		leg->done = 1;
		fails++;
		check_done();

		return -1;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{ "fake-ns", callback_fake_ns, 0, 0, 0, NULL, 0 },
	{ "cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sul_watchdog_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;
	lwsl_err("%s: timed out\n", __func__);
	fails++;
	lws_default_loop_exit(cx);
}

static void
sigint_handler(int sig)
{
	(void)sig;
	lws_default_loop_exit(cx);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
#if defined(LWS_WITH_UNIX_SOCK)
	char longpath[300];
#endif
	const char *p = getenv("LWS_ASYNCDNS_PORT");
	struct lws_vhost *vh;
	lws_sockaddr46 sa46;
	int ns_port, n;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: client fails before the fds table\n");

	ns_port = p ? atoi(p) : 0;
	if (ns_port <= 0 || ns_port > 65535) {
		lwsl_err("Set LWS_ASYNCDNS_PORT to a free udp port\n");

		return 1;
	}

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");

		return 1;
	}

	/* only our fake nameserver may be asked */

	n = 0;
	while (!lws_plat_asyncdns_get_server(cx, n++, &sa46))
		lws_async_dns_server_remove(cx, &sa46);
	memset(&sa46, 0, sizeof(sa46));
	if (lws_sa46_parse_numeric_address("127.0.0.1", &sa46) ||
	    !lws_async_dns_server_add(cx, &sa46)) {
		lwsl_err("Unable to pin the fake nameserver\n");
		goto bail;
	}

	info.protocols = protocols;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	vh = lws_create_vhost(cx, &info);
	if (!vh) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	if (!lws_create_adopt_udp(vh, "127.0.0.1", ns_port, LWS_CAUDP_BIND,
				  "fake-ns", NULL, NULL, NULL, NULL,
				  "fake-ns")) {
		lwsl_err("Unable to bind the fake nameserver on %d\n",
			 ns_port);
		goto bail;
	}

	for (n = 0; n < (int)LWS_ARRAY_SIZE(legs); n++) {
		memset(&i, 0, sizeof(i));
		i.context		= cx;
		i.vhost			= vh;
		i.address		= NX_NAME;
		i.host			= NX_NAME;
		i.origin		= NX_NAME;
		i.port			= 80;
		i.path			= "/";
		i.method		= "GET";
		i.protocol		= "cli";
		i.local_protocol_name	= "cli";
		i.opaque_user_data	= &legs[n];

#if defined(LWS_WITH_UNIX_SOCK)
		if (n == 1) {
			/* '+' asks for a unix socket, at a path too long */
			memset(longpath, 'x', sizeof(longpath) - 1);
			longpath[0] = '+';
			longpath[sizeof(longpath) - 1] = '\0';
			i.address	= longpath;
			i.host		= "localhost";
			i.origin	= "localhost";
		}
#endif

		lwsl_user("%s: connecting\n", legs[n].name);
		if (lws_client_connect_via_info(&i)) {
			if (!legs[n].expect) {
				lwsl_err("%s: not refused\n", legs[n].name);
				fails++;
			}
			continue;
		}

		/* refused: that is how a synchronous failure is told */
		if (legs[n].expect) {
			lwsl_err("%s: refused\n", legs[n].name);
			fails++;
		} else
			lwsl_user("%s: refused as expected\n", legs[n].name);
		legs[n].done = 1;
	}

	lws_sul_schedule(cx, 0, &sul_watchdog, sul_watchdog_cb,
			 WATCHDOG_S * LWS_US_PER_SEC);

	check_done();
	lws_context_default_loop_run_destroy(cx);
	cx = NULL;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(legs); n++)
		if (!!legs[n].expect != legs[n].errored) {
			lwsl_err("%s: %s CONNECTION_ERROR\n", legs[n].name,
				 legs[n].errored ? "unexpected" : "no");
			fails++;
		}

	if (!queries) {
		lwsl_err("The fake nameserver was never asked\n");
		fails++;
	}

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;

bail:
	lws_context_destroy(cx);

	return 1;
}
