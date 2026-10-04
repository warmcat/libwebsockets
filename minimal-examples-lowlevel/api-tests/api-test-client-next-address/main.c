/*
 * lws-api-test-client-next-address
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A client whose connect to the first address the resolver gave is refused
 * must go on to the next address, on the same connection.
 *
 * A fake nameserver on loopback, adopted into the event loop, answers every
 * A query with 127.0.0.1 and every AAAA query with ::1.  Two http servers
 * listen on kernel-chosen ports, one only on 127.0.0.1 and the other only on
 * ::1, and a client connects to the same name at each server's port.
 *
 * Which of the two addresses a client tries first is decided by the address
 * sort, ie, by the host's routes, so it differs between hosts.  But both
 * clients get both addresses in the same order, so whichever it is, one of
 * them starts on the address its server isn't listening on, is refused, and
 * must connect on the next one.  Both clients must end up connected, each on
 * the family its server listens on.
 *
 * The test runs under ctest, which gives the fake nameserver's port in
 * LWS_ASYNCDNS_PORT, the port the resolver asks its nameservers on.  To run
 * it by hand, set that to any free udp port.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#define NA_NAME			"nextads.invalid"
#define WATCHDOG_S		10

static const uint8_t ads4[] = { 127, 0, 0, 1 },
		     ads6[] = { 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 1 };

/* one leg per server family */

static struct leg {
	const char		*name;
	const char		*iface;
	struct lws_vhost	*vh;
	int			af;
	int			port;
	int			connected;
	int			done;
} legs[] = {
	{ "listening on 127.0.0.1 only", "127.0.0.1", NULL, AF_INET,  0, 0, 0 },
	{ "listening on ::1 only",	 "::1",       NULL, AF_INET6, 0, 0, 0 },
};

static struct lws_context *cx;
static lws_sorted_usec_list_t sul_watchdog;
static int fails, queries;

static void
check_done(void)
{
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(legs); n++)
		if (legs[n].vh && !legs[n].done)
			return;

	lws_default_loop_exit(cx);
}

/*
 * The fake nameserver: answers the question it was asked, with 127.0.0.1 for
 * A, ::1 for AAAA, and no records for anything else
 */

static int
callback_fake_ns(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	const uint8_t *q = (const uint8_t *)in;
	const uint8_t *ads = NULL;
	uint8_t resp[512];
	size_t o = 12, alen = 0;
	lws_sockfd_type fd;
	uint16_t qtype;
	ssize_t n;

	if (reason != LWS_CALLBACK_RAW_RX)
		return 0;

	/* walk the query's qname, which has no compression pointers */

	if (len < 12 || len > sizeof(resp) - 32)
		return 0;
	while (o < len && q[o]) {
		if (q[o] > 63)
			return 0;
		o += (size_t)q[o] + 1;
	}
	if (o + 5 > len)
		return 0;

	qtype = (uint16_t)((q[o + 1] << 8) | q[o + 2]);
	o += 5; /* the question section ends after QTYPE + QCLASS */

	memcpy(resp, q, o);
	resp[2] = 0x81;			/* QR + RD */
	resp[3] = 0x80;			/* RA, rcode NOERROR */
	resp[6] = 0; resp[7] = 0;	/* ANCOUNT */
	resp[8] = 0; resp[9] = 0;	/* NSCOUNT */
	resp[10] = 0; resp[11] = 0;	/* ARCOUNT */

	if (qtype == LWS_ADNS_RECORD_A) {
		ads = ads4;
		alen = sizeof(ads4);
	}
	if (qtype == LWS_ADNS_RECORD_AAAA) {
		ads = ads6;
		alen = sizeof(ads6);
	}

	if (ads) {
		resp[7] = 1;
		resp[o++] = 0xc0;	/* NAME: pointer to the qname */
		resp[o++] = 0x0c;
		resp[o++] = 0;
		resp[o++] = (uint8_t)qtype;
		resp[o++] = 0; resp[o++] = 1;	/* CLASS IN */
		resp[o++] = 0; resp[o++] = 0;
		resp[o++] = 0; resp[o++] = 60;	/* TTL 60s */
		resp[o++] = 0; resp[o++] = (uint8_t)alen;
		memcpy(&resp[o], ads, alen);
		o += alen;
	}

	queries++;

	fd = lws_get_socket_fd(wsi);
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
 * The clients: done when connected, or when the connect failed
 */

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct leg *leg = (struct leg *)lws_get_opaque_user_data(wsi);
	char peer[64];

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (!leg || leg->done)
			break;
		lwsl_err("%s: %s: connect failed: %s\n", __func__, leg->name,
			 in ? (const char *)in : "(null)");
		leg->done = 1;
		fails++;
		check_done();
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (!leg || leg->done)
			break;
		leg->done = 1;

		/* it must have connected where its server listens */

		lws_get_peer_simple(wsi, peer, sizeof(peer));
		if ((leg->af == AF_INET6) != !!strchr(peer, ':')) {
			lwsl_err("%s: %s: connected to %s\n", __func__,
				 leg->name, peer);
			fails++;
		} else {
			lwsl_user("%s: %s: connected to %s\n", __func__,
				  leg->name, peer);
			leg->connected = 1;
		}
		check_done();

		return -1; /* the answer itself is of no interest */

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
}, protocols_cli[] = {
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
	struct lws_vhost *vh_cli;
	const char *p = getenv("LWS_ASYNCDNS_PORT");
	lws_sockaddr46 sa46;
	int ns_port, n, ran = 0;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* the defaults budget fds for a lone client; we have every end */
	info.fd_limit_per_thread = 0;

	lwsl_user("LWS API selftest: client goes on to the next address\n");

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

	/* the servers, each listening on one family only */

	info.protocols = protocols_srv;
	info.port = 0;
	for (n = 0; n < (int)LWS_ARRAY_SIZE(legs); n++) {
		info.vhost_name = legs[n].iface;
		info.iface = legs[n].iface;
		legs[n].vh = lws_create_vhost(cx, &info);
		if (!legs[n].vh) {
			if (legs[n].af == AF_INET6) {
				/* a host with ipv6 disabled */
				lwsl_notice("Can't listen on ::1, skipping "
					    "that leg\n");
				continue;
			}
			lwsl_err("Failed to create vhost %s\n",
				 legs[n].iface);
			goto bail;
		}
		legs[n].port = lws_get_vhost_listen_port(legs[n].vh);
	}
	info.iface = NULL;

	/* the clients, and the fake nameserver */

	info.protocols = protocols_cli;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	vh_cli = lws_create_vhost(cx, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	if (!lws_create_adopt_udp(vh_cli, "127.0.0.1", ns_port, LWS_CAUDP_BIND,
				  "fake-ns", NULL, NULL, NULL, NULL,
				  "fake-ns")) {
		lwsl_err("Unable to bind the fake nameserver on %d\n",
			 ns_port);
		goto bail;
	}

	for (n = 0; n < (int)LWS_ARRAY_SIZE(legs); n++) {
		if (!legs[n].vh)
			continue;

		memset(&i, 0, sizeof(i));
		i.context		= cx;
		i.vhost			= vh_cli;
		i.address		= NA_NAME;
		i.host			= NA_NAME;
		i.origin		= NA_NAME;
		i.port			= legs[n].port;
		i.path			= "/";
		i.method		= "GET";
		i.protocol		= "cli";
		i.local_protocol_name	= "cli";
		i.opaque_user_data	= &legs[n];

		lwsl_user("%s: connecting to %s:%d\n", legs[n].name, NA_NAME,
			  legs[n].port);
		if (!lws_client_connect_via_info(&i)) {
			/* the failure was reported to the leg already */
			if (!legs[n].done) {
				lwsl_err("%s: client connect failed\n",
					 legs[n].name);
				legs[n].done = 1;
				fails++;
			}
		}
	}

	lws_sul_schedule(cx, 0, &sul_watchdog, sul_watchdog_cb,
			 WATCHDOG_S * LWS_US_PER_SEC);

	check_done();
	lws_context_default_loop_run_destroy(cx);
	cx = NULL;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(legs); n++)
		if (legs[n].vh) {
			ran++;
			if (!legs[n].connected) {
				lwsl_err("%s: not connected\n", legs[n].name);
				fails++;
			}
		}

	if (!queries) {
		lwsl_err("The fake nameserver was never asked\n");
		fails++;
	}

	lwsl_user("Completed: %s (%d legs)\n", fails || !ran ? "FAIL" : "PASS",
		  ran);

	return fails || !ran;

bail:
	lws_context_destroy(cx);

	return 1;
}
