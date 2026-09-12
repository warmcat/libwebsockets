/*
 * lws-api-test-dht-krpc
 *
 * Wire-level round-trip coverage for the DHT KRPC packet builders and
 * the bencode parser: two DHT contexts on separate vhosts in this one
 * process exchange real datagrams over loopback UDP.
 *
 *  - a ping from A is answered by B's pong, so A's routing table gains B
 *    as a known-good node (rx_pong observed on A, rx_ping on B)
 *  - a subscribe request from A is answered by B through the same
 *    closest-nodes + token reply path a get_peers reply uses; A parses
 *    the cursor-built reply and the token surfaces as the
 *    LWS_DHT_EVENT_TOKEN callback
 *  - A's neighbourhood maintenance issues a find_node to its only node
 *    within a few seconds (tx_find_node on A, rx_find_node on B)
 *  - a reliable-transport data datagram from A is reassembled by B's
 *    sequencer and delivered verbatim to B's event callback
 *
 * The two UDP ports are allocated uniquely at build time and passed in
 * on the command line, so parallel ctest instances do not collide.
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define POLL_US		(100 * LWS_US_PER_MS)
#define DEADLINE_US	(15 * LWS_US_PER_SEC)

static struct lws_context *cx;
static struct lws_vhost *vh_a, *vh_b;
static struct lws_dht_ctx *dht_a, *dht_b;
static lws_sorted_usec_list_t sul_poll, sul_deadline;

static struct sockaddr_in sa_a, sa_b;

static const char *data_msg = "PUT 0102030405 0 5 hello";
static size_t data_msg_len;

struct seen {
	unsigned char token_ok:1;	/* A got B's get_peers token */
	unsigned char data_ok:1;	/* B got A's data payload verbatim */
	unsigned char ping_sent:1;
	unsigned char searched:1;
	unsigned char data_sent:1;
};

static struct seen sv;
static int retcode = 1;

static void
cb_a(void *closure, int event, const lws_dht_hash_t *info_hash,
     const void *data, size_t data_len, const struct sockaddr *from,
     size_t fromlen)
{
	(void)closure;
	(void)info_hash;
	(void)from;
	(void)fromlen;

	switch (event) {
	case LWS_DHT_EVENT_TOKEN:
		/* B's get_peers reply carries the anti-spoof token */
		if (data_len == 8)
			sv.token_ok = 1;
		break;
	default:
		break;
	}
}

static void
cb_b(void *closure, int event, const lws_dht_hash_t *info_hash,
     const void *data, size_t data_len, const struct sockaddr *from,
     size_t fromlen)
{
	(void)closure;
	(void)info_hash;
	(void)from;
	(void)fromlen;

	switch (event) {
	case LWS_DHT_EVENT_DATA:
		if (data_len == data_msg_len &&
		    !memcmp(data, data_msg, data_len))
			sv.data_ok = 1;
		break;
	default:
		break;
	}
}

static int
stats_of(struct lws_vhost *vh, struct lws_dht_stats *s)
{
	return lws_dht_get_stats(vh, s, NULL, NULL);
}

static void
poll_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_dht_stats sa, sb;

	lws_sul_schedule(cx, 0, &sul_poll, poll_cb, POLL_US);

	if (!sv.ping_sent) {
		sv.ping_sent = 1;
		lws_dht_ping_node(dht_a, (struct sockaddr *)&sa_b,
				  sizeof(sa_b));
	}

	if (stats_of(vh_a, &sa) || stats_of(vh_b, &sb))
		return;

	/* once the pong made A's table good, exercise the rest */

	if (sa.rx_pong && !sv.searched) {
		lws_dht_hash_t *ih;
		uint8_t tid[4], idata[20];

		sv.searched = 1;

		/*
		 * Ask B to subscribe to a hash: the reply is built by the
		 * same closest-nodes + token path a get_peers reply uses.
		 * The tid deliberately carries the "gp" prefix so A routes
		 * the reply through the get_peers reply handling and the
		 * token surfaces as the LWS_DHT_EVENT_TOKEN callback.
		 */

		memset(idata, 0x44, sizeof(idata));
		ih = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, idata);
		if (!ih) {
			lwsl_err("%s: hash create failed\n", __func__);
			lws_default_loop_exit(cx);
			return;
		}

		tid[0] = 'g';
		tid[1] = 'p';
		tid[2] = 0;
		tid[3] = 0;
		lws_dht_send_subscribe(dht_a, (struct sockaddr *)&sa_b,
				       sizeof(sa_b), tid, 4, ih, 0, 0);
		lws_dht_hash_destroy(&ih);

		sv.data_sent = 1;
		lws_dht_send_data(dht_a, (struct sockaddr *)&sa_b,
				  data_msg, data_msg_len);
	}

	/*
	 * Everything observable has been seen: B answered the ping, the
	 * subscribe round trip produced a token, the data payload arrived
	 * verbatim, and A's maintenance find_node probe reached B.
	 */

	if (sv.token_ok && sv.data_ok &&
	    sa.tx_find_node && sb.rx_find_node &&
	    sb.rx_ping && !sa.rx_drops && !sb.rx_drops) {
		retcode = 0;
		lws_default_loop_exit(cx);
	}
}

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	lws_default_loop_exit(cx);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	lws_dht_info_t di;
	static const struct lws_protocols protocols[] = {
		{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
		LWS_PROTOCOL_LIST_TERM
	};
	uint8_t ida[20], idb[20];
	const char *p;
	int port_a = 0, port_b = 0, n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "--port-a")))
		port_a = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-b")))
		port_b = atoi(p);

	if (port_a < 1 || port_a > 65535 || port_b < 1 || port_b > 65535 ||
	    port_a == port_b) {
		lwsl_err("usage: --port-a <udp port> --port-b <udp port>\n");
		return 1;
	}

	signal(SIGINT, sigint_handler);
	data_msg_len = strlen(data_msg);

	memset(&sa_a, 0, sizeof(sa_a));
	sa_a.sin_family = AF_INET;
	sa_a.sin_port = htons((uint16_t)port_a);
	sa_a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	sa_b = sa_a;
	sa_b.sin_port = htons((uint16_t)port_b);

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.vhost_name = "dht-krpc-a";
	vh_a = lws_create_vhost(cx, &info);
	info.vhost_name = "dht-krpc-b";
	vh_b = lws_create_vhost(cx, &info);
	if (!vh_a || !vh_b) {
		lwsl_err("vhost creation failed\n");
		goto bail;
	}

	memset(ida, 0x11, sizeof(ida));
	memset(idb, 0x22, sizeof(idb));

	memset(&di, 0, sizeof(di));
	di.vhost	= vh_a;
	di.cb		= cb_a;
	di.name		= "krpc-a";
	di.port		= port_a;
	{
		lws_dht_hash_t *id = lws_dht_hash_create(
				LWS_DHT_HASH_TYPE_SHA1, 20, ida);
		di.id = id;
		dht_a = lws_dht_create(&di);
		lws_dht_hash_destroy(&id);
	}

	di.vhost	= vh_b;
	di.cb		= cb_b;
	di.name		= "krpc-b";
	di.port		= port_b;
	{
		lws_dht_hash_t *id = lws_dht_hash_create(
				LWS_DHT_HASH_TYPE_SHA1, 20, idb);
		di.id = id;
		dht_b = lws_dht_create(&di);
		lws_dht_hash_destroy(&id);
	}

	if (!dht_a || !dht_b) {
		lwsl_err("dht creation failed\n");
		goto bail;
	}

	lws_sul_schedule(cx, 0, &sul_deadline, deadline_cb, DEADLINE_US);
	poll_cb(&sul_poll);

	while (n >= 0)
		n = lws_service(cx, 0);

	{
		struct lws_dht_stats sa, sb;
		int fails = 0;

		if (stats_of(vh_a, &sa) || stats_of(vh_b, &sb)) {
			lwsl_err("stats unavailable\n");
			fails++;
		} else {
			if (!sa.rx_pong) {
				lwsl_err("A never saw B's pong\n");
				fails++;
			}
			if (!sb.rx_ping) {
				lwsl_err("B never saw A's ping\n");
				fails++;
			}
			if (!sv.token_ok) {
				lwsl_err("A never received B's subscription token\n");
				fails++;
			}
			if (sa.rx_drops || sb.rx_drops) {
				lwsl_err("datagrams were dropped as unparseable "
					 "(A %u, B %u)\n",
					 sa.rx_drops, sb.rx_drops);
				fails++;
			}
			if (!sv.data_ok) {
				lwsl_err("B never received the data payload verbatim\n");
				fails++;
			}
			if (!sa.tx_find_node || !sb.rx_find_node) {
				lwsl_err("A's find_node maintenance probe never reached B\n");
				fails++;
			}
		}

		if (retcode)
			retcode = fails ? 1 : 0;
	}

	lwsl_user("Completed: LWS api selftest: dht-krpc\n");

bail:
	lws_sul_cancel(&sul_poll);
	lws_sul_cancel(&sul_deadline);
	lws_context_destroy(cx);

	return retcode;
}
