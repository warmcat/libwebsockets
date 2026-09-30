/*
 * lws-api-test-dht-krpc
 *
 * Wire-level round-trip coverage for the DHT KRPC packet builders and
 * the bencode parser: DHT contexts on separate vhosts in this one
 * process exchange real datagrams over loopback UDP.
 *
 *  - a ping from A is answered by B's pong, so A's routing table gains B
 *    as a known-good node (rx_pong observed on A, rx_ping on B)
 *  - a subscribe request from A is answered by B through the same
 *    closest-nodes + token reply path a get_peers reply uses; A parses
 *    the cursor-built reply and the token surfaces as the
 *    LWS_DHT_EVENT_TOKEN callback
 *  - A returns that token in a subscribe_confirm with a 16-byte tid, so B
 *    registers A as a subscriber; B's notify reaches A, and A's ack (which
 *    echoes the 16-byte tid) clears B's pending notification, so notifying
 *    the same content again finds nothing to send.  A confirms twice, with
 *    different tids: that renews its one subscription, so B notifies once
 *  - A's neighbourhood maintenance issues a find_node to its only node
 *    within a few seconds (tx_find_node on A, rx_find_node on B)
 *  - a reliable-transport data datagram from A is reassembled by B's
 *    sequencer and delivered verbatim to B's event callback
 *  - once B is a good node for A, A probes it for A's external address:
 *    the probe's nonce survives the round trip, and in a two-node network
 *    the one other node is the quorum, so A learns 127.0.0.1:port-a from B
 *  - a third context C that uses B's node id pings A from its own port once
 *    B is good for A: A answers it, but B's entry keeps B's endpoint, so the
 *    good node A hands out for that id is still B
 *
 * The three UDP ports are allocated uniquely at build time and passed in
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
static struct lws_vhost *vh_a, *vh_b, *vh_c;
static struct lws_dht_ctx *dht_a, *dht_b, *dht_c;
static lws_sorted_usec_list_t sul_poll, sul_deadline;

static struct sockaddr_in sa_a, sa_b, sa_c;

static const char *data_msg = "PUT 0102030405 0 5 hello";
static size_t data_msg_len;

static uint8_t token[40];
static size_t token_len;

struct seen {
	unsigned char token_ok:1;	/* A got B's get_peers token */
	unsigned char confirmed:1;	/* A sent B its subscribe_confirm */
	unsigned char notified:1;	/* B sent A a notify */
	unsigned char notify_ok:1;	/* A got B's notify */
	unsigned char acked:1;		/* A's ack cleared B's pending notify */
	unsigned char dup_sub:1;	/* B notified A more than once */
	unsigned char data_ok:1;	/* B got A's data payload verbatim */
	unsigned char ping_sent:1;
	unsigned char searched:1;
	unsigned char data_sent:1;
	unsigned char probed:1;		/* A asked B for its external address */
	unsigned char extip_ok:1;	/* ...and learnt it */
	unsigned char extip_bad:1;	/* ...or learnt something else */
	unsigned char samid_sent:1;	/* C pinged A using B's id */
	unsigned char samid_ok:1;	/* ...and A still has B at B */
	unsigned char samid_bad:1;	/* ...or A moved B's entry */
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
		if (data_len == 8 && !sv.token_ok) {
			memcpy(token, data, data_len);
			token_len = data_len;
			sv.token_ok = 1;
		}
		break;
	case LWS_DHT_EVENT_NOTIFY:
		sv.notify_ok = 1;
		break;
	case LWS_DHT_EVENT_EXTERNAL_ADDR: {
		const struct lws_dht_consensus_info *ci =
				(const struct lws_dht_consensus_info *)data;
		const struct sockaddr_in *sin;

		/* B sees us at our loopback address and port, and says so */
		if (!ci || data_len != sizeof(*ci)) {
			sv.extip_bad = 1;
			break;
		}
		sin = (const struct sockaddr_in *)&ci->ss;
		if (sin->sin_family == AF_INET &&
		    sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK) &&
		    sin->sin_port == sa_a.sin_port && ci->num_peers == 1)
			sv.extip_ok = 1;
		else {
			lwsl_err("%s: unexpected external address report\n",
				 __func__);
			sv.extip_bad = 1;
		}
		break;
	}
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

/*
 * C shares B's node id but not its endpoint.  Once A has answered C's ping
 * it has seen C's claim to that id; the one good node A knows must still be
 * B at B's port.
 */

static void
same_id_step(void)
{
	struct sockaddr_in sin[4];
	struct sockaddr_in6 sin6[1];
	struct lws_dht_stats sc;
	int num = (int)LWS_ARRAY_SIZE(sin), num6 = 0;

	if (!sv.extip_ok || sv.samid_ok || sv.samid_bad)
		return;

	if (!sv.samid_sent) {
		sv.samid_sent = 1;
		lws_dht_ping_node(dht_c, (struct sockaddr *)&sa_a,
				  sizeof(sa_a));
		return;
	}

	if (stats_of(vh_c, &sc) || !sc.rx_pong)
		return;

	lws_dht_get_nodes(dht_a, sin, &num, sin6, &num6);
	if (num == 1 && sin[0].sin_port == sa_b.sin_port)
		sv.samid_ok = 1;
	else {
		lwsl_err("%s: A's node for B's id moved (%d good)\n",
			 __func__, num);
		sv.samid_bad = 1;
	}
}

static lws_dht_hash_t *
sub_hash(void)
{
	uint8_t idata[20];

	memset(idata, 0x44, sizeof(idata));

	return lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, idata);
}

/*
 * Subscribe, notify, ack: A confirms the subscription with the token B
 * gave it, B notifies A of new content, and A's ack must find the pending
 * notification by its 16-byte tid so B commits the content as delivered.
 *
 * A confirms twice with different tids, as a subscriber renewing does: B
 * must hold one subscription for A's endpoint, under the latest tid, not
 * one per tid.
 */

static void
subscription_step(void)
{
	uint8_t tid[16], sha_old[32], sha_new[32];
	lws_dht_hash_t *ih;
	int n;

	if (!sv.token_ok || sv.acked)
		return;

	ih = sub_hash();
	if (!ih)
		return;

	memset(sha_old, 0, sizeof(sha_old));
	memset(sha_new, 0x77, sizeof(sha_new));

	if (!sv.confirmed) {
		sv.confirmed = 1;
		for (n = 0; n < 2; n++) {
			lws_get_random(cx, tid, sizeof(tid));
			lws_dht_send_subscribe_confirm(dht_a,
					(struct sockaddr *)&sa_b, sizeof(sa_b),
					tid, sizeof(tid), ih, token, token_len,
					sha_old, 1);
		}
		goto bail;
	}

	/*
	 * Until B has registered A this finds no subscriber; once it has, it
	 * sends the notify.  After A's ack has been processed, B holds the
	 * new content as A's current one and there is nothing left to send.
	 */

	n = lws_dht_notify_subscribers(dht_b, ih, sha_new, NULL, 0);
	if (n > 1) {
		lwsl_err("%s: B holds %d subscriptions for A\n", __func__, n);
		sv.dup_sub = 1;
	}
	if (n > 0)
		sv.notified = 1;
	else if (!n && sv.notified && sv.notify_ok)
		sv.acked = 1;

bail:
	lws_dht_hash_destroy(&ih);
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

		sv.searched = 1;

		/*
		 * Ask B to subscribe to a hash: the reply is built by the
		 * same closest-nodes + token path a get_peers reply uses,
		 * and the library's own tid must route it back so the
		 * token surfaces as the LWS_DHT_EVENT_TOKEN callback.
		 */

		ih = sub_hash();
		if (!ih) {
			lwsl_err("%s: hash create failed\n", __func__);
			lws_default_loop_exit(cx);
			return;
		}

		lws_dht_send_subscribe(dht_a, (struct sockaddr *)&sa_b,
				       sizeof(sa_b), ih, 0, 0);
		lws_dht_hash_destroy(&ih);

		sv.data_sent = 1;
		lws_dht_send_data(dht_a, (struct sockaddr *)&sa_b,
				  data_msg, data_msg_len);
	}

	subscription_step();
	same_id_step();

	/*
	 * A only probes nodes it holds as good, and B becomes good by
	 * answering A's maintenance find_node
	 */

	if (!sv.probed) {
		int good = 0;

		lws_dht_nodes(dht_a, AF_INET, &good, NULL, NULL, NULL);
		if (good) {
			sv.probed = 1;
			lws_dht_test_external_ips(dht_a);
		}
	}

	/*
	 * Everything observable has been seen: B answered the ping, the
	 * subscribe round trip produced a token, the notify was acked, the
	 * data payload arrived verbatim, A's maintenance find_node probe
	 * reached B, B told A its external address, and C's use of B's id
	 * did not move B's entry in A's table.
	 */

	if (sv.token_ok && sv.acked && !sv.dup_sub && sv.data_ok &&
	    sv.extip_ok && !sv.extip_bad &&
	    sv.samid_ok && !sv.samid_bad &&
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
	int port_a = 0, port_b = 0, port_c = 0, n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "--port-a")))
		port_a = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-b")))
		port_b = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-c")))
		port_c = atoi(p);

	if (port_a < 1 || port_a > 65535 || port_b < 1 || port_b > 65535 ||
	    port_c < 1 || port_c > 65535 ||
	    port_a == port_b || port_a == port_c || port_b == port_c) {
		lwsl_err("usage: --port-a <udp port> --port-b <udp port> "
			 "--port-c <udp port>\n");
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
	sa_c = sa_a;
	sa_c.sin_port = htons((uint16_t)port_c);

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
	info.vhost_name = "dht-krpc-c";
	vh_c = lws_create_vhost(cx, &info);
	if (!vh_a || !vh_b || !vh_c) {
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

	/* C claims B's id from another endpoint */

	di.vhost	= vh_c;
	di.cb		= NULL;
	di.name		= "krpc-c";
	di.port		= port_c;
	{
		lws_dht_hash_t *id = lws_dht_hash_create(
				LWS_DHT_HASH_TYPE_SHA1, 20, idb);
		di.id = id;
		dht_c = lws_dht_create(&di);
		lws_dht_hash_destroy(&id);
	}

	if (!dht_a || !dht_b || !dht_c) {
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
			if (sv.dup_sub) {
				lwsl_err("A's renewed subscription took a second "
					 "slot on B\n");
				fails++;
			}
			if (!sv.notified || !sv.notify_ok) {
				lwsl_err("B's notify never reached subscriber A\n");
				fails++;
			} else if (!sv.acked) {
				lwsl_err("A's notify ack never cleared B's pending "
					 "notification\n");
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
			if (!sv.extip_ok || sv.extip_bad) {
				lwsl_err("A did not learn its external address "
					 "from B\n");
				fails++;
			}
			if (!sv.samid_ok || sv.samid_bad) {
				lwsl_err("C's use of B's id moved or hid B's "
					 "entry in A\n");
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
