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
 *    LWS_DHT_EVENT_TOKEN callback, naming the hash A subscribed to
 *  - A returns that token in a subscribe_confirm with a 16-byte tid, so B
 *    registers A as a subscriber; B's notify reaches A, and A's ack (which
 *    echoes the 16-byte tid) clears B's pending notification, so notifying
 *    the same content again finds nothing to send.  A confirms twice, with
 *    different tids: that renews its one subscription, so B notifies once
 *  - lws_dht_foreach_node() shows B in A's table as good, at B's port,
 *    having answered A
 *  - A's neighbourhood maintenance issues a find_node to its only node
 *    within a few seconds (tx_find_node on A, rx_find_node on B)
 *  - a reliable-transport data datagram from A is reassembled by B's
 *    sequencer and delivered verbatim to B's event callback
 *  - a CAP_REQ from A over the same transport is answered by B's CAP_RSP,
 *    sent back over the sequencer B made for A when A spoke first
 *  - data A sends to a port nobody listens on is retransmitted until the
 *    retry policy runs out, and then reported as LWS_DHT_EVENT_WRITE_FAILED
 *  - once B is a good node for A, A probes it for A's external address:
 *    the probe's nonce survives the round trip, and in a two-node network
 *    the one other node is the quorum, so A learns 127.0.0.1:port-a from B
 *  - a third context C that uses B's node id pings A from its own port once
 *    B is good for A: A answers it, but B's entry keeps B's endpoint, so the
 *    good node A hands out for that id is still B, and A warns that the id
 *    is claimed from two places
 *  - a plain UDP socket R asks B a find_node with no target; B refuses it
 *    with a BEP 5 error reply, which must be exactly the bencode
 *    d1:eli203e<len>:<message>e1:t<tid>1:y1:ee.  R then relays B's refusal
 *    verbatim to A, as a peer refusing A would, and A's parser reports it as
 *    LWS_DHT_EVENT_ERROR with the code, message and tid, not as a drop
 *
 * The UDP ports (four to listen on, one left unused) are allocated uniquely
 * at build time and passed in on the command line, so parallel ctest
 * instances do not collide.
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

static struct sockaddr_in sa_a, sa_b, sa_c, sa_dead;

static const char *data_msg = "PUT 0102030405 0 5 hello";
static const char *cap_req = "CAP_REQ 0102030405 0 0 ";
static size_t data_msg_len;

static uint8_t token[40];
static size_t token_len;

/*
 * R's raw KRPC: the query it asks B, the message B refuses it with, and the
 * one datagram R has waiting to go out and where to
 */
static const char raw_query_head[] = "d1:ad2:id20:";
static const char raw_query_tail[] = "e1:q9:find_node1:t2:aa1:y1:qe";
static const char err_msg[] = "find_node with no target";
static struct lws *wsi_raw;
static uint8_t raw_tx[128];
static size_t raw_tx_len;
static struct sockaddr_in raw_tx_to;

struct seen {
	unsigned char token_ok:1;	/* A got B's get_peers token */
	unsigned char token_ih_bad:1;	/* ... for some other hash */
	unsigned char table_ok:1;	/* foreach shows B good in A's table */
	unsigned char confirmed:1;	/* A sent B its subscribe_confirm */
	unsigned char notified:1;	/* B sent A a notify */
	unsigned char notify_ok:1;	/* A got B's notify */
	unsigned char acked:1;		/* A's ack cleared B's pending notify */
	unsigned char dup_sub:1;	/* B notified A more than once */
	unsigned char data_ok:1;	/* B got A's data payload verbatim */
	unsigned char ping_sent:1;
	unsigned char searched:1;
	unsigned char data_sent:1;
	unsigned char cap_ok:1;		/* A got B's CAP_RSP */
	unsigned char dead_sent:1;	/* A sent data to the unused port */
	unsigned char dead_failed:1;	/* ...and was told it failed */
	unsigned char probed:1;		/* A asked B for its external address */
	unsigned char extip_ok:1;	/* ...and learnt it */
	unsigned char extip_bad:1;	/* ...or learnt something else */
	unsigned char samid_sent:1;	/* C pinged A using B's id */
	unsigned char samid_ok:1;	/* ...and A still has B at B */
	unsigned char samid_bad:1;	/* ...or A moved B's entry */
	unsigned char raw_up:1;		/* R's socket is bound */
	unsigned char err_asked:1;	/* R asked B a find_node with no target */
	unsigned char err_wire_ok:1;	/* B's refusal is well-formed bencode */
	unsigned char err_wire_bad:1;	/* ...or it is not */
	unsigned char err_decoded_ok:1;	/* A decoded the relayed refusal */
	unsigned char err_decoded_bad:1;/* ...or decoded something else */
};

static struct seen sv;
static int samid_warned;

/* A's warning that B's id was claimed from C's endpoint too */

static void
emit_cb(int level, const char *line)
{
	if ((level & LLL_WARN) && strstr(line, "claimed from"))
		samid_warned = 1;

	lwsl_emit_stderr(level, line);
}
static int retcode = 1;

static lws_dht_hash_t *
sub_hash(void);

static int
table_b_cb(void *user, const lws_dht_node_info_t *ni)
{
	const struct sockaddr_in *sin = (const struct sockaddr_in *)ni->sa;

	if (ni->sa->sa_family == AF_INET && sin->sin_port == sa_b.sin_port &&
	    ni->good && ni->replied >= 0 && ni->heard >= 0 &&
	    ni->id->len == 20 && ni->id->id[0] == 0x22)
		*(int *)user = 1;

	return 0;
}

static void
cb_a(void *closure, int event, const lws_dht_hash_t *info_hash,
     const void *data, size_t data_len, const struct sockaddr *from,
     size_t fromlen)
{
	lws_dht_hash_t *ih;

	(void)closure;
	(void)from;
	(void)fromlen;

	switch (event) {
	case LWS_DHT_EVENT_TOKEN:
		/*
		 * B's subscribe reply carries the anti-spoof token, reported
		 * with the hash we subscribed to: that is what we must
		 * confirm with it
		 */
		if (data_len == 8 && !sv.token_ok) {
			ih = sub_hash();
			if (!ih || !info_hash || info_hash->len != ih->len ||
			    info_hash->type != ih->type ||
			    memcmp(info_hash->id, ih->id, ih->len))
				sv.token_ih_bad = 1;
			if (ih)
				lws_dht_hash_destroy(&ih);
			memcpy(token, data, data_len);
			token_len = data_len;
			sv.token_ok = 1;
		}
		break;
	case LWS_DHT_EVENT_NOTIFY:
		sv.notify_ok = 1;
		break;
	case LWS_DHT_EVENT_WRITE_FAILED:
		if (from && fromlen >= sizeof(sa_dead) &&
		    ((const struct sockaddr_in *)from)->sin_port ==
							sa_dead.sin_port)
			sv.dead_failed = 1;
		break;
	case LWS_DHT_EVENT_DATA:
		/* A registered no verbs, so B's CAP_RSP comes to us whole */
		if (data_len > 8 && !memcmp(data, "CAP_RSP ", 8))
			sv.cap_ok = 1;
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
	case LWS_DHT_EVENT_ERROR: {
		const struct lws_dht_error_info *ei =
				(const struct lws_dht_error_info *)data;

		/* B's refusal, relayed by R: code, message and tid intact */
		if (data_len == sizeof(*ei) && ei->code == 203 &&
		    ei->message_len == strlen(err_msg) &&
		    !memcmp(ei->message, err_msg, ei->message_len) &&
		    ei->tid_len == 2 && !memcmp(ei->tid, "aa", 2))
			sv.err_decoded_ok = 1;
		else {
			lwsl_err("%s: unexpected error reply report\n",
				 __func__);
			sv.err_decoded_bad = 1;
		}
		break;
	}
	default:
		break;
	}
}

/*
 * R: a plain UDP socket speaking KRPC by hand, the peer the DHT contexts
 * cannot be made to be.  It sends whatever was queued in raw_tx when the
 * event loop lets it, and inspects what B answers.
 */

static void
raw_queue(const void *buf, size_t len, const struct sockaddr_in *to)
{
	if (len > sizeof(raw_tx)) {
		lwsl_err("%s: %u bytes too long to queue\n", __func__,
			 (unsigned int)len);
		return;
	}

	memcpy(raw_tx, buf, len);
	raw_tx_len = len;
	raw_tx_to = *to;
	lws_callback_on_writable(wsi_raw);
}

static int
cb_raw(struct lws *wsi, enum lws_callback_reasons reason, void *user,
       void *in, size_t len)
{
	const struct lws_udp *udp;
	lws_sockfd_type fd;
	char exp[96];
	ssize_t n;

	(void)user;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		sv.raw_up = 1;
		break;

	case LWS_CALLBACK_RAW_RX:
		udp = lws_get_udp(wsi);
		if (!udp || udp->sa46.sa4.sin_family != AF_INET ||
		    udp->sa46.sa4.sin_port != sa_b.sin_port)
			break;

		/*
		 * B's refusal of our target-less find_node: BEP 5 wants the
		 * "e" member to be a list of the code and the message, and the
		 * tid we chose echoed back.  B has no "v" to add.
		 */
		n = lws_snprintf(exp, sizeof(exp),
				 "d1:eli203e%u:%se1:t2:aa1:y1:ee",
				 (unsigned int)strlen(err_msg), err_msg);
		if (len == (size_t)n && !memcmp(in, exp, len))
			sv.err_wire_ok = 1;
		else {
			lwsl_err("%s: B's error reply is not the expected "
				 "bencode\n", __func__);
			lwsl_hexdump_err(in, len);
			sv.err_wire_bad = 1;
		}

		/* relay it to A as it stands, as a peer refusing A would */
		raw_queue(in, len, &sa_a);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!raw_tx_len)
			break;

		fd = lws_get_socket_fd(wsi);
		if (fd == LWS_SOCK_INVALID) {
			lwsl_err("%s: no socket to send on\n", __func__);
			raw_tx_len = 0;
			break;
		}
		n = sendto(fd,
#if defined(WIN32)
			   (const char *)
#endif
			   raw_tx,
#if defined(WIN32)
			   (int)
#endif
			   raw_tx_len, 0, (const struct sockaddr *)&raw_tx_to,
			   sizeof(raw_tx_to));
		if (n != (ssize_t)raw_tx_len)
			lwsl_err("%s: sendto returned %d\n", __func__, (int)n);
		raw_tx_len = 0;
		break;

	default:
		break;
	}

	return 0;
}

/*
 * Once B is known to be answering, R asks it a find_node that has no target;
 * B must refuse that with a 203 rather than walk its table against nothing.
 */

static void
error_reply_step(const struct lws_dht_stats *sb)
{
	uint8_t q[sizeof(raw_query_head) - 1 + 20 + sizeof(raw_query_tail) - 1];
	uint8_t *p = q;

	if (!sv.raw_up || !sb->rx_ping || sv.err_asked)
		return;

	sv.err_asked = 1;

	memcpy(p, raw_query_head, sizeof(raw_query_head) - 1);
	p += sizeof(raw_query_head) - 1;
	memset(p, 0x33, 20); /* R's node id */
	p += 20;
	memcpy(p, raw_query_tail, sizeof(raw_query_tail) - 1);

	raw_queue(q, sizeof(q), &sa_b);
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
	if (num != 1 || sin[0].sin_port != sa_b.sin_port) {
		lwsl_err("%s: A's node for B's id moved (%d good)\n",
			 __func__, num);
		sv.samid_bad = 1;
		return;
	}
#if (_LWS_ENABLED_LOGS & LLL_WARN)
	if (!samid_warned) {
		lwsl_err("%s: A didn't warn of B's id from C\n", __func__);
		sv.samid_bad = 1;
		return;
	}
#endif
	sv.samid_ok = 1;
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
		lws_dht_send_data(dht_a, (struct sockaddr *)&sa_b,
				  cap_req, strlen(cap_req));
	}

	subscription_step();
	same_id_step();
	error_reply_step(&sb);

	if (sv.data_ok && !sv.dead_sent) {
		sv.dead_sent = 1;
		lws_dht_send_data(dht_a, (struct sockaddr *)&sa_dead,
				  data_msg, data_msg_len);
	}

	/*
	 * A only probes nodes it holds as good, and B becomes good by
	 * answering A's maintenance find_node
	 */

	if (!sv.probed) {
		int good = 0, seen = 0;

		lws_dht_nodes(dht_a, AF_INET, &good, NULL, NULL, NULL);
		if (good) {
			lws_dht_foreach_node(dht_a, AF_INET, table_b_cb, &seen);
			sv.table_ok = !!seen;
			sv.probed = 1;
			lws_dht_test_external_ips(dht_a);
		}
	}

	/*
	 * Everything observable has been seen: B answered the ping, the
	 * subscribe round trip produced a token, the notify was acked, the
	 * data payload arrived verbatim, A's maintenance find_node probe
	 * reached B, B told A its external address, C's use of B's id did
	 * not move B's entry in A's table, and B's refusal of R's broken
	 * find_node was well-formed on the wire and understood by A.
	 */

	if (sv.token_ok && !sv.token_ih_bad && sv.table_ok && sv.acked &&
	    !sv.dup_sub &&
	    sv.data_ok && sv.cap_ok &&
	    sv.dead_failed &&
	    sv.extip_ok && !sv.extip_bad &&
	    sv.samid_ok && !sv.samid_bad &&
	    sv.err_wire_ok && !sv.err_wire_bad &&
	    sv.err_decoded_ok && !sv.err_decoded_bad &&
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
		{ "krpc-raw", cb_raw, 0, 0, 0, NULL, 0 },
		LWS_PROTOCOL_LIST_TERM
	};
	uint8_t ida[20], idb[20];
	const char *p;
	int port_a = 0, port_b = 0, port_c = 0, port_r = 0, port_dead = 0,
	    n = 0;

	lws_context_info_defaults(&info, NULL);
	/* the builtin options keep the emit function we set here */
	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, emit_cb);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "--port-a")))
		port_a = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-b")))
		port_b = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-c")))
		port_c = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-r")))
		port_r = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-dead")))
		port_dead = atoi(p);

	if (port_a < 1 || port_a > 65535 || port_b < 1 || port_b > 65535 ||
	    port_c < 1 || port_c > 65535 || port_r < 1 || port_r > 65535 ||
	    port_dead < 1 || port_dead > 65535 ||
	    port_a == port_b || port_a == port_c || port_b == port_c ||
	    port_r == port_a || port_r == port_b || port_r == port_c ||
	    port_dead == port_a || port_dead == port_b || port_dead == port_c ||
	    port_dead == port_r) {
		lwsl_err("usage: --port-a <udp port> --port-b <udp port> "
			 "--port-c <udp port> --port-r <udp port> "
			 "--port-dead <unused udp port>\n");
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
	sa_dead = sa_a;
	sa_dead.sin_port = htons((uint16_t)port_dead);

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
	di.allow_private_ads = 1; /* the nodes are all on loopback */
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

	/* R: the hand-driven KRPC peer */

	wsi_raw = lws_create_adopt_udp(vh_c, "127.0.0.1", port_r,
				       LWS_CAUDP_BIND, protocols[1].name, NULL,
				       NULL, NULL, NULL, "krpc-r");
	if (!wsi_raw) {
		lwsl_err("raw udp socket creation failed\n");
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
			if (!sv.table_ok) {
				lwsl_err("A's table didn't show B as a good "
					 "node that answered it\n");
				fails++;
			}
			if (sv.token_ih_bad) {
				lwsl_err("A's subscription token was not reported "
					 "with the hash it subscribed to\n");
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
			if (!sv.cap_ok) {
				lwsl_err("B never answered A's CAP_REQ\n");
				fails++;
			}
			if (!sv.dead_failed) {
				lwsl_err("data to a dead port never failed\n");
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
			if (!sv.err_wire_ok || sv.err_wire_bad) {
				lwsl_err("B's error reply was not well-formed "
					 "bencode\n");
				fails++;
			}
			if (!sv.err_decoded_ok || sv.err_decoded_bad) {
				lwsl_err("A did not decode the relayed error "
					 "reply\n");
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
