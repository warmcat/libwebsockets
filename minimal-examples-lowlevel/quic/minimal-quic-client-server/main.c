/*
 * lws-minimal-quic-client-server
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates the native libwebsockets QUIC transport implementation,
 * instantiating a server via lejp-conf, and optionally a client that links up
 * and passes bulk bidirectional data.
 *
 * With --relay <port>, the client reaches the server through a UDP relay in
 * this process that sends each direction's datagrams on in batches, last
 * first, so both ends see the handshake and the stream data out of order and
 * have to reassemble it.  --write-size sets how much each lws_write() sends,
 * so small values make many small STREAM frames.  With --stray as well,
 * the relay also sends the client, now and then, a datagram that belongs to
 * some other QUIC connection, which the client must ignore.  With --outage
 * <ms>, once the client's first Initial has gone through, the relay loses
 * everything the client sends for that long except its Initial packets, so
 * the server's handshake has to survive a spell of never getting the
 * client's Finished.  With --early-1rtt, the relay sends the client's first
 * 1-RTT packet to the server ahead of its Finished, and the server must hold
 * it until its handshake completes rather than lose it.  With --forwarder,
 * copies of the client's small packets also reach the server first from
 * another address that never answers, and the server must not keep probing
 * that address.  With --pmtu <bytes>, the relay loses datagrams bigger than
 * that, as a path with a smaller MTU would, and each side must find the
 * biggest size the path carries, and stop probing past it.  With --blackhole,
 * the path's MTU falls to the base once each side is sending bigger packets,
 * and each must find that out and go back to the base, or its transfer stalls.
 * --spread <ms> has
 * the client spread its writes over that long, rather than send as fast as it
 * can.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static struct lws_context *context;
static int result = 1; /* 1 means failed/timeout, 0 means success */
static int server_only = 0;
static size_t write_size = 1024;
/* --spread: the client spreads its writes over this long, from established */
static lws_usec_t spread_us, spread_start;

static const struct lws_http_mount mount_redir = {
	.mountpoint = "/",
	.origin = "warmcat.com/git/blog",
	.origin_protocol = LWSMPRO_REDIR_HTTPS,
	.mountpoint_len = 1,
	.exact_match = 1,
};

static const char * const test_cert =
"-----BEGIN CERTIFICATE-----\n"
"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\n"
"e2Hl/7M0c/lbZ4FvXgARlex2rkgS0Ka06HE=\n"
"-----END CERTIFICATE-----\n";

static const char * const test_key =
"-----BEGIN PRIVATE KEY-----\n"
"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\n"
"fBrpEY1IATtPq1taBZZogRqI3rOkkPk=\n"
"-----END PRIVATE KEY-----\n";

#define TOTAL_DATA (128 * 1024)

/*
 * The reordering relay.  Datagrams from the server go to the client, all
 * others go to the server, and the client is whoever sent us one last.  Each
 * direction holds up to RELAY_BATCH, and sends them on last first when that
 * many arrived or RELAY_HOLD_US after the first one, so a lone datagram, such
 * as the client's first Initial, is only delayed.  A datagram arriving while
 * its direction is full is dropped, which QUIC recovers from like any loss.
 */

#define RELAY_BATCH	4
#define RELAY_HOLD_US	(2 * LWS_US_PER_MS)
#define RELAY_DGRAM_MAX	2048

/*
 * With --stray, ahead of every RELAY_STRAY_EVERY-th batch to the client,
 * starting with the first, which carries the server's first Initial, the relay
 * sends the client a stray long header packet (RFC 9000 17.2) of some other
 * connection: connection IDs that are not the client's, alternately in QUIC
 * v2 and v1, and a payload nobody has keys for.  Packets like that are an
 * ordinary network event; the client must drop them without them changing
 * anything about its own connection, before or after its handshake.
 */
#define RELAY_STRAY_EVERY	8

/*
 * With --outage <ms>, once the relay has passed on the client's first
 * datagram, its first Initial, it loses everything from the client for that
 * long except its Initial packets, as a run of corrupted packets would: a
 * datagram's packets after its Initial ones are blanked to padding, and one
 * with no Initial packet at the front is dropped.  The server hears the
 * client acknowledge its Initial, so it has an RTT sample, but never gets the
 * client's Finished, which is in a Handshake packet.  It must keep probing
 * and keep the half-open connection while it waits within its handshake
 * deadline, so the handshake completes when the client's retransmissions get
 * through again.
 */

#define QUIC_V2		0x6b3343cfu
#define RELAY_CID_MAX	20	/* RFC 9000 17.2: a v1 CID is up to 20 bytes */

/*
 * With --early-1rtt, the relay passes datagrams on as they come, except that
 * after the client's first Initial, it holds the datagrams the client sends
 * Handshake packets in, with its Finished, until the client's first 1-RTT
 * datagram has gone on ahead of them.  So the server
 * gets that 1-RTT packet, which has the start of the client's stream data,
 * before its handshake has completed.  Then for RELAY_EARLY_WINDOW_US the
 * relay loses the client's other 1-RTT datagrams, so nothing the client sends
 * again can stand in for that one: by the end of it, the server must have the
 * start of the stream, which it can only have from the packet that came
 * early, held until its handshake completed and then processed.
 */
#define RELAY_EARLY_WINDOW_US	(1 * LWS_US_PER_SEC)

/*
 * With --forwarder, the relay also has a second socket, the forwarder, and
 * sends the server a copy of each of the client's 1-RTT datagrams up to
 * RELAY_FWD_SMALL bytes, eg, its ACKs, from there, ahead of the original: as
 * an off-path attacker who sees the client's packets, or a broken middlebox,
 * might.  The copy is new and authentic to the server, so it looks like the
 * client moved there (RFC 9000 9.3), and the server probes the forwarder's
 * address with a PATH_CHALLENGE, which the forwarder never answers; the
 * original arriving after it is a duplicate.
 *
 * The server must stay on the validated path, so the transfer completes.  A
 * probe sends its PATH_CHALLENGE again no more than once a PTO, at least
 * 500ms, and gives up after 3 PTOs (RFC 9000 8.2.1, 8.2.4), however fast the
 * client's packets come; once it failed, the server doesn't probe the
 * forwarder again for 1s, doubling each time it fails again, however many
 * more packets come from it.
 *
 * Use it with a small --write-size, eg, 64, so the client sends plenty of
 * small packets, and spread them with --spread, eg, 12000, so the copies keep
 * coming for long enough to see the server probe, fail and wait several
 * times.  Over the time the server sent the forwarder anything, it may have
 * started a probe each time the last one, of at least 1.5s, and the wait
 * after it were over, and each probe sends at most 3 datagrams: the test
 * fails if it sent more than that allows, plus one probe for slack.  A server
 * that resends the challenge each time it's lost, which is as fast as the
 * client's packets are acked, sends dozens more; one that probes again at
 * once after failing sends about twice as many over the span.  It also fails
 * if fewer than RELAY_FWD_COPIES_MIN copies were made, so it didn't test
 * much.
 */
#define RELAY_FWD_SMALL		100
#define RELAY_FWD_COPIES_MIN	50
#define RELAY_FWD_PROBE_US	(1500 * LWS_US_PER_MS)
#define RELAY_FWD_WAIT_US	LWS_US_PER_SEC
#define RELAY_FWD_PROBE_DGRAMS	3

/*
 * With --pmtu <bytes>, the relay passes datagrams on as they come, but loses
 * any bigger than that, as a path whose MTU is that much more than the IP and
 * UDP headers would.  Each side probes for bigger sizes once its handshake
 * completed (RFC 9000 14.3), in probes of their own, so whatever else it has
 * to send: lws probes an IP MTU of RELAY_PMTU_FIRST, then up in
 * RELAY_PMTU_STEP to RELAY_PMTU_CEILING, as datagrams RELAY_PMTU_OVERHEAD
 * smaller, and gives up on a size after losing RELAY_PMTU_MAX_PROBES probes
 * of it.  By the end of the transfer, the biggest datagram each side sent
 * must be the biggest of those sizes that the path carries, and it must not
 * have lost more probes than that.
 */
#define RELAY_PMTU_FIRST	1380
#define RELAY_PMTU_STEP		100
#define RELAY_PMTU_CEILING	1500
#define RELAY_PMTU_OVERHEAD	48
#define RELAY_PMTU_MAX_PROBES	3

/*
 * With --blackhole, the relay passes datagrams on as they come, until it has
 * passed RELAY_BH_AFTER datagrams bigger than RELAY_BH_BASE in a direction,
 * which the base IP MTU, 1280, carries.  Then it loses every datagram bigger
 * than that in that direction, as a path whose MTU fell to the base would,
 * without telling anyone.  Each side must see the big packets it sends are
 * lost, and go back to the base (RFC 8899 4.3), confirming with a probe of
 * the base size that small packets still get through, so the transfer
 * completes.  The test fails if a direction never had the black hole, since
 * then nothing was tested.
 */
#define RELAY_BH_AFTER		10
#define RELAY_BH_BASE		(1280 - RELAY_PMTU_OVERHEAD)

/* a QUIC varint (RFC 9000 16), 0 if it fits in len */
static int
relay_varint(const uint8_t *p, size_t len, size_t *used, uint64_t *v)
{
	size_t n, m;

	if (!len)
		return 1;
	n = (size_t)1 << (p[0] >> 6);
	if (n > len)
		return 1;

	*v = p[0] & 0x3f;
	for (m = 1; m < n; m++)
		*v = (*v << 8) | p[m];
	*used = n;

	return 0;
}

/*
 * Keep the Initial packets at the front of the datagram and blank the rest
 * to padding, keeping its size, since a server only takes an Initial from a
 * datagram of at least 1200 bytes.  Returns 0 if there is nothing to keep.
 */
static int
relay_keep_initials(uint8_t *b, size_t len)
{
	size_t o = 0, q, n, u;
	uint64_t v;

	while (o < len && len - o >= 7) {
		const uint8_t *p = b + o;
		size_t r = len - o;
		uint32_t ver;

		if (!(p[0] & 0x80))
			break; /* a short header, or the padding */

		ver = ((uint32_t)p[1] << 24) | ((uint32_t)p[2] << 16) |
		      ((uint32_t)p[3] << 8) | p[4];
		/* the Initial's type bits are 0 in v1 and 1 in v2 */
		if (((p[0] >> 4) & 3) != (ver == QUIC_V2 ? 1 : 0))
			break;

		/*
		 * The DCID, then the SCID.  Each length is checked before it
		 * moves q, so q always indexes inside the packet.
		 */
		q = 5;
		if (p[q] > RELAY_CID_MAX)
			break;
		n = q + 1u + p[q];
		if (n >= r)
			break;
		q = n;
		if (p[q] > RELAY_CID_MAX)
			break;
		n = q + 1u + p[q];
		if (n >= r)
			break;
		q = n;

		/* the token, then the rest of the packet */
		if (relay_varint(p + q, r - q, &u, &v) || v > r - q - u)
			break;
		n = q + u + (size_t)v;
		if (n >= r)
			break;
		q = n;
		if (relay_varint(p + q, r - q, &u, &v) || v > r - q - u)
			break;
		n = q + u + (size_t)v;
		if (n > r)
			break;
		o += n;
	}

	if (!o || o > len)
		return 0;

	memset(b + o, 0, len - o);

	return 1;
}

struct relay_dgram {
	size_t			len;
	uint8_t			buf[RELAY_DGRAM_MAX];
};

struct relay_dir {
	lws_sorted_usec_list_t	sul;
	struct relay_dgram	q[RELAY_BATCH];
	lws_sockaddr46		dest;
	int			count;
	char			due;

	/* what became of the datagrams, for the report if it stalls */
	unsigned int		sent;
	unsigned int		dropped;

	size_t			largest;	/* --pmtu: passed on */
	unsigned int		big;		/* --blackhole: passed on */
};

static struct {
	struct lws		*wsi;
	struct relay_dir	dir[2]; /* to the server, to the client */
	lws_usec_t		outage_us;
	lws_usec_t		outage_start;

	/* --early-1rtt */
	lws_sorted_usec_list_t	sul_early;
	struct relay_dgram	early_q[RELAY_BATCH];
	lws_usec_t		early_start;
	int			early_count;
	char			early_1rtt;
	char			early_swapped;
	unsigned int		batches_to_client;
	unsigned int		strays;
	char			stray;

	/* --forwarder */
	struct lws		*fwd_wsi;
	unsigned int		fwd_copies;	/* we sent the server */
	unsigned int		fwd_rx;		/* the server sent us */
	lws_usec_t		fwd_rx_first;
	lws_usec_t		fwd_rx_last;
	char			forwarder;

	size_t			pmtu;		/* --pmtu */
	char			blackhole;
} relay;

static void
relay_send(lws_sockfd_type fd, const uint8_t *buf, size_t len,
	   const lws_sockaddr46 *dest)
{
	/* UDP send failures are losses QUIC recovers from */
	if (sendto(fd,
#if defined(WIN32)
		   (const char *)
#endif
		   buf,
#if defined(WIN32)
		   (int)
#endif
		   len, 0, sa46_sockaddr(dest), sa46_socklen(dest)) < 0)
		lwsl_info("relay: sendto failed\n");
}

static void
relay_send_stray(struct lws *wsi, lws_sockfd_type fd,
		 const lws_sockaddr46 *dest)
{
	uint8_t d[57];
	int v2 = !(relay.strays++ & 1);

	/* random CIDs, packet number and payload... */
	if (lws_get_random(lws_get_context(wsi), d, sizeof(d)) != sizeof(d))
		return;

	/* ... in a Handshake packet's long header */
	d[0] = v2 ? 0xf1 : 0xe1;
	d[1] = v2 ? 0x6b : 0x00;
	d[2] = v2 ? 0x33 : 0x00;
	d[3] = v2 ? 0x43 : 0x00;
	d[4] = v2 ? 0xcf : 0x01;
	d[5] = 8;	/* DCID length, 8 random bytes follow */
	d[14] = 8;	/* SCID length, 8 random bytes follow */
	d[23] = 0x40;	/* 2-byte varint Length: the 32 bytes after it */
	d[24] = 32;

	relay_send(fd, d, sizeof(d), dest);
}

static void
early_1rtt_check_cb(lws_sorted_usec_list_t *sul);

/* --early-1rtt: what the relay does with each datagram, see above */

static void
relay_early_1rtt(struct lws *wsi, struct relay_dir *d, const uint8_t *in,
		 size_t len)
{
	lws_sockaddr46 *dest = &relay.dir[0].dest;
	lws_sockfd_type fd = lws_get_socket_fd(wsi);
	int m;

	if (fd == LWS_SOCK_INVALID)
		return;

	if (d == &relay.dir[1] || !d->sent || relay.early_swapped) {
		if (d == &relay.dir[0] && relay.early_swapped &&
		    !(in[0] & 0x80) &&
		    lws_now_usecs() - relay.early_start < RELAY_EARLY_WINDOW_US) {
			/* the client's other 1-RTT datagrams, for a while */
			d->dropped++;
			return;
		}
		/* the server's, the client's first Initial, or after */
		relay_send(fd, in, len, &d->dest);
		d->sent++;
		return;
	}

	if (in[0] & 0x80) {
		uint32_t ver = ((uint32_t)in[1] << 24) | ((uint32_t)in[2] << 16) |
			       ((uint32_t)in[3] << 8) | in[4];

		/*
		 * Its Initials go on, or the server would be held to its
		 * anti-amplification limit by too little from the client
		 */
		if (len < 5 || ((in[0] >> 4) & 3) != (ver == QUIC_V2 ? 3 : 2)) {
			relay_send(fd, in, len, dest);
			d->sent++;
			return;
		}

		/* its Handshake packets wait */
		if (relay.early_count == RELAY_BATCH) {
			d->dropped++;
			return;
		}
		relay.early_q[relay.early_count].len = len;
		memcpy(relay.early_q[relay.early_count++].buf, in, len);
		return;
	}

	/* its first 1-RTT datagram goes on ahead of them */
	relay_send(fd, in, len, dest);
	for (m = 0; m < relay.early_count; m++)
		relay_send(fd, relay.early_q[m].buf, relay.early_q[m].len,
			   dest);
	d->sent += 1u + (unsigned int)relay.early_count;
	relay.early_swapped = 1;
	relay.early_start = lws_now_usecs();
	lws_sul_schedule(lws_get_context(wsi), 0, &relay.sul_early,
			 early_1rtt_check_cb, RELAY_EARLY_WINDOW_US);
}

/* --pmtu: datagrams go on as they come, unless they're too big */

static void
relay_pmtu(struct lws *wsi, struct relay_dir *d, const uint8_t *in, size_t len)
{
	lws_sockfd_type fd = lws_get_socket_fd(wsi);

	if (fd == LWS_SOCK_INVALID)
		return;

	if (len > relay.pmtu) {
		d->dropped++;
		return;
	}

	if (len > d->largest)
		d->largest = len;
	relay_send(fd, in, len, &d->dest);
	d->sent++;
}

/* --blackhole: big datagrams go on, until they don't */

static void
relay_blackhole(struct lws *wsi, struct relay_dir *d, const uint8_t *in,
		size_t len)
{
	lws_sockfd_type fd = lws_get_socket_fd(wsi);

	if (fd == LWS_SOCK_INVALID)
		return;

	if (len > RELAY_BH_BASE) {
		if (d->big >= RELAY_BH_AFTER) {
			d->dropped++;
			return;
		}
		d->big++;
	}

	relay_send(fd, in, len, &d->dest);
	d->sent++;
}

static void
relay_due(struct relay_dir *d)
{
	d->due = 1;
	if (relay.wsi)
		lws_callback_on_writable(relay.wsi);
}

static void
relay_hold_cb(lws_sorted_usec_list_t *sul)
{
	relay_due(lws_container_of(sul, struct relay_dir, sul));
}

static int
callback_relay(struct lws *wsi, enum lws_callback_reasons reason,
	       void *user, void *in, size_t len)
{
	const struct lws_udp *udp;
	struct relay_dir *d;
	lws_sockfd_type fd;
	int n, m;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		relay.wsi = wsi;
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		relay.wsi = NULL;
		for (n = 0; n < 2; n++)
			lws_sul_cancel(&relay.dir[n].sul);
		lws_sul_cancel(&relay.sul_early);
		break;

	case LWS_CALLBACK_RAW_RX:
		udp = lws_get_udp(wsi);
		if (!udp || len > RELAY_DGRAM_MAX)
			break;

		if (!lws_sa46_compare_ads(&udp->sa46, &relay.dir[0].dest) &&
		    udp->sa46.sa4.sin_port == relay.dir[0].dest.sa4.sin_port)
			d = &relay.dir[1];
		else {
			relay.dir[1].dest = udp->sa46;
			d = &relay.dir[0];
		}

		if (relay.early_1rtt) {
			relay_early_1rtt(wsi, d, in, len);
			break;
		}

		if (relay.pmtu) {
			relay_pmtu(wsi, d, in, len);
			break;
		}

		if (relay.blackhole) {
			relay_blackhole(wsi, d, in, len);
			break;
		}

		if (d == &relay.dir[0] && relay.fwd_wsi &&
		    !(((const uint8_t *)in)[0] & 0x80) &&
		    len <= RELAY_FWD_SMALL) {
			/* the copy goes now, ahead of the original */
			fd = lws_get_socket_fd(relay.fwd_wsi);
			if (fd != LWS_SOCK_INVALID) {
				relay_send(fd, in, len, &d->dest);
				relay.fwd_copies++;
			}
		}

		if (d->count == RELAY_BATCH) {
			d->dropped++;
			break;
		}

		d->q[d->count].len = len;
		memcpy(d->q[d->count].buf, in, len);

		if (d == &relay.dir[0] && relay.outage_us && d->sent) {
			/* the outage starts after the first Initial */
			if (!relay.outage_start)
				relay.outage_start = lws_now_usecs();
			if (lws_now_usecs() - relay.outage_start <
							relay.outage_us &&
			    !relay_keep_initials(d->q[d->count].buf, len)) {
				d->dropped++;
				break;
			}
		}
		if (++d->count == RELAY_BATCH) {
			lws_sul_cancel(&d->sul);
			relay_due(d);
		} else if (d->count == 1)
			lws_sul_schedule(lws_get_context(wsi), 0, &d->sul,
					 relay_hold_cb, RELAY_HOLD_US);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		fd = lws_get_socket_fd(wsi);
		if (fd == LWS_SOCK_INVALID)
			break;

		for (n = 0; n < 2; n++) {
			d = &relay.dir[n];
			if (!d->due)
				continue;

			if (n == 1 && relay.stray &&
			    !(relay.batches_to_client++ % RELAY_STRAY_EVERY))
				relay_send_stray(wsi, fd, &d->dest);

			for (m = d->count - 1; m >= 0; m--)
				relay_send(fd, d->q[m].buf, d->q[m].len,
					   &d->dest);
			d->sent += (unsigned int)d->count;
			d->count = 0;
			d->due = 0;
		}
		break;

	default:
		break;
	}

	return 0;
}

/* --forwarder: whatever the server sends the forwarder goes no further */

static int
callback_relay_fwd(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		relay.fwd_wsi = wsi;
		break;
	case LWS_CALLBACK_RAW_CLOSE:
		relay.fwd_wsi = NULL;
		break;
	case LWS_CALLBACK_RAW_RX:
		relay.fwd_rx++;
		if (!relay.fwd_rx_first)
			relay.fwd_rx_first = lws_now_usecs();
		relay.fwd_rx_last = lws_now_usecs();
		break;
	default:
		break;
	}

	return 0;
}

static struct lws_protocols relay_protocols[] = {
	{ "quic-relay", callback_relay, 0, 0, 0, NULL, 0 },
	{ "quic-relay-fwd", callback_relay_fwd, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static size_t client_sent = 0;
static size_t client_rx = 0;
static uint32_t client_hash = 5381; /* djb2 init */
static int client_done = 0;

static size_t server_sent = 0;
static size_t server_rx = 0;
static uint32_t server_hash = 5381; /* djb2 init */
static int server_done = 0;

static lws_usec_t last_rx_us;
static char early_1rtt_failed;

/*
 * With --spread, the client spreads its writes over spread_us: if its next one
 * isn't due yet, it's told when it is
 */

static int
client_write_not_due(struct lws *wsi)
{
	lws_usec_t due = spread_start + (lws_usec_t)
			 ((uint64_t)spread_us * client_sent / TOTAL_DATA),
		   now = lws_now_usecs();

	if (due <= now)
		return 0;

	lws_set_timer_usecs(wsi, due - now);

	return 1;
}

/* --early-1rtt: the relay's window is over, see RELAY_EARLY_WINDOW_US */

static void
early_1rtt_check_cb(lws_sorted_usec_list_t *sul)
{
	if (server_rx) {
		lwsl_user("early 1-RTT: the server had %lu bytes from the "
			  "packet that came before its handshake completed\n",
			  (unsigned long)server_rx);
		return;
	}

	lwsl_err("early 1-RTT: the server lost the packet that came before "
		 "its handshake completed\n");
	early_1rtt_failed = 1;
}

static uint32_t
simple_hash(uint32_t hash, const uint8_t *data, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++)
		hash = (hash << 5) + hash + data[i]; /* hash * 33 + c */
	return hash;
}



/*
 * Each byte sent is a function of its stream offset, so the receiver can tell
 * the data came in the right order, with nothing lost or repeated
 */
static uint8_t
pattern_byte(size_t ofs)
{
	return (uint8_t)(ofs + (ofs >> 8));
}

static void
pattern_fill(size_t at, uint8_t *data, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		data[i] = pattern_byte(at + i);
}

static int
pattern_ok(size_t at, const uint8_t *data, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		if (data[i] != pattern_byte(at + i))
			return 0;

	return 1;
}

/* where each side and the relay had got to, when the transfer stalls */

static void
report_progress(void)
{
	int n;

	lwsl_err("client: sent %lu, rx %lu; server: sent %lu, rx %lu\n",
		 (unsigned long)client_sent, (unsigned long)client_rx,
		 (unsigned long)server_sent, (unsigned long)server_rx);

	if (!relay.wsi)
		return;

	for (n = 0; n < 2; n++)
		lwsl_err("relay to the %s: sent %u, dropped %u, "
			 "%d held%s\n", n ? "client" : "server",
			 relay.dir[n].sent, relay.dir[n].dropped,
			 relay.dir[n].count,
			 relay.dir[n].due ? ", due" : "");
}

/* --forwarder: how did the server treat the address that never answers? */

static int
forwarder_failed(void)
{
	lws_usec_t span = relay.fwd_rx_last - relay.fwd_rx_first, t = 0,
		   wait = RELAY_FWD_WAIT_US;
	unsigned int probes = 1;

	if (!relay.forwarder)
		return 0;

	/* the most probes it could start in the span, backing off */
	while (relay.fwd_rx && (t += RELAY_FWD_PROBE_US + wait) <= span) {
		probes++;
		wait *= 2;
	}

	lwsl_user("forwarder: sent the server %u copies, over %lldms it "
		  "sent us %u datagrams, up to %u allowed\n", relay.fwd_copies,
		  (long long)(span / LWS_US_PER_MS), relay.fwd_rx,
		  (probes + 1) * RELAY_FWD_PROBE_DGRAMS);

	if (relay.fwd_copies < RELAY_FWD_COPIES_MIN) {
		lwsl_err("forwarder: too few copies to test anything\n");
		return 1;
	}
	if (relay.fwd_rx > (probes + 1) * RELAY_FWD_PROBE_DGRAMS) {
		lwsl_err("forwarder: the server kept probing an address that "
			 "never answers\n");
		return 1;
	}

	return 0;
}

/* --pmtu: did each side find the size the path carries, and stop there? */

static int
pmtu_failed(void)
{
	size_t want = 0;
	int mtu, n, e = 0;

	if (!relay.pmtu)
		return 0;

	/* the biggest datagram the search can find on this path */
	for (mtu = RELAY_PMTU_FIRST; ; mtu += RELAY_PMTU_STEP) {
		if (mtu > RELAY_PMTU_CEILING)
			mtu = RELAY_PMTU_CEILING;
		if ((size_t)(mtu - RELAY_PMTU_OVERHEAD) > relay.pmtu)
			break;
		want = (size_t)(mtu - RELAY_PMTU_OVERHEAD);
		if (mtu == RELAY_PMTU_CEILING)
			break;
	}

	for (n = 0; n < 2; n++) {
		const struct relay_dir *d = &relay.dir[n];
		const char *who = n ? "server" : "client";

		lwsl_user("pmtu: the %s's biggest datagram was %lu (want %lu), "
			  "it lost %u bigger than %lu\n", who,
			  (unsigned long)d->largest, (unsigned long)want,
			  d->dropped, (unsigned long)relay.pmtu);

		if (d->largest != want) {
			lwsl_err("pmtu: the %s didn't find the size the path "
				 "carries\n", who);
			e = 1;
		}
		if (d->dropped > RELAY_PMTU_MAX_PROBES) {
			lwsl_err("pmtu: the %s kept sending datagrams too big "
				 "for the path\n", who);
			e = 1;
		}
	}

	return e;
}

/* --blackhole: did both sides send big packets into it? */

static int
blackhole_failed(void)
{
	int n, e = 0;

	if (!relay.blackhole)
		return 0;

	for (n = 0; n < 2; n++) {
		const struct relay_dir *d = &relay.dir[n];
		const char *who = n ? "server" : "client";

		lwsl_user("blackhole: the %s sent %u datagrams bigger than %d "
			  "before the black hole, and %u into it\n", who,
			  d->big, RELAY_BH_BASE, d->dropped);

		if (d->big < RELAY_BH_AFTER || !d->dropped) {
			lwsl_err("blackhole: the %s never had the black hole, "
				 "nothing was tested\n", who);
			e = 1;
		}
	}

	return e;
}

static void
teardown_cb(lws_sorted_usec_list_t *sul)
{
	if (!result)
		result = forwarder_failed() || pmtu_failed() ||
			 blackhole_failed();
	lws_default_loop_exit(context);
}

static lws_sorted_usec_list_t sul_teardown;

static void
check_test_completion(struct lws *wsi)
{
	if (client_done && server_done) {
		lwsl_notice("Test completed successfully! Both sides received full data. Waiting 1.5s for ACKs...\n");
		result = early_1rtt_failed;
		if (!server_only)
			lws_sul_schedule(lws_get_context(wsi), 0, &sul_teardown, teardown_cb, 1500 * 1000);
	}
}

/*
 * This is the application protocol callback for the QUIC stream data.
 */
static int
callback_quic_test(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_PROTOCOL_INIT:
	{
#if (_LWS_ENABLED_LOGS & LLL_INFO)
		struct lws_vhost *vh = lws_get_vhost(wsi);
		lwsl_vhost_info(vh, "Protocol init");
#endif
		break;
	}

	case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
		lwsl_wsi_info(wsi, "Server received new QUIC client connection!");
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lwsl_wsi_notice(wsi, "Client successfully established QUIC connection!");
		spread_start = lws_now_usecs();
		/* Trigger a write to send bulk data */
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_TIMER:
		/* --spread: the client's next write is due */
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
	{
		uint8_t buf[LWS_PRE + 1024];

		if (client_sent >= TOTAL_DATA || client_write_not_due(wsi))
			break;

		size_t to_send = TOTAL_DATA - client_sent;
		if (to_send > write_size)
			to_send = write_size;
		pattern_fill(client_sent, &buf[LWS_PRE], to_send);
                lwsl_wsi_info(wsi, "CLIENT WSI allowance=%d", (int)lws_get_peer_write_allowance(wsi));
		int n = lws_write(wsi, &buf[LWS_PRE], to_send, LWS_WRITE_BINARY);
                if (n > 0) {
                        client_sent += (size_t)n;
                        if (client_sent < TOTAL_DATA)
                                lws_callback_on_writable(wsi);
                }
		break;
	}
	case LWS_CALLBACK_ESTABLISHED:
		lwsl_wsi_notice(wsi, "SERVER ESTABLISHED!");
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
	{
		uint8_t buf[LWS_PRE + 1024];

		if (server_only)
			break;

		if (server_sent >= TOTAL_DATA)
                        break;
		size_t to_send = TOTAL_DATA - server_sent;
		if (to_send > write_size)
			to_send = write_size;
		pattern_fill(server_sent, &buf[LWS_PRE], to_send);
                lwsl_wsi_info(wsi, "SERVER WSI allowance=%d", (int)lws_get_peer_write_allowance(wsi));
		int n = lws_write(wsi, &buf[LWS_PRE], to_send, LWS_WRITE_BINARY);
		if (n > 0) {
			server_sent += (size_t)n;
			if (server_sent < TOTAL_DATA)
				lws_callback_on_writable(wsi);
		} else {
                        lwsl_err("SERVER WROTE FAILED n=%d\n", n);
		}
		break;
	}

	case LWS_CALLBACK_QT_CLIENT_RECEIVE:
	{
		last_rx_us = lws_now_usecs();

		if (!pattern_ok(client_rx, in, len)) {
			lwsl_wsi_err(wsi, "Client rx data wrong near offset %lu",
				     (unsigned long)client_rx);
			result = 1;
			lws_default_loop_exit(lws_get_context(wsi));
			return -1;
		}
		client_rx += len;
		client_hash = simple_hash(client_hash, in, len);
		if (client_rx >= TOTAL_DATA && !client_done) {
			lwsl_wsi_notice(wsi, "Client received all %lu bytes, hash %u", (unsigned long)client_rx, client_hash);
			client_done = 1;
			check_test_completion(wsi);
		}
		break;
	}

	case LWS_CALLBACK_QT_SERVER_RECEIVE:
	{
		last_rx_us = lws_now_usecs();

		if (!pattern_ok(server_rx, in, len)) {
			lwsl_wsi_err(wsi, "Server rx data wrong near offset %lu",
				     (unsigned long)server_rx);
			result = 1;
			lws_default_loop_exit(lws_get_context(wsi));
			return -1;
		}
		server_rx += len;
		server_hash = simple_hash(server_hash, in, len);
		if (server_rx >= TOTAL_DATA && !server_done) {
			lwsl_wsi_notice(wsi, "Server received all %lu bytes, hash %u", (unsigned long)server_rx, server_hash);
			server_done = 1;
			check_test_completion(wsi);
		}
		break;
	}

	default:
		break;
	}

	return 0;
}

static struct lws_protocols protocols[] = {
	{ "quic-test-protocol", callback_quic_test, 0, 2048, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

void sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

enum {
	LWS_SW_HELP,
	LWS_SW_URL,
	LWS_SW_PORT,
	LWS_SW_SERVER_ONLY,
	LWS_SW_SERVER,
	LWS_SW_RELAY,
	LWS_SW_STRAY,
	LWS_SW_OUTAGE,
	LWS_SW_EARLY_1RTT,
	LWS_SW_FORWARDER,
	LWS_SW_PMTU,
	LWS_SW_BLACKHOLE,
	LWS_SW_WRITE_SIZE,
	LWS_SW_SPREAD,
	LWS_SW_CUBIC,
};

static const struct lws_switches switches[] = {
	[LWS_SW_HELP]	= { "--help",	"Show this help information" },
	[LWS_SW_URL]	= { "-u",	"URL to connect to (if absent, acts as server too)" },
	[LWS_SW_PORT]	= { "-p",	"Port to connect to / listen on (default 7681)" },
	[LWS_SW_SERVER_ONLY] = { "-s",	"Server only mode (do not launch client, do not send data unprompted)" },
	[LWS_SW_SERVER]	= { "--server",	"Server address to connect to (default 127.0.0.1)" },
	[LWS_SW_RELAY]	= { "--relay",	"Connect via a relay on this port that reorders datagrams (needs a numeric --server)" },
	[LWS_SW_STRAY] = { "--stray",	"The relay also sends the client stray packets of another connection (needs --relay)" },
	[LWS_SW_OUTAGE] = { "--outage",	"After the client's first Initial, the relay loses all but its Initial packets for this many ms (needs --relay)" },
	[LWS_SW_EARLY_1RTT] = { "--early-1rtt", "The relay sends the client's first 1-RTT packet ahead of its Finished (needs --relay)" },
	[LWS_SW_FORWARDER] = { "--forwarder", "The relay also sends the server copies of the client's small packets from an address that never answers (needs --relay)" },
	[LWS_SW_PMTU]	= { "--pmtu",	"The relay loses datagrams bigger than this, 1200 to 2048, and checks both sides found the biggest size they can send (needs --relay)" },
	[LWS_SW_BLACKHOLE] = { "--blackhole", "Once each side sends bigger packets than an IP MTU of 1280 carries, the relay loses them all, and both sides must go back to 1280 (needs --relay)" },
	[LWS_SW_WRITE_SIZE] = { "--write-size", "Bytes sent per write, 1 to 1024 (default 1024)" },
	[LWS_SW_SPREAD] = { "--spread",	"The client spreads its writes over this many ms (default 0, as fast as it can)" },
	[LWS_SW_CUBIC]	= { "--cubic",	"Use the CUBIC congestion controller instead of the default NewReno" },
};

#if defined(WIN32) && defined(LWS_WITH_SCHANNEL)
#include <windows.h>
static int is_quic_supported_on_os(void) {
    OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0, {0}, 0, 0 };
    DWORDLONG const dwlConditionMask = VerSetConditionMask(
        VerSetConditionMask(
        VerSetConditionMask(
            0, VER_MAJORVERSION, VER_GREATER_EQUAL),
               VER_MINORVERSION, VER_GREATER_EQUAL),
               VER_BUILDNUMBER,  VER_GREATER_EQUAL);

    osvi.dwMajorVersion = 10;
    osvi.dwMinorVersion = 0;
    osvi.dwBuildNumber  = 20348; /* Windows Server 2022 */

    return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_BUILDNUMBER, dwlConditionMask) != FALSE;
}
#endif

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	struct lws *client_wsi;
	struct lws_vhost *vh;
	lws_usec_t start_us;
	char url_buf[128];
	const char *p, *prot, *address, *path;
	int port = 7681, relay_port = 0, outage_ms = 0, pmtu = 0;
	int url_port = 0;

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

#if defined(WIN32) && defined(LWS_WITH_SCHANNEL)
       // if (!is_quic_supported_on_os()) {
       //      lwsl_user("SChannel QUIC requires Windows 11+ / Server 2022+\n");
       //      return 0;
       // }
#endif

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}

	p = lws_cmdline_option(argc, argv, "-p");
	if (p)
		{
			int __pt = atoi(p);
			if (__pt < 0 || __pt > 65535) {
				lwsl_err("Port %d is outside valid 16-bit range\n", __pt);
				return 1;
			}
			port = __pt;
		}

	if (lws_cmdline_option(argc, argv, "-s"))
		server_only = 1;

	p = lws_cmdline_option(argc, argv, switches[LWS_SW_WRITE_SIZE].sw);
	if (p) {
		int ws = atoi(p);

		if (ws < 1 || ws > 1024) {
			lwsl_err("--write-size must be 1 to 1024\n");
			return 1;
		}
		write_size = (size_t)ws;
	}

	p = lws_cmdline_option(argc, argv, switches[LWS_SW_SPREAD].sw);
	if (p) {
		int ms = atoi(p);

		/* the transfer has to be done inside the 60s the test allows */
		if (ms < 0 || ms > 30000) {
			lwsl_err("--spread must be 0 to 30000\n");
			return 1;
		}
		spread_us = (lws_usec_t)ms * LWS_US_PER_MS;
	}

	p = lws_cmdline_option(argc, argv, switches[LWS_SW_RELAY].sw);
	if (p) {
		relay_port = atoi(p);
		if (relay_port < 1 || relay_port > 65535) {
			lwsl_err("--relay port %d is outside valid 16-bit range\n",
				 relay_port);
			return 1;
		}
	}

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_STRAY].sw) &&
	    !relay_port) {
		lwsl_err("--stray needs --relay\n");
		return 1;
	}

	p = lws_cmdline_option(argc, argv, switches[LWS_SW_OUTAGE].sw);
	if (p) {
		int ms = atoi(p);

		if (!relay_port) {
			lwsl_err("--outage needs --relay\n");
			return 1;
		}
		if (ms < 1 || ms > 60000) {
			lwsl_err("--outage must be 1 to 60000ms\n");
			return 1;
		}
		outage_ms = ms;
	}

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_EARLY_1RTT].sw) &&
	    (!relay_port || outage_ms)) {
		lwsl_err("--early-1rtt needs --relay, and not --outage\n");
		return 1;
	}

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_FORWARDER].sw) &&
	    (!relay_port || outage_ms ||
	     lws_cmdline_option(argc, argv, switches[LWS_SW_EARLY_1RTT].sw))) {
		lwsl_err("--forwarder needs --relay, and not --outage or "
			 "--early-1rtt\n");
		return 1;
	}

	p = lws_cmdline_option(argc, argv, switches[LWS_SW_PMTU].sw);
	if (p) {
		pmtu = atoi(p);

		if (!relay_port || outage_ms ||
		    lws_cmdline_option(argc, argv, switches[LWS_SW_STRAY].sw) ||
		    lws_cmdline_option(argc, argv, switches[LWS_SW_EARLY_1RTT].sw) ||
		    lws_cmdline_option(argc, argv, switches[LWS_SW_FORWARDER].sw)) {
			lwsl_err("--pmtu needs --relay, and not --stray, "
				 "--outage, --early-1rtt or --forwarder\n");
			return 1;
		}
		/* RFC 9000 14: every path carries 1200-byte datagrams */
		if (pmtu < 1200 || pmtu > RELAY_DGRAM_MAX) {
			lwsl_err("--pmtu must be 1200 to %d\n", RELAY_DGRAM_MAX);
			return 1;
		}
	}

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_BLACKHOLE].sw) &&
	    (!relay_port || outage_ms || pmtu ||
	     lws_cmdline_option(argc, argv, switches[LWS_SW_STRAY].sw) ||
	     lws_cmdline_option(argc, argv, switches[LWS_SW_EARLY_1RTT].sw) ||
	     lws_cmdline_option(argc, argv, switches[LWS_SW_FORWARDER].sw))) {
		lwsl_err("--blackhole needs --relay, and not --stray, --outage, "
			 "--early-1rtt, --forwarder or --pmtu\n");
		return 1;
	}

	p = lws_cmdline_option(argc, argv, "-u");
	if (p) {
		lws_strncpy(url_buf, p, sizeof(url_buf));
		if (lws_parse_uri(url_buf, &prot, &address, &url_port, &path)) {
			lwsl_err("Failed to parse URL\n");
			return 1;
		}
		port = url_port;
	} else {
		address = lws_cmdline_option(argc, argv, switches[LWS_SW_SERVER].sw);
	}

	signal(SIGINT, sigint_handler);

	info.port                               = 7681;
	info.protocols                          = protocols;
	info.options                            = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
                                                 LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
                                                 LWS_SERVER_OPTION_IPV6_V6ONLY_MODIFY |
                                                 0;
	if (lws_cmdline_option(argc, argv, switches[LWS_SW_CUBIC].sw))
		/* both the server and the client in this context use it */
		info.quic_cc_ops		= &lws_cc_ops_cubic;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (!p) {
		/*
		 * We instantiate the QUIC server vhost explicitly.
		 * We pass CONTEXT_PORT_NO_LISTEN_SERVER so it doesn't create a TCP listener!
		 */
		info.port			        = CONTEXT_PORT_NO_LISTEN_SERVER;
		info.vhost_name			        = "quic-server";
		info.listen_accept_role		        = "quic";
		info.listen_accept_protocol	        = "quic-test-protocol";
		info.alpn				= "h3,lws-quic";

		/* TLS 1.3 requires valid certificates for QUIC. Use our in-memory certs. */
		info.server_ssl_cert_mem	        = test_cert;
		info.server_ssl_cert_mem_len            = (unsigned int)strlen(test_cert);
		info.server_ssl_private_key_mem         = test_key;
		info.server_ssl_private_key_mem_len     = (unsigned int)strlen(test_key);
		info.mounts                             = &mount_redir;
	} else {
		info.port			        = CONTEXT_PORT_NO_LISTEN;
		info.vhost_name			        = "quic-client";
	}

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create QUIC vhost\n");
		goto bail;
	}

	if (!p) {
		/* Explicitly instantiate a UDP listener socket and bind it to QUIC! */
		if (!lws_create_adopt_udp(vh, NULL, port, LWS_CAUDP_BIND,
					  "quic-test-protocol", NULL, NULL, NULL,
					  NULL, "quic_listen")) {
			lwsl_err("Failed to bind QUIC UDP listener\n");
			goto bail;
		}
	}

	if (relay_port) {
		struct lws_context_creation_info ri;
		const char *ads = address ? address : "127.0.0.1";
		struct lws_vhost *rvh;

		if (p || server_only) {
			lwsl_err("--relay needs the server and client in this process\n");
			goto bail;
		}

		/* the relay sends to the server at the client's address */
		memset(&relay, 0, sizeof(relay));
		relay.stray = !!lws_cmdline_option(argc, argv,
					switches[LWS_SW_STRAY].sw);
		relay.outage_us = (lws_usec_t)outage_ms * LWS_US_PER_MS;
		relay.early_1rtt = !!lws_cmdline_option(argc, argv,
					switches[LWS_SW_EARLY_1RTT].sw);
		relay.forwarder = !!lws_cmdline_option(argc, argv,
					switches[LWS_SW_FORWARDER].sw);
		relay.pmtu = (size_t)pmtu;
		relay.blackhole = !!lws_cmdline_option(argc, argv,
					switches[LWS_SW_BLACKHOLE].sw);
		if (lws_sa46_parse_numeric_address(ads, &relay.dir[0].dest)) {
			lwsl_err("--relay needs a numeric --server address\n");
			goto bail;
		}
#if defined(LWS_WITH_IPV6)
		if (relay.dir[0].dest.sa4.sin_family == AF_INET6)
			relay.dir[0].dest.sa6.sin6_port = htons((uint16_t)port);
		else
#endif
			relay.dir[0].dest.sa4.sin_port = htons((uint16_t)port);

		memset(&ri, 0, sizeof(ri));
		ri.port		= CONTEXT_PORT_NO_LISTEN_SERVER;
		ri.vhost_name	= "quic-relay";
		ri.protocols	= relay_protocols;
		ri.options	= info.options;

		rvh = lws_create_vhost(context, &ri);
		if (!rvh || !lws_create_adopt_udp(rvh, ads, relay_port,
						  LWS_CAUDP_BIND, "quic-relay",
						  NULL, NULL, NULL, NULL,
						  "quic_relay")) {
			lwsl_err("Failed to create the relay\n");
			goto bail;
		}

		/* the forwarder's socket, on any free port */
		if (relay.forwarder &&
		    !lws_create_adopt_udp(rvh, ads, 0, LWS_CAUDP_BIND,
					  "quic-relay-fwd", NULL, NULL, NULL,
					  NULL, "quic_fwd")) {
			lwsl_err("Failed to create the forwarder\n");
			goto bail;
		}
	}

	if (!server_only) {
		/*
		 * Immediately launch the client.
		 */
		memset(&i, 0, sizeof(i));
		i.context		= context;
		i.port			= relay_port ? relay_port : port;
		i.address		= address ? address : "127.0.0.1";
		i.host			= address ? address : "localhost";
		i.origin		= i.address;
		i.vhost			= vh;
		i.ssl_connection	= LCCSCF_USE_SSL;
		if (!p) /* by default, we use our canned selfsigned cert for local tests */
			i.ssl_connection |= LCCSCF_ALLOW_SELFSIGNED |
					    LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
		i.protocol		= "quic-test-protocol";
		i.alpn			= "lws-quic";
		i.local_protocol_name	= "quic-test-protocol";
		i.method		= "QUIC";

		client_wsi = lws_client_connect_via_info(&i);
		if (!client_wsi) {
			lwsl_err("Client connection failed\n");
			goto bail;
		}
	}

	start_us = lws_now_usecs();
	last_rx_us = start_us;

        while (lws_service(context, 0) >= 0) {
		if (!server_only) {
			if (lws_now_usecs() - start_us > 60000000) {
				lwsl_err("Timeout waiting for QUIC transfer (60s absolute)\n");
				report_progress();
				result = 1;
				break;
			}
			if (lws_now_usecs() - last_rx_us > 15000000) {
				lwsl_err("Timeout waiting for QUIC transfer (15s idle RX)\n");
				report_progress();
				result = 1;
				break;
			}
		}
	}

bail:
	lws_context_destroy(context);

        return lws_cmdline_passfail(argc, argv, result);
}
