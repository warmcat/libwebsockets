/*
 * lws-api-test-ws-close
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Exercises the clean ws close handshake in both directions, over h1 and
 * over ws-over-h2 (RFC 8441), with a ws server vhost and a ws client in one
 * process, and checks that the close status code and reason reach the peer
 * intact and that both sides see their close callbacks.
 *
 * With --proxy host:port, --socks host:port and --socks-auth host:port it
 * additionally runs h1 legs through an http CONNECT proxy, a SOCKS5 proxy
 * with no auth and a SOCKS5 proxy requiring username/password; ctest runs it
 * that way against proxy-fixture.py in this directory.
 *
 * Before this test, no ctest performed a clean ws close at all: every ws
 * connection in the suite ended by dropping the socket, so the close
 * handshake states (LRS_WAITING_TO_SEND_CLOSE, LRS_RETURNED_CLOSE,
 * LRS_AWAITING_CLOSE_ACK) and the proxy connect states were never reached.
 *
 * With permessage-deflate built in, a leg also has the server close while
 * the inflater still holds output of a compressed message it is partway
 * through, the ordinary case of an app refusing a message it has only seen
 * the start of.
 *
 * Three legs have the client stop reading (rx flow control) while the
 * server fills the connection, then send the server more than it reads at
 * once: the server sending a big message with pmd (it may not read until
 * that has gone), and the server closing on the first part of the client's
 * data with its tx still buffered, or with its socket full so its Close
 * frame has to wait (it reads nothing more either way).  The server must
 * wait quietly until the client reads again, then finish, and the client
 * must get all the server wrote before closing, although the server closed
 * with the client's data unread.
 *
 * Every leg must finish its close promptly and without the service loop
 * spinning meanwhile: a close handshake that only ends at its timeout, or
 * a service loop that goes around without waiting, fails the leg.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#if !defined(WIN32)
#include <sys/socket.h>
#endif

struct leg {
	const char	*name;
	const char	*vhost;		/* client vhost to connect from */
	const char	*alpn;
	uint8_t		h2;
	uint8_t		server_initiates;
	uint8_t		default_reason;	/* close without lws_close_reason() */
	uint8_t		pmd_mid_drain;	/* server closes on a compressed
					 * message it is partway through */
	uint8_t		stall;		/* enum stall: the client stops
					 * reading while the server sends */
};

enum stall {
	STALL_NONE,
	STALL_TX_DRAIN,		/* server sends one big pmd message */
	STALL_CLOSE_FLUSH,	/* server closes with its tx buffered */
	STALL_CLOSE_FULL,	/* server closes on a full socket */
};

/* where a stall leg is in its timeline */
enum {
	STAGE_FILLING,		/* the server fills the connection */
	STAGE_SETTLING,		/* the client has sent: let things settle */
	STAGE_STALLED,		/* count the loop's trips */
	STAGE_RESUMED		/* the client reads again */
};

static const struct leg legs[] = {
	{ "h1, client-initiated",		"cli",	   "http/1.1", 0, 0, 0, 0, 0 },
	{ "h1, server-initiated",		"cli",	   "http/1.1", 0, 1, 0, 0, 0 },
	{ "h2, client-initiated",		"cli",	   "h2",       1, 0, 0, 0, 0 },
	{ "h2, server-initiated",		"cli",	   "h2",       1, 1, 0, 0, 0 },
	{ "h1, client-initiated, default reason", "cli",  "http/1.1", 0, 0, 1, 0, 0 },
	{ "h1, server-initiated, default reason", "cli",  "http/1.1", 0, 1, 1, 0, 0 },
	{ "h2, client-initiated, default reason", "cli",  "h2",       1, 0, 1, 0, 0 },
	{ "h2, server-initiated, default reason", "cli",  "h2",       1, 1, 1, 0, 0 },
	{ "h1 via http CONNECT proxy",		"cli-hp",  "http/1.1", 0, 0, 0, 0, 0 },
	{ "h1 via socks5, no auth",		"cli-s5",  "http/1.1", 0, 0, 0, 0, 0 },
	{ "h1 via socks5, username/password",	"cli-s5a", "http/1.1", 0, 0, 0, 0, 0 },
	{ "h1, pmd, server closes mid-message",	"cli-pmd", "http/1.1", 0, 1, 0, 1, 0 },
	{ "h1, pmd, server sends to a client not reading", "cli-pmd", "http/1.1",
							0, 1, 0, 0, STALL_TX_DRAIN },
	{ "h1, server closes with tx buffered, client not reading", "cli",
					"http/1.1", 0, 1, 0, 0, STALL_CLOSE_FLUSH },
	{ "h1, server closes on a full socket, client not reading", "cli",
					"http/1.1", 0, 1, 0, 0, STALL_CLOSE_FULL },
};

#define CLI_CODE	LWS_CLOSE_STATUS_GOINGAWAY	/* 1001 */
#define CLI_REASON	"bye"
#define SRV_CODE	LWS_CLOSE_STATUS_NORMAL		/* 1000 */
#define SRV_REASON	"srv"

/*
 * A close handshake on loopback takes a few ms and a few dozen trips around
 * the service loop.  One that only ends at the 5s close timeout, or a loop
 * that spins meanwhile, is far outside these.
 */
#define LEG_MAX_US	(3 * LWS_US_PER_SEC)
#define LEG_MAX_TURNS	2000

/* the compressible message the pmd leg's client sends */
#define PMD_MSG_LEN	(16 * 1024)

/*
 * The stall legs.  The server fills the connection until its socket has
 * taken nothing for STALL_QUIET_US (loopback can buffer several MB: the
 * socket buffers grow while it fills); with pmd, one message bigger than
 * that does it.  The client then sends more than the server reads at once.
 * After STALL_SETTLE_US, we watch the STALL_WINDOW_US the server spends
 * stalled: a readable socket it does not read makes the service loop spin,
 * going around in every millisecond of it.  A quiet loop only wakes for
 * timers (and may go around a few times in the millisecond before one is
 * due), so it is allowed STALL_MAX_BUSY_MS milliseconds with any service
 * loop turn in them.
 *
 * The pmd message drains inside lws, so we never see the socket take each
 * part of it: there, the connection counts as full once the loop has had no
 * more than STALL_POLL_BUSY_MS busy milliseconds in each STALL_POLL_US for
 * STALL_QUIET_US.  On a slow cpu, compressing and encrypting what the socket
 * takes can last well past any fixed settling time.
 */
#define STALL_PMD_LEN		(8 * 1024 * 1024)
#define STALL_FILL_MAX		(64 * 1024 * 1024)
#define STALL_CLI_LEN		(64 * 1024)
#define STALL_CHUNK		1024
#define STALL_OVER_LEN		(256 * 1024)
#define STALL_QUIET_US		(300 * LWS_US_PER_MS)
#define STALL_POLL_US		(50 * LWS_US_PER_MS)
#define STALL_SETTLE_US		(1 * LWS_US_PER_SEC)
#define STALL_WINDOW_US		(500 * LWS_US_PER_MS)
#define STALL_MAX_BUSY_MS	50
#define STALL_POLL_BUSY_MS	5
#define STALL_DRAIN_MAX_US	(10 * LWS_US_PER_SEC)
/*
 * The close legs' client takes no more than this at a time, so when the
 * server closes, the tail of what it wrote is still waiting in its own socket
 * for the client to read: a close that has the kernel abort the connection
 * loses it.  Otherwise loopback can hand it all over first and hide that.
 */
#define STALL_CLI_RCVBUF	(64 * 1024)

static struct lws_context *context;
static struct lws_vhost *vh_cli[5];
static const char *vh_cli_names[5] = { "cli", "cli-hp", "cli-s5", "cli-s5a",
				       "cli-pmd" };
static lws_sorted_usec_list_t sul_next, sul_timeout, sul_stall;
static struct lws *srv_wsi, *cli_wsi;
static const char *server_ads = "127.0.0.1";
static int port_tcp = 7681, cur = -1, result = 1, legs_run, failed;
static unsigned long turns, leg_turns, stall_turns, busy_ms;
static lws_usec_t leg_start, stall_started, last_fill, last_busy_ms;

/* per-leg state */
static int cli_closed, srv_closed, peer_close_seen, peer_close_ok, sent_close,
	   sent_msg, cli_sent, stall_stage, srv_close_flushes;
static size_t cli_rx, srv_filled;

static void
fail_leg(const char *why)
{
	failed = 1;
	lwsl_err("--- leg %d (%s): FAIL: %s ---\n", cur, legs[cur].name, why);
	lws_default_loop_exit(context);
}

static struct lws_vhost *
vhost_for(const char *name)
{
	int n;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(vh_cli_names); n++)
		if (!strcmp(vh_cli_names[n], name))
			return vh_cli[n];

	return NULL;
}

static void
start_leg(lws_sorted_usec_list_t *sul);

static void
leg_done_check(void)
{
	lws_usec_t us;

	if (failed || !cli_closed || !srv_closed)
		return;

	if (legs[cur].stall && stall_stage != STAGE_RESUMED) {
		fail_leg("closed before the stall was over");
		return;
	}
	if (legs[cur].stall == STALL_TX_DRAIN && cli_rx != STALL_PMD_LEN) {
		lwsl_err("client received %lu of %lu\n", (unsigned long)cli_rx,
			 (unsigned long)STALL_PMD_LEN);
		fail_leg("the big message did not arrive whole");
		return;
	}
	/*
	 * The server closed on the client's unread data: its close must still
	 * deliver all it wrote before.  Closing the socket with that rx unread
	 * has the kernel abort the connection, losing the tail (and on OSX,
	 * leaving the client waiting for it).
	 */
	if (legs[cur].stall == STALL_CLOSE_FLUSH ||
	    legs[cur].stall == STALL_CLOSE_FULL) {
		size_t sent = srv_filled +
			(legs[cur].stall == STALL_CLOSE_FLUSH ? STALL_OVER_LEN : 0);

		if (cli_rx != sent) {
			lwsl_err("client received %lu of %lu\n",
				 (unsigned long)cli_rx, (unsigned long)sent);
			fail_leg("the server's tx did not all arrive");
			return;
		}
	}
	/*
	 * A close that has to flush tx first drops the connection after the
	 * flush, without a Close frame
	 */
	if (srv_close_flushes) {
		if (peer_close_seen) {
			fail_leg("close frame after a flush");
			return;
		}
	} else {
		if (!peer_close_seen) {
			fail_leg("peer never saw the close frame");
			return;
		}
		if (!peer_close_ok) {
			fail_leg("close code / reason did not survive");
			return;
		}
	}
	/*
	 * A stall leg's service turns after the stall are mostly its bulk
	 * transfer: its spinning is judged while it is stalled
	 */
	us = lws_now_usecs() - leg_start;
	if (us > LEG_MAX_US ||
	    (!legs[cur].stall && turns - leg_turns > LEG_MAX_TURNS)) {
		lwsl_err("%dms, %lu service turns\n", (int)(us / LWS_US_PER_MS),
			 turns - leg_turns);
		fail_leg(us > LEG_MAX_US ? "close took too long" :
					   "service loop spun during the close");
		return;
	}

	lwsl_user("--- leg %d (%s): OK (%dms, %lu service turns) ---\n", cur,
		  legs[cur].name, (int)(us / LWS_US_PER_MS), turns - leg_turns);
	legs_run++;

	/* leave the close path before reconnecting */
	lws_sul_schedule(context, 0, &sul_next, start_leg, 1000);
}

static int
check_encap(struct lws *wsi)
{
	int encap = lws_get_network_wsi(wsi) != wsi;

	if (encap != legs[cur].h2) {
		fail_leg(encap ? "unexpectedly ws-over-h2" :
				 "not ws-over-h2");
		return 1;
	}

	return 0;
}

static void
check_peer_close(void *in, size_t len, int code, const char *reason)
{
	const uint8_t *p = (const uint8_t *)in;
	size_t rl = strlen(reason);

	peer_close_seen = 1;

	if (len != 2 + rl) {
		lwsl_err("close payload len %d, expected %d\n", (int)len,
			 (int)(2 + rl));
		return;
	}
	if (((p[0] << 8) | p[1]) != code) {
		lwsl_err("close code %d, expected %d\n", (p[0] << 8) | p[1],
			 code);
		return;
	}
	if (memcmp(p + 2, reason, rl)) {
		lwsl_err("close reason mismatch\n");
		return;
	}

	peer_close_ok = 1;
}

/* compresses, but not to nothing */
static uint8_t *
compressible_alloc(size_t len)
{
	uint8_t *buf = malloc(LWS_PRE + len);
	size_t n;

	if (!buf)
		return NULL;

	for (n = 0; n < len; n++)
		buf[LWS_PRE + n] = (uint8_t)('a' + ((n * 7) % 13) +
					     ((n >> 9) & 7));

	return buf;
}

static uint8_t *
bulk_alloc(size_t len)
{
	uint8_t *buf = malloc(LWS_PRE + len);
	uint32_t r = 0x12345678;
	size_t n;

	if (!buf)
		return NULL;

	/*
	 * does not compress: pmd sends it all.  xorshift: noise, but the same
	 * noise each run
	 */
	for (n = 0; n < len; n++) {
		r ^= r << 13;
		r ^= r >> 17;
		r ^= r << 5;
		buf[LWS_PRE + n] = (uint8_t)r;
	}

	return buf;
}

/*
 * The stall legs' timeline, from the server's first write: wait for the
 * connection to be full, have the client send while it is not reading, let
 * the server settle, count the service loop's trips while it is stalled,
 * then have the client read again
 */
static void
stall_cb(lws_sorted_usec_list_t *sul)
{
	switch (stall_stage) {
	case STAGE_FILLING:
		if (legs[cur].stall == STALL_TX_DRAIN) {
			if (busy_ms > STALL_POLL_BUSY_MS)
				last_fill = lws_now_usecs();
			busy_ms = 0;
			if (lws_now_usecs() - stall_started > STALL_DRAIN_MAX_US) {
				fail_leg("the server's tx drain never went quiet");
				return;
			}
		}
		if (lws_now_usecs() - last_fill < STALL_QUIET_US) {
			lws_sul_schedule(context, 0, &sul_stall, stall_cb,
					 STALL_POLL_US);
			return;
		}
		if (legs[cur].stall == STALL_TX_DRAIN)
			lwsl_user("%s: server's tx drain quiet after %dms\n",
				  __func__, (int)((lws_now_usecs() -
					  stall_started) / LWS_US_PER_MS));
		else
			lwsl_user("%s: server's socket full after %luKB\n",
				  __func__, (unsigned long)(srv_filled / 1024));
		stall_stage = STAGE_SETTLING;
		lws_callback_on_writable(cli_wsi);
		lws_sul_schedule(context, 0, &sul_stall, stall_cb,
				 STALL_SETTLE_US);
		break;

	case STAGE_SETTLING:
		if (srv_closed || cli_closed) {
			fail_leg("connection ended while stalled");
			return;
		}
		if (legs[cur].stall == STALL_TX_DRAIN) {
			if (!lws_send_pipe_choked(srv_wsi)) {
				fail_leg("the server's tx never stalled");
				return;
			}
		} else
			if (!sent_close) {
				fail_leg("the server did not get the data");
				return;
			}
		stall_stage = STAGE_STALLED;
		stall_turns = turns;
		busy_ms = 0;
		lws_sul_schedule(context, 0, &sul_stall, stall_cb,
				 STALL_WINDOW_US);
		break;

	case STAGE_STALLED:
		lwsl_user("%s: stalled %dms: %lu service turns, in %lums of it\n",
			  __func__, (int)(STALL_WINDOW_US / LWS_US_PER_MS),
			  turns - stall_turns, busy_ms);
		if (busy_ms > STALL_MAX_BUSY_MS) {
			fail_leg("service loop spun while stalled");
			return;
		}
		if (srv_closed || cli_closed) {
			fail_leg("connection ended while stalled");
			return;
		}
		stall_stage = STAGE_RESUMED;
		/* the leg's own clock starts again from here */
		leg_start = lws_now_usecs();
		leg_turns = turns;
		lws_rx_flow_control(cli_wsi, 1);
		break;
	}
}

/* the stall leg's timeline starts from the server's first write */
static void
stall_start(struct lws *wsi)
{
	if (srv_wsi)
		return;

	srv_wsi = wsi;
	stall_started = last_fill = lws_now_usecs();
	busy_ms = 0;
	lws_sul_schedule(context, 0, &sul_stall, stall_cb, 100 * LWS_US_PER_MS);
}

/*
 * STALL_TX_DRAIN: the server's writeable sends one big message, which pmd
 * compresses into frames as the socket takes them.  Nothing is read until
 * it has all gone.
 */
static int
srv_stall_send(struct lws *wsi)
{
	uint8_t *buf;
	int n;

	if (sent_msg)
		return 0;
	sent_msg = 1;
	stall_start(wsi);

	buf = bulk_alloc(STALL_PMD_LEN);
	if (!buf)
		return -1;
	n = lws_write(wsi, buf + LWS_PRE, STALL_PMD_LEN, LWS_WRITE_BINARY);
	free(buf);

	return n < 0 ? -1 : 0;
}

/*
 * The server's writeable while it fills the connection its client is not
 * reading: only whole writes while the socket takes them, until it has
 * taken nothing for a while
 */
static int
srv_stall_fill(struct lws *wsi)
{
	uint8_t *buf;
	int n = 0;

	if (stall_stage != STAGE_FILLING)
		return 0;

	stall_start(wsi);

	buf = bulk_alloc(STALL_CHUNK);
	if (!buf)
		return -1;
	while (!lws_send_pipe_choked(wsi) && srv_filled < STALL_FILL_MAX) {
		n = lws_write(wsi, buf + LWS_PRE, STALL_CHUNK, LWS_WRITE_BINARY);
		if (n < 0)
			break;
		srv_filled += STALL_CHUNK;
		last_fill = lws_now_usecs();
	}
	free(buf);
	if (n < 0)
		return -1;
	if (srv_filled >= STALL_FILL_MAX) {
		fail_leg("the server's socket never filled");
		return -1;
	}

	lws_callback_on_writable(wsi);

	return 0;
}

/*
 * The client's data came while the server's socket is full: close on it,
 * with more tx buffered first for STALL_CLOSE_FLUSH
 */
static int
srv_stall_close(struct lws *wsi)
{
	uint8_t *buf;
	int n;

	if (legs[cur].stall == STALL_CLOSE_FLUSH) {
		buf = bulk_alloc(STALL_OVER_LEN);
		if (!buf)
			return -1;
		n = lws_write(wsi, buf + LWS_PRE, STALL_OVER_LEN,
			      LWS_WRITE_BINARY);
		free(buf);
		if (n < 0)
			return -1;
	}

	sent_close = 1;
	srv_close_flushes = lws_partial_buffered(wsi);
	lwsl_user("%s: server: closing, %s\n", __func__, srv_close_flushes ?
		  "tx buffered" : "close frame waits for the socket");
	if (legs[cur].stall == STALL_CLOSE_FULL && srv_close_flushes)
		/* the socket took a partial: the close flushes instead */
		lwsl_warn("%s: no full-socket close this time\n", __func__);
	lws_close_reason(wsi, SRV_CODE, (unsigned char *)SRV_REASON,
			 strlen(SRV_REASON));

	return -1;
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		lwsl_user("%s: server: established\n", __func__);
		if (check_encap(wsi))
			return -1;
		if (legs[cur].server_initiates && !legs[cur].pmd_mid_drain)
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RECEIVE:
		if (legs[cur].stall && !sent_close) {
			if (legs[cur].stall != STALL_TX_DRAIN)
				return srv_stall_close(wsi);

			/* the client's data got in after the big message */
			if (stall_stage != STAGE_RESUMED) {
				fail_leg("server read while its tx was stalled");
				return -1;
			}
			/* the close is timed from here, not the big message */
			leg_start = lws_now_usecs();
			leg_turns = turns;
			sent_close = 1;
			lws_close_reason(wsi, SRV_CODE,
					 (unsigned char *)SRV_REASON,
					 strlen(SRV_REASON));
			return -1;
		}
		if (!legs[cur].pmd_mid_drain || sent_close)
			break;
		/*
		 * The first inflated chunk of the client's message: the rest
		 * of the compressed frame is still to come, and the inflater
		 * holds more output from what came so far.  We have seen
		 * enough, and close.
		 */
		if (!lws_remaining_packet_payload(wsi)) {
			fail_leg("pmd message not partway through a frame");
			return -1;
		}
		sent_close = 1;
		lwsl_user("%s: server: closing mid-message\n", __func__);
		lws_close_reason(wsi, SRV_CODE, (unsigned char *)SRV_REASON,
				 strlen(SRV_REASON));
		return -1;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (legs[cur].stall == STALL_TX_DRAIN)
			return srv_stall_send(wsi);
		if (legs[cur].stall)
			return srv_stall_fill(wsi);
		if (!legs[cur].server_initiates || legs[cur].pmd_mid_drain ||
		    sent_close)
			break;
		sent_close = 1;
		lwsl_user("%s: server: initiating close\n", __func__);
		/*
		 * with no prepared reason, lws must still send a Close frame
		 * and the peer must see 1000 with no reason text
		 */
		if (!legs[cur].default_reason)
			lws_close_reason(wsi, SRV_CODE,
					 (unsigned char *)SRV_REASON,
					 strlen(SRV_REASON));
		return -1;

	case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
		lwsl_user("%s: server: peer-initiated close, %d bytes\n",
			  __func__, (int)len);
		if (legs[cur].server_initiates) {
			fail_leg("server saw a peer close it initiated");
			return -1;
		}
		if (legs[cur].default_reason)
			check_peer_close(in, len, LWS_CLOSE_STATUS_NORMAL, "");
		else
			check_peer_close(in, len, CLI_CODE, CLI_REASON);
		break;

	case LWS_CALLBACK_CLOSED:
		lwsl_user("%s: server: closed\n", __func__);
		srv_closed = 1;
		srv_wsi = NULL;
		leg_done_check();
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lwsl_user("%s: client: established\n", __func__);
		if (check_encap(wsi))
			return -1;
		if (legs[cur].stall) {
			/* the server is to fill the connection meanwhile */
			cli_wsi = wsi;
			lws_rx_flow_control(wsi, 0);
			if (legs[cur].stall != STALL_TX_DRAIN) {
				lws_sockfd_type sfd = lws_get_socket_fd(wsi);
				int rb = STALL_CLI_RCVBUF;

				if (sfd != LWS_SOCK_INVALID &&
				    setsockopt(sfd, SOL_SOCKET, SO_RCVBUF,
					       (const char *)&rb, sizeof(rb)))
					lwsl_warn("%s: SO_RCVBUF failed\n",
						  __func__);
			}
			break;
		}
		if (!legs[cur].server_initiates || legs[cur].pmd_mid_drain)
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		cli_rx += len;
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		if (legs[cur].stall) {
			uint8_t *buf;
			int n;

			/* while not reading, more than the server takes at once */
			if (cli_sent || stall_stage != STAGE_SETTLING)
				break;
			cli_sent = 1;
			buf = bulk_alloc(STALL_CLI_LEN);
			if (!buf)
				return -1;
			n = lws_write(wsi, buf + LWS_PRE, STALL_CLI_LEN,
				      LWS_WRITE_BINARY);
			free(buf);

			return n < 0 ? -1 : 0;
		}
		if (legs[cur].pmd_mid_drain) {
			uint8_t *buf;
			int n;

			if (sent_msg)
				break;
			sent_msg = 1;

			buf = compressible_alloc(PMD_MSG_LEN);
			if (!buf)
				return -1;
			n = lws_write(wsi, buf + LWS_PRE, PMD_MSG_LEN,
				      LWS_WRITE_TEXT);
			free(buf);
			if (n < 0)
				return -1;
			break;
		}
		if (legs[cur].server_initiates || sent_close)
			break;
		sent_close = 1;
		lwsl_user("%s: client: initiating close\n", __func__);
		if (!legs[cur].default_reason)
			lws_close_reason(wsi, CLI_CODE,
					 (unsigned char *)CLI_REASON,
					 strlen(CLI_REASON));
		return -1;

	case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
		lwsl_user("%s: client: peer-initiated close, %d bytes\n",
			  __func__, (int)len);
		if (!legs[cur].server_initiates) {
			fail_leg("client saw a peer close it initiated");
			return -1;
		}
		if (legs[cur].default_reason)
			check_peer_close(in, len, LWS_CLOSE_STATUS_NORMAL, "");
		else
			check_peer_close(in, len, SRV_CODE, SRV_REASON);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("--- client connection error: %s ---\n",
			 in ? (char *)in : "(null)");
		fail_leg("connection error");
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		lwsl_user("%s: client: closed\n", __func__);
		cli_closed = 1;
		cli_wsi = NULL;
		leg_done_check();
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * The stall legs use a protocol with a bigger rx buffer, since that also
 * bounds how much lws gives the socket at a time (and pmd's frames)
 */
#define PROT_BULK_RX	16384

static const struct lws_protocols protocols_srv[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	{ "wsclose", callback_srv, 0, 256, 0, NULL, 0 },
	{ "wsclose-bulk", callback_srv, 0, PROT_BULK_RX, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "wsclose", callback_cli, 0, 256, 0, NULL, 0 },
	{ "wsclose-bulk", callback_cli, 0, PROT_BULK_RX, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

#if !defined(LWS_WITHOUT_EXTENSIONS)
/*
 * The pmd client deflates into frames of up to 4KB, so each is larger than
 * the server's 256-byte rx buffer, and one message spans several
 */
static const struct lws_protocols protocols_cli_pmd[] = {
	{ "wsclose", callback_cli, 0, 4096, 0, NULL, 0 },
	{ "wsclose-bulk", callback_cli, 0, PROT_BULK_RX, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_extension extensions[] = {
	{
		"permessage-deflate",
		lws_extension_callback_pm_deflate,
		"permessage-deflate"
		 "; client_no_context_takeover"
		 "; client_max_window_bits"
	},
	{ NULL, NULL, NULL /* terminator */ }
};
#endif

static void
start_leg(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	struct lws_vhost *vh;

	do {
		cur++;
		if (cur == (int)LWS_ARRAY_SIZE(legs)) {
			lwsl_user("--- all %d legs passed ---\n", legs_run);
			result = 0;
			lws_default_loop_exit(context);
			return;
		}
		vh = vhost_for(legs[cur].vhost);
		if (!vh)
			lwsl_user("--- leg %d (%s): skipped, no %s ---\n", cur,
				  legs[cur].name, legs[cur].vhost);
	} while (!vh);

	lwsl_user("--- leg %d (%s): starting ---\n", cur, legs[cur].name);

	cli_closed = srv_closed = peer_close_seen = peer_close_ok =
			sent_close = sent_msg = cli_sent = stall_stage =
			srv_close_flushes = 0;
	cli_rx = srv_filled = 0;
	srv_wsi = cli_wsi = NULL;
	leg_start = lws_now_usecs();
	leg_turns = turns;

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.vhost = vh;
	i.address = server_ads;
	i.port = port_tcp;
	i.path = "/";
	i.host = server_ads;
	i.origin = server_ads;
	i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
			   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	i.alpn = legs[cur].alpn;
	i.protocol = legs[cur].stall ? "wsclose-bulk" : "wsclose";
	i.local_protocol_name = i.protocol;

	if (!lws_client_connect_via_info(&i))
		fail_leg("client connect failed");
}

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	if (cur >= 0 && cur < (int)LWS_ARRAY_SIZE(legs)) {
		fail_leg("timed out");
		return;
	}

	lwsl_err("--- FAIL: timed out ---\n");
	lws_default_loop_exit(context);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

static int
split_hostport(const char *hp, char *host, size_t hl, unsigned int *port)
{
	const char *c = strrchr(hp, ':');

	if (!c || (size_t)(c - hp) >= hl)
		return 1;

	memcpy(host, hp, (size_t)(c - hp));
	host[c - hp] = '\0';
	*port = (unsigned int)atoi(c + 1);

	return 0;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	char proxy_host[64], socks[128], socks_auth[128];
	unsigned int proxy_port = 0;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_tcp = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_ads = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: ws close handshake\n");

	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* ws server vhost, offering h2 and h1 */
	info.port = port_tcp;
	info.vhost_name = "srv";
	info.alpn = "h2,http/1.1";
	info.protocols = protocols_srv;
	info.ssl_cert_filepath = "localhost-100y.cert";
	info.ssl_private_key_filepath = "localhost-100y.key";
#if !defined(LWS_WITHOUT_EXTENSIONS)
	/* only a client that asks for it gets pmd */
	info.extensions = extensions;
#endif

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create server vhost\n");
		goto bail;
	}
	info.extensions = NULL;

	/* direct client vhost */
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.alpn = NULL;
	info.protocols = protocols_cli;
	info.ssl_cert_filepath = NULL;
	info.ssl_private_key_filepath = NULL;
	info.vhost_name = vh_cli_names[0];

	vh_cli[0] = lws_create_vhost(context, &info);
	if (!vh_cli[0]) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	/* client vhost via http CONNECT proxy */
	if ((p = lws_cmdline_option(argc, argv, "--proxy"))) {
		if (split_hostport(p, proxy_host, sizeof(proxy_host),
				   &proxy_port)) {
			lwsl_err("--proxy wants host:port\n");
			goto bail;
		}
		info.vhost_name = vh_cli_names[1];
		info.http_proxy_address = proxy_host;
		info.http_proxy_port = proxy_port;
		vh_cli[1] = lws_create_vhost(context, &info);
		info.http_proxy_address = NULL;
		info.http_proxy_port = 0;
		if (!vh_cli[1]) {
			lwsl_err("Failed to create proxy client vhost\n");
			goto bail;
		}
	}

#if defined(LWS_WITH_SOCKS5)
	/* client vhost via socks5, no auth */
	if ((p = lws_cmdline_option(argc, argv, "--socks"))) {
		lws_strncpy(socks, p, sizeof(socks));
		info.vhost_name = vh_cli_names[2];
		info.socks_proxy_address = socks;
		vh_cli[2] = lws_create_vhost(context, &info);
		info.socks_proxy_address = NULL;
		if (!vh_cli[2]) {
			lwsl_err("Failed to create socks client vhost\n");
			goto bail;
		}
	}

	/* client vhost via socks5 requiring username / password */
	if ((p = lws_cmdline_option(argc, argv, "--socks-auth"))) {
		lws_snprintf(socks_auth, sizeof(socks_auth), "user:pass@%s", p);
		info.vhost_name = vh_cli_names[3];
		info.socks_proxy_address = socks_auth;
		vh_cli[3] = lws_create_vhost(context, &info);
		info.socks_proxy_address = NULL;
		if (!vh_cli[3]) {
			lwsl_err("Failed to create socks auth client vhost\n");
			goto bail;
		}
	}
#else
	(void)socks;
	(void)socks_auth;
#endif

#if !defined(LWS_WITHOUT_EXTENSIONS)
	/* client vhost offering permessage-deflate */
	info.vhost_name = vh_cli_names[4];
	info.protocols = protocols_cli_pmd;
	info.extensions = extensions;
	vh_cli[4] = lws_create_vhost(context, &info);
	info.extensions = NULL;
	if (!vh_cli[4]) {
		lwsl_err("Failed to create pmd client vhost\n");
		goto bail;
	}
#endif

	lws_sul_schedule(context, 0, &sul_next, start_leg, 1);
	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 45 * LWS_US_PER_SEC);

	while (n >= 0) {
		n = lws_service(context, 0);
		turns++;
		if ((stall_stage == STAGE_FILLING ||
		     stall_stage == STAGE_STALLED) &&
		    lws_now_usecs() / LWS_US_PER_MS != last_busy_ms) {
			last_busy_ms = lws_now_usecs() / LWS_US_PER_MS;
			busy_ms++;
		}
	}

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
