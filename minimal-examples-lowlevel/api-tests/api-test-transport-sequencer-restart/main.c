/*
 * lws-api-test-transport-sequencer-restart
 *
 * Two sequencers, A sending to B, over a simulated network in this process
 * that can drop chosen chunks, checking two ways a stream used to get stuck
 * for good:
 *
 *  - B restarts in the middle of A's stream.  What B acked is gone with it,
 *    and the new B receives from 0, while A's stream carries on from where
 *    it was, past the new B's window: nothing A sends is taken any more.
 *    Told B lost its session, A renumbers what B hadn't acked from 0
 *    (lws_transport_sequencer_tx_rebase()) and sends it again: the new B
 *    gets it, in order, and A's session completes.
 *
 *  - B never takes one chunk, but takes the ones A keeps writing after it,
 *    and acks them.  Those acks used to restart the retries of the chunk B
 *    refuses, so it was resent forever and the session never failed: now it
 *    fails on time, while the acks for the others are still coming.
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define CHUNK		256
#define CHUNKS		16
/* B has acked all before this when it restarts, A has the rest to send */
#define RESTART_AT	(12 * CHUNK)
/* small, so A's stream carries on well past the new B's window */
#define WINDOW		1024
#define NET_US		(1 * LWS_US_PER_MS)
#define STEP_US		(10 * LWS_US_PER_MS)
#define DEADLINE_US	(5 * LWS_US_PER_SEC)
/*
 * In the second test, A writes a new chunk this often, so acks for them keep
 * coming while it resends the one B refuses.  B holds at most 64 pieces past
 * the gap, and then stops taking and acking any: A must give up before that,
 * while the acks are still coming.
 */
#define TRICKLE_US	(30 * LWS_US_PER_MS)
#define TRICKLE_MAX	60

enum {
	ST_FILL,	/* B takes all of A's stream before RESTART_AT */
	ST_RESTARTED,	/* B restarted: does A's stream reach the new B? */
	ST_STUCK,	/* B never takes A's first chunk: does A give up? */
	ST_DONE
};

struct ep {
	struct lws_transport_sequencer	*ts;
	uint8_t				rx[CHUNKS * CHUNK];
	uint64_t			rx_hi; /* end of the furthest data */
	int				idx;
	int				state; /* 0, or 1 + on_state_change's */
};

struct pkt {
	lws_dll2_t			list;
	lws_transport_sequencer_sack_block_t sack[4];
	uint64_t			offset;
	uint64_t			cumulative;
	size_t				len;
	size_t				num_sack;
	int				to;
	int				ack;
	uint8_t				data[CHUNK];
};

static struct lws_context *context;
static lws_sorted_usec_list_t sul_net, sul_step;
static lws_dll2_owner_t net;
static struct ep ep[2]; /* A, B */
static lws_usec_t started;
static uint64_t drop_from = (uint64_t)-1, drop_only = (uint64_t)-1;
static int state, fails, done, trickled;

static const lws_retry_bo_t retry = {
	.retry_ms_table		= (uint32_t[]){ 25, 50, 100 },
	.retry_ms_table_count	= 3,
	.conceal_count		= 5,
};

static void
fail(const char *why)
{
	lwsl_user("FAIL: %s\n", why);
	fails++;
	done = 1;
	lws_cancel_service(context);
}

/* the network: what one side sends, the other gets a moment later */

static void
net_send(int to, int ack, uint64_t offset, const uint8_t *buf, size_t len,
	 struct lws_transport_sequencer *ts)
{
	struct pkt *p = calloc(1, sizeof(*p));

	if (!p)
		return;

	p->to = to;
	p->ack = ack;
	p->offset = offset;
	p->len = len;
	if (buf && len <= sizeof(p->data))
		memcpy(p->data, buf, len);
	if (ack) {
		p->cumulative = lws_transport_sequencer_get_stats(ts)->rx_offset;
		p->num_sack = lws_transport_sequencer_get_sack_blocks(ts,
					p->sack, LWS_ARRAY_SIZE(p->sack));
	}

	lws_dll2_add_tail(&p->list, &net);
}

static void
net_cb(lws_sorted_usec_list_t *sul)
{
	/* what's delivered now may send more: that goes next time */
	int n = (int)net.count;

	while (n-- && net.head) {
		struct pkt *p = lws_container_of(net.head, struct pkt, list);
		struct ep *e = &ep[p->to];

		lws_dll2_remove(&p->list);

		if (e->ts) {
			if (p->ack)
				lws_transport_sequencer_acknowledge_sack(e->ts,
					p->cumulative, p->sack, p->num_sack, 0);
			else
				lws_transport_sequencer_rx(e->ts, p->offset,
							   p->data, p->len);
		}
		free(p);
	}

	lws_sul_schedule(context, 0, &sul_net, net_cb, NET_US);
}

static int
tx_chunk(struct lws_transport_sequencer *ts, uint64_t offset,
	 const uint8_t *buf, size_t len)
{
	struct ep *e = lws_transport_sequencer_get_info(ts)->user_data;

	/* only A's data is dropped, on its way to B */
	if (!e->idx && (offset >= drop_from || offset == drop_only))
		return 0;

	net_send(!e->idx, 0, offset, buf, len, ts);

	return 0;
}

static int
tx_ack(struct lws_transport_sequencer *ts, uint64_t offset, size_t len)
{
	struct ep *e = lws_transport_sequencer_get_info(ts)->user_data;

	net_send(!e->idx, 1, offset, NULL, len, ts);

	return 0;
}

static int
on_rx_data(struct lws_transport_sequencer *ts, uint64_t offset,
	   const uint8_t *buf, size_t len)
{
	struct ep *e = lws_transport_sequencer_get_info(ts)->user_data;

	if (state == ST_STUCK)
		/* only the first test looks at what B got */
		return 0;

	if (offset + len > sizeof(e->rx)) {
		fail("data delivered past what was sent");
		return 0;
	}
	memcpy(e->rx + offset, buf, len);
	if (offset + len > e->rx_hi)
		e->rx_hi = offset + len;

	return 0;
}

static void
on_state_change(struct lws_transport_sequencer *ts, int st, int status)
{
	struct ep *e = lws_transport_sequencer_get_info(ts)->user_data;

	e->state = 1 + st;
}

static const lws_transport_sequencer_ops_t ops = {
	.name			= "test-seq",
	.tx_chunk		= tx_chunk,
	.tx_ack			= tx_ack,
	.on_rx_data		= on_rx_data,
	.on_state_change	= on_state_change,
};

static int
ep_create(int idx, uint32_t window)
{
	lws_transport_sequencer_info_t i;

	memset(&ep[idx], 0, sizeof(ep[idx]));
	ep[idx].idx = idx;

	memset(&i, 0, sizeof(i));
	i.cx		= context;
	i.ops		= &ops;
	i.retry_policy	= &retry;
	i.user_data	= &ep[idx];
	i.window_size	= window;

	ep[idx].ts = lws_transport_sequencer_create(&i);

	return !ep[idx].ts;
}

/* chunk n is all the byte n + 1, so we can tell which arrived where */

static void
chunk(int n, uint8_t *buf)
{
	memset(buf, n + 1, CHUNK);
}

static void
step(lws_sorted_usec_list_t *sul)
{
	uint8_t buf[CHUNK];
	int n;

	if (done)
		return;

	if (lws_now_usecs() - started > DEADLINE_US) {
		fail(state == ST_STUCK ? "A resends the chunk B refuses "
			"forever, its session never fails" :
			"A's stream never reached the restarted B");
		return;
	}

	switch (state) {
	case ST_FILL:
		if (lws_transport_sequencer_get_stats(ep[0].ts)->ack_offset <
								RESTART_AT)
			break;

		lwsl_user("B acked up to %d, restarting it\n", RESTART_AT);
		lws_transport_sequencer_destroy(&ep[1].ts);
		if (ep_create(1, WINDOW)) {
			fail("making the new B");
			return;
		}
		drop_from = (uint64_t)-1;

		/*
		 * What the transport does when the new B challenges A's
		 * session, see lib/misc/dht: B starts from 0, so A does too
		 */
		lws_transport_sequencer_tx_rebase(ep[0].ts);
		lws_transport_sequencer_resend(ep[0].ts);
		state = ST_RESTARTED;
		break;

	case ST_RESTARTED:
		if (ep[0].state == 2) {
			fail("A's session failed sending to the restarted B");
			return;
		}
		if (ep[0].state != 1)
			break;

		/* the new B has the chunks after RESTART_AT, from 0, in order */
		if (ep[1].rx_hi != (CHUNKS * CHUNK) - RESTART_AT) {
			fail("the restarted B got the wrong amount");
			return;
		}
		for (n = 0; n < CHUNKS - RESTART_AT / CHUNK; n++) {
			chunk(RESTART_AT / CHUNK + n, buf);
			if (memcmp(ep[1].rx + (n * CHUNK), buf, CHUNK)) {
				fail("the restarted B got the wrong data");
				return;
			}
		}
		lwsl_user("the restarted B got the rest of A's stream\n");

		lws_transport_sequencer_destroy(&ep[0].ts);
		lws_transport_sequencer_destroy(&ep[1].ts);
		if (ep_create(0, 65536) || ep_create(1, 65536)) {
			fail("making the second A and B");
			return;
		}

		/* B never gets A's first chunk, but all the others */
		drop_only = 0;
		chunk(0, buf);
		lws_transport_sequencer_write(ep[0].ts, buf, CHUNK);
		trickled = 1;
		started = lws_now_usecs();
		state = ST_STUCK;
		lws_sul_schedule(context, 0, &sul_step, step, TRICKLE_US);
		return;

	case ST_STUCK:
		if (ep[0].state == 2) {
			lwsl_user("A gave up on the chunk B refuses, after %d "
				  "more chunks were acked\n", trickled - 1);
			if (trickled < 4)
				fail("A gave up before acks for other data "
				     "had a chance to keep it going");
			else if (trickled >= TRICKLE_MAX)
				fail("A only gave up once the acks for other "
				     "data stopped");
			else
				state = ST_DONE;
			break;
		}
		if (trickled < TRICKLE_MAX) {
			chunk(trickled++ % CHUNKS, buf);
			lws_transport_sequencer_write(ep[0].ts, buf, CHUNK);
		}
		lws_sul_schedule(context, 0, &sul_step, step, TRICKLE_US);
		return;

	case ST_DONE:
		done = 1;
		lws_cancel_service(context);
		return;
	}

	lws_sul_schedule(context, 0, &sul_step, step, STEP_US);
}

static void
sigint_handler(int sig)
{
	done = 1;
	lws_cancel_service(context);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	uint8_t buf[CHUNK];
	int n;

	signal(SIGINT, sigint_handler);
	memset(&info, 0, sizeof(info));
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	lwsl_user("LWS API selftest: transport sequencer, peer restart and "
		  "stuck chunk\n");

	info.port = CONTEXT_PORT_NO_LISTEN;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (ep_create(0, WINDOW) || ep_create(1, WINDOW)) {
		fail("making A and B");
		goto bail;
	}

	/* B doesn't get the end of A's stream before it restarts */
	drop_from = RESTART_AT;
	for (n = 0; n < CHUNKS; n++) {
		chunk(n, buf);
		if (lws_transport_sequencer_write(ep[0].ts, buf, CHUNK) !=
							LWS_TSW_QUEUED) {
			fail("A refused a write");
			goto bail;
		}
	}

	started = lws_now_usecs();
	lws_sul_schedule(context, 0, &sul_net, net_cb, NET_US);
	lws_sul_schedule(context, 0, &sul_step, step, STEP_US);

	while (!done && lws_service(context, 0) >= 0)
		;

bail:
	lws_sul_cancel(&sul_net);
	lws_sul_cancel(&sul_step);
	lws_transport_sequencer_destroy(&ep[0].ts);
	lws_transport_sequencer_destroy(&ep[1].ts);
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, net.head) {
		lws_dll2_remove(d);
		free(lws_container_of(d, struct pkt, list));
	} lws_end_foreach_dll_safe(d, d1);
	lws_context_destroy(context);

	if (state != ST_DONE)
		fails++;

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
