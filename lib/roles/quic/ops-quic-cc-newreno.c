/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * ...
 */

#include "private-lib-core.h"
#include "private-lib-roles-quic.h"


static void
newreno_init(struct lws *nwsi)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	struct lws_vhost *vh = lws_get_vhost(nwsi);
	struct lws_quic_cc_newreno *st;
	uint32_t mtu = vh->quic_mtu ? vh->quic_mtu : 1280;

	if (!qn->cc_state)
		qn->cc_state = lws_zalloc(sizeof(*st), __func__);

	if (!qn->cc_state)
		return;

	st = (struct lws_quic_cc_newreno *)qn->cc_state;

	/* RFC 9002: Initial Window */
	st->cwnd = 10 * mtu;
	st->ssthresh = (size_t)-1; /* Infinity */
	st->bytes_in_flight = 0;
	st->congestion_recovery_start_time = 0;
	st->last_pacing_time = lws_now_usecs();
	st->pacing_credit = st->cwnd; /* initial burst allowed */

	lwsl_cx_info(nwsi->a.context, "QUIC NewReno: init cwnd=%zu, mtu=%u", st->cwnd, mtu);
}

static void
newreno_on_sent(struct lws *nwsi, size_t bytes)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	struct lws_quic_cc_newreno *st = (struct lws_quic_cc_newreno *)qn->cc_state;

	if (!st) return;

	st->bytes_in_flight += bytes;
	if (st->pacing_credit >= bytes)
		st->pacing_credit -= bytes;
	else
		st->pacing_credit = 0;
}

static void
newreno_on_ack(struct lws *nwsi, size_t bytes_acked, lws_usec_t rtt)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	struct lws_vhost *vh = lws_get_vhost(nwsi);
	struct lws_quic_cc_newreno *st = (struct lws_quic_cc_newreno *)qn->cc_state;
	uint32_t mtu = vh->quic_mtu ? vh->quic_mtu : 1280;

	if (!st) return;

	if (st->bytes_in_flight >= bytes_acked)
		st->bytes_in_flight -= bytes_acked;
	else
		st->bytes_in_flight = 0;

	/* Update RTT Tracking */
	if (!qn->smoothed_rtt) {
		qn->smoothed_rtt = rtt;
		qn->rttvar = rtt / 2;
		qn->min_rtt = rtt;
	} else {
		qn->min_rtt = rtt < qn->min_rtt ? rtt : qn->min_rtt;
		lws_usec_t rtt_diff = qn->smoothed_rtt > rtt ? qn->smoothed_rtt - rtt : rtt - qn->smoothed_rtt;
		qn->rttvar = (3 * qn->rttvar + rtt_diff) / 4;
		qn->smoothed_rtt = (7 * qn->smoothed_rtt + rtt) / 8;
	}
	qn->latest_rtt = rtt;

	if (st->cwnd < st->ssthresh) {
		/* Slow Start */
		st->cwnd += bytes_acked;
	} else {
		/* Congestion Avoidance */
		st->cwnd += (mtu * bytes_acked) / st->cwnd;
	}
}

static void
newreno_on_discard(struct lws *nwsi, size_t bytes_discarded)
{
        struct lws_quic_netconn *qn = nwsi->quic.qn;
        struct lws_quic_cc_newreno *st = (struct lws_quic_cc_newreno *)qn->cc_state;

        if (!st) return;

        if (st->bytes_in_flight >= bytes_discarded)
                st->bytes_in_flight -= bytes_discarded;
        else
                st->bytes_in_flight = 0;
}

static void
newreno_on_loss(struct lws *nwsi, size_t bytes_lost)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	struct lws_vhost *vh = lws_get_vhost(nwsi);
	struct lws_quic_cc_newreno *st = (struct lws_quic_cc_newreno *)qn->cc_state;
	uint32_t mtu = vh->quic_mtu ? vh->quic_mtu : 1280;
	size_t min_cwnd = 2 * mtu;
	lws_usec_t now = lws_now_usecs();

	if (!st) return;

	if (st->bytes_in_flight >= bytes_lost)
		st->bytes_in_flight -= bytes_lost;
	else
		st->bytes_in_flight = 0;

	/* Only react to losses that started after the last recovery period */
	if (now - st->congestion_recovery_start_time <= qn->smoothed_rtt)
		return;

	st->congestion_recovery_start_time = now;
	st->ssthresh = st->cwnd / 2;
	if (st->ssthresh < min_cwnd)
		st->ssthresh = min_cwnd;

	st->cwnd = st->ssthresh;

#if (_LWS_ENABLED_LOGS & LLL_INFO)
	LWS_RATELIMIT_DEFINE_STATIC(rl);
	lwsl_ratelimit_info(&rl, 1000000, "QUIC NewReno: loss detected, cwnd reduced to %zu", st->cwnd);
#endif
}

static int
newreno_can_send(struct lws *nwsi, size_t bytes)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	struct lws_quic_cc_newreno *st = (struct lws_quic_cc_newreno *)qn->cc_state;

	if (!st) return 0;

	return (st->bytes_in_flight + bytes <= st->cwnd);
}

static lws_usec_t
newreno_get_pacing_delay(struct lws *nwsi, size_t bytes_to_send)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	struct lws_quic_cc_newreno *st = (struct lws_quic_cc_newreno *)qn->cc_state;
	lws_usec_t rtt, delay_us;

	if (!st) return 0;

	rtt = qn->smoothed_rtt;
	if (rtt < 1000)
		rtt = 1000; /* Minimum 1ms for pacing math */

	lws_usec_t now = lws_now_usecs();
	lws_usec_t elapsed = now - st->last_pacing_time;

	/* Replenish credit based on elapsed time: R = cwnd / srtt */
	size_t credit_added = (size_t)(((uint64_t)elapsed * (uint64_t)st->cwnd) / (uint64_t)rtt);
	st->pacing_credit += credit_added;

	/*
	 * Cap credit to max burst (64 packets) to prevent very large bursts
	 * while still allowing good throughput for large concurrent stream
	 * queues (e.g. 1999 streams in the multiplexing test).
	 */
	size_t max_burst = 64 * (lws_get_vhost(nwsi)->quic_mtu ? lws_get_vhost(nwsi)->quic_mtu : 1280);
	if (st->pacing_credit > max_burst)
		st->pacing_credit = max_burst;

	if (st->pacing_credit >= bytes_to_send) {
		/*
		 * Enough credit to send this packet: consume credit and
		 * record the time only when we actually allow a send.
		 * This is critical: if we updated last_pacing_time even
		 * when blocking, the next call after a short timer would
		 * compute elapsed ≈ 0 → near-zero credit added → endless
		 * tight-loop stall.
		 */
		st->last_pacing_time = now;
		return 0;
	}

	/* Not enough credit. Calculate how long to wait for the missing credit. */
	size_t missing_credit = bytes_to_send - st->pacing_credit;
	delay_us = (lws_usec_t)(((uint64_t)missing_credit * (uint64_t)rtt) / (uint64_t)st->cwnd);

	if (delay_us == 0)
		delay_us = 1;

	/* Do NOT update last_pacing_time here: the credit already earned
	 * (credit_added) is preserved in st->pacing_credit, and next call
	 * the elapsed time from *now* will be added on top of it. */

	return delay_us;
}

const struct lws_cc_ops lws_cc_ops_newreno = {
	.init			= newreno_init,
	.on_sent		= newreno_on_sent,
	.on_ack			= newreno_on_ack,
	.on_loss		= newreno_on_loss,
	.on_discard		= newreno_on_discard,
	.can_send		= newreno_can_send,
	.get_pacing_delay	= newreno_get_pacing_delay,
};
