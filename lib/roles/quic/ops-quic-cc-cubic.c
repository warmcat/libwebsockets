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
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "private-lib-core.h"
#include "private-lib-roles-quic.h"

struct lws_quic_cc_cubic {
	size_t			cwnd;
	size_t			ssthresh;
	size_t			bytes_in_flight;
	lws_usec_t		congestion_recovery_start_time;

	lws_usec_t		last_pacing_time;
	size_t			pacing_credit;

	/* CUBIC specifics */
	lws_usec_t		epoch_start_time;
	size_t			w_max;
	size_t			w_est;
	int32_t			k;
	uint8_t			is_in_fast_convergence;
};

/* Integer cube root approximation */
static uint32_t
integer_cbrt(uint64_t x)
{
	uint32_t y = 0;
	int s;
	for (s = 63; s >= 0; s -= 3) {
		y += y;
		uint32_t b = 3 * y * (y + 1) + 1;
		if ((x >> s) >= b) {
			x -= (uint64_t)b << s;
			y++;
		}
	}
	return y;
}

static void
cubic_init(struct lws *nwsi)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	struct lws_vhost *vh = lws_get_vhost(nwsi);
	struct lws_quic_cc_cubic *st;
	uint32_t mtu = vh->quic_mtu ? vh->quic_mtu : 1280;

	if (!qn->cc_state)
		qn->cc_state = lws_zalloc(sizeof(*st), __func__);

	if (!qn->cc_state)
		return;

	st = (struct lws_quic_cc_cubic *)qn->cc_state;

	/* RFC 9002: Initial Window */
	st->cwnd = 10 * mtu;
	st->ssthresh = (size_t)-1; /* Infinity */
	st->bytes_in_flight = 0;
	st->congestion_recovery_start_time = 0;
	st->last_pacing_time = lws_now_usecs();
	st->pacing_credit = st->cwnd; /* initial burst allowed */

	st->epoch_start_time = 0;
	st->w_max = 0;
	st->w_est = 0;
	st->k = 0;
	st->is_in_fast_convergence = 0;

	lwsl_cx_info(nwsi->a.context, "QUIC CUBIC: init cwnd=%zu, mtu=%u", st->cwnd, mtu);
}

static void
cubic_on_sent(struct lws *nwsi, size_t bytes)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	struct lws_quic_cc_cubic *st = (struct lws_quic_cc_cubic *)qn->cc_state;

	if (!st) return;

	st->bytes_in_flight += bytes;
	if (st->pacing_credit >= bytes)
		st->pacing_credit -= bytes;
	else
		st->pacing_credit = 0;
}

static void
cubic_on_ack(struct lws *nwsi, size_t bytes_acked, lws_usec_t rtt)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	struct lws_vhost *vh = lws_get_vhost(nwsi);
	struct lws_quic_cc_cubic *st = (struct lws_quic_cc_cubic *)qn->cc_state;
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
		/* Slow Start: Reno behavior */
		st->cwnd += bytes_acked;
	} else {
		/* Congestion Avoidance: CUBIC */
		lws_usec_t now = lws_now_usecs();
		if (st->epoch_start_time == 0) {
			st->epoch_start_time = now;
			if (st->w_max < st->cwnd) {
				st->w_max = st->cwnd;
				st->k = 0;
			} else {
				/* K = cbrt( (W_max - cwnd) / C ) where C = 0.4 */
				/* Working in MSS */
				uint64_t w_max_mss = st->w_max / mtu;
				uint64_t cwnd_mss = st->cwnd / mtu;
				if (w_max_mss > cwnd_mss) {
					/* K = cbrt( (w_max_mss - cwnd_mss) * 10 / 4 ) */
					st->k = (int32_t)integer_cbrt(((w_max_mss - cwnd_mss) * 10) / 4);
				} else {
					st->k = 0;
				}
			}
		}

		int32_t t = (int32_t)((now - st->epoch_start_time) / 1000000); /* seconds */
		int32_t diff = t - st->k;
		int64_t diff3 = (int64_t)diff * diff * diff;
		
		uint64_t target_mss = (uint64_t)(((int64_t)4 * diff3) / 10 + (int64_t)(st->w_max / mtu));

		/* TCP Friendliness (Reno approximation) */
		/* W_est = W_max * beta + (3 * (1-beta) / (1+beta)) * (t / RTT) */
		/* beta = 0.7, so (3 * 0.3 / 1.7) approx 9/17 */
		uint64_t srtt_sec = (uint64_t)(qn->smoothed_rtt / 1000000);
		if (srtt_sec == 0) srtt_sec = 1;
		st->w_est = ((st->w_max / mtu) * 7) / 10 + ((uint64_t)(9 * t) / (17 * srtt_sec));

		if (target_mss < st->w_est)
			target_mss = st->w_est;

		uint64_t target_bytes = target_mss * mtu;
		if (target_bytes > st->cwnd) {
			/* Standard CUBIC cwnd increment per ACK */
			size_t cwnd_inc = (mtu * (target_bytes - st->cwnd)) / (st->cwnd ? st->cwnd : 1);
			if (cwnd_inc == 0) cwnd_inc = 1; /* ensure forward progress */
			st->cwnd += cwnd_inc;
		}
	}
}

static void
cubic_on_loss(struct lws *nwsi, size_t bytes_lost)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	struct lws_vhost *vh = lws_get_vhost(nwsi);
	struct lws_quic_cc_cubic *st = (struct lws_quic_cc_cubic *)qn->cc_state;
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
	st->epoch_start_time = 0;

	/* Fast Convergence */
	if (st->cwnd < st->w_max) {
		st->w_max = (st->cwnd * 17) / 20; /* w_max = cwnd * (1 + beta) / 2 */
	} else {
		st->w_max = st->cwnd;
	}

	st->ssthresh = (st->cwnd * 7) / 10; /* cwnd * beta (0.7) */
	if (st->ssthresh < min_cwnd)
		st->ssthresh = min_cwnd;

	st->cwnd = st->ssthresh;

#if (_LWS_ENABLED_LOGS & LLL_INFO)
	LWS_RATELIMIT_DEFINE_STATIC(rl);
	lwsl_ratelimit_info(&rl, 1000000, "QUIC CUBIC: loss detected, cwnd reduced to %zu", st->cwnd);
#endif
}

static int
cubic_can_send(struct lws *nwsi, size_t bytes)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	struct lws_quic_cc_cubic *st = (struct lws_quic_cc_cubic *)qn->cc_state;

	if (!st) return 0;

	return (st->bytes_in_flight + bytes <= st->cwnd);
}

static lws_usec_t
cubic_get_pacing_delay(struct lws *nwsi, size_t bytes_to_send)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	struct lws_quic_cc_cubic *st = (struct lws_quic_cc_cubic *)qn->cc_state;
	lws_usec_t rtt, delay_us;

	if (!st) return 0;

	rtt = qn->smoothed_rtt;
	if (rtt < 1000)
		rtt = 1000; /* Minimum 1ms for pacing math */

	lws_usec_t now = lws_now_usecs();
	lws_usec_t elapsed = now - st->last_pacing_time;
	st->last_pacing_time = now;

	/* Replenish credit based on elapsed time: R = cwnd / srtt */
	size_t credit_added = (size_t)(((uint64_t)elapsed * (uint64_t)st->cwnd) / (uint64_t)rtt);
	st->pacing_credit += credit_added;

	/* Cap credit to max burst to prevent micro-bursts (e.g. 10 packets) */
	size_t max_burst = 10 * (lws_get_vhost(nwsi)->quic_mtu ? lws_get_vhost(nwsi)->quic_mtu : 1280);
	if (st->pacing_credit > max_burst)
		st->pacing_credit = max_burst;

	if (st->pacing_credit >= bytes_to_send) {
		/* We have enough credit to send this packet */
		return 0;
	}

	/* Not enough credit. Calculate how long it will take to earn the missing credit. */
	size_t missing_credit = bytes_to_send - st->pacing_credit;
	delay_us = (lws_usec_t)(((uint64_t)missing_credit * (uint64_t)rtt) / (uint64_t)st->cwnd);

	if (delay_us == 0)
		delay_us = 1;

	return delay_us;
}

const struct lws_cc_ops lws_cc_ops_cubic = {
	.init			= cubic_init,
	.on_sent		= cubic_on_sent,
	.on_ack			= cubic_on_ack,
	.on_loss		= cubic_on_loss,
	.can_send		= cubic_can_send,
	.get_pacing_delay	= cubic_get_pacing_delay,
};
