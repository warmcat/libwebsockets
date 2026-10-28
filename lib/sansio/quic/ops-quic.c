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

#include "private-lib-core.h"
#include "sansio/quic/private-lib-roles-quic.h"

static int quic_secret_cb(struct lws *wsi, enum lws_tls_quic_secret_type type, const uint8_t *secret, size_t secret_len);

/*
 * 0-RTT debug accounting helper for the QUIC-Interop-Runner "zerortt"
 * failure mode (client emits too many bytes in 1-RTT packets after
 * attempting 0-RTT; the runner fails the test if 1-RTT payload bytes
 * exceed 0.5 * NUM_FILES * FILENAMELEN, i.e. 5000 bytes for the default
 * 40-file / 250-char-name case).
 *
 * Fires ONLY on the bad path: client-side connections that attempted
 * 0-RTT (early_data_status == LWS_0RTT_STATUS_ATTEMPTED).  In every
 * other case it collapses to a single cheap branch and returns, so it
 * is safe to call from every frame-queueing site without polluting
 * normal H3 / server logs.  Defined here, above its first caller, so no
 * forward declaration is needed.
 */
static void
lws_quic_dbg_1rtt_account(struct lws_quic_netconn *qn,
			  const struct lws_quic_tx_frame *f,
			  const char *where)
{
	uint64_t bytes;

	if (!qn || !f || qn->is_server ||
	    qn->early_data_status != LWS_0RTT_STATUS_ATTEMPTED)
		return;

	bytes = (uint64_t)f->len;

	/*
	 * The byte/frame counters stay maintained at every log level so a
	 * future dump of qn->dbg_1rtt_* works regardless; only the per-frame
	 * notice line and its label build are compiled out under no-logs.
	 */
	qn->dbg_1rtt_frames++;
	qn->dbg_1rtt_bytes += bytes;
	if (!qn->handshake_done) {
		qn->dbg_1rtt_pre_hs_frames++;
		qn->dbg_1rtt_pre_hs_bytes += bytes;
	}

#if (_LWS_ENABLED_LOGS & LLL_INFO)
	{
		const char *name;
		uint8_t type = (uint8_t)f->type;

		/* STREAM frames carry 0x08-0x0f depending on OFF/LEN/FIN bits;
		 * the enum is laid out so LWS_QUIC_FT_MAX_DATA (0x10) is the
		 * next named value, so it bounds the STREAM range cleanly */
		if (type >= LWS_QUIC_FT_STREAM && type < LWS_QUIC_FT_MAX_DATA)
			name = "STREAM";
		else switch (type) {
		case LWS_QUIC_FT_PADDING:		  name = "PADDING";		break;
		case LWS_QUIC_FT_PING:			  name = "PING";		break;
		case LWS_QUIC_FT_ACK:			  name = "ACK";			break;
		case LWS_QUIC_FT_ACK_ECN:		  name = "ACK_ECN";		break;
		case LWS_QUIC_FT_RESET_STREAM:		  name = "RESET_STREAM";	break;
		case LWS_QUIC_FT_STOP_SENDING:		  name = "STOP_SENDING";	break;
		case LWS_QUIC_FT_CRYPTO:		  name = "CRYPTO";		break;
		case LWS_QUIC_FT_MAX_DATA:		  name = "MAX_DATA";		break;
		case LWS_QUIC_FT_MAX_STREAM_DATA:	  name = "MAX_STREAM_DATA";	break;
		case LWS_QUIC_FT_MAX_STREAMS_BIDI:	  name = "MAX_STREAMS_BIDI";	break;
		case LWS_QUIC_FT_MAX_STREAMS_UNIDI:	  name = "MAX_STREAMS_UNIDI";	break;
		case LWS_QUIC_FT_DATA_BLOCKED:		  name = "DATA_BLOCKED";	break;
		case LWS_QUIC_FT_STREAM_DATA_BLOCKED:	  name = "STREAM_DATA_BLOCKED";	break;
		case LWS_QUIC_FT_STREAMS_BLOCKED_BIDI:	  name = "STREAMS_BLOCKED_B";	break;
		case LWS_QUIC_FT_STREAMS_BLOCKED_UNIDI:	  name = "STREAMS_BLOCKED_U";	break;
		case LWS_QUIC_FT_NEW_CONNECTION_ID:	  name = "NEW_CONNECTION_ID";	break;
		case LWS_QUIC_FT_RETIRE_CONNECTION_ID:	  name = "RETIRE_CONNECTION_ID";break;
		case LWS_QUIC_FT_PATH_CHALLENGE:	  name = "PATH_CHALLENGE";	break;
		case LWS_QUIC_FT_PATH_RESPONSE:		  name = "PATH_RESPONSE";	break;
		case LWS_QUIC_FT_CONNECTION_CLOSE:	  name = "CONNECTION_CLOSE";	break;
		case LWS_QUIC_FT_CONNECTION_CLOSE_APP:	  name = "CC_APP";		break;
		case LWS_QUIC_FT_HANDSHAKE_DONE:	  name = "HANDSHAKE_DONE";	break;
		case LWS_QUIC_FT_DATAGRAM:		  name = "DATAGRAM";		break;
		case LWS_QUIC_FT_DATAGRAM + 1:		  name = "DATAGRAM_LEN";	break;
		default:				  name = "OTHER";		break;
		}

		lwsl_wsi_notice(qn->nwsi, "0RTTDBG app-queue %-18s type=0x%02x len=%5llu "
				"stream=%u sid=0x%x @%s (hs_done=%d) | "
				"app-total: %llu frames / %llu bytes (pre-hs %llu / %llu)",
				name, type, (unsigned long long)bytes,
				f->stream_id != 0, (unsigned)f->stream_id, where,
				qn->handshake_done,
				(unsigned long long)qn->dbg_1rtt_frames,
				(unsigned long long)qn->dbg_1rtt_bytes,
				(unsigned long long)qn->dbg_1rtt_pre_hs_frames,
				(unsigned long long)qn->dbg_1rtt_pre_hs_bytes);
		(void)name;
	}
#endif
}

/*
 * A flow control limit we advertise: our transport parameters' initial_max_*
 * and the limits in MAX_DATA / MAX_STREAM_DATA.  Fault injection can
 * advertise a bigger one from a range, eg "wsi/quic_tp_window(2^62-1..2^62)",
 * to exercise how the peer handles huge grants.  Only the advertisement
 * changes, not what we enforce, so a test using it must keep each stream and
 * the connection under the window we really give (LWS_QUIC_DEFAULT_WINDOW).
 */
static uint64_t
lws_quic_fi_window(struct lws *wsi, const char *fi_name, uint64_t limit)
{
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	uint64_t u;

	if (!lws_fi_range(&wsi->fic, fi_name, &u))
		return u;
#else
	(void)wsi;
	(void)fi_name;
#endif

	return limit;
}

/*
 * A client took a Retry: what it had in flight in Initial is sent again, from
 * the start of the reset Initial PN space, in the order it was first sent
 */
static void
lws_quic_initial_requeue(struct lws_quic_netconn *qn)
{
	size_t bytes = 0;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
			qn->in_flight[LWS_QUIC_LEVEL_INITIAL].head) {
		struct lws_quic_tx_frame *f = lws_container_of(d,
					struct lws_quic_tx_frame, list);

		bytes += f->wire_len;
		lws_dll2_remove(&f->list);
		f->sent_in_pn = 0;
		f->sent_time_us = 0;
		f->wire_len = 0;
		lws_dll2_add_tail(&f->list,
				  &qn->pending_tx[LWS_QUIC_LEVEL_INITIAL]);
	} lws_end_foreach_dll_safe(d, d1);

	if (bytes && qn->cc_ops && qn->cc_ops->on_discard && qn->nwsi)
		qn->cc_ops->on_discard(qn->nwsi, bytes);
}

/* the frames the connection has in flight, over all levels */
static uint32_t
lws_quic_in_flight_count(const struct lws_quic_netconn *qn)
{
	uint32_t n = 0;
	int l;

	for (l = 0; l < LWS_QUIC_LEVEL_COUNT; l++)
		n += qn->in_flight[l].count;

	return n;
}

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
void
lws_quic_fi_stat_ack_start(struct lws_quic_netconn *qn)
{
	qn->fi_stats.ack_frames++;
	qn->fi_stats.cur_visits = 0;
	qn->fi_stats.cur_ranges = 0;
	qn->fi_stats.cur_in_flight = lws_quic_in_flight_count(qn);
}

void
lws_quic_fi_stat_ack_done(struct lws_quic_netconn *qn)
{
	uint64_t allowed = qn->fi_stats.cur_ranges +
			   2 * qn->fi_stats.cur_in_flight;

	if (qn->fi_stats.cur_visits > allowed &&
	    qn->fi_stats.cur_visits - allowed > qn->fi_stats.excess_max)
		qn->fi_stats.excess_max = qn->fi_stats.cur_visits - allowed;
}
#endif

/*
 * Is it time to hold back new frames until some in flight are acked or found
 * lost, as for the congestion window, see LWS_QUIC_IN_FLIGHT_MAX
 */
static int
lws_quic_in_flight_full(const struct lws_quic_netconn *qn)
{
	return lws_quic_in_flight_count(qn) >= LWS_QUIC_IN_FLIGHT_MAX;
}

/*
 * RFC 9000 17.2.3: a client stops sending 0-RTT once it has the 1-RTT keys.
 * 0-RTT and 1-RTT share the application PN space, so a frame first sent in
 * 0-RTT that has to go again after that, eg because the server refused 0-RTT
 * and will never ack it, goes again in 1-RTT
 */
static int
lws_quic_resend_level(const struct lws_quic_netconn *qn, int level)
{
	if (level == LWS_QUIC_LEVEL_EARLY && qn->handshake_done)
		return LWS_QUIC_LEVEL_APP;

	return level;
}

/*
 * The client handshake completed: frames queued for 0-RTT and not sent yet go
 * in 1-RTT instead.  Those already sent in 0-RTT stay in flight, acked in the
 * shared application PN space if the server took them, or found lost there
 * and resent in 1-RTT if it didn't
 */
void
lws_quic_early_tx_to_app(struct lws_quic_netconn *qn)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   qn->pending_tx[LWS_QUIC_LEVEL_EARLY].head) {
		struct lws_quic_tx_frame *f = lws_container_of(d,
					struct lws_quic_tx_frame, list);

		lws_dll2_remove(&f->list);
		lws_quic_dbg_1rtt_account(qn, f, "early-to-1rtt");
		lws_dll2_add_tail(&f->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
	} lws_end_foreach_dll_safe(d, d1);
}

void
lws_quic_queue_path_challenge(struct lws *nwsi)
{
        if (!nwsi || !nwsi->quic.qn) return;
        struct lws_quic_tx_frame *f_pc = lws_zalloc(sizeof(*f_pc) + 8, "quic path_chall");
        if (f_pc) {
                f_pc->type = LWS_QUIC_FT_PATH_CHALLENGE;
                f_pc->len = 8;
                f_pc->data = (uint8_t *)&f_pc[1];
                if (lws_get_random(nwsi->a.context, f_pc->data, 8) != 8) {
                        lws_free(f_pc);
                        return;
                }
		memcpy(nwsi->quic.qn->path_challenge, f_pc->data, 8);
		nwsi->quic.qn->path_challenge_pending = 1;

		lws_quic_dbg_1rtt_account(nwsi->quic.qn, f_pc, "path-challenge");
		lws_dll2_add_tail(&f_pc->list, &nwsi->quic.qn->pending_tx[LWS_QUIC_LEVEL_APP]);
		lws_callback_on_writable(nwsi);
	}
}

int
lws_quic_sa46_same_path(const lws_sockaddr46 *a, const lws_sockaddr46 *b)
{
	if (a->sa4.sin_family != b->sa4.sin_family)
		return 0;
#if defined(LWS_WITH_IPV6)
	if (a->sa4.sin_family == AF_INET6)
		return a->sa6.sin6_port == b->sa6.sin6_port &&
		       !lws_sa46_compare_sin6_addr(&a->sa6.sin6_addr,
						   &b->sa6.sin6_addr);
#endif
	return a->sa4.sin_port == b->sa4.sin_port &&
	       a->sa4.sin_addr.s_addr == b->sa4.sin_addr.s_addr;
}

/*
 * Frames that are not sent again when the packet carrying them is lost:
 * DATAGRAM (RFC 9221 5), PATH_RESPONSE (RFC 9000 13.3), which answers one
 * PATH_CHALLENGE on the path it came from; a peer still waiting for the answer
 * sends a new challenge, and PING (RFC 9000 13.3), which carries nothing: it
 * was there to elicit an ack, and the loss was found from the acks that came.
 */
static int
lws_quic_frame_not_retransmitted(const struct lws_quic_tx_frame *f)
{
	return (f->type & 0xfe) == LWS_QUIC_FT_DATAGRAM ||
	       f->type == LWS_QUIC_FT_PATH_RESPONSE ||
	       f->type == LWS_QUIC_FT_PING;
}

/*
 * A server's PATH_CHALLENGE to a peer address it is probing, ie, not the
 * connection's path.  Losing it says nothing about the connection's path, so
 * it doesn't count as congestion there, nor towards PMTUD's black hole, and
 * it isn't sent again by loss recovery: that would send it again each time
 * a few packets on the connection's path are acked after it, ie, as fast as
 * the connection goes.  The probe sends it again once a PTO instead (RFC 9000
 * 8.2.1), see lws_quic_path_probe_sul_cb().
 */
static int
lws_quic_frame_probes_another_path(const struct lws_quic_netconn *qn,
				   const struct lws_quic_tx_frame *f)
{
	return f->type == LWS_QUIC_FT_PATH_CHALLENGE && f->has_dest &&
	       !lws_quic_sa46_same_path(&f->dest_sa46, &qn->path_sa46);
}

/*
 * DPLPMTUD (RFC 9000 14.3): each probe is a packet of its own, a PING padded
 * out to the size being probed.  So the search goes on whether there is
 * anything else to send or not, and the peer acks each probe, since a PING is
 * ack-eliciting.  Losing a probe costs nothing but the probe: it isn't sent
 * again by loss recovery, and doesn't count as congestion (RFC 9000 14.4).
 */
static uint32_t
lws_quic_pmtud_ceiling(const struct lws_quic_netconn *qn)
{
	if (qn->peer_max_udp_payload &&
	    qn->peer_max_udp_payload <
			LWS_QUIC_PMTU_CEILING - LWS_QUIC_PMTU_OVERHEAD)
		return qn->peer_max_udp_payload + LWS_QUIC_PMTU_OVERHEAD;

	return LWS_QUIC_PMTU_CEILING;
}

/* the confirming probes given up for lost have nothing to say any more */
static void
lws_quic_pmtud_bh_from_late_clear(struct lws_quic_netconn *qn)
{
	unsigned int n;

	for (n = 0; n < LWS_ARRAY_SIZE(qn->pmtud_bh_from_late_pn); n++)
		qn->pmtud_bh_from_late_pn[n] = LWS_QUIC_PMTUD_PROBE_NONE;
	qn->pmtud_bh_from_fails = 0;
}

/* start the search again from the base, eg, on a new path */
void
lws_quic_pmtud_reset(struct lws_quic_netconn *qn)
{
	qn->current_mtu			= LWS_QUIC_PMTU_BASE;
	qn->probed_mtu			= LWS_QUIC_PMTU_FIRST_PROBE;
	qn->pmtud_probe_pn		= LWS_QUIC_PMTUD_PROBE_NONE;
	qn->pmtud_bh_probe_pn		= LWS_QUIC_PMTUD_PROBE_NONE;
	qn->pmtud_bh_from_probe_pn	= LWS_QUIC_PMTUD_PROBE_NONE;
	lws_quic_pmtud_bh_from_late_clear(qn);
	qn->pmtud_held_fails		= 0;
	qn->pmtud_late_probe_pn		= LWS_QUIC_PMTUD_PROBE_NONE;
	qn->pmtud_probe_fails		= 0;
	qn->consecutive_mtu_losses	= 0;
	qn->pmtud_big_acked_pn1		= 0;
	qn->pmtud_bh_from_mtu		= 0;
	qn->pmtud_raise_at		= 0;
	qn->pmtud_state			= 1; /* SEARCHING */
}

/*
 * The stream limits a new connection advertises to its peer in its transport
 * parameters: the peer's streams are held to them until a MAX_STREAMS raises
 * them (lws_quic_stream_cleanup())
 */
static void
lws_quic_streams_limits_init(struct lws_quic_netconn *qn, uint64_t limit)
{
	qn->max_streams_bidi_local	= limit;
	qn->max_streams_bidi_adv	= limit;
	qn->max_streams_bidi_window	= limit;
	qn->max_streams_unidi_local	= limit;
	qn->max_streams_unidi_adv	= limit;
	qn->max_streams_unidi_window	= limit;
}

/*
 * Not before the handshake is confirmed, ie, until both sides have 1-RTT keys
 * and the client knows the server's 1-RTT packets get through, nor to a peer
 * whose address a server hasn't validated
 */
static int
lws_quic_pmtud_may_probe(const struct lws_quic_netconn *qn)
{
	return qn->handshake_confirmed && !qn->is_closing && qn->nwsi &&
	       !(qn->is_server && !qn->address_validated);
}

static int
lws_quic_pmtud_queue_probe(struct lws_quic_netconn *qn, uint8_t kind)
{
	struct lws_quic_tx_frame *f = lws_zalloc(sizeof(*f), "quic pmtud probe");

	if (!f)
		return 1;

	f->type		= LWS_QUIC_FT_PING;
	f->pmtud_probe	= kind;
	lws_quic_dbg_1rtt_account(qn, f, "pmtud-probe");
	/* lws_quic_packet_tx() sends it ahead of what else is waiting */
	lws_dll2_add_tail(&f->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
	lws_callback_on_writable(qn->nwsi);

	return 0;
}

/*
 * Queue the next search probe, if the search wants one now and none is on its
 * way.  A search that settled below the ceiling tries the size it settled
 * under again once LWS_QUIC_PMTUD_RAISE_US is up, since the path may carry it
 * by then; one that went back to the base for a black hole that wasn't
 * confirmed either way starts again from the base.
 */
void
lws_quic_pmtud_kick(struct lws_quic_netconn *qn)
{
	if (!lws_quic_pmtud_may_probe(qn))
		return;

	if (qn->pmtud_raise_at && lws_wsi_now(qn->nwsi) >= qn->pmtud_raise_at) {
		qn->pmtud_raise_at	= 0;
		/* every size is worth trying again now */
		qn->pmtud_held_fails	= 0;
		if (!qn->pmtud_state)
			lws_quic_pmtud_reset(qn);
		else if (qn->pmtud_state == 2) {
			qn->pmtud_probe_fails	= 0;
			qn->pmtud_state		= 1; /* SEARCHING */
		}
	}

	if (qn->pmtud_state != 1 || qn->pmtud_probe_queued ||
	    qn->pmtud_probe_pn != LWS_QUIC_PMTUD_PROBE_NONE)
		return;

	if (qn->probed_mtu > lws_quic_pmtud_ceiling(qn)) {
		qn->pmtud_state = 2; /* SEARCH_COMPLETE */
		return;
	}

	if (!lws_quic_pmtud_queue_probe(qn, LWS_QUIC_PMTUD_PROBE_SEARCH))
		qn->pmtud_probe_queued = 1;
}

/*
 * A search probe of mtu was acked: the path carries it, so the search goes on
 * from there, unless it has reached the ceiling.  If the search had settled
 * below mtu, because the probe's ack was late, it searches on.
 */
static void
lws_quic_pmtud_carries(struct lws_quic_netconn *qn, uint32_t mtu)
{
	uint32_t ceiling = lws_quic_pmtud_ceiling(qn);

	qn->pmtud_probe_pn		= LWS_QUIC_PMTUD_PROBE_NONE;
	qn->consecutive_mtu_losses	= 0;

	if (mtu <= qn->current_mtu || !qn->pmtud_state)
		return;

	lwsl_wsi_info(qn->nwsi, "QUIC PMTUD: mtu %u -> %u", qn->current_mtu,
		      mtu);
	qn->current_mtu		= mtu;
	qn->pmtud_probe_fails	= 0;
	qn->pmtud_raise_at	= 0;

	if (mtu >= ceiling) {
		qn->pmtud_state = 2; /* SEARCH_COMPLETE */
		return;
	}

	qn->pmtud_state = 1; /* SEARCHING */
	if (qn->probed_mtu <= mtu) {
		qn->probed_mtu = mtu + LWS_QUIC_PMTU_STEP;
		if (qn->probed_mtu > ceiling)
			qn->probed_mtu = ceiling;
	}

	if (!qn->pmtud_held_fails)
		return;

	if (mtu >= qn->pmtud_held_mtu) {
		/* a late ack: the path carries it after all */
		qn->pmtud_held_fails = 0;
		return;
	}

	if (qn->probed_mtu != qn->pmtud_held_mtu)
		return;

	/*
	 * The search got back to the size it lost probes of before a black
	 * hole started it again: those still count
	 */
	qn->pmtud_probe_fails	= qn->pmtud_held_fails;
	qn->pmtud_held_fails	= 0;
	if (qn->pmtud_probe_fails < LWS_QUIC_PMTUD_MAX_PROBES)
		return;

	lwsl_wsi_info(qn->nwsi, "QUIC PMTUD: %u probes of %u were lost before, "
		      "settling on %u", qn->pmtud_probe_fails, qn->probed_mtu,
		      qn->current_mtu);
	qn->pmtud_state		= 2; /* SEARCH_COMPLETE */
	qn->pmtud_raise_at	= lws_wsi_now(qn->nwsi) + LWS_QUIC_PMTUD_RAISE_US;
}

/*
 * A packet that wasn't a probe was lost.  If it was bigger than the base, and
 * enough of those were lost with no bigger packet sent after them getting
 * through, the path's MTU may have fallen: go back to the base now, and check
 * the base still gets through, see LWS_QUIC_PMTUD_BH_LOSSES.  *last_pn is the
 * PN of the last lost frame the caller saw, so each packet counts once.
 */
static void
lws_quic_pmtud_lost_packet(struct lws_quic_netconn *qn,
			   const struct lws_quic_tx_frame *f, uint64_t *last_pn)
{
	if (f->sent_in_pn == *last_pn)
		return;
	*last_pn = f->sent_in_pn;

	if (f->packet_size + LWS_QUIC_PMTU_OVERHEAD <= LWS_QUIC_PMTU_BASE ||
	    f->sent_in_pn < qn->pmtud_big_acked_pn1)
		return;

	if (qn->consecutive_mtu_losses < LWS_QUIC_PMTUD_BH_LOSSES)
		qn->consecutive_mtu_losses++;

	if (qn->consecutive_mtu_losses < LWS_QUIC_PMTUD_BH_LOSSES ||
	    qn->current_mtu <= LWS_QUIC_PMTU_BASE ||
	    !lws_quic_pmtud_may_probe(qn))
		return;

	lwsl_wsi_info(qn->nwsi, "QUIC PMTUD: %u packets bigger than %u lost, "
		      "going back to %u", qn->consecutive_mtu_losses,
		      LWS_QUIC_PMTU_BASE - LWS_QUIC_PMTU_OVERHEAD,
		      LWS_QUIC_PMTU_BASE);

	qn->pmtud_bh_from_mtu	= qn->current_mtu;
	qn->pmtud_bh_from_state	= qn->pmtud_state;
	qn->current_mtu		= LWS_QUIC_PMTU_BASE;
	qn->pmtud_state		= 0; /* BASE */
	/*
	 * A search probe on its way stays the search's: if this was no black
	 * hole, the search goes on from where it was, and that probe's loss
	 * counts against its size, as it would have.  Forgotten, nothing would
	 * stop the search sending another of that size while it is still out,
	 * so a stall that looked like a black hole would cost the path one
	 * more probe it can't carry.  A confirming probe from an earlier black
	 * hole says nothing now.
	 */
	qn->pmtud_late_probe_pn	= LWS_QUIC_PMTUD_PROBE_NONE;
	qn->pmtud_bh_from_probe_pn = LWS_QUIC_PMTUD_PROBE_NONE;
	lws_quic_pmtud_bh_from_late_clear(qn);
	qn->pmtud_raise_at	= lws_wsi_now(qn->nwsi) + LWS_QUIC_PMTUD_RAISE_US;

	if (qn->pmtud_bh_probe_queued ||
	    qn->pmtud_bh_probe_pn != LWS_QUIC_PMTUD_PROBE_NONE)
		return;

	if (!lws_quic_pmtud_queue_probe(qn, LWS_QUIC_PMTUD_PROBE_BASE))
		qn->pmtud_bh_probe_queued = 1;
}

/*
 * The base gets through, and the probe of the size from before going back to
 * it was lost: the path's MTU fell, so the search starts again from the base
 */
static void
lws_quic_pmtud_bh_confirmed(struct lws_quic_netconn *qn)
{
	lwsl_wsi_warn(qn->nwsi, "QUIC PMTUD: black hole: packets of %u are "
		      "lost, the base gets through: searching again from %u",
		      qn->pmtud_bh_from_mtu - LWS_QUIC_PMTU_OVERHEAD,
		      LWS_QUIC_PMTU_BASE);
	qn->pmtud_bh_from_mtu		= 0;
	lws_quic_pmtud_bh_from_late_clear(qn);
	qn->consecutive_mtu_losses	= 0;
	/*
	 * A search probe from before says nothing about the new search, but
	 * those of its size that were lost still count against that size,
	 * see LWS_QUIC_PMTUD_BH_LOSSES.  It is always bigger than where the
	 * new search starts.
	 */
	qn->pmtud_held_fails		= qn->pmtud_probe_fails;
	qn->pmtud_held_mtu		= qn->probed_mtu;
	qn->pmtud_probe_pn		= LWS_QUIC_PMTUD_PROBE_NONE;
	qn->probed_mtu			= LWS_QUIC_PMTU_FIRST_PROBE;
	qn->pmtud_probe_fails		= 0;
	qn->pmtud_raise_at		= 0;
	qn->pmtud_state			= 1; /* SEARCHING */
	lws_quic_pmtud_kick(qn);
}

/*
 * A packet bigger than the base got through while a black hole is suspected,
 * not confirmed yet: it wasn't a black hole, so go back to the size from
 * before, and the search to where it was
 */
static void
lws_quic_pmtud_bh_undo(struct lws_quic_netconn *qn)
{
	lwsl_wsi_info(qn->nwsi, "QUIC PMTUD: a packet bigger than %u got "
		      "through after all, back to %u", LWS_QUIC_PMTU_BASE -
		      LWS_QUIC_PMTU_OVERHEAD, qn->pmtud_bh_from_mtu);
	qn->current_mtu		= qn->pmtud_bh_from_mtu;
	qn->pmtud_state		= qn->pmtud_bh_from_state;
	qn->pmtud_bh_from_mtu	= 0;
	/* whichever packet it was, the confirming probes have nothing to say */
	qn->pmtud_bh_from_probe_pn = LWS_QUIC_PMTUD_PROBE_NONE;
	lws_quic_pmtud_bh_from_late_clear(qn);
	/* a settled search tries the size it settled under again later */
	qn->pmtud_raise_at	= qn->pmtud_state == 2 ? lws_wsi_now(qn->nwsi) +
						LWS_QUIC_PMTUD_RAISE_US : 0;
	lws_quic_pmtud_kick(qn);
}

/*
 * Packet f, bigger than the base, was acked.  If going back to the base for a
 * black hole is still unconfirmed, f was sent before then, so it was loss,
 * or it is the probe of the size from before: it wasn't a black hole.
 */
static void
lws_quic_pmtud_big_acked(struct lws_quic_netconn *qn,
			 const struct lws_quic_tx_frame *f)
{
	qn->consecutive_mtu_losses = 0;
	if (f->sent_in_pn >= qn->pmtud_big_acked_pn1)
		qn->pmtud_big_acked_pn1 = f->sent_in_pn + 1;

	if (qn->pmtud_bh_from_mtu)
		lws_quic_pmtud_bh_undo(qn);
}

/*
 * The transport couldn't take the packet with probe f in it, which goes back
 * to pending_tx to be sent in a packet of its own again
 */
static void
lws_quic_pmtud_probe_unsent(struct lws_quic_netconn *qn,
			    const struct lws_quic_tx_frame *f)
{
	if (f->pmtud_probe == LWS_QUIC_PMTUD_PROBE_BASE) {
		if (f->sent_in_pn == qn->pmtud_bh_probe_pn)
			qn->pmtud_bh_probe_pn = LWS_QUIC_PMTUD_PROBE_NONE;
		qn->pmtud_bh_probe_queued = 1;
	} else if (f->pmtud_probe == LWS_QUIC_PMTUD_PROBE_FROM) {
		if (f->sent_in_pn == qn->pmtud_bh_from_probe_pn)
			qn->pmtud_bh_from_probe_pn = LWS_QUIC_PMTUD_PROBE_NONE;
		qn->pmtud_bh_from_probe_queued = 1;
	} else if (f->pmtud_probe) {
		if (f->sent_in_pn == qn->pmtud_probe_pn)
			qn->pmtud_probe_pn = LWS_QUIC_PMTUD_PROBE_NONE;
		qn->pmtud_probe_queued = 1;
	}
}

/*
 * A probe's packet was lost.  The size of a search probe may be too big for
 * the path, or the probe was just unlucky, so it is tried again until that
 * size lost LWS_QUIC_PMTUD_MAX_PROBES, then the search settles on the size it
 * has.  A base size probe being lost says the path loses small packets too,
 * eg, it is down for a while, so the big ones lost before it say nothing
 * about its MTU: the base is probed again, until one gets through.  The probe
 * of the size from before going back, sent once the base got through, may
 * only be late, so it is tried again until LWS_QUIC_PMTUD_MAX_PROBES of them
 * are lost, which confirms the black hole.  A search probe sent before going
 * back counts as it would have, for the search going on if it was no black
 * hole.
 *
 * Returns nonzero if f is a probe, which the caller frees, without sending it
 * again or counting it as congestion.
 */
static int
lws_quic_pmtud_probe_lost(struct lws_quic_netconn *qn,
			  const struct lws_quic_tx_frame *f)
{
	if (!f->pmtud_probe)
		return 0;

	if (f->pmtud_probe == LWS_QUIC_PMTUD_PROBE_FROM) {
		if (f->sent_in_pn != qn->pmtud_bh_from_probe_pn)
			return 1; /* it has nothing to say any more */
		qn->pmtud_bh_from_probe_pn = LWS_QUIC_PMTUD_PROBE_NONE;
		if (!qn->pmtud_bh_from_mtu)
			return 1;
		/*
		 * Its ack may yet come, if it was only late.  There is room
		 * for every one until the last confirms the black hole.
		 */
		if (qn->pmtud_bh_from_fails <
				LWS_ARRAY_SIZE(qn->pmtud_bh_from_late_pn))
			qn->pmtud_bh_from_late_pn[qn->pmtud_bh_from_fails] =
								f->sent_in_pn;
		if (++qn->pmtud_bh_from_fails >= LWS_QUIC_PMTUD_MAX_PROBES)
			lws_quic_pmtud_bh_confirmed(qn);
		else if (!qn->pmtud_bh_from_probe_queued &&
			 lws_quic_pmtud_may_probe(qn) &&
			 !lws_quic_pmtud_queue_probe(qn,
						LWS_QUIC_PMTUD_PROBE_FROM))
			qn->pmtud_bh_from_probe_queued = 1;
		return 1;
	}

	if (f->pmtud_probe == LWS_QUIC_PMTUD_PROBE_BASE) {
		if (f->sent_in_pn != qn->pmtud_bh_probe_pn)
			return 1;
		qn->pmtud_bh_probe_pn = LWS_QUIC_PMTUD_PROBE_NONE;
		if (qn->pmtud_bh_from_mtu && !qn->pmtud_bh_probe_queued &&
		    lws_quic_pmtud_may_probe(qn) &&
		    !lws_quic_pmtud_queue_probe(qn, LWS_QUIC_PMTUD_PROBE_BASE))
			qn->pmtud_bh_probe_queued = 1;
		return 1;
	}

	if (f->sent_in_pn != qn->pmtud_probe_pn)
		return 1; /* one from before the search was reset */

	/* its ack may yet come, if it was only late, see lws_quic_ack_range() */
	qn->pmtud_late_probe_pn		= f->sent_in_pn;
	qn->pmtud_late_probe_mtu	= qn->probed_mtu;
	qn->pmtud_probe_pn		= LWS_QUIC_PMTUD_PROBE_NONE;
	if (++qn->pmtud_probe_fails >= LWS_QUIC_PMTUD_MAX_PROBES) {
		/*
		 * Back at the base for a black hole, it's the search going on
		 * from where it was, if it was no black hole, that settles
		 */
		lwsl_wsi_info(qn->nwsi, "QUIC PMTUD: %u lost probes of %u, "
			      "settling on %u", qn->pmtud_probe_fails,
			      qn->probed_mtu, qn->pmtud_state ?
				qn->current_mtu : qn->pmtud_bh_from_mtu);
		if (!qn->pmtud_state)
			qn->pmtud_bh_from_state	= 2; /* SEARCH_COMPLETE */
		else {
			qn->pmtud_state		= 2; /* SEARCH_COMPLETE */
			qn->pmtud_raise_at	= lws_wsi_now(qn->nwsi) +
						LWS_QUIC_PMTUD_RAISE_US;
		}
	} else
		lws_quic_pmtud_kick(qn);

	return 1;
}

/*
 * The most DATAGRAM payload one packet can carry on the connection's path as
 * it is now: a short header packet with nothing else in it, fitted the way
 * lws_quic_packet_tx() fits frames
 */
static size_t
lws_quic_datagram_max(const struct lws_quic_netconn *qn)
{
	uint32_t mtu = qn->current_mtu ? qn->current_mtu : 1280;
	size_t room = mtu > 48 ? mtu - 48 : 1200,
	       over = 1u + qn->rem_cid.len + 2u + LWS_QUIC_FRAME_HDR_MAX +
		      LWS_QUIC_FIT_SLACK;

	if (room > 1200 && !qn->handshake_done)
		room = 1200;

	return room > over ? room - over : 0;
}

/*
 * Stop probing the address in probing_sa46.  failed says why the probe failed,
 * or is NULL when it's only superseded by a probe of another address
 */
void
lws_quic_path_probe_abandon(struct lws *nwsi, const char *failed)
{
	struct lws_quic_netconn *qn = nwsi ? nwsi->quic.qn : NULL;

	if (!qn || !qn->is_server || !qn->probing_sa46_valid)
		return;

	if (failed) {
		unsigned int shift = qn->probe_fails;
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
		char ads[64];

		lws_sa46_write_numeric_address(&qn->probing_sa46, ads,
					       sizeof(ads));
#endif

		if (shift > LWS_QUIC_PROBE_HOLDOFF_MAX_SHIFT)
			shift = LWS_QUIC_PROBE_HOLDOFF_MAX_SHIFT;
		if (qn->probe_fails < 255)
			qn->probe_fails++;
		qn->probe_holdoff_until = lws_wsi_now(nwsi) +
				((lws_usec_t)LWS_QUIC_PROBE_HOLDOFF_US << shift);

		lwsl_wsi_notice(nwsi, "QUIC: probe of peer's new address %s "
				"failed, %s (%u in a row, sent %llu, rx %llu): "
				"staying on validated path, not probing it "
				"again for %llus", ads, failed, qn->probe_fails,
				(unsigned long long)qn->probe_bytes_sent,
				(unsigned long long)qn->probe_bytes_received,
				(unsigned long long)(LWS_QUIC_PROBE_HOLDOFF_US
						<< shift) / LWS_US_PER_SEC);
	} else
		lwsl_wsi_info(nwsi, "QUIC: path probe superseded");

	lws_sul_cancel(&qn->path_probe_sul);
	qn->probing_sa46_valid = 0;
	qn->path_challenge_pending = 0;
	/*
	 * probing_sa46 and the probe byte counters are deliberately kept: if
	 * the same address shows up again, its allowance and what we already
	 * sent there carry over, so the 3x bound holds per address across
	 * probe attempts and is not reset by simply retriggering a probe.
	 */

	/*
	 * Drop our unsent PATH_CHALLENGE.  Anything of ours still in flight
	 * to the abandoned address is purged by the tx path when loss
	 * recovery requeues it, since its destination then matches neither
	 * the committed path nor a live probe.
	 */
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   qn->pending_tx[LWS_QUIC_LEVEL_APP].head) {
		struct lws_quic_tx_frame *f = lws_container_of(d,
					struct lws_quic_tx_frame, list);

		if (f->type == LWS_QUIC_FT_PATH_CHALLENGE) {
			lws_dll2_remove(&f->list);
			lws_free(f);
		}
	} lws_end_foreach_dll_safe(d, d1);
}

/*
 * Queue the server's PATH_CHALLENGE, with the data in path_challenge, to the
 * address it is probing, unless one is already waiting to go.  It goes at the
 * head of the queue, so the tx path gives it a packet of its own, sized to
 * the address' anti-amplification allowance.
 */
static int
lws_quic_path_probe_queue_challenge(struct lws *nwsi)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	struct lws_quic_tx_frame *f;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      qn->pending_tx[LWS_QUIC_LEVEL_APP].head) {
		f = lws_container_of(d, struct lws_quic_tx_frame, list);
		if (f->type == LWS_QUIC_FT_PATH_CHALLENGE)
			return 0;
	} lws_end_foreach_dll(d);

	f = lws_zalloc(sizeof(*f) + sizeof(qn->path_challenge),
		       "quic path_chall");
	if (!f)
		return 1;

	f->type		= LWS_QUIC_FT_PATH_CHALLENGE;
	f->len		= sizeof(qn->path_challenge);
	f->data		= (uint8_t *)&f[1];
	memcpy(f->data, qn->path_challenge, sizeof(qn->path_challenge));
	f->dest_sa46	= qn->probing_sa46;
	f->has_dest	= 1;

	qn->path_challenge_pending = 1;
	lws_dll2_add_head(&f->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
	lws_callback_on_writable(nwsi);

	return 0;
}

/*
 * A connection's timers all live on the pt of its network wsi (G-536), so
 * that they run on the service thread that services the connection, and
 * that thread, which is the one that cancels them, owns the list they are
 * on.  The network wsi changes at ALPN negotiation, but to a new wsi on the
 * same tsi, so timers already scheduled stay on the right list.
 *
 * Debug SMP builds check, as each timer fires, that it fires on that thread.
 */
static void
lws_quic_sul_schedule(struct lws_quic_netconn *qn, lws_sorted_usec_list_t *sul,
		      sul_cb_t cb, lws_usec_t us)
{
	lws_sul_schedule(qn->nwsi->a.context, qn->nwsi->tsi, sul, cb, us);
}

#if defined(_DEBUG) && defined(LWS_WITH_NETWORK) && LWS_MAX_SMP > 1
#define lws_quic_sul_assert_thread(qn) \
	assert(lws_pthread_self_to_tsi((qn)->nwsi->a.context) < 0 || \
	       lws_pthread_self_to_tsi((qn)->nwsi->a.context) == \
						(int)(qn)->nwsi->tsi)
#else
#define lws_quic_sul_assert_thread(qn)
#endif

/*
 * Each PTO while the server's probe of a peer address is unanswered: send the
 * PATH_CHALLENGE again, in case it was lost, until the probe's deadline, when
 * it is abandoned (RFC 9000 8.2.1, 8.2.4).  It's the same challenge each
 * time, so a PATH_RESPONSE to any of them validates the address.
 */
static void
lws_quic_path_probe_sul_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_quic_netconn *qn = lws_container_of(sul,
					struct lws_quic_netconn, path_probe_sul);
	lws_usec_t now, next;

	if (!qn->nwsi || !qn->probing_sa46_valid)
		return;

	lws_quic_sul_assert_thread(qn);

	now = lws_wsi_now(qn->nwsi);
	if (now >= qn->probe_deadline) {
		lws_quic_path_probe_abandon(qn->nwsi, "no PATH_RESPONSE in "
						      "time (RFC 9000 8.2.4)");
		return;
	}

	if (lws_quic_path_probe_queue_challenge(qn->nwsi)) {
		lws_quic_path_probe_abandon(qn->nwsi, "OOM");
		return;
	}

	next = qn->probe_deadline - now;
	if (next > qn->probe_pto)
		next = qn->probe_pto;
	lws_quic_sul_schedule(qn, &qn->path_probe_sul,
			      lws_quic_path_probe_sul_cb, next);
}

/*
 * Client preferred_address active migration (RFC 9000 §9.5/§9.6).
 *
 * Swap the nwsi onto a fresh UDP socket (new source port) connected to the
 * server's preferred address, and start using the new DCID the server
 * advertised.  This is "break-before-make": the old path is abandoned at probe
 * start and in-flight data is recovered by QUIC loss detection.  A PATH_RESPONSE
 * validates the new path; a timeout reverts to a fresh socket on the original
 * server address with the original DCID.
 */
#define LWS_QUIC_PREFADDR_DEADLINE_US (10 * LWS_USEC_PER_SEC)

static void
lws_quic_prefaddr_sul_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_quic_netconn *qn = lws_container_of(sul,
					struct lws_quic_netconn, prefaddr_sul);
	struct lws *nwsi = qn->nwsi;

	if (!nwsi)
		return;

	lws_quic_sul_assert_thread(qn);

	lwsl_wsi_notice(nwsi, "QUIC: preferred_address path validation timed out, "
			   "reverting to original server path");

	qn->probing_sa46_valid = 0;
	qn->path_challenge_pending = 0;
	qn->prefaddr_active = 0;
	qn->rem_cid = qn->prefaddr_original_rem_cid;

	if (lws_io_path(nwsi, LWS_IOPATH_NEW_SOCKET,
			&qn->prefaddr_original_sa46))
		lwsl_wsi_err(nwsi, "prefaddr: revert socket failed");
	else
		qn->path_sa46 = qn->prefaddr_original_sa46;

	lws_callback_on_writable(nwsi);
}

int
lws_quic_client_probe_preferred_address(struct lws *nwsi,
					const lws_sockaddr46 *pref_sa46,
					const struct lws_quic_cid *pref_cid,
					const uint8_t *pref_token)
{
	struct lws_quic_netconn *qn;

	if (!nwsi || !nwsi->quic.qn || !pref_sa46)
		return 1;
	qn = nwsi->quic.qn;

	if (qn->is_server)
		return 1;

	/*
	 * Remember how to get back before we change anything, so the probe
	 * timeout can revert to a fresh socket on the original server path
	 * (and original DCID).  This is entered at most twice for one probe
	 * (once at TP parse, once at HANDSHAKE_DONE), both before any swap.
	 */
	qn->prefaddr_original_sa46 = qn->path_sa46;
	qn->prefaddr_original_rem_cid = qn->rem_cid;

	/* Save the migration parameters for later */
	qn->probing_sa46 = *pref_sa46;
	if (pref_cid) {
		qn->prefaddr_rem_cid = *pref_cid;
		if (pref_token)
			memcpy(qn->prefaddr_rem_token, pref_token, 16);
	}

	/*
	 * Defer the actual socket swap + DCID change until the server confirms
	 * handshake completion via HANDSHAKE_DONE.  The preferred_address TP
	 * arrives during the handshake; swapping before both sides have APP
	 * keys strands the migration.
	 */
	if (!qn->handshake_done) {
		qn->prefaddr_pending = 1;
		return 0;
	}

	qn->prefaddr_pending = 0;
	qn->prefaddr_active = 1;
	qn->prefaddr_committed = 0;

	/* a new local port for the new path, RFC 9000 9.5 */
	if (lws_io_path(nwsi, LWS_IOPATH_NEW_SOCKET, pref_sa46))
		return 1;
	qn->path_sa46 = *pref_sa46;

	if (pref_cid && pref_cid->len)
		qn->rem_cid = *pref_cid;

	/*
	 * The probe is in flight from here: the PATH_RESPONSE that answers
	 * it commits the path and cancels prefaddr_sul, and the tx puts its
	 * PATH_CHALLENGE first.  Both only act on a probe marked valid.
	 */
	qn->probing_sa46_valid = 1;

	lws_quic_queue_path_challenge(nwsi);

	lws_quic_sul_schedule(qn, &qn->prefaddr_sul, lws_quic_prefaddr_sul_cb,
			      LWS_QUIC_PREFADDR_DEADLINE_US);

	return 0;
}

/*
 * Find a server connection on this listener by DCID: either the CID we
 * allocated for the connection, the original client DCID (it may not have
 * switched yet), or the preferred_address CID we advertised (RFC 9000 9.6).
 */
struct lws *
lws_quic_find_child_by_dcid(struct lws *listener,
			    const struct lws_quic_cid *dcid)
{
	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&listener->mux.child_list_owner)) {
		struct lws *w = lws_container_of(d, struct lws,
						 mux.sibling_list);
		if (!w->quic.qn)
			continue;
		/*
		 * A zero-length DCID would "match" any connection whose
		 * orig_dcid / preferred-address cid is simply unset (len 0),
		 * letting an off-path sender inject into someone else's
		 * connection.  A server multiplexing on one socket never
		 * issues zero-length cids, so refuse to match on one.
		 */
		if (!dcid->len)
			return NULL;
		if ((w->quic.qn->loc_cid.len == dcid->len &&
		     !memcmp(w->quic.qn->loc_cid.id, dcid->id, dcid->len)) ||
		    (w->quic.qn->orig_dcid.len == dcid->len &&
		     !memcmp(w->quic.qn->orig_dcid.id, dcid->id, dcid->len)) ||
		    (w->quic.qn->prefaddr_rem_cid.len == dcid->len &&
		     !memcmp(w->quic.qn->prefaddr_rem_cid.id, dcid->id,
			     dcid->len)))
			return w;
	} lws_end_foreach_dll(d);

	return NULL;
}



static void
lws_quic_pacer_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_quic_netconn *qn = lws_container_of(sul, struct lws_quic_netconn, pacer_sul);
	if (qn && qn->nwsi) {
		lws_quic_sul_assert_thread(qn);
		lws_callback_on_writable(qn->nwsi);
	}
}

/*
 * Delayed-ACK timer (RFC 9000 §13.2.1).  When it fires, a deferred App-space
 * ACK is due; just wake the network wsi so rops_handle_POLLOUT_quic builds and
 * sends it (the TX path cancels this sul and resets the counters as it emits
 * the ACK frame).  We bypass CC/pacing there exactly as for an immediate ACK.
 */
static void
lws_quic_ack_delay_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_quic_netconn *qn = lws_container_of(sul, struct lws_quic_netconn,
							ack_delay_sul);
	if (qn) {
		qn->ack_delay_armed = 0;
		if (qn->nwsi) {
			lws_quic_sul_assert_thread(qn);
			lws_callback_on_writable(qn->nwsi);
		}
	}
}

/*
 * RFC 9002 5.3 PTO interval without an RTT sample yet, or with the current
 * smoothed_rtt / rttvar estimate.
 */
static lws_usec_t
lws_quic_pto_base_us(const struct lws_quic_netconn *qn)
{
	return qn->smoothed_rtt ?
		(qn->smoothed_rtt + (4 * qn->rttvar) + 25000) :
		LWS_QUIC_DEFAULT_PTO_US;
}

/*
 * RFC 9002 6.2 PTO interval with exponential backoff: pto_count consecutive
 * PTO firings double the delay.  The shift is clamped so a large pto_count
 * (which the count-based death conditions do not always bound) saturates
 * instead of producing an out-of-range shift.
 *
 * While the TLS handshake is still incomplete, the backoff is capped at 4x the
 * base interval.  Pre-handshake_done, the death of a peer we have heard
 * nothing from is owned by the wsi connect timeout
 * (PENDING_TIMEOUT_AWAITING_CONNECT_RESPONSE, default 20s), not by this
 * backoff; with unbounded doubling from the 500ms default base only ~6
 * Initial probes fit in that window, which is too few to ride out a
 * corruption streak (interop corrupt-rate scenario, 30% each direction:
 * P(all 6 probes corrupted) ~ 7e-4 per connection).  Capping the probe
 * spacing fits ~12 probes in the same window (P ~ 5e-7).  For handshakes that
 * did make some progress, the RFC 9002 A.11 backoff reset on PN space discard
 * in lws_quic_discard_keys() handles the accumulated backoff instead.
 */
static lws_usec_t
lws_quic_pto_delay_us(const struct lws_quic_netconn *qn, uint8_t count)
{
	lws_usec_t base = lws_quic_pto_base_us(qn);
	uint8_t shift = count > 6 ? 6 : count;
	lws_usec_t delay = base << shift;

	if (!qn->handshake_done && delay > base * 4)
		delay = base * 4;
	if (delay > 10000000)
		delay = 10000000;

	return delay;
}

/*
 * RFC 9002 A.8 (SetLossDetectionTimer): with nothing ack-eliciting in flight,
 * only a client still in its handshake keeps the PTO armed, so a server held
 * at its anti-amplification limit can be unblocked (6.2.2.1).  A server whose
 * own flight was acked has nothing to probe for: what it waits for, the
 * client's Finished, is the client's to send again, on its own PTO.  Probing
 * anyway, every probe acked reset the backoff, so it sent a PING every RTT or
 * so until the Finished came.
 */
static int
lws_quic_pto_armed_idle(const struct lws_quic_netconn *qn)
{
	return !qn->is_server && !qn->handshake_done;
}

/* what in a packet given up on by a PTO goes again, see below */
static int
lws_quic_frame_pto_resent(const struct lws_quic_netconn *qn,
			  const struct lws_quic_tx_frame *f)
{
	return !f->pmtud_probe && !lws_quic_frame_not_retransmitted(f) &&
	       !lws_quic_frame_probes_another_path(qn, f);
}

/*
 * RFC 9002 6.2.4: an app level PTO's probe carries data that is unacked,
 * not only a PING.  The PTO firing says nothing was lost, and it is loss
 * detection, from the acks that come, that sends lost data again.  But if
 * no ack comes, eg, each one the peer sends is lost, nothing is ever found
 * lost, and data that was, eg, a request, is never sent again however many
 * probes go: the peer, waiting for it, has nothing to send, and the
 * connection dies at the PTO count.
 *
 * So the packets in flight with the data that was first sent longest ago,
 * about what one probe of the base size carries, go back to be sent at the
 * head of what is pending, which the probe, right behind its PING, carries.
 * It is by when the data was first sent, not where it is in flight: what a
 * probe sends again is in flight again at the tail, and if that probe is lost
 * too, the next one must send it again, not what was sent after it, which the
 * peer can't deliver without it.  Their frames that are not sent again, eg, a
 * PING, are freed, as loss would, and their bytes leave flight uncharged (the
 * caller's on_discard).  The rest of what is in flight stays there, so the
 * acks of it, coming late, still reset pto_count and give an RTT sample.
 */
static size_t
lws_quic_pto_requeue_app(struct lws_quic_netconn *qn)
{
	lws_dll2_owner_t *fl = &qn->in_flight[LWS_QUIC_LEVEL_APP];
	struct lws_quic_tx_frame *f, *oldest;
	size_t bytes = 0, taken = 0;
	lws_dll2_owner_t resend;
	struct lws_dll2 *d, *n;
	int packets = 0;
	uint64_t pn;

	lws_dll2_owner_clear(&resend);

	while (taken < LWS_QUIC_PMTU_BASE - LWS_QUIC_PMTU_OVERHEAD &&
	       packets++ < LWS_QUIC_PTO_RESEND_PACKETS) {
		oldest = NULL;
		lws_start_foreach_dll(struct lws_dll2 *, p, lws_dll2_get_head(fl)) {
			f = lws_container_of(p, struct lws_quic_tx_frame, list);
			if (lws_quic_frame_pto_resent(qn, f) &&
			    (!oldest || f->first_sent_us < oldest->first_sent_us))
				oldest = f;
		} lws_end_foreach_dll(p);

		if (!oldest)
			break;

		/* a packet's frames are together in the list, in order */
		pn = oldest->sent_in_pn;
		d = &oldest->list;
		while (lws_dll2_get_prev(d) &&
		       lws_container_of(lws_dll2_get_prev(d),
				struct lws_quic_tx_frame, list)->sent_in_pn == pn)
			d = lws_dll2_get_prev(d);

		lwsl_wsi_info(qn->nwsi, "QUIC PTO: sending pn %llu's frames again",
			      (unsigned long long)pn);

		for (; d; d = n) {
			n = lws_dll2_get_next(d);
			f = lws_container_of(d, struct lws_quic_tx_frame, list);
			if (f->sent_in_pn != pn)
				break;
			lws_dll2_remove(d);
			bytes += f->wire_len;
			f->wire_len = 0;
			if (!lws_quic_frame_pto_resent(qn, f)) {
				lws_free(f);
				continue;
			}
			taken += f->len;
			lws_quic_dbg_1rtt_account(qn, f, "pto-requeue");
			lws_dll2_add_tail(d, &resend);
		}
	}

	/* ahead of what is pending, in the order they were first sent */
	while ((d = lws_dll2_get_tail(&resend))) {
		lws_dll2_remove(d);
		lws_dll2_add_head(d, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
	}

	return bytes;
}

static void
lws_quic_pto_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_quic_netconn *qn = lws_container_of(sul, struct lws_quic_netconn, pto_sul);
	if (qn && qn->nwsi) {
		lws_quic_sul_assert_thread(qn);
		qn->pto_count++;
		/*
		 * Pre-handshake_done, leave the death of a silent peer to the
		 * handshake's own deadline, the wsi connect timeout on a client
		 * and PENDING_TIMEOUT_AWAITING_CLIENT_HS_SEND on a server, so
		 * the capped probe spacing in lws_quic_pto_delay_us() can keep
		 * probing for the whole of it.  Otherwise the counter kills it
		 * at ~4x base x 8 first: on a short path, a server waiting for
		 * the client's Finished gave up after a couple of seconds of
		 * corrupted packets, while the client, its handshake done,
		 * carried on sending to a connection that no longer existed.
		 */
		if (qn->pto_count >= 8 && qn->handshake_done) {
			lwsl_wsi_notice(qn->nwsi, "QUIC connection dead: max PTO count (%d) reached\n", qn->pto_count);
			lws_close_free_wsi(qn->nwsi, LWS_CLOSE_STATUS_NOSTATUS, "quic pto timeout");
			return;
		}

		qn->pto_probe_needed = 2;
#if (_LWS_ENABLED_LOGS & LLL_INFO)
		LWS_RATELIMIT_DEFINE_STATIC(rl);
		lwsl_ratelimit_info(&rl, 1000000, "QUIC PTO Timer Fired! Sending a probe\n");
#endif
		int sent_ping = 0;
		size_t total_bytes_lost = 0;
		/*
		 * Aggressively retransmit Initial/Handshake frames (RFC 9002
		 * 6.2.4), and 0-RTT ones, which go in 1-RTT once the handshake
		 * completed
		 */
		for (int i = 0; i < LWS_QUIC_LEVEL_APP; i++) {
			if (qn->in_flight[i].count) {
				int rl = lws_quic_resend_level(qn, i);

				lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->in_flight[i].head) {
					struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);
					lws_dll2_remove(d);
					total_bytes_lost += f->wire_len;
					f->wire_len = 0; /* CRITICAL: Reset wire_len */
					if (rl == LWS_QUIC_LEVEL_APP)
						lws_quic_dbg_1rtt_account(qn, f, "pto-requeue-early");
					lws_dll2_add_tail(&f->list, &qn->pending_tx[rl]);
				} lws_end_foreach_dll_safe(d, d1);
				lwsl_wsi_info(qn->nwsi, "QUIC PTO: Retransmitting level %d at level %d", i, rl);
				sent_ping = 1;
			}
		}

		/*
		 * For App Data, a PING to elicit an ACK, behind what is unacked
		 * from the oldest packets in flight
		 */
		if (!sent_ping && qn->in_flight[LWS_QUIC_LEVEL_APP].count) {
			struct lws_quic_tx_frame *ping;

			total_bytes_lost += lws_quic_pto_requeue_app(qn);

			ping = lws_zalloc(sizeof(*ping), "pto ping");
			if (ping) {
				ping->type = LWS_QUIC_FT_PING;
				/* Add at HEAD so the PING is serialized first, before data frames
				 * fill the MTU and cause pto_probe_needed to decrement prematurely */
				lws_quic_dbg_1rtt_account(qn, ping, "pto-ping");
				lws_dll2_add_head(&ping->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
				lwsl_wsi_info(qn->nwsi, "QUIC PTO: Enqueued PING for level 3");
                                qn->pto_probe_needed = 1;
			}
			sent_ping = 1;
		}

		if (total_bytes_lost && qn->cc_ops && qn->cc_ops->on_discard)
			qn->cc_ops->on_discard(qn->nwsi, total_bytes_lost);

		if (!sent_ping && lws_quic_pto_armed_idle(qn)) {
			int target_level = LWS_QUIC_LEVEL_INITIAL;
			if (qn->keys[LWS_QUIC_LEVEL_HANDSHAKE]) target_level = LWS_QUIC_LEVEL_HANDSHAKE;
			struct lws_quic_tx_frame *ping = lws_zalloc(sizeof(*ping), "pto ping");
			if (ping) {
				ping->type = LWS_QUIC_FT_PING;
				lws_dll2_add_tail(&ping->list, &qn->pending_tx[target_level]);
				lwsl_wsi_info(qn->nwsi, "QUIC PTO: Enqueued PING for level %d (no in-flight, handshake incomplete)", target_level);
				qn->pto_probe_needed = 1;
			}
		}

		lws_callback_on_writable(qn->nwsi);

		/* the timer runs while anything is in flight, or see above */
		int any_in_flight = 0;
		for (int i = 0; i < LWS_QUIC_LEVEL_COUNT; i++) {
			if (qn->in_flight[i].count) {
				any_in_flight = 1;
				break;
			}
		}

		if (any_in_flight || lws_quic_pto_armed_idle(qn)) {
			lws_usec_t pto_delay = lws_quic_pto_delay_us(qn, qn->pto_count);
			lws_quic_sul_schedule(qn, &qn->pto_sul, lws_quic_pto_cb,
					      pto_delay);
		}
	}
}

/* RFC 9000 Section 17.1 */
static uint64_t
lws_quic_decode_packet_number(uint64_t largest_pn, uint64_t truncated_pn, int pn_nbits)
{
	uint64_t expected_pn = largest_pn + 1;
	uint64_t pn_win = 1ULL << pn_nbits;
	uint64_t pn_hwin = pn_win / 2;
	uint64_t pn_mask = pn_win - 1;
	uint64_t candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

	if (candidate_pn + pn_hwin <= expected_pn && candidate_pn < (1ULL << 62) - pn_win)
		return candidate_pn + pn_win;
	if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win)
		return candidate_pn - pn_win;

	return candidate_pn;
}

/*
 * RFC 9002 6.1.2: how long before a packet sent ahead of one acked is taken
 * for lost.  The larger of the smoothed and latest RTT, so a path whose RTT
 * just grew isn't judged by the estimate from before, which lags it.
 */
static lws_usec_t
lws_quic_loss_time_us(const struct lws_quic_netconn *qn)
{
	lws_usec_t rtt = qn->latest_rtt > qn->smoothed_rtt ?
				qn->latest_rtt : qn->smoothed_rtt;

	if (!rtt)
		return 50000;

	rtt = rtt * 9 / 8;

	return rtt < LWS_QUIC_GRANULARITY_US ? LWS_QUIC_GRANULARITY_US : rtt;
}

void
lws_quic_detect_loss(struct lws *nwsi, int level, uint64_t largest_acked)
{
        struct lws_quic_netconn *qn = nwsi->quic.qn;
        if (!qn) return;

        size_t total_bytes_lost = 0, bytes_off_path = 0;
        lws_usec_t now = lws_wsi_now(nwsi);
        lws_usec_t loss_time = lws_quic_loss_time_us(qn);
        lws_usec_t oldest_lost = 0, newest_lost = 0;
	uint64_t last_lost_pn = LWS_QUIC_PMTUD_PROBE_NONE;

	int check_levels[] = { level, level == LWS_QUIC_LEVEL_APP ? LWS_QUIC_LEVEL_EARLY : -1 };
	for (int i = 0; i < 2; i++) {
		int curlvl = check_levels[i];
		if (curlvl == -1) continue;

		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->in_flight[curlvl].head) {
			struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);

			lws_quic_fi_stat(qn, ack_visits, 1);
			lws_quic_fi_stat(qn, cur_visits, 1);

			/*
			 * The list is in PN order, and nothing from the
			 * Largest Acknowledged up is lost
			 */
			if (f->sent_in_pn >= largest_acked)
				break;

			if (f->sent_in_pn + 3 <= largest_acked ||
			    now > f->sent_time_us + loss_time) {

				if (lws_quic_pmtud_probe_lost(qn, f)) {
					/* not congestion, see RFC 9000 14.4 */
					bytes_off_path += f->wire_len;
					lws_dll2_remove(&f->list);
					lws_free(f);
					continue;
				}

				if (lws_quic_frame_probes_another_path(qn, f)) {
					/* the probe sends it again */
					bytes_off_path += f->wire_len;
					lws_dll2_remove(&f->list);
					lws_free(f);
					continue;
				}

				/* Mark as lost */
				total_bytes_lost += f->wire_len;
				lwsl_wsi_info(nwsi, "QUIC LOSS: Packet %llu lost, frame %d", (unsigned long long)f->sent_in_pn, f->type);
				lws_quic_pmtud_lost_packet(qn, f, &last_lost_pn);
				
				if (!oldest_lost || f->sent_time_us < oldest_lost)
					oldest_lost = f->sent_time_us;
				if (!newest_lost || f->sent_time_us > newest_lost)
					newest_lost = f->sent_time_us;

				lws_dll2_remove(&f->list);

				int pending_lvl = curlvl;
				if (curlvl == LWS_QUIC_LEVEL_EARLY)
					pending_lvl = LWS_QUIC_LEVEL_APP;

				if (lws_quic_frame_not_retransmitted(f)) {
					/*
					 * The lost bytes still count for cc,
					 * but the frame itself is freed
					 */
					lws_free(f);
				} else {
					f->wire_len = 0;

					if (pending_lvl == LWS_QUIC_LEVEL_APP)
						lws_quic_dbg_1rtt_account(qn, f,
							  curlvl == LWS_QUIC_LEVEL_EARLY ?
								"loss-requeue-early"
							      : "loss-requeue");
					lws_dll2_add_tail(&f->list, &qn->pending_tx[pending_lvl]);
				}
			}
		} lws_end_foreach_dll_safe(d, d1);
	}

        if (total_bytes_lost && qn->cc_ops && qn->cc_ops->on_loss) {
                qn->cc_ops->on_loss(nwsi, total_bytes_lost);

                if (newest_lost > oldest_lost) {
                        lws_usec_t pto = qn->smoothed_rtt + (qn->rttvar * 4 > 1000 ? qn->rttvar * 4 : 1000) + 25000;
                        lws_usec_t pc_period = pto * 3;
                        if ((newest_lost - oldest_lost) >= pc_period) {
                                if (qn->cc_ops->on_persistent_congestion)
                                        qn->cc_ops->on_persistent_congestion(nwsi);
                        }
                }
        }

        /* not congestion on our path, but no longer in flight either */
        if (bytes_off_path && qn->cc_ops && qn->cc_ops->on_discard)
                qn->cc_ops->on_discard(nwsi, bytes_off_path);

	lws_quic_fi_stat_ack_done(qn);

        if (total_bytes_lost)
                lws_callback_on_writable(nwsi);
}

void
lws_quic_ack_begin(struct lws *nwsi, struct lws_quic_ack_walk *aw, int level,
		   uint64_t ack_delay)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;

	memset(aw, 0, sizeof(*aw));
	aw->level	= level;
	aw->now		= lws_wsi_now(nwsi);
	/*
	 * The parser clamps ack_delay to the peer's max_ack_delay; this is
	 * only a last line of defense so the lws_usec_t arithmetic below can
	 * never see a negative value.
	 */
	aw->ack_delay	= ack_delay > 0x7fffffff ? 0x7fffffff : ack_delay;

	/* 0-RTT frames are acked in the app PN space too */
	aw->cur[0] = lws_dll2_get_tail(&qn->in_flight[level]);
	if (level == LWS_QUIC_LEVEL_APP)
		aw->cur[1] = lws_dll2_get_tail(&qn->in_flight[LWS_QUIC_LEVEL_EARLY]);

	lws_quic_fi_stat_ack_start(qn);
}

/*
 * A frame in flight was acked: it got there, free it
 */
static void
lws_quic_frame_acked(struct lws *nwsi, struct lws_quic_ack_walk *aw,
		     struct lws_quic_tx_frame *f, int largest)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	lws_usec_t rtt = aw->now > f->sent_time_us ?
				aw->now - f->sent_time_us : 0;
	uint64_t sid = f->stream_id;
	struct lws *child;

	lws_quic_fi_stat(qn, ack_acked, 1);
	aw->bytes_acked += f->wire_len;

	/* the walk goes down: the first frame acked is the newest */
	if (!aw->rtt)
		aw->rtt = rtt;
	/*
	 * RFC 9002 5.1: an RTT sample is only taken when the Largest
	 * Acknowledged is newly acked
	 */
	if (largest)
		aw->rtt_largest = rtt;
	/* a packet bigger than the base got through */
	if (f->packet_size + LWS_QUIC_PMTU_OVERHEAD > LWS_QUIC_PMTU_BASE)
		lws_quic_pmtud_big_acked(qn, f);

	lws_dll2_remove(&f->list);
	lws_free(f);

	child = lws_quic_stream_find(nwsi, sid);
	if (child && (lwsi_flushing_to_close(child) ||
		      lwsi_state_live(child) == LRS_TXN_COMPLETING))
		lws_callback_on_writable(child);
}

void
lws_quic_ack_range(struct lws *nwsi, struct lws_quic_ack_walk *aw,
		   uint64_t pn_lo, uint64_t pn_hi)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	int level = aw->level, first = !aw->ranges, i;

	aw->ranges = 1;
	lws_quic_fi_stat(qn, ack_ranges, 1);
	lws_quic_fi_stat(qn, cur_ranges, 1);

	/*
	 * PMTUD: our probe, in the application PN space, was acknowledged, so
	 * the path carries its size: probe the next one up, if any.  So it does
	 * if the ack came after we gave the probe up for lost.
	 */
	if (level == LWS_QUIC_LEVEL_APP &&
	    qn->pmtud_probe_pn != LWS_QUIC_PMTUD_PROBE_NONE &&
	    qn->pmtud_probe_pn >= pn_lo && qn->pmtud_probe_pn <= pn_hi) {
		lwsl_wsi_info(nwsi, "QUIC PMTUD: probe %llu of %u acked",
			      (unsigned long long)qn->pmtud_probe_pn,
			      qn->probed_mtu);
		lws_quic_pmtud_carries(qn, qn->probed_mtu);
	}

	if (level == LWS_QUIC_LEVEL_APP &&
	    qn->pmtud_late_probe_pn != LWS_QUIC_PMTUD_PROBE_NONE &&
	    qn->pmtud_late_probe_pn >= pn_lo &&
	    qn->pmtud_late_probe_pn <= pn_hi) {
		lwsl_wsi_info(nwsi, "QUIC PMTUD: probe %llu of %u acked after "
			      "it was given up for lost",
			      (unsigned long long)qn->pmtud_late_probe_pn,
			      qn->pmtud_late_probe_mtu);
		qn->pmtud_late_probe_pn = LWS_QUIC_PMTUD_PROBE_NONE;
		lws_quic_pmtud_carries(qn, qn->pmtud_late_probe_mtu);
	}

	/*
	 * A confirming probe given up for lost was only late: no black hole.
	 * Unused entries are LWS_QUIC_PMTUD_PROBE_NONE, never in a range.
	 */
	for (i = 0; level == LWS_QUIC_LEVEL_APP && qn->pmtud_bh_from_mtu &&
		    i < (int)LWS_ARRAY_SIZE(qn->pmtud_bh_from_late_pn); i++)
		if (qn->pmtud_bh_from_late_pn[i] >= pn_lo &&
		    qn->pmtud_bh_from_late_pn[i] <= pn_hi) {
			lwsl_wsi_info(nwsi, "QUIC PMTUD: probe %llu of %u acked "
				      "after it was given up for lost",
				      (unsigned long long)
					qn->pmtud_bh_from_late_pn[i],
				      qn->pmtud_bh_from_mtu);
			lws_quic_pmtud_bh_undo(qn);
			break;
		}

	/* the next probe, or the first since the search was reset */
	if (level == LWS_QUIC_LEVEL_APP)
		lws_quic_pmtud_kick(qn);

	/*
	 * The lists are in ascending PN order and the ranges come descending,
	 * so each cursor only ever moves down: frames above this range are
	 * passed over, frames in it are acked, and the first one below it is
	 * where the next range starts looking
	 */
	for (i = 0; i < 2; i++) {
		while (aw->cur[i]) {
			struct lws_quic_tx_frame *f = lws_container_of(
					aw->cur[i], struct lws_quic_tx_frame, list);

			lws_quic_fi_stat(qn, ack_visits, 1);
			lws_quic_fi_stat(qn, cur_visits, 1);

			if (f->sent_in_pn < pn_lo)
				break;

			aw->cur[i] = lws_dll2_get_prev(aw->cur[i]);

			if (f->sent_in_pn <= pn_hi)
				lws_quic_frame_acked(nwsi, aw, f,
						first && f->sent_in_pn == pn_hi);
		}
	}

	/*
	 * PMTUD black hole check: the base size probe got through, and no big
	 * packet from before going back to the base did.  The path is up, but
	 * that doesn't say big packets are lost, eg, after an outage of
	 * everything: confirm it with a probe of the size from before, see
	 * LWS_QUIC_PMTUD_BH_LOSSES.  Its ack is a big packet's, which goes back
	 * to that size, and losing it confirms the black hole.
	 */
	if (level == LWS_QUIC_LEVEL_APP &&
	    qn->pmtud_bh_probe_pn != LWS_QUIC_PMTUD_PROBE_NONE &&
	    qn->pmtud_bh_probe_pn >= pn_lo && qn->pmtud_bh_probe_pn <= pn_hi) {
		qn->pmtud_bh_probe_pn = LWS_QUIC_PMTUD_PROBE_NONE;

		if (qn->pmtud_bh_from_mtu &&
		    !qn->pmtud_bh_from_probe_queued &&
		    qn->pmtud_bh_from_probe_pn == LWS_QUIC_PMTUD_PROBE_NONE) {
			lwsl_wsi_info(nwsi, "QUIC PMTUD: the base gets through, "
				      "probing %u again", qn->pmtud_bh_from_mtu);
			if (!lws_quic_pmtud_queue_probe(qn,
						LWS_QUIC_PMTUD_PROBE_FROM))
				qn->pmtud_bh_from_probe_queued = 1;
		}
	}
}

void
lws_quic_ack_end(struct lws *nwsi, struct lws_quic_ack_walk *aw)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	lws_usec_t rtt = aw->rtt_largest ? aw->rtt_largest : aw->rtt;

	if (aw->bytes_acked) {
		lws_callback_on_writable(nwsi);
		qn->pto_count = 0;

		/* Update RTT Estimator (RFC 9002 5.3) */
		if (aw->rtt_largest > 0) {
			lws_usec_t adjusted_rtt = aw->rtt_largest;

			rtt = aw->rtt_largest;
			if (qn->min_rtt && rtt > qn->min_rtt + (lws_usec_t)aw->ack_delay) {
				adjusted_rtt = rtt - (lws_usec_t)aw->ack_delay;
			}
			qn->latest_rtt = rtt;
			if (!qn->smoothed_rtt) {
				qn->smoothed_rtt = rtt;
				qn->rttvar = rtt / 2;
				qn->min_rtt = rtt;
			} else {
				if (rtt < qn->min_rtt) qn->min_rtt = rtt;
				lws_usec_t rtt_diff = qn->smoothed_rtt > adjusted_rtt ? (qn->smoothed_rtt - adjusted_rtt) : (adjusted_rtt - qn->smoothed_rtt);
				qn->rttvar = (3 * qn->rttvar + rtt_diff) / 4;
				qn->smoothed_rtt = (7 * qn->smoothed_rtt + adjusted_rtt) / 8;
			}
		}

		if (qn->cc_ops && qn->cc_ops->on_ack)
			qn->cc_ops->on_ack(nwsi, aw->bytes_acked, rtt);

		/* If we have pending TX and CC might have unblocked, trigger POLLOUT */
		int pending = 0;
		for (int i = 0; i < LWS_QUIC_LEVEL_COUNT; i++) {
			if (qn->pending_tx[i].count) {
				pending = 1;
				break;
			}
		}
		if (pending)
			lws_callback_on_writable(nwsi);

		{
			struct lws_quic_cc_newreno *_cc = qn->cc_ops ? (struct lws_quic_cc_newreno *)qn->cc_state : NULL;
			(void)_cc;
			lwsl_debug("QUIC TX: ACK processing: bytes_acked=%zu, cc_bif=%zu cc_cwnd=%zu cc_pacing=%zu, in_flight_app=%d, pending_tx=%d, blocked=%d\n",
				    aw->bytes_acked,
				    _cc ? _cc->bytes_in_flight : 0,
				    _cc ? _cc->cwnd : 0,
				    _cc ? _cc->pacing_credit : 0,
				    qn->in_flight[LWS_QUIC_LEVEL_APP].count,
				    qn->pending_tx[LWS_QUIC_LEVEL_APP].count,
				    (int)(qn->cc_ops && qn->cc_ops->can_send ? !qn->cc_ops->can_send(nwsi, 1000) : 0));
		}


		/*
		 * ACKs opened the congestion window. Child streams may have
		 * been stalled by the application-layer pacing throttle in
		 * rops_tx_credit_quic() (64KB pending_tx cap). Wake them up
		 * so they can generate more application data.
		 */
		{
			lws_start_foreach_dll(struct lws_dll2 *, d,
					      lws_dll2_get_head(&nwsi->mux.child_list_owner)) {
				struct lws *w = lws_container_of(d, struct lws,
								 mux.sibling_list);
				if (w->mux.requested_POLLOUT)
					lws_callback_on_writable(w);
			}
			lws_end_foreach_dll(d);
		}
	}

	/* If there are no more in-flight packets across all levels, we can cancel the PTO timer */
	{
		int any_in_flight2 = 0;
		for (int i2 = 0; i2 < LWS_QUIC_LEVEL_COUNT; i2++) {
			if (qn->in_flight[i2].count) {
				any_in_flight2 = 1;
				break;
			}
		}
		if (!any_in_flight2) {
			if (lws_quic_pto_armed_idle(qn)) {
				/* RFC 9002 6.2.2.1: the server may be blocked */
				lwsl_info("lws_quic_ack_end: Keeping PTO timer active (no in-flight, handshake incomplete)\n");
			} else {
				lws_sul_cancel(&qn->pto_sul);
			}
		} else if (aw->bytes_acked) {
			/*
			 * RFC 9002 Section 6.2.1: When a packet is acknowledged, the
			 * PTO timer must be updated.  Reset it using pto_count=0 (since
			 * we just reset pto_count above) so the doubled timer from the
			 * PTO callback is replaced by a fresh base-rate timer.
			 */
			lws_usec_t pto_base2 = lws_quic_pto_base_us(qn);
			lws_quic_sul_schedule(qn, &qn->pto_sul,
					      lws_quic_pto_cb, pto_base2);
		}
	}
}

void
lws_quic_discard_keys(struct lws *nwsi, int level)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	size_t bytes_discarded = 0;
	int discarded = 0;

	if (!qn) return;

	if (qn->keys[level]) {
		lws_quic_keys_destroy(qn->keys[level]);
		qn->keys[level] = NULL;
		discarded = 1;
	}
	if (level == LWS_QUIC_LEVEL_APP)
		/* derived from them */
		lws_quic_rx_next_discard(qn);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->pending_tx[level].head) {
		struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);
		lws_dll2_remove(&f->list);
		lws_free(f);
	} lws_end_foreach_dll_safe(d, d1);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->in_flight[level].head) {
		struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);
		bytes_discarded += f->wire_len;
		lws_dll2_remove(&f->list);
		lws_free(f);
	} lws_end_foreach_dll_safe(d, d1);

	/*
	 * RFC 9002 A.11: the space's packets still in flight are no longer
	 * in flight for congestion control either.  They are neither acked
	 * nor lost, so cwnd stays as it is.  Left counted, they are a
	 * permanent debt against the window: once loss shrinks cwnd near
	 * its minimum, nothing in flight is left to arm the PTO, and what
	 * the window has no room for is never sent.
	 */
	if (bytes_discarded && qn->cc_ops && qn->cc_ops->on_discard)
		qn->cc_ops->on_discard(nwsi, bytes_discarded);

	lws_quic_rx_held_destroy(&qn->rx_crypto_held[level]);

	/*
	 * RFC 9002 A.11 (OnPacketNumberSpaceDiscarded): discarding a packet
	 * number space resets the PTO backoff.  In both directions, getting
	 * far enough to drop a space proves the peer processed at least one
	 * of our packets (eg, a client that receives a Handshake packet
	 * knows the server got its Initial), so any exponential backoff
	 * accumulated on a dead-looking path no longer applies.
	 *
	 * Without this, a handshake that survived a long corruption streak
	 * (eg, the interop corrupt-rate scenario) inherits a fully backed-off
	 * PTO timer after the Initial phase, and a single further loss can
	 * then never be retransmitted inside the client handshake timeout.
	 */
	if (discarded) {
		int any_in_flight = 0, lvl;

		qn->pto_count = 0;

		for (lvl = 0; lvl < LWS_QUIC_LEVEL_COUNT; lvl++)
			if (qn->in_flight[lvl].count) {
				any_in_flight = 1;
				break;
			}

		if (any_in_flight || lws_quic_pto_armed_idle(qn)) {
			lws_usec_t pto_base = lws_quic_pto_base_us(qn);

			/* reschedule the PTO at the fresh, unbacked-off delay */
			lws_quic_sul_schedule(qn, &qn->pto_sul,
					      lws_quic_pto_cb, pto_base);
		}
	}
}

struct lws *
lws_get_quic_network_wsi(struct lws *wsi)
{
	if (!wsi) return NULL;
	while (wsi) {
		if (wsi->quic.qn)
			return wsi;
		wsi = wsi->mux.parent_wsi;
	}
	return NULL;
}

/*
 * A stream timed out sending its ws close, or waiting for the peer's answer to
 * it, or flushing what it sent before closing with nothing left to flush, or
 * its connection timed out with streams like that, or with frames of theirs
 * still waiting or in flight: say what the stream and its connection were
 * doing, at notice, ie, which of the things that give a stream its turn to
 * write, or get what it wrote to the peer, didn't happen.  Logging before
 * such a stall can change its timing enough to hide it, so this is only
 * printed once it happened.
 */
static int
lws_quic_dump_frames(struct lws *wsi, const char *what, lws_dll2_owner_t *o,
		     uint64_t sid, lws_usec_t now, int print)
{
	int n = 0;

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(o)) {
		struct lws_quic_tx_frame *f = lws_container_of(d,
					struct lws_quic_tx_frame, list);

		if ((f->type & 0xf8) != LWS_QUIC_FT_STREAM ||
		    f->stream_id != sid)
			continue;
		if (print && n < 4)
			lwsl_wsi_notice(wsi, "  %s: off %llu len %u fin %d, "
					"pn %llu, sent %lldms ago", what,
					(unsigned long long)f->offset,
					(unsigned int)f->len, f->type & 1,
					(unsigned long long)f->sent_in_pn,
					f->sent_time_us ? (long long)
					((now - f->sent_time_us) /
						LWS_US_PER_MS) : -1ll);
		n++;
	} lws_end_foreach_dll(d);

	return n;
}

/* stream w's frames still waiting or in flight */
static int
lws_quic_stream_frames(struct lws_quic_netconn *qn, struct lws *w,
		       lws_usec_t now)
{
	uint64_t sid = w->quic.qs->stream_id;

	return lws_quic_dump_frames(w, NULL, &qn->pending_tx[LWS_QUIC_LEVEL_APP],
				    sid, now, 0) ||
	       lws_quic_dump_frames(w, NULL, &qn->in_flight[LWS_QUIC_LEVEL_APP],
				    sid, now, 0);
}

/*
 * Is stream w closing once what it sent has gone, with nothing left to go?
 * Then it can only be waiting on its own next turn, which never came.  One
 * still sending, or waiting for the peer to acknowledge it, is not stuck
 * here: a peer that went away takes as long as its flush timeout.
 */
static int
lws_quic_stream_flush_stuck(struct lws_quic_netconn *qn, struct lws *w,
			    lws_usec_t now)
{
	return lwsi_flushing_to_close(w) && !w->buflist_out &&
	       !lws_quic_stream_frames(qn, w, now);
}

/* does stream w still wait on its peer for anything, see above */
static int
lws_quic_stream_outstanding(struct lws_quic_netconn *qn, struct lws *w,
			    lws_usec_t now)
{
	return lwsi_close(w) == LCS_WAITING_TO_SEND_CLOSE ||
	       lwsi_close(w) == LCS_AWAITING_CLOSE_ACK ||
	       lws_quic_stream_flush_stuck(qn, w, now) ||
	       lws_quic_stream_frames(qn, w, now);
}

#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
static const char * const close_phase_names[] = {
	[LCS_NONE]			= "none",
	[LCS_CLOSE_WHEN_FLUSHED]	= "close when flushed",
	[LCS_CLOSING]			= "closing",
	[LCS_WAITING_TO_SEND_CLOSE]	= "waiting to send close",
	[LCS_RETURNED_CLOSE]		= "returned close",
	[LCS_AWAITING_CLOSE_ACK]	= "awaiting close ack",
	[LCS_FLUSHING_BEFORE_CLOSE]	= "flushing before close",
	[LCS_SHUTDOWN]			= "shutdown",
	[LCS_DEAD_SOCKET]		= "dead socket",
	[LCS_USER_TOLD]			= "user told",
};
#endif

static void
lws_quic_dump_stream(struct lws_quic_netconn *qn, struct lws *w,
		     lws_usec_t now)
{
	struct lws_quic_stream *qs = w->quic.qs;
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
	unsigned int cp = (unsigned int)lwsi_close(w);
#endif

	/*
	 * Its role and state say whose turn to write it gets (a ws stream's
	 * is not an h3 one's), lws' own held tx is what a close flushes
	 */
	lwsl_wsi_notice(w, "  stream %llu: role %s, state 0x%x, close phase "
			"%s, wants write %d, tx_offset %llu, tx credit %d, "
			"fin sent %d, fin rx %d, lws holds %u tx",
			(unsigned long long)qs->stream_id,
			w->role_ops ? w->role_ops->name : "none",
			(unsigned int)lwsi_state(w),
			cp < LWS_ARRAY_SIZE(close_phase_names) &&
				close_phase_names[cp] ?
					close_phase_names[cp] : "?",
			w->mux.requested_POLLOUT,
			(unsigned long long)qs->tx_offset, (int)w->txc.tx_cr,
			qs->sent_fin, qs->fin_received,
			(unsigned int)lws_buflist_total_len(&w->buflist_out));
	lws_quic_dump_frames(w, "waiting", &qn->pending_tx[LWS_QUIC_LEVEL_APP],
			     qs->stream_id, now, 1);
	lws_quic_dump_frames(w, "in flight", &qn->in_flight[LWS_QUIC_LEVEL_APP],
			     qs->stream_id, now, 1);
}

void
lws_quic_dump_stalled(struct lws *wsi)
{
	struct lws *nwsi = lws_get_quic_network_wsi(wsi);
	struct lws_quic_netconn *qn;
	lws_usec_t now;
	int l, any = 0;

	if (!nwsi || !nwsi->quic.qn)
		return;

	qn = nwsi->quic.qn;
	now = lws_wsi_now(nwsi);

	if (wsi->quic.qs)
		any = wsi->pending_timeout !=
				PENDING_FLUSH_STORED_SEND_BEFORE_CLOSE ||
		      lws_quic_stream_flush_stuck(qn, wsi, now);
	else
		lws_start_foreach_dll(struct lws_dll2 *, d,
				lws_dll2_get_head(&nwsi->mux.child_list_owner)) {
			struct lws *w = lws_container_of(d, struct lws,
							 mux.sibling_list);

			if (w->quic.qs && lws_quic_stream_outstanding(qn, w, now))
				any = 1;
		} lws_end_foreach_dll(d);

	if (!any)
		return;

	lwsl_wsi_notice(wsi, "QUIC: timed out (%d) with a stream stuck",
			wsi->pending_timeout);
	lwsl_wsi_notice(nwsi, "  conn: handshake done %d, closing %d, tx "
			"credit %d, pto_count %u, pto armed %d, wants write %d "
			"(its listener %d), last pass held %d full %d failed %d, "
			"mtu %u, pmtud state %u, probe queued %d/%d/%d",
			qn->handshake_done, qn->is_closing, (int)nwsi->txc.tx_cr,
			qn->pto_count, !lws_dll2_is_detached(&qn->pto_sul.list),
			nwsi->mux.requested_POLLOUT, nwsi->mux.parent_wsi ?
				nwsi->mux.parent_wsi->mux.requested_POLLOUT : -1,
			qn->tx_held, qn->tx_full, qn->tx_failed,
			qn->current_mtu, qn->pmtud_state,
			qn->pmtud_probe_queued, qn->pmtud_bh_probe_queued,
			qn->pmtud_bh_from_probe_queued);
	for (l = 0; l < LWS_QUIC_LEVEL_COUNT; l++)
		if (qn->pending_tx[l].count || qn->in_flight[l].count ||
		    qn->needs_ack[l])
			lwsl_wsi_notice(nwsi, "  level %d: %u waiting, %u in "
					"flight, ack owed %d", l,
					(unsigned int)qn->pending_tx[l].count,
					(unsigned int)qn->in_flight[l].count,
					qn->needs_ack[l]);
	if (qn->cc_ops && qn->cc_ops->can_send)
		lwsl_wsi_notice(nwsi, "  cc can send a packet: %d",
				qn->cc_ops->can_send(nwsi, qn->current_mtu));

	if (wsi->quic.qs) {
		lws_quic_dump_stream(qn, wsi, now);
		return;
	}

	lws_start_foreach_dll(struct lws_dll2 *, d,
			lws_dll2_get_head(&nwsi->mux.child_list_owner)) {
		struct lws *w = lws_container_of(d, struct lws,
						 mux.sibling_list);

		if (w->quic.qs && lws_quic_stream_outstanding(qn, w, now))
			lws_quic_dump_stream(qn, w, now);
	} lws_end_foreach_dll(d);
}

#if defined(LWS_WITH_SERVER)
/*
 * A listener answering without a connection (version negotiation, retry)
 * queues the datagram for its tx, bounded: it is not a connection's, and a
 * flood of unanswerable Initials must not grow it.
 */
static void
lws_quic_queue_reply(struct lws *lwsi, const uint8_t *buf, size_t len,
		     const lws_sockaddr46 *dest)
{
	struct lws_quic_reply *r;

	if (lwsi->quic.tx_replies.count >= LWS_QUIC_MAX_QUEUED_REPLIES) {
		lwsl_wsi_info(lwsi, "reply queue full, dropping");
		return;
	}

	r = lws_malloc(sizeof(*r) + len, "quic reply");
	if (!r)
		return;

	memset(&r->list, 0, sizeof(r->list));
	r->dest = *dest;
	r->len = len;
	memcpy(&r[1], buf, len);
	lws_dll2_add_tail(&r->list, &lwsi->quic.tx_replies);

	lws_callback_on_writable(lwsi);
}

/*
 * Do two addresses share an IPv4 /24 or IPv6 /64 (an IPv4-mapped one counts
 * as the IPv4 address it maps)?
 */
static int
lws_quic_same_prefix(const lws_sockaddr46 *a, const lws_sockaddr46 *b)
{
	if (a->sa4.sin_family != b->sa4.sin_family)
		return 0;

	if (a->sa4.sin_family == AF_INET)
		return !memcmp(&a->sa4.sin_addr, &b->sa4.sin_addr, 3);

#if defined(LWS_WITH_IPV6)
	if (a->sa4.sin_family == AF_INET6) {
		int mapped = lws_sa46_is_ipv4_mapped(a);

		if (mapped != lws_sa46_is_ipv4_mapped(b))
			return 0;

		/* ::ffff:a.b.c.d: the /24 is the first 15 bytes */
		return !memcmp(a->sa6.sin6_addr.s6_addr,
			       b->sa6.sin6_addr.s6_addr, mapped ? 15 : 8);
	}
#endif

	return 0;
}

/*
 * May an unvalidated Initial from sa46 have a new server connection?  See
 * LWS_QUIC_HALFOPEN_MAX.  Returns nonzero if it is to be dropped.
 */
static int
lws_quic_halfopen_admit(struct lws *lwsi, const lws_sockaddr46 *sa46)
{
	struct lws_context_per_thread *pt = &lwsi->a.context->pt[(int)lwsi->tsi];
	struct lws_quic_netconn *oldest;
	unsigned int same = 0;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&pt->quic_halfopen)) {
		struct lws_quic_netconn *qn = lws_container_of(d,
				struct lws_quic_netconn, pt_list);

		if (lws_quic_same_prefix(&qn->path_sa46, sa46) &&
		    ++same >= LWS_QUIC_HALFOPEN_PER_PREFIX) {
			lwsl_wsi_info(lwsi, "too many handshakes from one "
					    "network, dropping Initial");
			return 1;
		}
	} lws_end_foreach_dll(d);

	/* it could not complete: see lws_quic_server_admit_established() */
	if (pt->quic_established.count >= lwsi->a.context->fd_limit_per_thread) {
		lwsl_wsi_info(lwsi, "QUIC connections at limit, dropping Initial");
		return 1;
	}

	if (pt->quic_halfopen.count < LWS_QUIC_HALFOPEN_MAX)
		return 0;

	/*
	 * Full: the oldest goes.  It never completed a handshake, so the
	 * close sends it nothing (a spoofed source would be the target).
	 */
	oldest = lws_container_of(lws_dll2_get_head(&pt->quic_halfopen),
				  struct lws_quic_netconn, pt_list);
	lwsl_wsi_info(lwsi, "handshakes in progress at limit, evicting oldest");
	lws_dll2_remove(&oldest->pt_list);
	lws_close_free_wsi(oldest->nwsi, LWS_CLOSE_STATUS_NOSTATUS,
			   "quic halfopen evicted");

	return 0;
}

/*
 * A server connection's handshake is completing.  Completed connections hold
 * no fd either, and a peer keeps one up as long as it likes (a PING refreshes
 * the idle timeout), so they are bounded here: a service thread keeps at most
 * as many as it has fd slots (fd_limit_per_thread), the bound TCP connections
 * have.  Beyond that, the newest, this one, is refused.  (With
 * LWS_WITH_PEER_LIMITS, it has counted against its peer's limits since it
 * was born, see lws_quic_peer_account().)  Returns nonzero if it is to be
 * closed.
 */
int
lws_quic_server_admit_established(struct lws *nwsi)
{
	struct lws_context *cx = nwsi->a.context;
	struct lws_context_per_thread *pt = &cx->pt[(int)nwsi->tsi];
	struct lws_quic_netconn *qn = nwsi->quic.qn;

	if (pt->quic_established.count >= cx->fd_limit_per_thread) {
		lwsl_wsi_notice(nwsi, "QUIC connections at limit (%u), "
				      "refusing", cx->fd_limit_per_thread);
		return 1;
	}

	lws_dll2_remove(&qn->pt_list);
	lws_dll2_add_tail(&qn->pt_list, &pt->quic_established);

	return 0;
}
#endif

/*
 * What a connection's peer address stack says about it follows what QUIC
 * proved.  A netconn's entry starts as hearsay, a datagram's source address
 * (lws_io_path() commits it so), and is raised on evidence that travelled
 * the path:
 *
 *  - ROUTABLE, address validation (RFC 9000 8.1): a packet protected with
 *    the Handshake keys, which only an endpoint that received our Initial
 *    can have, proves the address that Initial went to (initial_sa46), not
 *    the source of the datagram carrying it; a valid Retry token proves the
 *    address it is bound to, and a PATH_RESPONSE to our PATH_CHALLENGE the
 *    address it came from (8.2)
 *
 *  - CRYPTO, the handshake done: every entry already validated is now bound
 *    to the keys the peer proved it holds.  A server's handshake completes
 *    over Handshake packets, so its peer is proven by then; if it is not, it
 *    would count against no host's limits for as long as it lives, so it is
 *    refused instead (an embedder whose IO carries no peer stack has no
 *    peer to key anything on either way)
 *
 * lws_io_peer_raise() raises only an entry with seen's address and port, so
 * evidence arriving from somewhere else, eg, the new address of a path
 * migration that is not committed yet, raises nothing; a path that is
 * committed (RFC 9000 9) starts again at hearsay, until its validation
 * raises it.
 *
 * A server connection's peer limits accounting follows it, see
 * lws_quic_peer_account().  Returns nonzero if the connection is to be
 * refused for them.
 */
int
lws_quic_peer_proven(struct lws *nwsi, const lws_sockaddr46 *seen,
		     lws_peer_cred_t cred)
{
	lws_peer_entry_t e[LWS_PEER_WALK_MAX];
	int n;

	if (cred != LWS_PEER_CRED_CRYPTO) {
		if (seen)
			lws_io_peer_raise(nwsi, seen, cred);
		/*
		 * QUIC validated the path to it (RFC 9000 8): if a relay
		 * carries it, the relay is proven too, as long as it is still
		 * the one the connection was reached through.  A Retry token
		 * does not count: it is bound to an address, not a path.
		 */
		if (seen && nwsi->quic.qn && nwsi->quic.qn->address_validated)
			lws_io_path(nwsi, LWS_IOPATH_PROVEN, seen);
	} else {
		n = lws_io_peer_walk(nwsi, e, (int)LWS_ARRAY_SIZE(e));
		while (n-- > 0)
			if (e[n].cred >= LWS_PEER_CRED_ROUTABLE)
				lws_io_peer_raise(nwsi, &e[n].sa46,
					       LWS_PEER_CRED_CRYPTO);

		if (nwsi->quic.qn && nwsi->quic.qn->is_server &&
		    !lws_io_peer_effective(nwsi, &e[0]) &&
		    e[0].cred < LWS_PEER_CRED_VOUCHED) {
			lwsl_wsi_err(nwsi, "handshake done, peer unproven");

			return 1;
		}
	}

	return lws_quic_peer_account(nwsi);
}

/*
 * With LWS_WITH_PEER_LIMITS, a server connection counts as one wsi from its
 * first Initial until it is closed (lws_quic_netconn_destroy() gives it
 * back), but against whom follows its peer address stack: while the address
 * is only hearsay, a datagram's source anyone could have written, against
 * the one unproven budget all such connections share (unproven_limit_wsi),
 * and once QUIC proved it, against that address's own peer (ip_limit_wsi),
 * as a TCP connection does; lws_get_or_create_peer_wsi() decides which, as
 * lws_get_peer_host_key() would.  So unvalidated Initials, whatever source
 * they claim, can spend neither a real client's budget nor more than the
 * unproven one, and connections already proven are not touched by it.
 *
 * Returns nonzero if where it now belongs is at its limit: it is to be
 * refused.  While it closes, it then counts against nobody, so a connection
 * refused for its proven address's limit does not hold on to the unproven
 * budget either: like every connection, it is still bounded by the
 * thread's QUIC connection limits until it is gone.
 */
int
lws_quic_peer_account(struct lws *nwsi)
{
#if defined(LWS_WITH_PEER_LIMITS) && defined(LWS_WITH_SERVER)
	struct lws_quic_netconn *qn = nwsi->quic.qn;

	if (!qn || !qn->is_server)
		return 0;

	if (!lws_peer_move_wsi(nwsi->a.context, &qn->peer,
			       lws_get_or_create_peer_wsi(nwsi),
			       LWS_SOCK_INVALID))
		return 0;

	lws_peer_track_wsi_close(nwsi->a.context, qn->peer);
	qn->peer = NULL;

	return 1;
#else
	(void)nwsi;

	return 0;
#endif
}

static void
lws_quic_replies_destroy(struct lws *lwsi)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
			lws_dll2_get_head(&lwsi->quic.tx_replies)) {
		struct lws_quic_reply *r = lws_container_of(d,
					struct lws_quic_reply, list);

		lws_dll2_remove(&r->list);
		lws_free(r);
	} lws_end_foreach_dll_safe(d, d1);
}

/*
 * The DCID and SCID of the long header packet at p (RFC 9000 17.2), or -1 if
 * the header does not fit in len or a CID is longer than QUIC allows
 */
int
lws_quic_long_hdr_cids(const uint8_t *p, size_t len, struct lws_quic_cid *dcid,
		       struct lws_quic_cid *scid)
{
	size_t pos = 6;

	if (len < pos + 1 || p[5] > LWS_QUIC_MAX_CID_LEN ||
	    len < pos + p[5] + 1u)
		return -1;
	dcid->len = p[5];
	memcpy(dcid->id, &p[pos], dcid->len);
	pos += dcid->len;

	if (p[pos] > LWS_QUIC_MAX_CID_LEN || len < pos + 1u + p[pos])
		return -1;
	scid->len = p[pos];
	memcpy(scid->id, &p[pos + 1], scid->len);

	return 0;
}

/*
 * A client is only sent long headers by its server, which puts the SCID we
 * chose in them as their DCID (RFC 9000 7.2), and uses the version we are on,
 * or v2 if we offered it in version_information (RFC 9368).  Once one of the
 * server's Initials authenticated, the server's SCID is fixed as well (RFC
 * 9000 7.2).  Nothing in a long header is authenticated before the AEAD, so a
 * packet failing any of these belongs to some other connection, or to a
 * spoofer, and must be dropped before it changes anything.
 *
 * Returns nonzero if the packet is not for this connection.
 */
static int
lws_quic_client_long_hdr_foreign(struct lws *nwsi,
				 const struct lws_quic_cid *dcid,
				 const struct lws_quic_cid *scid,
				 uint32_t version)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;

	if (dcid->len != qn->loc_cid.len ||
	    memcmp(dcid->id, qn->loc_cid.id, dcid->len))
		return 1;

	if (version != qn->version &&
	    (version != LWS_QUIC_VERSION_2 ||
	     qn->version != qn->original_version ||
	     !(nwsi->a.context->options &
			     LWS_SERVER_OPTION_QUIC_LATEST_VERSION)))
		return 1;

	return qn->peer_iscid_set &&
	       (scid->len != qn->peer_iscid.len ||
		memcmp(scid->id, qn->peer_iscid.id, scid->len));
}

/*
 * sansIO rx for quic: one datagram, from peer, with its ECN bits.  It may
 * carry several coalesced packets; each is decrypted in place and its frames
 * parsed.  wsi is the socket's wsi: on a server the listening one, where the
 * packet's DCID finds the connection it belongs to.
 */
static lws_handling_result_t
lws_quic_rx_early_pkts(struct lws *wsi, struct lws_quic_netconn *qn);

/*
 * Keep a copy of a 1-RTT packet that reached a server before its handshake
 * completed, see struct lws_quic_early_pkt.  Returns 0 if it was kept.
 */
static int
lws_quic_hold_early_pkt(struct lws_quic_netconn *qn, const uint8_t *pkt,
			size_t len, const lws_sockaddr46 *peer, uint8_t ecn)
{
	struct lws_quic_early_pkt *ep;

	if (lws_dll2_count(&qn->early_pkts) >= LWS_QUIC_EARLY_PKTS_MAX)
		return 1;

	ep = lws_malloc(sizeof(*ep) + len, __func__);
	if (!ep)
		return 1;

	memset(&ep->list, 0, sizeof(ep->list));
	ep->peer	= *peer;
	ep->len		= len;
	ep->ecn		= ecn;
	memcpy(&ep[1], pkt, len);
	lws_dll2_add_tail(&ep->list, &qn->early_pkts);

	return 0;
}

static lws_handling_result_t
rops_rx_dgram_quic(struct lws *wsi, uint8_t *buf, size_t len,
		   const lws_sockaddr46 *peer, uint8_t ecn,
		   const lws_peer_entry_t *via)
{
	lws_sockaddr46 sa46 = *peer;
	int n = (int)len, orig_n = n;
	uint8_t *p;
	uint8_t scid_len = 0;
	uint8_t dcid_len = 0;
	struct lws_quic_cid dcid, scid;

	if (n < 2)
		return LWS_HPI_RET_HANDLED;

	p = buf;

	memset(&dcid, 0, sizeof(dcid));
	memset(&scid, 0, sizeof(scid));

	if (p[0] & 0x80) {
		dcid_len = p[5];
		if (dcid_len > LWS_QUIC_MAX_CID_LEN || n < 6 + dcid_len) {
			lwsl_wsi_notice(wsi, "QUIC RX: Invalid DCID length");
			return LWS_HPI_RET_HANDLED;
		}

		dcid.len = dcid_len;
		memcpy(dcid.id, &p[6], dcid_len);

		int scid_pos = 6 + dcid_len;
		if (n < scid_pos + 1) {
			lwsl_wsi_notice(wsi, "QUIC RX: Truncated before SCID");
			return LWS_HPI_RET_HANDLED;
		}

		scid_len = p[scid_pos];
		if (scid_len > LWS_QUIC_MAX_CID_LEN || n < scid_pos + 1 + scid_len) {
			lwsl_wsi_notice(wsi, "QUIC RX: Invalid SCID length");
			return LWS_HPI_RET_HANDLED;
		}

		scid.len = scid_len;
		memcpy(scid.id, &p[scid_pos + 1], scid_len);
	} else {
		dcid_len = 8;
		if (n < 1 + dcid_len) {
			lwsl_wsi_notice(wsi, "QUIC RX: dropping, short header too short");
			return LWS_HPI_RET_HANDLED;
		}

		dcid.len = dcid_len;
		memcpy(dcid.id, &p[1], dcid_len);
	}

	struct lws *nwsi = NULL;
	if (wsi->quic.qn && !wsi->quic.qn->is_server) {
		/*
		 * Client connection: the wsi itself is the connection.  What
		 * the server's long headers tell us (its SCID, a v2 upgrade)
		 * is only taken from a packet that authenticates, see
		 * lws_quic_client_long_hdr_foreign() and after the AEAD below
		 */
		nwsi = wsi;
	} else {
		/* Server listener: search children */
		nwsi = lws_quic_find_child_by_dcid(wsi, &dcid);
#if defined(LWS_WITH_SERVER)
		/*
		 * Active migration can move the client onto a path served by
		 * a different one of the vhost's QUIC listeners (eg, an IPv6
		 * connection migrating to the server's IPv4 preferred
		 * address).  If the receiving listener doesn't know the DCID,
		 * search the sibling QUIC listeners before giving up.
		 *
		 * We go on to drive the connection on this thread, so only a
		 * sibling on our own service thread will do.  A vhost's QUIC
		 * listeners are created on one thread for this (G-544): one
		 * on another, which shouldn't exist, is skipped rather than
		 * let a peer choose which thread drives its connection.
		 */
		if (!nwsi && wsi->a.vhost) {
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					lws_dll2_get_head(&wsi->a.vhost->listen_wsi)) {
				struct lws *lw = lws_container_of(d, struct lws,
								listen_list);
				if (lw == wsi || lw->role_ops != &role_ops_quic ||
				    lw->tsi != wsi->tsi)
					continue;
				nwsi = lws_quic_find_child_by_dcid(lw, &dcid);
				if (nwsi)
					break;
			} lws_end_foreach_dll_safe(d, d1);
		}
#endif
	}

	/* only the connection's own service thread ever drives it */
	if (nwsi && nwsi->quic.qn) {
		lws_quic_sul_assert_thread(nwsi->quic.qn);
	}


#if defined(LWS_WITH_SERVER)
	if (!nwsi) {
		if (!(p[0] & 0x80) || ((p[0] & 0x30) >> 4) != 0) {
			// lwsl_wsi_notice(wsi, "QUIC RX: Unknown DCID and not Initial, dropping");
			return LWS_HPI_RET_HANDLED;
		}

		uint32_t pkt_version = ((uint32_t)p[1] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 8) | p[4];

		if (pkt_version != LWS_QUIC_VERSION_1 && pkt_version != LWS_QUIC_VERSION_2) {
			uint8_t vn[128];

			/*
			 * RFC 9000 6.1 / 14.1: a server MUST NOT send Version
			 * Negotiation in response to a datagram smaller than
			 * the 1200-byte minimum, otherwise a spoofed-source
			 * one-liner makes us a reflector
			 */
			if (orig_n < 1200)
				return LWS_HPI_RET_HANDLED;

			lwsl_wsi_notice(wsi, "QUIC RX: Unsupported version 0x%08X, sending VN packet", pkt_version);
			uint8_t *vp = vn;
			*vp++ = 0x80; /* Long Header */
			*vp++ = 0; *vp++ = 0; *vp++ = 0; *vp++ = 0; /* Version 0 */
			*vp++ = scid.len;
			if (scid.len) { memcpy(vp, scid.id, scid.len); vp += scid.len; }
			*vp++ = dcid.len;
			if (dcid.len) { memcpy(vp, dcid.id, dcid.len); vp += dcid.len; }
			/* Add v1 */
			*vp++ = (uint8_t)(LWS_QUIC_VERSION_1 >> 24); *vp++ = (uint8_t)(LWS_QUIC_VERSION_1 >> 16);
			*vp++ = (uint8_t)(LWS_QUIC_VERSION_1 >> 8); *vp++ = (uint8_t)(LWS_QUIC_VERSION_1);
			/* Add v2 */
			*vp++ = (uint8_t)(LWS_QUIC_VERSION_2 >> 24); *vp++ = (uint8_t)(LWS_QUIC_VERSION_2 >> 16);
			*vp++ = (uint8_t)(LWS_QUIC_VERSION_2 >> 8); *vp++ = (uint8_t)(LWS_QUIC_VERSION_2);

			lws_quic_queue_reply(wsi, vn, (size_t)(vp - vn), &sa46);
			return LWS_HPI_RET_HANDLED;
		}

		/* Enforce 1200-byte padding for client-to-server Initial packets (RFC 9000 Section 14.1) */
		if (n < 1200) {
			lwsl_wsi_notice(wsi, "QUIC RX: Dropping under-padded Initial packet (len %d)", n);
			return LWS_HPI_RET_HANDLED;
		}

		struct lws_quic_cid valid_retry_scid;
		memset(&valid_retry_scid, 0, sizeof(valid_retry_scid));
		if (getenv("LWS_QUIC_FORCE_RETRY")) {
			int scid_pos_tmp = 6 + dcid_len;
			size_t t_off = (size_t)scid_pos_tmp + 1 + scid.len;
			uint64_t t_len = 0;
			size_t t_cons = lws_quic_parse_varint(&p[t_off], (size_t)n - t_off, &t_len);
			if (!t_cons) return LWS_HPI_RET_HANDLED;

			uint8_t peer_ip[16] = {0};
			size_t peer_ip_len = 0;
			if (sa46.sa4.sin_family == AF_INET) {
				memcpy(peer_ip, &sa46.sa4.sin_addr, 4);
				peer_ip_len = 4;
			}
#if defined(LWS_WITH_IPV6)
			else {
				memcpy(peer_ip, &sa46.sa6.sin6_addr, 16);
				peer_ip_len = 16;
			}
#endif

			if (t_len == 0) {
				uint8_t retry_pkt[1200];
				uint8_t *rp = retry_pkt;
				*rp++ = 0xf0; /* Long Header, Retry */
				memcpy(rp, &p[1], 4); rp += 4; /* Version */
				*rp++ = scid.len;
				if (scid.len) { memcpy(rp, scid.id, scid.len); rp += scid.len; }
				struct lws_quic_cid retry_scid;
				retry_scid.len = 8;
				if (lws_get_random(wsi->a.context, retry_scid.id, 8) != 8) return LWS_HPI_RET_HANDLED;
				*rp++ = retry_scid.len;
				memcpy(rp, retry_scid.id, retry_scid.len); rp += retry_scid.len;
				size_t tok_out_len = 0;
				if (!lws_quic_create_retry_token(wsi, dcid.id, dcid.len, retry_scid.id, retry_scid.len, peer_ip, peer_ip_len, rp, &tok_out_len)) {
					rp += tok_out_len;
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
					/*
					 * A token longer than a client can
					 * keep: RFC 9000 sets no limit, so a
					 * server may send one.  It never
					 * validates, the client must drop
					 * the Retry and take the next one
					 */
					if (lws_fi(&wsi->fic, "quic_retry_token_pad")) {
						memset(rp, 0, LWS_QUIC_FI_RETRY_TOKEN_PAD);
						rp += LWS_QUIC_FI_RETRY_TOKEN_PAD;
					}
#endif
					uint8_t tag[16];
					if (!lws_quic_create_retry_tag(dcid.id, dcid.len, retry_pkt, (size_t)(rp - retry_pkt), tag)) {
						memcpy(rp, tag, 16); rp += 16;
						lwsl_wsi_notice(wsi, "QUIC RX: Forcing Retry, sending Retry packet!");
						lws_quic_queue_reply(wsi, retry_pkt, (size_t)(rp - retry_pkt), &sa46);
					}
				}
				return LWS_HPI_RET_HANDLED;

			} else {
				if (lws_quic_validate_retry_token(wsi, &p[t_off + t_cons], (size_t)t_len, peer_ip, peer_ip_len, &dcid, &valid_retry_scid)) {
					lwsl_wsi_notice(wsi, "QUIC RX: Invalid Retry Token, dropping Initial packet");
					return LWS_HPI_RET_HANDLED;
				}
			}
		}

		if (lws_quic_halfopen_admit(wsi, &sa46))
			return LWS_HPI_RET_HANDLED;

		/* 1.5 Instantiate new QUIC network connection */
		nwsi = lws_create_new_server_wsi(wsi->a.vhost, wsi->tsi, 0, "quic child");
		if (!nwsi) {
			lwsl_wsi_notice(wsi, "QUIC RX: failed to create server wsi");
			return LWS_HPI_RET_HANDLED;
		}

		lws_wsi_event_role(nwsi, LWS_WSIEV_ADOPTED_TLS, &role_ops_quic);

		nwsi->quic.qn = lws_zalloc(sizeof(*nwsi->quic.qn), "quic_netconn");
		if (!nwsi->quic.qn) {
			lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NOSTATUS, "oom");
			return LWS_HPI_RET_HANDLED;
		}

		nwsi->quic.qn->nwsi = nwsi;
		nwsi->quic.qn->is_server = 1;
		nwsi->quic.qn->next_stream_id_bidi_local = 1;
		nwsi->quic.qn->next_stream_id_unidi_local = 3;
		nwsi->quic.qn->version = pkt_version;
		nwsi->quic.qn->original_version = pkt_version;
		lws_quic_streams_limits_init(nwsi->quic.qn, 400);
		nwsi->quic.qn->peer_ack_delay_exponent = 3;
		/* RFC 9000 §13.2.1 default max_ack_delay cap for delayed ACKs */
		nwsi->quic.qn->ack_delay_us = 25 * LWS_US_PER_MS;

		lws_quic_pmtud_reset(nwsi->quic.qn);

		if (nwsi->a.context->quic_cc_ops)
			nwsi->quic.qn->cc_ops = nwsi->a.context->quic_cc_ops;
		else
			nwsi->quic.qn->cc_ops = &lws_cc_ops_newreno;

		if (nwsi->quic.qn->cc_ops->init)
			nwsi->quic.qn->cc_ops->init(nwsi);

		/* Initialize RX Flow Control limits */
		nwsi->quic.qn->rx_max_data = LWS_QUIC_DEFAULT_WINDOW;
		nwsi->quic.qn->advertised_rx_max_data = LWS_QUIC_DEFAULT_WINDOW;
		nwsi->quic.qn->rx_window_size = LWS_QUIC_DEFAULT_WINDOW;
		nwsi->quic.qn->last_rx_update_us = lws_wsi_now(nwsi);
		nwsi->txc.peer_tx_cr_est = LWS_QUIC_DEFAULT_WINDOW; /* How much the peer can write to us */
		/* tx_cr is strictly initialized when we parse the peer's initial_max_data parameter */

		/*
		 * the peer we were born from is the committed path, and where
		 * our Initial goes
		 */
		nwsi->quic.qn->path_sa46 = sa46;
		nwsi->quic.qn->initial_sa46 = sa46;
		lws_io_path(nwsi, LWS_IOPATH_COMMIT, &sa46);

		/*
		 * A trusted relay carried it: sa46 is the client the relay
		 * claims, and what we send it goes back through the relay.
		 * The claim stays where our Initial goes, and what the
		 * handshake proves (initial_sa46)
		 */
		if (via && lws_io_path(nwsi, LWS_IOPATH_RELAYED,
				       &via[0].sa46)) {
			lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NOSTATUS,
					   "quic relay");
			return LWS_HPI_RET_HANDLED;
		}

		/*
		 * It counts from now on, in the unproven budget, unless its
		 * Retry token, bound to the address our Retry went to, came
		 * back (RFC 9000 8.1.2) and proved it.  Refused, it never
		 * completed a handshake, so the close sends it nothing.
		 */
		if (valid_retry_scid.len ?
			lws_quic_peer_proven(nwsi, &sa46,
					     LWS_PEER_CRED_ROUTABLE) :
			lws_quic_peer_account(nwsi)) {
			lwsl_wsi_info(wsi, "QUIC RX: peer limit, dropping "
					   "Initial");
			lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NOSTATUS,
					   "quic peer limit");
			return LWS_HPI_RET_HANDLED;
		}

#if defined(LWS_WITH_TLS)
		nwsi->use_ssl = (unsigned int)wsi->a.vhost->tls.use_ssl;
		if (lws_tls_quic_session(nwsi, quic_secret_cb)) {
			lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NOSTATUS, "ssl fail");
			return LWS_HPI_RET_HANDLED;
		}
#endif

		/* The client's SCID becomes our Remote CID */
		nwsi->quic.qn->rem_cid = scid;
		nwsi->quic.qn->peer_iscid = scid;
		nwsi->quic.qn->peer_iscid_set = 1;

		/* Save the original DCID to route subsequent Initial packets */
		nwsi->quic.qn->orig_dcid = dcid;

		nwsi->quic.qn->retry_scid = valid_retry_scid;

		/* Generate our own 8-byte Local CID */
		nwsi->quic.qn->loc_cid.len = 8;
		if (lws_get_random(wsi->a.context, nwsi->quic.qn->loc_cid.id, 8) != 8) {
			lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NOSTATUS, "random fail");
			return LWS_HPI_RET_HANDLED;
		}

		{
			uint8_t *local_tp_buf = lws_malloc(4096, "quic tp scratch");
			if (!local_tp_buf) {
				/*
				 * Q-10: nwsi is fully allocated and linked by
				 * here (qn, loc_cid, etc.).  Match the tp_overflow
				 * cleanup so OOM doesn't leak the nwsi + qn + its
				 * fd / TLS session.  local_tp_buf is NULL, so
				 * there's nothing to free.
				 */
				lwsl_wsi_err(wsi, "OOM allocating tp scratch buffer");
				lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NOSTATUS,
						   "tp scratch oom");
				return LWS_HPI_RET_HANDLED;
			}
			uint8_t *tp = local_tp_buf;
			uint8_t *tp_end = tp + 4096;
			uint64_t win;

#define LWS_QUIC_WRITE_TP_VARINT(_id, _val) \
	do { \
		int _vlen; \
		if (lws_ptr_diff_size_t(tp_end, tp) < 2) goto tp_overflow; \
		*tp++ = (_id); \
		_vlen = (int)lws_quic_write_varint(tp + 1, lws_ptr_diff_size_t(tp_end, tp + 1), (_val)); \
		if (!_vlen) goto tp_overflow; \
		*tp++ = (uint8_t)_vlen; \
		tp += _vlen; \
	} while (0)

#define LWS_QUIC_WRITE_TP_BUF(_id, _buf, _len) \
	do { \
		if (lws_ptr_diff_size_t(tp_end, tp) < (size_t)(2 + (_len))) goto tp_overflow; \
		*tp++ = (_id); \
		*tp++ = (uint8_t)(_len); \
		memcpy(tp, (_buf), (_len)); \
		tp += (_len); \
	} while (0)

			// lwsl_notice("QUIC CLIENT: Writing TP buffer! buf size %d", (int)(tp - local_tp_buf));
			win = lws_quic_fi_window(nwsi, "quic_tp_window",
						 LWS_QUIC_DEFAULT_WINDOW);
			LWS_QUIC_WRITE_TP_VARINT(0x04, win);
			LWS_QUIC_WRITE_TP_VARINT(0x05, win);
			LWS_QUIC_WRITE_TP_VARINT(0x06, win);
			LWS_QUIC_WRITE_TP_VARINT(0x07, win);
			LWS_QUIC_WRITE_TP_VARINT(0x08, nwsi->quic.qn->max_streams_bidi_local);
			LWS_QUIC_WRITE_TP_VARINT(0x09, nwsi->quic.qn->max_streams_unidi_local);
			LWS_QUIC_WRITE_TP_VARINT(0x20, 65535);
			LWS_QUIC_WRITE_TP_VARINT(0x01, nwsi->a.vhost->quic_max_idle_ms);

			LWS_QUIC_WRITE_TP_BUF(0x0F, nwsi->quic.qn->loc_cid.id, nwsi->quic.qn->loc_cid.len);
			LWS_QUIC_WRITE_TP_BUF(0x00, nwsi->quic.qn->orig_dcid.id, nwsi->quic.qn->orig_dcid.len);
			if (nwsi->quic.qn->retry_scid.len) {
				LWS_QUIC_WRITE_TP_BUF(0x10, nwsi->quic.qn->retry_scid.id, nwsi->quic.qn->retry_scid.len);
			}
                        if (wsi->a.context->options & LWS_SERVER_OPTION_QUIC_LATEST_VERSION) {
                                uint8_t vi_buf[12];
                                vi_buf[0] = (uint8_t)(nwsi->quic.qn->version >> 24);
                                vi_buf[1] = (uint8_t)(nwsi->quic.qn->version >> 16);
                                vi_buf[2] = (uint8_t)(nwsi->quic.qn->version >> 8);
                                vi_buf[3] = (uint8_t)(nwsi->quic.qn->version);
                                vi_buf[4] = (uint8_t)(LWS_QUIC_VERSION_1 >> 24);
                                vi_buf[5] = (uint8_t)(LWS_QUIC_VERSION_1 >> 16);
                                vi_buf[6] = (uint8_t)(LWS_QUIC_VERSION_1 >> 8);
                                vi_buf[7] = (uint8_t)(LWS_QUIC_VERSION_1);
                                vi_buf[8] = (uint8_t)(LWS_QUIC_VERSION_2 >> 24);
                                vi_buf[9] = (uint8_t)(LWS_QUIC_VERSION_2 >> 16);
                                vi_buf[10] = (uint8_t)(LWS_QUIC_VERSION_2 >> 8);
                                vi_buf[11] = (uint8_t)(LWS_QUIC_VERSION_2);
                                LWS_QUIC_WRITE_TP_BUF(0x11, vi_buf, 12);
                        }

			if (wsi->a.vhost->options & LWS_SERVER_OPTION_QUIC_PAD_CRYPTO) {
				lwsl_notice("QUIC TX: Padding handshake crypto data to artificially hit anti-amplification limits\n");
				/* Append a 3000-byte dummy transport parameter with reserved ID 0x31 */
				if (lws_ptr_diff_size_t(tp_end, tp) < 3003) goto tp_overflow;
				*tp++ = 0x31;
				*tp++ = 0x4B; /* 2-byte varint for length 3000 (0x4BB8 = 0x4000 | 3000) */
				*tp++ = 0xB8;
				memset(tp, 0, 3000);
				tp += 3000;
			}

                        if (wsi->a.vhost->quic_preferred_addresses) {
                                lwsl_notice("QUIC TX: Processing preferred_address config: '%s'\n", wsi->a.vhost->quic_preferred_addresses);
                                const char *p = wsi->a.vhost->quic_preferred_addresses;
                                lws_sockaddr46 sa4, sa6;
                                memset(&sa4, 0, sizeof(sa4));
                                memset(&sa6, 0, sizeof(sa6));
                                
                                while (p && *p) {
                                        char chunk[128];
                                        const char *comma = strchr(p, ',');
                                        size_t clen = comma ? (size_t)(comma - p) : strlen(p);
                                        if (clen >= sizeof(chunk)) clen = sizeof(chunk) - 1;
                                        memcpy(chunk, p, clen);
                                        chunk[clen] = '\0';
                                        
                                        char *colon = strrchr(chunk, ':');
                                        const char *rb = strchr(chunk, ']');
                                        int port = 443;
                                        /*
                                         * "[v6]:port" has its port after the
                                         * bracket.  No brackets: an
                                         * "addr:port" has exactly one colon,
                                         * more than one is a bare IPv6
                                         * literal, which takes the default
                                         * port.
                                         */
                                        if (colon && (rb ? colon > rb :
                                                      strchr(chunk, ':') == colon)) {
                                                port = atoi(colon + 1);
                                                *colon = '\0';
                                        }
                                        
                                        char *addr = chunk;
                                        if (addr[0] == '[') {
                                                addr++;
                                                char *rb = strchr(addr, ']');
                                                if (rb) *rb = '\0';
                                        }
                                        
                                        lws_sockaddr46 sa;
                                        memset(&sa, 0, sizeof(sa));
                                        if (lws_sa46_parse_numeric_address(addr, &sa) == 0) {
                                                if (sa.sa4.sin_family == AF_INET) {
                                                        sa4 = sa;
                                                        sa4.sa4.sin_port = htons((uint16_t)port);
#if defined(LWS_WITH_IPV6)
                                                } else {
                                                        sa6 = sa;
                                                        sa6.sa6.sin6_port = htons((uint16_t)port);
#endif
                                                }
                                        }
                                        p = comma ? comma + 1 : NULL;
                                }

                                /* We only send preferred_address if we have a valid address */
#if defined(LWS_WITH_IPV6)
                                if (sa4.sa4.sin_family == AF_INET || sa6.sa6.sin6_family == AF_INET6) {
#else
                                if (sa4.sa4.sin_family == AF_INET) {
#endif
                                        uint8_t pref_buf[128];
                                        uint8_t *pb = pref_buf;
                                        
                                        /* IPv4 (4 bytes addr, 2 bytes port) */
                                        if (sa4.sa4.sin_family == AF_INET) {
                                                memcpy(pb, &sa4.sa4.sin_addr.s_addr, 4); pb += 4;
                                                memcpy(pb, &sa4.sa4.sin_port, 2); pb += 2;
                                        } else {
                                                memset(pb, 0, 6); pb += 6;
                                        }
                                        
                                        /* IPv6 (16 bytes addr, 2 bytes port) */
#if defined(LWS_WITH_IPV6)
                                        if (sa6.sa6.sin6_family == AF_INET6) {
                                                memcpy(pb, sa6.sa6.sin6_addr.s6_addr, 16); pb += 16;
                                                memcpy(pb, &sa6.sa6.sin6_port, 2); pb += 2;
                                        } else {
                                                memset(pb, 0, 18); pb += 18;
                                        }
#else
                                        memset(pb, 0, 18); pb += 18;
#endif
                                        
                                        /* CID Length (1 byte) */
                                        *pb++ = 8; /* Generating an 8-byte CID */
                                        /* CID Bytes */
                                        if (lws_get_random(wsi->a.context, pb, 8) != 8) goto tp_overflow;
                                        /* Store so server can route migrated client packets addressed to it */
                                        if (nwsi->quic.qn) {
                                                nwsi->quic.qn->prefaddr_rem_cid.len = 8;
                                                memcpy(nwsi->quic.qn->prefaddr_rem_cid.id, pb, 8);
                                        }
                                        pb += 8;
                                        /* Stateless Reset Token */
                                        if (lws_get_random(wsi->a.context, pb, 16) != 16) goto tp_overflow;
                                        pb += 16;
                                        
                                        LWS_QUIC_WRITE_TP_BUF(0x0D, pref_buf, (size_t)(pb - pref_buf));
                                        lwsl_notice("QUIC TX: Sent preferred_address TP (0x0D)\n");
                                }
                        }

			lws_io_tls_quic_set_tp(nwsi, local_tp_buf, (size_t)(tp - local_tp_buf));
			lws_free(local_tp_buf);
			goto tp_ok;
tp_overflow:
			lws_free(local_tp_buf);
			lwsl_wsi_err(wsi, "QUIC TX: tp buffer overflow");
			lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NOSTATUS, "tp overflow");
			return LWS_HPI_RET_HANDLED;
tp_ok:
			;
#undef LWS_QUIC_WRITE_TP_VARINT
#undef LWS_QUIC_WRITE_TP_BUF
		}

		/* Link it to the UDP listening socket */
		lws_mux_mark_immortal(nwsi);
		nwsi->mux_substream = 1;
		wsi->mux_listener = 1;
		lws_wsi_mux_insert(nwsi, wsi, nwsi->mux.my_sid);

		/* Derive the Initial keys using the client's initial DCID */
		if (lws_quic_derive_initial_keys(nwsi, &dcid)) {
			lwsl_wsi_err(wsi, "QUIC RX: Initial key derivation failed");
			lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NOSTATUS, "keys failed");
			return LWS_HPI_RET_HANDLED;
		}

		/*
		 * Nothing else bounds the life of a server connection that
		 * never gets to send: PTO only arms on tx, and we only tx once
		 * CRYPTO offset 0 has arrived and TLS has something to say.
		 * So a spoofed Initial with no usable CRYPTO in it would sit
		 * here for ever.  Give the handshake the same deadline as a
		 * TLS accept; lws_quic_server_idle_check() takes over once
		 * the handshake completes.
		 */
		lws_set_timeout(nwsi, PENDING_TIMEOUT_AWAITING_CLIENT_HS_SEND,
				(int)wsi->a.context->timeout_secs);
		nwsi->quic.qn->hs_deadline_us = lws_wsi_now(nwsi) +
				(lws_usec_t)wsi->a.context->timeout_secs *
								LWS_US_PER_SEC;

		/* ... and count it against the half-open limits until then */
		lws_dll2_add_tail(&nwsi->quic.qn->pt_list,
				  &wsi->a.context->pt[(int)wsi->tsi].quic_halfopen);

		lwsl_wsi_info(wsi, "QUIC RX: Created new connection! (loc_cid len %d)", nwsi->quic.qn->loc_cid.len);
	}
#else
	if (!nwsi) {
		lwsl_wsi_notice(wsi, "QUIC RX: Unknown DCID and no server support, dropping");
		return LWS_HPI_RET_HANDLED;
	}
#endif

	int pending_migration = 0;
	lws_sockaddr46 migration_sa46;

	if (nwsi && nwsi->quic.qn) {
		int addr_changed = 0;
		if (nwsi->quic.qn->path_sa46.sa4.sin_family != sa46.sa4.sin_family) {
			addr_changed = 1;
		} else if (sa46.sa4.sin_family == AF_INET) {
			if (nwsi->quic.qn->path_sa46.sa4.sin_addr.s_addr != sa46.sa4.sin_addr.s_addr ||
			    nwsi->quic.qn->path_sa46.sa4.sin_port != sa46.sa4.sin_port)
				addr_changed = 1;
		}
#if defined(LWS_WITH_IPV6)
		else if (sa46.sa4.sin_family == AF_INET6) {
			if (lws_sa46_compare_sin6_addr(&nwsi->quic.qn->path_sa46.sa6.sin6_addr,
						       &sa46.sa6.sin6_addr) ||
			    nwsi->quic.qn->path_sa46.sa6.sin6_port != sa46.sa6.sin6_port)
				addr_changed = 1;
		}
#endif
		if (addr_changed) {
			pending_migration = 1;
			migration_sa46 = sa46;
		} else {
			nwsi->quic.qn->path_sa46 = sa46;
		}
	}

	int valid_datagram_bytes = 0;
	struct lws_quic_cid pdcid, pscid; /* this long header packet's CIDs */
	uint32_t pkt_version = 0;

	memset(&pdcid, 0, sizeof(pdcid));
	memset(&pscid, 0, sizeof(pscid));

	/* F-69: bytes_received is no longer unconditionally incremented here */

	while (n > 0) {
		/* If ALPN negotiation migrated the connection in a previous packet, update nwsi */
		if (nwsi && !nwsi->quic.qn) {
			nwsi = lws_get_quic_network_wsi(nwsi);
		}

		if (!nwsi || !nwsi->quic.qn) {
			lwsl_wsi_notice(wsi, "QUIC RX: network connection gone, dropping remaining packets");
			break;
		}

		if (nwsi->quic.qn->is_closing) {
			lwsl_wsi_notice(wsi, "QUIC RX: Connection is closing, dropping remaining packets");
			break;
		}

		/* We have the connection! Grab the appropriate keys based on packet type */
		int level = LWS_QUIC_LEVEL_APP;
		if (p[0] == 0x00) {
			lwsl_wsi_info(wsi, "QUIC RX: Next byte is 0x00, ignoring as padding");
			p++;
			n--;
			continue;
		}

		/*
		 * Fixed bit (RFC 9000 §17.2 & §17.3).  This is the one bit in
		 * the first byte that is NOT covered by header protection (the
		 * HP mask only touches the low nibble of a long header and the
		 * low 5 bits of a short header), so we can check it here, before
		 * trusting any field derived from this byte and before AEAD.
		 *
		 * A compliant sender always sets it.  A cleared Fixed bit means
		 * the byte is corrupt or not a QUIC packet; since every field we
		 * would parse next (form, type, version, CID lengths) is derived
		 * from this byte, we cannot trust the length field to find the
		 * next coalesced packet boundary either, so drop the rest of the
		 * datagram rather than advance blindly.
		 *
		 * The reserved bits (0x0c long / 0x18 short) are header-protected
		 * and so cannot be checked until after lws_quic_unmask_header();
		 * the existing post-AEAD check still handles those.
		 */
		if (!(p[0] & 0x40)) {
			lwsl_wsi_notice(wsi, "QUIC RX: Fixed bit not set (0x%02x), "
					      "dropping corrupt datagram", p[0]);
			break;
		}
		if (p[0] & 0x80) {
			uint8_t type = (uint8_t)((p[0] & 0x30) >> 4);

			if (lws_quic_long_hdr_cids(p, (size_t)n, &pdcid, &pscid)) {
				lwsl_wsi_notice(wsi, "QUIC RX: truncated long header");
				break;
			}
			pkt_version = ((uint32_t)p[1] << 24) |
				      ((uint32_t)p[2] << 16) |
				      ((uint32_t)p[3] << 8) | p[4];

			if (!nwsi->quic.qn->is_server &&
			    lws_quic_client_long_hdr_foreign(nwsi, &pdcid,
							     &pscid, pkt_version)) {
				lwsl_wsi_info(wsi, "QUIC RX: long header not for "
						   "this connection, dropping");
				break;
			}

			/*
			 * The type bits mean what the packet's own version
			 * says they mean (RFC 9369 3.2), as when its length
			 * is parsed (lws_quic_get_pn_offset())
			 */
			int is_v2 = pkt_version == LWS_QUIC_VERSION_2;

                        uint8_t v1_type = type;
                        if (is_v2) {
                                switch (type) {
                                case 0: v1_type = LWS_QUIC_PT_RETRY; break;
                                case 1: v1_type = LWS_QUIC_PT_INITIAL; break;
                                case 2: v1_type = LWS_QUIC_PT_0RTT; break;
                                case 3: v1_type = LWS_QUIC_PT_HANDSHAKE; break;
                                }
                        }

                        if (v1_type == LWS_QUIC_PT_INITIAL) level = LWS_QUIC_LEVEL_INITIAL;
                        else if (v1_type == LWS_QUIC_PT_HANDSHAKE) level = LWS_QUIC_LEVEL_HANDSHAKE;
                        else if (v1_type == LWS_QUIC_PT_0RTT) level = LWS_QUIC_LEVEL_EARLY;
                        else if (v1_type == LWS_QUIC_PT_RETRY) {
				/*
				 * A client takes at most one Retry, and none
				 * once it processed an Initial (RFC 9000
				 * 17.2.5.2), so rem_cid here is still the DCID
				 * of the Initial the Retry answers
				 */
				if (nwsi && nwsi->quic.qn && !nwsi->quic.qn->is_server &&
				    !nwsi->quic.qn->peer_iscid_set &&
				    !nwsi->quic.qn->retry_scid.len) {
					size_t tag_pos = (size_t)n - 16;
					size_t tok_pos = 7u + pdcid.len + pscid.len;
					if (n >= 16 && tag_pos >= tok_pos) {
						if (!lws_quic_validate_retry_tag(nwsi->quic.qn, nwsi->quic.qn->rem_cid.id, nwsi->quic.qn->rem_cid.len, p, tag_pos, &p[tag_pos])) {
							/*
							 * Check the token fits before
							 * committing anything: a
							 * too-long length left in
							 * retry_token_len would be
							 * read past retry_token[] on
							 * to the wire in every
							 * following Initial, and a
							 * Retry we drop must leave
							 * the connection as it was,
							 * still sending to the
							 * original DCID and still
							 * able to take a Retry
							 */
							if (tag_pos - tok_pos > sizeof(nwsi->quic.qn->retry_token)) {
								lwsl_wsi_notice(wsi, "QUIC RX: Retry token too large, dropping packet");
								n = 0;
								break;
							}
							nwsi->quic.qn->retry_scid = pscid;
							nwsi->quic.qn->rem_cid = pscid;
							nwsi->quic.qn->retry_token_len = tag_pos - tok_pos;
							memcpy(nwsi->quic.qn->retry_token, &p[tok_pos], nwsi->quic.qn->retry_token_len);
							
							/* RFC 9000 17.2.5.1: The client MUST NOT change the cryptographic keys it uses for Initial packets */
							/* But it MUST reset its Initial packet number space */
							if (nwsi->quic.qn->keys[LWS_QUIC_LEVEL_INITIAL]) {
								nwsi->quic.qn->keys[LWS_QUIC_LEVEL_INITIAL]->pn_tx = 0;
								nwsi->quic.qn->keys[LWS_QUIC_LEVEL_INITIAL]->pn_rx_largest = 0;
							}
							nwsi->quic.qn->highest_rx_pn[LWS_QUIC_LEVEL_INITIAL] = 0;
							nwsi->quic.qn->rx_pn_bitmask[LWS_QUIC_LEVEL_INITIAL] = 0;

							/*
							 * The server kept nothing of
							 * what we sent in Initial: it
							 * goes again, under the reset
							 * PNs, and is no longer in
							 * flight (RFC 9002 6.3).  Left
							 * there, in_flight would no
							 * longer be in PN order
							 */
							lws_quic_initial_requeue(nwsi->quic.qn);
							
							/* Re-arm writable to send the new Initial packet */
							lws_callback_on_writable(nwsi);
							lwsl_wsi_notice(wsi, "QUIC RX: Accepted Retry packet, resending Initial!");
							break; /* Drop remaining datagram */
						} else {
							lwsl_wsi_notice(wsi, "QUIC RX: Invalid Retry Integrity Tag, dropping packet");
							break;
						}
					}
				}
				break;
			}
			else {
				lwsl_wsi_notice(wsi, "QUIC RX: Unsupported long header type %d", type);
				break;
			}
		}

		if (nwsi && nwsi->quic.qn) {
			if (level > nwsi->quic.qn->highest_rx_level)
				nwsi->quic.qn->highest_rx_level = (uint8_t)level;
		}

		int pn_space = (level == LWS_QUIC_LEVEL_EARLY || level == LWS_QUIC_LEVEL_APP) ? LWS_QUIC_LEVEL_APP : level;

		/*
		 * Enforce 1200-byte padding for subsequent client-to-server Initial packets (RFC 9000 Section 14.1)
		 * Note: RFC 9000 allows the client to stop padding Initial packets once it has received an
		 * acknowledgment from the server or sent/received a packet other than Initial/VN. Therefore,
		 * we MUST NOT discard subsequent unpadded Initial packets. The first Initial packet (which
		 * instantiates the connection) is already checked and validated for 1200-byte padding earlier.
		 */

		size_t local_dcid_len = (nwsi && nwsi->quic.qn) ? nwsi->quic.qn->loc_cid.len : 8;
		if (local_dcid_len == 0) local_dcid_len = 8;
		size_t payload_len_stated = 0;
		size_t pn_offset = lws_quic_get_pn_offset(p, (size_t)n, &payload_len_stated, local_dcid_len);
		if (!pn_offset) {
			lwsl_wsi_notice(wsi, "QUIC RX: Malformed or truncated packet");
			break;
		}

		size_t packet_size = pn_offset + payload_len_stated;
		if (packet_size > (size_t)n) {
			lwsl_wsi_notice(wsi, "QUIC RX: Packet stated size %zu > remaining UDP %zu", packet_size, (size_t)n);
			break;
		}

		/* F-57: Validate short header DCID */
		if (!(p[0] & 0x80) && nwsi && nwsi->quic.qn && nwsi->quic.qn->loc_cid.len) {
			if (local_dcid_len > (size_t)n - 1 ||
			    (memcmp(&p[1], nwsi->quic.qn->loc_cid.id, local_dcid_len) &&
			     memcmp(&p[1], nwsi->quic.qn->prefaddr_rem_cid.id, local_dcid_len))) {
				lwsl_wsi_notice(wsi, "QUIC RX: Short header DCID mismatch");
				/* Drop packet */
				p += packet_size;
				n -= (int)packet_size;
				continue;
			}
		}

		/*
		 * A server must not process 1-RTT packets before its handshake
		 * is complete (RFC 9001 5.7), even though it has their keys
		 * from when it sent its Finished.  Until then the client's
		 * certificate has not been confirmed against the vhost's
		 * policy (lws_tls_quic_confirm_peer()), so a request in one
		 * would be served to a peer that may yet be refused... and
		 * the handshake keys, which the client's Finished still
		 * needs, are discarded below on the first 1-RTT packet.  So
		 * don't decrypt it yet.  It can simply have overtaken the
		 * client's Finished on the way, so hold a few still
		 * protected until the handshake completes, and process them
		 * then (lws_quic_rx_early_pkts()).  Any more are dropped
		 * unacknowledged, and the client's loss recovery sends their
		 * frames again.
		 *
		 * 0-RTT is served before the handshake completes by design,
		 * with nothing yet known about this client: a vhost that
		 * asks for client certificates takes none of it the same way.
		 */

		if (nwsi->quic.qn->is_server && !nwsi->quic.qn->handshake_done &&
		    (level == LWS_QUIC_LEVEL_APP ||
		     (level == LWS_QUIC_LEVEL_EARLY && nwsi->a.vhost &&
		      lws_check_opt(nwsi->a.vhost->options,
			LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT)))) {
			if (level == LWS_QUIC_LEVEL_APP &&
			    !lws_quic_hold_early_pkt(nwsi->quic.qn, p,
						     packet_size, peer, ecn))
				lwsl_wsi_info(wsi, "QUIC RX: 1-RTT before the "
						   "handshake completed, holding "
						   "%zu bytes", packet_size);
			else
				lwsl_wsi_info(wsi, "QUIC RX: level %d before "
						   "the handshake completed, "
						   "dropping %zu bytes",
						   level, packet_size);
			p += packet_size;
			n -= (int)packet_size;
			continue;
		}

		struct lws_quic_keys *k = nwsi->quic.qn->keys[level];

		if (!k || !k->el_hp_rx.len) {
			lwsl_wsi_info(wsi, "QUIC RX: No valid keys for this packet level %d, skipping %zu bytes", level, packet_size);
			p += packet_size;
			n -= (int)packet_size;
			continue;
		}
		
		lwsl_wsi_info(wsi, "QUIC RX: Parsing packet level %d, UDP remaining %d, stated packet_size %zu", level, n, packet_size);

		/* 3. Unmasking: Reveal the true Packet Number */
		int pn_len = lws_quic_unmask_header(k, p, packet_size, pn_offset);
		if (pn_len < 0) {
			lwsl_wsi_notice(wsi, "QUIC RX: Header unmask failed");
			break;
		}


		/*
		 * Reconstruct full 62-bit PN.
		 */
		uint64_t truncated_pn = 0;
		for (int i = 0; i < pn_len; i++)
			truncated_pn = (truncated_pn << 8) | p[pn_offset + (size_t)i];

		uint64_t largest_pn = nwsi->quic.qn ? nwsi->quic.qn->highest_rx_pn[pn_space] : 0;
		uint64_t full_pn = lws_quic_decode_packet_number(largest_pn, truncated_pn, pn_len * 8);
		lwsl_wsi_info(wsi, "QUIC RX: Packet level %d, decoded full_pn = %llu", level, (unsigned long long)full_pn);

		struct lws_quic_keys *decryption_keys = k;
		int is_key_update = 0;

		if (!(p[0] & 0x80)) { /* Short header */
			uint8_t kp = (uint8_t)((p[0] & 0x04) >> 2);
			if (nwsi->quic.qn && nwsi->quic.qn->handshake_done &&
			    nwsi->quic.qn->rx_key_phase != kp) {
				/*
				 * Maybe the peer's key update: try the next
				 * phase's read keys, which are derived once
				 * and kept.  The bit is unprotected until the
				 * packet authenticates, so a forged or corrupted
				 * one only costs the attempt; it can't make us
				 * stop following real key updates (G-104).
				 */
				struct lws_quic_keys *nk =
					lws_quic_rx_next_keys(nwsi->quic.qn);

				if (nk) {
					decryption_keys = nk;
					is_key_update = 1;
				}
			}
		}

		/* 4. Decryption: Authenticate and decrypt the payload in-place! */
		int dec_len = lws_quic_decrypt_payload(decryption_keys, p, packet_size, pn_offset, (uint8_t)pn_len, full_pn);
		if (dec_len < 0) {
			lwsl_wsi_info(wsi, "QUIC RX: AEAD Decryption failed (bad tag or truncated)");

			/*
			 * Anyone who sees the DCID can send these, so they
			 * change nothing about the connection, beyond the
			 * count RFC 9001 6.6 asks for: past the AEAD's
			 * integrity limit, the chance that some forgery got
			 * through is too high to go on (G-104)
			 */
			if (nwsi && nwsi->quic.qn) {
				if (++nwsi->quic.qn->rx_auth_fail >
				    (k->cipher_type == 1 ?
					LWS_QUIC_AEAD_INTEGRITY_LIMIT_CHACHA :
					LWS_QUIC_AEAD_INTEGRITY_LIMIT_GCM)) {
					lwsl_wsi_warn(wsi, "QUIC RX: AEAD "
						      "integrity limit reached, "
						      "closing");
					lws_quic_enter_closing_state(nwsi,
						LWS_QUIC_ERR_AEAD_LIMIT_REACHED,
						0, 0);
					/*
					 * On the server, wsi is the listener
					 * shared by every connection: only
					 * the affected child may be closed
					 */
					if (nwsi != wsi)
						goto next_packet;
					return LWS_HPI_RET_PLEASE_CLOSE_ME;
				}
			}

			/* F-130: Stateless Reset Token detection */
			if (nwsi && nwsi->quic.qn && (size_t)n >= 21) {
				static const uint8_t zero_token[16] = {0};
				if (memcmp(nwsi->quic.qn->rem_stateless_reset_token, zero_token, 16) &&
				    !memcmp(&p[n - 16], nwsi->quic.qn->rem_stateless_reset_token, 16)) {
					lwsl_wsi_notice(wsi, "QUIC RX: Stateless reset token matched! Terminating connection silently.");
					if (nwsi != wsi) {
						/*
						 * as for a peer CONNECTION_CLOSE
						 * (C-471): the close frees nwsi
						 * and the loop head reads it, and
						 * it is a silent end, no
						 * CONNECTION_CLOSE of ours goes out
						 */
						nwsi->quic.qn->is_closing = 1;
						lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NORMAL, "quic stateless reset");
						nwsi = NULL;
						goto next_packet;
					}
					return LWS_HPI_RET_PLEASE_CLOSE_ME;
				}
			}
			goto next_packet;
		}

		/* Check reserved bits AFTER successful AEAD decryption (RFC 9000 5.4.1 & 12.2) */
		if (p[0] & 0x80) {
			/* Long header: Bits 0x0c MUST be zero */
			if (p[0] & 0x0c) {
				lwsl_wsi_notice(wsi, "QUIC RX: Reserved bits non-zero in long header");
				if (nwsi && nwsi != wsi) {
					lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_PROTOCOL_VIOLATION, 0, 0);
					goto next_packet;
				}
				return LWS_HPI_RET_PLEASE_CLOSE_ME;
			}
		} else {
			/* Short header: Bits 0x18 MUST be zero */
			if (p[0] & 0x18) {
				lwsl_wsi_notice(wsi, "QUIC RX: Reserved bits non-zero in short header");
				if (nwsi && nwsi != wsi) {
					lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_PROTOCOL_VIOLATION, 0, 0);
					goto next_packet;
				}
				return LWS_HPI_RET_PLEASE_CLOSE_ME;
			}
		}

		/* Decryption succeeded! Commit key update if pending */
		if (is_key_update) {
			lws_quic_rx_next_commit(nwsi->quic.qn);
			/* ...and have the phase after ready (RFC 9001 6.3) */
			lws_quic_rx_next_keys(nwsi->quic.qn);
			nwsi->quic.qn->rx_key_phase ^= 1;
			nwsi->quic.qn->rx_packets_since_update = 0;
			if (!nwsi->quic.qn->key_update_pending) {
				/* Peer initiated, so we echo by updating TX keys */
				lws_quic_initiate_key_update(nwsi);
				nwsi->quic.qn->key_update_pending = 0; /* Echoed */
			} else {
				/* We initiated, this is the peer echoing back */
				nwsi->quic.qn->key_update_pending = 0;
			}
			lwsl_wsi_notice(wsi, "QUIC RX: Key Update completed successfully");
		}
		
		        if (nwsi->quic.qn) {
                nwsi->quic.qn->rx_packets_since_update++;

		if (ecn == 1)
			nwsi->quic.qn->ecn_rx_ect1++;
		else if (ecn == 2)
			nwsi->quic.qn->ecn_rx_ect0++;
		else if (ecn == 3)
			nwsi->quic.qn->ecn_rx_ce++;
        }

		if (nwsi->quic.qn && level == LWS_QUIC_LEVEL_HANDSHAKE) {
			nwsi->quic.qn->address_validated = 1;
			/*
			 * Only who got our Initial has these keys, so what
			 * they prove is the address it went to, not this
			 * datagram's source: a client whose Handshake packets
			 * come from another port (two sockets, or a NAT
			 * rebinding mid-handshake) has still proven the path
			 * it is on, and the other address is only a migration
			 * to probe like any other, below
			 */
			if (lws_quic_peer_proven(nwsi,
					&nwsi->quic.qn->initial_sa46,
					LWS_PEER_CRED_ROUTABLE) ||
			    /*
			     * and a server's connection, validated, takes its
			     * tls restriction slot only now, so spoofed
			     * Initials can't fill it
			     */
			    (nwsi->quic.qn->is_server &&
			     lws_io_tls_quic_admit(nwsi))) {
				/* its proven address, or tls, is at its limit */
				lws_quic_enter_closing_state(nwsi,
					LWS_QUIC_ERR_CONNECTION_REFUSED, 0, 0);
				if (nwsi != wsi)
					goto next_packet;
				return LWS_HPI_RET_PLEASE_CLOSE_ME;
			}
		}

		/*
		 * A client takes the SCID of the server's first Initial that
		 * authenticated as the DCID of everything it sends from now
		 * on (RFC 9000 7.2), and the server's
		 * initial_source_connection_id transport parameter must match
		 * it (RFC 9000 7.3).  A server's long header in v2, which we
		 * offered, moves us to v2 (RFC 9368 2.3), again only once it
		 * authenticated.
		 */
		if (nwsi->quic.qn && !nwsi->quic.qn->is_server &&
		    (p[0] & 0x80)) {
			if (level == LWS_QUIC_LEVEL_INITIAL &&
			    !nwsi->quic.qn->peer_iscid_set) {
				nwsi->quic.qn->peer_iscid = pscid;
				nwsi->quic.qn->peer_iscid_set = 1;
				nwsi->quic.qn->rem_cid = pscid;
			}
			if (pkt_version != nwsi->quic.qn->version) {
				nwsi->quic.qn->version = pkt_version;
				lwsl_wsi_notice(wsi, "QUIC RX: server moved us "
						     "to QUIC v2 (RFC 9368)");
			}
		}

		if (level == LWS_QUIC_LEVEL_HANDSHAKE) {
			lws_quic_discard_keys(nwsi, LWS_QUIC_LEVEL_INITIAL);
		} else if (level == LWS_QUIC_LEVEL_APP) {
			lws_quic_discard_keys(nwsi, LWS_QUIC_LEVEL_INITIAL);
			if (nwsi->quic.qn && nwsi->quic.qn->is_server) {
				lws_quic_discard_keys(nwsi, LWS_QUIC_LEVEL_HANDSHAKE);
			}
		}

		lwsl_wsi_info(wsi, "QUIC RX: SUCCESS! Decrypted %d bytes of payload", dec_len);

		/* F-69: Only count bytes_received for valid (decrypted) datagrams */
		if (valid_datagram_bytes == 0 && nwsi->quic.qn) {
			nwsi->quic.qn->bytes_received += (uint64_t)orig_n;
			/*
			 * ... and separately for the path we are probing, since
			 * that path's 3x anti-amplification allowance (RFC 9000
			 * 9.3.1) is only earned by bytes that arrived from it.
			 */
			if (pending_migration && nwsi->quic.qn->is_server &&
			    nwsi->quic.qn->probing_sa46_valid &&
			    lws_quic_sa46_same_path(&migration_sa46,
						    &nwsi->quic.qn->probing_sa46))
				nwsi->quic.qn->probe_bytes_received += (uint64_t)orig_n;
			valid_datagram_bytes = 1;
		}

		/* Check for duplicate/replayed packet numbers (Security Fix) */
		int is_out_of_order = 0;
		if (nwsi->quic.qn) {
			uint64_t highest = nwsi->quic.qn->highest_rx_pn[pn_space];
			if ((nwsi->quic.qn->rx_pn_bitmask[pn_space] != 0 || highest != 0) && full_pn <= highest) {
				uint64_t diff = highest - full_pn;
				if (diff >= 64 || (nwsi->quic.qn->rx_pn_bitmask[pn_space] & (1ULL << diff))) {
					lwsl_wsi_notice(wsi, "QUIC RX: Dropping duplicated or very old packet %llu", (unsigned long long)full_pn);
					goto next_packet;
				}
				nwsi->quic.qn->rx_pn_bitmask[pn_space] |= (1ULL << diff);
				is_out_of_order = 1;
			} else {
				if (nwsi->quic.qn->rx_pn_bitmask[pn_space] != 0 || highest != 0) {
					uint64_t diff = full_pn - highest;
					/*
					 * Forward-PN plausibility guard.  A
					 * corrupted truncated PN decodes to an
					 * arbitrary value, and a huge forward
					 * jump would rescale the receive
					 * bitmask and bump highest_rx_pn past
					 * thousands of imaginary gaps,
					 * poisoning ACK and loss accounting.
					 * QUIC senders never gap PNs by this
					 * much in practice, so drop the packet
					 * rather than trust the decode.
					 */
					if (diff > LWS_QUIC_PN_FORWARD_JUMP_LIMIT) {
						lwsl_wsi_notice(wsi,
							"QUIC RX: decoded PN %llu "
							"jumps %llu ahead of "
							"highest %llu; treating "
							"as corrupted truncated PN",
							(unsigned long long)full_pn,
							(unsigned long long)diff,
							(unsigned long long)highest);
						goto next_packet;
					}
					if (diff >= 64)
						nwsi->quic.qn->rx_pn_bitmask[pn_space] = 0;
					else
						nwsi->quic.qn->rx_pn_bitmask[pn_space] <<= diff;
				}
				nwsi->quic.qn->rx_pn_bitmask[pn_space] |= 1ULL;
				nwsi->quic.qn->highest_rx_pn[pn_space] = full_pn;
			}
			
			/*
			 * Connection Migration: Execute pending migration now that
			 * the packet is cryptographically verified.  Skip if a probe
			 * is already in flight for this address to avoid overwriting
			 * the pending path_challenge (which would make the client's
			 * PATH_RESPONSE not match).
			 */
			if (pending_migration) {
				if (nwsi->quic.qn->probing_sa46_valid &&
				    lws_quic_sa46_same_path(&migration_sa46,
							    &nwsi->quic.qn->probing_sa46)) {
					pending_migration = 0;
				} else if (is_out_of_order) {
					lwsl_notice("QUIC: Ignoring connection migration from out-of-order packet (PN %llu <= highest %llu)\n",
						    (unsigned long long)full_pn, (unsigned long long)highest);
					pending_migration = 0;
				} else {
				pending_migration = 0;
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
				char buf_old[64], buf_new[64];
				uint16_t port_old, port_new;

				lws_sa46_write_numeric_address(&nwsi->quic.qn->path_sa46, buf_old, sizeof(buf_old));
				lws_sa46_write_numeric_address(&migration_sa46, buf_new, sizeof(buf_new));
				
#if defined(LWS_WITH_IPV6)
				port_old = nwsi->quic.qn->path_sa46.sa4.sin_family == AF_INET ? nwsi->quic.qn->path_sa46.sa4.sin_port : nwsi->quic.qn->path_sa46.sa6.sin6_port;
				port_new = migration_sa46.sa4.sin_family == AF_INET ? migration_sa46.sa4.sin_port : migration_sa46.sa6.sin6_port;
#else
				port_old = nwsi->quic.qn->path_sa46.sa4.sin_port;
				port_new = migration_sa46.sa4.sin_port;
#endif
#endif

				if (nwsi->quic.qn->is_server &&
				    nwsi->quic.qn->probe_fails &&
				    lws_quic_sa46_same_path(&migration_sa46,
						&nwsi->quic.qn->probing_sa46) &&
				    lws_wsi_now(nwsi) <
					nwsi->quic.qn->probe_holdoff_until) {
					/*
					 * Probing this address failed lately,
					 * don't try again yet; what it sends
					 * still earns its allowance for when we
					 * do
					 */
					nwsi->quic.qn->probe_bytes_received +=
							(uint64_t)orig_n;
				} else if (nwsi->quic.qn->is_server) {
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
					/* trying an address again is not news */
					if (nwsi->quic.qn->probe_fails &&
					    lws_quic_sa46_same_path(&migration_sa46,
						    &nwsi->quic.qn->probing_sa46))
						lwsl_info("QUIC Server: probing peer address %s:%u again\n",
							  buf_new,
							  (unsigned int)ntohs(port_new));
					else
						lwsl_notice("QUIC Server: Connection Migration initiated! Peer address changed from %s:%u to %s:%u (pending validation)\n",
						    buf_old, (unsigned int)ntohs(port_old),
						    buf_new, (unsigned int)ntohs(port_new));
#endif
					/*
					 * RFC 9000 9.3 / 9.5: do NOT commit to the new
					 * address on the strength of a packet that
					 * merely arrived from it; UDP sources are
					 * spoofable, and an authenticated client could
					 * otherwise redirect this connection's whole
					 * output (response data, retransmissions, PMTUD
					 * probes) at a third party.  Keep udp->sa46 so
					 * everything continues on the validated path,
					 * and probe the new address with a PATH_CHALLENGE
					 * addressed to it alone.  Only a PATH_RESPONSE
					 * arriving from that address commits the
					 * migration (parse-quic.c); until then the tx
					 * path limits what goes there to 3x what we got
					 * from it, and the probe is abandoned on timeout
					 * (8.2.4).  A probe to a different address that
					 * is still outstanding is superseded.
					 */
					lws_quic_path_probe_abandon(nwsi, NULL);
					nwsi->quic.qn->rx_has_non_probing = 0;
					if (lws_quic_sa46_same_path(&migration_sa46,
						    &nwsi->quic.qn->probing_sa46))
						/* same address as last probe: credit accrues */
						nwsi->quic.qn->probe_bytes_received += (uint64_t)orig_n;
					else {
						nwsi->quic.qn->probing_sa46 = migration_sa46;
						nwsi->quic.qn->probe_bytes_received = (uint64_t)orig_n;
						nwsi->quic.qn->probe_bytes_sent = 0;
						/* a new address has failed nothing yet */
						nwsi->quic.qn->probe_fails = 0;
					}
					nwsi->quic.qn->probing_sa46_valid = 1;

					{
						struct lws_quic_netconn *qn =
							nwsi->quic.qn;
						lws_usec_t pto;

						if (lws_get_random(wsi->a.context,
							qn->path_challenge,
							sizeof(qn->path_challenge)) !=
						      sizeof(qn->path_challenge) ||
						    lws_quic_path_probe_queue_challenge(nwsi)) {
							qn->probing_sa46_valid = 0;
							return LWS_HPI_RET_HANDLED;
						}

						/*
						 * RFC 9000 8.2.4: give up after three
						 * times the larger of the current PTO
						 * and the initial PTO, sending the
						 * challenge again each PTO until then
						 */
						pto = lws_quic_pto_base_us(qn);
						if (pto < LWS_QUIC_DEFAULT_PTO_US)
							pto = LWS_QUIC_DEFAULT_PTO_US;
						qn->probe_pto = pto;
						qn->probe_deadline = lws_wsi_now(nwsi) +
								     3 * pto;
						lws_quic_sul_schedule(qn,
							&qn->path_probe_sul,
							lws_quic_path_probe_sul_cb, pto);
					}

				} else {
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
					lwsl_notice("QUIC Client: Server address changed from %s:%u to %s:%u, re-connecting socket\n",
						    buf_old, (unsigned int)ntohs(port_old),
						    buf_new, (unsigned int)ntohs(port_new));
#endif

					/* the path is the new server address */
					if (lws_io_path(nwsi, LWS_IOPATH_COMMIT,
							&migration_sa46))
						lwsl_wsi_warn(nwsi, "QUIC: failed to re-connect client socket");

					nwsi->quic.qn->path_sa46 = migration_sa46;

					/* Reset Congestion Control State (RFC 9000 9.3.3) */
					if (nwsi->quic.qn->cc_ops && nwsi->quic.qn->cc_ops->init)
						nwsi->quic.qn->cc_ops->init(nwsi);

					/* Reset RTT estimator */
					nwsi->quic.qn->smoothed_rtt = 0;
					nwsi->quic.qn->rttvar = 0;
					nwsi->quic.qn->latest_rtt = 0;

					/* Reset PMTUD */
					lws_quic_pmtud_reset(nwsi->quic.qn);

					/* Set path to unvalidated */
					nwsi->quic.qn->address_validated = 0;

					/* Reset Path Bytes for Anti-Amplification tracking */
					nwsi->quic.qn->bytes_received = (uint64_t)orig_n;
					nwsi->quic.qn->bytes_sent = 0;
				}

				/*
				 * Client path: queue PATH_CHALLENGE for the
				 * server-address-change case (server already did
				 * its own above).
				 */
				if (!nwsi->quic.qn->is_server &&
				    !nwsi->quic.qn->path_challenge_pending) {
					struct lws_quic_tx_frame *f_pc =
						lws_zalloc(sizeof(*f_pc) + 8, "quic path_chall");
					if (f_pc) {
						f_pc->type = LWS_QUIC_FT_PATH_CHALLENGE;
						f_pc->len = 8;
						f_pc->data = (uint8_t *)&f_pc[1];
						if (lws_get_random(wsi->a.context, f_pc->data, 8) != 8) {
							lws_free(f_pc);
							return LWS_HPI_RET_HANDLED;
						}
						memcpy(nwsi->quic.qn->path_challenge, f_pc->data, 8);
						nwsi->quic.qn->path_challenge_pending = 1;
						lws_dll2_add_head(&f_pc->list,
							&nwsi->quic.qn->pending_tx[LWS_QUIC_LEVEL_APP]);
					}
				}
				lws_callback_on_writable(nwsi);
				}
			}

			/* 5. Parse and handle all frames in the payload */
			if (dec_len == 0) {
				lwsl_wsi_notice(wsi, "QUIC RX: Packet payload is empty (no frames)");
				if (nwsi && nwsi != wsi) {
					lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_PROTOCOL_VIOLATION, 0, 0);
					goto next_packet;
				}
				return LWS_HPI_RET_PLEASE_CLOSE_ME;
			}

			int parse_res = lws_quic_parse_frames(nwsi, pn_space, &p[pn_offset + (size_t)pn_len], (size_t)dec_len, &sa46);

			/* ALPN negotiation might have migrated the network WSI! */
			if (nwsi && !nwsi->quic.qn) {
				nwsi = lws_get_quic_network_wsi(nwsi);
			}

			/*
			 * After frame parsing may have generated Handshake-level
			 * ACKs, discard any pending Initial/Handshake TX so those
			 * ACKs don't race ahead of PATH_CHALLENGE to the new path.
			 * The handshake is done; only APP-level frames (including
			 * PATH_CHALLENGE) should reach the new client port.
			 */
			if (nwsi && nwsi->quic.qn && nwsi->quic.qn->probing_sa46_valid &&
			    nwsi->quic.qn->handshake_done) {
				int _li;
				/* Discard Initial/Handshake TX */
				for (_li = 0; _li <= LWS_QUIC_LEVEL_HANDSHAKE; _li++) {
					lws_start_foreach_dll_safe(struct lws_dll2 *, _d, _d1,
							nwsi->quic.qn->pending_tx[_li].head) {
						struct lws_quic_tx_frame *_f = lws_container_of(_d,
								struct lws_quic_tx_frame, list);
						lws_dll2_remove(&_f->list);
						lws_free(_f);
					} lws_end_foreach_dll_safe(_d, _d1);
				}
				/*
				 * Ensure PATH_CHALLENGE is the first APP frame sent
				 * to the new path.  A PATH_RESPONSE generated by
				 * parse_frames (in response to the client's
				 * PATH_CHALLENGE) may have been add_head'd on top
				 * of our PATH_CHALLENGE; move our CHALLENGE back
				 * to the front.
				 */
				if (nwsi->quic.qn->path_challenge_pending) {
					lws_start_foreach_dll_safe(struct lws_dll2 *, _d, _d1,
							nwsi->quic.qn->pending_tx[LWS_QUIC_LEVEL_APP].head) {
						struct lws_quic_tx_frame *_f = lws_container_of(_d,
								struct lws_quic_tx_frame, list);
						if (_f->type == LWS_QUIC_FT_PATH_CHALLENGE) {
							lws_dll2_remove(&_f->list);
							lws_dll2_add_head(&_f->list,
								&nwsi->quic.qn->pending_tx[LWS_QUIC_LEVEL_APP]);
						}
					} lws_end_foreach_dll_safe(_d, _d1);
				}
			}

			/*
			 * The server commits the new path ONLY on PATH_RESPONSE
			 * validation (handled in parse-quic.c).  Do NOT commit
			 * here on non-probing packets.
			 */

			/*
			 * The user RECEIVE callback that ran during parse_frames
			 * above may have synchronously closed (and freed) an
			 * arbitrary sibling stream via lws_wsi_close(..,
			 * LWS_TO_KILL_SYNC).  The dll2 _safe iterator caches the
			 * next node before the body, and lws_close_free_wsi()
			 * detaches the child via lws_wsi_mux_sibling_disconnect()
			 * (-> lws_dll2_remove), so the cached next stays valid.
			 */
			if (nwsi) {
				lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
						lws_dll2_get_head(&nwsi->mux.child_list_owner)) {
					struct lws *w = lws_container_of(d,
							struct lws, mux.sibling_list);

					if (w->quic.qs && w->quic.qs->close_after_rx) {
						lwsl_wsi_info(w, "QUIC RX Post-Processing: Closing stream WSI");
						/*
						 * Once: a close that defers
						 * (flushing) must not be
						 * started again on every
						 * packet, its own timeout or
						 * drain completes it.  And a
						 * stream the app refused
						 * doesn't wait for its own
						 * in-flight frames to be acked
						 * (its request HEADERS, which
						 * kept it flushing for seconds
						 * and re-closing 200 times a
						 * second meanwhile): it is
						 * abandoned, RESET / STOP_SENDING
						 * do the rest
						 */
						w->quic.qs->close_after_rx = 0;
						if (w->quic.qs->abandon)
							lwsi_set_skt_unusable(w, 1);
						lws_close_free_wsi(w,
							LWS_CLOSE_STATUS_NOSTATUS,
							"quic post rx stream close");
					}
				} lws_end_foreach_dll_safe(d, d1);
			}

			/*
			 * A packet that authenticated and parsed is activity:
			 * it restarts the transport idle timeout (RFC 9000
			 * 10.1), and refreshes the server's keepalive, as h2
			 * does on rx, so a peer keeping the connection alive
			 * with PINGs (RFC 9000 10.1.2) is not reaped as idle.
			 */
			if (parse_res >= 0 && nwsi && nwsi->quic.qn) {
				lws_quic_idle_restart(nwsi->quic.qn, 0);
				if (nwsi->quic.qn->is_server &&
				    nwsi->pending_timeout == PENDING_TIMEOUT_UDP_IDLE)
					lws_quic_server_idle_check(nwsi);
			}

			if (parse_res < 0) {
			if (parse_res == -3) {
				/* Peer closed the connection via CONNECTION_CLOSE. Drop silently without replying. */
				lwsl_wsi_info(nwsi ? nwsi : wsi, "QUIC RX: peer closed connection");
				/* draining: RFC 9000 10.2.2, nothing may be sent back */
				if (nwsi && nwsi->quic.qn)
					nwsi->quic.qn->is_closing = 1;
				if (nwsi && nwsi != wsi) {
					lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NORMAL, "quic peer closed");
					/*
					 * nwsi is freed now (synchronously with
					 * the poll loop).  The loop head
					 * dereferences it to find the netconn,
					 * so it must not see the stale pointer:
					 * with it NULL the head drops whatever
					 * else was coalesced in this datagram,
					 * which is all we can do for a closed
					 * connection anyway.
					 */
					nwsi = NULL;
					goto next_packet;
				}
				return LWS_HPI_RET_PLEASE_CLOSE_ME;
			}
			/* We found an error and queued a CONNECTION_CLOSE frame */
			lwsl_wsi_notice(wsi, "QUIC RX: frame parsing aborted (%d)", parse_res);
			if (nwsi) {
				lws_quic_enter_closing_state(nwsi, parse_res == -2 ? LWS_QUIC_ERR_PROTOCOL_VIOLATION : LWS_QUIC_ERR_FRAME_ENCODING_ERROR, 0, 0);
				lws_callback_on_writable(nwsi);
			}
			goto next_packet;
			} else if (parse_res > 0) {
				/*
				 * The packet contained at least one ack-eliciting
				 * frame, so we must ACK it.  For Initial/Handshake
				 * pn-spaces, and before the handshake completes, we
				 * send the ACK immediately (RFC 9000 §13.2.1 rule 3
				 * keeps handshake / loss-detection timely).  For
				 * Application (1-RTT) pn-space we coalesce: send
				 * immediately on every 2nd ack-eliciting packet
				 * (§13.2.1 rule 4) and otherwise arm the delayed-ACK
				 * timer, so a burst of N packets yields ~N/2 ACKs
				 * instead of N.
				 */
				if (nwsi && nwsi->quic.qn) {
					struct lws_quic_netconn *qn = nwsi->quic.qn;

					qn->needs_ack[pn_space] = 1;

					if (pn_space != LWS_QUIC_LEVEL_APP ||
					    !qn->handshake_done) {
						lws_callback_on_writable(nwsi);
						goto next_packet;
					}

					/*
					 * App-space ACK: apply the 2nd-packet rule,
					 * else defer to the delayed-ACK timer.
					 */
					unsigned int ack_every = 2;
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
					/*
					 * quic_ack_late: every so many, or when
					 * the timer's max_ack_delay is up, so
					 * the peer has more in flight
					 */
					int fi_late = lws_fi(&nwsi->fic,
							     "quic_ack_late");

					if (fi_late)
						ack_every = LWS_QUIC_FI_ACK_LATE;
#endif
					if (++qn->rx_ack_eliciting_count >= ack_every ||
					    !qn->smoothed_rtt) {
						lws_sul_cancel(&qn->ack_delay_sul);
						qn->ack_delay_armed = 0;
						lws_callback_on_writable(nwsi);
						goto next_packet;
					}

					if (!qn->ack_delay_armed) {
						/*
						 * RTT/8 capped at the configured
						 * max_ack_delay (ours or the peer's
						 * advertised TP 0x0b, whichever is
						 * smaller).  The TX path stamps the
						 * real dwell time into the ACK
						 * Delay field when it emits it.
						 */
						lws_usec_t delay = qn->smoothed_rtt / 8;
						lws_usec_t cap = qn->ack_delay_us;

						if (qn->peer_max_ack_delay_us &&
						    qn->peer_max_ack_delay_us < cap)
							cap = qn->peer_max_ack_delay_us;
						if (delay > cap || !delay)
							delay = cap;
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
						if (fi_late)
							delay = cap;
#endif

						qn->rx_ack_eliciting_since_us =
							lws_wsi_now(nwsi);
						qn->ack_delay_armed = 1;
						lws_quic_sul_schedule(qn,
							&qn->ack_delay_sul,
							lws_quic_ack_delay_cb, delay);
					}
				}
			}
		}

next_packet:
		n -= (int)packet_size;
		p += packet_size;
	}

	/*
	 * If this completed a server's handshake, the 1-RTT packets that got
	 * here before it can be processed now
	 */
	if (nwsi && nwsi != wsi && nwsi->quic.qn &&
	    nwsi->quic.qn->handshake_done &&
	    lws_dll2_count(&nwsi->quic.qn->early_pkts))
		return lws_quic_rx_early_pkts(wsi, nwsi->quic.qn);

	return LWS_HPI_RET_HANDLED;
}

/*
 * The server's 1-RTT packets that came before its handshake completed, once it
 * has: each is processed as if it had just arrived alone in a datagram from
 * where it came.  They are taken off the connection first, since processing
 * one may close it.
 */
static lws_handling_result_t
lws_quic_rx_early_pkts(struct lws *wsi, struct lws_quic_netconn *qn)
{
	lws_handling_result_t r = LWS_HPI_RET_HANDLED;
	lws_dll2_owner_t owner;
	struct lws_dll2 *d;

	memset(&owner, 0, sizeof(owner));
	while ((d = lws_dll2_get_head(&qn->early_pkts))) {
		lws_dll2_remove(d);
		lws_dll2_add_tail(d, &owner);
	}

	while ((d = lws_dll2_get_head(&owner))) {
		struct lws_quic_early_pkt *ep = lws_container_of(d,
					struct lws_quic_early_pkt, list);

		lws_dll2_remove(d);
		if (r == LWS_HPI_RET_HANDLED) {
			lwsl_wsi_info(wsi, "QUIC RX: processing held 1-RTT "
					   "packet, %zu bytes", ep->len);
			r = rops_rx_dgram_quic(wsi, (uint8_t *)&ep[1], ep->len,
					       &ep->peer, ep->ecn, NULL);
		}
		lws_free(ep);
	}

	return r;
}

/* a quic socket's datagrams are read one at a time, to rx_dgram */
static int
rops_rx_policy_quic(struct lws *wsi, int *flags, size_t *max)
{
	(void)wsi;
	/* and the pass's POLLOUT is served whatever the state */
	*flags = LWS_RXPOL_F_POLLOUT;
	*max = 0;

	return LWS_RXPOL_PUMP_DGRAM;
}


int
lws_tls_quic_tx_crypto_cb(struct lws *wsi, int level, const uint8_t *buf, size_t len)
{
	struct lws_quic_netconn *qn = wsi->quic.qn;
	struct lws_quic_tx_frame *f;

	if (!qn)
		return -1;

	// lwsl_notice("QUIC TLS TX: %s generated %d bytes of crypto data for level %d\n", lws_wsi_tag(wsi), (int)len, level);

	/* Allocate frame struct + payload buffer natively */
	f = lws_zalloc(sizeof(*f) + len, "quic tx frame");
	if (!f)
		return -1;

	f->type = LWS_QUIC_FT_CRYPTO;
	f->data = (uint8_t *)&f[1];
	f->len = len;

	/* Copy the TLS library's output into the frame */
	memcpy(f->data, buf, len);

	/*
	 * Set proper offset tracking for CRYPTO streams.
	 */
	f->offset = qn->crypto_tx_offset[level];
	qn->crypto_tx_offset[level] += len;

	/* Add to the pending TX queue for this encryption level! */
	lws_dll2_add_tail(&f->list, &qn->pending_tx[level]);

	/* Wake up the event loop to instantly trigger POLLOUT and send the packet */
	lws_callback_on_writable(wsi);

	return 0;
}

static int
quic_secret_cb(struct lws *wsi, enum lws_tls_quic_secret_type type,
	       const uint8_t *secret, size_t secret_len)
{
	lwsl_info("QUIC TLS: Extracted secret type %d (len %d)\n", type, (int)secret_len);
	if (lws_quic_set_keys(wsi, type, secret, secret_len)) {
		lwsl_wsi_err(wsi, "Failed to set QUIC keys for type %d", type);
		return -1;
	}
	return 0;
}

/*
 * Queue the one CONNECTION_CLOSE frame that ends the connection, at the
 * highest encryption level we have keys for, dropping everything else
 * pending except the CRYPTO frames the peer may still need to derive keys
 */
static void
lws_quic_queue_connection_close(struct lws *nwsi, uint64_t err_code,
				uint64_t frame_type, int is_app_error)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	struct lws_quic_tx_frame *f;
	int level, target_level = LWS_QUIC_LEVEL_INITIAL;

	/* Determine highest available encryption level to send CONNECTION_CLOSE */
	int start_level = qn->highest_rx_level;
	for (level = start_level; level >= LWS_QUIC_LEVEL_INITIAL; level--) {
		if (qn->keys[level] && qn->keys[level]->el_hp_tx.len) {
			target_level = level;
			break;
		}
	}

	/*
	 * Clear pending queues, we are closing, but keep the handshake's
	 * CRYPTO frames so peer can derive keys!
	 *
	 * Not the 1-RTT ones though: they only carry post-handshake messages,
	 * nothing needed for keys, and the one they do carry at the end of a
	 * server handshake is a NewSessionTicket.  A connection closed because
	 * its peer was refused, eg, a client cert its vhost does not accept,
	 * must not hand him a ticket to resume what was refused, possibly
	 * with 0-RTT served before anything checks him again.
	 *
	 * Nor a HANDSHAKE_DONE (RFC 9000 10.2.1: closing, we send only the
	 * CONNECTION_CLOSE).  Ahead of it in the same packet, it confirms the
	 * handshake the close ends, eg, when the packet that made us close came
	 * with the client's Finished, and a peer may take the connection as
	 * established before it sees the close.
	 */
	for (level = 0; level < LWS_QUIC_LEVEL_COUNT; level++) {
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->pending_tx[level].head) {
			struct lws_quic_tx_frame *tf = lws_container_of(d, struct lws_quic_tx_frame, list);
			if (tf->type != LWS_QUIC_FT_CRYPTO ||
			    level == LWS_QUIC_LEVEL_APP) {
				lws_dll2_remove(&tf->list);
				lws_free(tf);
			}
		} lws_end_foreach_dll_safe(d, d1);
	}

	/* Enqueue a single CONNECTION_CLOSE frame */
	f = lws_zalloc(sizeof(*f) + 16, "quic tx cc");
	if (f) {
		uint8_t *p = (uint8_t *)&f[1];
		f->type = is_app_error ? LWS_QUIC_FT_CONNECTION_CLOSE_APP : LWS_QUIC_FT_CONNECTION_CLOSE;
		
		lwsl_wsi_info(nwsi, "QUIC TX: Enqueueing CONNECTION_CLOSE (type 0x%x, err 0x%llx) at level %d",
			f->type, (unsigned long long)err_code, target_level);

		/* Encode the error code (varint) */
		p += lws_quic_write_varint(p, 8, err_code);

		/* Frame type (varint) - only for Transport Errors (0x1c) */
		if (!is_app_error) {
			p += lws_quic_write_varint(p, 8, frame_type);
		}

		/* Reason phrase length (0) */
		p += lws_quic_write_varint(p, 8, 0);

		f->data = (uint8_t *)&f[1];
		f->len = (size_t)(p - f->data);
		lwsl_hexdump_debug(f->data, f->len);

		if (target_level == LWS_QUIC_LEVEL_APP)
			lws_quic_dbg_1rtt_account(qn, f, "connection-close");
		lws_dll2_add_tail(&f->list, &qn->pending_tx[target_level]);
	}

}

void
lws_quic_enter_closing_state(struct lws *wsi, uint64_t err_code, uint64_t frame_type, int is_app_error)
{
	struct lws_quic_netconn *qn;
	struct lws *nwsi = lws_get_quic_network_wsi(wsi);

	if (!nwsi || !nwsi->quic.qn) {
		lwsl_notice("lws_quic_enter_closing_state: nwsi %s, qn %p (wsi %s parent %s)\n", 
			lws_wsi_tag(nwsi), nwsi ? nwsi->quic.qn : NULL, lws_wsi_tag(wsi), lws_wsi_tag(wsi ? wsi->mux.parent_wsi : NULL));
		return;
	}

	qn = nwsi->quic.qn;

	if (qn->is_closing) {
		lwsl_notice("lws_quic_enter_closing_state: qn->is_closing is already 1\n");
		return; /* Already closing */
	}

	qn->is_closing = 1;
	qn->conn_close_err = err_code;


	lwsl_wsi_warn(nwsi, "QUIC: Entering Closing State (err 0x%llx)", (unsigned long long)err_code);

	lws_quic_queue_connection_close(nwsi, err_code, frame_type,
					is_app_error);

	/* Wait 3 seconds, then drop the socket */
	lws_set_timeout(nwsi, PENDING_TIMEOUT_KILLED_BY_SSL_INFO, 3);
	lws_callback_on_writable(nwsi);
}

/* one produced packet: what the send and the accounting after it need */
/*
 * sansIO tx of the connection's next packet (README.sans-io-split.md, "A
 * content source's tx").  From tp->level up, finds the first encryption
 * level that has something to send and may send it now, and assembles one
 * packet into IO's buffer: header, ACK, as many pending frames as fit within
 * the path MTU (fragmenting STREAM and CRYPTO), padding, length, packet
 * number, encrypted in place.  The frames that went in move to in_flight
 * tagged with the packet number, as if sent; lws_quic_packet_sent() makes
 * that final or, if IO could not take the packet, puts them back.
 *
 * Returns the packet's length, with tp filled in for the send and the
 * accounting; 0 when no level from tp->level has anything to send;
 * LWS_TX_WAIT when sending is held (amplification limit, congestion window,
 * pacing: the pacer sul or an ACK wakes us); LWS_TX_FAIL when assembly or
 * encryption failed.
 */
static int
lws_quic_packet_tx(struct lws *wsi, uint8_t *buf, size_t max,
		   struct lws_quic_tx_pkt *tp)
{
	struct lws_quic_netconn *qn = wsi->quic.qn;
	lws_usec_t pto_delay = lws_quic_pto_delay_us(qn, qn->pto_count);
	int level, n;

	if (max > LWS_QUIC_MAX_DGRAM)
		max = LWS_QUIC_MAX_DGRAM;
	memset(buf, 0, max);

	for (level = tp->level; level < LWS_QUIC_LEVEL_COUNT; level++) {
		if (!qn->keys[level]) {
			continue;
		}

		if (!qn->keys[level]->el_hp_tx.len) {
			continue;
		}

		/* Server MUST NOT send 0-RTT (EARLY) packets */
		if (level == LWS_QUIC_LEVEL_EARLY && qn->is_server) {
			continue;
		}

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
		/*
		 * quic_no_half_rtt: a server sends nothing in 1-RTT until its
		 * handshake completes, like one whose tls sends its tickets
		 * only once it has the client's Finished.  RFC 8446 4.6.1 lets
		 * it send them after its own, and some tls libraries do.
		 */
		if (level == LWS_QUIC_LEVEL_APP && qn->is_server &&
		    !qn->handshake_done && lws_fi(&wsi->fic, "quic_no_half_rtt"))
			continue;
#endif

		int pn_space = (level == LWS_QUIC_LEVEL_EARLY || level == LWS_QUIC_LEVEL_APP) ? LWS_QUIC_LEVEL_APP : level;
		int is_ack_allowed = (level != LWS_QUIC_LEVEL_EARLY);
		/* we owe the peer an ACK we may send in this packet */
		int ack_due = qn->needs_ack[pn_space] && is_ack_allowed;

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
		/*
		 * quic_ack_late: an app PN space ACK waits for its delayed-ACK
		 * timer or LWS_QUIC_FI_ACK_LATE packets, rather than going
		 * with whatever we send meanwhile
		 */
		if (ack_due && pn_space == LWS_QUIC_LEVEL_APP &&
		    qn->ack_delay_armed && lws_fi(&wsi->fic, "quic_ack_late"))
			ack_due = 0;
#endif

		if (!qn->pending_tx[level].count && !ack_due) {
			continue;
		}

		lwsl_debug("QUIC TX: Processing level %d. pending=%d, needs_ack=%d, pto_needed=%d", level, qn->pending_tx[level].count, qn->needs_ack[pn_space], qn->pto_probe_needed);

		/* Determine if we're allowed to send */
		uint32_t mtu = qn->current_mtu ? qn->current_mtu : 1280;
		/*
		 * A PTO's probe is there to get an ack back, so it is no bigger
		 * than the path surely carries.  Its packets of the current MTU
		 * may be just what the path stopped carrying (a black hole, RFC
		 * 9000 14.4): then, sized like them, the probe is lost too, no
		 * ack comes, and nothing is ever found lost.  Acked, it lets
		 * loss detection find them lost, which goes back to the base.
		 */
		if (pn_space == LWS_QUIC_LEVEL_APP && qn->pto_probe_needed &&
		    mtu > LWS_QUIC_PMTU_BASE)
			mtu = LWS_QUIC_PMTU_BASE;
		/*
		 * The anti-amplification allowances are datagram (UDP payload)
		 * bytes, like the bytes received that earn them: they cap the
		 * datagram, not the path MTU the IP and UDP headers come off.
		 */
		size_t dgram_cap = max;

		/* Enforce RFC 9000 Anti-Amplification Limit (Section 8.1) for servers */
		if (qn->is_server && !qn->address_validated) {
			uint64_t allowance = 3 * qn->bytes_received;
			if (qn->bytes_sent >= allowance) {
				lwsl_notice("QUIC TX: Anti-Amplification limit reached! Sent: %llu, Recv: %llu. Blocking send.\n",
					    (unsigned long long)qn->bytes_sent, (unsigned long long)qn->bytes_received);
				return LWS_TX_WAIT;
			}
			uint64_t remaining = allowance - qn->bytes_sent;
			if (dgram_cap > remaining)
				dgram_cap = (size_t)remaining;

			if (remaining < 48) { /* Too small to send anything useful */
				lwsl_notice("QUIC TX: Anti-Amplification remaining (%llu) too small. Blocking send.\n", (unsigned long long)remaining);
				return LWS_TX_WAIT;
			}
		}

		/*
		 * Congestion control (RFC 9002 7): the window, pacing and how
		 * many frames we have in flight already hold back what is
		 * ack-eliciting, but for PTO probes.  Packets of only ACK
		 * frames are not congestion controlled: an ACK we owe goes
		 * anyway, on its own (ack_only), which is all that gets
		 * through while we are held.
		 */
		int cc_held = !qn->pto_probe_needed &&
			      (lws_quic_in_flight_full(qn) ||
			       (qn->cc_ops && qn->cc_ops->can_send &&
				!qn->cc_ops->can_send(wsi, mtu)));

		if (!cc_held && !qn->pto_probe_needed && qn->cc_ops &&
		    qn->cc_ops->get_pacing_delay) {
			lws_usec_t delay = qn->cc_ops->get_pacing_delay(wsi, mtu);
			if (delay > 0) {
				lws_quic_sul_schedule(qn, &qn->pacer_sul,
						      lws_quic_pacer_cb, delay);
				cc_held = 1;
			}
		}

		if (cc_held && !ack_due)
			return LWS_TX_WAIT;

		int ack_only = cc_held;

		/* AEAD Confidentiality Limits Check (RFC 9001 Section 6.6) */
		uint64_t update_limit = (1ULL << 20);
		if (wsi->a.vhost && (wsi->a.vhost->options & LWS_SERVER_OPTION_QUIC_EARLY_KEY_UPDATE)) {
			update_limit = 10; /* Trigger early for interop testing */
		}
		if (level == LWS_QUIC_LEVEL_APP && qn->tx_packets_since_update > update_limit) {
			lws_quic_initiate_key_update(wsi);
		}

		/* We have frames to send at this encryption level! */
		uint8_t *p = buf;
		uint64_t my_pn = qn->keys[level]->pn_tx++;
		lws_sockaddr46 packet_dest_sa46;
		int has_packet_dest = 0;

		/* 1. Serialize Header */
		size_t pn_offset = 0;
		size_t header_len = 0;

		if (level == LWS_QUIC_LEVEL_INITIAL || level == LWS_QUIC_LEVEL_HANDSHAKE || level == LWS_QUIC_LEVEL_EARLY) {
			if (level == LWS_QUIC_LEVEL_INITIAL) {
                                if (qn->version == LWS_QUIC_VERSION_2)
                                        *p++ = 0xc0 | 0x10 | 0x01; /* v2 Initial */
                                else
                                        *p++ = 0xc0 | 0x00 | 0x01; /* v1 Initial */
                        } else if (level == LWS_QUIC_LEVEL_EARLY) {
                                if (qn->version == LWS_QUIC_VERSION_2)
                                        *p++ = 0xc0 | 0x20 | 0x01; /* v2 0-RTT */
                                else
                                        *p++ = 0xc0 | 0x10 | 0x01; /* v1 0-RTT */
                        } else {
                                if (qn->version == LWS_QUIC_VERSION_2)
                                        *p++ = 0xc0 | 0x30 | 0x01; /* v2 Handshake */
                                else
                                        *p++ = 0xc0 | 0x20 | 0x01; /* v1 Handshake */
                        }

			/* Version */
			*p++ = (uint8_t)(qn->version >> 24);
			*p++ = (uint8_t)(qn->version >> 16);
			*p++ = (uint8_t)(qn->version >> 8);
			*p++ = (uint8_t)(qn->version);
			/* DCID */
			*p++ = qn->rem_cid.len;
			if (qn->rem_cid.len) { memcpy(p, qn->rem_cid.id, qn->rem_cid.len); p += qn->rem_cid.len; }
			/* SCID */
			*p++ = qn->loc_cid.len;
			if (qn->loc_cid.len) { memcpy(p, qn->loc_cid.id, qn->loc_cid.len); p += qn->loc_cid.len; }

			if (level == LWS_QUIC_LEVEL_INITIAL) {
				/* Token Length */
				if (!qn->is_server && qn->retry_token_len > 0) {
					p += lws_quic_write_varint(p, max - (size_t)(p - buf), qn->retry_token_len);
					memcpy(p, qn->retry_token, qn->retry_token_len);
					p += qn->retry_token_len;
				} else {
					*p++ = 0x00;
				}
			}
			/* Length (2-byte varint, will fill in later) */
			*p++ = 0x40; *p++ = 0x00;

			pn_offset = (size_t)(p - buf);
			header_len = pn_offset + 2; /* 2-byte PN */
			p += 2; /* Skip PN bytes */
		} else {
			uint8_t sh = 0x40 | 0x01; /* Short Header, Fixed bit, 2-byte PN */
			if (qn->tx_key_phase)
				sh |= 0x04; /* Key Phase bit */
			*p++ = sh;
			/* DCID */
			if (qn->rem_cid.len) { memcpy(p, qn->rem_cid.id, qn->rem_cid.len); p += qn->rem_cid.len; }

			pn_offset = (size_t)(p - buf);
			header_len = pn_offset + 2;
			p += 2;
		}

		/*
		 * A PMTUD probe has a packet of its own, so where it is in the
		 * queue, it would wait until everything ahead of it was sent,
		 * and loss recovery keeps putting what was lost ahead of it.
		 * Behind a black hole, that is never: move it to the front.
		 */
		if (level == LWS_QUIC_LEVEL_APP &&
		    (qn->pmtud_probe_queued || qn->pmtud_bh_probe_queued ||
		     qn->pmtud_bh_from_probe_queued)) {
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					qn->pending_tx[level].head) {
				struct lws_quic_tx_frame *f =
					lws_container_of(d, struct lws_quic_tx_frame, list);
				if (f->pmtud_probe) {
					lws_dll2_remove(&f->list);
					lws_dll2_add_head(&f->list,
						&qn->pending_tx[level]);
					break;
				}
			} lws_end_foreach_dll_safe(d, d1);
		}

		/*
		 * If a path probe is pending, promote PATH_CHALLENGE to the
		 * very front of pending_tx so it is the first APP frame sent
		 * to the new address (QIR requires this for connectionmigration
		 * and rebind-addr tests).  This must happen before ACK
		 * generation below so that, on the server, the probe packet
		 * carries nothing but probing frames.
		 */
		if (level == LWS_QUIC_LEVEL_APP &&
		    qn->probing_sa46_valid && qn->path_challenge_pending) {
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					qn->pending_tx[level].head) {
				struct lws_quic_tx_frame *f =
					lws_container_of(d, struct lws_quic_tx_frame, list);
				if (f->type == LWS_QUIC_FT_PATH_CHALLENGE) {
					lws_dll2_remove(&f->list);
					lws_dll2_add_head(&f->list,
						&qn->pending_tx[level]);
					break;
				}
			} lws_end_foreach_dll_safe(d, d1);
		}

		/*
		 * Server-side path probing (RFC 9000 9.3): frames that carry
		 * their own destination are PATH_CHALLENGE / PATH_RESPONSE.
		 * When that destination is a peer address we have not validated
		 * yet, what we send there must stay within 3x the bytes we
		 * received from it (9.3.1 / 21.1.1.1), so clamp this packet's
		 * size to the remaining allowance and abandon the probe once
		 * even the smallest packet no longer fits.  Frames addressed to
		 * a path that is neither the committed one nor the one being
		 * probed are stale (the probe was abandoned or superseded) and
		 * are dropped rather than sent to an address we never validated.
		 */
		uint64_t probe_budget = 0;
		int to_probe_path = 0, has_path_challenge = 0;

		if (level == LWS_QUIC_LEVEL_APP && qn->is_server) {
			if (!ack_only && qn->probing_sa46_valid &&
			    qn->pending_tx[level].head) {
				struct lws_quic_tx_frame *first_f = lws_container_of(
					qn->pending_tx[level].head,
					struct lws_quic_tx_frame, list);

				if (first_f->has_dest &&
				    lws_quic_sa46_same_path(&first_f->dest_sa46,
							    &qn->probing_sa46)) {
					uint64_t allowance = 3 * qn->probe_bytes_received;
					size_t probe_min = header_len +
						LWS_QUIC_FRAME_HDR_MAX +
						LWS_QUIC_PATH_CHALLENGE_LEN +
						LWS_QUIC_FIT_SLACK;

					if (qn->probe_bytes_sent + probe_min >
								allowance) {
						lws_quic_path_probe_abandon(wsi,
							"anti-amplification "
							"limit reached");
					} else {
						probe_budget = allowance - qn->probe_bytes_sent;
						to_probe_path = 1;
						if (dgram_cap > probe_budget)
							dgram_cap = (size_t)probe_budget;
					}
				}
			}

			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					qn->pending_tx[level].head) {
				struct lws_quic_tx_frame *f =
					lws_container_of(d, struct lws_quic_tx_frame, list);

				if (f->has_dest &&
				    !lws_quic_sa46_same_path(&f->dest_sa46,
							     &qn->path_sa46) &&
				    (!qn->probing_sa46_valid ||
				     !lws_quic_sa46_same_path(&f->dest_sa46,
							      &qn->probing_sa46))) {
					lws_dll2_remove(&f->list);
					lws_free(f);
				}
			} lws_end_foreach_dll_safe(d, d1);
		}

		/* 1.5 Generate ACK frame if needed */
		int has_ack = 0;
		int skip_ack_for_dest = 0;
		if (!ack_only && qn->pending_tx[level].head) {
			struct lws_quic_tx_frame *first_f = lws_container_of(qn->pending_tx[level].head, struct lws_quic_tx_frame, list);
			if (first_f->has_dest) {
				/*
				 * Skip ACK for now, this packet will be
				 * dedicated to first_f's destination: the ACK
				 * goes in the next one, see
				 * lws_quic_packet_sent()
				 */
				skip_ack_for_dest = 1;
			}
		}
		tp->ack_skipped = (uint8_t)(ack_due && skip_ack_for_dest);
		if (ack_due && !skip_ack_for_dest) {
			/*
			 * ACK Delay (RFC 9000 §19.3): encoded in microseconds
			 * scaled by 2 ^ ack_delay_exponent.  We leave our
			 * exponent implicitly defaulted to 3 (we don't emit TP
			 * 0x0a), so divide by 8.  For App-space ACKs we report
			 * how long we actually held the ACK (so the peer can
			 * subtract it for RTT); Initial/Handshake ACKs are sent
			 * immediately so their delay is genuinely 0.
			 */
			uint8_t * const _ack_start = p;
			uint64_t ack_delay_enc = 0;

			tp->ack_since_us = 0;

			if (pn_space == LWS_QUIC_LEVEL_APP &&
			    qn->rx_ack_eliciting_since_us) {
				lws_usec_t held = lws_wsi_now(wsi) -
					qn->rx_ack_eliciting_since_us;
				if (held > 0)
					ack_delay_enc = (uint64_t)(held >> 3);
			}

                        if (qn->ecn_rx_ect0 || qn->ecn_rx_ect1 || qn->ecn_rx_ce) {
                                *p++ = 0x03; /* ACK_ECN */
                        } else {
                                *p++ = LWS_QUIC_FT_ACK; /* ACK (0x02) */
                        }
                        uint64_t ack_largest = qn->highest_rx_pn[pn_space];
                        uint64_t first_ack_range = 0, fi_ranges = 0;
                        unsigned int ack_bit = 0;
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
			/*
			 * quic_ack_ranges: every other ACK reports PNs only up
			 * to LWS_QUIC_FI_ACK_LAG below the largest we have, so
			 * the peer still has what it sent since in flight while
			 * it walks the ranges.  Then come one-PN ranges of PNs
			 * more than 64 below that, every other one down from
			 * there.  They are long settled, acked or found lost,
			 * so what the peer makes of them only costs it the work
			 */
			uint64_t fi_top = 0;
			int fi_ack = pn_space == LWS_QUIC_LEVEL_APP &&
				     lws_fi(&wsi->fic, "quic_ack_ranges");

			if (fi_ack) {
				qn->fi_ack_lag = !qn->fi_ack_lag;
				if (qn->fi_ack_lag &&
				    ack_largest > LWS_QUIC_FI_ACK_LAG &&
				    ((qn->rx_pn_bitmask[pn_space] >>
						LWS_QUIC_FI_ACK_LAG) & 1)) {
					ack_bit = LWS_QUIC_FI_ACK_LAG;
					ack_largest -= LWS_QUIC_FI_ACK_LAG;
				}
			}
#endif
                        uint64_t bm = qn->rx_pn_bitmask[pn_space] >> (ack_bit + 1);
                        while (ack_bit + first_ack_range < 63 && (bm & 1)) {
                                first_ack_range++;
                                bm >>= 1;
                        }
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
			if (fi_ack && ack_largest > 66) {
				fi_top = ack_largest - 66;
				fi_ranges = fi_top / 2 + 1;
				if (fi_ranges > LWS_QUIC_FI_ACK_RANGES)
					fi_ranges = LWS_QUIC_FI_ACK_RANGES;
			}
#endif
                        p += lws_quic_write_varint(p, max - (size_t)(p - buf), ack_largest); /* Largest Acknowledged */
                        p += lws_quic_write_varint(p, max - (size_t)(p - buf), ack_delay_enc); /* ACK Delay */
                        p += lws_quic_write_varint(p, max - (size_t)(p - buf), fi_ranges); /* ACK Range Count */
                        p += lws_quic_write_varint(p, max - (size_t)(p - buf), first_ack_range); /* First ACK Range */
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
			for (uint64_t r = 0; r < fi_ranges; r++) {
				/* gap: the PNs skipped, less one */
				p += lws_quic_write_varint(p, max - (size_t)(p - buf),
					r ? 0 : ack_largest - first_ack_range -
							fi_top - 2);
				p += lws_quic_write_varint(p, max - (size_t)(p - buf), 0);
			}
#endif

                        if (qn->ecn_rx_ect0 || qn->ecn_rx_ect1 || qn->ecn_rx_ce) {
                                p += lws_quic_write_varint(p, max - (size_t)(p - buf), qn->ecn_rx_ect0);
                                p += lws_quic_write_varint(p, max - (size_t)(p - buf), qn->ecn_rx_ect1);
                                p += lws_quic_write_varint(p, max - (size_t)(p - buf), qn->ecn_rx_ce);
                        }
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
			if (fi_ranges) {
				size_t al = (size_t)(p - _ack_start);

				for (int c = 1; c < LWS_QUIC_FI_ACK_COPIES; c++) {
					memcpy(p, _ack_start, al);
					p += al;
				}
			}
#endif

                        qn->needs_ack[pn_space] = 0;
			/*
			 * Reset the delayed-ACK coalescing state for App-space:
			 * the timer (if armed) is no longer needed and the
			 * 2nd-packet counter restarts from the next eliciting
			 * packet we receive.
			 */
			if (pn_space == LWS_QUIC_LEVEL_APP) {
				/* to owe it again if the socket refuses it */
				tp->ack_since_us = qn->rx_ack_eliciting_since_us;
				lws_sul_cancel(&qn->ack_delay_sul);
				qn->ack_delay_armed = 0;
				qn->rx_ack_eliciting_count = 0;
				qn->rx_ack_eliciting_since_us = 0;
			}
                        has_ack = 1;
			if (pn_space == LWS_QUIC_LEVEL_APP) {
				struct lws_quic_tx_frame _ackfake;
				memset(&_ackfake, 0, sizeof(_ackfake));
				_ackfake.type = (qn->ecn_rx_ect0 || qn->ecn_rx_ect1 ||
						 qn->ecn_rx_ce) ? LWS_QUIC_FT_ACK_ECN
								: LWS_QUIC_FT_ACK;
				_ackfake.len = (uint64_t)(p - _ack_start);
				lws_quic_dbg_1rtt_account(qn, &_ackfake, "ack-emit");
			}
		}

		/*
		 * 2. Bundle frames from pending_tx until MTU is reached, unless
		 * congestion control holds them back and only the ACK goes
		 */
		uint8_t * const p_frames = p;
		int pmtud_probe = 0;

		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				ack_only ? NULL : qn->pending_tx[level].head) {
			struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);

			if (has_packet_dest) {
				if (!f->has_dest) {
					d = d1;
					continue;
				}
				/* Compare f->dest_sa46 with packet_dest_sa46 */
				int match = 0;
				if (packet_dest_sa46.sa4.sin_family == f->dest_sa46.sa4.sin_family) {
					if (packet_dest_sa46.sa4.sin_family == AF_INET) {
						if (packet_dest_sa46.sa4.sin_addr.s_addr == f->dest_sa46.sa4.sin_addr.s_addr &&
						    packet_dest_sa46.sa4.sin_port == f->dest_sa46.sa4.sin_port)
							match = 1;
					}
#if defined(LWS_WITH_IPV6)
					else if (packet_dest_sa46.sa6.sin6_family == AF_INET6) {
						if (!lws_sa46_compare_sin6_addr(&packet_dest_sa46.sa6.sin6_addr,
										&f->dest_sa46.sa6.sin6_addr) &&
						    packet_dest_sa46.sa6.sin6_port == f->dest_sa46.sa6.sin6_port)
							match = 1;
					}
#endif
				}
				if (!match) {
					d = d1;
					continue;
				}
			} else if (f->has_dest) {
				/*
				 * A frame with its own destination only ever
				 * starts a packet, where the probe path clamp
				 * above sized the whole packet for that
				 * destination.  One that lost its place at the
				 * head (requeued after loss, or behind frames
				 * added at the head) waits until it is back
				 * there: otherwise the frames bundled ahead of
				 * it would go with it to an address that may
				 * not be validated, uncharged against its 3x
				 * allowance (RFC 9000 9.3.1, 21.1.1.1).
				 */
				if ((size_t)(p - buf) != header_len) {
					d = d1;
					continue;
				}
				packet_dest_sa46 = f->dest_sa46;
				has_packet_dest = 1;
			}

			/*
			 * A PMTUD probe's PING has a packet of its own, but
			 * for an ACK, so it waits for one that has nothing
			 * else in it yet
			 */
			if (f->pmtud_probe && p != p_frames) {
				d = d1;
				continue;
			}

			/* Check if frame fits in remaining MTU (leaving room for headers and 16-byte AEAD tag) */
			size_t frame_header_max_len = LWS_QUIC_FRAME_HDR_MAX;
			size_t max_udp_payload = mtu > 48 ? mtu - 48 : 1200;
			if (max_udp_payload > 1200 && !qn->handshake_done) max_udp_payload = 1200; /* RFC 9000 Section 14.1 */
			if (max_udp_payload > dgram_cap) max_udp_payload = dgram_cap;

			if ((size_t)(p - buf) + frame_header_max_len + LWS_QUIC_FIT_SLACK >= max_udp_payload)
				break;

			size_t send_len = f->len;

			if ((size_t)(p - buf) + frame_header_max_len + send_len + LWS_QUIC_FIT_SLACK > max_udp_payload) {
				if ((f->type & 0xf8) == LWS_QUIC_FT_STREAM || f->type == LWS_QUIC_FT_CRYPTO) {
					send_len = max_udp_payload - (size_t)(p - buf) - frame_header_max_len - LWS_QUIC_FIT_SLACK;
				} else if ((f->type & 0xfe) == LWS_QUIC_FT_DATAGRAM &&
					   f->len > lws_quic_datagram_max(qn)) {
					/*
					 * The path MTU fell since it was
					 * queued: no packet can carry it now,
					 * and it must not hold up what is
					 * behind it.  RFC 9221 5 lets a
					 * DATAGRAM be dropped.
					 */
					lws_dll2_remove(&f->list);
					lws_free(f);
					d = d1;
					continue;
				} else {
					break; /* Non-fragmentable frame doesn't fit */
				}
			}
			if (send_len == 0 && f->len > 0)
				break;

			/* Serialize the frame type */
			uint8_t type = f->type;
			if (send_len < f->len && (type & 0xf8) == LWS_QUIC_FT_STREAM) {
				type &= 0xfe; /* Clear FIN bit for intermediate fragment */
			}
			if (type == LWS_QUIC_FT_PATH_CHALLENGE)
				has_path_challenge = 1;
			*p++ = type;

			/* Serialize frame-specific headers */
			if (type == LWS_QUIC_FT_PING) {
				/* PING has no payload or additional headers */
			} else if (type == LWS_QUIC_FT_CRYPTO) {
				p += lws_quic_write_varint(p, max - (size_t)(p - buf), f->offset);
				p += lws_quic_write_varint(p, max - (size_t)(p - buf), send_len);
			} else if ((type & 0xf8) == LWS_QUIC_FT_STREAM) {
				/* Stream ID */
                                p += lws_quic_write_varint(p, max - (size_t)(p - buf), f->stream_id);
				if (type & 0x04) /* OFF */
					p += lws_quic_write_varint(p, max - (size_t)(p - buf), f->offset);
				if (type & 0x02) /* LEN */
					p += lws_quic_write_varint(p, max - (size_t)(p - buf), send_len);
			} else if ((type & 0xfe) == LWS_QUIC_FT_DATAGRAM) {
				if (type & 0x01) /* LEN */
					p += lws_quic_write_varint(p, max - (size_t)(p - buf), send_len);
			} else if (type == LWS_QUIC_FT_DATA_BLOCKED) {
				p += lws_quic_write_varint(p, max - (size_t)(p - buf), f->limit);
			} else if (type == LWS_QUIC_FT_MAX_DATA) {
				p += lws_quic_write_varint(p, max - (size_t)(p - buf),
					lws_quic_fi_window(wsi, "quic_max_data", f->limit));
			} else if (type == LWS_QUIC_FT_MAX_STREAM_DATA || type == LWS_QUIC_FT_STREAM_DATA_BLOCKED) {
                                p += lws_quic_write_varint(p, max - (size_t)(p - buf), f->stream_id);
				p += lws_quic_write_varint(p, max - (size_t)(p - buf),
					type == LWS_QUIC_FT_STREAM_DATA_BLOCKED ? f->limit :
					lws_quic_fi_window(wsi, "quic_max_data", f->limit));
			} else if (type == LWS_QUIC_FT_RESET_STREAM) {
                                p += lws_quic_write_varint(p, max - (size_t)(p - buf), f->stream_id);
				p += lws_quic_write_varint(p, max - (size_t)(p - buf), f->offset); /* app_err_code */
				p += lws_quic_write_varint(p, max - (size_t)(p - buf), f->limit); /* final_size */
			} else if (type == LWS_QUIC_FT_STOP_SENDING ||
				   type == LWS_QUIC_FT_NEW_CONNECTION_ID) {
				/*
				 * STOP_SENDING: stream_id, app_err_code
				 * NEW_CONNECTION_ID: seq, retire_prior_to, then
				 * the cid + token ride in data
				 */
                                p += lws_quic_write_varint(p, max - (size_t)(p - buf), f->stream_id);
				p += lws_quic_write_varint(p, max - (size_t)(p - buf), f->offset);
			} else if (type == LWS_QUIC_FT_MAX_STREAMS_BIDI || type == LWS_QUIC_FT_MAX_STREAMS_UNIDI ||
				   type == LWS_QUIC_FT_STREAMS_BLOCKED_BIDI || type == LWS_QUIC_FT_STREAMS_BLOCKED_UNIDI) {
				p += lws_quic_write_varint(p, max - (size_t)(p - buf), f->limit);
				/*
				 * Going out: the peer may open streams up to
				 * it from now, and not before
				 */
				if (type == LWS_QUIC_FT_MAX_STREAMS_BIDI &&
				    f->limit > qn->max_streams_bidi_adv)
					qn->max_streams_bidi_adv = f->limit;
				if (type == LWS_QUIC_FT_MAX_STREAMS_UNIDI &&
				    f->limit > qn->max_streams_unidi_adv)
					qn->max_streams_unidi_adv = f->limit;
			} else if (type == LWS_QUIC_FT_RETIRE_CONNECTION_ID) {
                                p += lws_quic_write_varint(p, max - (size_t)(p - buf), f->stream_id); /* seq */
			}

			if (send_len) {
				memcpy(p, f->data, send_len);
				p += send_len;
			}

			if (send_len < f->len) {
				/* Fragmentation! Duplicate into in_flight */
				struct lws_quic_tx_frame *f_sent = lws_malloc(sizeof(*f_sent) + send_len, "quic tx frag");
				if (!f_sent)
					return LWS_TX_FAIL;
				*f_sent = *f;
				lws_dll2_clear(&f_sent->list);
				f_sent->len = send_len;
				f_sent->data = (uint8_t *)&f_sent[1];
				memcpy(f_sent->data, f->data, send_len);

				f_sent->sent_in_pn = my_pn;
				f_sent->sent_time_us = lws_wsi_now(wsi);
				if (!f_sent->first_sent_us)
					f_sent->first_sent_us = f_sent->sent_time_us;
				f_sent->wire_len = 0;

				/* Clear the FIN bit from intermediate fragment */
				if ((f_sent->type & 0xf8) == LWS_QUIC_FT_STREAM)
					f_sent->type &= 0xfe;

				lws_dll2_add_tail(&f_sent->list, &qn->in_flight[level]);


				/* Update original f in pending_tx */
				f->offset += send_len;
				f->len -= send_len;
				f->data += send_len;

				/* Schedule PTO timer since we have data in-flight */
				lws_quic_sul_schedule(qn, &qn->pto_sul,
						      lws_quic_pto_cb, pto_delay);

				break; /* We filled the MTU */
			} else {
				/* Sent entirely */
				lws_dll2_remove(&f->list);
				f->sent_in_pn = my_pn;
				f->sent_time_us = lws_wsi_now(wsi);
				if (!f->first_sent_us)
					f->first_sent_us = f->sent_time_us;
				f->wire_len = 0;
				lws_dll2_add_tail(&f->list, &qn->in_flight[level]);

				/* Schedule PTO timer since we have data in-flight */
				lws_quic_sul_schedule(qn, &qn->pto_sul,
						      lws_quic_pto_cb, pto_delay);

				if (f->pmtud_probe) {
					/* nothing else joins it */
					if (f->pmtud_probe ==
						LWS_QUIC_PMTUD_PROBE_BASE)
						qn->pmtud_bh_probe_queued = 0;
					else if (f->pmtud_probe ==
						LWS_QUIC_PMTUD_PROBE_FROM)
						qn->pmtud_bh_from_probe_queued = 0;
					else
						qn->pmtud_probe_queued = 0;
					pmtud_probe = f->pmtud_probe;
					break;
				}
			}

		} lws_end_foreach_dll_safe(d, d1);

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
		/*
		 * quic_path_challenge_flood: a packet with frames in it gets a
		 * run of PATH_CHALLENGEs as well, if there is room, for the
		 * peer to answer.  Not ACK-only packets, nor ones dedicated to
		 * the peer's answers: those would elicit more challenges for
		 * ever
		 */
		if (level == LWS_QUIC_LEVEL_APP && qn->handshake_done &&
		    p != p_frames && !has_packet_dest &&
		    (size_t)(p - buf) + LWS_QUIC_FI_PATH_CHALLENGES *
				(1 + LWS_QUIC_PATH_CHALLENGE_LEN) +
				LWS_QUIC_FIT_SLACK <=
				(mtu > 48 && mtu - 48 < dgram_cap ?
						mtu - 48 : dgram_cap) &&
		    lws_fi(&wsi->fic, "quic_path_challenge_flood"))
			for (int c = 0; c < LWS_QUIC_FI_PATH_CHALLENGES; c++) {
				*p++ = LWS_QUIC_FT_PATH_CHALLENGE;
				if (lws_get_random(wsi->a.context, p,
					   LWS_QUIC_PATH_CHALLENGE_LEN) !=
					   LWS_QUIC_PATH_CHALLENGE_LEN)
					memset(p, c, LWS_QUIC_PATH_CHALLENGE_LEN);
				p += LWS_QUIC_PATH_CHALLENGE_LEN;
			}

		/* frames that went although congestion control held them */
		if (cc_held && p != p_frames)
			qn->fi_stats.cc_bypassed++;
		{
			uint32_t fl = lws_quic_in_flight_count(qn);

			if (fl > qn->fi_stats.in_flight_peak)
				qn->fi_stats.in_flight_peak = fl;
		}
#endif

		size_t payload_len = (size_t)(p - (buf + header_len));
		if (payload_len == 0 && !has_ack)
			continue;

		/* Ensure payload is at least 4 bytes for header protection sampling (RFC 9000 Section 5.4.2) */
		if (payload_len < 4) {
			memset(p, LWS_QUIC_FT_PADDING, 4 - payload_len);
			p += (4 - payload_len);
			payload_len = 4;
		}

		/* pad out to 1200 minimum total tx length for client initial */
		if (level == LWS_QUIC_LEVEL_INITIAL && !qn->is_server) {
			size_t target_payload_len = 1200 - header_len - 16;

			/* never past the buffer IO handed us (small serv_buf) */
			if (target_payload_len > max - header_len - 16)
				target_payload_len = max - header_len - 16;
			if (payload_len < target_payload_len) {
				memset(p, LWS_QUIC_FT_PADDING, target_payload_len - payload_len);
				p += (target_payload_len - payload_len);
				payload_len = target_payload_len;
			}
		}

		/*
		 * PMTUD: the packet with a probe's PING is padded out to the
		 * datagram size being probed, or for a black hole check, the
		 * base, then the size from before it.  If we can't send one
		 * that big anyway, there is nothing to find out, and the
		 * search is over.  If a server's peer moved since the probe was
		 * queued, the new path isn't validated, so it only gets a plain
		 * PING, and the search goes on there with the first ack after
		 * it is.  So does a search probe queued before a black hole
		 * stopped the search, and a probe confirming a black hole that
		 * was settled meanwhile.
		 */
		if (pmtud_probe && !(qn->is_server && !qn->address_validated)) {
			uint64_t *probe_pn = NULL;
			uint32_t mtu_probed = 0;

			switch (pmtud_probe) {
			case LWS_QUIC_PMTUD_PROBE_BASE:
				mtu_probed = LWS_QUIC_PMTU_BASE;
				probe_pn = &qn->pmtud_bh_probe_pn;
				break;
			case LWS_QUIC_PMTUD_PROBE_FROM:
				if (!qn->pmtud_bh_from_mtu)
					break;
				mtu_probed = qn->pmtud_bh_from_mtu;
				probe_pn = &qn->pmtud_bh_from_probe_pn;
				break;
			default:
				if (qn->pmtud_state != 1)
					break;
				mtu_probed = qn->probed_mtu;
				probe_pn = &qn->pmtud_probe_pn;
				break;
			}

			if (probe_pn) {
				size_t target = mtu_probed -
						LWS_QUIC_PMTU_OVERHEAD;

				if (target > max) {
					if (pmtud_probe ==
						LWS_QUIC_PMTUD_PROBE_SEARCH)
						qn->pmtud_state = 2; /* SEARCH_COMPLETE */
				} else {
					if (header_len + payload_len + 16 <
								target) {
						size_t pad = target -
							header_len -
							payload_len - 16;

						memset(p, LWS_QUIC_FT_PADDING,
						       pad);
						p += pad;
						payload_len += pad;
					}
					*probe_pn = my_pn;
				}
			}
		}

		/*
		 * RFC 9000 8.2.1: a datagram carrying PATH_CHALLENGE is expanded
		 * to 1200 bytes so validation also proves the new path can carry
		 * a minimum-MTU datagram, but only as far as the unvalidated
		 * path's anti-amplification allowance permits.
		 */
		if (to_probe_path && has_path_challenge) {
			size_t target = 1200;

			if (target > probe_budget)
				target = (size_t)probe_budget;
			if (target > max)
				target = max;
			if (target > header_len + 16 &&
			    payload_len < target - header_len - 16) {
				size_t target_payload_len = target - header_len - 16;

				memset(p, LWS_QUIC_FT_PADDING, target_payload_len - payload_len);
				p += (target_payload_len - payload_len);
				payload_len = target_payload_len;
			}
		}

		/* Fill in Length for Initial/Handshake/0-RTT packets */
		if (level == LWS_QUIC_LEVEL_INITIAL || level == LWS_QUIC_LEVEL_HANDSHAKE || level == LWS_QUIC_LEVEL_EARLY) {
			uint16_t quic_len = (uint16_t)(payload_len + 2 + 16); /* PN (2) + AEAD Tag (16) */
			uint8_t *len_ptr = buf + pn_offset - 2;
			len_ptr[0] = (uint8_t)(0x40 | ((quic_len >> 8) & 0x3F));
			len_ptr[1] = (uint8_t)(quic_len & 0xFF);
		}

		/* Fill in Packet Number */
		buf[pn_offset]     = (uint8_t)((my_pn >> 8) & 0xFF);
		buf[pn_offset + 1] = (uint8_t)(my_pn & 0xFF);

		/* 3. Encrypt payload and mask header */
		n = lws_quic_encrypt_payload(qn->keys[level], buf, (size_t)(p - buf), pn_offset, 2, my_pn);
		if (n < 0) {
			lwsl_wsi_warn(wsi, "QUIC TX: Payload encryption failed");
			return LWS_TX_FAIL;
		}

		if (level == LWS_QUIC_LEVEL_APP)
			qn->tx_packets_since_update++;

		/* 4. Transmit UDP Datagram */

		size_t send_len = (size_t)(p - buf) + 16;

		/* PMTUD: tag in-flight frames with this packet's wire length so we can track MTU losses */
		lws_start_foreach_dll_back(struct lws_dll2 *, d,
					   lws_dll2_get_tail(&qn->in_flight[level])) {
			struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);

			if (f->sent_in_pn != my_pn)
				break;

			f->packet_size = (uint16_t)send_len;
		} lws_end_foreach_dll_back(d);


		/* which peer the packet goes to: sansIO's decision */
		tp->has_dest = 0;
		{
			struct lws *nwsi_quic = lws_get_quic_network_wsi(wsi);
			int is_client = nwsi_quic ? lwsi_role_client(nwsi_quic) :
						    lwsi_role_client(wsi);

			if (!is_client) {
				if (has_packet_dest) {
					tp->dest = packet_dest_sa46;
					tp->has_dest = 1;
				} else if (wsi->quic.qn) {
					tp->dest = wsi->quic.qn->path_sa46;
					tp->has_dest = 1;
				} else if (wsi->mux_substream && wsi->mux.parent_wsi &&
					   wsi->mux.parent_wsi->quic.qn) {
					tp->dest = wsi->mux.parent_wsi->quic.qn->path_sa46;
					tp->has_dest = 1;
				}
			}
		}

		tp->level = level;
		tp->pn = my_pn;
		tp->len = send_len;
		tp->to_probe_path = (uint8_t)to_probe_path;
		tp->has_ack = (uint8_t)has_ack;

		return (int)send_len;
	}

	return 0;
}

/*
 * The packet's bytes went to IO.  n is what it took, or
 * LWS_SSL_CAPABLE_MORE_SERVICE_WRITE when the transport could not take it
 * now: its frames go back to pending, to be sent first next time under the
 * same packet number, and sending stops for this pass; the OS wakes us with
 * POLLOUT when the socket drains.  Returns 0 to go on, 1 to stop sending for
 * now, -1 when the write failed.
 */
static int
lws_quic_packet_sent(struct lws *wsi, const struct lws_quic_tx_pkt *tp, int n)
{
	struct lws_quic_netconn *qn = wsi->quic.qn;

	if (n < 0) {
		if (n == LWS_SSL_CAPABLE_MORE_SERVICE_WRITE) {
			lwsl_wsi_info(wsi, "QUIC TX: transport cannot take the datagram now, pausing send");
			
			/* 
			 * The OS UDP socket buffer is full. We cannot send this packet.
			 * We MUST NOT pretend it was sent, because it would move to in_flight
			 * and wait for a PTO timer to retransmit, causing massive stalls.
			 * Instead, we keep the frames in pending_tx, and stop sending.
			 * The OS will wake us up with POLLOUT when the socket drains.
			 */
			struct lws_dll2 *d = qn->in_flight[tp->level].tail;
			while (d) {
				struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);
				if (f->sent_in_pn == tp->pn) {
					struct lws_dll2 *prev = lws_dll2_get_prev(d);
					lws_dll2_remove(d);
					/* before its pn goes */
					lws_quic_pmtud_probe_unsent(qn, f);
					f->sent_in_pn = 0;
					f->sent_time_us = 0;
					f->wire_len = 0;
					/* Push to head so it is sent first next time */
					lws_dll2_add_head(&f->list, &qn->pending_tx[tp->level]);
					d = prev;
				} else {
					break;
				}
			}
			
			/* Revert PN */
			qn->keys[tp->level]->pn_tx--;

			/*
			 * The ACK in it wasn't sent either.  It's no frame to go
			 * back to pending, but it is still owed: built, it was
			 * taken for sent, and waiting for the next thing the
			 * peer elicits one with, the peer may meanwhile take
			 * what it sent for lost
			 */
			if (tp->has_ack) {
				int space = tp->level == LWS_QUIC_LEVEL_EARLY ?
						LWS_QUIC_LEVEL_APP : tp->level;

				qn->needs_ack[space] = 1;
				if (space == LWS_QUIC_LEVEL_APP &&
				    !qn->rx_ack_eliciting_since_us)
					qn->rx_ack_eliciting_since_us =
							tp->ack_since_us;
			}
			
			/* the caller keeps POLLOUT: the transport wakes us */
			return 1;
		} else {
			struct lws_dll2 *d = qn->in_flight[tp->level].tail;

			/*
			 * A PMTUD probe can be too big for our own interface,
			 * eg, a tunnel's, which with Don't Fragment the OS
			 * refuses to send: it's lost, now.  Only the probe is:
			 * an ACK that went with it is still owed, and what is
			 * waiting behind it must still go, so ask to write
			 * again, as a sent packet would.  Nothing else may come
			 * along to wake us, eg, a close frame waiting behind
			 * the probe would only go at the close timeout.
			 */
			if (d) {
				struct lws_quic_tx_frame *f = lws_container_of(d,
						struct lws_quic_tx_frame, list);

				if (f->sent_in_pn == tp->pn && f->pmtud_probe) {
					lwsl_wsi_info(wsi, "QUIC TX: PMTUD probe "
						      "of %u not sent",
						      (unsigned int)tp->len);
					lws_quic_pmtud_probe_lost(qn, f);
					lws_dll2_remove(d);
					lws_free(f);

					qn->needs_ack[LWS_QUIC_LEVEL_APP] = 1;
					lws_callback_on_writable(wsi);

					return -1;
				}
			}

			lwsl_wsi_err(wsi, "QUIC TX: write failed");
			return -1;
		}
	}

	qn->bytes_sent += (uint64_t)n;
	if (tp->to_probe_path)
		qn->probe_bytes_sent += (uint64_t)n;

	/* Find the first frame we sent in this packet to attach wire_len to */
	int ack_eliciting = 0;
	if (qn->in_flight[tp->level].tail) {
		/* Start from the end, which is the most recently added frame */
		lws_start_foreach_dll(struct lws_dll2 *, d, qn->in_flight[tp->level].tail) {
			struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);
			if (f->sent_in_pn == tp->pn) {
				f->wire_len = tp->len;
				ack_eliciting = 1;
				break;
			}
			/* If we find a different PN, we didn't add any frames for this packet */
			if (f->sent_in_pn != tp->pn)
				break;
		} lws_end_foreach_dll(d);
	}

	if (ack_eliciting) {
		lws_quic_idle_restart(qn, 1);
		if (qn->pto_probe_needed > 0)
			qn->pto_probe_needed--;
		if (qn->cc_ops && qn->cc_ops->on_sent)
			qn->cc_ops->on_sent(wsi, tp->len);
	}

	/*
	 * If we still have pending frames we couldn't fit, or an ACK we owe
	 * did not go in a packet dedicated to another destination, request
	 * another POLLOUT
	 */
	if (qn->pending_tx[tp->level].count || tp->ack_skipped) {
		lws_callback_on_writable(wsi);
	}
            
	/*
	 * If we successfully sent application-level data, the pending_tx buffer
	 * has shrunk. We MUST wake up the child streams because they may have
	 * been stalled by the application-layer pacing throttle in tx_credit!
	 */
	if (tp->level == LWS_QUIC_LEVEL_APP) {
		lws_start_foreach_dll(struct lws_dll2 *, d,
				lws_dll2_get_head(&wsi->mux.child_list_owner)) {
			struct lws *w = lws_container_of(d, struct lws,
							 mux.sibling_list);
			if (w->mux.requested_POLLOUT)
				lws_callback_on_writable(w);
		}
		lws_end_foreach_dll(d);
	}

	return 0;
}

/*
 * One connection's next packet this tx pass (README.sans-io-split.md, "A
 * content source's tx"): one per encryption level per pass, Initial >
 * Handshake > Application, into IO's buffer sized to the path MTU.  first
 * starts the connection's pass.
 */
static int
lws_quic_conn_tx(struct lws *nwsi, uint8_t *buf, size_t max,
		 lws_sockaddr46 *dest, int first)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	int n;

	if (first) {
		/*
		 * The pass that serves the connection's request to write starts
		 * here, so it is consumed here: a re-arm from what the pass
		 * does next (frames that did not fit, a stream's next write)
		 * must stand, or the listener's next pull passes us over.
		 */
		nwsi->mux.requested_POLLOUT = 0;
		qn->tx_level = 0;
		qn->tx_held = 0;
		qn->tx_full = 0;
		qn->tx_failed = 0;
	}

	if (qn->tx_failed || qn->tx_level >= LWS_QUIC_LEVEL_COUNT)
		return 0;

	qn->tx_pkt.level = qn->tx_level;
	n = lws_quic_packet_tx(nwsi, buf, max, &qn->tx_pkt);
	switch (n) {
	case 0:
		break;
	case LWS_TX_WAIT:
		qn->tx_held = 1;
		break;
	case LWS_TX_FAIL:
		qn->tx_failed = 1;
		break;
	default:
		if (qn->tx_pkt.has_dest)
			*dest = qn->tx_pkt.dest;
		break;
	}

	return n;
}

/* how IO's send of the connection's packet went: 1 = the transport is full */
static int
lws_quic_conn_tx_sent(struct lws *nwsi, int n)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	int m = lws_quic_packet_sent(nwsi, &qn->tx_pkt, n);

	if (m < 0) {
		qn->tx_failed = 1;
		return 0;
	}
	if (m > 0) {
		qn->tx_full = 1;
		return 1;
	}

	qn->tx_level = qn->tx_pkt.level + 1;

	return 0;
}

/*
 * tx: IO pulls the next datagram of the socket wsi owns.  A client's
 * connection owns its socket.  A listener's connections share its socket:
 * its own replies go first, then its connections that asked to write, each
 * taken until it has nothing more this pass.
 */
static int
rops_tx_quic(struct lws *wsi, uint8_t *buf, size_t max,
		   lws_sockaddr46 *dest, int first)
{
	struct lws_dll2 *d;
	int n;

	if (wsi->quic.qn) {
		n = lws_quic_conn_tx(wsi, buf, max, dest, first);

		/* a failed packet ends our pass, not the connection */
		return n == LWS_TX_FAIL ? 0 : n;
	}

	if (first) {
		wsi->quic.tx_cur = NULL;
		lws_start_foreach_dll(struct lws_dll2 *, d1,
				lws_dll2_get_head(&wsi->mux.child_list_owner)) {
			struct lws *w = lws_container_of(d1, struct lws,
							 mux.sibling_list);
			if (w->quic.qn)
				w->quic.qn->tx_in_pass = 0;
		} lws_end_foreach_dll(d1);
	}

	d = lws_dll2_get_head(&wsi->quic.tx_replies);
	if (d) {
		struct lws_quic_reply *r = lws_container_of(d,
					struct lws_quic_reply, list);

		if (r->len <= max) {
			memcpy(buf, &r[1], r->len);
			*dest = r->dest;
			wsi->quic.tx_is_reply = 1;

			return (int)r->len;
		}

		/* cannot be: they are small */
		lws_dll2_remove(&r->list);
		lws_free(r);
	}

	d = wsi->quic.tx_cur ? &wsi->quic.tx_cur->mux.sibling_list :
			       lws_dll2_get_head(&wsi->mux.child_list_owner);
	while (d) {
		struct lws *w = lws_container_of(d, struct lws,
						 mux.sibling_list);
		int f = 0;

		d = d->next;
		if (!w->quic.qn || !w->mux.requested_POLLOUT)
			continue;

		if (!w->quic.qn->tx_in_pass) {
			w->quic.qn->tx_in_pass = 1;
			f = 1;
		}

		n = lws_quic_conn_tx(w, buf, max, dest, f);
		if (n > 0) {
			wsi->quic.tx_cur = w;
			return n;
		}
		/* nothing more from w this pass: on to the next */
	}

	wsi->quic.tx_cur = NULL;

	return 0;
}

static int
rops_tx_sent_quic(struct lws *wsi, int n)
{
	if (wsi->quic.qn)
		return lws_quic_conn_tx_sent(wsi, n);

	if (wsi->quic.tx_is_reply) {
		struct lws_dll2 *d = lws_dll2_get_head(&wsi->quic.tx_replies);

		/* sent or not, a reply is not kept */
		wsi->quic.tx_is_reply = 0;
		if (d) {
			lws_dll2_remove(d);
			lws_free(lws_container_of(d, struct lws_quic_reply,
						  list));
		}

		return n == LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
	}

	if (!wsi->quic.tx_cur || !lws_quic_conn_tx_sent(wsi->quic.tx_cur, n))
		return 0;

	/*
	 * The socket is full for all of them: the connections the pass did
	 * not reach hear it too, and keep asking to write
	 */
	lws_start_foreach_dll(struct lws_dll2 *, d1,
			lws_dll2_get_head(&wsi->mux.child_list_owner)) {
		struct lws *w = lws_container_of(d1, struct lws,
						 mux.sibling_list);
		if (w->quic.qn && w->mux.requested_POLLOUT)
			w->quic.qn->tx_full = 1;
	} lws_end_foreach_dll(d1);

	return 1;
}

static lws_handling_result_t
rops_handle_POLLOUT_quic(struct lws *wsi)
{
	struct lws_quic_netconn *qn = wsi->quic.qn;
	int level, blocked, eagain_blocked;

	if (!qn) {
		lws_handling_result_t hr_ret = LWS_HP_RET_DROP_POLLOUT;

		/*
		 * The listener's pass: each connection the tx pulled this pass,
		 * or that still asks to write (the pull did not reach it), has
		 * its streams serviced.  The pull already consumed the request
		 * of those it reached; what re-armed since stays armed.
		 */
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				lws_dll2_get_head(&wsi->mux.child_list_owner)) {
			struct lws *w = lws_container_of(d, struct lws,
							 mux.sibling_list);
			if (w->mux.requested_POLLOUT ||
			    (w->quic.qn && w->quic.qn->tx_in_pass)) {
				lws_handling_result_t hr_child = rops_handle_POLLOUT_quic(w);
				if (hr_child == LWS_HP_RET_BAIL_DIE)
					return LWS_HP_RET_BAIL_DIE;
				if (hr_child == LWS_HP_RET_BAIL_OK)
					hr_ret = LWS_HP_RET_BAIL_OK;
			}
		} lws_end_foreach_dll_safe(d, d1);
		return hr_ret;
	}

	if (qn->tx_failed)
		/* producing or sending failed: nothing more this pass */
		return LWS_HP_RET_BAIL_OK;

	/* how IO's tx pull went for us, just before this pass */
	blocked = qn->tx_held || qn->tx_full;
	eagain_blocked = qn->tx_full;

	/* If we handled all pending crypto/internal frames, give the user a chance to write */
	struct lws *nwsi = lws_get_quic_network_wsi(wsi);
	/* Process stream queues for Application (1-RTT) and Early (0-RTT) data */
	if (qn->handshake_done ||
	    qn->early_data_status == LWS_0RTT_STATUS_ATTEMPTED ||
	    qn->early_data_status == LWS_0RTT_STATUS_ACCEPTED) {
		if (lws_wsi_txc_check_skint(&wsi->txc, (int32_t)wsi->txc.tx_cr))
			goto end_children;
		if (nwsi && lws_wsi_txc_check_skint(&nwsi->txc, (int32_t)nwsi->txc.tx_cr))
			goto end_children;

		/*
		 * Fair-share POLLOUT service, forward walk.  We visit each child
		 * once per pass; the lws_start_foreach_dll_safe iterator caches
		 * next before the body, so moving the current node to the tail
		 * (fair-share rotation) or removing it (close) is safe.  The
		 * rotation alone does not make the walk terminate: a serviced
		 * child goes behind the next one's cached next, so two children
		 * that re-arm on every visit (a file stream whose last frame is
		 * still in flight, and another whose HEADERS wait in pending_tx)
		 * alternate forever inside this one pass, and the connection's
		 * PTO never fires.  The bound is the count at pass start: every
		 * child then present is seen once, and nodes a callback adds or
		 * re-arms are picked up on a future pass.
		 *
		 * The connection-level credit guard is post-tested (first
		 * iteration skips it) so we always service at least one child
		 * per POLLOUT; per-stream throttling below (usable_credit and
		 * lws_wsi_txc_check_skint) still breaks/re-arms correctly.
		 */
		int first_iteration = 1,
		    remaining = (int)wsi->mux.child_list_owner.count;
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				lws_dll2_get_head(&wsi->mux.child_list_owner)) {
			struct lws *w = lws_container_of(d, struct lws,
							 mux.sibling_list);

			if (remaining-- <= 0)
				break;

			if (!first_iteration &&
			    (wsi->txc.tx_cr <= 0 ||
			     (nwsi && nwsi->txc.tx_cr <= 0)))
				break;
			first_iteration = 0;

			if (!w->mux.requested_POLLOUT)
				continue;	/* not interested; leave in place */

			/* fair-share: move this child to the tail before servicing.
			 * The cached d1 (next) stays valid across the relocate. */
			lws_dll2_remove(&w->mux.sibling_list);
			lws_dll2_add_tail(&w->mux.sibling_list,
					  &wsi->mux.child_list_owner);

			int is_peer_initiated = (w->mux.my_sid & 1) != (qn->is_server ? 1 : 0);
			int is_unidiri = (w->mux.my_sid & 2);
			if (is_peer_initiated && is_unidiri) {
				w->mux.requested_POLLOUT = 0;
				continue;
			}

			int32_t usable_credit = w->txc.tx_cr;
			if (lws_rops_fidx(w->role_ops, LWS_ROPS_tx_credit)) {
				usable_credit = lws_rops_func_fidx(w->role_ops, LWS_ROPS_tx_credit).
							tx_credit(w, LWSTXCR_US_TO_PEER, 0);
			}

			/* Check for actual flow control exhaustion */
			if (lws_wsi_txc_check_skint(&w->txc, w->txc.tx_cr)) {
				if (!w->quic.tx_blocked_sent) {
					struct lws_quic_tx_frame *f_sdb = lws_zalloc(sizeof(*f_sdb), "quic sdb");
					if (f_sdb) {
						f_sdb->type = LWS_QUIC_FT_STREAM_DATA_BLOCKED;
						f_sdb->stream_id = w->mux.my_sid;
						f_sdb->limit = w->quic.qs ? w->quic.qs->tx_offset : 0;
						lws_quic_dbg_1rtt_account(qn, f_sdb, "stream-data-blocked-fairshare");
						lws_dll2_add_head(&f_sdb->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
					}
					w->quic.tx_blocked_sent = 1;
					lws_callback_on_writable(wsi);
				}
				if (!lwsi_flushing_to_close(w)) {
					w->mux.requested_POLLOUT = 0;
					continue;
				}
			}

			/* Check for local throttling (e.g., pending_tx queue full) */
			if (usable_credit <= 0 && !lwsi_flushing_to_close(w)) {
				w->mux.requested_POLLOUT = 1;
				break;
			}

			w->mux.requested_POLLOUT = 0;

#if defined(LWS_ROLE_WS)
			/*
			 * ws over h3 (RFC 9220): what the ws role owes the peer
			 * itself, its close, its answer to the peer's, a ping
			 * or pong, goes before the app hears it may write
			 */
			if (lwsi_role_ws(w)) {
				int r = lws_ws_mux_child_pollout(w);

				if (r < 0) {
					if (!lws_dll2_is_detached(&w->mux.sibling_list))
						lws_close_free_wsi(w, LWS_CLOSE_STATUS_NOSTATUS,
								   "quic child write close");
					continue;
				}
				if (r)
					continue;
			}
#endif

			if (lws_rops_fidx(w->role_ops, LWS_ROPS_perform_user_POLLOUT)) {
				if (lws_rops_func_fidx(w->role_ops, LWS_ROPS_perform_user_POLLOUT).
								perform_user_POLLOUT(w) == -1) {
					/* if the cb didn't already close w, close it */
					if (!lws_dll2_is_detached(&w->mux.sibling_list))
						lws_close_free_wsi(w, LWS_CLOSE_STATUS_NOSTATUS, "quic child write close");
				}
			} else {
				if (lws_callback_as_writeable(w)) {
					if (!lws_dll2_is_detached(&w->mux.sibling_list))
						lws_close_free_wsi(w, LWS_CLOSE_STATUS_NOSTATUS, "quic child write close");
				}
			}
		} lws_end_foreach_dll_safe(d, d1);

end_children:
		;
		/* Give children output credits based on fair sharing */
		int can_process_children = ((qn->handshake_done || qn->early_data_status == LWS_0RTT_STATUS_ATTEMPTED || qn->early_data_status == LWS_0RTT_STATUS_ACCEPTED) && wsi->txc.tx_cr > 0 && (!nwsi || nwsi->txc.tx_cr > 0));
		int have_pending_tx = 0;
		for (level = 0; level < LWS_QUIC_LEVEL_COUNT; level++) {
			if (qn->pending_tx[level].count && qn->keys[level] && qn->keys[level]->el_hp_tx.len) {
				have_pending_tx = 1;
				break;
			}
		}

		if (!blocked && can_process_children) {
			if (lws_wsi_mux_action_pending_writeable_reqs(wsi) < 0)
				return LWS_HP_RET_BAIL_DIE;

			for (level = 0; level < LWS_QUIC_LEVEL_COUNT; level++) {
				if (qn->pending_tx[level].count && qn->keys[level] && qn->keys[level]->el_hp_tx.len) {
					have_pending_tx = 1;
					break;
				}
			}
		}

		int children_need_POLLOUT = 0;
		{
			lws_start_foreach_dll(struct lws_dll2 *, d,
					lws_dll2_get_head(&wsi->mux.child_list_owner)) {
				struct lws *w_child = lws_container_of(d,
						struct lws, mux.sibling_list);
				if (w_child->mux.requested_POLLOUT) {
					children_need_POLLOUT = 1;
					break;
				}
			}
			lws_end_foreach_dll(d);
		}

		{
			/*
			 * Same reentrancy-safe situation as the post-RX loop
			 * above; the dll2 _safe iterator keeps the cached next
			 * valid across the close (which detaches via
			 * lws_dll2_remove).
			 */
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					lws_dll2_get_head(&wsi->mux.child_list_owner)) {
				struct lws *w = lws_container_of(d,
						struct lws, mux.sibling_list);

				if (w->quic.qs && w->quic.qs->close_after_rx) {
					w->quic.qs->close_after_rx = 0;
					if (w->quic.qs->abandon)
						lwsi_set_skt_unusable(w, 1);
					lws_close_free_wsi(w,
						LWS_CLOSE_STATUS_NOSTATUS,
						"quic post tx stream close");
				}
			} lws_end_foreach_dll_safe(d, d1);
		}

		/*
		 * The poll flag is IO's: the answer says whether to keep it.
		 * Frames of ours are waiting: keep POLLOUT, unless quic's own
		 * limits blocked the send (not the socket) and no child wants
		 * a turn, when the ACK that lifts them re-arms us.  So does an
		 * ACK the socket refused: it's no frame, but it's still owed.
		 */
		if (have_pending_tx || (eagain_blocked && qn->tx_pkt.has_ack))
			return (blocked && !eagain_blocked &&
				!children_need_POLLOUT) ?
				LWS_HP_RET_DROP_POLLOUT : LWS_HP_RET_BAIL_OK;

		/*
		 * Nothing of ours: a child that still wants a turn keeps
		 * POLLOUT (it went to LRS_ISSUING_FILE and asked for its
		 * next fragment); otherwise IO drops it.
		 */
		{
			lws_start_foreach_dll(struct lws_dll2 *, d,
					lws_dll2_get_head(&wsi->mux.child_list_owner)) {
				struct lws *w = lws_container_of(d, struct lws,
								 mux.sibling_list);
				if (w->mux.requested_POLLOUT)
					return LWS_HP_RET_BAIL_OK;
			}
			lws_end_foreach_dll(d);
		}
	}

	return LWS_HP_RET_DROP_POLLOUT;
}

static int
rops_write_role_protocol_quic(struct lws *wsi, unsigned char *buf, size_t len,
                              enum lws_write_protocol *wp)
{
	struct lws *nwsi = lws_get_quic_network_wsi(wsi);
	struct lws_quic_netconn *qn = nwsi ? nwsi->quic.qn : wsi->quic.qn;
	struct lws_quic_tx_frame *f;

	if (!qn)
		return -1;

	if (len == 0 && !((*wp) & LWS_WRITE_H2_STREAM_END)) {
		return 0;
	}

	if (((*wp) & 0x1f) == LWS_WRITE_QUIC_DATAGRAM) {
		uint8_t vb[8];
		size_t flen = 1 + lws_quic_write_varint(vb, sizeof(vb), len) + len;

		/*
		 * RFC 9221 3: DATAGRAM frames only go to a peer that
		 * advertised max_datagram_frame_size, and no bigger than that
		 * (the frame's type and length count), else it is a
		 * PROTOCOL_VIOLATION on its side
		 */
		if (flen > qn->peer_max_datagram_frame_size) {
			lwsl_wsi_notice(wsi, "DATAGRAM frame of %u exceeds peer's max %llu",
					(unsigned int)flen,
					(unsigned long long)qn->peer_max_datagram_frame_size);
			return -1;
		}

		/*
		 * ... and it cannot be split: one no packet on the path can
		 * carry would never be sent, and hold up everything queued
		 * behind it
		 */
		if (len > lws_quic_datagram_max(qn)) {
			lwsl_wsi_notice(wsi, "DATAGRAM of %u exceeds the %u the "
					     "path can carry", (unsigned int)len,
					(unsigned int)lws_quic_datagram_max(qn));
			return -1;
		}
	}

	/*
	 * Nothing can follow the FIN on a stream: data past the final size
	 * (or a second FIN at a different size) is a connection-level
	 * FINAL_SIZE_ERROR from the peer, taking every stream with it.  A
	 * repeated FIN-only write is pointless but harmless, drop it quietly.
	 */
	if (wsi->quic.qs && wsi->quic.qs->sent_fin) {
		if (len)
			lwsl_wsi_notice(wsi, "binning %d byte write after FIN",
					(int)len);

		return 0;
	}

	/* Enforce stream and connection flow control limits */
	if (len > 0) {
		int did_enqueue = 0;
		if (wsi->txc.tx_cr <= 0 && !wsi->quic.tx_blocked_sent) {
			/* Generate STREAM_DATA_BLOCKED */
			struct lws_quic_tx_frame *f_sdb = lws_zalloc(sizeof(*f_sdb), "quic sdb");
			if (f_sdb) {
				f_sdb->type = LWS_QUIC_FT_STREAM_DATA_BLOCKED;
				f_sdb->stream_id = wsi->mux.my_sid;
				f_sdb->limit = wsi->quic.qs ? wsi->quic.qs->tx_offset : 0;
				lws_quic_dbg_1rtt_account(qn, f_sdb, "stream-data-blocked");
				lws_dll2_add_head(&f_sdb->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
			}
			wsi->quic.tx_blocked_sent = 1;
			did_enqueue = 1;
		}

		if (nwsi && nwsi != wsi && nwsi->txc.tx_cr <= 0 && !nwsi->quic.tx_blocked_sent) {
			/* Generate DATA_BLOCKED */
			struct lws_quic_tx_frame *f_db = lws_zalloc(sizeof(*f_db), "quic db");
			if (f_db) {
				f_db->type = LWS_QUIC_FT_DATA_BLOCKED;
				f_db->limit = qn->tx_conn_offset;
				lws_quic_dbg_1rtt_account(qn, f_db, "data-blocked");
				lws_dll2_add_head(&f_db->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
			}
			nwsi->quic.tx_blocked_sent = 1;
			did_enqueue = 1;
		}

		/* Kick output to send these control frames */
		if (did_enqueue)
			lws_callback_on_writable(nwsi ? nwsi : wsi);
	}

	f = lws_zalloc(sizeof(*f) + len, "quic tx frame");
	if (!f)
		return -1;

	f->data = (uint8_t *)&f[1];
	f->len = len;
	memcpy(f->data, buf, len);

	if (((*wp) & 0x1f) == LWS_WRITE_QUIC_DATAGRAM) {
		/* It's a DATAGRAM frame */
		f->type = LWS_QUIC_FT_DATAGRAM + 1; /* with LEN */
		f->stream_id = 0; /* Datagrams aren't attached to a stream ID */
		f->offset = 0;
	} else {
		f->type = LWS_QUIC_FT_STREAM | 0x02 | 0x04; /* STREAM | OFF | LEN */
		if (((*wp) & LWS_WRITE_H2_STREAM_END) ||
		    ((*wp) & 0x1f) == LWS_WRITE_HTTP_FINAL) {
			f->type |= 0x01; /* FIN */
			if (wsi->quic.qs) {
				wsi->quic.qs->sent_fin = 1;
				if (wsi->quic.qs->is_unidirectional || wsi->quic.qs->fin_received) {
					wsi->quic.qs->close_after_rx = 1;
				}
			}
		}

		if (!wsi->quic.qs) {
			lwsl_wsi_err(wsi, "QUIC: Cannot send stream data without a quic stream structure!");
			lws_free(f);
			return -1;
		}
		f->stream_id = wsi->quic.qs->stream_id;
		f->offset = wsi->quic.qs->tx_offset;
		wsi->quic.qs->tx_offset += len;

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
		if (!f->offset && !wsi->quic.qs->fi_replay &&
		    lws_fi(&wsi->fic, "quic_stream_replay")) {
			struct lws_quic_tx_frame *r = lws_malloc(sizeof(*f) + len,
							 "quic fi replay");

			if (r) {
				memcpy(r, f, sizeof(*f) + len);
				r->data = (uint8_t *)&r[1];
				wsi->quic.qs->fi_replay = r;
			}
		}
#endif

		/* Deduct credit here so current_max calculations work correctly */
		wsi->txc.tx_cr -= (int)len;
		if (nwsi) {
			nwsi->txc.tx_cr -= (int)len;
			qn->tx_conn_offset += len;
		}
	}

	wsi->quic.tx_blocked_sent = 0;
	if (nwsi && nwsi != wsi)
		nwsi->quic.tx_blocked_sent = 0;

	/* Stream frames usually go in Application level, but check for 0-RTT */
	int tx_level = LWS_QUIC_LEVEL_APP;
	if (!qn->is_server && !qn->handshake_done &&
	    qn->early_data_status == LWS_0RTT_STATUS_ATTEMPTED &&
	    wsi->quic.qs && wsi->quic.qs->opted_into_early_data) {
		tx_level = LWS_QUIC_LEVEL_EARLY;
	}

	if (tx_level == LWS_QUIC_LEVEL_APP)
		lws_quic_dbg_1rtt_account(qn, f, "stream-write");
	lws_dll2_add_tail(&f->list, &qn->pending_tx[tx_level]);

	/* Wake up the event loop to send the packet */
	lws_callback_on_writable(wsi);

	return (int)len;
}

#if defined(LWS_WITH_CLIENT)
static int
rops_client_bind_quic(struct lws *wsi, const struct lws_client_connect_info *i)
{
	if (!i) {
		/* finalize */
		if (!wsi->user_space && wsi->stash && wsi->stash->cis[CIS_METHOD])
			if (lws_ensure_user_space(wsi))
				return 0;
		return 0;
	}

	if ((i->method && !strcmp(i->method, "QUIC")) ||
	    (i->alpn && !strcmp(i->alpn, "h3"))) {
		struct lws_quic_cid dcid;

#if defined(LWS_ROLE_WS)
		/*
		 * No method is a ws ask, as for h1: over h3 the stream asks
		 * with an extended CONNECT (RFC 9220), and once answered is
		 * the ws connection.  Not a WebTransport ask, which names the
		 * "webtransport" protocol and has no method either
		 */
		if (!i->method &&
		    !(i->protocol && !strcmp(i->protocol, "webtransport")) &&
		    !(i->local_protocol_name &&
		      !strcmp(i->local_protocol_name, "webtransport"))) {
			if (lws_create_client_ws_object(i, wsi))
				return 1;
			wsi->do_ws = 1;
		}
#endif

		/* Allocate QUIC netconn for client! */
                if (!wsi->quic.qn) {
                        wsi->quic.qn = lws_zalloc(sizeof(*wsi->quic.qn), "quic_netconn");
			if (!wsi->quic.qn)
				return 1;
		}

		wsi->quic.qn->nwsi = wsi;
		wsi->quic.qn->is_server = 0;
		wsi->quic.qn->next_stream_id_bidi_local = 0;
		wsi->quic.qn->next_stream_id_unidi_local = 2;
		wsi->quic.qn->version = LWS_QUIC_VERSION_1;
		wsi->quic.qn->original_version = LWS_QUIC_VERSION_1;
		lws_quic_streams_limits_init(wsi->quic.qn, 1000);
		wsi->quic.qn->peer_ack_delay_exponent = 3;
		/* RFC 9000 §13.2.1 default max_ack_delay cap for delayed ACKs */
		wsi->quic.qn->ack_delay_us = 25 * LWS_US_PER_MS;

		lws_quic_pmtud_reset(wsi->quic.qn);

		if (wsi->a.context->quic_cc_ops)
			wsi->quic.qn->cc_ops = wsi->a.context->quic_cc_ops;
		else
			wsi->quic.qn->cc_ops = &lws_cc_ops_newreno;

		if (wsi->quic.qn->cc_ops->init)
			wsi->quic.qn->cc_ops->init(wsi);

		/*
		 * Connection flow control: what the peer may send us is the
		 * window we advertise, and what we may send it is set from its
		 * initial_max_data when its transport parameters arrive
		 */
		int32_t init_cr = i->manual_initial_tx_credit;
		if (!init_cr)
			init_cr = 65535;
		wsi->txc.peer_tx_cr_est = LWS_QUIC_DEFAULT_WINDOW;
		wsi->txc.tx_cr = init_cr;

		wsi->quic.qn->rx_max_data = LWS_QUIC_DEFAULT_WINDOW;
		wsi->quic.qn->advertised_rx_max_data = LWS_QUIC_DEFAULT_WINDOW;
		wsi->quic.qn->rx_window_size = LWS_QUIC_DEFAULT_WINDOW;
		wsi->quic.qn->last_rx_update_us = lws_wsi_now(wsi);

		/* Generate random CIDs */
		dcid.len = 8;
		if (lws_get_random(wsi->a.context, dcid.id, 8) != 8)
			return 1;
		wsi->quic.qn->rem_cid = dcid;
		/* the server's original_destination_connection_id must be it */
		wsi->quic.qn->orig_dcid = dcid;

		wsi->quic.qn->loc_cid.len = 8;
		if (lws_get_random(wsi->a.context, wsi->quic.qn->loc_cid.id, 8) != 8) return 1;

		/* Derive Initial Keys */
		if (lws_quic_derive_initial_keys(wsi, &dcid)) {
			lwsl_wsi_err(wsi, "Failed to derive initial keys");
			return 1;
		}

		{
			uint8_t *local_tp_buf = lws_malloc(4096, "quic tp scratch");
			if (!local_tp_buf) {
				lwsl_wsi_err(wsi, "OOM allocating tp scratch buffer");
				return 1;
			}
			uint8_t *tp = local_tp_buf;
			uint8_t *tp_end = tp + 4096;
			uint64_t win;

#define LWS_QUIC_WRITE_TP_VARINT(_id, _val) \
	do { \
		int _vlen; \
		if (lws_ptr_diff_size_t(tp_end, tp) < 2) goto tp_overflow2; \
		*tp++ = (_id); \
		_vlen = (int)lws_quic_write_varint(tp + 1, lws_ptr_diff_size_t(tp_end, tp + 1), (_val)); \
		if (!_vlen) goto tp_overflow2; \
		*tp++ = (uint8_t)_vlen; \
		tp += _vlen; \
	} while (0)

#define LWS_QUIC_WRITE_TP_BUF(_id, _buf, _len) \
	do { \
		if (lws_ptr_diff_size_t(tp_end, tp) < (size_t)(2 + (_len))) goto tp_overflow2; \
		*tp++ = (_id); \
		*tp++ = (uint8_t)(_len); \
		memcpy(tp, (_buf), (_len)); \
		tp += (_len); \
	} while (0)

			win = lws_quic_fi_window(wsi, "quic_tp_window",
						 LWS_QUIC_DEFAULT_WINDOW);
			LWS_QUIC_WRITE_TP_VARINT(0x04, win);
			LWS_QUIC_WRITE_TP_VARINT(0x05, win);
			LWS_QUIC_WRITE_TP_VARINT(0x06, win);
			LWS_QUIC_WRITE_TP_VARINT(0x07, win);
			LWS_QUIC_WRITE_TP_VARINT(0x08, wsi->quic.qn->max_streams_bidi_local);
			LWS_QUIC_WRITE_TP_VARINT(0x09, wsi->quic.qn->max_streams_unidi_local);
			LWS_QUIC_WRITE_TP_VARINT(0x20, 65535);
			LWS_QUIC_WRITE_TP_VARINT(0x01, wsi->a.vhost->quic_max_idle_ms);

			LWS_QUIC_WRITE_TP_BUF(0x0F, wsi->quic.qn->loc_cid.id, wsi->quic.qn->loc_cid.len);
                        if (wsi->a.context->options & LWS_SERVER_OPTION_QUIC_LATEST_VERSION) {
                                uint8_t vi_buf[12];
                                vi_buf[0] = (uint8_t)(LWS_QUIC_VERSION_1 >> 24);
                                vi_buf[1] = (uint8_t)(LWS_QUIC_VERSION_1 >> 16);
                                vi_buf[2] = (uint8_t)(LWS_QUIC_VERSION_1 >> 8);
                                vi_buf[3] = (uint8_t)(LWS_QUIC_VERSION_1);
                                vi_buf[4] = (uint8_t)(LWS_QUIC_VERSION_1 >> 24);
                                vi_buf[5] = (uint8_t)(LWS_QUIC_VERSION_1 >> 16);
                                vi_buf[6] = (uint8_t)(LWS_QUIC_VERSION_1 >> 8);
                                vi_buf[7] = (uint8_t)(LWS_QUIC_VERSION_1);
                                vi_buf[8] = (uint8_t)(LWS_QUIC_VERSION_2 >> 24);
                                vi_buf[9] = (uint8_t)(LWS_QUIC_VERSION_2 >> 16);
                                vi_buf[10] = (uint8_t)(LWS_QUIC_VERSION_2 >> 8);
                                vi_buf[11] = (uint8_t)(LWS_QUIC_VERSION_2);
                                LWS_QUIC_WRITE_TP_BUF(0x11, vi_buf, 12);
                        }

			lws_io_tls_quic_set_tp(wsi, local_tp_buf, (size_t)(tp - local_tp_buf));
			lws_free(local_tp_buf);
			goto tp_ok2;
tp_overflow2:
			lws_free(local_tp_buf);
			lwsl_wsi_err(wsi, "QUIC TX: tp buffer overflow");
			return 1;
tp_ok2:
			;
#undef LWS_QUIC_WRITE_TP_VARINT
#undef LWS_QUIC_WRITE_TP_BUF
		}

		lws_wsi_event_role(wsi, LWS_WSIEV_CLIENT_BIND, &role_ops_quic);
		lws_callback_on_writable(wsi);
		return 1;
	}
	return 0;
}
#endif

static int
rops_adoption_bind_quic(struct lws *wsi, int type, const char *vh_prot_name)
{
	if (!(type & LWS_ADOPT_FLAG_UDP))
		return 0;

	if ((wsi->a.vhost && wsi->a.vhost->listen_accept_role &&
	     !strcmp(wsi->a.vhost->listen_accept_role, "quic")) ||
	    (vh_prot_name && !strcmp(vh_prot_name, "quic")) ||
	    (wsi->role_ops == &role_ops_quic)) {
		/* Initialize Flow Control Credits */
		int32_t init_cr = wsi->txc.manual_initial_tx_credit;
		if (!init_cr)
			init_cr = 65535;
		wsi->txc.peer_tx_cr_est = init_cr;
		wsi->txc.tx_cr = init_cr;

		if (!(type & _LWS_ADOPT_FINISH))
			lws_wsi_event_role(wsi, LWS_WSIEV_ADOPTED, &role_ops_quic);
		lws_bind_protocol(wsi, wsi->a.protocol, __func__);

		return 1;
	}
	return 0;
}

static int
rops_callback_on_writable_quic(struct lws *wsi)
{
	struct lws *nwsi = lws_get_quic_network_wsi(wsi);

	if (!nwsi) return 0;

	/* Mark the entire parent chain as needing POLLOUT */
	lws_wsi_mux_mark_parents_needing_writeable(wsi);

	return 0; /* not handled, let core enable socket POLLOUT */
}

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
/* long after a loopback peer acked our end of the stream and freed it */
#define LWS_QUIC_FI_REPLAY_DELAY_MS 100

static void
lws_quic_fi_replay_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_quic_netconn *qn = lws_container_of(sul,
				struct lws_quic_netconn, fi_replay_sul);

	lws_quic_sul_assert_thread(qn);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&qn->fi_replays)) {
		lws_dll2_remove(d);
		lws_dll2_add_tail(d, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
	} lws_end_foreach_dll_safe(d, d1);

	lwsl_wsi_notice(qn->nwsi, "quic_stream_replay: sending again");
	lws_callback_on_writable(qn->nwsi);
}
#endif

/*
 * Tell the peer the stream limit we will give it now, eg, as its streams end.
 *
 * Coalesce: an already-queued MAX_STREAMS frame of the same type has its limit
 * updated in place, rather than allocating a new frame per closed stream.  With
 * many concurrent streams (e.g. the multiplexing QIR test with 1999 streams),
 * the O(N) frame flood would fill the TX queue and trigger PTO/congestion-window
 * collapse.
 */
void
lws_quic_queue_max_streams(struct lws *nwsi, int unidi)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	uint8_t want_type = unidi ? LWS_QUIC_FT_MAX_STREAMS_UNIDI :
				    LWS_QUIC_FT_MAX_STREAMS_BIDI;
	uint64_t limit = unidi ? qn->max_streams_unidi_local :
				 qn->max_streams_bidi_local;
	struct lws_quic_tx_frame *f_max;

	lws_start_foreach_dll(struct lws_dll2 *, d,
		lws_dll2_get_head(&qn->pending_tx[LWS_QUIC_LEVEL_APP])) {
		struct lws_quic_tx_frame *f = lws_container_of(d,
					struct lws_quic_tx_frame, list);
		if (f->type == want_type) {
			f->limit = limit;
			lws_callback_on_writable(nwsi);
			return;
		}
	} lws_end_foreach_dll(d);

	f_max = lws_zalloc(sizeof(*f_max), "quic max strm");
	if (!f_max)
		return;

	f_max->stream_id = ~0ULL;
	f_max->type = want_type;
	f_max->limit = limit;
	lws_dll2_add_tail(&f_max->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
	lws_callback_on_writable(nwsi);
}

int
lws_quic_peer_stream_over_limit(const struct lws_quic_netconn *qn,
				uint64_t stream_id)
{
	/* the stream count it needs is its index + 1 */
	return (stream_id >> 2) >= ((stream_id & 2) ?
				qn->max_streams_unidi_adv :
				qn->max_streams_bidi_adv);
}

int
lws_quic_reset_budget_spend(struct lws *nwsi, struct lws *child)
{
#if defined(LWS_ROLE_H3) && defined(LWS_WITH_SERVER)
	struct lws_quic_netconn *qn = nwsi ? nwsi->quic.qn : NULL;
	struct lws_quic_stream *qs = child->quic.qs;

	/*
	 * Only the request streams of an h3 server connection, a bidi stream
	 * the peer opened, that we had not finished answering; not while the
	 * connection is going anyway, closing its streams.  Each one once,
	 * whether the peer ends it (RESET_STREAM, STOP_SENDING) or we do.
	 */
	if (!qn || !qs || !qn->is_server || !nwsi->h3.h3n || qn->is_closing ||
	    lwsi_close_started(nwsi) || (qs->stream_id & 3) ||
	    qs->sent_fin || qs->reset_counted)
		return 0;

	qs->reset_counted = 1;

	if (!lws_mux_reset_budget_spend(nwsi, &qn->reset_budget))
		return 0;

	lws_quic_enter_closing_state(nwsi, LWS_H3_EXCESSIVE_LOAD, 0, 1);

	return 1;
#else
	(void)nwsi;
	(void)child;

	return 0;
#endif
}

void
lws_quic_stream_cleanup(struct lws *wsi)
{
	struct lws *nwsi = wsi;
	while (nwsi && !nwsi->quic.qn) {
		nwsi = nwsi->mux.parent_wsi;
	}
	struct lws_quic_netconn *qn = nwsi ? nwsi->quic.qn : NULL;
	int i;

	if (!wsi->quic.qs)
		return;

	/* 1. Stop charging the held rx chunks against the connection... */
	if (qn) {
		if (qn->rx_stream_buffered >= wsi->quic.qs->rx_held.charged)
			qn->rx_stream_buffered -= wsi->quic.qs->rx_held.charged;
		else
			qn->rx_stream_buffered = 0;
	}
	/* ... and free them */
	lws_quic_rx_held_destroy(&wsi->quic.qs->rx_held);

	/*
	 * Give the connection-level flow control window back whatever this
	 * stream took from it that the application never consumed (the
	 * credit-back in rops_tx_credit_quic() only happens on delivery):
	 * data still buffered here, data dropped because the app refused it
	 * (close_after_rx), and, for a stream we abandon with STOP_SENDING,
	 * whatever the peer may still legitimately send or claim as the
	 * final size in its RESET_STREAM, which is bounded by the stream's
	 * advertised limit.  Without this each abandoned stream permanently
	 * eats its unread bytes out of the 1MB connection window, and after
	 * a few of them the peer is flow-control blocked on every later
	 * stream of the connection, which then look like silent hangs.
	 */
	if (nwsi && nwsi != wsi && qn) {
		uint64_t bound = wsi->quic.qs->fin_received ?
					wsi->quic.qs->highest_rx_offset :
					wsi->quic.qs->rx_max_data;

		/*
		 * If we are abandoning the stream before its FIN, the peer
		 * will still count everything it had in flight for it, and
		 * the final size in its RESET_STREAM, against the connection
		 * window: but those arrive for a stream we no longer know and
		 * are dropped.  Pre-account the most it can legally claim now,
		 * so our view of what the peer has used doesn't fall behind
		 * the peer's own and leave us thinking it has plenty of window
		 * left while it sits DATA_BLOCKED and never gets a MAX_DATA.
		 * The credit-back below covers the same amount, so this can't
		 * push highest_rx_offset over rx_max_data.
		 */
		if (bound > wsi->quic.qs->highest_rx_offset)
			qn->highest_rx_offset += bound -
						 wsi->quic.qs->highest_rx_offset;

		if (bound > wsi->quic.qs->rx_credited) {
			uint64_t back = bound - wsi->quic.qs->rx_credited;

			if (back > (uint64_t)INT32_MAX)
				back = INT32_MAX;
			wsi->quic.qs->rx_credited = bound;
			lws_wsi_tx_credit(nwsi, LWSTXCR_PEER_TO_US, (int)back);
		}
	}

	/* 2. Purge pending and in-flight TX frames for this stream from parent network connection */
	if (qn) {
		uint64_t sid = wsi->quic.qs->stream_id;

		/*
		 * Work out which stream directions are still incomplete at
		 * close, so we can do the right thing per direction:
		 *
		 *  tx_reset:  our own sending side never completed.  We must
		 *             abandon it with RESET_STREAM, and drop anything
		 *             of ours still queued or in flight for it.
		 *  stop_peer: the peer's sending side never completed, and we
		 *             are closing the stream anyway, so ask them to
		 *             stop sending the rest.
		 *
		 * These are independent: a server that answers a POST without
		 * draining the request body completes its own response side
		 * cleanly (no RESET_STREAM, response frames must still go out)
		 * while the peer is still mid-body (STOP_SENDING applies).
		 */
		int is_unidirectional = (sid & 2) != 0;
		int is_remote_initiated = (qn->is_server && (sid & 1) == 0) || (!qn->is_server && (sid & 1) == 1);
		int we_are_sender = (qn->is_server == is_remote_initiated) ? 1 : 0;
		int tx_reset, stop_peer;

		if (is_unidirectional) {
			/* only one side is the sender on a unidi stream */
			we_are_sender = is_remote_initiated ? 0 : 1;
			tx_reset  = we_are_sender && !wsi->quic.qs->sent_fin;
			stop_peer = !we_are_sender && !wsi->quic.qs->fin_received;
		} else {
			tx_reset  = !wsi->quic.qs->sent_fin;
			stop_peer = !wsi->quic.qs->fin_received;
		}

		/* If we're abandoning our own sending side, notify the peer */
		if (tx_reset) {
			/*
			 * If we started sending a response (HEADERS went out)
			 * but never sent our FIN (== h3 END_STREAM), and this
			 * isn't an immortal SSE / long-poll stream, the response
			 * was incomplete -- usually a headers-only response
			 * written without LWS_WRITE_H2_STREAM_END.  Warn so the
			 * user-code bug is visible even when the peer (or the
			 * network) beat the PENDING_TIMEOUT_HTTP_RESPONSE
			 * watchdog to closing the stream.
			 */
			if (wsi->http.sent_response_headers &&
			    !wsi->quic.qs->sent_fin && !wsi->mux_stream_immortal &&
			    /*
			     * Only the server response side can be "user code
			     * left the response incomplete": client streams also
			     * get sent_response_headers set when they write
			     * their request HEADERS, and a client need not have
			     * sent FIN when the transaction completes cleanly
			     */
			    /*
			     * An established websocket's h3 handshake response
			     * is headers-only with no END_STREAM by design; the
			     * stream then carries ws frames until one side
			     * closes it, so a ws peer disconnect is not an
			     * incomplete-response bug.
			     */
#if defined(LWS_ROLE_WS)
			    !lwsi_role_ws(wsi) &&
#endif
			    lwsi_role_server(wsi))
				lwsl_wsi_warn(wsi, "h3 stream closed with response "
					      "headers sent but no END_STREAM "
					      "(incomplete response; user code "
					      "likely wrote a headers-only response "
					      "without LWS_WRITE_H2_STREAM_END), "
					      "protocol=%s, uri=\"%s\"",
					      wsi->a.protocol ?
						      wsi->a.protocol->name :
						      "none",
					      lws_wsi_request_uri(wsi) ?
						      lws_wsi_request_uri(wsi) : "");

			/* Send RESET_STREAM to notify the peer that we're abandoning the stream */
			struct lws_quic_tx_frame *f_reset = lws_zalloc(sizeof(*f_reset), "quic reset");
			if (f_reset) {
				f_reset->type = LWS_QUIC_FT_RESET_STREAM;
				f_reset->stream_id = sid;
				f_reset->offset = wsi->quic.qs->close_app_err; /* app error code */
				f_reset->limit = wsi->quic.qs->tx_offset; /* final size */
				lws_quic_dbg_1rtt_account(qn, f_reset, "reset-stream");
				lws_dll2_add_head(&f_reset->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
			}
		}

		/*
		 * Send STOP_SENDING to tell the peer to stop sending data to
		 * us.  This has to be queued at the TAIL: any frames for this
		 * stream that are still queued ahead of it belong to our own,
		 * cleanly-completed response and must reach the peer first.
		 * If STOP_SENDING jumped ahead of them (as RESET_STREAM may,
		 * above), the peer would tear the stream down on receipt and
		 * discard the transaction we just finished delivering.
		 */
		if (stop_peer) {
			struct lws_quic_tx_frame *f_stop = lws_zalloc(sizeof(*f_stop), "quic stop_sending");
			if (f_stop) {
				f_stop->type = LWS_QUIC_FT_STOP_SENDING;
				f_stop->stream_id = sid;
				f_stop->offset = wsi->quic.qs->close_app_err; /* app error code */
				lws_quic_dbg_1rtt_account(qn, f_stop, "stop-sending");
				lws_dll2_add_tail(&f_stop->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
			}
		}

		if ((tx_reset || stop_peer) && nwsi)
			lws_callback_on_writable(nwsi);

#if defined(LWS_ROLE_H3)
		/*
		 * We are abandoning a request stream before we answered it, for
		 * any reason but refusing it for want of an ah (G-028): it
		 * counts against the connection, as one the peer reset does.
		 * One the peer reset was counted already, when it did.
		 */
		if (tx_reset && nwsi &&
		    wsi->quic.qs->close_app_err != LWS_H3_REQUEST_REJECTED)
			lws_quic_reset_budget_spend(nwsi, wsi);
#endif

		/* If this was a remote-initiated stream, increase our limit and notify peer */
		if (is_remote_initiated) {
			uint64_t *credit = is_unidirectional ?
					&qn->max_streams_unidi_local :
					&qn->max_streams_bidi_local,
				 adv = is_unidirectional ?
					qn->max_streams_unidi_adv :
					qn->max_streams_bidi_adv,
				 batch = (is_unidirectional ?
					qn->max_streams_unidi_window :
					qn->max_streams_bidi_window) / 8;

			/*
			 * The stream's credit comes back to the peer, but only
			 * with the MAX_STREAMS saying so: until that goes out,
			 * the peer is held to the limit it was told (RFC 9000
			 * 4.6, lws_quic_peer_stream_over_limit()), so ending a
			 * stream, eg, by resetting it, can't be what lets the
			 * peer open the next one.  Credit is given back in
			 * batches of an eighth of the initial limit, so a peer
			 * opening and ending streams as fast as it can waits
			 * for our MAX_STREAMS every so many of them, rather
			 * than us sending one for each.
			 */
			(*credit)++;
			if (*credit - adv >= (batch ? batch : 1))
				lws_quic_queue_max_streams(nwsi, is_unidirectional);
		}

		/*
		 * Only drop our queued / in-flight frames for the stream if we
		 * actually abandoned our own sending side with RESET_STREAM.
		 * When only the peer's side is incomplete (eg, we answered a
		 * POST without draining the body), our completed response
		 * frames must still be delivered.
		 */
		if (tx_reset) {
			for (i = 0; i < LWS_QUIC_LEVEL_COUNT; i++) {
				/* Purge pending_tx */
				lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->pending_tx[i].head) {
					struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);
					int is_stream_frame = ((f->type & 0xf8) == LWS_QUIC_FT_STREAM) ||
							      (f->type == LWS_QUIC_FT_MAX_STREAM_DATA) ||
							      (f->type == LWS_QUIC_FT_STREAM_DATA_BLOCKED);
					if (is_stream_frame && f->stream_id == sid) {
						lws_dll2_remove(&f->list);
						lws_free(f);
					}
				} lws_end_foreach_dll_safe(d, d1);

				/* Purge in_flight */
				lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->in_flight[i].head) {
					struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);
					int is_stream_frame = ((f->type & 0xf8) == LWS_QUIC_FT_STREAM) ||
							      (f->type == LWS_QUIC_FT_MAX_STREAM_DATA) ||
							      (f->type == LWS_QUIC_FT_STREAM_DATA_BLOCKED);
					if (is_stream_frame && f->stream_id == sid) {
						if (qn->cc_ops && qn->cc_ops->on_discard)
							qn->cc_ops->on_discard(nwsi, f->wire_len);
						lws_dll2_remove(&f->list);
						lws_free(f);
					}
				} lws_end_foreach_dll_safe(d, d1);
			}
		}
	}

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	/*
	 * quic_stream_replay: our first STREAM frame goes again once the peer
	 * has had time to finish with the stream too
	 */
	if (wsi->quic.qs->fi_replay) {
		if (qn && nwsi) {
			lws_dll2_add_tail(&wsi->quic.qs->fi_replay->list,
					  &qn->fi_replays);
			lws_quic_sul_schedule(qn, &qn->fi_replay_sul,
					      lws_quic_fi_replay_cb,
					      LWS_QUIC_FI_REPLAY_DELAY_MS *
					      LWS_US_PER_MS);
		} else
			lws_free(wsi->quic.qs->fi_replay);
		wsi->quic.qs->fi_replay = NULL;
	}
#endif

	lws_free_set_NULL(wsi->quic.qs);
}

/*
 * Server-side keepalive reaping.
 *
 * A server connection is idle when it has no bidirectional (request)
 * streams.  The child count cannot be used for that: the h3 control and
 * qpack unidi streams are children of the network wsi that live as long as
 * the connection, and they are marked immortal, which also makes
 * lws_set_timeout() refuse PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE for the
 * network wsi.  So count request streams directly and use a reason the
 * immortal check does not apply to.
 *
 * Stream 0 is a child from the ALPN migration on, whether or not the peer
 * ever uses it, so a stream of the peer's counts only once the peer has
 * opened it (sent a STREAM frame for it).
 *
 * Idle, the connection waits as h1's does.  Until the peer's first request,
 * it has the vhost's timeout_secs_ah_idle, h1's hold of a connection for its
 * request head, as a deadline from the handshake: nothing the peer sends
 * short of a request stream extends it, or a peer that only sends PINGs
 * keeps it for as long as it likes.  After a request, it has the vhost's
 * keepalive_timeout, refreshed by what the peer sends, as h1 waits for the
 * next request on a connection that had one.  A connection that never had
 * a request may be one whose request was lost and is still coming: the
 * longer first wait gives its sender's probes more of a chance.
 *
 * This is the shorter policy for connections with nothing to do: the
 * transport's own idle timeout (lws_quic_idle_start()) bounds every
 * connection, whatever its streams.
 *
 * Called when the handshake completes, when the ALPN migration has made
 * stream 0, when the peer opens a stream, when a child closes, and (to
 * refresh) when a packet is accepted while the idle timeout is armed.
 * Leaves the timeout alone if something else owns it, eg, the
 * CONNECTION_CLOSE drain in lws_quic_enter_closing_state().
 */
void
lws_quic_server_idle_check(struct lws *nwsi)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;

	if (!qn || !qn->is_server || !qn->handshake_done)
		return;

	if (qn->is_closing)
		return;

	if (nwsi->pending_timeout != NO_PENDING_TIMEOUT &&
	    nwsi->pending_timeout != PENDING_TIMEOUT_UDP_IDLE &&
	    nwsi->pending_timeout != PENDING_TIMEOUT_AWAITING_CLIENT_HS_SEND)
		return;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&nwsi->mux.child_list_owner)) {
		struct lws *w = lws_container_of(d, struct lws, mux.sibling_list);

		if (w->quic.qs && !w->quic.qs->is_unidirectional &&
		    (w->quic.qs->is_server_initiated ||
		     lws_quic_idtr_is_opened(&qn->peer_opened[0],
					     w->quic.qs->stream_id >> 2))) {
			/* has a request stream: not idle */
			qn->had_request = 1;
			if (nwsi->pending_timeout != NO_PENDING_TIMEOUT)
				lws_set_timeout(nwsi, NO_PENDING_TIMEOUT, 0);
			return;
		}
	} lws_end_foreach_dll(d);

	if (!qn->had_request) {
		/* the deadline for the first request, not refreshed */
		if (nwsi->pending_timeout != PENDING_TIMEOUT_UDP_IDLE)
			lws_set_timeout(nwsi, PENDING_TIMEOUT_UDP_IDLE,
					nwsi->a.vhost->timeout_secs_ah_idle);
		return;
	}

	lws_set_timeout(nwsi, PENDING_TIMEOUT_UDP_IDLE,
			nwsi->a.vhost->keepalive_timeout ?
				nwsi->a.vhost->keepalive_timeout : 5);
}

/*
 * The transport idle timeout, RFC 9000 10.1, on server and client
 * connections alike.  It is the shorter of the max_idle_timeout we
 * advertised and the peer's, but at least three PTOs, and it restarts when
 * a packet from the peer is processed, and when we send an ack-eliciting
 * packet after one, but not again until the peer sends another.  When it
 * runs out the connection is closed silently: the peer, by the same rule,
 * has already discarded it, or will.
 *
 * It is armed when the handshake completes (before that the handshake's own
 * deadline bounds the connection), and has nothing to do with streams: a
 * peer that wants a quiet connection kept sends something, eg, PING.
 */

static lws_usec_t
lws_quic_idle_timeout_us(const struct lws_quic_netconn *qn)
{
	uint64_t ms = qn->nwsi->a.vhost->quic_max_idle_ms;
	lws_usec_t us, pto3 = 3 * lws_quic_pto_base_us(qn);

	if (qn->peer_max_idle_timeout_ms && qn->peer_max_idle_timeout_ms < ms)
		ms = qn->peer_max_idle_timeout_ms;

	us = (lws_usec_t)ms * LWS_US_PER_MS;

	return us < pto3 ? pto3 : us;
}

static void
lws_quic_idle_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_quic_netconn *qn = lws_container_of(sul,
					struct lws_quic_netconn, idle_sul);
	struct lws *nwsi = qn->nwsi;
	lws_usec_t now, due;

	/* a connection closing already ends by its own deadline */
	if (!nwsi || qn->is_closing)
		return;

	lws_quic_sul_assert_thread(qn);

	now = lws_wsi_now(nwsi);
	due = qn->idle_restart_us + lws_quic_idle_timeout_us(qn);
	if (now < due) {
		/* it restarted since we were scheduled */
		lws_quic_sul_schedule(qn, &qn->idle_sul, lws_quic_idle_cb,
				      due - now);
		return;
	}

	lwsl_wsi_info(nwsi, "QUIC idle timeout, closing silently");

	/* nothing is sent: is_closing keeps CONNECTION_CLOSE back */
	qn->is_closing = 1;
	lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NOSTATUS, "quic idle timeout");
}

void
lws_quic_idle_start(struct lws_quic_netconn *qn)
{
	if (!qn->nwsi)
		return;

	qn->idle_restart_us = lws_wsi_now(qn->nwsi);
	qn->idle_tx_since_rx = 0;
	lws_quic_sul_schedule(qn, &qn->idle_sul, lws_quic_idle_cb,
			      lws_quic_idle_timeout_us(qn));
}

void
lws_quic_idle_restart(struct lws_quic_netconn *qn, int tx)
{
	if (!qn->handshake_done || !qn->nwsi)
		return;

	if (tx) {
		/* only the first ack-eliciting one since the peer's last */
		if (qn->idle_tx_since_rx)
			return;
		qn->idle_tx_since_rx = 1;
	} else
		qn->idle_tx_since_rx = 0;

	qn->idle_restart_us = lws_wsi_now(qn->nwsi);
}

/*
 * Free a netconn and everything it owns: the per-level keys, queued and
 * in-flight tx frames, rx crypto chunks and buffers, and the congestion
 * control state.  Used at network wsi close, and when a client wsi that
 * was bound as a fresh QUIC connection is instead adopted as a stream on
 * an existing one and its unused netconn is dropped.
 */

void
lws_quic_netconn_destroy(struct lws_quic_netconn **pqn)
{
	struct lws_quic_netconn *qn = *pqn;
	int i;

	if (!qn)
		return;

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	if (qn->nwsi && qn->fi_stats.ack_frames &&
	    lws_fi(&qn->nwsi->fic, "quic_stats"))
		lwsl_wsi_notice(qn->nwsi, "QUIC FI stats: %s, ack frames %llu, "
				"ignored %llu, ranges %llu, acked %llu, visits %llu, "
				"in flight peak %u, excess max %llu, path "
				"responses peak %u, cc bypassed %llu",
				qn->is_server ? "server" : "client",
				(unsigned long long)qn->fi_stats.ack_frames,
				(unsigned long long)qn->fi_stats.ack_ignored,
				(unsigned long long)qn->fi_stats.ack_ranges,
				(unsigned long long)qn->fi_stats.ack_acked,
				(unsigned long long)qn->fi_stats.ack_visits,
				(unsigned int)qn->fi_stats.in_flight_peak,
				(unsigned long long)qn->fi_stats.excess_max,
				(unsigned int)qn->fi_stats.path_responses_peak,
				(unsigned long long)qn->fi_stats.cc_bypassed);
#endif

	lws_dll2_remove(&qn->pt_list);
	lws_sul_cancel(&qn->idle_sul);
#if defined(LWS_WITH_PEER_LIMITS)
	if (qn->peer && qn->nwsi)
		lws_peer_track_wsi_close(qn->nwsi->a.context, qn->peer);
	qn->peer = NULL;
#endif

	lws_quic_rx_next_discard(qn);

	for (i = 0; i < LWS_QUIC_LEVEL_COUNT; i++) {
		/* Free keys */
		if (qn->keys[i]) {
			lws_quic_keys_destroy(qn->keys[i]);
			qn->keys[i] = NULL;
		}

		/* Free pending tx */
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->pending_tx[i].head) {
			struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);
			lws_dll2_remove(&f->list);
			lws_free(f);
		} lws_end_foreach_dll_safe(d, d1);

		/* Free in flight */
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->in_flight[i].head) {
			struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);
			lws_dll2_remove(&f->list);
			lws_free(f);
		} lws_end_foreach_dll_safe(d, d1);

		/* Free RX Crypto chunks */
		lws_quic_rx_held_destroy(&qn->rx_crypto_held[i]);
	}

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&qn->early_pkts)) {
		lws_dll2_remove(d);
		lws_free(lws_container_of(d, struct lws_quic_early_pkt, list));
	} lws_end_foreach_dll_safe(d, d1);

	if (qn->cc_state)
		lws_free_set_NULL(qn->cc_state);

	lws_quic_idtr_destroy(&qn->peer_opened[0]);
	lws_quic_idtr_destroy(&qn->peer_opened[1]);

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	lws_sul_cancel(&qn->fi_replay_sul);
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&qn->fi_replays)) {
		lws_dll2_remove(d);
		lws_free(lws_container_of(d, struct lws_quic_tx_frame, list));
	} lws_end_foreach_dll_safe(d, d1);
#endif

	for (i = 0; i < 4; i++)
		if (qn->crypto_rx_buf[i]) {
			lws_free(qn->crypto_rx_buf[i]);
			qn->crypto_rx_buf[i] = NULL;
		}

	lws_free_set_NULL(*pqn);
}

static int
rops_close_kill_connection_quic(struct lws *wsi, enum lws_close_status reason)
{
	struct lws_quic_netconn *qn = wsi->quic.qn;

	/* a listener's replies not yet sent */
	lws_quic_replies_destroy(wsi);

	if(!lws_dll2_is_empty(&wsi->mux.child_list_owner))
		lws_wsi_mux_close_children(wsi, (int)reason);

	if (wsi->mux.parent_wsi) {
		struct lws *nwsi = wsi->mux.parent_wsi;
		lws_wsi_mux_sibling_disconnect(wsi);
		if (nwsi->quic.qn)
			lws_quic_server_idle_check(nwsi);
#if defined(LWS_WITH_CLIENT)
		lws_wsi_mux_client_idle_check(nwsi);
#endif
	}

	lws_quic_stream_cleanup(wsi);

	if (!qn)
		return 0;

	/* If we are the network wsi, free the qn and all resources */
	if (qn->nwsi == wsi) {
		lws_sul_cancel(&qn->prefaddr_sul);
		lws_sul_cancel(&qn->path_probe_sul);
		lws_sul_cancel(&qn->pto_sul);
		lws_sul_cancel(&qn->idle_sul);
		lws_sul_cancel(&qn->pacer_sul);
		lws_sul_cancel(&qn->ack_delay_sul);
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
		lws_sul_cancel(&qn->fi_replay_sul);
#endif

#if defined(LWS_ROLE_H3)
		if (wsi->h3.h3n) {
			/*
			 * Both QPACK tables own malloc'd per-entry strings;
			 * freeing h3n without these leaked them per connection
			 */
			lws_qpack_destroy_dynamic_header(
					&wsi->h3.h3n->qpack_dec_ctx);
			lws_qpack_tx_encoder_destroy(
					&wsi->h3.h3n->qpack_tx_encoder);
			lws_buflist_destroy_all_segments(
					&wsi->h3.h3n->qpack_dec_tx_bl);
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
			lws_buflist_destroy_all_segments(
					&wsi->h3.h3n->fi_late_insert);
#endif
			/*
			 * a stream still waiting for inserts would point into
			 * the h3n: it is closed before us, which takes it off
			 */
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				lws_dll2_get_head(
					&wsi->h3.h3n->qpack_blocked_owner)) {
				lws_dll2_remove(d);
			} lws_end_foreach_dll_safe(d, d1);
			lws_free_set_NULL(wsi->h3.h3n);
		}
#endif

		lws_quic_netconn_destroy(&wsi->quic.qn);
	}

	return 0;
}

/*
 * A live quic connection we are closing of our own accord (the keep-warm or
 * idle timeout, the user, a redirect) tells the peer with CONNECTION_CLOSE,
 * RFC 9000 10.2, the way a tls close sends close_notify: one packet, sent
 * now, then the close carries on to free the connection.  We do not linger
 * in the closing state to repeat it: if it is lost the peer idles the
 * connection out, as it did before when it was never sent.
 *
 * A connection the peer closed (draining, RFC 9000 10.2.2: nothing may be
 * sent) or one already closing after an error has nothing to add.  The
 * close flow does not come here for a socket already unusable, nor at
 * context destroy.
 */
static int
rops_close_via_role_protocol_quic(struct lws *wsi, enum lws_close_status reason)
{
	struct lws_quic_netconn *qn = wsi->quic.qn;
	uint64_t err = 0;

	if (!qn || qn->nwsi != wsi || qn->is_closing || !qn->handshake_done)
		return 0;

#if defined(LWS_ROLE_H3)
	/*
	 * The application error space is the ALPN's: h3's "no error" is
	 * H3_NO_ERROR, RFC 9114 8.1; 0 is not an h3 code at all
	 */
	if (wsi->h3.h3n)
		err = LWS_H3_NO_ERROR;
#endif

	qn->is_closing = 1;
	lws_quic_queue_connection_close(wsi, err, 0, 1);

	lwsl_wsi_info(wsi, "sending CONNECTION_CLOSE 0x%llx (%d)",
		      (unsigned long long)err, (int)reason);

	/* now, not on a later POLLOUT: best effort, the close goes on */
	lws_io_tx_now(wsi);

	return 0; /* the close carries on */
}

int
rops_tx_credit_quic(struct lws *wsi, char peer_to_us, int add)
{
	struct lws *nwsi = lws_get_quic_network_wsi(wsi);
	struct lws_quic_netconn *qn = nwsi ? nwsi->quic.qn : NULL;
	int n;

	if (!qn) {
		return 0;
	}

	if (add) {
		if (peer_to_us == LWSTXCR_PEER_TO_US) {
			/* We want to tell the peer they can write an additional "add" bytes to us */
			wsi->txc.peer_tx_cr_est = lws_txc_cr_add(
					wsi->txc.peer_tx_cr_est, add);
			if (nwsi != wsi)
				nwsi->txc.peer_tx_cr_est = lws_txc_cr_add(
					nwsi->txc.peer_tx_cr_est, add);

			lws_usec_t now = lws_wsi_now(wsi);

			if (wsi->quic.qs) {
				wsi->quic.qs->rx_credited += (uint64_t)(add > 0 ? add : 0);
				wsi->quic.qs->rx_max_data += (uint64_t)(add > 0 ? add : 0);
				uint64_t ungranted = 0;
				if (wsi->quic.qs->advertised_rx_max_data > wsi->quic.qs->highest_rx_offset)
					ungranted = wsi->quic.qs->advertised_rx_max_data - wsi->quic.qs->highest_rx_offset;
				
				if (nwsi->a.context->quic_tx_credit_cb) {
					uint64_t new_win = nwsi->a.context->quic_tx_credit_cb(
						wsi, wsi->quic.qs->rx_window_size, (uint64_t)(add > 0 ? add : 0), 
						(uint64_t)(now - wsi->quic.qs->last_rx_update_us));
					if (new_win > wsi->quic.qs->rx_window_size && new_win <= LWS_QUIC_MAX_WINDOW) {
						wsi->quic.qs->rx_max_data += (new_win - wsi->quic.qs->rx_window_size);
						wsi->quic.qs->rx_window_size = new_win;
						ungranted = 0;
						if (wsi->quic.qs->advertised_rx_max_data > wsi->quic.qs->highest_rx_offset)
							ungranted = wsi->quic.qs->advertised_rx_max_data - wsi->quic.qs->highest_rx_offset;
					}
				}

				if (ungranted < wsi->quic.qs->rx_window_size / 2) {
					wsi->quic.qs->last_rx_update_us = now;
					struct lws_quic_tx_frame *f_msd = lws_zalloc(sizeof(*f_msd), "quic msd");
					if (f_msd) {
						f_msd->type = LWS_QUIC_FT_MAX_STREAM_DATA;
						f_msd->stream_id = wsi->mux.my_sid;
						f_msd->limit = wsi->quic.qs->rx_max_data;
						wsi->quic.qs->advertised_rx_max_data = wsi->quic.qs->rx_max_data;
						lws_quic_dbg_1rtt_account(qn, f_msd, "max-stream-data");
						lws_dll2_add_tail(&f_msd->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
					}
					lws_callback_on_writable(nwsi);
				}
			}

			qn->rx_max_data += (uint64_t)(add > 0 ? add : 0);
			uint64_t ungranted = 0;
			if (qn->advertised_rx_max_data > qn->highest_rx_offset)
				ungranted = qn->advertised_rx_max_data - qn->highest_rx_offset;

			if (nwsi->a.context->quic_tx_credit_cb) {
				uint64_t new_win = nwsi->a.context->quic_tx_credit_cb(
					nwsi, qn->rx_window_size, (uint64_t)(add > 0 ? add : 0), 
					(uint64_t)(now - qn->last_rx_update_us));
				if (new_win > qn->rx_window_size && new_win <= LWS_QUIC_MAX_WINDOW) {
					qn->rx_max_data += (new_win - qn->rx_window_size);
					qn->rx_window_size = new_win;
					ungranted = 0;
					if (qn->advertised_rx_max_data > qn->highest_rx_offset)
						ungranted = qn->advertised_rx_max_data - qn->highest_rx_offset;
				}
			}

			if (ungranted < qn->rx_window_size / 2) {
				qn->last_rx_update_us = now;
				struct lws_quic_tx_frame *f_md = lws_zalloc(sizeof(*f_md), "quic md");
				if (f_md) {
					f_md->type = LWS_QUIC_FT_MAX_DATA;
					f_md->limit = qn->rx_max_data;
					qn->advertised_rx_max_data = qn->rx_max_data;
					lws_quic_dbg_1rtt_account(qn, f_md, "max-data");
					lws_dll2_add_tail(&f_md->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
				}
				lws_callback_on_writable(nwsi);
			}

			lws_callback_on_writable(nwsi);
			return 0;
		}

		/*
		 * We're being told we can write an additional "add" bytes to
		 * the peer: the peer may have granted more than int32 holds
		 */
		wsi->txc.tx_cr = lws_txc_cr_add(wsi->txc.tx_cr, add);
		if (add > 0)
			wsi->quic.tx_blocked_sent = 0;

		/* Unblock if blocked */
		if (wsi->txc.tx_cr > 0) {
			lws_callback_on_writable(wsi);

			lws_start_foreach_dll(struct lws_dll2 *, d,
					lws_dll2_get_head(&wsi->mux.child_list_owner)) {
				struct lws *w = lws_container_of(d, struct lws,
								 mux.sibling_list);
				lws_callback_on_writable(w);
			}
			lws_end_foreach_dll(d);
		}
		return 0;
	}

	if (peer_to_us == LWSTXCR_US_TO_PEER) {
		/*
		 * How much can we write to the peer?
		 * Min of stream's local tx credit and the nwsi's global tx credit.
		 */
		int cr = wsi->txc.tx_cr;
		if (nwsi->txc.tx_cr < cr)
			cr = nwsi->txc.tx_cr;

		size_t queued_bytes = 0;
		if (nwsi->quic.qn) {
			uint32_t mtu = nwsi->quic.qn->current_mtu ?
				nwsi->quic.qn->current_mtu : 1280;

			lws_start_foreach_dll(struct lws_dll2 *, d,
				    lws_dll2_get_head(&nwsi->quic.qn->pending_tx[LWS_QUIC_LEVEL_APP])) {
				struct lws_quic_tx_frame *f = lws_container_of(d,
					struct lws_quic_tx_frame, list);
				queued_bytes += f->len;
			} lws_end_foreach_dll(d);

			/*
			 * Throttle based on available cwnd headroom: cap new writes
			 * to cwnd - bytes_in_flight - queued_bytes.  bytes_in_flight
			 * only counts serialized frames; queued_bytes (pending_tx) is
			 * already committed but not yet on the wire.  Together they
			 * represent our total debt against the cwnd.
			 *
			 * Floor: always allow at least 1 MTU so the stream
			 * makes progress even when the window is exactly full.
			 */
			if (nwsi->quic.qn->cc_state) {
				struct lws_quic_cc_newreno *cc =
					(struct lws_quic_cc_newreno *)nwsi->quic.qn->cc_state;
				size_t debt = cc->bytes_in_flight + queued_bytes;
				size_t headroom = (cc->cwnd > debt) ? cc->cwnd - debt : 0;
				if (headroom < mtu)
					headroom = mtu; /* always allow 1 packet */
				if (cr > (int)headroom)
					cr = (int)headroom;
			}
		}

		/*
		 * Accounts for H3 framing overhead (DATA/HEADERS frame type + length: max 9 bytes).
		 * If we don't subtract this, the caller reads `cr` bytes of payload, and then
		 * H3 frames it (adding overhead), resulting in a write request of `cr + overhead` bytes,
		 * which exceeds the flow control window and blocks, causing issues on non-seekable streams.
		 */
		if (cr >= 3) {
			if (cr > 9)
				cr -= 9;
			else
				cr -= 2;
		} else {
			cr = 0;
		}

		if (!cr && !add)
			lwsl_debug("rops_tx_credit_quic: US_TO_PEER returning 0: "
				    "wsi_tx_cr=%d, nwsi_tx_cr=%d, queued=%zu, "
				    "wsi=%s, nwsi=%s\n",
				    (int)wsi->txc.tx_cr, (int)nwsi->txc.tx_cr,
				    queued_bytes, lws_wsi_tag(wsi),
				    lws_wsi_tag(nwsi));

		lwsl_debug("rops_tx_credit_quic: LWSTXCR_US_TO_PEER returning %d (wsi->txc.tx_cr=%d, nwsi->txc.tx_cr=%d)\n",
			  cr, (int)wsi->txc.tx_cr, (int)nwsi->txc.tx_cr);
		return cr; /* how much we can write to peer */
	}

	n = wsi->txc.peer_tx_cr_est; /* how much peer can write to us */
	if (n > nwsi->txc.peer_tx_cr_est)
		n = nwsi->txc.peer_tx_cr_est;

	lwsl_debug("rops_tx_credit_quic: returning %d\n", n);
	return n;
}

static int
rops_alpn_negotiated_quic(struct lws *wsi, const char *alpn)
{
	struct lws_quic_stream *qs;
	struct lws *nwsi;
	const struct lws_role_ops *role;

#if defined(LWS_WITH_CLIENT)
	/*
	 * The handshake is done: quic has won the race for the connection,
	 * and the tcp connects racing it as the fallback, their pacing timers
	 * and the h3 grace go now.  It must be before anything below moves
	 * off this wsi: the racers' event-lib watchers live in its evlib
	 * block, which the migration moves to the new network wsi.  Torn down
	 * after that, a parked tcp socket kept a live libuv poll handle whose
	 * data pointed at this wsi, freed when its h3 stream ends, and the
	 * peer's idle close of that unused connection ten to forty seconds
	 * later was the POLLIN that dereferenced it.
	 */
	if (lwsi_role_client(wsi))
		lws_client_transport_established(wsi);
#endif

	if (strcmp(alpn, "h3") && strcmp(alpn, "lws-quic"))
		return 0;

	lwsl_info("ENTER rops_alpn_negotiated_quic: wsi=%p\n", wsi);

	lwsl_wsi_info(wsi, "QUIC negotiated %s, migrating network connection to new wsi", alpn);

	role = lws_role_by_name(alpn);
	if (!role) {
		role = &role_ops_quic;
	}

	/* If it's already migrated or it's a stream, don't migrate again! */
	if (!wsi->quic.qn || wsi->quic.qn->alpn_migrated)
		return 0;

	/*
	 * This wsi goes on as stream 0 with a stream of its own.  Get that
	 * first: failing it after the connection moved to the new network wsi
	 * left the connection half way between the two, its netconn leaked
	 * and still on the pt's lists naming a freed wsi.
	 */
	qs = lws_zalloc(sizeof(*qs), "quic stream");
	if (!qs)
		return 1;

	/* Create the new network WSI */
	nwsi = lws_create_new_server_wsi(wsi->a.vhost, wsi->tsi, 0, "quic_nwsi");
	if (!nwsi) {
		lws_free(qs);
		return 1;
	}

#if defined(LWS_WITH_CLIENT)
	if (wsi->cli_hostname_copy)
		nwsi->cli_hostname_copy = lws_strdup(wsi->cli_hostname_copy);
	nwsi->c_port = wsi->c_port;
	/* how long we stay warm after our last stream closes: the request's */
	nwsi->keep_warm_secs = wsi->keep_warm_secs;
#endif

	/* the socket, its place in the poll set and its watcher move over */
	if (lws_io_transfer(wsi, nwsi)) {
		lws_free(qs);
		lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NOSTATUS,
				   "transfer fail");
		return 1;
	}

	/* Transfer the quic contexts (the udp state moved with the socket) */
	nwsi->quic = wsi->quic;
	nwsi->txc = wsi->txc;
#if defined(LWS_WITH_TLS)
	/* what the connection asked for goes with it (the join test reads it) */
	nwsi->use_ssl = wsi->use_ssl;
#endif
	memset(&wsi->quic, 0, sizeof(wsi->quic));
	wsi->quic.qs = qs;
	qs->rx_max_data = LWS_QUIC_DEFAULT_WINDOW;
	qs->advertised_rx_max_data = LWS_QUIC_DEFAULT_WINDOW;
	qs->rx_window_size = LWS_QUIC_DEFAULT_WINDOW;
	qs->last_rx_update_us = lws_wsi_now(wsi);

	/* Initialize flow control credits for the new child stream */
	int32_t init_cr = nwsi->txc.manual_initial_tx_credit;
	if (!init_cr) {
		if (nwsi->quic.qn)
			init_cr = lws_quic_peer_initial_stream_cr(nwsi->quic.qn,
				!wsi->quic.qs->is_unidirectional,
				wsi->quic.qs->is_server_initiated ==
						nwsi->quic.qn->is_server);
		else
			init_cr = 65535;
	}
	wsi->txc.peer_tx_cr_est = init_cr;
	wsi->txc.tx_cr = init_cr;

#if defined(LWS_WITH_CLIENT)
        /* Transfer active connection and pipeline queue from child to network WSI */ 
        if (!lws_dll2_is_detached(&wsi->dll_cli_active_conns)) { 
                lws_dll2_remove(&wsi->dll_cli_active_conns); 
                lws_dll2_add_tail(&nwsi->dll_cli_active_conns, &wsi->a.vhost->dll_cli_active_conns_owner); 
        } 
        lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, 
                        lws_dll2_get_head(&wsi->dll2_cli_txn_queue_owner)) { 
                struct lws *ww = lws_container_of(d, struct lws, dll2_cli_txn_queue); 
                lws_dll2_remove(&ww->dll2_cli_txn_queue); 
                lws_dll2_add_tail(&ww->dll2_cli_txn_queue, &nwsi->dll2_cli_txn_queue_owner); 
        } lws_end_foreach_dll_safe(d, d1); 
#endif

	lwsl_info("rops_alpn_negotiated_quic: old_wsi=%p\n", wsi);
	lwsl_info("rops_alpn_negotiated_quic: new_nwsi=%p\n", nwsi);
	lwsl_info("rops_alpn_negotiated_quic: qn=%p\n", nwsi->quic.qn);

	/* Important: the network WSI must point back to itself */
	if (nwsi->quic.qn)
		nwsi->quic.qn->nwsi = nwsi;

	/* the new network wsi is on our side, and up */
	lws_wsi_event_x(nwsi, LWS_WSIEV_CONN_TAKEOVER, &role_ops_quic, wsi);

	/* Transition wsi to HTTP/3 and link as a child of nwsi */
	/*
	 * This wsi becomes stream 0 of the connection: on an h3 client it goes
	 * on to send its request, on an h3 server it starts by parsing one
	 */
	lws_wsi_event_role(wsi, LWS_WSIEV_ALPN_DONE, role);
#if defined(LWS_ROLE_H3)
	if (!strcmp(alpn, "h3")) {
		memset(&wsi->h3, 0, sizeof(wsi->h3));
	}
#endif

	wsi->mux_substream = 1;
#if defined(LWS_WITH_CLIENT)
        if (lwsi_role_client(wsi))
                wsi->client_mux_substream = 1;
        else
                wsi->client_mux_substream = 0;
#endif
	nwsi->quic.qn->alpn_migrated = 1;

#if defined(LWS_WITH_CLIENT)
	/*
	 * QUIC succeeded (the racers were already torn down at the top,
	 * before the evlib block moved): remember the host is h3-capable
	 */
	if (lwsi_role_client(wsi)) {
		if (wsi->a.context->h3_cap_cache && wsi->stash && wsi->stash->cis[CIS_HOST]) {
			lws_h3_cap_info_t cap;
			cap.state = LWS_H3_STATE_KNOWN_GOOD;
			cap.latency_us = (uint32_t)(lws_wsi_now(wsi) - nwsi->quic.quic_race_start_us);

			lws_cache_write_through(wsi->a.context->h3_cap_cache, wsi->stash->cis[CIS_HOST],
						(const uint8_t *)&cap, sizeof(cap),
						lws_wsi_now(wsi) + (3600ll * LWS_US_PER_SEC), NULL);
		}
	}
#endif

	/* 
	 * The quic child stream is migrating to be a child of nwsi. 
	 * So we disconnect it from the listener socket first. 
	 */
	/* 
	 * Important: The new network connection nwsi must be in the listener's 
	 * child list so it can receive incoming UDP packets! 
	 * We must get the listener socket BEFORE we disconnect the wsi.
	 */
	struct lws *listener = wsi->mux.parent_wsi;

	if (wsi->mux.parent_wsi)
                lws_wsi_mux_sibling_disconnect(wsi);

        /*
         * Transfer all of wsi's mux children to nwsi.  Under dll2 this is a
         * per-child remove+add_head; owner.count and the parent_wsi back-link
         * are kept consistent as we go.
         */
        lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&wsi->mux.child_list_owner)) {
		struct lws *c = lws_container_of(d, struct lws, mux.sibling_list);

		lws_dll2_remove(&c->mux.sibling_list);
		c->mux.parent_wsi = nwsi;
		lws_dll2_add_head(&c->mux.sibling_list,
				  &nwsi->mux.child_list_owner);
	} lws_end_foreach_dll_safe(d, d1);

        lws_wsi_mux_insert(wsi, nwsi, 0); /* client first request is stream ID 0 */
        if (nwsi->quic.qn->next_stream_id_bidi_local == 0)
                nwsi->quic.qn->next_stream_id_bidi_local = 4;
        lws_set_timeout(nwsi, NO_PENDING_TIMEOUT, 0);
	/*
	 * A server's connection deadlines were set while this wsi was the
	 * connection: the handshake's, or once that completed, the keepalive
	 * reap.  They belong to the connection, not stream 0: left here, stream
	 * 0 was closed when they ran out, however much was still coming on it,
	 * and the connection was left with no deadline at all.  The handshake
	 * is still going if 0-RTT brought us here early, and then its deadline
	 * goes on unchanged on the new network wsi.  Otherwise the keepalive
	 * is decided again for the connection, where stream 0 counts only once
	 * the peer uses it.
	 */
	if (nwsi->quic.qn->is_server) {
		if (wsi->pending_timeout == PENDING_TIMEOUT_UDP_IDLE ||
		    wsi->pending_timeout == PENDING_TIMEOUT_AWAITING_CLIENT_HS_SEND)
			lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

		if (!nwsi->quic.qn->handshake_done) {
			lws_usec_t now = lws_wsi_now(nwsi),
				   dl = nwsi->quic.qn->hs_deadline_us;

			/* already due: it goes on the next pass */
			lws_set_timeout_us(nwsi,
				PENDING_TIMEOUT_AWAITING_CLIENT_HS_SEND,
				dl > now ? dl - now : 1);
		} else
			lws_quic_server_idle_check(nwsi);
	}

	if (listener) {
		nwsi->mux_substream = 1;
		lws_wsi_mux_insert(nwsi, listener, nwsi->mux.my_sid);
	}

	/* Inform the H3 role that it negotiated ALPN */
	if (role && role != &role_ops_quic &&
	    lws_rops_fidx(role, LWS_ROPS_alpn_negotiated)) {
		(lws_rops_func_fidx(role, LWS_ROPS_alpn_negotiated)).
			alpn_negotiated(wsi, alpn);
	}

	/* We are ready to send headers! */
	lws_callback_on_writable(wsi);

#if defined(LWS_WITH_CLIENT)
        if (!strcmp(alpn, "h3") && lwsi_role_client(wsi)) {
                lws_wsi_mux_apply_queue(nwsi);
        }
#endif

	return 0;
}

static int
rops_destroy_role_quic(struct lws *wsi)
{
	return rops_close_kill_connection_quic(wsi, LWS_CLOSE_STATUS_NOSTATUS);
}

#if defined(LWS_WITH_CLIENT)
static lws_handling_result_t
rops_client_transport_up_quic(struct lws *wsi, const lws_sockaddr46 *peer)
{
	/*
	 * the committed path is the peer IO connected us to; unset, the
	 * server's first packet looked like the server moving, and the client
	 * "migrated" mid-handshake: cc, rtt and pmtud reset, the path
	 * unvalidated and a PATH_CHALLENGE sent
	 */
	struct lws_quic_netconn *qn = wsi->quic.qn;

	if (qn && wsi->quic.initialized &&
	    (lws_sa46_compare_ads(&qn->initial_sa46, peer) ||
	     qn->initial_sa46.sa4.sin_port != peer->sa4.sin_port)) {
		/*
		 * Up again, to another peer: the one before refused us before
		 * it answered, and IO aimed the connection at the next of its
		 * addresses.  Nothing came back, so nothing we sent got
		 * anywhere and nothing of the peer was learned: start the
		 * handshake there, sending what is in flight again now rather
		 * than at the probe timeout.
		 */
		qn->path_sa46 = *peer;
		qn->initial_sa46 = *peer;
		qn->pto_count = 0;
		lws_quic_sul_schedule(qn, &qn->pto_sul, lws_quic_pto_cb, 1);

		return LWS_HPI_RET_HANDLED;
	}

	if (qn) {
		qn->path_sa46 = *peer;
		/* ...and where our Initial goes */
		qn->initial_sa46 = *peer;
	}

	/* quic drives its own tls handshake, inside its packets */
	lws_wsi_event(wsi, LWS_WSIEV_TLS_START);

#if defined(LWS_WITH_TLS)
	if (!wsi->quic.initialized && (wsi->use_ssl & LCCSCF_USE_SSL)) {
		wsi->quic.initialized = 1;

		if (lws_tls_quic_session(wsi, quic_secret_cb))
			return LWS_HPI_RET_PLEASE_CLOSE_ME;
		/* the ClientHello, queued as our first CRYPTO frames */
		lws_tls_quic_rx_crypto(wsi, LWS_QUIC_LEVEL_INITIAL, NULL, 0);
	}
#endif

	/* the first tx sends them */
	lws_callback_on_writable(wsi);

	return LWS_HPI_RET_HANDLED;
}
#endif

static const lws_rops_t rops_table_quic[] = {
	/*  1 */ { .handle_POLLIN	  = NULL }, /* a sansIO role has none */
	/*  2 */ { .handle_POLLOUT	  = rops_handle_POLLOUT_quic },
	/*  3 */ { .callback_on_writable  = rops_callback_on_writable_quic },
	/*  4 */ { .tx_credit		  = rops_tx_credit_quic },
	/*  5 */ { .write_role_protocol	  = rops_write_role_protocol_quic },
	/*  6 */ { .alpn_negotiated	  = rops_alpn_negotiated_quic },
	/*  7 */ { .close_kill_connection = rops_close_kill_connection_quic },
	/*  8 */ { .close_via_role_protocol = rops_close_via_role_protocol_quic },
	/*  9 */ { .destroy_role          = rops_destroy_role_quic },
	/* 10 */ { .adoption_bind	  = rops_adoption_bind_quic },
#if defined(LWS_WITH_CLIENT)
	/* 11 */ { .client_bind		  = rops_client_bind_quic },
	/* 12 */ { .client_transport_up	  = rops_client_transport_up_quic },
#endif
	/* 13, or 11 without client */
		 { .rx_dgram		  = rops_rx_dgram_quic },
	/* 14, or 12 without client */
		 { .rx_policy		  = rops_rx_policy_quic },
	/* 15, or 13 without client */
		 { .tx			  = rops_tx_quic },
	/* 16, or 14 without client */
		 { .tx_sent		  = rops_tx_sent_quic },
};

const struct lws_role_ops role_ops_quic = {
	/* role name */			"quic",
	/* alpn id */			"h3",

	/* rops_table */		rops_table_quic,
	/* rops_idx */			{
	  /* LWS_ROPS_check_upgrades */
	  /* LWS_ROPS_pt_init_destroy */		0x00, 0x00,
	  /* LWS_ROPS_init_vhost */
	  /* LWS_ROPS_destroy_vhost */			0x00, 0x00,
	  /* LWS_ROPS_service_flag_pending */
	  /* LWS_ROPS_handle_POLLIN */			0x00, 0x00,
	  /* LWS_ROPS_handle_POLLOUT */
	  /* LWS_ROPS_perform_user_POLLOUT */		0x02, 0x00,
	  /* LWS_ROPS_callback_on_writable */
	  /* LWS_ROPS_tx_credit */			0x03, 0x04,
	  /* LWS_ROPS_write_role_protocol */
	  /* LWS_ROPS_encapsulation_parent */		0x05, 0x00,
	  /* LWS_ROPS_alpn_negotiated */
	  /* LWS_ROPS_close_via_role_protocol */	0x06, 0x08,
	  /* LWS_ROPS_close_role */
	  /* LWS_ROPS_close_kill_connection */		0x00, 0x07,
	  /* LWS_ROPS_destroy_role */
	  /* LWS_ROPS_adoption_bind */			0x09, 0x0A,
#if defined(LWS_WITH_CLIENT)
	  /* LWS_ROPS_client_bind */
	  /* LWS_ROPS_issue_keepalive */		0x0B, 0x00,
	  /* LWS_ROPS_client_transport_up */
	  /* LWS_ROPS_rx */				0x0C, 0x00,
	  /* LWS_ROPS_rx_dgram */			0x0D, 0x0E,
	  /* LWS_ROPS_rx_done */
	  /* LWS_ROPS_tx */			0x00, 0x0F,
	  /* LWS_ROPS_tx_sent */			0x10,
#else
	  /* LWS_ROPS_client_bind */
	  /* LWS_ROPS_issue_keepalive */		0x00, 0x00,
	  /* LWS_ROPS_client_transport_up */
	  /* LWS_ROPS_rx */				0x00, 0x00,
	  /* LWS_ROPS_rx_dgram */			0x0B, 0x0C,
	  /* LWS_ROPS_rx_done */
	  /* LWS_ROPS_tx */			0x00, 0x0D,
	  /* LWS_ROPS_tx_sent */			0x0E,
#endif
					},

	/* adoption_cb clnt, srv */	{ LWS_CALLBACK_CLIENT_ESTABLISHED,
					  LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED },
	/* rx_cb clnt, srv */		{ LWS_CALLBACK_QT_CLIENT_RECEIVE,
					  LWS_CALLBACK_QT_SERVER_RECEIVE },
	/* writeable cb clnt, srv */	{ LWS_CALLBACK_CLIENT_WRITEABLE,
					  LWS_CALLBACK_SERVER_WRITEABLE },
	/* close cb clnt, srv */	{ LWS_CALLBACK_CLOSED_CLIENT_HTTP,
					  LWS_CALLBACK_CLOSED },
	/* protocol_bind_cb c,s */	{ LWS_CALLBACK_CLIENT_HTTP_BIND_PROTOCOL,
					  LWS_CALLBACK_HTTP_BIND_PROTOCOL },
	/* protocol_unbind_cb c,s */	{ LWS_CALLBACK_CLIENT_HTTP_DROP_PROTOCOL,
					  LWS_CALLBACK_HTTP_DROP_PROTOCOL },
	/* file_handle */		0,
	/* child_stdio */		0,
};
