/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2019 - 2026 Andy Green <andy@warmcat.com>
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

struct lws_transport_sequencer_range {
	lws_dll2_t			list;
	uint64_t			offset;
	uint32_t			len;
	void				*dsh_obj;
	uint8_t				acked;
	uint8_t				sent; /* tx: has been on the wire */
};

/*
 * Bound on how many out-of-order rx ranges we will track for one sequencer.
 * The peer is unauthenticated, so without this he can make us allocate a range
 * struct per packet just by leaving gaps, and every subsequent packet then
 * walks the whole list twice.
 */

#define LWS_TS_MAX_RX_RANGES 64

/*
 * What we will send an unproven peer, beyond its first chunk, before it has
 * acknowledged anything: at most this many bytes more than it has sent us.
 * Its source address may be forged, and anything it gets us to send, eg, a
 * bigger reply to each small request, goes to whoever really has that
 * address (G-182).  The rest waits in the dsh until the peer proves itself.
 */

#define LWS_TS_UNPROVEN_TX_ALLOWANCE 1536

static int
range_compare(const lws_dll2_t *d, const lws_dll2_t *i)
{
	const struct lws_transport_sequencer_range *rd = lws_container_of(d, struct lws_transport_sequencer_range, list);
	const struct lws_transport_sequencer_range *ri = lws_container_of(i, struct lws_transport_sequencer_range, list);

	if (rd->offset < ri->offset)
		return -1;
	if (rd->offset > ri->offset)
		return 1;
	return 0;
}

static int
lws_dll2_remove_it(struct lws_dll2 *d, void *user)
{
	lws_dll2_remove(d);
	lws_free(d);
	return 0;
}

struct lws_transport_sequencer {
	lws_transport_sequencer_info_t	info;

	lws_sorted_usec_list_t		sul_retry;
	lws_sorted_usec_list_t		sul_writeable;
	lws_dsh_t			*dsh;

	lws_dll2_owner_t		scoreboard; /* sender side ranges */
	lws_dll2_owner_t		rx_scoreboard; /* receiver side ranges */

	uint64_t			next_tx_offset; /* Highest byte sent + 1 */
	uint64_t			ack_offset;     /* Cumulative ACK point */
	uint64_t			next_rx_offset; /* Cumulative receive point */
	uint64_t			active_offset; /* offset of currently in-flight chunk */
	uint64_t			unproven_tx; /* bytes sent while unproven */
	uint32_t			held; /* tx ranges waiting for the proof */

	uint16_t			retry_count;
	uint16_t			active_len;

	/*
	 * DIAGNOSTIC (temporary): what the logs need to show a stream that is
	 * stuck, see ts_diag_due()
	 */
	uint64_t			diag_resend_offset; /* chunk being resent */
	uint32_t			diag_resends; /* times in a row */
	uint32_t			diag_dups; /* duplicates since new data */
	uint32_t			diag_drops_window;
	uint32_t			diag_drops_full;

	uint8_t				completed:1;
	uint8_t				peer_proven:1; /* acked our data */
	uint8_t				busy:1; /* refused a write, owes on_writeable */
	uint8_t				diag_rx_started:1; /* rx'd since reset */
	uint8_t				diag_sacked_past:1; /* acks for data past
								 * the head arrive */
	lws_transport_sequencer_stats_t	stats;
};

#define ts_peer(_ts) ((_ts)->info.peer ? (_ts)->info.peer : "?")

/*
 * DIAGNOSTIC (temporary): a condition seen n times is logged the first
 * time, and then at 16, 32, 64... times, so a stream stuck for hours still
 * says so now and then without flooding the log
 */

static int
ts_diag_due(uint32_t n)
{
	return n == 1 || (n >= 16 && !(n & (n - 1)));
}

static void
sul_retry_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_transport_sequencer *ts = lws_container_of(sul,
			struct lws_transport_sequencer, sul_retry);
	void *obj;
	size_t len;
	uint64_t *p_off;

	if (ts->completed)
		return;

	if (lws_dsh_get_head(ts->dsh, 0, &obj, &len))
		return;

	p_off = (uint64_t *)obj;

	/*
	 * ->retry_count is advanced by lws_retry_get_delay_ms() each time the
	 * timer is armed, so here it is the number of timeouts so far: the
	 * policy's conceal_count retransmits have gone out, and the last of
	 * them has had its own timeout to be acked, once it is past that.
	 * (It used to be advanced here as well, so only half the retransmits
	 * went out and the timer stopped being armed before this was reached:
	 * a dead peer never failed the session.)
	 */
	if (ts->retry_count > ts->info.retry_policy->conceal_count) {
		lwsl_notice("%s: %s: no ack after %d retries, failing session "
			    "and freeing %llu unacked bytes\n", __func__,
			    ts->info.ops->name, ts->retry_count,
			    (unsigned long long)(ts->next_tx_offset -
						 ts->ack_offset));
		ts->completed = 1;
		if (ts->info.ops->on_state_change)
			ts->info.ops->on_state_change(ts, 1 /* FAILED */, 0);
		return;
	}

	/*
	 * A peer that has never acknowledged anything may be a forged source:
	 * the retry still counts, so the session fails on schedule, but the
	 * copy only goes out once the peer has shown it receives from us.
	 */
	/* DIAGNOSTIC (temporary) */
	if (*p_off == ts->diag_resend_offset)
		ts->diag_resends++;
	else {
		ts->diag_resend_offset = *p_off;
		ts->diag_resends = 1;
	}
	if (ts->diag_resends >= 16 && ts_diag_due(ts->diag_resends))
		lwsl_warn("%s: %s to %s: STUCK SENDING: the chunk at %llu (%u "
			  "bytes) has gone %u times without an ack.  %s\n",
			  __func__, ts->info.ops->name, ts_peer(ts),
			  (unsigned long long)*p_off,
			  (unsigned int)(len - sizeof(uint64_t)),
			  ts->diag_resends,
			  !ts->peer_proven ? "The peer has never acked "
			  "anything: it does not get our chunks, or its acks "
			  "do not get back to us." :
			  ts->diag_sacked_past ? "Its acks keep arriving for "
			  "data after this chunk, so it is up and gets our "
			  "chunks, but it does not take this one: look at its "
			  "log for STUCK RECEIVING from us, eg, it restarted "
			  "and waits for data before this chunk that we will "
			  "not send again." :
			  "Acks for it stopped arriving: it does not get this "
			  "chunk, or its acks do not get back to us.");

	if (ts->peer_proven) {
		ts->stats.tx_retries++;

		/* Call protocol-specific TX hook with data after the offset prefix */
		ts->info.ops->tx_chunk(ts, *p_off, (uint8_t *)obj + sizeof(uint64_t),
					len - sizeof(uint64_t));
	}

	/*
	 * Schedule the next timeout, even after the last retransmit, so it
	 * gets its chance to be acked before we give up
	 */
	lws_sul_schedule(ts->info.cx, 0, &ts->sul_retry, sul_retry_cb,
			 (lws_usec_t)lws_retry_get_delay_ms(ts->info.cx,
					ts->info.retry_policy, &ts->retry_count,
					NULL) * LWS_US_PER_MS);
}

static void
sul_writeable_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_transport_sequencer *ts = lws_container_of(sul,
			struct lws_transport_sequencer, sul_writeable);

	if (ts->completed || !ts->busy)
		return;

	lwsl_info("%s: %s: tx buffer has room again (%u of %u used)\n",
		  __func__, ts->info.ops->name,
		  (unsigned int)ts->dsh->locally_in_use,
		  (unsigned int)ts->dsh->buffer_size);

	ts->busy = 0;
	/* the last thing we do: it may write, or destroy ts */
	if (ts->info.ops->on_writeable)
		ts->info.ops->on_writeable(ts);
}

struct lws_transport_sequencer *
lws_transport_sequencer_create(const lws_transport_sequencer_info_t *i)
{
	struct lws_transport_sequencer *ts = lws_zalloc(sizeof(*ts), __func__);

	if (!ts)
		return NULL;

	ts->info = *i;
	ts->peer_proven = !i->unproven_peer;

	/* Create DSH for buffering unacknowledged packets (TX kind 0, RX kind 1) */
	ts->dsh = lws_dsh_create(NULL, i->window_size * 2 + 32768, 2);
	if (!ts->dsh) {
		lws_free(ts);
		return NULL;
	}

	lws_dll2_owner_clear(&ts->scoreboard);
	lws_dll2_owner_clear(&ts->rx_scoreboard);

	return ts;
}

void
lws_transport_sequencer_destroy(struct lws_transport_sequencer **pts)
{
	struct lws_transport_sequencer *ts = *pts;

	if (!ts)
		return;

	lws_sul_cancel(&ts->sul_retry);
	lws_sul_cancel(&ts->sul_writeable);
	if (ts->dsh)
		lws_dsh_destroy(&ts->dsh);

	lws_dll2_foreach_safe(&ts->scoreboard, NULL, lws_dll2_remove_it);
	lws_dll2_foreach_safe(&ts->rx_scoreboard, NULL, lws_dll2_remove_it);

	lws_free(ts);
	*pts = NULL;
}

/*
 * The peer has proven it receives from us: send what was held back from it
 * while it was unproven, in the order it was written
 */

static void
lws_ts_send_held(struct lws_transport_sequencer *ts)
{
	struct lws_transport_sequencer_range *r;

	if (!ts->peer_proven || !ts->held)
		return;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&ts->scoreboard)) {
		r = lws_container_of(d, struct lws_transport_sequencer_range,
				     list);

		if (!r->sent) {
			r->sent = 1;
			ts->held--;
			if (r->dsh_obj) {
				ts->info.ops->tx_chunk(ts, r->offset,
					(uint8_t *)r->dsh_obj + sizeof(uint64_t),
					r->len);
				ts->stats.tx_packets++;
				ts->stats.tx_bytes += r->len;
			}
		}
	} lws_end_foreach_dll(d);
}

int
lws_transport_sequencer_write_at(struct lws_transport_sequencer *ts,
				 uint64_t offset, const uint8_t *buf, size_t len)
{
	struct lws_transport_sequencer_range *r;

	if (ts->completed)
		return LWS_TSW_FAILED;

	/* Windowing is now heap-limited by DSH, not range-based */

	r = lws_zalloc(sizeof(*r), __func__);
	if (!r) {
		lwsl_err("%s: %s: OOM, refusing %u-byte write\n", __func__,
			 ts->info.ops->name, (unsigned int)len);
		return LWS_TSW_FAILED;
	}

	/*
	 * Buffer in DSH with offset prefix.  The dsh is this sequencer's own
	 * fixed buffer, allocated at create: failing here is not heap OOM, it
	 * is the peer not having acked enough of what is already queued to
	 * it to leave room for this.  We refuse this write and keep the rest
	 * queued: it drains as the peer acks, and the caller hears from
	 * on_writeable() when there's room... or the session fails, and frees
	 * it all, when the retransmits of the oldest chunk run out.
	 *
	 * Said in full once per episode, the caller may well try again first.
	 */
	if (lws_dsh_alloc_tail(ts->dsh, 0, &offset, sizeof(offset), buf, len)) {
		if (!lws_dll2_get_head(&ts->scoreboard)) {
			/* nothing to drain: it will never fit */
			lwsl_err("%s: %s: %u-byte write can't fit tx buffer "
				 "(%u)\n", __func__, ts->info.ops->name,
				 (unsigned int)len,
				 (unsigned int)ts->dsh->buffer_size);
			lws_free(r);
			return LWS_TSW_FAILED;
		}
		if (!ts->busy)
			lwsl_warn("%s: %s: tx buffer full (%u of %u used, "
				  "%u ranges, %u held, %llu unacked, peer "
				  "%sproven, retry %u/%u), refusing %u-byte "
				  "write at %llu\n", __func__,
				  ts->info.ops->name,
				  (unsigned int)ts->dsh->locally_in_use,
				  (unsigned int)ts->dsh->buffer_size,
				  (unsigned int)lws_dll2_count(&ts->scoreboard),
				  (unsigned int)ts->held,
				  (unsigned long long)(ts->next_tx_offset -
						       ts->ack_offset),
				  ts->peer_proven ? "" : "un",
				  (unsigned int)ts->retry_count,
				  (unsigned int)
					ts->info.retry_policy->conceal_count,
				  (unsigned int)len, (unsigned long long)offset);
		else
			lwsl_info("%s: %s: tx buffer still full, refusing "
				  "%u-byte write\n", __func__,
				  ts->info.ops->name, (unsigned int)len);
		ts->busy = 1;
		lws_free(r);
		return LWS_TSW_BUSY;
	}

	r->offset = offset;
	r->len = (uint32_t)len;
	{
		lws_dsh_obj_t *obj = lws_container_of(lws_dll2_get_tail(&ts->dsh->oha[1].owner),
						      lws_dsh_obj_t, list);
		r->dsh_obj = (void *)(&obj[1]);
	}
	lws_dll2_add_tail(&r->list, &ts->scoreboard);

	if (offset + len > ts->next_tx_offset)
		ts->next_tx_offset = offset + len;

	/*
	 * Send the packet immediately (Broadsiding)... unless the peer is
	 * unproven and has had its allowance: then it waits, in order, for
	 * the peer to ack what it was sent
	 */
	if (ts->peer_proven ||
	    (!ts->held && (!ts->unproven_tx ||
			   ts->unproven_tx + len <= ts->stats.rx_bytes +
					LWS_TS_UNPROVEN_TX_ALLOWANCE))) {
		if (!ts->peer_proven)
			ts->unproven_tx += len;
		r->sent = 1;
		ts->info.ops->tx_chunk(ts, offset, buf, len);
		ts->stats.tx_packets++;
		ts->stats.tx_bytes += len;
	} else
		ts->held++;

	/*
	 * Ensure retransmission timer is running for the unacked
	 * head in DSH Kind 0 if not already active.
	 */
	if (lws_dll2_is_detached(&ts->sul_retry.list)) {
		ts->retry_count = 0;
		ts->active_offset = offset;
		ts->active_len = (uint16_t)len;

		lws_retry_sul_schedule(ts->info.cx, 0, &ts->sul_retry,
					 ts->info.retry_policy, sul_retry_cb,
					 &ts->retry_count);
	}

	return LWS_TSW_QUEUED;
}

int
lws_transport_sequencer_write(struct lws_transport_sequencer *ts,
			      const uint8_t *buf, size_t len)
{
	return lws_transport_sequencer_write_at(ts, ts->next_tx_offset, buf, len);
}

int
lws_transport_sequencer_acknowledge_sack(struct lws_transport_sequencer *ts,
					 uint64_t cumulative_offset,
					 const lws_transport_sequencer_sack_block_t *blocks,
					 size_t num_blocks, int status)
{
	struct lws_transport_sequencer_range *r;
	size_t i, obj_len;
	int freed = 0;
	void *obj;
	uint64_t *p_off;

	if (ts->completed)
		return 1;

	/*
	 * The transport has bound this ack to our session, but its contents
	 * are still the peer's word.  An ack for bytes we never sent is not a
	 * delivery report, it is a forgery or a broken peer: refuse it whole,
	 * before it can retire anything or prove the peer.  The SACK blocks are
	 * checked without overflowing, start + len is the peer's arithmetic.
	 */

	if (cumulative_offset > ts->next_tx_offset)
		goto bad_ack;

	for (i = 0; i < num_blocks; i++)
		if (blocks[i].start > ts->next_tx_offset ||
		    blocks[i].len > ts->next_tx_offset - blocks[i].start)
			goto bad_ack;

	if (status != 0) {
		lwsl_notice("%s: received error status %d, failing session\n",
			    __func__, status);
		ts->completed = 1;
		if (ts->info.ops->on_state_change)
			ts->info.ops->on_state_change(ts, 1 /* FAILED */, status);
		return 0;
	}

	ts->stats.rx_packets++;
	/*
	 * We don't have the literal packet size here easily,
	 * but we can use cumulative_offset/num_blocks as a hint.
	 * For stats we can just use a placeholder or 64 bytes (ACK size).
	 */
	ts->stats.rx_bytes += 64;

	/* Mark cumulative ACKs in scoreboard and retire from DSH */
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&ts->scoreboard)) {
		r = lws_container_of(d, struct lws_transport_sequencer_range, list);
		if (r->offset + r->len <= cumulative_offset) {
			/*
			 * The peer acknowledged data we really sent, so it
			 * receives at the address we are sending to
			 */
			ts->peer_proven = 1;
			r->acked = 1;
			if (r->dsh_obj) {
				lws_dsh_free(&r->dsh_obj);
				freed = 1;
			}
		}
	} lws_end_foreach_dll_safe(d, d1);

	/* DIAGNOSTIC (temporary): the peer takes data past what we resend */
	ts->diag_sacked_past = !!num_blocks;

	/* Mark SACK blocks */
	for (i = 0; i < num_blocks; i++) {
		lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&ts->scoreboard)) {
			r = lws_container_of(d, struct lws_transport_sequencer_range, list);
			if (r->offset >= blocks[i].start &&
			    r->offset + r->len <= blocks[i].start + blocks[i].len) {
				ts->peer_proven = 1;
				r->acked = 1;
				if (r->dsh_obj) {
					lws_dsh_free(&r->dsh_obj);
					freed = 1;
				}
			}
		} lws_end_foreach_dll(d);
	}

	/* Retire contiguous ACKed packets from scoreboard */
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&ts->scoreboard)) {
		r = lws_container_of(d, struct lws_transport_sequencer_range, list);

		if (!r->acked)
			break;

		/* This contiguous packet is acked, we can retire from scoreboard */
		ts->ack_offset = r->offset + r->len;
		ts->stats.ack_offset = ts->ack_offset;
		if (ts->active_offset == r->offset)
			lws_sul_cancel(&ts->sul_retry);

		if (!r->sent) /* acked unseen, it is not held any more */
			ts->held--;
		lws_dll2_remove(&r->list);
		lws_free(r);
	} lws_end_foreach_dll_safe(d, d1);

	/* the ack proved the peer: what we held back from it can go */
	lws_ts_send_held(ts);

	/*
	 * A writer we refused can try again now there's room... from the
	 * event loop, so it doesn't write or destroy ts from inside here
	 */
	if (freed && ts->busy)
		lws_sul_schedule(ts->info.cx, 0, &ts->sul_writeable,
				 sul_writeable_cb, 1);

	/* Schedule next retransmission from head of DSH if window not empty */
	if (ts->next_tx_offset > ts->ack_offset) {
		if (!lws_dsh_get_head(ts->dsh, 0, &obj, &obj_len)) {
			p_off = (uint64_t *)obj;

			/*
			 * Only progress on the chunk we resend starts its
			 * retries again.  Acks for other data, eg, while the
			 * peer will not take this one, used to restart them
			 * too, so a stuck stream was resent forever and never
			 * failed.
			 */
			if (*p_off != ts->active_offset ||
			    lws_dll2_is_detached(&ts->sul_retry.list)) {
				ts->retry_count = 0;
				ts->active_offset = *p_off;
				ts->active_len = (uint16_t)(obj_len -
							    sizeof(uint64_t));

				lws_retry_sul_schedule(ts->info.cx, 0,
						&ts->sul_retry,
						ts->info.retry_policy,
						sul_retry_cb, &ts->retry_count);
			}
		}
	} else {
		if (ts->info.ops->on_state_change && ts->next_tx_offset == ts->ack_offset)
			ts->info.ops->on_state_change(ts, 0 /* SUCCESS */, 0);
	}

	return 0;

bad_ack:
	lwsl_notice("%s: %s: ack to %llu beyond the %llu sent, refused\n",
		    __func__, ts->info.ops->name,
		    (unsigned long long)cumulative_offset,
		    (unsigned long long)ts->next_tx_offset);

	return -1;
}

int
lws_transport_sequencer_acknowledge(struct lws_transport_sequencer *ts,
				    uint64_t offset, size_t len, int status)
{
	/* the range is the peer's: bound it before adding it up */
	if (offset > ts->next_tx_offset || len > ts->next_tx_offset - offset)
		return -1;

	if (offset == ts->ack_offset)
		return lws_transport_sequencer_acknowledge_sack(ts, offset + len, NULL, 0, status);

	/* Out of order ACK, treat as SACK block */
	lws_transport_sequencer_sack_block_t block;
	block.start = offset;
	block.len = (uint32_t)len;

	return lws_transport_sequencer_acknowledge_sack(ts, ts->ack_offset, &block, 1, status);
}

int
lws_transport_sequencer_rx(struct lws_transport_sequencer *ts,
			   uint64_t offset, const uint8_t *buf, size_t len)
{
	struct lws_transport_sequencer_range *r;
	uint64_t ack_offset = offset;
	size_t ack_len = len;

	/*
	 * DIAGNOSTIC (temporary): a stream should start where we expect it,
	 * at 0 after we were made or reset
	 */
	if (!ts->diag_rx_started) {
		ts->diag_rx_started = 1;
		if (offset > ts->next_rx_offset)
			lwsl_warn("%s: %s from %s: the peer's stream starts at "
				  "%llu, we expect %llu.  If the peer kept its "
				  "stream while we restarted, the data before "
				  "it is never sent again, and we hold what "
				  "follows as out of order until we fill up "
				  "and stop taking any\n", __func__,
				  ts->info.ops->name, ts_peer(ts),
				  (unsigned long long)offset,
				  (unsigned long long)ts->next_rx_offset);
	}

	/* Check if we already have this OOO range or part of it, OR cumulative */
	if (offset + len <= ts->next_rx_offset) {
		ts->stats.rx_duplicates++;
		/* DIAGNOSTIC (temporary) */
		if (++ts->diag_dups >= 16 && ts_diag_due(ts->diag_dups))
			lwsl_warn("%s: %s from %s: STUCK RECEIVING: the peer "
				  "has sent data we already have %u times "
				  "since anything new (this time %llu, we have "
				  "all up to %llu).  We ack every one, so our "
				  "acks are not getting back to it, or it "
				  "refuses them: look at its log for STUCK "
				  "SENDING to us, and at the path from us to "
				  "it\n", __func__, ts->info.ops->name,
				  ts_peer(ts), ts->diag_dups,
				  (unsigned long long)offset,
				  (unsigned long long)ts->next_rx_offset);
		ts->info.ops->tx_ack(ts, offset, len);
		return 0;
	}

	/*
	 * Refuse anything outside the receive window outright... along with
	 * the range count cap below, that is what bounds the scoreboard
	 * against an unauthenticated peer choosing arbitrary offsets.
	 */

	if (ts->info.window_size &&
	    offset > ts->next_rx_offset + ts->info.window_size) {
		/* DIAGNOSTIC (temporary) */
		if (ts_diag_due(++ts->diag_drops_window))
			lwsl_warn("%s: %s from %s: STUCK RECEIVING: dropped "
				  "unacked, %u times, a chunk at %llu, past our "
				  "%u window from %llu, where we wait for data "
				  "the peer is not sending.  Eg, it kept its "
				  "stream while we restarted\n", __func__,
				  ts->info.ops->name, ts_peer(ts),
				  ts->diag_drops_window,
				  (unsigned long long)offset,
				  (unsigned int)ts->info.window_size,
				  (unsigned long long)ts->next_rx_offset);
		return 0;
	}

	/*
	 * If it straddles our cumulative point, we already delivered the part
	 * below it... deliver and record only the new part.  Otherwise the
	 * peer can make us re-deliver stream bytes, and leave behind a range
	 * that the retire loop below can never match.  We still ACK what he
	 * actually sent, so he can retire his whole chunk.
	 */

	if (offset < ts->next_rx_offset) {
		size_t adj = (size_t)(ts->next_rx_offset - offset);

		ts->stats.rx_duplicates++;
		buf += adj;
		len -= adj;
		offset = ts->next_rx_offset;
	}

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&ts->rx_scoreboard)) {
		r = lws_container_of(d, struct lws_transport_sequencer_range, list);

		/*
		 * If the arriving packet is entirely within an already received range, it's a duplicate.
		 * For simplicity we only check exact matches or full containment for now.
		 */
		if (offset >= r->offset && offset + len <= (uint64_t)r->offset + r->len) {
			ts->stats.rx_duplicates++;
			ts->info.ops->tx_ack(ts, ack_offset, ack_len);
			return 0;
		}
	} lws_end_foreach_dll(d);

	/*
	 * Don't let him grow the scoreboard without bound by leaving gaps...
	 * dropping the packet is fail-safe, we simply don't ACK it and he
	 * retransmits it once the hole in front of it is filled.
	 */

	if (offset != ts->next_rx_offset &&
	    lws_dll2_count(&ts->rx_scoreboard) >= LWS_TS_MAX_RX_RANGES) {
		/* DIAGNOSTIC (temporary) */
		if (ts_diag_due(++ts->diag_drops_full))
			lwsl_warn("%s: %s from %s: STUCK RECEIVING: dropped "
				  "unacked, %u times, a chunk at %llu: we hold "
				  "%d pieces after a gap from %llu that the "
				  "peer is not filling, and take no more out "
				  "of order.  Eg, it kept its stream while we "
				  "restarted\n", __func__, ts->info.ops->name,
				  ts_peer(ts), ts->diag_drops_full,
				  (unsigned long long)offset,
				  LWS_TS_MAX_RX_RANGES,
				  (unsigned long long)ts->next_rx_offset);
		return 0;
	}

	ts->diag_dups = 0; /* DIAGNOSTIC (temporary): something new */

	/*
	 * Everything the sequencer does with this chunk is done before it is
	 * delivered: on_rx_data is the last thing that sees ts, because the
	 * consumer may destroy the sequencer from inside it, eg, by sending to
	 * enough new peers that its transport recycles this one (G-181).
	 * Delivery is immediate and unconditional, so acking first acks
	 * nothing that is not delivered.  If we cannot record the range, we
	 * neither deliver nor ack it, and the peer retransmits it.
	 */

	r = lws_zalloc(sizeof(*r), __func__);
	if (!r)
		return 1;

	r->offset = offset;
	r->len = (uint32_t)len;
	lws_dll2_add_sorted(&r->list, &ts->rx_scoreboard, range_compare);

	ts->stats.rx_packets++;
	ts->stats.rx_bytes += len;

	/*
	 * Since we deliver immediately, we just need to keep next_rx_offset
	 * up to date for cumulative ACKs by checking the scoreboard for
	 * contiguous blocks, including the one just added.
	 */
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&ts->rx_scoreboard)) {
		r = lws_container_of(d, struct lws_transport_sequencer_range, list);

		if (r->offset > ts->next_rx_offset)
			break;

		/*
		 * This range starts at or before our cumulative point, so it
		 * can only extend it, and either way we have no further use
		 * for it.  Ranges that straddle the cumulative point used to
		 * match neither the "==" nor the "already covered" test and
		 * stayed on the list for the life of the sequencer.
		 */

		if ((uint64_t)r->offset + r->len > ts->next_rx_offset) {
			ts->next_rx_offset = (uint64_t)r->offset + r->len;
			/*
			 * what our acks report as received: not
			 * stats.ack_offset, which is the send half's
			 */
			ts->stats.rx_offset = ts->next_rx_offset;
		}

		lws_dll2_remove(&r->list);
		lws_free(r);

	} lws_end_foreach_dll_safe(d, d1);

	/* Always ACK anything within window */
	ts->info.ops->tx_ack(ts, ack_offset, ack_len);

	/* Deliver immediately - Sparse Transport.  ts may not exist after. */
	return ts->info.ops->on_rx_data(ts, offset, buf, len);
}

void
lws_transport_sequencer_rx_reset(struct lws_transport_sequencer *ts)
{
	lws_dll2_foreach_safe(&ts->rx_scoreboard, NULL, lws_dll2_remove_it);
	ts->next_rx_offset = 0;
	ts->stats.rx_offset = 0;
	ts->diag_rx_started = 0; /* DIAGNOSTIC (temporary) */
	ts->diag_dups = 0;
}

int
lws_transport_sequencer_resend(struct lws_transport_sequencer *ts)
{
	struct lws_transport_sequencer_range *r;
	size_t len;
	void *obj;
	int n;

	if (ts->completed)
		return -1;

	if (lws_dsh_get_head(ts->dsh, 0, &obj, &len))
		return 1;

	/* the transport bound the request to our session: he hears us */
	ts->peer_proven = 1;
	ts->stats.tx_retries++;

	/* the oldest chunk goes now, even if it was held back */
	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&ts->scoreboard)) {
		r = lws_container_of(d, struct lws_transport_sequencer_range,
				     list);
		if (r->dsh_obj == obj) {
			if (!r->sent) {
				r->sent = 1;
				ts->held--;
			}
			break;
		}
	} lws_end_foreach_dll(d);

	n = ts->info.ops->tx_chunk(ts, *(uint64_t *)obj,
				   (uint8_t *)obj + sizeof(uint64_t),
				   len - sizeof(uint64_t));

	/* and gets what we held back from him meanwhile */
	lws_ts_send_held(ts);

	return n < 0 ? -1 : 0;
}

int
lws_transport_sequencer_tx_rebase(struct lws_transport_sequencer *ts)
{
	struct lws_transport_sequencer_range *r;
	uint64_t o = 0;

	if (ts->completed)
		return -1;

	/*
	 * The scoreboard is in offset order, the order the data was written:
	 * renumbering it, and the offset each dsh object starts with, keeps
	 * that order with no gaps.  What was acked, even only selectively,
	 * is no longer in the dsh, and the peer has lost it.
	 */
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&ts->scoreboard)) {
		r = lws_container_of(d, struct lws_transport_sequencer_range,
				     list);

		if (r->acked || !r->dsh_obj) {
			if (!r->sent)
				ts->held--;
			lws_dll2_remove(&r->list);
			lws_free(r);
			continue;
		}

		*(uint64_t *)r->dsh_obj = o;
		r->offset = o;
		o += r->len;
	} lws_end_foreach_dll_safe(d, d1);

	ts->next_tx_offset = o;
	ts->ack_offset = 0;
	ts->stats.ack_offset = 0;

	/*
	 * The retry timer, if it is running, goes on with what is now the
	 * head, so a peer that never acks still fails on time
	 */
	ts->active_offset = 0;

	return 0;
}

LWS_VISIBLE const lws_transport_sequencer_info_t *
lws_transport_sequencer_get_info(struct lws_transport_sequencer *ts)
{
	return &ts->info;
}
LWS_VISIBLE const lws_transport_sequencer_stats_t *
lws_transport_sequencer_get_stats(struct lws_transport_sequencer *ts)
{
	return &ts->stats;
}

LWS_VISIBLE size_t
lws_transport_sequencer_get_sack_blocks(struct lws_transport_sequencer *ts,
					lws_transport_sequencer_sack_block_t *blocks,
					size_t max_blocks)
{
	struct lws_transport_sequencer_range *r;
	size_t n = 0;

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&ts->rx_scoreboard)) {
		r = lws_container_of(d, struct lws_transport_sequencer_range, list);

		if (n >= max_blocks)
			break;

		/* Only report blocks that are beyond the next_rx_offset */
		if (r->offset > ts->next_rx_offset) {
			blocks[n].start = r->offset;
			blocks[n].len = r->len;
			n++;
		}
	} lws_end_foreach_dll(d);

	return n;
}
