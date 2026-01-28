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
};

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
	lws_dsh_t			*dsh;

	lws_dll2_owner_t		scoreboard; /* sender side ranges */
	lws_dll2_owner_t		rx_scoreboard; /* receiver side ranges */

	uint64_t			next_tx_offset; /* Highest byte sent + 1 */
	uint64_t			ack_offset;     /* Cumulative ACK point */
	uint64_t			next_rx_offset; /* Cumulative receive point */
	uint64_t			active_offset; /* offset of currently in-flight chunk */

	uint16_t			retry_count;
	uint16_t			active_len;

	uint8_t				completed:1;
	lws_transport_sequencer_stats_t	stats;
};

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

	if (ts->retry_count >= ts->info.retry_policy->conceal_count) {
		lwsl_notice("%s: Retry limit reached (%d), failing session\n",
			    __func__, ts->retry_count);
		ts->completed = 1;
		if (ts->info.ops->on_state_change)
			ts->info.ops->on_state_change(ts, 1 /* FAILED */, 0);
		return;
	}

	ts->retry_count++;
	ts->stats.tx_retries++;

	/* Call protocol-specific TX hook with data after the offset prefix */
	ts->info.ops->tx_chunk(ts, *p_off, (uint8_t *)obj + sizeof(uint64_t),
				len - sizeof(uint64_t));

	/* Schedule next timeout */
	lws_retry_sul_schedule(ts->info.cx, 0, &ts->sul_retry,
				 ts->info.retry_policy, sul_retry_cb,
				 &ts->retry_count);
}

struct lws_transport_sequencer *
lws_transport_sequencer_create(const lws_transport_sequencer_info_t *i)
{
	struct lws_transport_sequencer *ts = lws_zalloc(sizeof(*ts), __func__);

	if (!ts)
		return NULL;

	ts->info = *i;

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
	if (ts->dsh)
		lws_dsh_destroy(&ts->dsh);

	lws_dll2_foreach_safe(&ts->scoreboard, NULL, lws_dll2_remove_it);
	lws_dll2_foreach_safe(&ts->rx_scoreboard, NULL, lws_dll2_remove_it);

	lws_free(ts);
	*pts = NULL;
}

int
lws_transport_sequencer_write_at(struct lws_transport_sequencer *ts,
				 uint64_t offset, const uint8_t *buf, size_t len)
{
	struct lws_transport_sequencer_range *r;

	if (ts->completed)
		return 1;

	/* Windowing is now heap-limited by DSH, not range-based */

	/* Buffer in DSH with offset prefix */
	if (lws_dsh_alloc_tail(ts->dsh, 0, &offset, sizeof(offset), buf, len)) {
		lwsl_notice("%s: DSH alloc failed\n", __func__);
		return 1;
	}

	r = lws_zalloc(sizeof(*r), __func__);
	if (!r)
		return 1;

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

	/* Always send the packet immediately (Broadsiding) */
	ts->info.ops->tx_chunk(ts, offset, buf, len);
	ts->stats.tx_packets++;
	ts->stats.tx_bytes += len;

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

	return 0;
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
	void *obj;
	uint64_t *p_off;

	if (ts->completed)
		return -1;

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
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, ts->scoreboard.head) {
		r = lws_container_of(d, struct lws_transport_sequencer_range, list);
		if (r->offset + r->len <= cumulative_offset) {
			r->acked = 1;
			if (r->dsh_obj)
				lws_dsh_free(&r->dsh_obj);
		}
	} lws_end_foreach_dll_safe(d, d1);

	/* Mark SACK blocks */
	for (i = 0; i < num_blocks; i++) {
		lws_start_foreach_dll(struct lws_dll2 *, d, ts->scoreboard.head) {
			r = lws_container_of(d, struct lws_transport_sequencer_range, list);
			if (r->offset >= blocks[i].start &&
			    r->offset + r->len <= blocks[i].start + blocks[i].len) {
				r->acked = 1;
				if (r->dsh_obj)
					lws_dsh_free(&r->dsh_obj);
			}
		} lws_end_foreach_dll(d);
	}

	/* Retire contiguous ACKed packets from scoreboard */
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, ts->scoreboard.head) {
		r = lws_container_of(d, struct lws_transport_sequencer_range, list);

		if (!r->acked)
			break;

		/* This contiguous packet is acked, we can retire from scoreboard */
		ts->ack_offset = r->offset + r->len;
		ts->stats.ack_offset = ts->ack_offset;
		if (ts->active_offset == r->offset)
			lws_sul_cancel(&ts->sul_retry);

		lws_dll2_remove(&r->list);
		lws_free(r);
	} lws_end_foreach_dll_safe(d, d1);

	/* Schedule next retransmission from head of DSH if window not empty */
	if (ts->next_tx_offset > ts->ack_offset) {
		if (!lws_dsh_get_head(ts->dsh, 0, &obj, &obj_len)) {
			p_off = (uint64_t *)obj;
			ts->retry_count = 0;
			ts->active_offset = *p_off;
			ts->active_len = (uint16_t)(obj_len - sizeof(uint64_t));

			lws_retry_sul_schedule(ts->info.cx, 0, &ts->sul_retry,
							 ts->info.retry_policy, sul_retry_cb,
							 &ts->retry_count);
		}
	} else {
		if (ts->info.ops->on_state_change && ts->next_tx_offset == ts->ack_offset)
			ts->info.ops->on_state_change(ts, 0 /* SUCCESS */, 0);
	}

	return 0;
}

int
lws_transport_sequencer_acknowledge(struct lws_transport_sequencer *ts,
				    uint64_t offset, size_t len, int status)
{
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

	/* Check if we already have this OOO range or part of it, OR cumulative */
	if (offset + len <= ts->next_rx_offset) {
		ts->stats.rx_duplicates++;
		ts->info.ops->tx_ack(ts, offset, len);
		return 0;
	}

	lws_start_foreach_dll(struct lws_dll2 *, d, ts->rx_scoreboard.head) {
		r = lws_container_of(d, struct lws_transport_sequencer_range, list);

		/*
		 * If the arriving packet is entirely within an already received range, it's a duplicate.
		 * For simplicity we only check exact matches or full containment for now.
		 */
		if (offset >= r->offset && offset + len <= (uint64_t)r->offset + r->len) {
			ts->stats.rx_duplicates++;
			ts->info.ops->tx_ack(ts, offset, len);
			return 0;
		}
	} lws_end_foreach_dll(d);

	/* Deliver immediately - Sparse Transport */
	ts->info.ops->on_rx_data(ts, offset, buf, len);

	/* Update next_rx_offset for cumulative ACK if it matches exactly */
	if (offset == ts->next_rx_offset) {
		ts->next_rx_offset += len;
		ts->stats.ack_offset = ts->next_rx_offset;
	}

	ts->stats.rx_packets++;

	/* Check if we can now retire next_rx_offset from OOO buffered scoreboard...
	 * Wait, if we deliver EVERY packet immediately, we don't need a scoreboard
	 * or DSH buffering for RX at all!
	 *
	 * We still need to ACK it though.
	 */

	r = lws_zalloc(sizeof(*r), __func__);
	if (!r)
		return 1;

	r->offset = offset;
	r->len = (uint32_t)len;
	lws_dll2_add_sorted(&r->list, &ts->rx_scoreboard, range_compare);

	/* Always ACK anything within window */
	ts->stats.rx_bytes += len;

	/*
	 * Since we delivered immediately, we just need to keep next_rx_offset
	 * up to date for cumulative ACKs by checking the scoreboard for contiguous blocks.
	 */
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, ts->rx_scoreboard.head) {
		r = lws_container_of(d, struct lws_transport_sequencer_range, list);

		if (r->offset > ts->next_rx_offset)
			break;

		if (r->offset == ts->next_rx_offset) {
			ts->next_rx_offset += r->len;
			/* Note: for a receiver, ack_offset in stats refers to next_rx_offset */
			ts->stats.ack_offset = ts->next_rx_offset; /* Update stats.ack_offset for RX */
			lws_dll2_remove(&r->list);
			lws_free(r);
		} else if (r->offset + r->len <= ts->next_rx_offset) {
			/* Already covered */
			lws_dll2_remove(&r->list);
			lws_free(r);
		}
	} lws_end_foreach_dll_safe(d, d1);

	ts->info.ops->tx_ack(ts, offset, len);

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

	lws_start_foreach_dll(struct lws_dll2 *, d, ts->rx_scoreboard.head) {
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
