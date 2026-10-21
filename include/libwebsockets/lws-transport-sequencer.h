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
#if !defined(__LWS_TRANSPORT_SEQUENCER_H__)
#define __LWS_TRANSPORT_SEQUENCER_H__

#include <stdint.h>
#include <stddef.h>

#if defined(LWS_WITH_TRANSPORT_SEQUENCER)


/** \defgroup transport_sequencer Transport Sequencer
 * ##Transport Sequencer
 *
 * lws_transport_sequencer provides a generic layer for reliable delivery over
 * unreliable transports (like raw UDP). It handles sequencing,
 * acknowledgments, retransmissions with backoff, and flow control.
 */
/**@{*/

struct lws_transport_sequencer;

typedef int (*lws_transport_sequencer_cb_t)(struct lws_transport_sequencer *ts,
					    uint64_t offset, uint8_t *buf,
					    size_t *len);

typedef struct lws_transport_sequencer_sack_block {
	uint64_t	start;
	uint32_t	len;
} lws_transport_sequencer_sack_block_t;

/*
 * Lifetime: tx_chunk and tx_ack are called in the middle of the sequencer's
 * work and must not destroy it.  on_rx_data and on_state_change are always
 * the last thing the sequencer does before returning to its caller, and it
 * does not touch ts after them, so they (or what they call) may destroy it.
 * A caller of lws_transport_sequencer_rx(), _acknowledge(), or
 * _acknowledge_sack() must not use ts after it returns, unless it knows its
 * callbacks did not destroy it.
 */

typedef struct lws_transport_sequencer_ops {
	const char *name;

	int (*tx_chunk)(struct lws_transport_sequencer *ts, uint64_t offset,
			const uint8_t *buf, size_t len);
	/**< Protocol-specific way to send a data chunk. DHT would wrap this
	 * in its Bencode/CMD frame.  Must not destroy the sequencer. */

	int (*tx_ack)(struct lws_transport_sequencer *ts, uint64_t offset,
		      size_t len);
	/**< Protocol-specific way to send an ACK.  Must not destroy the
	 * sequencer. */

	int (*on_rx_data)(struct lws_transport_sequencer *ts, uint64_t offset,
			  const uint8_t *buf, size_t len);
	/**< Delivers received data.  The chunk has already been recorded and
	 * acked, and this is the last thing lws_transport_sequencer_rx()
	 * does: it may destroy the sequencer.  Its return is what
	 * lws_transport_sequencer_rx() returns. */

	void (*on_state_change)(struct lws_transport_sequencer *ts, int state, int status);
	/**< Notify that the sequencer session state changed.
	 * state 0 = SUCCESS, 1 = FAILED.
	 * status is protocol-specific error code (e.g., DHT_STATUS_OUT_OF_STORAGE).
	 * This is the last thing the sequencer does: it may destroy it. */

	void (*on_writeable)(struct lws_transport_sequencer *ts);
	/**< Optional.  A write was refused with LWS_TSW_BUSY, and the peer
	 * has since acknowledged enough to make room: write again.  Called
	 * once per refusal episode, from the event loop and not from inside
	 * any sequencer api, so it may write, or destroy the sequencer.  If
	 * the session fails before there is room, on_state_change() reports
	 * that instead. */

} lws_transport_sequencer_ops_t;

typedef struct lws_transport_sequencer_stats {
	uint32_t	tx_packets;
	uint32_t	tx_retries;
	uint32_t	rx_packets;
	uint32_t	rx_duplicates;
	uint64_t	tx_bytes;
	uint64_t	rx_bytes;
	uint64_t	ack_offset;
	/**< send half: the peer has acknowledged everything we sent below
	 * this offset */
	uint64_t	rx_offset;
	/**< receive half: we have received everything the peer sent below
	 * this offset, the cumulative point our acks report */
} lws_transport_sequencer_stats_t;

typedef struct lws_transport_sequencer_info {
	struct lws_context *cx;
	const lws_transport_sequencer_ops_t *ops;
	const lws_retry_bo_t *retry_policy;
	void *user_data;

	uint32_t window_size;
	/**< Maximum unacknowledged data in flight (bytes). */

	uint8_t unproven_peer:1;
	/**< The peer's address is not known to be genuine: it spoke to us
	 * first, over a transport where the source address can be forged.
	 * Nothing is retransmitted to it until it has acknowledged data we
	 * sent, so a forged source gets at most one copy of anything we
	 * send in reply, not one per retry.  And after the first chunk, we
	 * send it at most a small allowance more than it has sent us: the
	 * rest is kept, and sent in order once it has acknowledged
	 * something, so a forged source cannot have us send its victim
	 * more than it sent us. */
} lws_transport_sequencer_info_t;

/**
 * lws_transport_sequencer_create() - Create a new sequencer instance
 *
 * \param i: sequencer creation information
 */
LWS_VISIBLE LWS_EXTERN struct lws_transport_sequencer *
lws_transport_sequencer_create(const lws_transport_sequencer_info_t *i);

/**
 * lws_transport_sequencer_destroy() - Destroy a sequencer instance
 *
 * \param pts: pointer to sequencer pointer to be destroyed and set to NULL
 */
LWS_VISIBLE LWS_EXTERN void
lws_transport_sequencer_destroy(struct lws_transport_sequencer **pts);

/**
 * enum lws_transport_sequencer_write_result - what became of a write
 */
enum lws_transport_sequencer_write_result {
	LWS_TSW_QUEUED		= 0,
	/**< taken, it is sent and kept until it is acknowledged */
	LWS_TSW_FAILED		= 1,
	/**< refused, it never can be: the session is over, or OOM */
	LWS_TSW_BUSY		= 2,
	/**< refused for now: the tx buffer is full of data the peer has not
	 * acknowledged.  ops->on_writeable() is called when there is room,
	 * unless the session fails first */
};

/**
 * lws_transport_sequencer_write() - Queue data for reliable transmission
 *
 * \param ts: sequencer instance
 * \param buf: data to send
 * \param len: length of data
 *
 * The sequencer keeps what it sends until the peer acknowledges it, in a
 * fixed buffer of about twice the window size.  When that is full, the write
 * is refused with LWS_TSW_BUSY, and the caller must keep it and write it
 * again from ops->on_writeable().
 *
 * Returns an enum lws_transport_sequencer_write_result.
 */
LWS_VISIBLE LWS_EXTERN int
lws_transport_sequencer_write(struct lws_transport_sequencer *ts,
			      const uint8_t *buf, size_t len);

/**
 * lws_transport_sequencer_write_at() - Queue data at specific offset
 *
 * \param ts: sequencer instance
 * \param offset: absolute offset in the stream
 * \param buf: data to send
 * \param len: length of data
 *
 * The offset must be within [ack_offset, ack_offset + window_size].
 *
 * Returns as lws_transport_sequencer_write().
 */
LWS_VISIBLE LWS_EXTERN int
lws_transport_sequencer_write_at(struct lws_transport_sequencer *ts,
				 uint64_t offset, const uint8_t *buf, size_t len);

/**
 * lws_transport_sequencer_acknowledge() - Inform sequencer that data was ACKed
 *
 * \param ts: sequencer instance
 * \param offset: the offset acknowledged by the peer
 * \param len: the length acknowledged
 * \param status: protocol status, nonzero fails the session
 *
 * As lws_transport_sequencer_acknowledge_sack(), for one acknowledged range.
 */
LWS_VISIBLE LWS_EXTERN int
lws_transport_sequencer_acknowledge(struct lws_transport_sequencer *ts,
				    uint64_t offset, size_t len, int status);

/**
 * lws_transport_sequencer_acknowledge_sack() - Inform sequencer of OOO ACKs
 *
 * \param ts: sequencer instance
 * \param cumulative_offset: the highest contiguous offset acknowledged
 * \param blocks: pointer to array of SACK blocks
 * \param num_blocks: number of SACK blocks
 * \param status: protocol status, nonzero fails the session
 *
 * The sequencer cannot tell a real ack from a forged one: the transport must
 * only pass it acks it has bound to this session, eg, by a random nonce sent
 * with the data that the peer must echo, not just by source address, which
 * can be spoofed on datagram transports.  An ack retires the data it covers
 * and proves an `unproven_peer`.
 *
 * An ack covering bytes that were never sent (the cumulative offset or any
 * SACK block beyond the highest offset sent) is refused whole and returns -1:
 * nothing is retired and the peer is not proven by it.  Since the transport
 * bound the ack to the session, the peer is broken or hostile.
 *
 * Returns 0 if the ack was taken, 1 if the session is already over, or -1 if
 * it was refused.
 */
LWS_VISIBLE LWS_EXTERN int
lws_transport_sequencer_acknowledge_sack(struct lws_transport_sequencer *ts,
					 uint64_t cumulative_offset,
					 const lws_transport_sequencer_sack_block_t *blocks,
					 size_t num_blocks, int status);

/**
 * lws_transport_sequencer_resend() - Send the oldest unacknowledged chunk now
 *
 * \param ts: sequencer instance
 *
 * For a peer that asks, through an exchange the transport has bound to this
 * session as it must an ack (see lws_transport_sequencer_acknowledge_sack()),
 * for our data again, eg, because it did not recognise our session and wants
 * it proven.  Having answered our session, the peer receives from us, so an
 * `unproven_peer` is proven.  The retry schedule is not changed, so a session
 * the peer never acknowledges still fails on time.
 *
 * Returns 0 if a chunk was sent, 1 if nothing is waiting to be acked, or -1
 * if the session is over.
 */
LWS_VISIBLE LWS_EXTERN int
lws_transport_sequencer_resend(struct lws_transport_sequencer *ts);

LWS_VISIBLE LWS_EXTERN const lws_transport_sequencer_stats_t *
lws_transport_sequencer_get_stats(struct lws_transport_sequencer *ts);

/**
 * lws_transport_sequencer_rx() - Pass received raw data chunk to sequencer
 *
 * \param ts: sequencer instance
 * \param offset: offset from the frame
 * \param buf: payload data
 * \param len: payload length
 *
 * The transport must only pass chunks it has bound to the peer's session: see
 * lws_transport_sequencer_rx_reset().
 *
 * A new chunk is recorded and acked, then delivered with ops->on_rx_data(),
 * which may destroy the sequencer: ts must not be used after this returns,
 * unless the caller knows on_rx_data did not destroy it.
 *
 * Returns what on_rx_data returned for a delivered chunk, 0 for a chunk that
 * was not delivered (a duplicate, or outside the window), or 1 if the chunk
 * could not be recorded (it is neither delivered nor acked).
 */
LWS_VISIBLE LWS_EXTERN int
lws_transport_sequencer_rx(struct lws_transport_sequencer *ts,
			   uint64_t offset, const uint8_t *buf, size_t len);

/**
 * lws_transport_sequencer_rx_reset() - Start a new receive stream from 0
 *
 * \param ts: sequencer instance
 *
 * The receive half only knows offsets: it cannot tell the peer's chunks from
 * forged ones, or a peer that restarted its stream from one repeating old
 * chunks.  The transport binds the receive half to the peer's session, and
 * only passes it chunks of that session.  When it has proof the peer began a
 * new session, it calls this to forget what was received of the old one, so
 * the new one is received from offset 0.  The send half is not affected.
 */
LWS_VISIBLE LWS_EXTERN void
lws_transport_sequencer_rx_reset(struct lws_transport_sequencer *ts);

/**
 * lws_transport_sequencer_get_sack_blocks() - Get OOO blocks for SACK
 *
 * \param ts: sequencer instance
 * \param blocks: pointer to array to be filled
 * \param max_blocks: capacity of the array
 *
 * Returns number of blocks filled.
 */
LWS_VISIBLE LWS_EXTERN size_t
lws_transport_sequencer_get_sack_blocks(struct lws_transport_sequencer *ts,
					lws_transport_sequencer_sack_block_t *blocks,
					size_t max_blocks);

LWS_VISIBLE LWS_EXTERN const lws_transport_sequencer_info_t *
lws_transport_sequencer_get_info(struct lws_transport_sequencer *ts);

/**@}*/

#endif /* LWS_WITH_TRANSPORT_SEQUENCER */

#endif /* __LWS_TRANSPORT_SEQUENCER_H__ */
