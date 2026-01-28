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

typedef struct lws_transport_sequencer_ops {
	const char *name;

	int (*tx_chunk)(struct lws_transport_sequencer *ts, uint64_t offset,
			const uint8_t *buf, size_t len);
	/**< Protocol-specific way to send a data chunk. DHT would wrap this
	 * in its Bencode/CMD frame. */

	int (*tx_ack)(struct lws_transport_sequencer *ts, uint64_t offset,
		      size_t len);
	/**< Protocol-specific way to send an ACK. */

	int (*on_rx_data)(struct lws_transport_sequencer *ts, uint64_t offset,
			  const uint8_t *buf, size_t len);
	/**< Callback when the sequencer has confirmed in-order data reception. */

	void (*on_state_change)(struct lws_transport_sequencer *ts, int state, int status);
	/**< Notify that the sequencer session state changed.
	 * state 0 = SUCCESS, 1 = FAILED.
	 * status is protocol-specific error code (e.g., DHT_STATUS_OUT_OF_STORAGE). */

} lws_transport_sequencer_ops_t;

typedef struct lws_transport_sequencer_stats {
	uint32_t	tx_packets;
	uint32_t	tx_retries;
	uint32_t	rx_packets;
	uint32_t	rx_duplicates;
	uint64_t	tx_bytes;
	uint64_t	rx_bytes;
	uint64_t	ack_offset;
} lws_transport_sequencer_stats_t;

typedef struct lws_transport_sequencer_info {
	struct lws_context *cx;
	const lws_transport_sequencer_ops_t *ops;
	const lws_retry_bo_t *retry_policy;
	void *user_data;

	uint32_t window_size;
	/**< Maximum unacknowledged data in flight (bytes). */
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
 * lws_transport_sequencer_write() - Queue data for reliable transmission
 *
 * \param ts: sequencer instance
 * \param buf: data to send
 * \param len: length of data
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
 * \param status: protocol status
 */
LWS_VISIBLE LWS_EXTERN int
lws_transport_sequencer_acknowledge_sack(struct lws_transport_sequencer *ts,
					 uint64_t cumulative_offset,
					 const lws_transport_sequencer_sack_block_t *blocks,
					 size_t num_blocks, int status);

LWS_VISIBLE LWS_EXTERN const lws_transport_sequencer_stats_t *
lws_transport_sequencer_get_stats(struct lws_transport_sequencer *ts);

/**
 * lws_transport_sequencer_rx() - Pass received raw data chunk to sequencer
 *
 * \param ts: sequencer instance
 * \param offset: offset from the frame
 * \param buf: payload data
 * \param len: payload length
 */
LWS_VISIBLE LWS_EXTERN int
lws_transport_sequencer_rx(struct lws_transport_sequencer *ts,
			   uint64_t offset, const uint8_t *buf, size_t len);

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
