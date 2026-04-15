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

#ifndef _LWS_TXPACER_H
#define _LWS_TXPACER_H

#if defined(LWS_HAVE_PTHREAD_H)

struct lws_txp;

typedef struct lws_txp_info {
	void		*user;
	int		(*tx_cb)(void *user, const uint8_t *buf, size_t len);

	uint32_t	target_rate_bps;    /* Target bits per second */
	uint32_t	interval_us;        /* Pacing interval (e.g., 2000 for 2ms) */
	size_t		max_buflist_bytes;  /* Max buffering before packet drop */

} lws_txp_info_t;

/**
 * lws_txp_create() - Create a generic TX pacer (Leaky Bucket Shaper)
 *
 * \param txp_info:	Configuration and callbacks
 *
 * Spawns a high-resolution pthread dedicated to calling your `tx_cb`
 * at precise intervals until the accumulated token bucket is empty.
 * Returns an opaque control struct.
 */
LWS_VISIBLE LWS_EXTERN struct lws_txp *
lws_txp_create(const lws_txp_info_t *txp_info);

/**
 * lws_txp_destroy() - Safely drain and destroy a TX pacer
 *
 * \param ptxp:	Pointer to your pointer to the txpacer
 *
 * Gracefully signals the pacer thread to exit, waits for join, and
 * frees all resources, including draining any un-sent packets.
 * Set ptxp to NULL gracefully.
 */
LWS_VISIBLE LWS_EXTERN void
lws_txp_destroy(struct lws_txp **ptxp);

/**
 * lws_txp_append() - Queue a packet to be sent by the pacer
 *
 * \param txp:	The pacer struct
 * \param buf:	The packet heap allocation (Must be from lws_malloc)
 * \param len:	The exact size of the payload inside `buf`
 *
 * Transfers ownership of `buf` to the pacer. If the pacer drops the packet
 * (e.g. because max_buflist_bytes is reached), it will immediately `lws_free()` it.
 * Otherwise, it will free it after your `tx_cb` fires.
 *
 * Return 0 if successfully accepted, or < 0 if dropped.
 */
LWS_VISIBLE LWS_EXTERN int
lws_txp_append(struct lws_txp *txp, uint8_t *buf, size_t len);

#endif /* LWS_HAVE_PTHREAD_H */

#endif /* _LWS_TXPACER_H */
