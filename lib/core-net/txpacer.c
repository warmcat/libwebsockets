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

#if defined(LWS_HAVE_PTHREAD_H)

struct lws_txp {
	lws_txp_info_t		txp_info;

	pthread_t		thread;
	pthread_mutex_t		lock;
	pthread_cond_t		cond;

	struct lws_buflist	*buflist;
	size_t			buflist_len;

	int			exit_req;

	int64_t			tokens;       /* bytes allowed to send */
	int64_t			bucket_size;  /* maximum burst budget in bytes */
	uint64_t		byte_rate_s;   /* target bytes per second */
};

static void *
lws_txpacer_thread(void *d)
{
	struct lws_txp *txp = (struct lws_txp *)d;
	lws_usec_t last_us = lws_now_usecs();

	pthread_mutex_lock(&txp->lock);

	while (!txp->exit_req) {
		/* Calculate token replenishment */
		lws_usec_t now_us = lws_now_usecs();
		int64_t elapsed_us = (int64_t)(now_us - last_us);

		if (elapsed_us > 0) {
			if (elapsed_us > 2000000000ll) /* 2000s max to prevent math overflow */
				elapsed_us = 2000000000ll;
			txp->tokens += (int64_t)(((uint64_t)elapsed_us * txp->byte_rate_s) / 1000000);
			if (txp->tokens > txp->bucket_size)
				txp->tokens = txp->bucket_size;
		}
		last_us = now_us;

		/* Drain packets as long as we have tokens */
		while (!txp->exit_req && txp->tokens > 0) {
			uint8_t *buf = NULL;
			size_t len = lws_buflist_next_segment_len(&txp->buflist, &buf);

			if (!len || !buf)
				break;

			/* We process the full segment (packet) atomically */
			if (txp->txp_info.tx_cb) {
				txp->txp_info.tx_cb(txp->txp_info.user, buf, len);
			}

			txp->tokens -= (int64_t)len;
			txp->buflist_len -= len;
			lws_buflist_use_segment(&txp->buflist, len);
		}

		if (txp->exit_req)
			break;

		if (!txp->buflist) {
			/* No packets queued. Sleep indefinitely until woken by append or exit. */
			pthread_cond_wait(&txp->cond, &txp->lock);
		} else {
			/* Calculate sleep time */
			struct timespec ts;
			lws_usec_t target_us = lws_now_usecs() + txp->txp_info.interval_us;
			ts.tv_sec = (time_t)(target_us / 1000000);
			ts.tv_nsec = (long)((target_us % 1000000) * 1000);

			/* Wait for signal (new packet) or timeout (next pacing tick) */
			pthread_cond_timedwait(&txp->cond, &txp->lock, &ts);
		}
	}

	pthread_mutex_unlock(&txp->lock);
	return NULL;
}

LWS_VISIBLE LWS_EXTERN struct lws_txp *
lws_txp_create(const lws_txp_info_t *txp_info)
{
	struct lws_txp *txp = lws_zalloc(sizeof(*txp), __func__);

	if (!txp)
		return NULL;

	txp->txp_info = *txp_info;
	txp->byte_rate_s = txp_info->target_rate_bps / 8;

	/* Allow bursting up to 2 intervals worth of data, or at least 4KB */
	txp->bucket_size = (int64_t)(txp->byte_rate_s * txp_info->interval_us * 2 / 1000000);
	if (txp->bucket_size < 4096)
		txp->bucket_size = 4096;

	txp->tokens = txp->bucket_size;

	pthread_mutex_init(&txp->lock, NULL);
	pthread_cond_init(&txp->cond, NULL);

	if (pthread_create(&txp->thread, NULL, lws_txpacer_thread, txp)) {
		pthread_cond_destroy(&txp->cond);
		pthread_mutex_destroy(&txp->lock);
		lws_free(txp);
		return NULL;
	}

	return txp;
}

LWS_VISIBLE LWS_EXTERN void
lws_txp_destroy(struct lws_txp **ptxp)
{
	struct lws_txp *txp;

	if (!ptxp || !*ptxp)
		return;

	txp = *ptxp;
	*ptxp = NULL;

	pthread_mutex_lock(&txp->lock);
	txp->exit_req = 1;
	pthread_cond_signal(&txp->cond);
	pthread_mutex_unlock(&txp->lock);

	pthread_join(txp->thread, NULL);

	/* Clean up any abandoned buffers */
	lws_buflist_destroy_all_segments(&txp->buflist);

	pthread_cond_destroy(&txp->cond);
	pthread_mutex_destroy(&txp->lock);

	lws_free(txp);
}

LWS_VISIBLE LWS_EXTERN int
lws_txp_append(struct lws_txp *txp, uint8_t *buf, size_t len)
{
	int ret = 0;

	if (!txp || !buf || !len)
		return -1;

	pthread_mutex_lock(&txp->lock);

	if (txp->txp_info.max_buflist_bytes && txp->buflist_len + len > txp->txp_info.max_buflist_bytes) {
		/* Queue is full, drop it to enforce backpressure */
		lws_free(buf);
		ret = -1;
		goto bail;
	}

	if (lws_buflist_append_segment_take_ownership(&txp->buflist, buf, len) < 0) {
		lws_free(buf);
		ret = -1;
		goto bail;
	}

	txp->buflist_len += len;

	/* Signal thread to wake up immediately if it was idling with empty queue */
	pthread_cond_signal(&txp->cond);

bail:
	pthread_mutex_unlock(&txp->lock);
	return ret;
}

#endif /* LWS_HAVE_PTHREAD_H */
