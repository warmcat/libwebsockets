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
 *
 * async-queue.c: the worker threads a source hands blocking work to (a
 * file read for the http file server).  A worker pool is neither half of
 * the sans-IO split: it moves no bytes and decides nothing about them.
 */

#include "private-lib-core.h"

#if defined(LWS_WITH_ASYNC_QUEUE)

void *
lws_async_worker_worker(void *d)
{
	struct lws_context *cx = (struct lws_context *)d;
	struct lws_async_job *job;
	struct lws_dll2 *d2;

	pthread_mutex_lock(&cx->async_worker_mutex);
	while (!cx->being_destroyed) {
		d2 = lws_dll2_get_head(&cx->async_worker_waiting);
		if (!d2) {
			/* Scale down if we have multiple threads but no waiting work */
			if (cx->async_worker_threads_active > 1) {
				/* Wake up the next sleeping thread so it evaluates whether to exit */
				pthread_cond_signal(&cx->async_worker_cond);
				break;
			}
			/* Wait until work arrives or destruction */
			cx->async_worker_threads_idle++;
			pthread_cond_wait(&cx->async_worker_cond, &cx->async_worker_mutex);
			cx->async_worker_threads_idle--;
			continue;
		}

		job = lws_container_of(d2, struct lws_async_job, list);
		lws_dll2_remove(&job->list);
		pthread_mutex_unlock(&cx->async_worker_mutex);

		/* Do the blocking I/O */
		if (job->wsi) {
			switch (job->type) {
			case LWS_AQ_FILE_READ:
				job->u.fs.amount = 0;
				if (lws_vfs_file_read(job->u.fs.fop_fd, &job->u.fs.amount, job->u.fs.buf, job->u.fs.len) < 0) {
					job->u.fs.amount = (lws_filepos_t)-1; /* Error */
				}
				break;
			case LWS_AQ_SSL_ACCEPT:
#if defined(LWS_WITH_TLS) && defined(LWS_WITH_SERVER)
				// lwsl_notice("worker handling LWS_AQ_SSL_ACCEPT for wsi %s\n", lws_wsi_tag(job->wsi));
				job->wsi->io.tls.ssl_accept_in_bg = 1;
				job->u.ssl.status = lws_tls_server_accept(job->wsi);
				job->wsi->io.tls.ssl_accept_in_bg = 0;
				// lwsl_notice("worker finished LWS_AQ_SSL_ACCEPT, st %d\n", job->u.ssl.status);
#endif
				break;
			default:
				break;
			}
		} else {
			/* WSI is gone, we don't care about the result, but still cleanly finish if we were already reading */
			if (job->type == LWS_AQ_FILE_READ)
				job->u.fs.amount = (lws_filepos_t)-1;
		}

		/* Done reading, re-acquire to post result or cleanup */
		pthread_mutex_lock(&cx->async_worker_mutex);

		if (!job->wsi) {
			/* The connection was closed while we were reading or waiting */
			lws_free(job);
		} else {
			/* The WSI still exists! Wake the event loop using cancel service */
			lws_dll2_add_tail(&job->list, &cx->async_worker_finished);
			lws_cancel_service(cx);
		}

		/* Scale down check previously at the end of job is removed; it's handled at top-of-loop */
	}

	cx->async_worker_threads_active--;
	pthread_mutex_unlock(&cx->async_worker_mutex);

	return NULL;
}

/*
 * Hand a job to the async worker threads, starting one if none is idle and
 * the limit allows.  Returns 1 when the queue is saturated: the caller does
 * the work inline instead, as a build without the queue does.
 */
int
lws_async_queue_submit(struct lws_context *cx, struct lws_async_job *job)
{
	pthread_mutex_lock(&cx->async_worker_mutex);
	if (lws_dll2_count(&cx->async_worker_waiting) >=
	    (uint32_t)(cx->count_async_threads * 10)) {
		pthread_mutex_unlock(&cx->async_worker_mutex);

		return 1;
	}

	lws_dll2_add_tail(&job->list, &cx->async_worker_waiting);

	/* Scale threads up to limit if needed */
	if (cx->async_worker_threads_idle == 0 &&
	    cx->async_worker_threads_active < cx->count_async_threads) {
		pthread_t pt;

		cx->async_worker_threads_active++;
		if (pthread_create(&pt, NULL, lws_async_worker_worker, cx) == 0)
			pthread_detach(pt);
		else
			cx->async_worker_threads_active--;
	}

	pthread_cond_signal(&cx->async_worker_cond);
	pthread_mutex_unlock(&cx->async_worker_mutex);

	return 0;
}
#endif
