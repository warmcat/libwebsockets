/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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
 * These are exports needed by event lib plugins.
 *
 * You should consider these opaque for normal user code.
 */

LWS_VISIBLE LWS_EXTERN void *
lws_realloc(void *ptr, size_t size, const char *reason);

LWS_VISIBLE LWS_EXTERN void
lws_vhost_destroy1(struct lws_vhost *vh);

LWS_VISIBLE LWS_EXTERN void
lws_close_free_wsi(struct lws *wsi, enum lws_close_status reason,
		   const char *caller);

struct lws_context_per_thread;
LWS_VISIBLE LWS_EXTERN void
lws_service_do_ripe_rxflow(struct lws_context_per_thread *pt);

#if !defined(wsi_from_fd) && !defined(WIN32) && !defined(_WIN32)
struct lws_context;
LWS_VISIBLE LWS_EXTERN struct lws *
wsi_from_fd(const struct lws_context *context, int fd);
#endif

LWS_VISIBLE LWS_EXTERN int
_lws_plat_service_forced_tsi(struct lws_context *context, int tsi);

LWS_VISIBLE LWS_EXTERN void
lws_context_destroy2(struct lws_context *context);

LWS_VISIBLE LWS_EXTERN void
lws_destroy_event_pipe(struct lws *wsi);

LWS_VISIBLE LWS_EXTERN void
__lws_close_free_wsi_final(struct lws *wsi);

#if LWS_MAX_SMP > 1

struct lws_mutex_refcount {
	pthread_mutex_t lock;
	pthread_t lock_owner;
	const char *last_lock_reason;
	char lock_depth;
	char metadata;
};

LWS_VISIBLE LWS_EXTERN void
lws_mutex_refcount_assert_held(struct lws_mutex_refcount *mr);

LWS_VISIBLE LWS_EXTERN void
lws_mutex_refcount_init(struct lws_mutex_refcount *mr);

LWS_VISIBLE LWS_EXTERN void
lws_mutex_refcount_destroy(struct lws_mutex_refcount *mr);

LWS_VISIBLE LWS_EXTERN void
lws_mutex_refcount_lock(struct lws_mutex_refcount *mr, const char *reason);

LWS_VISIBLE LWS_EXTERN void
lws_mutex_refcount_unlock(struct lws_mutex_refcount *mr);

#endif
