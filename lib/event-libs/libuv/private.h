/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2018 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 *  This is included from core/private.h if LWS_WITH_LIBUV
 */

#include <uv.h>

/*
 * libuv's async destroy cb means that asking to close something doesn't mean
 * you can destroy it or parent things until after the close completes.
 *
 * So we must reference-count creation and close completions with libuv.
 *
 * All "static" (per-pt or per-context) uv handles must
 *
 *  - have their .data set to point to the context
 *
 *  - contribute to context->uv_count_static_asset_handles
 *    counting
 */
#define LWS_UV_REFCOUNT_STATIC_HANDLE_NEW(_x, _ctx) \
		{ uv_handle_t *_uht = (uv_handle_t *)(_x); _uht->data = _ctx; \
		_ctx->count_event_loop_static_asset_handles++; }
#define LWS_UV_REFCOUNT_STATIC_HANDLE_TO_CONTEXT(_x) \
		((struct lws_context *)((uv_handle_t *)((_x)->data)))
#define LWS_UV_REFCOUNT_STATIC_HANDLE_DESTROYED(_x) \
		(--(LWS_UV_REFCOUNT_STATIC_HANDLE_TO_CONTEXT(_x)-> \
				count_event_loop_static_asset_handles))

struct lws_pt_eventlibs_libuv {
	uv_loop_t *io_loop;
	uv_signal_t signals[8];
	uv_timer_t timeout_watcher;
	uv_timer_t hrtimer;
	uv_idle_t idle;
};

struct lws_context_eventlibs_libuv {
	uv_loop_t loop;
};

struct lws_io_watcher_libuv {
	uv_poll_t watcher;
};

struct lws_signal_watcher_libuv {
	uv_signal_t watcher;
};

extern struct lws_event_loop_ops event_loop_ops_uv;

LWS_VISIBLE uv_loop_t *
lws_uv_getloop(struct lws_context *context, int tsi);
