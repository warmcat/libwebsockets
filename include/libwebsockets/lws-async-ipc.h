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

#ifndef _LWS_ASYNC_IPC_H_
#define _LWS_ASYNC_IPC_H_

struct lws_async_ipc;

typedef enum {
	LWS_ASYNC_IPC_STATE_CONNECTED,
	LWS_ASYNC_IPC_STATE_RX,
	LWS_ASYNC_IPC_STATE_TIMEOUT,
	LWS_ASYNC_IPC_STATE_ERROR,
	LWS_ASYNC_IPC_STATE_DESTROYED,
} lws_async_ipc_state_t;

struct lws_async_ipc_cb_args {
	struct lws_async_ipc		*ipc;
	lws_async_ipc_state_t		state;
	const void			*data;
	size_t				len;
	void				*opaque;
};

typedef int (*lws_async_ipc_cb_t)(const struct lws_async_ipc_cb_args *args);

struct lws_async_ipc_info {
	struct lws_context		*cx;
	const char			*uds_path;
	lws_async_ipc_cb_t		cb;
	void				*opaque;
};

LWS_VISIBLE LWS_EXTERN struct lws_async_ipc *
lws_async_ipc_create(const struct lws_async_ipc_info *info);

LWS_VISIBLE LWS_EXTERN void
lws_async_ipc_destroy(struct lws_async_ipc **ipc);

LWS_VISIBLE LWS_EXTERN int
lws_async_ipc_queue_payload(struct lws_async_ipc *ipc,
			    const void *payload, size_t len);

#endif
