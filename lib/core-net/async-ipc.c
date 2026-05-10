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
#include <string.h>

struct lws_async_ipc_msg {
	lws_dll2_t              list;
	size_t                  len;
	uint8_t                 payload[1]; /* variable length */
};

struct lws_async_ipc {
	struct lws_context      *cx;
        lws_async_ipc_cb_t      cb;
        void                    *opaque;
	char                    uds_path[256];

	struct lws              *wsi;
	lws_dll2_owner_t        msg_queue;
	lws_sorted_usec_list_t  sul_timeout;

	int                     connecting;
};

static void
lws_async_ipc_timeout_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_async_ipc *ipc = lws_container_of(sul, struct lws_async_ipc, sul_timeout);

	lwsl_err("lws_async_ipc: timeout waiting for IPC %s\n", ipc->uds_path);

	/* Clear queue */
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, ipc->msg_queue.head) {
		struct lws_async_ipc_msg *msg = lws_container_of(d, struct lws_async_ipc_msg, list);
		lws_dll2_remove(d);
		lws_free(msg);
	} lws_end_foreach_dll_safe(d, d1);

	if (ipc->wsi) {
		lws_set_timeout(ipc->wsi, 1, LWS_TO_KILL_ASYNC);
		ipc->wsi = NULL;
	}

	ipc->connecting = 0;

	if (ipc->cb) {
		struct lws_async_ipc_cb_args args = {
			.ipc = ipc,
			.state = LWS_ASYNC_IPC_STATE_TIMEOUT,
			.data = NULL,
			.len = 0,
			.opaque = ipc->opaque
		};
		ipc->cb(&args);
	}
}

static int
callback_async_ipc(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	struct lws_async_ipc *ipc = (struct lws_async_ipc *)user;
	struct lws_async_ipc_cb_args args;

	if (ipc) {
		args.ipc        = ipc;
		args.data       = in;
		args.len        = len;
		args.opaque     = ipc->opaque;
	}

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("lws_async_ipc: connection error: %s\n", in ? (char *)in : "unknown");
		if (ipc) {
			ipc->wsi = NULL;
			ipc->connecting = 0;
			lws_sul_cancel(&ipc->sul_timeout);

			/* Clear queue */
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, ipc->msg_queue.head) {
				struct lws_async_ipc_msg *msg = lws_container_of(d, struct lws_async_ipc_msg, list);
				lws_dll2_remove(d);
				lws_free(msg);
			} lws_end_foreach_dll_safe(d, d1);

			if (ipc->cb) {
				args.state = LWS_ASYNC_IPC_STATE_ERROR;
				ipc->cb(&args);
			}
		}
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lwsl_notice("lws_async_ipc: RAW_CONNECTED / ESTABLISHED\n");
		if (ipc) {
			ipc->connecting = 0;
			lws_sul_schedule(ipc->cx, 0, &ipc->sul_timeout, lws_async_ipc_timeout_cb, 5 * LWS_US_PER_SEC);
			lws_callback_on_writable(wsi);

			if (ipc->cb) {
				args.state = LWS_ASYNC_IPC_STATE_CONNECTED;
				args.data  = NULL;
				args.len   = 0;
				ipc->cb(&args);
			}
		}
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
	case LWS_CALLBACK_CLIENT_WRITEABLE:
		lwsl_notice("lws_async_ipc: WRITEABLE (ipc=%p, msg_queue.head=%p)\n", ipc, ipc ? ipc->msg_queue.head : NULL);
		if (ipc && ipc->msg_queue.head) {
			struct lws_async_ipc_msg *msg = lws_container_of(ipc->msg_queue.head, struct lws_async_ipc_msg, list);

			/* Pre-allocate buffer for LWS_PRE padding */
			uint8_t *buf = lws_malloc(LWS_PRE + msg->len, "async_ipc_tx");
			if (buf) {
				memcpy(buf + LWS_PRE, msg->payload, msg->len);
				int m = lws_write(wsi, buf + LWS_PRE, msg->len, LWS_WRITE_RAW);
				lws_free(buf);

				if (m < 0) {
					lwsl_err("lws_async_ipc: write failed\n");
					return -1;
				}

				lws_dll2_remove(&msg->list);
				lws_free(msg);

				/* Extend timeout on successful write, expecting a response soon */
				lws_sul_schedule(ipc->cx, 0, &ipc->sul_timeout, lws_async_ipc_timeout_cb, 5 * LWS_US_PER_SEC);
			}

			if (ipc->msg_queue.head)
				lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_RAW_RX:
	case LWS_CALLBACK_CLIENT_RECEIVE:
		lwsl_notice("lws_async_ipc: RX (%d bytes)\n", (int)len);
		if (ipc) {
			/* Got a response, clear timeout */
			lws_sul_cancel(&ipc->sul_timeout);
			if (ipc->cb) {
				args.state = LWS_ASYNC_IPC_STATE_RX;
				ipc->cb(&args);
			}
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
	case LWS_CALLBACK_CLIENT_CLOSED:
		if (ipc) {
			ipc->wsi = NULL;
			ipc->connecting = 0;
			lws_sul_cancel(&ipc->sul_timeout);
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

const struct lws_protocols lws_async_ipc_protocol = {
	"lws-async-ipc", callback_async_ipc, 0, 0, 0, NULL, 0
};

static int
lws_async_ipc_connect(struct lws_async_ipc *ipc)
{
	struct lws_client_connect_info i;

	if (ipc->wsi || ipc->connecting)
		return 0;

	memset(&i, 0, sizeof(i));
	i.context        = ipc->cx;
	i.address        = ipc->uds_path;
	i.port           = 0; /* indicates UDS */
	i.host           = i.address;
	i.origin         = i.address;
	i.method         = "RAW";
	i.protocol       = "lws-async-ipc";
	i.local_protocol_name = "lws-async-ipc";
	i.userdata       = ipc;
	i.vhost          = lws_get_vhost_by_name(ipc->cx, "default"); /* typically need a vhost */
	if (!i.vhost)
		i.vhost = ipc->cx->vhost_list;

	/* Register the protocol if it's not already in the vhost */
	/* Actually, we should just use the context's internal logic, or register dynamically? */
	/* The cleanest way is to use a custom protocol array for the client connection. */

	ipc->connecting = 1;
	lws_sul_schedule(ipc->cx, 0, &ipc->sul_timeout, lws_async_ipc_timeout_cb, 5 * LWS_US_PER_SEC);

	ipc->wsi = lws_client_connect_via_info(&i);
	if (!ipc->wsi) {
		ipc->connecting = 0;
		lws_sul_cancel(&ipc->sul_timeout);
		return 1;
	}

	return 0;
}

LWS_VISIBLE LWS_EXTERN struct lws_async_ipc *
lws_async_ipc_create(const struct lws_async_ipc_info *info)
{
	struct lws_async_ipc *ipc = lws_zalloc(sizeof(*ipc), "async_ipc");
	if (!ipc)
		return NULL;

	ipc->cx          = info->cx;
	if (info->uds_path && info->uds_path[0] != '+')
		lws_snprintf(ipc->uds_path, sizeof(ipc->uds_path), "+%s", info->uds_path);
	else if (info->uds_path)
		lws_strncpy(ipc->uds_path, info->uds_path, sizeof(ipc->uds_path));
	ipc->cb          = info->cb;
	ipc->opaque      = info->opaque;

	return ipc;
}

LWS_VISIBLE LWS_EXTERN void
lws_async_ipc_destroy(struct lws_async_ipc **_ipc)
{
	struct lws_async_ipc *ipc = *_ipc;
	if (!ipc)
		return;

	if (ipc->wsi) {
		lws_set_timeout(ipc->wsi, 1, LWS_TO_KILL_ASYNC);
		ipc->wsi = NULL;
	}

	lws_sul_cancel(&ipc->sul_timeout);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, ipc->msg_queue.head) {
		struct lws_async_ipc_msg *msg = lws_container_of(d, struct lws_async_ipc_msg, list);
		lws_dll2_remove(d);
		lws_free(msg);
	} lws_end_foreach_dll_safe(d, d1);

	if (ipc->cb) {
		struct lws_async_ipc_cb_args args = {
			.ipc    = ipc,
			.state  = LWS_ASYNC_IPC_STATE_DESTROYED,
			.data   = NULL,
			.len    = 0,
			.opaque = ipc->opaque
		};
		ipc->cb(&args);
	}

	lws_free(ipc);
	*_ipc = NULL;
}

LWS_VISIBLE LWS_EXTERN int
lws_async_ipc_queue_payload(struct lws_async_ipc *ipc,
			    const void *payload, size_t len)
{
	struct lws_async_ipc_msg *msg = lws_malloc(sizeof(*msg) + len, "async_ipc_msg");
	if (!msg)
		return 1;

	memset(msg, 0, sizeof(*msg));
	msg->len = len;
	memcpy(msg->payload, payload, len);

	lws_dll2_add_tail(&msg->list, &ipc->msg_queue);

	if (ipc->wsi)
		lws_callback_on_writable(ipc->wsi);
	else
		lws_async_ipc_connect(ipc);

	return 0;
}
