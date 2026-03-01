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

#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>

struct per_vhost_data__latency {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;
};

struct per_session_data__latency {
	struct per_vhost_data__latency *vhd;
	uint64_t last_since_us;
};

static int
callback_latency(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	struct per_session_data__latency *pss =
			(struct per_session_data__latency *)user;
	struct per_vhost_data__latency *vhd =
			(struct per_vhost_data__latency *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	uint8_t buf[LWS_PRE + 2048];
	int n, m;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__latency));
		if (!vhd)
			return -1;
		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);
		break;

	case LWS_CALLBACK_ESTABLISHED:
		pss->vhd = vhd;
		pss->last_since_us = 0;
		lws_set_timer_usecs(wsi, 200 * LWS_US_PER_MS);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		{
#if defined(LWS_WITH_LATENCY)
			n = lws_latency_get_json(vhd->context, 0, pss->last_since_us,
						 (char *)&buf[LWS_PRE], sizeof(buf) - LWS_PRE);
			if (n > 0) {
				m = (int)strlen((char *)&buf[LWS_PRE]);
				/* if no buckets were valid, it might just be {"buckets":[]} */
				if (m > 16) {
					n = lws_write(wsi, &buf[LWS_PRE], (size_t)m, LWS_WRITE_TEXT);
					if (n < m)
						return -1;
				}
			}
			pss->last_since_us = (uint64_t)lws_now_usecs();
#endif
		}
		break;

	case LWS_CALLBACK_TIMER:
		lws_callback_on_writable(wsi);
		lws_set_timer_usecs(wsi, 200 * LWS_US_PER_MS);
		break;

	default:
		break;
	}

	return 0;
}

LWS_VISIBLE const struct lws_protocols lws_latency_protocols[] = {
	{
		"lws-latency",
		callback_latency,
		sizeof(struct per_session_data__latency),
		128,
		0, NULL, 0
	},
};

LWS_VISIBLE const lws_plugin_protocol_t lws_latency = {
	.hdr = {
		.name = "lws latency",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},

	.protocols = lws_latency_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_latency_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
