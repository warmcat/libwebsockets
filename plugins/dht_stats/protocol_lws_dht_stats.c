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
#include <libwebsockets/lws-dht.h>
#include <string.h>
#include <stdlib.h>

struct per_vhost_data__dht_stats {
	struct lws_vhost *dht_vh;
};

struct per_session_data__dht_stats {
	struct per_vhost_data__dht_stats *vhd;
};

static int
append_stats_json(char *buf, size_t size, const struct lws_dht_stats *s, int idx)
{
	return lws_snprintf(buf, size,
		"    \"window_%d\": {\n"
		"      \"tx\": { \"ping\": %u, \"pong\": %u, \"find_node\": %u, \"get_peers\": %u, \"announce_peer\": %u, \"put\": %u, \"get\": %u },\n"
		"      \"rx\": { \"ping\": %u, \"pong\": %u, \"find_node\": %u, \"get_peers\": %u, \"announce_peer\": %u, \"put\": %u, \"get\": %u, \"drops\": %u },\n"
		"      \"peer_count\": %u\n"
		"    }",
		idx,
		(unsigned)s->tx_ping, (unsigned)s->tx_pong, (unsigned)s->tx_find_node, (unsigned)s->tx_get_peers, (unsigned)s->tx_announce_peer, (unsigned)s->tx_put, (unsigned)s->tx_get,
		(unsigned)s->rx_ping, (unsigned)s->rx_pong, (unsigned)s->rx_find_node, (unsigned)s->rx_get_peers, (unsigned)s->rx_announce_peer, (unsigned)s->rx_put, (unsigned)s->rx_get, (unsigned)s->rx_drops,
		(unsigned)s->peer_count);
}

static int
callback_lws_dht_stats(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
	struct per_session_data__dht_stats *pss = (struct per_session_data__dht_stats *)user;
	struct per_vhost_data__dht_stats *vhd =
			(struct per_vhost_data__dht_stats *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
	int n, i;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__dht_stats));
		if (!vhd)
			return -1;
		vhd->dht_vh = lws_get_vhost_by_name(lws_get_context(wsi), "dht");
		if (!vhd->dht_vh)
			vhd->dht_vh = lws_get_vhost(wsi);
		break;

	case LWS_CALLBACK_ESTABLISHED:
		pss->vhd = vhd;
		lws_set_timer_usecs(wsi, LWS_US_PER_SEC);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE: {
		struct lws_dht_stats current;
		const struct lws_dht_stats *history;
		int head;
		size_t alloc_size = LWS_PRE + 32768; /* 32KB max for 48 buckets */
		uint8_t *pre = malloc(alloc_size);
		char *p;
		char *end;

		if (!pre)
			return 1;

		p = (char *)pre + LWS_PRE;
		end = (char *)pre + alloc_size - 1;

		if (lws_dht_get_stats(vhd->dht_vh, &current, &history, &head)) {
			free(pre);
			return 0;
		}

		n = lws_snprintf(p, lws_ptr_diff_size_t(end, p), "{\n  \"stats_current\": {\n");
		n += append_stats_json(p + n, lws_ptr_diff_size_t(end, p + n), &current, 0);
		n += lws_snprintf(p + n, lws_ptr_diff_size_t(end, p + n), "\n  },\n  \"stats_history\": {\n");

		for (i = 0; i < LWS_DHT_STAT_BUCKETS; i++) {
			int idx = (head + i) % LWS_DHT_STAT_BUCKETS;
			n += append_stats_json(p + n, lws_ptr_diff_size_t(end, p + n), &history[idx], i);
			if (i < LWS_DHT_STAT_BUCKETS - 1)
				n += lws_snprintf(p + n, lws_ptr_diff_size_t(end, p + n), ",\n");
		}
		
		n += lws_snprintf(p + n, lws_ptr_diff_size_t(end, p + n), "\n  }\n}\n");

		if (lws_write(wsi, pre + LWS_PRE, (size_t)n, LWS_WRITE_TEXT) < 0) {
			free(pre);
			return -1;
		}

		free(pre);
		break;
	}

	case LWS_CALLBACK_TIMER:
		lws_callback_on_writable(wsi);
		lws_set_timer_usecs(wsi, LWS_US_PER_SEC);
		break;

	default:
		break;
	}

	return 0;
}

LWS_VISIBLE const struct lws_protocols lws_dht_stats_protocols[] = {
	{
		"lws-dht-stats",
		callback_lws_dht_stats,
		sizeof(struct per_session_data__dht_stats),
		32768, /* rx buffer size - not really needed */
		0, NULL, 0
	},
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

/*
 * The exported lws_plugin_protocol_t struct MUST be named EXACTLY the same as
 * your plugin's shared object suffix (after removing 'libprotocol_').
 * lwsws uses this exact string directly in its dlsym() lookup on startup.
 */
LWS_VISIBLE const lws_plugin_protocol_t lws_dht_stats = {
	.hdr = {
		.name = "lws dht stats",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},
	.protocols = lws_dht_stats_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_dht_stats_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
