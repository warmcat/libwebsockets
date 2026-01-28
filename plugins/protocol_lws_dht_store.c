/*
 * ws protocol handler plugin for "lws dht store"
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This plugin implements a DHT node for object storage and retrieval.
 */

#if !defined(LWS_PLUGIN_STATIC)
#if !defined(LWS_DLL)
#define LWS_DLL
#endif
#if !defined(LWS_INTERNAL)
#define LWS_INTERNAL
#endif
#include <libwebsockets.h>
#endif

#include <libwebsockets/lws-dht.h>
#include <string.h>
#include <stdlib.h>

struct vhd_dht_store {
	struct lws_context *context;
	struct lws_vhost *vhost;
	struct lws_dht_ctx *dht;

	const char *storage_path;
	const char *dht_iface;
	int dht_port;
};

static void
cb_dht(void *closure, int event, const lws_dht_hash_t *info_hash,
       const void *data, size_t data_len, const struct sockaddr *from, size_t fromlen)
{
	struct vhd_dht_store *vhd = (struct vhd_dht_store *)closure;
	(void)info_hash;
	(void)data;
	(void)data_len;
	(void)from;
	(void)fromlen;

	switch (event) {
	case LWS_DHT_EVENT_VALUES:
	case LWS_DHT_EVENT_VALUES6:
		lwsl_notice("%s: LWS_DHT_EVENT_VALUES\n", __func__);
		break;
	case LWS_DHT_EVENT_SEARCH_DONE:
	case LWS_DHT_EVENT_SEARCH_DONE6:
		lwsl_notice("%s: LWS_DHT_EVENT_SEARCH_DONE\n", __func__);
		break;
	case LWS_DHT_EVENT_EXTERNAL_ADDR:
	case LWS_DHT_EVENT_EXTERNAL_ADDR6:
		lwsl_notice("%s: LWS_DHT_EVENT_EXTERNAL_ADDR\n", __func__);
		break;
	case LWS_DHT_EVENT_DATA:
		lwsl_notice("%s: LWS_DHT_EVENT_DATA: %d bytes\n", __func__, (int)data_len);
		if (data_len >= 5 && memcmp(data, "ECHO ", 5) == 0) {
			/* Echo back the rest of the data */
			lwsl_notice("%s: Echoing data back\n", __func__);
			lws_dht_send_data(vhd->dht, from, (const char *)data + 5, data_len - 5);
		}
		break;
	default:
		break;
	}
}

static int
callback_lws_dht_store(struct lws *wsi, enum lws_callback_reasons reason,
		       void *user, void *in, size_t len)
{
	struct vhd_dht_store *vhd = (struct vhd_dht_store *)lws_protocol_vh_priv_get(
			lws_get_vhost(wsi), lws_get_protocol(wsi));
	const char *pvo_val;
	lws_dht_info_t i;

	(void)user;
	(void)len;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi), sizeof(struct vhd_dht_store));
		if (!vhd)
			return -1;

		vhd->context = lws_get_context(wsi);
		vhd->vhost = lws_get_vhost(wsi);

		/* defaults */
		vhd->dht_port = 5000;

		/* Parse PVOs */
		if (lws_pvo_get_str(in, "dht-storage-path", &vhd->storage_path)) {
			lwsl_err("%s: dht-storage-path PVO required\n", __func__);
			return -1;
		}

		if (!lws_pvo_get_str(in, "dht-port", &pvo_val))
			vhd->dht_port = atoi(pvo_val);

		lws_pvo_get_str(in, "dht-iface", &vhd->dht_iface);

		lwsl_user("%s: init: path '%s', port %d\n", __func__,
				vhd->storage_path, vhd->dht_port);

		/* Create DHT context */
		memset(&i, 0, sizeof(i));
		i.vhost = vhd->vhost;
		i.cb = cb_dht;
		i.closure = vhd;
		i.port = vhd->dht_port;
		i.iface = vhd->dht_iface;
		/* i.ipv6 = 1; */ /* Enable IPv6 if needed/supported by env */

		vhd->dht = lws_dht_create(&i);
		if (!vhd->dht) {
			lwsl_err("%s: failed to create DHT\n", __func__);
			return -1;
		}

		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd && vhd->dht)
			lws_dht_destroy(&vhd->dht);
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		"lws_dht_store",
		callback_lws_dht_store,
		0,
		0, 0, NULL, 0
	},
};

LWS_VISIBLE const lws_plugin_protocol_t lws_dht_store = {
	.hdr = {
		"lws dht store",
		"lws_protocol_plugin",
		LWS_BUILD_HASH,
		LWS_PLUGIN_API_MAGIC
	},

	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
