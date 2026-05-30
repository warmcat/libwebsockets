/*
 * WebTransport + WebSocket shared world test plugin
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#if !defined (LWS_PLUGIN_STATIC)
#if !defined(LWS_DLL)
#define LWS_DLL
#endif
#if !defined(LWS_INTERNAL)
#define LWS_INTERNAL
#endif
#include <libwebsockets.h>
#endif
#include <libwebsockets/lws-webtransport.h>
#include <string.h>

struct vhd__shared_world {
	uint32_t seed;
};

struct pss__shared_world {
	int seed_sent;
};

static int
callback_shared_world(struct lws *wsi, enum lws_callback_reasons reason,
		      void *user, void *in, size_t len)
{
	struct pss__shared_world *pss = (struct pss__shared_world *)user;
	struct vhd__shared_world *vhd = (struct vhd__shared_world *)
		lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
	uint8_t buf[LWS_PRE + 128];
	int m;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct vhd__shared_world));
		if (!vhd)
			return -1;
		{
			struct lws_xos xos;
			lws_xos_init(&xos, 0x12345678); /* Simple predictable seed for PRNG to gen actual world seed */
			vhd->seed = (uint32_t)lws_xos(&xos);
		}
		lwsl_notice("Shared World Plugin Initialized, Seed: %u\n", vhd->seed);
		break;

	case LWS_CALLBACK_ESTABLISHED:
		/* Could be WS or WT stream */
#if defined(LWS_ROLE_WT)
		if (lws_wt_is_session(wsi)) {
			lwsl_user("WT Session established\n");
			break; /* We don't send data on the session itself */
		}
#endif
		lwsl_user("Connection/Stream established\n");
		pss->seed_sent = 0;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (!pss->seed_sent) {
			m = lws_snprintf((char *)buf + LWS_PRE, sizeof(buf) - LWS_PRE, 
					 "{\"seed\": %u}", vhd->seed);
			if (lws_write(wsi, buf + LWS_PRE, (unsigned int)m, LWS_WRITE_TEXT) < m)
				return -1;
			pss->seed_sent = 1;
		}
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_SHARED_WORLD \
	{ \
		"webtransport-shared-world", \
		callback_shared_world, \
		sizeof(struct pss__shared_world), \
		1024, \
		0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)
LWS_VISIBLE const struct lws_protocols shared_world_protocols[] = {
	LWS_PLUGIN_PROTOCOL_SHARED_WORLD
};

LWS_VISIBLE const lws_plugin_protocol_t webtransport_shared_world = {
	.hdr = {
		.name = "webtransport shared world",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},
	.protocols = shared_world_protocols,
	.count_protocols = LWS_ARRAY_SIZE(shared_world_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
#endif
