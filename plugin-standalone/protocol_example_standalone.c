/*
 * ws protocol handler plugin for "dumb increment"
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The person who associated a work with this deed has dedicated
 * the work to the public domain by waiving all of his or her rights
 * to the work worldwide under copyright law, including all related
 * and neighboring rights, to the extent allowed by law. You can copy,
 * modify, distribute and perform the work, even for commercial purposes,
 * all without asking permission.
 *
 * These test plugins are intended to be adapted for use in your code, which
 * may be proprietary.  So unlike the library itself, they are licensed
 * Public Domain.
 *
 * This is a copy of dumb_increment adapted slightly to serve as the
 * "example-standalone-protocol", to show how to build protocol plugins
 * outside the library easily.
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

#include <string.h>

/* period of the repeating "broadcast the current number" timer in us */
#define DI_PERIOD_US 50000

struct per_vhost_data__dumb_increment {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;

	/*
	 * Repeating scheduler that, every DI_PERIOD_US us, asks lws to make
	 * every connection on this vhost/protocol writable.  This is the lws
	 * event-loop-agnostic equivalent of the libuv uv_timer_t the original
	 * dumb_increment used: it works unchanged on the default poll() loop,
	 * libuv, or any other lws event lib.
	 */
	lws_sorted_usec_list_t sul;
};

struct per_session_data__dumb_increment {
	int number;
};

static void
sul_cb_dumb_increment(lws_sorted_usec_list_t *sul)
{
	struct per_vhost_data__dumb_increment *vhd = lws_container_of(sul,
			struct per_vhost_data__dumb_increment, sul);

	lws_callback_on_writable_all_protocol_vhost(vhd->vhost, vhd->protocol);

	/* re-arm for the next period */
	lws_sul_schedule(vhd->context, 0, &vhd->sul,
			 sul_cb_dumb_increment, DI_PERIOD_US);
}

static int
callback_dumb_increment(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct per_session_data__dumb_increment *pss =
			(struct per_session_data__dumb_increment *)user;
	struct per_vhost_data__dumb_increment *vhd =
			(struct per_vhost_data__dumb_increment *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	unsigned char buf[LWS_PRE + 512];
	unsigned char *p = &buf[LWS_PRE];
	int n, m;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__dumb_increment));
		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);
		lws_sul_schedule(vhd->context, 0, &vhd->sul,
				 sul_cb_dumb_increment, DI_PERIOD_US);
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd)
			lws_sul_cancel(&vhd->sul);
		break;

	case LWS_CALLBACK_ESTABLISHED:
		pss->number = 0;
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		n = lws_snprintf((char *)p, 512, "%d", pss->number++);
		m = lws_write(wsi, p, n, LWS_WRITE_TEXT);
		if (m < n) {
			lwsl_vhost_err(vhd->vhost, "ERROR %d writing to di socket", n);
			return -1;
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		if (len < 6)
			break;
		if (strcmp((const char *)in, "reset\n") == 0)
			pss->number = 0;
		if (strcmp((const char *)in, "closeme\n") == 0) {
			lwsl_notice("dumb_inc: closing as requested\n");
			lws_close_reason(wsi, LWS_CLOSE_STATUS_GOINGAWAY,
					 (unsigned char *)"seeya", 5);
			return -1;
		}
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		"example-standalone-protocol",
		callback_dumb_increment,
		sizeof(struct per_session_data__dumb_increment),
		10, /* rx buf size must be >= permessage-deflate rx size */
	},
};

/*
 * The exported lws_plugin_protocol_t struct MUST be named EXACTLY the same as
 * your plugin's shared object suffix (after removing 'libprotocol_').
 * lwsws uses this exact string directly in its dlsym() lookup on startup.
 */
LWS_VISIBLE const lws_plugin_protocol_t example_standalone = {
	.hdr = {
		.name = "standalone",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},

	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
