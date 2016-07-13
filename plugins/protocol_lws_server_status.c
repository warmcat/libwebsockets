/*
 * libwebsockets-test-server - libwebsockets test implementation
 *
 * Copyright (C) 2010-2016 Andy Green <andy@warmcat.com>
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
 * The test apps are intended to be adapted for use in your code, which
 * may be proprietary.  So unlike the library itself, they are licensed
 * Public Domain.
 */

#define LWS_DLL
#define LWS_INTERNAL
#include "../lib/libwebsockets.h"
#include <string.h>
#include <stdlib.h>

struct lws_ss_load_sample {
	time_t t;
	int load_x100;
};

struct lws_ss_dumps {
	char buf[32768];
	int length;

	struct lws_ss_load_sample load[64];
	int load_head;
	int load_tail;
};

static struct lws_ss_dumps d;
static uv_timer_t timeout_watcher;
static struct lws_context *context;
static int tow_flag;

struct per_session_data__server_status {
	int ver;
	int pos;
};

static const struct lws_protocols protocols[1];

static void
uv_timeout_cb_server_status(uv_timer_t *w
#if UV_VERSION_MAJOR == 0
		, int status
#endif
)
{
	char *p = d.buf + LWS_PRE;

#if 0
#ifdef LWS_HAVE_GETLOADAVG
	double l = 0.0;

	getloadavg(&l, 1);
	d.load[d.load_head].load_x100 = (int)(l * 100);
	d.load[d.load_head].t = lws_now_secs();
	d.load_head++;
	if (d.load_head == ARRAY_SIZE(d.load))
		d.load_head = 0;
	if (d.load_head == d.load_tail) {
		d.load_tail++;
		if (d.load_tail == ARRAY_SIZE(d.load))
			d.load_tail = 0;
	}
#endif
#endif

	d.length = lws_json_dump_context(context, p,
					 sizeof(d.buf) - LWS_PRE);

	lws_callback_on_writable_all_protocol(context, &protocols[0]);
}

static int
callback_lws_server_status(struct lws *wsi, enum lws_callback_reasons reason,
			   void *user, void *in, size_t len)
{
	const struct lws_protocol_vhost_options *pvo =
			(const struct lws_protocol_vhost_options *)in;
	int m, period = 1000;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_info("%s: LWS_CALLBACK_ESTABLISHED\n", __func__);
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_PROTOCOL_INIT: /* per vhost */
		if (tow_flag)
			break;
		while (pvo) {
			if (!strcmp(pvo->name, "update-ms"))
				period = atoi(pvo->value);
			pvo = pvo->next;
		}
		context = lws_get_context(wsi);
		uv_timer_init(lws_uv_getloop(context, 0), &timeout_watcher);
		uv_timer_start(&timeout_watcher,
				uv_timeout_cb_server_status, 2000, period);
		tow_flag = 1;
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY: /* per vhost */
		if (!tow_flag)
			break;
		uv_timer_stop(&timeout_watcher);
		tow_flag = 0;
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		m = lws_write(wsi, (unsigned char *)d.buf + LWS_PRE, d.length,
			      LWS_WRITE_TEXT);
		if (m < 0)
			return -1;
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		"lws-server-status",
		callback_lws_server_status,
		sizeof(struct per_session_data__server_status),
		1024,
	},
};

LWS_EXTERN LWS_VISIBLE int
init_protocol_lws_server_status(struct lws_context *context,
			     struct lws_plugin_capability *c)
{
	if (c->api_magic != LWS_PLUGIN_API_MAGIC) {
		lwsl_err("Plugin API %d, library API %d",
			 LWS_PLUGIN_API_MAGIC, c->api_magic);
		return 1;
	}

	c->protocols = protocols;
	c->count_protocols = ARRAY_SIZE(protocols);
	c->extensions = NULL;
	c->count_extensions = 0;

	return 0;
}

LWS_EXTERN LWS_VISIBLE int
destroy_protocol_lws_server_status(struct lws_context *context)
{
	return 0;
}

