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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

struct lws_ss_load_sample {
	time_t t;
	int load_x100;
};

struct lws_ss_filepath {
	struct lws_ss_filepath *next;
	char filepath[128];
};

struct lws_ss_dumps {
	char buf[32768];
	int length;

	struct lws_ss_load_sample load[64];
	int load_head;
	int load_tail;
};

struct per_session_data__server_status {
	int ver;
	int pos;
};

struct per_vhost_data__lws_server_status {
	struct lws_context *context;
	int hide_vhosts;
	int tow_flag;
	int period_us;
	struct lws_ss_dumps d;
	struct lws_ss_filepath *fp;
};

static const struct lws_protocols protocols[1];

static void
update(struct per_vhost_data__lws_server_status *v)
{
	struct lws_ss_filepath *fp;
	char *p = v->d.buf + LWS_PRE, contents[256], pure[256];
	int n, l, first = 1, fd;

	l = sizeof(v->d.buf) - LWS_PRE - 1;

	n = lws_snprintf(p, l, "{\"i\":");
	p += n;
	l -= n;

	n = lws_json_dump_context(v->context, p, l, v->hide_vhosts);
	p += n;
	l -= n;

	n = lws_snprintf(p, l, ", \"files\": [");
	p += n;
	l -= n;

	fp = v->fp;
	while (fp) {
		if (!first) {
			n = lws_snprintf(p, l, ",");
			p += n;
			l -= n;
		}
		fd = open(fp->filepath, LWS_O_RDONLY);
		if (fd >= 0) {
			n = read(fd, contents, sizeof(contents) - 1);
			if (n >= 0) {
				contents[n] = '\0';
				lws_json_purify(pure, contents, sizeof(pure));

				n = lws_snprintf(p, l,
					"{\"path\":\"%s\",\"val\":\"%s\"}",
						fp->filepath, pure);
				p += n;
				l -= n;
				first = 0;
			}
			close(fd);
		}
		fp = fp->next;
	}
	n = lws_snprintf(p, l, "]}");
	p += n;
	l -= n;

	v->d.length = p - (v->d.buf + LWS_PRE);

	lws_callback_on_writable_all_protocol(v->context, &protocols[0]);
}

static int
callback_lws_server_status(struct lws *wsi, enum lws_callback_reasons reason,
			   void *user, void *in, size_t len)
{
	const struct lws_protocol_vhost_options *pvo =
			(const struct lws_protocol_vhost_options *)in;
	struct per_vhost_data__lws_server_status *v =
			(struct per_vhost_data__lws_server_status *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	struct lws_ss_filepath *fp, *fp1, **fp_old;
	int m;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_info("%s: LWS_CALLBACK_ESTABLISHED\n", __func__);
		lws_set_timer_usecs(wsi, v->period_us);
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_PROTOCOL_INIT: /* per vhost */
		if (v)
			break;

		lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__lws_server_status));
		v = (struct per_vhost_data__lws_server_status *)
				lws_protocol_vh_priv_get(lws_get_vhost(wsi),
				lws_get_protocol(wsi));

		fp_old = &v->fp;

		while (pvo) {
			if (!strcmp(pvo->name, "hide-vhosts"))
				v->hide_vhosts = atoi(pvo->value);
			if (!strcmp(pvo->name, "update-ms"))
				v->period_us = atoi(pvo->value) * 1000;
			else
				v->period_us = 5 * 1000 * 1000;
			if (!strcmp(pvo->name, "filepath")) {
				fp = malloc(sizeof(*fp));
				fp->next = NULL;
				lws_snprintf(&fp->filepath[0],
					     sizeof(fp->filepath), "%s",
					     pvo->value);
				*fp_old = fp;
				fp_old = &fp->next;
			}
			pvo = pvo->next;
		}
		v->context = lws_get_context(wsi);

		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY: /* per vhost */
		if (!v)
			break;
		fp = v->fp;
		while (fp) {
			fp1= fp->next;
			free(fp);
			fp = fp1;
		}
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		m = lws_write(wsi, (unsigned char *)v->d.buf + LWS_PRE,
			      v->d.length, LWS_WRITE_TEXT);
		if (m < 0)
			return -1;
		break;

	case LWS_CALLBACK_TIMER:
		lws_set_timer_usecs(wsi, v->period_us);
		update(v);
		lws_callback_on_writable(wsi);
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
