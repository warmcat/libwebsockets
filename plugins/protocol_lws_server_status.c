/*
 * libwebsockets-test-server - libwebsockets test implementation
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
 * The test apps are intended to be adapted for use in your code, which
 * may be proprietary.  So unlike the library itself, they are licensed
 * Public Domain.
 */

#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

struct lws_ss_filepath {
	struct lws_ss_filepath *next;
	char filepath[128];
};

struct lws_ss_dumps {
	char buf[32768];
	int length;
};

struct pss {
	int ver;
	int pos;
};

struct vhd {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;
	lws_sorted_usec_list_t sul;
	int hide_vhosts;
	int tow_flag;
	int period_s;
	int clients;
	struct lws_ss_dumps d;
	struct lws_ss_filepath *fp;
};

static const struct lws_protocols protocols[1];

static void
update(struct lws_sorted_usec_list *sul)
{
	struct vhd *v = lws_container_of(sul, struct vhd, sul);
	struct lws_ss_filepath *fp;
	char contents[256], pure[256], *p = v->d.buf + LWS_PRE,
	     *end = v->d.buf + sizeof(v->d.buf) - LWS_PRE - 1;
	int n, first = 1, fd;

	p += lws_snprintf(p, lws_ptr_diff(end, p), "{\"i\":");
	p += lws_json_dump_context(v->context, p, lws_ptr_diff(end, p),
				   v->hide_vhosts);
	p += lws_snprintf(p, lws_ptr_diff(end, p), ", \"files\": [");

	fp = v->fp;
	while (fp) {
		if (!first)
			p += lws_snprintf(p, lws_ptr_diff(end, p), ",");

		strcpy(pure, "(unknown)");
		fd = lws_open(fp->filepath, LWS_O_RDONLY);
		if (fd >= 0) {
			n = read(fd, contents, sizeof(contents) - 1);
			close(fd);
			if (n >= 0) {
				contents[n] = '\0';
				lws_json_purify(pure, contents, sizeof(pure), NULL);
			}
		}

		p += lws_snprintf(p, lws_ptr_diff(end, p),
				"{\"path\":\"%s\",\"val\":\"%s\"}",
					fp->filepath, pure);
		first = 0;

		fp = fp->next;
	}
	p += lws_snprintf(p, lws_ptr_diff(end, p), "]}");
	v->d.length = p - (v->d.buf + LWS_PRE);

	lws_callback_on_writable_all_protocol(v->context, &protocols[0]);

	lws_sul_schedule(v->context, 0, &v->sul, update, v->period_s * LWS_US_PER_SEC);
}

static int
callback_lws_server_status(struct lws *wsi, enum lws_callback_reasons reason,
			   void *user, void *in, size_t len)
{
	const struct lws_protocol_vhost_options *pvo =
			(const struct lws_protocol_vhost_options *)in;
	struct vhd *v = (struct vhd *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	struct lws_ss_filepath *fp, *fp1, **fp_old;
	int m;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_info("%s: LWS_CALLBACK_ESTABLISHED\n", __func__);
		if (!v->clients++) {
			lws_sul_schedule(lws_get_context(wsi), 0, &v->sul, update, 1);
			lwsl_info("%s: starting updates\n", __func__);
		}
		break;

	case LWS_CALLBACK_CLOSED:
		if (!--v->clients)
			lwsl_notice("%s: stopping updates\n", __func__);

		break;

	case LWS_CALLBACK_PROTOCOL_INIT: /* per vhost */
		if (v)
			break;

		lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
					    lws_get_protocol(wsi),
					    sizeof(struct vhd));
		v = (struct vhd *)lws_protocol_vh_priv_get(lws_get_vhost(wsi),
							   lws_get_protocol(wsi));

		fp_old = &v->fp;

		while (pvo) {
			if (!strcmp(pvo->name, "hide-vhosts"))
				v->hide_vhosts = atoi(pvo->value);
			if (!strcmp(pvo->name, "update-ms"))
				v->period_s = (atoi(pvo->value) + 500) / 1000;
			else
				v->period_s = 5;
			if (!strcmp(pvo->name, "filepath")) {
				fp = malloc(sizeof(*fp));
				if (!fp)
					return -1;
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
		v->vhost = lws_get_vhost(wsi);
		v->protocol = lws_get_protocol(wsi);

		lws_sul_schedule(lws_get_context(wsi), 0, &v->sul, update, 1);
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

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		"lws-server-status",
		callback_lws_server_status,
		sizeof(struct pss),
		1024,
	},
};

LWS_VISIBLE const lws_plugin_protocol_t lws_server_status = {
	.hdr = {
		"lws server status",
		"lws_protocol_plugin",
		LWS_PLUGIN_API_MAGIC
	},

	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
