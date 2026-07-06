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
 */

#include "private-lws-hls.h"
#include <string.h>

static int
callback_lws_hls(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	struct per_vhost_data__lws_hls *vhd =
			(struct per_vhost_data__lws_hls *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	const struct lws_protocol_vhost_options *pvo;

	struct per_session_data__lws_hls *pss =
			(struct per_session_data__lws_hls *)user;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		if (!in)
			return 0;

		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi), sizeof(struct per_vhost_data__lws_hls));
		if (!vhd)
			return 1;

		if ((pvo = lws_pvo_search((const struct lws_protocol_vhost_options *)in, "media-dir")))
			vhd->media_dir = pvo->value;
		else {
			lwsl_err("%s: media-dir pvo required\n", __func__);
			return 1;
		}

		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);

		pthread_mutex_init(&vhd->lock, NULL);
		pthread_cond_init(&vhd->cond, NULL);
		vhd->thread_exit = 0;
		if (pthread_create(&vhd->thumb_thread, NULL, lws_hls_thumbnail_worker, vhd)) {
			lwsl_err("Failed to create thumbnail thread\n");
			return 1;
		}

		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd)
			break;
		vhd->thread_exit = 1;
		pthread_cond_signal(&vhd->cond);
		pthread_join(vhd->thumb_thread, NULL);
		pthread_mutex_destroy(&vhd->lock);
		pthread_cond_destroy(&vhd->cond);
		
		/* free cache */
		struct thumb_cache *c = vhd->cache_head;
		while (c) {
			struct thumb_cache *next = c->next;
			free(c->data);
			free(c);
			c = next;
		}
		
		/* free task queue */
		struct thumb_task *t = vhd->task_head;
		while (t) {
			struct thumb_task *next = t->next;
			free(t);
			t = next;
		}
		break;

	case LWS_CALLBACK_HTTP:
	{
		const char *url = (const char *)in;

		if (!vhd)
			return lws_callback_http_dummy(wsi, reason, user, in, len);

		lwsl_user("HLS plugin received HTTP request for '%s'\n", url ? url : "NULL");
		
		if (!strcmp(url, "")) {
			/* Redirect to add trailing slash */
			char uri[512];
			int ulen = lws_hdr_copy(wsi, uri, sizeof(uri) - 2, WSI_TOKEN_GET_URI);
			if (ulen > 0) {
				unsigned char redirect_buf[512 + LWS_PRE];
				unsigned char *p_red = redirect_buf + LWS_PRE;
				unsigned char *end_red = redirect_buf + sizeof(redirect_buf) - 1;

				uri[ulen] = '/';
				uri[ulen + 1] = '\0';
				ulen++;

				int m = lws_http_redirect(wsi, HTTP_STATUS_MOVED_PERMANENTLY,
							  (unsigned char *)uri, ulen, &p_red, end_red);
				if (m < 0)
					return -1;
				return lws_http_transaction_completed(wsi);
			}
		}

		/* Simple routing based on URL prefix */
		if (!strcmp(url, "/") || !strcmp(url, "/index.html")) {
			return lws_hls_serve_dir(wsi, vhd->media_dir);
		}
		else if (!strncmp(url, "/preview/", 9)) {
			return lws_hls_serve_thumbnail(wsi, vhd->media_dir, url + 9);
		}
		else if (!strncmp(url, "/stream/", 8)) {
			return lws_hls_serve_manifest(wsi, vhd->media_dir, url + 8);
		}
		else if (!strncmp(url, "/init/", 6)) {
			return lws_hls_serve_init(wsi, vhd->media_dir, url + 6);
		}
		else if (!strncmp(url, "/segment/", 9)) {
			const char *p = url + 9;
			const char *sep = strchr(p, '/');
			if (!sep)
				goto err_404;

			char filename[256];
			size_t fn_len = (size_t)(sep - p);
			if (fn_len >= sizeof(filename))
				goto err_404;
			
			strncpy(filename, p, fn_len);
			filename[fn_len] = '\0';
			
			int segment_idx = atoi(sep + 1);
			return lws_hls_serve_segment(wsi, vhd->media_dir, filename, segment_idx);
		} else {
			/* Let LWS standard file serving handle static files from the mount origin */
			return lws_callback_http_dummy(wsi, reason, user, in, len);
		}

		return 0;

err_404:
		lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
		return -1;
	}

	case LWS_CALLBACK_EVENT_WAIT_CANCELLED:
		if (!vhd)
			break;
		/* Thread finished a thumbnail. Wake up all waiting HTTP sessions */
		lws_start_foreach_llp(struct per_session_data__lws_hls **,
				      ppss, vhd->pss_list) {
			if ((*ppss)->waiting_for_thumbnail)
				lws_callback_on_writable((*ppss)->wsi);
		} lws_end_foreach_llp(ppss, pss_list);
		break;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (pss && pss->waiting_for_thumbnail) {
			pthread_mutex_lock(&vhd->lock);
			struct thumb_cache *c = vhd->cache_head;
			while (c) {
				if (!strcmp(c->filename, pss->thumb_filename))
					break;
				c = c->next;
			}
			
			if (c) {
				/* Found it in cache! */
				size_t len = c->len;
				uint8_t *buf = malloc(LWS_PRE + len);
				if (!buf) {
					pthread_mutex_unlock(&vhd->lock);
					return -1;
				}
				
				uint8_t *start = buf + LWS_PRE;
				uint8_t *p = start;
				uint8_t *end = p + len;
				
				if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "image/jpeg",
								(lws_filepos_t)len, &p, end)) {
					free(buf);
					pthread_mutex_unlock(&vhd->lock);
					return 1;
				}
				
				if (lws_finalize_write_http_header(wsi, start, &p, end)) {
					free(buf);
					pthread_mutex_unlock(&vhd->lock);
					return 1;
				}
				
				memcpy(buf + LWS_PRE, c->data, len);
				lws_write(wsi, buf + LWS_PRE, len, LWS_WRITE_HTTP_FINAL);
				free(buf);
				
				pss->waiting_for_thumbnail = 0;
				pthread_mutex_unlock(&vhd->lock);
				
				if (lws_http_transaction_completed(wsi))
					return -1;
				return 0;
			}
			
			/* Not in cache. Did it fail? */
			int is_pending = 0;
			struct thumb_task *t = vhd->task_head;
			while (t) {
				if (!strcmp(t->filename, pss->thumb_filename)) {
					is_pending = 1;
					break;
				}
				t = t->next;
			}
			
			pthread_mutex_unlock(&vhd->lock);
			
			if (!is_pending) {
				/* Not pending and not in cache -> extraction failed */
				pss->waiting_for_thumbnail = 0;
				lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
				return -1;
			}
			
			/* Still pending, keep waiting */
			return 0;
		}

		if (!pss || !pss->segment_buf || pss->segment_pos >= pss->segment_len)
			return 1; /* Done or nothing to write */
			
		size_t rem = pss->segment_len - pss->segment_pos;
		int flags = (pss->segment_pos + rem == pss->segment_len) ? LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP;
		
		int m = lws_write(wsi, pss->segment_buf + LWS_PRE + pss->segment_pos, rem, (enum lws_write_protocol)flags);
		if (m < 0) {
			free(pss->segment_buf);
			pss->segment_buf = NULL;
			return -1;
		}
		
		pss->segment_pos += (size_t)m;
		if (pss->segment_pos < pss->segment_len) {
			lws_callback_on_writable(wsi);
			return 0;
		}
		
		free(pss->segment_buf);
		pss->segment_buf = NULL;
		return 1; /* Close connection after sending segment */

	case LWS_CALLBACK_CLOSED_HTTP:
		if (pss) {
			if (vhd)
				lws_ll_fwd_remove(struct per_session_data__lws_hls, pss_list,
						  pss, vhd->pss_list);
			if (pss->segment_buf) {
				free(pss->segment_buf);
				pss->segment_buf = NULL;
			}
		}
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_LWS_HLS \
	{ \
		"lws-hls", \
		callback_lws_hls, \
		sizeof(struct per_session_data__lws_hls), \
		1024, \
		0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)

LWS_VISIBLE const struct lws_protocols lws_hls_protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_HLS
};

LWS_VISIBLE const lws_plugin_protocol_t lws_hls = {
	.hdr = {
		.name = "lws hls",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},

	.protocols = lws_hls_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_hls_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};

#endif
