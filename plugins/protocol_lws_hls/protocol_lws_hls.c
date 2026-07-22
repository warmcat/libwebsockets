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
#include <unistd.h>
#include <libgen.h>

static const char * const stub_req_paths[] = { "delete" };

static signed char
stub_req_cb(struct lejp_ctx *ctx, char reason)
{
	struct per_session_data__lws_hls *pss = (struct per_session_data__lws_hls *)ctx->user;
	struct per_vhost_data__lws_hls *vhd = (struct per_vhost_data__lws_hls *)
			lws_protocol_vh_priv_get(lws_get_vhost(pss->wsi),
					lws_get_protocol(pss->wsi));

	if (reason == LEJPCB_VAL_STR_END && ctx->path_match - 1 == 0) {
		char filename[256];
		lws_strncpy(filename, ctx->buf, sizeof(filename));
		lws_filename_purify_inplace(filename);
		if (strchr(filename, '/'))
			return 0;
		
		char path[512];
		lws_snprintf(path, sizeof(path), "%s/%s", vhd->media_dir, filename);
		
		lwsl_notice("Stub deleting: %s\n", path);
		unlink(path);
		
		/* if there was a container subdir, and it is now empty, remove it */
		char *dir_path = dirname(path);
		if (dir_path && strncmp(dir_path, vhd->media_dir, strlen(vhd->media_dir)) == 0 && strcmp(dir_path, vhd->media_dir) != 0) {
			rmdir(dir_path); /* rmdir only succeeds if directory is empty */
		}
	}

	return 0;
}

static int
callback_lws_hls(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len);

#define LWS_PLUGIN_PROTOCOL_LWS_HLS \
	{ \
		"lws-hls", \
		callback_lws_hls, \
		sizeof(struct per_session_data__lws_hls), \
		1024, \
		0, NULL, 0 \
	}

static const struct lws_protocols stub_prots[] = {
	LWS_PLUGIN_PROTOCOL_LWS_HLS,
	LWS_PROTOCOL_LIST_TERM
};

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
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi), sizeof(struct per_vhost_data__lws_hls));
		if (!vhd)
			return 1;

#if defined(LWS_WITH_STUB)
		const char *stub = lws_cmdline_option_cx(lws_get_context(wsi), "--lws-stub");
		if (stub) {
			if (strcmp(stub, "lws-hls-stub"))
				return 0;

			struct lws_stub_config sc;
			char secret[129];
			char extra[512];
			memset(&sc, 0, sizeof(sc));
			memset(extra, 0, sizeof(extra));
			sc.cx = lws_get_context(wsi);
			sc.vh = lws_get_vhost(wsi);
			sc.stub_name = "lws-hls-stub";
			sc.uds_path = "/tmp/lws-hls-stub.sock";
			sc.protocols = stub_prots;
			
			if (lws_stub_server_init(&sc, secret, extra, sizeof(extra)) < 0)
				return 1;
				
			/* Update our media_dir to the one provided by the parent via extra_payload */
			if (extra[0])
				vhd->media_dir = strdup(extra);
			else
				vhd->media_dir = "/tmp";
				
			return 0;
		}
#endif

		if (in && (pvo = lws_pvo_search((const struct lws_protocol_vhost_options *)in, "media-dir")))
			vhd->media_dir = pvo->value;
		else {
			lwsl_err("%s: media-dir pvo required\n", __func__);
			return 1;
		}

#if defined(LWS_WITH_STUB)
		{
			struct lws_stub_config sc;
			memset(&sc, 0, sizeof(sc));
			sc.cx = lws_get_context(wsi);
			sc.vh = lws_get_vhost(wsi);
			sc.stub_name = "lws-hls-stub";
			sc.uds_path = "/tmp/lws-hls-stub.sock";
			sc.protocols = stub_prots;
			sc.parent_protocol_name = "lws-hls";
			sc.extra_payload = vhd->media_dir;
			sc.extra_payload_len = strlen(vhd->media_dir) + 1;
			vhd->stub_mgr = lws_stub_spawn(&sc);
		}
#endif

		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);

		av_log_set_level(AV_LOG_ERROR);

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

		/* free index cache */
		struct hls_file_index *idx = vhd->index_head;
		while (idx) {
			struct hls_file_index *next = idx->next;
			free(idx->entries);
			free(idx);
			idx = next;
		}

#if defined(LWS_WITH_STUB)
		if (vhd->stub_mgr)
			lws_stub_destroy(&vhd->stub_mgr);
#endif
		if (vhd->has_jwk)
			lws_jwk_destroy(&vhd->jwk);
		break;

	case LWS_CALLBACK_HTTP_BIND_PROTOCOL:
		if (vhd && pss) {
			pss->wsi = wsi;
			lws_ll_fwd_insert(pss, pss_list, vhd->pss_list);
		}
		break;

	case LWS_CALLBACK_HTTP:
	{
		const char *url = (const char *)in;

		if (!vhd)
			return lws_callback_http_dummy(wsi, reason, user, in, len);

		pss->has_star_grant = 0;
		if (vhd->has_jwk) {
			struct lws_jwt_auth *ja = lws_jwt_auth_create(wsi, &vhd->jwk, "auth_session", NULL, wsi, NULL);
			if (ja) {
				if (lws_jwt_auth_query_grant(ja, "*") >= 1 || lws_jwt_auth_query_grant(ja, "hls:2") >= 1) {
					pss->has_star_grant = 1;
				}
				lws_jwt_auth_destroy(&ja);
			}
		}

		lwsl_info("HLS plugin received HTTP request for '%s'\n", url ? url : "NULL");
		
		lwsl_notice("HLS HTTP REQ: url='%s', waiting=%d\n", url ? url : "NULL", pss->waiting_for_thumbnail);

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
			char filename[256];
			lws_strncpy(filename, url + 9, sizeof(filename));
			lws_filename_purify_inplace(filename);
			if (strchr(filename, '/'))
				goto err_404;
			return lws_hls_serve_thumbnail(wsi, vhd->media_dir, filename);
		}
		else if (!strncmp(url, "/stream/", 8)) {
			char filename[256];
			lws_strncpy(filename, url + 8, sizeof(filename));
			lws_filename_purify_inplace(filename);
			if (strchr(filename, '/'))
				goto err_404;
			return lws_hls_serve_manifest(wsi, vhd->media_dir, filename);
		}
		else if (!strncmp(url, "/init/", 6)) {
			char filename[256];
			lws_strncpy(filename, url + 6, sizeof(filename));
			lws_filename_purify_inplace(filename);
			if (strchr(filename, '/'))
				goto err_404;
			return lws_hls_serve_init(wsi, vhd->media_dir, filename);
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
			lws_filename_purify_inplace(filename);
			if (strchr(filename, '/'))
				goto err_404;
			
			int segment_idx = atoi(sep + 1);
			return lws_hls_serve_segment(wsi, vhd->media_dir, filename, segment_idx);
		} else if (!strncmp(url, "/delete/", 8)) {
			if (!pss->has_star_grant) {
				lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, "Forbidden");
				return -1;
			}
			char filename[256];
			lws_strncpy(filename, url + 8, sizeof(filename));
			lws_filename_purify_inplace(filename);
			if (strchr(filename, '/')) {
				lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, "Not Found");
				return -1;
			}
#if defined(LWS_WITH_STUB)
			if (vhd->stub_mgr) {
				char json[256];
				lws_snprintf(json, sizeof(json), "{\"delete\":\"%s\"}", filename);
				lws_stub_request(vhd->stub_mgr, json, NULL, 0, NULL, NULL, NULL);
			}
#endif
			lws_return_http_status(wsi, HTTP_STATUS_OK, "OK");
			return -1;
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
			if ((*ppss)->waiting_for_thumbnail) {
				lws_callback_on_writable((*ppss)->wsi);
			}
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
				uint8_t buf[LWS_PRE + 2048];
				uint8_t *start = buf + LWS_PRE;
				uint8_t *p = start;
				uint8_t *end = buf + sizeof(buf) - 1;

				lwsl_notice("HLS WRITEABLE: sending headers for '%s', len=%zu\n", c->filename, len);

				if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "image/jpeg",
								(lws_filepos_t)len, &p, end)) {
					pthread_mutex_unlock(&vhd->lock);
					return 1;
				}
				
				if (lws_finalize_http_header(wsi, &p, end)) {
					pthread_mutex_unlock(&vhd->lock);
					return 1;
				}
				
				size_t hl = lws_ptr_diff_size_t(p, start);
				if (lws_write(wsi, start, hl, LWS_WRITE_HTTP_HEADERS) != (int)hl) {
					pthread_mutex_unlock(&vhd->lock);
					return 1;
				}
				
				pss->segment_buf = malloc(LWS_PRE + len);
				if (!pss->segment_buf) {
					pthread_mutex_unlock(&vhd->lock);
					return -1;
				}
				
				memcpy(pss->segment_buf + LWS_PRE, c->data, len);
				pss->segment_len = len;
				pss->segment_pos = 0;
				

				
				pss->waiting_for_thumbnail = 0;
				pthread_mutex_unlock(&vhd->lock);
				
				lws_callback_on_writable(wsi);
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

			if (!is_pending && vhd->current_task_filename[0] &&
			    !strcmp(vhd->current_task_filename, pss->thumb_filename)) {
				is_pending = 1;
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
		size_t chunk = rem;
		if (chunk > 4096) {
			chunk = 4096;
		}

		int flags = (pss->segment_pos + chunk == pss->segment_len) ? LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP;
		lwsl_notice("HLS WRITEABLE chunk: pos=%zu, chunk=%zu, total=%zu, final=%d\n", pss->segment_pos, chunk, pss->segment_len, flags == LWS_WRITE_HTTP_FINAL);

		int m = lws_write(wsi, pss->segment_buf + LWS_PRE + pss->segment_pos, chunk, (enum lws_write_protocol)flags);
		lwsl_notice("HLS WRITEABLE chunk: lws_write returned %d\n", m);
		
		if (m < 0) {
			free(pss->segment_buf);
			pss->segment_buf = NULL;
			return -1;
		}
		
		pss->segment_pos += (size_t)m;
		if (pss->segment_pos < pss->segment_len) {
			if (m > 0)
				lws_callback_on_writable(wsi);
			return 0;
		}
		
		free(pss->segment_buf);
		pss->segment_buf = NULL;
		lwsl_notice("HLS WRITEABLE: transaction completed\n");
		return lws_http_transaction_completed(wsi);

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
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

	case LWS_CALLBACK_RAW_RX:
		if (!pss)
			break;
		if (!pss->parser_valid) {
			lejp_construct(&pss->jctx, stub_req_cb, pss, stub_req_paths, 1);
			pss->wsi = wsi;
			pss->parser_valid = 1;
		}
		if (lejp_parse(&pss->jctx, (uint8_t *)in, (int)len) < 0) {
			lwsl_err("Stub lejp parse failed\n");
			return -1;
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		if (pss && pss->parser_valid) {
			lejp_destruct(&pss->jctx);
			pss->parser_valid = 0;
		}
		break;

	case LWS_CALLBACK_RAW_RX_FILE: {
		char buf[512];
		ssize_t n;
		int fd = (int)lws_get_socket_fd(wsi);

		if (fd < 0)
			return -1;

		n = read(fd, buf, sizeof(buf) - 1);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			return -1;
		}
		if (n == 0)
			return -1;

		buf[n] = '\0';
		lwsl_notice("[HLS-STUB] %s", buf);
		break;
	}

	default:
		break;
	}

	return 0;
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
