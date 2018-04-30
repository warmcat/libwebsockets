/*
 * ws protocol handler plugin for "POST demo"
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
 * These test plugins are intended to be adapted for use in your code, which
 * may be proprietary.  So unlike the library itself, they are licensed
 * Public Domain.
 */

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include "../lib/libwebsockets.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef WIN32
#include <io.h>
#endif
#include <stdio.h>

struct per_session_data__post_demo {
	struct lws_spa *spa;
	char result[LWS_PRE + 512];
	int result_len;

	char filename[64];
	long file_length;
#if !defined(LWS_WITH_ESP32)
	lws_filefd_type fd;
#endif
};

static const char * const param_names[] = {
	"text",
	"send",
	"file",
	"upload",
};

enum enum_param_names {
	EPN_TEXT,
	EPN_SEND,
	EPN_FILE,
	EPN_UPLOAD,
};

static int
file_upload_cb(void *data, const char *name, const char *filename,
	       char *buf, int len, enum lws_spa_fileupload_states state)
{
	struct per_session_data__post_demo *pss =
			(struct per_session_data__post_demo *)data;
#if !defined(LWS_WITH_ESP32)
	int n;

	(void)n;
#endif

	switch (state) {
	case LWS_UFS_OPEN:
		lws_strncpy(pss->filename, filename, sizeof(pss->filename));
		/* we get the original filename in @filename arg, but for
		 * simple demo use a fixed name so we don't have to deal with
		 * attacks  */
#if !defined(LWS_WITH_ESP32)
		pss->fd = (lws_filefd_type)(long long)open("/tmp/post-file",
			       O_CREAT | O_TRUNC | O_RDWR, 0600);
#endif
		break;
	case LWS_UFS_FINAL_CONTENT:
	case LWS_UFS_CONTENT:
		if (len) {
			pss->file_length += len;

			/* if the file length is too big, drop it */
			if (pss->file_length > 100000)
				return 1;

#if !defined(LWS_WITH_ESP32)
			n = write((int)(long long)pss->fd, buf, len);
			lwsl_info("%s: write %d says %d\n", __func__, len, n);
#else
			lwsl_notice("%s: Received chunk size %d\n", __func__, len);
#endif
		}
		if (state == LWS_UFS_CONTENT)
			break;
#if !defined(LWS_WITH_ESP32)
		close((int)(long long)pss->fd);
		pss->fd = LWS_INVALID_FILE;
#endif
		break;
	}

	return 0;
}

static int
callback_post_demo(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	struct per_session_data__post_demo *pss =
			(struct per_session_data__post_demo *)user;
	unsigned char *buffer;
	unsigned char *p, *start, *end;
	int n;

	switch (reason) {
	case LWS_CALLBACK_HTTP_BODY:
		/* create the POST argument parser if not already existing */
		if (!pss->spa) {
			pss->spa = lws_spa_create(wsi, param_names,
					ARRAY_SIZE(param_names), 1024,
					file_upload_cb, pss);
			if (!pss->spa)
				return -1;

			pss->filename[0] = '\0';
			pss->file_length = 0;
		}

		/* let it parse the POST data */
		if (lws_spa_process(pss->spa, in, (int)len))
			return -1;
		break;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		lwsl_debug("LWS_CALLBACK_HTTP_BODY_COMPLETION: %p\n", wsi);
		/* call to inform no more payload data coming */
		lws_spa_finalize(pss->spa);

		p = (unsigned char *)pss->result + LWS_PRE;
		end = p + sizeof(pss->result) - LWS_PRE - 1;
		p += sprintf((char *)p,
			"<html><body><h1>Form results (after urldecoding)</h1>"
			"<table><tr><td>Name</td><td>Length</td><td>Value</td></tr>");

		for (n = 0; n < (int)ARRAY_SIZE(param_names); n++) {
			if (!lws_spa_get_string(pss->spa, n))
				p += lws_snprintf((char *)p, end - p,
				    "<tr><td><b>%s</b></td><td>0</td><td>NULL</td></tr>",
				    param_names[n]);
			else
				p += lws_snprintf((char *)p, end - p,
				    "<tr><td><b>%s</b></td><td>%d</td><td>%s</td></tr>",
				    param_names[n],
				    lws_spa_get_length(pss->spa, n),
				    lws_spa_get_string(pss->spa, n));
		}

		p += lws_snprintf((char *)p, end - p, "</table><br><b>filename:</b> %s, <b>length</b> %ld",
				pss->filename, pss->file_length);

		p += lws_snprintf((char *)p, end - p, "</body></html>");
		pss->result_len = lws_ptr_diff(p, pss->result + LWS_PRE);

		n = LWS_PRE + 1024;
		buffer = malloc(n);
		p = buffer + LWS_PRE;
		start = p;
		end = p + n - LWS_PRE - 1;

		if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end))
			goto bail;

		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
				(unsigned char *)"text/html", 9, &p, end))
			goto bail;
		if (lws_add_http_header_content_length(wsi, pss->result_len, &p, end))
			goto bail;
		if (lws_finalize_http_header(wsi, &p, end))
			goto bail;

		n = lws_write(wsi, start, p - start, LWS_WRITE_HTTP_HEADERS);
		if (n < 0)
			goto bail;
		free(buffer);

		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss->result_len) {
			lwsl_debug("nothing in result_len\n");
			break;
		}
		lwsl_debug("LWS_CALLBACK_HTTP_WRITEABLE: sending %d\n",
			   pss->result_len);
		n = lws_write(wsi, (unsigned char *)pss->result + LWS_PRE,
			      pss->result_len, LWS_WRITE_HTTP_FINAL);
		if (n < 0)
			return 1;
		goto try_to_reuse;

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		/* called when our wsi user_space is going to be destroyed */
		if (pss->spa) {
			lws_spa_destroy(pss->spa);
			pss->spa = NULL;
		}
		break;

	default:
		break;
	}

	return 0;

bail:
	free(buffer);

	return 1;

try_to_reuse:
	if (lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_POST_DEMO \
	{ \
		"protocol-post-demo", \
		callback_post_demo, \
		sizeof(struct per_session_data__post_demo), \
		1024, \
		0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)

static const struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_POST_DEMO
};

LWS_EXTERN LWS_VISIBLE int
init_protocol_post_demo(struct lws_context *context,
			struct lws_plugin_capability *c)
{
	if (c->api_magic != LWS_PLUGIN_API_MAGIC) {
		lwsl_err("Plugin API %d, library API %d", LWS_PLUGIN_API_MAGIC,
			 c->api_magic);
		return 1;
	}

	c->protocols = protocols;
	c->count_protocols = ARRAY_SIZE(protocols);
	c->extensions = NULL;
	c->count_extensions = 0;

	return 0;
}

LWS_EXTERN LWS_VISIBLE int
destroy_protocol_post_demo(struct lws_context *context)
{
	return 0;
}

#endif
