/*
 * gitws - git to websockets bridge
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#define LWS_DLL
#define LWS_INTERNAL
#include "../lib/libwebsockets.h"
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <libjsongit2.h>

enum {
	EMIT_STATE_SUMMARY,
	EMIT_STATE_SUMMARY_LOG,
};

enum {
	HTTP_STATE_CANNED,
	HTTP_STATE_JSON,
	HTTP_STATE_COMPLETED
};

struct pss_gitws {
	struct jg2_ctx *ctx;
	struct lws *wsi;
	int state;

	/* http */
	size_t pos;
	int http_state;
};

struct vhd_gitws {
	struct jg2_vhost *jg2_vhost;
	const char *html, *vpath;
	unsigned char *html_content;
	size_t html_len;
	size_t dynamic;
};

#define JG2_HTML_DYNAMIC "<!-- libjsongit2:initial-json -->"
#define JG2_HTML_DYNAMIC_LEN 33

static unsigned char *
alloc_file(const char *filepath, size_t *len)
{
	unsigned char *a;
	struct stat s;
	int fd;

	if (stat(filepath, &s)) {
		lwsl_err("%s: cannot stat %s\n", __func__, filepath);

		return NULL;
	}

	a = malloc(s.st_size + 1);
	if (!a) {
		lwsl_err("%s: %s: cannot alloc %llu\n", __func__, filepath,
			(unsigned long long)s.st_size);

		return NULL;
	}
	*len = s.st_size;
	a[s.st_size] = '\0';

	fd = open(filepath, O_RDONLY);
	if (fd < 0) {
		lwsl_err("%s: cannot open %s\n", __func__, filepath);
		goto bail;
	}

	if (read(fd, a, s.st_size) < 0) {
		lwsl_err("%s: cannot read %s\n", __func__, filepath);
		goto bail1;
	}

	close(fd);

	return a;

bail1:
	close(fd);
bail:
	free(a);

	return NULL;
}

void refchange(void * user)
{
	struct pss_gitws *pss = (struct pss_gitws *)user;

	lwsl_notice("%s: %p\n", __func__, pss);

	lws_callback_on_writable(pss->wsi);
}

static int
callback_gitws(struct lws *wsi, enum lws_callback_reasons reason,
	       void *user, void *in, size_t len)
{
	struct pss_gitws *pss = (struct pss_gitws *)user;
	struct vhd_gitws *vhd = (struct vhd_gitws *)
			      lws_protocol_vh_priv_get(lws_get_vhost(wsi),
						       lws_get_protocol(wsi));
	char buf[LWS_PRE + 4096], partway;
	unsigned char *p = (unsigned char *)&buf[LWS_PRE], *start = p,
		      *end = (unsigned char *)buf + sizeof(buf);
	struct jg2_vhost_config config;
	int n, m, more;

	switch (reason) {

	/* --------------- protocol --------------- */

	case LWS_CALLBACK_PROTOCOL_INIT: /* per vhost */
		lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
					    lws_get_protocol(wsi),
					    sizeof(struct vhd_gitws));
		vhd = (struct vhd_gitws *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
						 lws_get_protocol(wsi));

		vhd->html = lws_pvo_search(
				(const struct lws_protocol_vhost_options *)in,
				"html-file")->value;
		vhd->vpath = lws_pvo_search(
				(const struct lws_protocol_vhost_options *)in,
				"vpath")->value;

		/* we hold the vhost's canned html in memory for speed */

		vhd->html_content = alloc_file(vhd->html, &vhd->html_len);
		if (!vhd->html_content)
			return 1;

		{
			char *q = strstr((char *)vhd->html_content,
					 JG2_HTML_DYNAMIC);

			if (q)
				vhd->dynamic = q - (char *)vhd->html_content;
			else {
				lwsl_err("%s: %s lacks %s marker\n",
					 __func__, vhd->html, JG2_HTML_DYNAMIC);

				return -1;
			}
		}

		memset(&config, 0, sizeof(config));
		config.virtual_base_urlpath = vhd->vpath;
		config.refchange = refchange;
		vhd->jg2_vhost = jg2_vhost_create(&config);

		if (!vhd->jg2_vhost)
			return -1;

		lws_timed_callback_vh_protocol(lws_get_vhost(wsi),
						lws_get_protocol(wsi),
						LWS_CALLBACK_USER, 3);
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY: /* per vhost */
		if (vhd->html_content)
			free(vhd->html_content);
		jg2_vhost_destroy(vhd->jg2_vhost);
		vhd->jg2_vhost = NULL;
		break;

	case LWS_CALLBACK_USER:

		jg2_vhost_repo_reflist_update(vhd->jg2_vhost);

		lws_timed_callback_vh_protocol(lws_get_vhost(wsi),
						lws_get_protocol(wsi),
						LWS_CALLBACK_USER, 3);
		break;

	/* --------------- ws --------------- */

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_notice("%s: LWS_CALLBACK_ESTABLISHED\n", __func__);
		if (jg2_ctx_create(vhd->jg2_vhost, &pss->ctx,
					"/projects/libwebsockets/.git", pss))
			return -1;
		pss->wsi = wsi;
		break;

	case LWS_CALLBACK_CLOSED:
		lwsl_err("%s: LWS_CALLBACK_CLOSED\n", __func__);
		jg2_ctx_destroy(pss->ctx);
		break;

	case LWS_CALLBACK_RECEIVE:
		/*
		 * 		pss->state = EMIT_STATE_SUMMARY;
		jg2_ctx_set_job(pss->ctx, jg2_get_job(JG2_JOB_REFLIST),
				     NULL, 0, 0);
		lws_callback_on_writable(wsi);
		 */
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:

		if (!jg2_ctx_get_job(pss->ctx))
			break;

		partway = jg2_ctx_is_partway(pss->ctx);

		m = jg2_ctx_get_job(pss->ctx)(pss->ctx, &buf[LWS_PRE],
				     sizeof(buf) - LWS_PRE);
		if (m < 0)
			return -1;

		if (lws_write(wsi, (unsigned char *)&buf[LWS_PRE],
			      jg2_ctx_buf_used(pss->ctx),
			      lws_write_ws_flags(LWS_WRITE_TEXT, !partway,
					jg2_ctx_is_final(pss->ctx))) < 0) {
			lwsl_err("write failed: %d %d\n",
				 jg2_ctx_buf_used(pss->ctx),
				 lws_write_ws_flags(LWS_WRITE_TEXT, !partway,
				 	jg2_ctx_is_final(pss->ctx)));
			return -1;
		}

		if (m)
			lws_callback_on_writable(wsi);
		else {
			switch (pss->state) {
			case EMIT_STATE_SUMMARY:
				pss->state = EMIT_STATE_SUMMARY_LOG;
				jg2_ctx_set_job(pss->ctx,
						jg2_get_job(JG2_JOB_LOG),
						     "refs/heads/master", 10, 1);
				lws_callback_on_writable(wsi);
				break;
			default:
				break;
			}
		}
		break;

	/* --------------- http --------------- */

	case LWS_CALLBACK_HTTP:
		/*
		 * "in" contains the url part after our mountpoint, if any.
		 *
		 * Our strategy is to record the URL for the duration of the
		 * transaction and return the user's configured html template,
		 * plus JSON prepared based on the URL.  That lets the page
		 * display remotely in one roundtrip (+tls) without having to
		 * wait for the ws link to come up.
		 *
		 * Serving anything other than the configured html template
		 * will have to come from outside this mount URL path.
		 */
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
				"text/html", LWS_ILLEGAL_HTTP_CONTENT_LEN,
				&p, end))
			return 1;
		if (lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_CLOSED_HTTP:
		lwsl_err("%s: LWS_CALLBACK_CLOSED_HTTP\n", __func__);
		jg2_ctx_destroy(pss->ctx);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:

		if (!pss || pss->http_state == HTTP_STATE_COMPLETED)
			break;

		n = LWS_WRITE_HTTP;
		m = 0;
		switch (pss->http_state) {
		case HTTP_STATE_CANNED:
			m = vhd->dynamic - pss->pos > sizeof(buf) - LWS_PRE ?
			    sizeof(buf) - LWS_PRE : vhd->dynamic - pss->pos;
			memcpy(buf + LWS_PRE, vhd->html_content + pss->pos, m);
			pss->pos += m;
			if (pss->pos == vhd->dynamic) {
				pss->http_state = HTTP_STATE_JSON;
				if (jg2_ctx_create(vhd->jg2_vhost, &pss->ctx,
							"/projects/libwebsockets/.git", pss)) {
					lwsl_err("%s: jg2_ctx_create fail\n", __func__);
					return -1;
				}

				pss->state = EMIT_STATE_SUMMARY;
				jg2_ctx_set_job(pss->ctx,
						jg2_get_job(JG2_JOB_REFLIST),
						     NULL, 0, 0);
			}
			break;
		case HTTP_STATE_JSON:
			if (!jg2_ctx_get_job(pss->ctx))
				break;

			partway = jg2_ctx_is_partway(pss->ctx);
			more = jg2_ctx_get_job(pss->ctx)(pss->ctx,
					     &buf[LWS_PRE], sizeof(buf) - LWS_PRE -
					     ((vhd->html_len - vhd->dynamic) -
					     JG2_HTML_DYNAMIC_LEN));
			if (more < 0) {
				lwsl_err("get_job failed\n");
				return -1;
			}

			m = jg2_ctx_buf_used(pss->ctx);
			if (more)
				break;

			switch (pss->state) {
			case EMIT_STATE_SUMMARY:
				pss->state = EMIT_STATE_SUMMARY_LOG;
				jg2_ctx_set_job(pss->ctx,
						jg2_get_job(JG2_JOB_LOG),
						     "refs/heads/master", 10, 1);
				break;
			default:
				strcpy(buf + LWS_PRE + m,
				       (char *)vhd->html_content +
				       vhd->dynamic + JG2_HTML_DYNAMIC_LEN);
				m += vhd->html_len - vhd->dynamic -
				     JG2_HTML_DYNAMIC_LEN;
				pss->http_state = HTTP_STATE_COMPLETED;
				n = LWS_WRITE_HTTP_FINAL;
				break;
			}
			break;
		default:
			return 0;
		}

		if (lws_write(wsi, (unsigned char *)buf + LWS_PRE, m, n) != m)
			return 1;

		if (pss->http_state == HTTP_STATE_COMPLETED) {
		    if (lws_http_transaction_completed(wsi))
			return -1;
		} else
			lws_callback_on_writable(wsi);

		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{
		"lws-gitws",
		callback_gitws,
		sizeof(struct pss_gitws),
		4096,
	},
};

LWS_EXTERN LWS_VISIBLE int
init_protocol_gitws(struct lws_context *context,
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
destroy_protocol_gitws(struct lws_context *context)
{
	return 0;
}
