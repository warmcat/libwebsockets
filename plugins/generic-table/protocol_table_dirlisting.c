/*
 * ws protocol handler plugin for dirlisting "generic table" demo
 *
 * Copyright (C) 2010-2016 Andy Green <andy@warmcat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation:
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301  USA
 */

#define LWS_DLL
#define LWS_INTERNAL
#include "../lib/libwebsockets.h"

#include <stdlib.h>
#include <string.h>
#include <uv.h>

struct fobj {
	struct fobj *next;
	const char *name, *uri, *icon, *date;
	time_t m;
	unsigned long size;
};

struct per_session_data__tbl_dir {
	struct fobj base;
	char strings[64 * 1024];
	char reldir[256];
	char *p;
	const char *dir;

#if UV_VERSION_MAJOR > 0
	uv_fs_event_t *event_req;
#endif
	struct lws *wsi;
};

#if UV_VERSION_MAJOR > 0
static void
mon_cb(uv_fs_event_t *handle, const char *filename, int events, int status)
{
	struct per_session_data__tbl_dir *pss = handle->data;

	//lwsl_notice("%s\n", __func__);

	if (pss && pss->wsi)
		lws_callback_on_writable(pss->wsi);
}

static void lws_uv_close_cb(uv_handle_t *handle)
{
	free(handle);
}

static void
lws_protocol_dir_kill_monitor(struct per_session_data__tbl_dir *pss)
{
	if (!pss->event_req)
		return;
	pss->wsi = NULL;
	pss->event_req->data = NULL;
	uv_fs_event_stop(pss->event_req);
	uv_close((uv_handle_t *)pss->event_req, lws_uv_close_cb);
	pss->event_req = NULL;
}
#endif

static int
scan_dir(struct lws *wsi, struct per_session_data__tbl_dir *pss)
{
/* uuh travis... */
#if UV_VERSION_MAJOR > 0
	uv_loop_t *loop = lws_uv_getloop(lws_get_context(wsi), 0);
	char *end = &(pss->strings[sizeof(pss->strings) - 1]);
	struct fobj *prev = &pss->base;
	char path[512], da[200];
	const char *icon;
	uv_dirent_t dent;
	struct fobj *f;
	struct stat st;
	struct tm *tm;
	int ret = 0, n;
	uv_fs_t req;

	lws_protocol_dir_kill_monitor(pss);

	lws_snprintf(path, sizeof(path) - 1, "%s/%s", pss->dir, pss->reldir);
	//lwsl_notice("path = %s\n", path);

	pss->event_req = malloc(sizeof(*pss->event_req));
	if (!pss->event_req)
		return 2;

	pss->wsi = wsi;
	pss->event_req->data = pss;

        uv_fs_event_init(lws_uv_getloop(lws_get_context(wsi), 0),
        		 pss->event_req);
        // The recursive flag watches subdirectories too.
        n = uv_fs_event_start(pss->event_req, mon_cb, path, UV_FS_EVENT_RECURSIVE);
        //lwsl_notice("monitoring %s (%d)\n", path, n);

	if (!uv_fs_scandir(loop, &req, path, 0, NULL)) {
		lwsl_err("Scandir on %s failed\n", path);
		return 2;
	}

	pss->p = pss->strings;

	while (uv_fs_scandir_next(&req, &dent) != UV_EOF) {
		lws_snprintf(path, sizeof(path) - 1, "%s/%s/%s", pss->dir, pss->reldir, dent.name);

		if (stat(path, &st)) {
			lwsl_info("unable to stat %s\n", path);
			continue;
		}
		f = malloc(sizeof(*f));
		f->next = NULL;
		f->name = pss->p;
		n = lws_snprintf(pss->p, end - pss->p, "%s", dent.name);
		pss->p += n + 1;
		f->uri = NULL;
		if ((S_IFMT & st.st_mode) == S_IFDIR) {
			n = lws_snprintf(pss->p, end - pss->p, "=%s/%s", pss->reldir, dent.name);
			f->uri = pss->p;
		}
		if (lws_get_mimetype(dent.name, NULL)) {
			n = lws_snprintf(pss->p, end - pss->p, "./serve/%s/%s", pss->reldir, dent.name);
			f->uri = pss->p;
		}
		if (f->uri)
			pss->p += n + 1;

		if (end - pss->p < 100) {
			free(f);
			break;
		}

		icon = " ";
		if ((S_IFMT & st.st_mode) == S_IFDIR)
			icon = "&#x1f4c2;";

		f->icon = pss->p;
		n = lws_snprintf(pss->p, end - pss->p, "%s", icon);
		pss->p += n + 1;

		f->date = pss->p;
		tm = gmtime(&st.st_mtime);
		strftime(da, sizeof(da), "%Y-%b-%d %H:%M:%S %z", tm);
		n = lws_snprintf(pss->p, end - pss->p, "%s", da);
		pss->p += n + 1;

		f->size = st.st_size;
		f->m = st.st_mtime;
		prev->next = f;
		prev = f;
	}

	uv_fs_req_cleanup(&req);

	return ret;
#else
	return 0;
#endif
}

static void
free_scan_dir(struct per_session_data__tbl_dir *pss)
{
	struct fobj *f = pss->base.next, *f1;

	while (f) {
		f1 = f->next;
		free(f);
		f = f1;
	}

	pss->base.next = NULL;
}

static int
callback_lws_table_dirlisting(struct lws *wsi, enum lws_callback_reasons reason,
			      void *user, void *in, size_t len)
{
	struct per_session_data__tbl_dir *pss = (struct per_session_data__tbl_dir *)user;
	char j[LWS_PRE + 16384], *p = j + LWS_PRE, *start = p, *q, *q1, *w,
		*end = j + sizeof(j) - LWS_PRE, e[384], s[384], s1[384];
	const struct lws_protocol_vhost_options *pmo;
	struct fobj *f;
	int n, first = 1;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT: /* per vhost */
		break;

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_debug("LWS_CALLBACK_ESTABLISHED\n");
		/*
		 * send client the lwsgt table layout
		 */
		start = "{\"cols\":["
			"  {\"name\": \"Date\"},"
			"  {\"name\": \"Size\", \"align\": \"right\"},"
			"  {\"name\": \"Icon\"},"
			"  {\"name\": \"Name\", \"href\": \"uri\"},"
			"  {\"name\": \"uri\", \"hide\": \"1\" }"
			" ]"
			"}";
		if (lws_write(wsi, (unsigned char *)start, strlen(start),
			      LWS_WRITE_TEXT) < 0)
			return -1;

		/* send a view update next */
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RECEIVE:
		if (len > sizeof(pss->reldir) - 1)
			len = sizeof(pss->reldir) - 1;
		if (!strstr(in, "..") && !strchr(in, '~'))
			lws_strncpy(pss->reldir, in, len + 1);
		else
			len = 0;
		pss->reldir[len] = '\0';
		if (pss->reldir[0] == '/' && !pss->reldir[1])
			pss->reldir[0] = '\0';
		lwsl_info("%s\n", pss->reldir);
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:

		if (scan_dir(wsi, pss))
			return 1;

		p += lws_snprintf(p, end - p, "{\"breadcrumbs\":[");
		q = pss->reldir;

		if (!q[0])
			p += lws_snprintf(p, end - p, "{\"name\":\"top\"}");

		while (*q) {

			q1 = strchr(q, '/');
			if (!q1) {
				if (first)
					strcpy(s, "top1");
				else
					strcpy(s, q);
				s1[0] = '\0';
				q += strlen(q);
			} else {
				n = lws_ptr_diff(q1, q);
				if (n > (int)sizeof(s) - 1)
					n = sizeof(s) - 1;
				if (first) {
					strcpy(s1, "/");
					strcpy(s, "top");
				} else {
					lws_strncpy(s, q, n + 1);

					n = lws_ptr_diff(q1, pss->reldir);
					if (n > (int)sizeof(s1) - 1)
						n = sizeof(s1) - 1;
					lws_strncpy(s1, pss->reldir, n + 1);
				}
				q = q1 + 1;
			}
			if (!first)
				p += lws_snprintf(p, end - p, ",");
			else
				first = 0;

			p += lws_snprintf(p, end - p, "{\"name\":\"%s\"",
					lws_json_purify(e, s, sizeof(e)));
			if (*q) {
				w = s1;
				while (w[0] == '/' && w[1] == '/')
					w++;
				p += lws_snprintf(p, end - p, ",\"url\":\"%s\"",
					lws_json_purify(e, w, sizeof(e)));
			}
			p += lws_snprintf(p, end - p, "}");
			if (!q1)
				break;
		}

		p += lws_snprintf(p, end - p, "],\"data\":[");

		f = pss->base.next;
		while (f) {
			/* format in JSON */
			p += lws_snprintf(p, end - p, "{\"Icon\":\"%s\",",
					lws_json_purify(e, f->icon, sizeof(e)));
			p += lws_snprintf(p, end - p, " \"Date\":\"%s\",",
				lws_json_purify(e, f->date, sizeof(e)));
			p += lws_snprintf(p, end - p, " \"Size\":\"%ld\",",
				f->size);
			if (f->uri)
				p += lws_snprintf(p, end - p, " \"uri\":\"%s\",",
						lws_json_purify(e, f->uri, sizeof(e)));
			p += lws_snprintf(p, end - p, " \"Name\":\"%s\"}",
				lws_json_purify(e, f->name, sizeof(e)));

			f = f->next;

			if (f)
				p += lws_snprintf(p, end - p, ",");
		}

		p += lws_snprintf(p, end - p, "]}");

		free_scan_dir(pss);

		if (lws_write(wsi, (unsigned char *)start, p - start,
			      LWS_WRITE_TEXT) < 0)
			return -1;

		break;

	case LWS_CALLBACK_HTTP_PMO:
		/* find the per-mount options we're interested in */
		lwsl_debug("LWS_CALLBACK_HTTP_PMO\n");
		pmo = (struct lws_protocol_vhost_options *)in;
		while (pmo) {
			if (!strcmp(pmo->name, "dir")) /* path to list files */
				pss->dir = pmo->value;
			pmo = pmo->next;
		}
		if (!pss->dir[0]) {
			lwsl_err("dirlisting: \"dir\" pmo missing\n");
			return 1;
		}
		break;

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		//lwsl_notice("LWS_CALLBACK_HTTP_DROP_PROTOCOL\n");
#if UV_VERSION_MAJOR > 0
		lws_protocol_dir_kill_monitor(pss);
#endif
		break;

	default:
		return 0;
	}

	return 0;

}

static const struct lws_protocols protocols[] = {
	{
		"protocol-lws-table-dirlisting",
		callback_lws_table_dirlisting,
		sizeof(struct per_session_data__tbl_dir),
		0,
	},
};

LWS_EXTERN LWS_VISIBLE int
init_protocol_lws_table_dirlisting(struct lws_context *context,
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
destroy_protocol_lws_table_dirlisting(struct lws_context *context)
{
	return 0;
}
