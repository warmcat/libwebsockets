/*
 * hproxy - unidirectional proxy
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
 *
 *
 * This isn't a generic proxy.
 *
 * You can request a cache dir be filled by reading things from a specific
 * remote URL base + a path, using an api reachable from the protocol name +
 * vhost instance.  It's the only way to make requests to fill the cache.
 *
 * Then, separately, you can expose the cache dir as a normal read-only mount
 * dir with whatever caching policy you want.
 *
 * Downstream cache consumers can't request things that aren't already in the
 * cache then, removing any worries about being misused to attack the upstream.
 */

#define LWS_DLL
#define LWS_INTERNAL
#include "../lib/libwebsockets.h"
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>

#include <sys/stat.h>

struct req {
	struct lws_dll next;
	char filepath[384];
	int fd;
};

struct pss_hproxy {
	struct lws *wsi;
	int state;
};

struct vhd_hproxy {
	const char *remote_base /*
				 * the remote URL being proxied, eg,
				 * https://somewhere.com/ ... fetches will only
				 * be made to URLs starting with this plus
				 * whatever path came in on the request
				 */,
		   *cache_dir;

	struct lws_dll head;
	struct lws_context *context;
};

static const struct lws_protocols protocols[];

static int
path_to_cache_filename(const char *path, char *filename, int len)
{
	const char *p = path;
	char *p1 = filename;

	while (*p && --len > 5) {
		if (*p == '.' && p[1] == '.') {
			*p1++ = '-';
			*p1++ = '-';
			p++;
		} else
			if (*p == '/')
				*p1++ = '_';
			else if (*p == '?')
				*p1++ = '_';
			else if (*p == '&')
				*p1++ = '_';
			else
				*p1++ = *p;

		p++;
	}

	*p1++ = '.'; /* hack... currently everything in the proxy is a png */
	*p1++ = 'p';
	*p1++ = 'n';
	*p1++ = 'g';
	*p1 = '\0';

	return !len;
}

/*
 * Unlike a generic proxy, the downstream side cannot make requests to fill
 * the cache directly.
 *
 * This api function is the only way to request "path" from vhd->remote_base
 * (ie, https://myremote.base/path) to appear in vhd->cache_dir, in "flattened"
 * filename form.
 */

enum {
	MENTION_REQUESTED,
	MENTION_FAILED,
	MENTION_EXISTS,
};

static int
mention(struct lws_protocols *pcol, struct lws_vhost *vh, const char *path)
{
	struct vhd_hproxy *vhd = (struct vhd_hproxy *)
					  lws_protocol_vh_priv_get(vh, pcol);
	struct lws_client_connect_info i;
	const char *prot, *opath;
	struct req *req;
	struct lws *wsi;
	char *tmp;
	int fd;

	req = malloc(sizeof(*req));
	if (!req)
		return MENTION_FAILED;
	memset(req, 0, sizeof(*req));

	strcpy(req->filepath, vhd->cache_dir);
	if (req->filepath[strlen(req->filepath) - 1] != '/')
		strcat(req->filepath, "/");
	if (path_to_cache_filename(path, req->filepath + strlen(req->filepath),
				   sizeof(req->filepath) - 1 -
				   strlen(req->filepath)))
		goto bail1;

	/* it already exists as a file in the cache? */

	fd = open(req->filepath, O_RDONLY);
	if (fd >= 0) {
		free(req);
		close(fd);

		return MENTION_EXISTS;
	}

	/* a request is underway already? */

	lws_start_foreach_dll(struct lws_dll *, p, vhd->head.next) {
		struct req *r = (struct req *)p;

		if (!strcmp(r->filepath, req->filepath)) {
			free(req);

			return MENTION_REQUESTED;
		}
	} lws_end_foreach_dll(p);

	/* we're going to request it then... */

	req->fd = open(req->filepath, O_RDWR | O_TRUNC | O_CREAT, 0600);
	if (req->fd < 0) {
		lwsl_err("%s: unable to open %s: errno %d\n", __func__,
				req->filepath, errno);
		goto bail1;
	}

	memset(&i, 0, sizeof(i));

	i.context = vhd->context;
	i.ssl_connection = LCCSCF_PIPELINE /* | LCCSCF_ALLOW_SELFSIGNED */;

	tmp = strdup(vhd->remote_base);
	if (lws_parse_uri(tmp, &prot, &i.address, &i.port, &opath)) {
		lwsl_notice("%s: parse uri %s: failed\n", __func__, tmp);
		free(tmp);
		return MENTION_FAILED;
	}
	if (!strcmp(prot, "https"))
		i.ssl_connection |= LCCSCF_USE_SSL;

	i.host = i.address;
	i.origin = i.address;
	i.method = "GET";
	i.protocol = "lws-hproxy";
	i.path = path;
	i.vhost = vh;
	i.alpn = "http/1.1";

	i.userdata = req;

	lws_dll_add_front(&req->next, &vhd->head);

	wsi = lws_client_connect_via_info(&i);
	if (wsi) {
		lwsl_notice("%s: requested %s %s:%d %s\n", __func__, prot,
				i.address, i.port, path);
		free(tmp);

		return MENTION_REQUESTED;
	}
	free(tmp);

	/* wasn't able to get started */

	lws_dll_remove(&req->next);

	lwsl_notice("%s: lws_client_connect_via_info failed\n", __func__);

bail1:
	free(req);

	lwsl_notice("%s: failed %s\n", __func__, path);

	return MENTION_FAILED;
}

static int
get_pvo(void *in, const char *name, const char **result)
{
	const struct lws_protocol_vhost_options *pv =
		lws_pvo_search((const struct lws_protocol_vhost_options *)in,
				name);

	if (!pv)
		return 1;

	*result = (const char *)pv->value;

	return 0;
}

static int
callback_hproxy(struct lws *wsi, enum lws_callback_reasons reason,
	       void *user, void *in, size_t len)
{
	struct vhd_hproxy *vhd = (struct vhd_hproxy *)
			      lws_protocol_vh_priv_get(lws_get_vhost(wsi),
						       lws_get_protocol(wsi));
	struct req *req;

	switch (reason) {

	/* --------------- protocol --------------- */

	case LWS_CALLBACK_PROTOCOL_INIT: /* per vhost */
		lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
					    lws_get_protocol(wsi),
					    sizeof(struct vhd_hproxy));
		vhd = (struct vhd_hproxy *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
						 lws_get_protocol(wsi));

		if (get_pvo(in, "remote-base", &vhd->remote_base))
			return -1;
		if (get_pvo(in, "cache-dir", &vhd->cache_dir))
			return -1;

		vhd->context = lws_get_context(wsi);

		lws_timed_callback_vh_protocol(lws_get_vhost(wsi),
					       lws_get_protocol(wsi),
					       LWS_CALLBACK_USER, 3);
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY: /* per vhost */
		break;

	case LWS_CALLBACK_USER:
		lws_timed_callback_vh_protocol(lws_get_vhost(wsi),
						lws_get_protocol(wsi),
						LWS_CALLBACK_USER, 3);
		break;

	/* --------------- http client --------------- */

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		lwsl_user("LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP %p\n", wsi);
		return 0;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
				in ? (char *)in : "(null)");
		req = (struct req *)user;
		lws_dll_remove(&req->next);
		free(req);
		return 0;

	/* chunks of chunked content, with header removed */
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		lwsl_user("RECEIVE_CLIENT_HTTP_READ: read %d\n", (int)len);
		req = (struct req *)user;
		write(req->fd, in, len);
		return 0; /* don't passthru */

	/* uninterpreted http content */
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		{
			char buffer[1024 + LWS_PRE];
			char *px = buffer + LWS_PRE;
			int lenx = sizeof(buffer) - LWS_PRE;

			if (lws_http_client_read(wsi, &px, &lenx) < 0)
				return -1;
		}
		return 0; /* don't passthru */

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		lwsl_user("LWS_CALLBACK_COMPLETED_CLIENT_HTTP %p\n", wsi);
		return 0;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		lwsl_user("LWS_CALLBACK_CLOSED_CLIENT_HTTP %p\n", wsi);
		req = (struct req *)user;
		close(req->fd);
		lws_dll_remove(&req->next);
		free(req);
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{
		"lws-hproxy",
		callback_hproxy,
		sizeof(struct pss_hproxy),
		4096,
		0,
		(void *)mention
	},
};

LWS_EXTERN LWS_VISIBLE int
init_protocol_hproxy(struct lws_context *context,
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
destroy_protocol_hproxy(struct lws_context *context)
{
	return 0;
}
