/*
 * libwebsockets web server application
 *
 * Copyright (C) 2010-2016 Andy Green <andy@warmcat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
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

#include "lwsws.h"

static const char * const paths_global[] = {
	"global.uid",
	"global.gid",
	"global.interface",
	"global.count-threads",
	"global.init-ssl",
};

enum lejp_global_paths {
	LEJPGP_UID,
	LEJPGP_GID,
	LEJPGP_INTERFACE,
	LEJPGP_COUNT_THREADS,
	LWJPGP_INIT_SSL,
};

static const char * const paths_vhosts[] = {
	"vhosts[]",
	"vhosts[].mounts[]",
	"vhosts[].name",
	"vhosts[].port",
	"vhosts[].host-ssl-key",
	"vhosts[].host-ssl-cert",
	"vhosts[].host-ssl-ca",
	"vhosts[].mounts[].mountpoint",
	"vhosts[].mounts[].origin",
	"vhosts[].mounts[].default",
	"vhosts[].ws-protocols[].*.*",
	"vhosts[].ws-protocols[].*",
	"vhosts[].ws-protocols[]"
};

enum lejp_vhost_paths {
	LEJPVP,
	LEJPVP_MOUNTS,
	LEJPVP_NAME,
	LEJPVP_PORT,
	LEJPVP_HOST_SSL_KEY,
	LEJPVP_HOST_SSL_CERT,
	LEJPVP_HOST_SSL_CA,
	LEJPVP_MOUNTPOINT,
	LEJPVP_ORIGIN,
	LEJPVP_DEFAULT,
	LEJPVP_PROTOCOL_NAME_OPT,
	LEJPVP_PROTOCOL_NAME,
	LEJPVP_PROTOCOL,
};

struct jpargs {
	struct lws_context_creation_info *info;
	struct lws_context *context;
	const struct lws_protocols *protocols;
	const struct lws_extension *extensions;
	char *p, *end, valid;
	struct lws_http_mount *head, *last;
	char *mountpoint, *origin, *def;
	struct lws_protocol_vhost_options *pvo;
};

static void *
lwsws_align(struct jpargs *a)
{
	if ((unsigned long)(a->p) & 15)
		a->p += 16 - ((unsigned long)(a->p) & 15);

	return a->p;
}

static int arg_to_bool(const char *s)
{
	static const char * const on[] = { "on", "yes", "true" };
	int n = atoi(s);

	if (n)
		return 1;

	for (n = 0; n < ARRAY_SIZE(on); n++)
		if (!strcasecmp(s, on[n]))
			return 1;

	return 0;
}

static char
lejp_globals_cb(struct lejp_ctx *ctx, char reason)
{
	struct jpargs *a = (struct jpargs *)ctx->user;

	/* we only match on the prepared path strings */
	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {
	case LEJPGP_UID:
		a->info->uid = atoi(ctx->buf);
		return 0;
	case LEJPGP_GID:
		a->info->gid = atoi(ctx->buf);
		return 0;
	case LEJPGP_INTERFACE:
		a->info->iface = a->p;
		break;
	case LEJPGP_COUNT_THREADS:
		a->info->count_threads = atoi(ctx->buf);
		return 0;
	case LWJPGP_INIT_SSL:
		if (arg_to_bool(ctx->buf))
			a->info->options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
		return 0;

	default:
		return 0;
	}

	a->p += snprintf(a->p, a->end - a->p, "%s", ctx->buf);

	return 0;
}

static char
lejp_vhosts_cb(struct lejp_ctx *ctx, char reason)
{
	struct jpargs *a = (struct jpargs *)ctx->user;
	struct lws_protocol_vhost_options *pvo;
	struct lws_http_mount *m;
	int n;

//	lwsl_notice(" %d: %s (%d)\n", reason, ctx->path, ctx->path_match);
//	for (n = 0; n < ctx->wildcount; n++)
//		lwsl_notice("    %d\n", ctx->wild[n]);

	if (reason == LEJPCB_OBJECT_START && ctx->path_match == LEJPVP + 1) {
		/* set the defaults for this vhost */
		a->valid = 1;
		a->head = NULL;
		a->last = NULL;
		a->info->port = 0;
		a->info->iface = NULL;
		a->info->protocols = a->protocols;
		a->info->extensions = a->extensions;
		a->info->ssl_cert_filepath = NULL;
		a->info->ssl_private_key_filepath = NULL;
		a->info->ssl_ca_filepath = NULL;
		a->info->timeout_secs = 5;
		a->info->ssl_cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:"
				       "ECDHE-RSA-AES256-GCM-SHA384:"
				       "DHE-RSA-AES256-GCM-SHA384:"
				       "ECDHE-RSA-AES256-SHA384:"
				       "HIGH:!aNULL:!eNULL:!EXPORT:"
				       "!DES:!MD5:!PSK:!RC4:!HMAC_SHA1:"
				       "!SHA1:!DHE-RSA-AES128-GCM-SHA256:"
				       "!DHE-RSA-AES128-SHA256:"
				       "!AES128-GCM-SHA256:"
				       "!AES128-SHA256:"
				       "!DHE-RSA-AES256-SHA256:"
				       "!AES256-GCM-SHA384:"
				       "!AES256-SHA256";
		a->info->pvo = NULL;
	}

	if (reason == LEJPCB_OBJECT_START &&
	    ctx->path_match == LEJPVP_MOUNTS + 1) {
		a->mountpoint = NULL;
		a->origin = NULL;
		a->def = NULL;
	}

	/* this catches, eg, vhosts[].ws-protocols[].xxx-protocol */
	if (reason == LEJPCB_OBJECT_START &&
	    ctx->path_match == LEJPVP_PROTOCOL_NAME + 1) {
		a->pvo = lwsws_align(a);
		a->p += sizeof(*a->pvo);

		n = lejp_get_wildcard(ctx, 0, a->p, a->end - a->p);
		/* ie, enable this protocol, no options yet */
		a->pvo->next = a->info->pvo;
		a->info->pvo = a->pvo;
		a->pvo->name = a->p;
		lwsl_err("adding %s\n", a->p);
		a->p += n;
		a->pvo->value = a->p;
		a->pvo->options = NULL;
		a->p += snprintf(a->p, a->end - a->p, "%s", ctx->buf);
		*(a->p)++ = '\0';
	}

	if (reason == LEJPCB_OBJECT_END &&
	    (ctx->path_match == LEJPVP + 1 || !ctx->path[0]) &&
	    a->valid) {

		//lwsl_notice("%s\n", ctx->path);
		if (!a->info->port) {
			lwsl_err("Port required (eg, 443)");
			return 1;
		}
		a->valid = 0;

		if (!lws_create_vhost(a->context, a->info, a->head)) {
			lwsl_err("Failed to create vhost %s\n",
				 a->info->vhost_name);
			return 1;
		}

		return 0;
	}

	if (reason == LEJPCB_OBJECT_END &&
	    ctx->path_match == LEJPVP_MOUNTS + 1) {
		if (!a->mountpoint || !a->origin) {
			lwsl_err("mountpoint and origin required\n");
			return 1;
		}

		n = lws_write_http_mount(a->last, &m, a->p, a->mountpoint,
					 a->origin, a->def);
		if (!n)
			return 1;
		a->p += n;
		if (!a->head)
			a->head = m;

		a->last = m;
	}

	/* we only match on the prepared path strings */
	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {
	case LEJPVP_NAME:
		a->info->vhost_name = a->p;
		break;
	case LEJPVP_PORT:
		a->info->port = atoi(ctx->buf);
		return 0;
	case LEJPVP_HOST_SSL_KEY:
		a->info->ssl_private_key_filepath = a->p;
		break;
	case LEJPVP_HOST_SSL_CERT:
		a->info->ssl_cert_filepath = a->p;
		break;
	case LEJPVP_HOST_SSL_CA:
		a->info->ssl_ca_filepath = a->p;
		break;
	case LEJPVP_MOUNTPOINT:
		a->mountpoint = a->p;
		break;
	case LEJPVP_ORIGIN:
		a->origin = a->p;
		break;
	case LEJPVP_DEFAULT:
		a->def = a->p;
		break;

	case LEJPVP_PROTOCOL_NAME_OPT:
		/* this catches, eg,
		 * vhosts[].ws-protocols[].xxx-protocol.yyy-option
		 * ie, these are options attached to a protocol with { }
		 */
		pvo = lwsws_align(a);
		a->p += sizeof(*a->pvo);

		n = lejp_get_wildcard(ctx, 1, a->p, a->end - a->p);
		/* ie, enable this protocol, no options yet */
		pvo->next = a->pvo->options;
		a->pvo->options = pvo;
		pvo->name = a->p;
		a->p += n;
		pvo->value = a->p;
		pvo->options = NULL;
		a->p += snprintf(a->p, a->end - a->p, "%s", ctx->buf);
		*(a->p)++ = '\0';
		break;

	default:
		return 0;
	}

	a->p += snprintf(a->p, a->end - a->p, "%s", ctx->buf);
	*(a->p)++ = '\0';

	return 0;
}

/*
 * returns 0 = OK, 1 = can't open, 2 = parsing error
 */

static int
lwsws_get_config(void *user, const char *f, const char * const *paths,
		 int count_paths, lejp_callback cb)
{
	unsigned char buf[128];
	struct lejp_ctx ctx;
	int n, m, fd;

	fd = open(f, O_RDONLY);
	if (fd < 0) {
		lwsl_err("Cannot open %s\n", f);
		return 1;
	}
	lwsl_info("%s: %s\n", __func__, f);
	lejp_construct(&ctx, cb, user, paths, count_paths);

	do {
		n = read(fd, buf, sizeof(buf));
		if (!n)
			break;

		m = (int)(char)lejp_parse(&ctx, buf, n);
	} while (m == LEJP_CONTINUE);

	close(fd);
	n = ctx.line;
	lejp_destruct(&ctx);

	if (m < 0) {
		lwsl_err("%s(%u): parsing error %d\n", f, n, m);
		return 2;
	}

	return 0;
}

#ifndef _WIN32
static int filter(const struct dirent *ent)
{
	if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
		return 0;

	return 1;
}
#endif

static int
lwsws_get_config_d(void *user, const char *d, const char * const *paths,
		   int count_paths, lejp_callback cb)
{
#ifndef _WIN32
	struct dirent **namelist;
	char path[256];
	int n, i, ret = 0;

	n = scandir(d, &namelist, filter, alphasort);
	if (n < 0) {
		lwsl_err("Scandir on %d failed\n", d);
	}

	for (i = 0; i < n; i++) {
		snprintf(path, sizeof(path) - 1, "%s/%s", d,
			 namelist[i]->d_name);
		ret = lwsws_get_config(user, path, paths, count_paths, cb);
		if (ret) {
			while (i++ < n)
				free(namelist[i]);
			goto bail;
		}
		free(namelist[i]);
	}

bail:
	free(namelist);

	return ret;
#else
	return 0;
#endif
}

int
lwsws_get_config_globals(struct lws_context_creation_info *info, const char *d,
			 char **cs, int *len)
{
	struct jpargs a;

	a.info = info;
	a.p = *cs;
	a.end = a.p + *len;
	a.valid = 0;

	if (lwsws_get_config(&a, "/etc/lwsws/conf", paths_global,
			     ARRAY_SIZE(paths_global), lejp_globals_cb) > 1)
		return 1;
	if (lwsws_get_config_d(&a, d, paths_global,
			       ARRAY_SIZE(paths_global), lejp_globals_cb) > 1)
		return 1;

	*cs = a.p;
	*len = a.end - a.p;

	return 0;
}

int
lwsws_get_config_vhosts(struct lws_context *context,
			struct lws_context_creation_info *info, const char *d,
			char **cs, int *len)
{
	struct jpargs a;

	a.info = info;
	a.p = *cs;
	a.end = a.p + *len;
	a.valid = 0;
	a.context = context;
	a.protocols = info->protocols;
	a.extensions = info->extensions;

	if (lwsws_get_config(&a, "/etc/lwsws/conf", paths_vhosts,
			     ARRAY_SIZE(paths_vhosts), lejp_vhosts_cb) > 1)
		return 1;
	if (lwsws_get_config_d(&a, d, paths_vhosts,
			       ARRAY_SIZE(paths_vhosts), lejp_vhosts_cb) > 1)
		return 1;

	*cs = a.p;
	*len = a.end - a.p;

	lws_finalize_startup(context);

	return 0;
}
