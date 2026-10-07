/*
 * sai-virt - v-conf.c
 *
 * Copyright (C) 2019 - 2026 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 */

#include <libwebsockets.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "v-private.h"

static const char * const paths_plat[] = {
	"name",
	"platform",
	"base_image",
	"overlay_size",
};

enum {
	VJ_NAME,
	VJ_PLATFORM,
	VJ_BASE_IMAGE,
	VJ_OVERLAY_SIZE,
};

struct v_conf_ctx {
	saiv_plat_t *plat;
};

static signed char
saiv_conf_plat_cb(struct lejp_ctx *ctx, char reason)
{
	struct v_conf_ctx *v = (struct v_conf_ctx *)ctx->user;

	if (reason == LEJPCB_OBJECT_START && ctx->path_match == 0) {
		v->plat = malloc(sizeof(*v->plat));
		if (!v->plat)
			return -1;
		memset(v->plat, 0, sizeof(*v->plat));
		return 0;
	}

	if (reason == LEJPCB_OBJECT_END && ctx->path_match == 0) {
		if (v->plat && v->plat->name[0] && v->plat->base_image[0]) {
			lws_dll2_add_tail(&v->plat->list, &virt.plat_owner);
			lwsl_notice("Added platform %s (base %s)\n", v->plat->name, v->plat->base_image);
			v->plat = NULL;
		} else if (v->plat) {
			lwsl_err("Platform definition missing name or base_image\n");
			free(v->plat);
			v->plat = NULL;
		}
		return 0;
	}

	if (reason == LEJPCB_VAL_STR_END) {
		switch (ctx->path_match - 1) {
		case VJ_NAME:
			lws_strncpy(v->plat->name, ctx->buf, sizeof(v->plat->name));
			break;
		case VJ_PLATFORM:
			lws_strncpy(v->plat->platform, ctx->buf, sizeof(v->plat->platform));
			break;
		case VJ_BASE_IMAGE:
			lws_strncpy(v->plat->base_image, ctx->buf, sizeof(v->plat->base_image));
			break;
		case VJ_OVERLAY_SIZE:
			lws_strncpy(v->plat->overlay_size, ctx->buf, sizeof(v->plat->overlay_size));
			break;
		}
	}

	return 0;
}

static int
saiv_conf_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	char filepath[256];
	struct lejp_ctx ctx;
	struct v_conf_ctx vctx;
	int fd, m = 0;
	ssize_t n;
	uint8_t buf[1024];

	if (lde->name[0] == '.')
		return 0;

	lws_snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, lde->name);

	fd = open(filepath, O_RDONLY);
	if (fd < 0) {
		lwsl_err("Cannot open %s\n", filepath);
		return 0;
	}

	memset(&vctx, 0, sizeof(vctx));
	lejp_construct(&ctx, saiv_conf_plat_cb, &vctx, paths_plat, LWS_ARRAY_SIZE(paths_plat));
	sai_lejp_enable_comments(&ctx);

	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		m = lejp_parse(&ctx, buf, (int)n);
		if (m < 0 && m != LEJP_CONTINUE) {
			lwsl_err("%s: JSON decode error %d\n", filepath, m);
			break;
		}
	}
	close(fd);
	lejp_destruct(&ctx);

	if (vctx.plat)
		free(vctx.plat);

	return 0;
}

int
saiv_config(struct sai_virt *virt, const char *d)
{
	lwsl_notice("Parsing configuration directory %s\n", d);
	return lws_dir(d, virt, saiv_conf_dir_cb);
}

static const char * const paths_global[] = {
	"link-key",
	"servers[].url",
	"max_vms",
	"bind",
	"port",
};

enum {
	VJG_LINK_KEY,
	VJG_SERVER_URL,
	VJG_MAX_VMS,
	VJG_BIND,
	VJG_PORT,
};

static signed char
saiv_conf_global_cb(struct lejp_ctx *ctx, char reason)
{
	struct sai_virt *v = (struct sai_virt *)ctx->user;

	/* numbers may be given as JSON numbers or strings */
	if (reason == LEJPCB_VAL_STR_END || reason == LEJPCB_VAL_NUM_INT) {
		switch (ctx->path_match - 1) {
		case VJG_LINK_KEY:
			v->link_key = strdup(ctx->buf);
			break;

		case VJG_SERVER_URL:
		{
			/* the streams are created by saiv_servers_start() */
			saiv_server_t *srv = malloc(sizeof(*srv));
			if (srv) {
				memset(srv, 0, sizeof(*srv));
				srv->url = strdup(ctx->buf);
				if (srv->url)
					lws_dll2_add_tail(&srv->list,
							  &v->sai_server_owner);
				else
					free(srv);
			}
			break;
		}
		case VJG_MAX_VMS:
			v->max_vms = atoi(ctx->buf);
			lwsl_notice("Set max_vms to %d\n", v->max_vms);
			break;

		case VJG_BIND:
			v->bind = strdup(ctx->buf);
			break;

		case VJG_PORT:
			v->port = atoi(ctx->buf);
			break;
		}
	}
	return 0;
}

/*
 * Connect to the servers from the global conf, once our listener for the
 * builders exists
 */

void
saiv_servers_start(struct sai_virt *virt)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   virt->sai_server_owner.head) {
		saiv_server_t *srv = lws_container_of(d, saiv_server_t, list);

		if (lws_ss_create(virt->context, 0, &ssi_saiv_server_link_t,
				  srv, &srv->ss, NULL, NULL)) {
			lwsl_err("%s: failed to create ss for %s\n", __func__,
				 srv->url);
			lws_dll2_remove(&srv->list);
			free((void *)srv->url);
			free(srv);
		} else
			lwsl_notice("Added server %s\n", srv->url);
	} lws_end_foreach_dll_safe(d, d1);
}

int
saiv_config_global(struct sai_virt *virt, const char *filepath)
{
	struct lejp_ctx ctx;
	int fd, m = 0;
	ssize_t n;
	uint8_t buf[1024];

	lwsl_notice("Parsing global configuration %s\n", filepath);

	fd = open(filepath, O_RDONLY);
	if (fd < 0) {
		lwsl_err("Cannot open %s\n", filepath);
		return 1;
	}

	lejp_construct(&ctx, saiv_conf_global_cb, virt, paths_global, LWS_ARRAY_SIZE(paths_global));
	sai_lejp_enable_comments(&ctx);

	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		m = lejp_parse(&ctx, buf, (int)n);
		if (m < 0 && m != LEJP_CONTINUE) {
			lwsl_err("%s: JSON decode error %d\n", filepath, m);
			break;
		}
	}
	close(fd);
	lejp_destruct(&ctx);

	return 0;
}
