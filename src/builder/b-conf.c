/*
 * sai-builder conf.c
 *
 * Copyright (C) 2019 - 2020 Andy Green <andy@warmcat.com>
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

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>

#include "sai-git-hash.h"
#include "b-private.h"

/* global part */

static const char * const paths_global[] = {
	"home",
	"perms",
	"host",
	"metrics_uri",
	"metrics_path",
	"metrics_secret",
	"link-key",
	"sai-power",
	"power_controller",
	"power-on.type",
	"power-on.url",
	"power-on.mac",
	"power-off.type",
	"power-off.url",
	"power-monitor.url",
	"rebuild_script_user",
	"rebuild_script_root",
	"build-timeout-secs"
};

enum enum_paths_global {
	LEJPM_HOME,
	LEJPM_PERMS,
	LEJPM_HOST,
	LEJPM_METRICS_URI,
	LEJPM_METRICS_PATH,
	LEJPM_METRICS_SECRET,
	LEJPM_LINK_KEY,
	LEJPM_SAI_POWER,
	LEJPM_POWER_CONTROLLER,
	LEJPM_POWER_ON_TYPE,
	LEJPM_POWER_ON_URL,
	LEJPM_POWER_ON_MAC,
	LEJPM_POWER_OFF_TYPE,
	LEJPM_POWER_OFF_URL,
	LEJPM_POWER_MONITOR_URL,
	LEJPM_REBUILD_SCRIPT_USER,
	LEJPM_REBUILD_SCRIPT_ROOT,
	LEJPM_BUILD_TIMEOUT_SECS
};

/* platform-related part */

static const char * const paths[] = {

	"platforms[].name",
	"platforms[].env[].*",
	"platforms[].env[]",
	"platforms[].servers",
	"platforms[].job-limit",
	/*
	 * Listed so the "idle" object itself matches this, rather than the
	 * "platforms[]" it's in: that would start another platform
	 */
	"platforms[].idle",
	"platforms[].idle.share",
	"platforms[].idle.instances",
	"platforms[].idle.slice-secs",
	"platforms[].idle.settle-secs",
	"platforms[]",
};

enum enum_paths {

	LEJPM_PLATFORMS_NAME,
	LEJPM_PLATFORMS_ENV_ITEM,
	LEJPM_PLATFORMS_ENV,
	LEJPM_PLATFORMS_SERVERS,
	LEJPM_PLATFORMS_JOB_LIMIT,
	LEJPM_PLATFORMS_IDLE,
	LEJPM_PLATFORMS_IDLE_SHARE,
	LEJPM_PLATFORMS_IDLE_INSTANCES,
	LEJPM_PLATFORMS_IDLE_SLICE_SECS,
	LEJPM_PLATFORMS_IDLE_SETTLE_SECS,
	LEJPM_PLATFORMS,
};

static signed char
saib_conf_cb(struct lejp_ctx *ctx, char reason)
{
	struct jpargs *a = (struct jpargs *)ctx->user;
	sai_plat_server_ref_t *mref;
	struct lws_ss_handle *h;
	const char **pp;
	char temp[65];
	int n;

#if 0
	lwsl_notice(" %d: %s (%d)\n", reason, ctx->path, ctx->path_match);
	for (n = 0; n < ctx->wildcount; n++)
		lwsl_notice("    %d\n", ctx->wild[n]);
#endif

	if (reason == LEJPCB_OBJECT_START) {
		switch (ctx->path_match - 1) {

		case LEJPM_PLATFORMS:
			/*
			 * Create the sai_plat object
			 */
			a->sai_plat = lwsac_use_zero(&a->builder->conf_head,
					         sizeof(*a->sai_plat), 4096);
			if (!a->sai_plat)
				return -1;

			lws_strncpy(a->sai_plat->sai_hash, SAI_BUILD_INFO,
				    sizeof(a->sai_plat->sai_hash));
			lws_strncpy(a->sai_plat->lws_hash, LWS_BUILD_HASH,
				    sizeof(a->sai_plat->lws_hash));

			a->sai_plat->job_limit = 0;
			a->sai_plat->idle_instances = 1;
			a->sai_plat->idle_slice_secs = SAIB_IDLE_DEF_SLICE_SECS;
			a->sai_plat->idle_settle_secs = SAIB_IDLE_DEF_SETTLE_SECS;

			lws_dll2_add_tail(&a->sai_plat->sai_plat_list,
					  &a->builder->sai_plat_owner);
			break;

		default:
			return 0;
		}
	}

	if (lejp_string_unify_part(ctx, &a->builder->conf_head, reason))
		return 1;

	/* we only match on the prepared path strings */
	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	if (ctx->path_match - 1 == LEJPM_PLATFORMS_JOB_LIMIT) {
		a->sai_plat->job_limit = (unsigned int)atoi(ctx->buf);
		lwsl_err("%s: LEJPM_PLATFORMS_JOB_LIMIT %u\n", __func__, a->sai_plat->job_limit);
	}

	/*
	 * What the platform should do with its idle time, see README-idle.md
	 */

	switch (ctx->path_match - 1) {
	case LEJPM_PLATFORMS_IDLE_SHARE:
		n = atoi(ctx->buf);
		a->sai_plat->idle_share = n < 0 ? 0 : (n > 100 ? 100 : (unsigned int)n);
		break;
	case LEJPM_PLATFORMS_IDLE_INSTANCES:
		n = atoi(ctx->buf);
		a->sai_plat->idle_instances = n < 1 ? 1 : (unsigned int)n;
		break;
	case LEJPM_PLATFORMS_IDLE_SLICE_SECS:
		n = atoi(ctx->buf);
		a->sai_plat->idle_slice_secs = n < 60 ? 60 : (unsigned int)n;
		break;
	case LEJPM_PLATFORMS_IDLE_SETTLE_SECS:
		n = atoi(ctx->buf);
		a->sai_plat->idle_settle_secs = n < 0 ? 0 : (unsigned int)n;
		break;
	}

	if (reason != LEJPCB_VAL_STR_END)
		return 0;

	if (lejp_string_unify(ctx, &a->builder->conf_head))
		return 1;

	/* only the end part of the string, where we know the length */

	switch (ctx->path_match - 1) {

	case LEJPM_PLATFORMS_ENV:
		lwsl_notice("env %s %s\n", ctx->path, ctx->buf);
		return 0;
		// break;

	case LEJPM_PLATFORMS_NAME:
		n = lws_snprintf(temp, sizeof(temp), "%s.%.*s",
				 builder.host, ctx->npos, ctx->buf);
		a->sai_plat->name = lwsac_use(&a->builder->conf_head, (unsigned int)n + 1, 512);
		memcpy((char *)a->sai_plat->name, temp, (unsigned int)n + 1);
		lwsl_notice("%s: platform: %.*s, name %s\n", __func__,
			    ctx->npos, ctx->buf, a->sai_plat->name);
#if defined(WIN32)
		a->sai_plat->windows = 1;
#endif
		pp = &a->sai_plat->platform;
		a->sai_plat->index = a->next_plat_index++;
		break;

	case LEJPM_PLATFORMS_SERVERS:

		mref = lwsac_use_zero(&a->builder->conf_head, sizeof(*mref),
					512);

		/*
		 * The builder as a whole maintains only one SS connection to
		 * each server.  If there are multiple platforms supported by
		 * the builder that want to accept tasks from the same server,
		 * only the first platform creates the SS to the server, and
		 * the others just use that.
		 *
		 * The sai_plat_server is instantiated as the ss userdata.
		 *
		 * So let's see if we already have the connection created
		 * for this server...
		 */

		lws_start_foreach_dll(struct lws_dll2 *, p,
				      a->builder->sai_plat_server_owner.head) {
			struct sai_plat_server *cm = lws_container_of(p, sai_plat_server_t, list);

			if (!strncmp(ctx->buf, cm->url, ctx->npos)) {
				/* we already have a logical connection... */
				mref->spm = cm;
				cm->refcount++;
				lws_dll2_add_tail(&mref->list,
						  &a->sai_plat->servers);

				return 0;
			}
		} lws_end_foreach_dll(p);

		a->mref = mref;

		/*
		 * This is the first plat that wants to talk to this server,
		 * we need to create the logical SS connection.
		 *
		 * The created SS in turn creates a struct sai_plat_server as
		 * its user object, its CREATING callback in b-comms.c adds
		 * that to the builder .sai_plat_server_owner
		 */

		if (lws_ss_create(builder.context, 0, &ssi_sai_builder,
				  (void *)ctx, &h, NULL, NULL)) {
			lwsl_err("%s: failed to create secure stream\n",
				 __func__);
			return -1;
		}

		return 0;

	default:
		return 0;
	}

	*pp = ctx->su.fp;

	return 0;
}

static signed char
saib_conf_global_cb(struct lejp_ctx *ctx, char reason)
{
	struct jpargs *a = (struct jpargs *)ctx->user;
	const char **pp;
#if 0
	int n;

	lwsl_notice("%s: reason: %d, path: %s, match %d\n", __func__,
			reason, ctx->path, ctx->path_match);
	for (n = 0; n < ctx->wildcount; n++)
		lwsl_notice("    %d\n", ctx->wild[n]);
#endif

	if (lejp_string_unify_part(ctx, &a->builder->conf_head, reason))
		return 1;

	/* we only match on the prepared path strings */
	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	if (ctx->path_match - 1 == LEJPM_BUILD_TIMEOUT_SECS) {
		a->builder->build_timeout_secs = (unsigned int)atoi(ctx->buf);
		lwsl_notice("%s: LEJPM_BUILD_TIMEOUT_SECS %u\n", __func__, a->builder->build_timeout_secs);
	}

	if (reason != LEJPCB_VAL_STR_END)
		return 0;

	if (lejp_string_unify(ctx, &a->builder->conf_head))
		return 1;

	/* only the end part of the string, where we know the length */

	switch (ctx->path_match - 1) {
	case LEJPM_HOME:
		pp = &a->builder->home;
		break;

	case LEJPM_PERMS:
		pp = &a->builder->perms;
		break;

	case LEJPM_HOST:
		pp = &a->builder->host;
		break;

	case LEJPM_SAI_POWER:
		pp = &a->builder->url_sai_power;
		break;

	case LEJPM_POWER_CONTROLLER:
		pp = &a->builder->power_controller_name;
		break;

	case LEJPM_METRICS_URI:
		pp = &a->builder->metrics_uri;
		break;

	case LEJPM_METRICS_PATH:
		pp = &a->builder->metrics_path;
		break;

	case LEJPM_METRICS_SECRET:
		pp = &a->builder->metrics_secret;
		break;

	case LEJPM_LINK_KEY:
		pp = &a->builder->link_key;
		break;

	case LEJPM_POWER_ON_TYPE:
		pp = &a->builder->power_on_type;
		break;
	case LEJPM_POWER_ON_URL:
		pp = &a->builder->power_on_url;
		break;
	case LEJPM_POWER_ON_MAC:
		pp = &a->builder->power_on_mac;
		break;
	case LEJPM_POWER_OFF_TYPE:
		pp = &a->builder->power_off_type;
		break;
	case LEJPM_POWER_OFF_URL:
		pp = &a->builder->power_off_url;
		break;
	case LEJPM_POWER_MONITOR_URL:
		pp = &a->builder->power_monitor_url;
		break;

	case LEJPM_REBUILD_SCRIPT_USER:
		pp = &a->builder->rebuild_script_user;
		break;

	case LEJPM_REBUILD_SCRIPT_ROOT:
		pp = &a->builder->rebuild_script_root;
		break;

	default:
		return 0;
	}

	*pp = ctx->su.fp;

	return 0;
}

int
saib_config_global(struct sai_builder *builder, const char *d)
{
	unsigned char buf[128];
	struct lejp_ctx ctx;
	int n, m, fd;
	struct jpargs a;

	memset(&a, 0, sizeof(a));
	a.builder = builder;

#if defined(WIN32)
	lws_snprintf((char *)buf, sizeof(buf) - 1, "%s\\conf", d);
#else
	lws_snprintf((char *)buf, sizeof(buf) - 1, "%s/conf", d);
#endif

	fd = lws_open((char *)buf, O_RDONLY);
	if (fd < 0) {
		lwsl_err("Cannot open %s\n", (char *)buf);
		return 2;
	}
	lwsl_info("%s: %s\n", __func__, (char *)buf);
	lejp_construct(&ctx, saib_conf_global_cb, &a,
			paths_global, LWS_ARRAY_SIZE(paths_global));
	sai_lejp_enable_comments(&ctx);

	do {
		n = (int)read(fd, buf, sizeof(buf));
		if (!n)
			break;

		m = lejp_parse(&ctx, buf, n);
	} while (m == LEJP_CONTINUE);

	close(fd);
	n = (int)ctx.line;
	lejp_destruct(&ctx);

	return 0;
}

int
saib_config(struct sai_builder *builder, const char *d)
{
	unsigned char buf[128];
	struct lejp_ctx ctx;
	int n, m, fd;
	struct jpargs a;

	memset(&a, 0, sizeof(a));
	a.builder = builder;

#if defined(WIN32)
	lws_snprintf((char *)buf, sizeof(buf) - 1, "%s\\conf", d);
#else
	lws_snprintf((char *)buf, sizeof(buf) - 1, "%s/conf", d);
#endif

	fd = lws_open((char *)buf, O_RDONLY);
	if (fd < 0) {
		lwsl_err("Cannot open %s\n", (char *)buf);
		return 2;
	}
	lwsl_notice("%s: %s\n", __func__, (char *)buf);
	lejp_construct(&ctx, saib_conf_cb, &a, paths, LWS_ARRAY_SIZE(paths));
	sai_lejp_enable_comments(&ctx);

	do {
		n = (int)read(fd, buf, sizeof(buf));
		if (!n)
			break;

		m = lejp_parse(&ctx, buf, n);
	} while (m == LEJP_CONTINUE);

	close(fd);
	n = (int)ctx.line;
	lejp_destruct(&ctx);

	if (m < 0) {
		lwsl_err("%s/conf(%u): parsing error %d: %s\n", d, n, m,
			 lejp_error_to_string(m));
		return 2;
	}

	lwsl_notice("%s: parsing completed\n", __func__);

	return 0;
}

void
saib_config_destroy(struct sai_builder *builder)
{
	lwsac_free(&builder->conf_head);

#if defined(__APPLE__)
	sul_release_wakelock_cb(NULL);
#endif
}
