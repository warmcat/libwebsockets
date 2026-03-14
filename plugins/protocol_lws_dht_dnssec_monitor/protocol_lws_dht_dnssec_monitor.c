/*
 * libwebsockets - protocol - dht_dnssec_monitor
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 *  This plugin monitors a config directory and a zone directory to automate
 *  DNSSEC signing tasks over operations exported by lws-dht-dnssec.
 */

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

struct vhd {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_dht_dnssec_ops *ops;

	const char *zone_dir;
	const char *conf_dir;
	uint32_t signature_duration;

	lws_sorted_usec_list_t sul_scan;
};

struct parsed_config {
	struct vhd *vhd;
	char common_name[256];
	char email[256];
};

static const char * const config_paths[] = {
	"common-name",
	"email",
};

enum enum_config_paths {
	LEJP_CONF_COMMON_NAME,
	LEJP_CONF_EMAIL,
};

static signed char
cb_conf(struct lejp_ctx *ctx, char reason)
{
	struct parsed_config *pc = (struct parsed_config *)ctx->user;

	if (reason == LEJPCB_VAL_STR_END) {
		switch (ctx->path_match - 1) {
		case LEJP_CONF_COMMON_NAME:
			lws_strncpy(pc->common_name, ctx->buf, sizeof(pc->common_name));
			break;
		case LEJP_CONF_EMAIL:
			lws_strncpy(pc->email, ctx->buf, sizeof(pc->email));
			break;
		}
	}

	return 0;
}

static int
scan_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct vhd *vhd = (struct vhd *)user;
	char filepath[1024];
	int fd;
	struct stat st;
	char *buf;
	struct parsed_config pc;
	struct lejp_ctx jctx;

	if (lde->type != LDOT_UNKNOWN && lde->type != LDOT_FILE)
		return 0;

	size_t len = strlen(lde->name);
	if (len < 5 || strcmp(&lde->name[len - 5], ".json"))
		return 0;

	lws_snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, lde->name);

	fd = open(filepath, O_RDONLY);
	if (fd < 0)
		return 0;

	if (fstat(fd, &st) < 0 || st.st_size == 0) {
		close(fd);
		return 0;
	}

	buf = malloc((size_t)st.st_size + 1);
	if (!buf) {
		close(fd);
		return 0;
	}

	if (read(fd, buf, (size_t)st.st_size) != st.st_size) {
		free(buf);
		close(fd);
		return 0;
	}
	buf[st.st_size] = '\0';
	close(fd);

	memset(&pc, 0, sizeof(pc));
	pc.vhd = vhd;
	lejp_construct(&jctx, cb_conf, &pc, config_paths, LWS_ARRAY_SIZE(config_paths));
	int m = lejp_parse(&jctx, (uint8_t *)buf, (int)st.st_size);
	lejp_destruct(&jctx);
	free(buf);

	if (m < 0 && m != LEJP_REJECT_UNKNOWN) {
		lwsl_err("%s: JSON decode failed for %s: %d\n", __func__, filepath, m);
		return 0;
	}

	if (pc.common_name[0]) {
		lwsl_notice("%s: Parsed domain %s from %s\n", __func__, pc.common_name, filepath);

		/* Directory format requires <zone_dir>/<common_name>/ */
		char key_path[1024];

		/* Check ZSK */
		lws_snprintf(key_path, sizeof(key_path), "%s/%s/%s.zsk.private.jwk", vhd->zone_dir, pc.common_name, pc.common_name);
		int has_zsk = (access(key_path, F_OK) == 0);

		/* Check KSK */
		lws_snprintf(key_path, sizeof(key_path), "%s/%s/%s.ksk.private.jwk", vhd->zone_dir, pc.common_name, pc.common_name);
		int has_ksk = (access(key_path, F_OK) == 0);

		if (!has_zsk || !has_ksk) {
			lwsl_notice("%s: Missing keys for %s, automatically generating...\n", __func__, pc.common_name);
			struct lws_dht_dnssec_keygen_args kargs;
			memset(&kargs, 0, sizeof(kargs));
			kargs.domain = pc.common_name;

			/* Assume ES256 fallback if unspecified (or whatever dnssec module defaults to) */
			kargs.curve = "P-256";

			if (vhd->ops->keygen(vhd->context, &kargs))
				lwsl_err("%s: Failed to generate keys for %s\n", __func__, pc.common_name);
		}

		/* Check resign triggers */
		char input_path[1024];
		char output_path[1024];
		char jws_path[1024];
		char zsk_path[1024];
		char ksk_path[1024];

		lws_snprintf(input_path, sizeof(input_path), "%s/%s/%s.zone", vhd->zone_dir, pc.common_name, pc.common_name);
		lws_snprintf(output_path, sizeof(output_path), "%s/%s/%s.signed", vhd->zone_dir, pc.common_name, pc.common_name);
		lws_snprintf(jws_path, sizeof(jws_path), "%s/%s/%s.jws", vhd->zone_dir, pc.common_name, pc.common_name);
		lws_snprintf(zsk_path, sizeof(zsk_path), "%s/%s/%s.zsk.private.jwk", vhd->zone_dir, pc.common_name, pc.common_name);
		lws_snprintf(ksk_path, sizeof(ksk_path), "%s/%s/%s.ksk.private.jwk", vhd->zone_dir, pc.common_name, pc.common_name);

		int needs_resign = 0;
		struct stat st_in, st_out;

		if (stat(input_path, &st_in) == 0) {
			if (stat(output_path, &st_out) != 0) {
				/* output doesn't exist */
				needs_resign = 1;
			} else {
				if (st_in.st_mtime > st_out.st_mtime) {
					/* unsigned zone is newer than signed zone */
					needs_resign = 1;
				}
				/* TODO: 75% lifetime exhaustion check, but requires parsing the signature. */
			}
		} else {
			lwsl_info("%s: Missing domain %s base zone config, skipping resign\n", __func__, input_path);
		}

		if (needs_resign) {
			lwsl_notice("%s: Signing zone for %s\n", __func__, pc.common_name);
			struct lws_dht_dnssec_signzone_args sargs;
			memset(&sargs, 0, sizeof(sargs));
			sargs.domain = pc.common_name;
			sargs.sign_validity_duration = vhd->signature_duration;

			if (vhd->ops->signzone(vhd->context, &sargs)) {
				lwsl_err("%s: Failed signing zone for %s\n", __func__, pc.common_name);
			} else {
				lwsl_notice("%s: Successfully signed zone for %s, publishing...\n", __func__, pc.common_name);
				if (vhd->ops->publish_jws) {
					vhd->ops->publish_jws(vhd->context, jws_path);
				}
			}
		}
	}

	return 0;
}

static void
sul_scan_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_scan);

	lwsl_notice("%s: Scanning config directory: %s\n", __func__, vhd->conf_dir);

	lws_dir(vhd->conf_dir, vhd, scan_dir_cb);

	lws_sul_schedule(vhd->context, 0, &vhd->sul_scan, sul_scan_cb, 5 * 60 * LWS_US_PER_SEC);
}

static int
callback_dht_dnssec_monitor(struct lws *wsi, enum lws_callback_reasons reason,
			    void *user, void *in, size_t len)
{
	struct vhd *vhd = (struct vhd *)user;
	struct lws_vhost *vhost = lws_get_vhost(wsi);
	const struct lws_protocols *protocol = lws_get_protocol(wsi);
	const struct lws_protocol_vhost_options *pvo;

	switch (reason) {

	case LWS_CALLBACK_PROTOCOL_INIT:
		{
			if (!in)
				return 0;

			/* Fast path: Prevent duplicate instantiation */
			if (lws_protocol_vh_priv_get(vhost, protocol))
				return 0;

			vhd = lws_protocol_vh_priv_zalloc(vhost, protocol, sizeof(*vhd));
			if (!vhd)
				return -1;

			vhd->context = lws_get_context(wsi);
			vhd->vhost = vhost;
			vhd->signature_duration = 31536000; /* 1 year default fallback */

			/* Load standard PVOs */
			if ((pvo = lws_pvo_search(in, "zone-dir")))
				vhd->zone_dir = pvo->value;
			if ((pvo = lws_pvo_search(in, "conf-dir")))
				vhd->conf_dir = pvo->value;
			if ((pvo = lws_pvo_search(in, "signature-duration")))
				vhd->signature_duration = (uint32_t)atoi(pvo->value);

			if (!vhd->zone_dir || !vhd->conf_dir) {
				lwsl_err("%s: zone-dir and conf-dir pvos are required\n", __func__);
				return -1;
			}

			/* Locate the operational ops struct off the prerequisite plugin */
			const struct lws_protocols *prot = lws_vhost_name_to_protocol(vhd->vhost, "lws-dht-dnssec");
			if (!prot || !prot->user) {
				lwsl_err("%s: prerequisite protocol lws-dht-dnssec is missing or has no ops exported\n", __func__);
				return -1;
			}
			vhd->ops = (const struct lws_dht_dnssec_ops *)prot->user;

			lwsl_notice("%s: initialized monitor (conf-dir: %s, zone-dir: %s)\n", __func__, vhd->conf_dir, vhd->zone_dir);

			/* Launch periodic directory loop */
			lws_sul_schedule(vhd->context, 0, &vhd->sul_scan, sul_scan_cb, 5 * LWS_US_PER_SEC);
		}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd)
			break;
		lws_sul_cancel(&vhd->sul_scan);
		break;

	default:
		break;
	}

	return 0;
}

LWS_VISIBLE const struct lws_protocols lws_dht_dnssec_monitor_protocols[] = {
	{ "lws-dht-dnssec-monitor", callback_dht_dnssec_monitor, 0, 0, 0, NULL, 0 },
};

LWS_VISIBLE const lws_plugin_protocol_t lws_dht_dnssec_monitor = {
	.hdr = {
		"dht dnssec monitor",
		"lws_protocol_plugin",
		LWS_BUILD_HASH,
		LWS_PLUGIN_API_MAGIC,
		10 /* priority */
	},
	.protocols = lws_dht_dnssec_monitor_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_dht_dnssec_monitor_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
