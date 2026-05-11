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

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../../lib/tls/private-lib-tls.h"

#if defined(WIN32) || defined(_WIN32)
#else
#include <sys/wait.h>
#endif

#define PSS_MAGIC 0x50535301

struct pss {
	uint32_t magic;
	struct lws *wsi;
	struct lws *cwsi;

	lws_sorted_usec_list_t sul;
	int retry_count;

	/* TX (proxy -> root) buffer */
	uint8_t tx[LWS_PRE + 65536];
	size_t tx_len;

	/* RX (root -> proxy) buffer */
	uint8_t rx[LWS_PRE + 65536];
	size_t rx_len;

	lws_dll2_t list;
	int send_ext_ips;
};

struct pub_state {
	struct lws_dll2 list;
	char domain[64];
	time_t mtime;
};

struct vhd {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_dht_dnssec_ops *ops;

	char *base_dir;
	const char *uds_path;
	uint32_t signature_duration;

	lws_sorted_usec_list_t sul_timer;
	struct lws_dir_notify *dn;

	struct lws_spawn_piped *lsp;
	int root_process_active;

	char cookie_name[64];
	char jwk_path[256];
	struct lws_jwk jwk;

	/* UDS raw rx buffer for server */
	uint8_t rx[LWS_PRE + 65536];
	size_t rx_len;

	char auth_token[129];
	struct lws_jwk auth_jwk;

	lws_dll2_owner_t ui_clients;
	struct lws_smd_peer *smd_peer;
	char ext_ips[256];

	/* ACME client configuration state */
	int acme_production;
	char acme_email[128];
	char acme_profile[128];

	uid_t proxy_uid;
	gid_t proxy_gid;

	/* UDS Proxy clients queue */
	lws_dll2_owner_t clients;

	lws_dll2_owner_t pub_states;
	int initial_parent_scan_done;
};

#define ACME_PROFILES_MAGIC 0xAC3E0001
struct acme_profiles_fetch_info {
	uint32_t magic;
	struct pss *root_pss;
	char *json;
	size_t json_len;
	size_t json_alloc;
};

#define CERT_CHECK_MAGIC 0xCE670001
struct cert_check_info {
	uint32_t magic;
	char fqdn[128];
	char domain[128];
	int port;
	int starttls_state; /* 0=none, 1=wait 220, 2=sent EHLO, 3=wait 250, 4=sent STARTTLS, 5=wait 220 */
};

struct cert_check_result {
	lws_dll2_t list;
	char fqdn[128];
	int port;
	int status_err;
	char msg[256];
	char local_msg[128];
	char issuer[128];
};


static struct vhd *global_root_vhd = NULL;

extern const struct lws_protocols lws_dht_dnssec_monitor_protocols[];

static int
smd_cb_network(void *opaque, lws_smd_class_t c, lws_usec_t ts, void *buf, size_t len)
{
	struct vhd *vhd = (struct vhd *)opaque;
	if ((c & LWSSMDCL_NETWORK) && buf && strstr((const char *)buf, "\"ext-ips\"")) {
		lws_strncpy(vhd->ext_ips, (const char *)buf, sizeof(vhd->ext_ips));
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->ui_clients.head) {
			struct pss *pss = lws_container_of(d, struct pss, list);
			pss->send_ext_ips = 1;
			lws_callback_on_writable(pss->wsi);
		} lws_end_foreach_dll_safe(d, d1);
	}
	return 0;
}

static void
lws_dht_dnssec_monitor_reap_cb(void *opaque, const struct lws_spawn_resource_us *res,
			       siginfo_t *si, int we_killed_him)
{
	struct vhd *vhd = (struct vhd *)opaque;
	lwsl_notice("%s: Spawned root monitor process terminated (killed: %d)\n", __func__, we_killed_him);
	vhd->root_process_active = 0;
	vhd->lsp = NULL;
}

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
scan_dir_cb_fast(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct vhd *vhd = (struct vhd *)user;
	char filepath[1024];
	int fd;
	struct stat st;
	char *buf;
	struct parsed_config pc;
	struct lejp_ctx jctx;

	if (lde->type != LDOT_DIR)
		return 0;

	if (lde->name[0] == '.')
		return 0;

	lws_snprintf(filepath, sizeof(filepath), "%s/%s/conf.d/%s.json", dirpath, lde->name, lde->name);

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
		if (strchr(pc.common_name, '/') || strstr(pc.common_name, "..")) {
			lwsl_err("%s: Invalid common-name containing path traversal characters: %s\n", __func__, pc.common_name);
			return 0;
		}

		lwsl_info("%s: Parsed domain %s from %s\n", __func__, pc.common_name, filepath);

		/* Directory format requires <base_dir>/domains/<common_name>/ */
		char key_path[1024];

		/* Check ZSK */
		lws_snprintf(key_path, sizeof(key_path), "%s/domains/%s/%s.zsk.private.jwk", vhd->base_dir, pc.common_name, pc.common_name);
		int has_zsk = (access(key_path, F_OK) == 0);

		/* Check KSK */
		lws_snprintf(key_path, sizeof(key_path), "%s/domains/%s/%s.ksk.private.jwk", vhd->base_dir, pc.common_name, pc.common_name);
		int has_ksk = (access(key_path, F_OK) == 0);

		if (!has_zsk || !has_ksk) {
			lwsl_notice("%s: Missing keys for %s, automatically generating...\n", __func__, pc.common_name);
			char wd[512];
			lws_snprintf(wd, sizeof(wd), "%s/domains/%s", vhd->base_dir, pc.common_name);

			struct lws_dht_dnssec_keygen_args kargs;
			memset(&kargs, 0, sizeof(kargs));
			kargs.domain = pc.common_name;
			kargs.workdir = wd;

			/* Assume ES256 fallback if unspecified (or whatever dnssec module defaults to) */
			kargs.curve = "P-256";

			if (vhd->ops->keygen(vhd->context, &kargs))
				lwsl_err("%s: Failed to generate keys for %s\n", __func__, pc.common_name);
		}

		/* Check resign triggers */
		char input_path[1024];
		char output_path[1024];

		lws_snprintf(input_path, sizeof(input_path), "%s/domains/%s/%s.zone", vhd->base_dir, pc.common_name, pc.common_name);
		lws_snprintf(output_path, sizeof(output_path), "%s/domains/%s/%s.zone.signed", vhd->base_dir, pc.common_name, pc.common_name);

		char acme_path[1024];
		lws_snprintf(acme_path, sizeof(acme_path), "%s.acme", input_path);
		struct stat st_acme;
		int has_acme = (stat(acme_path, &st_acme) == 0);

		int needs_resign = 0;
		struct stat st_in, st_out;

		if (stat(input_path, &st_in) == 0) {
			if (stat(output_path, &st_out) != 0) {
				/* output doesn't exist */
				lwsl_user("dnssec_monitor: %s does not exist! Triggering resign!\n", output_path);
				needs_resign = 1;
			} else {
				if (st_in.st_mtime > st_out.st_mtime) {
					/* unsigned zone is newer than signed zone */
					lwsl_user("dnssec-monitor: unsigned zone %s (mtime %lu) is newer than signed zone %s (mtime %lu)! Triggering resign!\n", input_path, (unsigned long)st_in.st_mtime, output_path, (unsigned long)st_out.st_mtime);
					needs_resign = 1;
				} else if (has_acme && st_acme.st_mtime > st_out.st_mtime) {
					lwsl_user("dnssec-monitor: .acme challenge file %s (mtime %lu) is newer than signed zone %s (mtime %lu)! Triggering resign!\n", acme_path, (unsigned long)st_acme.st_mtime, output_path, (unsigned long)st_out.st_mtime);
					needs_resign = 1;
				} else {
					lwsl_info("dnssec-monitor: unsigned zone %s (mtime %lu) is NOT newer than signed zone %s (mtime %lu), skipping resign.\n", input_path, (unsigned long)st_in.st_mtime, output_path, (unsigned long)st_out.st_mtime);
				}
			}
		} else {
			lwsl_info("%s: Missing domain %s base zone config, skipping resign\n", __func__, input_path);
		}

		if (needs_resign) {
			char wd[512];
			lws_snprintf(wd, sizeof(wd), "%s/domains/%s", vhd->base_dir, pc.common_name);

			lwsl_user("%s: Signing zone for %s\n", __func__, pc.common_name);
			struct lws_dht_dnssec_signzone_args sargs;
			memset(&sargs, 0, sizeof(sargs));
			sargs.domain = pc.common_name;
			sargs.workdir = wd;
			sargs.certs_dir = vhd->acme_production ? "production" : "staging";
			sargs.sign_validity_duration = vhd->signature_duration;

			if (vhd->ops->signzone(vhd->context, &sargs)) {
				lwsl_user("%s: Failed signing zone for %s\n", __func__, pc.common_name);
			} else {
				lwsl_user("%s: Successfully signed zone for %s\n", __func__, pc.common_name);
			}
		}
	}

	return 0;
}

static int
scan_dir_cb_expiry(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct vhd *vhd = (struct vhd *)user;
	char filepath[1024];
	int fd;
	struct stat st;
	char *buf;
	struct parsed_config pc;
	struct lejp_ctx jctx;

	if (lde->type != LDOT_DIR)
		return 0;

	if (lde->name[0] == '.')
		return 0;

	lws_snprintf(filepath, sizeof(filepath), "%s/%s/conf.d/%s.json", dirpath, lde->name, lde->name);

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

	if (m < 0 && m != LEJP_REJECT_UNKNOWN)
		return 0;

	if (pc.common_name[0]) {
		if (strchr(pc.common_name, '/') || strstr(pc.common_name, ".."))
			return 0;

		char output_path[1024];
		lws_snprintf(output_path, sizeof(output_path), "%s/domains/%s/%s.zone.signed", vhd->base_dir, pc.common_name, pc.common_name);

		struct stat st_out;
		if (stat(output_path, &st_out) == 0) {
			time_t now = time(NULL);
			if (now > st_out.st_mtime && (uint32_t)(now - st_out.st_mtime) >= (vhd->signature_duration * 3 / 4)) {
				lwsl_user("dnssec-monitor: signed zone %s is older than 75%% of signature lifetime, triggering resign by unlinking!\n", output_path);
				unlink(output_path);
			}
		}
	}

	return 0;
}

#if defined(LWS_WITH_DIR)
static void
dir_notify_cb(const char *path, int is_file, void *user)
{
	struct vhd *vhd = (struct vhd *)user;
	char scan_path[1024];

	lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);

	lwsl_user("%s: Detected inotify filesystem change %s (file: %d), manually rescanning domains: %s\n", __func__, path, is_file, scan_path);

	lws_dir(scan_path, vhd, scan_dir_cb_fast);
}
#endif

static int
parent_scan_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct vhd *vhd = (struct vhd *)user;
	if (lde->type != LDOT_DIR || lde->name[0] == '.') return 0;

	char jws_path[1024];
	lws_snprintf(jws_path, sizeof(jws_path), "%s/domains/%s/%s.zone.signed.jws", vhd->base_dir, lde->name, lde->name);

	struct stat st_jws;
	if (stat(jws_path, &st_jws) == 0) {
		int needs_pub = 1;
		struct pub_state *ps = NULL;

		lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->pub_states)) {
			struct pub_state *p = lws_container_of(d, struct pub_state, list);
			if (!strcmp(p->domain, lde->name)) {
				ps = p;
				if (st_jws.st_mtime <= ps->mtime)
					needs_pub = 0;
				break;
			}
		} lws_end_foreach_dll(d);

		if (needs_pub) {
			if (vhd->initial_parent_scan_done) {
				lwsl_notice("%s: Parent detected new JWS for %s! Triggering DHT publication loop.\n", __func__, lde->name);
				if (vhd->ops && vhd->ops->publish_jws) {
					vhd->ops->publish_jws(vhd->vhost, jws_path);
				}
			} else {
				lwsl_notice("%s: Initial startup scan observed existing JWS for %s, marking as already published.\n", __func__, lde->name);
			}

			if (!ps) {
				ps = calloc(1, sizeof(*ps));
				if (ps) {
					lws_strncpy(ps->domain, lde->name, sizeof(ps->domain));
					lws_dll2_add_tail(&ps->list, &vhd->pub_states);
				}
			}
			if (ps)
				ps->mtime = st_jws.st_mtime;
		}
	}
	return 0;
}

static void
parent_dnssec_monitor_timer_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_timer);
	char scan_path[1024];

	// lwsl_notice("%s: Parent timer fired!\n", __func__);

	lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);
	lws_dir(scan_path, vhd, parent_scan_dir_cb);
	vhd->initial_parent_scan_done = 1;
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, parent_dnssec_monitor_timer_cb, 5 * LWS_US_PER_SEC);
}

static void
dnssec_monitor_expiry_timer_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_timer);
	char scan_path[1024];

	// lwsl_notice("%s: Expiry timer fired!\n", __func__);

	lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);
	lws_dir(scan_path, vhd, scan_dir_cb_expiry);

	lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, dnssec_monitor_expiry_timer_cb, 4 * 3600 * LWS_US_PER_SEC);
}


#include <sys/stat.h>
#include <dirent.h>

struct monitor_req_args {
	char req[32];
	char domain[128];
	char subdomain[128];
	char email[128];
	char organization[128];
	char directory_url[256];
	char *zone_buf;
	int zone_len;
	int zone_alloc;
	char jwt[2048];
	char suffix[64];
	int port;
	int enabled;
	int production;
	char country[128];
	char state[128];
	char locality[128];
	char profile[128];
	char key_type[32];
	int sign_validity_days;
};

static const char * const monitor_req_paths[] = {
	"req",
	"domain",
	"subdomain",
	"email",
	"organization",
	"directory_url",
	"zone",
	"jwt",
	"suffix",
	"port",
	"enabled",
	"production",
	"country",
	"state",
	"locality",
	"profile",
	"key_type",
	"sign_validity_days"
};

enum enum_req_paths {
	LRP_REQ,
	LRP_DOMAIN,
	LRP_SUBDOMAIN,
	LRP_EMAIL,
	LRP_ORG,
	LRP_DIR_URL,
	LRP_ZONE,
	LRP_JWT,
	LRP_SUFFIX,
	LRP_PORT,
	LRP_ENABLED,
	LRP_PRODUCTION,
	LRP_COUNTRY,
	LRP_STATE,
	LRP_LOCALITY,
	LRP_PROFILE,
	LRP_KEY_TYPE,
	LRP_SIGN_VALIDITY_DAYS
};

static signed char
monitor_req_cb(struct lejp_ctx *ctx, char reason)
{
	struct monitor_req_args *a = (struct monitor_req_args *)ctx->user;

	if (reason == LEJPCB_VAL_NUM_INT) {
		if (ctx->path_match - 1 == LRP_PORT) {
			a->port = atoi(ctx->buf);
		}
		if (ctx->path_match - 1 == LRP_SIGN_VALIDITY_DAYS) {
			a->sign_validity_days = atoi(ctx->buf);
		}
	}

	if (reason == LEJPCB_VAL_TRUE) {
		if (ctx->path_match - 1 == LRP_ENABLED) a->enabled = 1;
		if (ctx->path_match - 1 == LRP_PRODUCTION) a->production = 1;
	}

	if (reason == LEJPCB_VAL_FALSE) {
		if (ctx->path_match - 1 == LRP_ENABLED) a->enabled = 0;
		if (ctx->path_match - 1 == LRP_PRODUCTION) a->production = 0;
	}

	if (reason == LEJPCB_VAL_STR_START) {
		if (ctx->path_match - 1 == LRP_ZONE) {
			a->zone_len = 0;
		}
	}

	if (reason == LEJPCB_VAL_STR_CHUNK || reason == LEJPCB_VAL_STR_END) {
		switch (ctx->path_match - 1) {
		case LRP_REQ:
			lws_strncpy(a->req, ctx->buf, sizeof(a->req));
			break;
		case LRP_DOMAIN:
			lws_strncpy(a->domain, ctx->buf, sizeof(a->domain));
			break;
		case LRP_SUBDOMAIN:
			lws_strncpy(a->subdomain, ctx->buf, sizeof(a->subdomain));
			break;
		case LRP_EMAIL:
			lws_strncpy(a->email, ctx->buf, sizeof(a->email));
			break;
		case LRP_ORG:
			lws_strncpy(a->organization, ctx->buf, sizeof(a->organization));
			break;
		case LRP_DIR_URL:
			lws_strncpy(a->directory_url, ctx->buf, sizeof(a->directory_url));
			break;
		case LRP_ZONE:
			if (!a->zone_buf) {
				a->zone_alloc = 8192;
				a->zone_buf = malloc((size_t)a->zone_alloc);
				if (!a->zone_buf) return -1;
			}
			if (a->zone_len + ctx->npos >= a->zone_alloc) {
				a->zone_alloc *= 2;
				char *nb = realloc(a->zone_buf, (size_t)a->zone_alloc);
				if (!nb) return -1;
				a->zone_buf = nb;
			}
			memcpy(a->zone_buf + a->zone_len, ctx->buf, ctx->npos);
			a->zone_len += ctx->npos;
			if (reason == LEJPCB_VAL_STR_END) {
				a->zone_buf[a->zone_len] = '\0';
			}
			break;
		case LRP_JWT:
			lws_strncpy(a->jwt, ctx->buf, sizeof(a->jwt));
			break;
		case LRP_SUFFIX:
			lws_strncpy(a->suffix, ctx->buf, sizeof(a->suffix));
			break;
		case LRP_COUNTRY:
			lws_strncpy(a->country, ctx->buf, sizeof(a->country));
			break;
		case LRP_STATE:
			lws_strncpy(a->state, ctx->buf, sizeof(a->state));
			break;
		case LRP_LOCALITY:
			lws_strncpy(a->locality, ctx->buf, sizeof(a->locality));
			break;
		case LRP_PROFILE:
			lws_strncpy(a->profile, ctx->buf, sizeof(a->profile));
			break;
		case LRP_KEY_TYPE:
			lws_strncpy(a->key_type, ctx->buf, sizeof(a->key_type));
			break;
		}
	}

	return 0;
}


#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static char *
read_file(const char *path)
{
	int fd = open(path, O_RDONLY);
	struct stat st;
	char *buf = NULL;

	if (fd < 0)
		return NULL;

	if (!fstat(fd, &st)) {
		buf = malloc((size_t)st.st_size + 1);
		if (buf) {
			if (read(fd, buf, (size_t)st.st_size) != st.st_size) {
				free(buf);
				buf = NULL;
			} else {
				buf[st.st_size] = '\0';
			}
		}
	}
	close(fd);

	return buf;
}

static int
write_pem(const char *path, const char *type, const uint8_t *der, size_t der_len)
{
	char *b64;
	size_t b64_len = (size_t)lws_base64_size((int)der_len) + 1;
	int fd, n;
	size_t pos = 0, len;
	char hdr[128];

	b64 = malloc(b64_len);
	if (!b64)
		return 1;

	lws_b64_encode_string((const char *)der, (int)der_len, b64, (int)b64_len);
	len = strlen(b64);

	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if (fd < 0) {
		free(b64);
		return 1;
	}

	n = lws_snprintf(hdr, sizeof(hdr), "-----BEGIN %s-----\n", type);
	if (write(fd, hdr, (size_t)n) != n) goto bail;

	while (pos < len) {
		size_t chunk = len - pos > 64 ? 64 : len - pos;
		if (write(fd, b64 + pos, chunk) != (ssize_t)chunk) goto bail;
		if (write(fd, "\n", 1) != 1) goto bail;
		pos += chunk;
	}

	n = lws_snprintf(hdr, sizeof(hdr), "-----END %s-----\n", type);
	if (write(fd, hdr, (size_t)n) != n) goto bail;

	close(fd);
	free(b64);
	return 0;

bail:
	close(fd);
	free(b64);
	return 1;
}

static int
generate_cert_internal(struct vhd *vhd, const char *cn, const char *out_crt, const char *out_key,
		      const char *ca_crt_path, const char *ca_key_path, int is_ca, int is_server)
{
	struct lws_x509_cert_gen_info info;
	uint8_t *cert_buf = NULL, *key_buf = NULL;
	size_t cert_len = 0, key_len = 0;
	char *ca_crt_pem = NULL, *ca_key_pem = NULL;
	int ret = 1;

	memset(&info, 0, sizeof(info));
	info.san = cn;
	info.curve_name = "P-384"; /* ECDSA P-384 for Distribution PKI */
	info.is_ca = is_ca;
	info.is_server = is_server;

	if (!is_ca && ca_crt_path && ca_key_path) {
		ca_crt_pem = read_file(ca_crt_path);
		ca_key_pem = read_file(ca_key_path);
		if (!ca_crt_pem || !ca_key_pem) {
			lwsl_err("%s: failed to read CA cert or key\n", __func__);
			goto bail;
		}
		info.ca_cert_pem = ca_crt_pem;
		info.ca_key_pem = ca_key_pem;
	}

	if (lws_x509_create_cert(vhd->context, &cert_buf, &cert_len, &key_buf, &key_len, &info)) {
		lwsl_err("%s: failed to create cert\n", __func__);
		goto bail;
	}

	if (write_pem(out_crt, "CERTIFICATE", cert_buf, cert_len)) {
		lwsl_err("%s: failed to write cert\n", __func__);
		goto bail;
	}

	if (write_pem(out_key, "EC PRIVATE KEY", key_buf, key_len)) {
		lwsl_err("%s: failed to write key\n", __func__);
		goto bail;
	}

	ret = 0;

bail:
	if (ca_crt_pem) free(ca_crt_pem);
	if (ca_key_pem) free(ca_key_pem);
	if (cert_buf) free(cert_buf);
	if (key_buf) free(key_buf);

	return ret;
}

static void
generate_dist_pki(struct vhd *vhd)
{
	char path_crt[1024], path_key[1024], path_dir[1024];

	lws_snprintf(path_dir, sizeof(path_dir), "%s/pki", vhd->base_dir);
	if (mkdir(path_dir, 0700) < 0 && errno != EEXIST)
		lwsl_notice("%s: Failed to create pki dir\n", __func__);

	lws_snprintf(path_crt, sizeof(path_crt), "%s/pki/distribution-ca.crt", vhd->base_dir);
	lws_snprintf(path_key, sizeof(path_key), "%s/pki/distribution-ca.key", vhd->base_dir);

	if (access(path_crt, F_OK) != 0) {
		lwsl_notice("%s: Generating Distribution CA\n", __func__);
		generate_cert_internal(vhd, "dnssec-monitor-distribution-ca", path_crt, path_key, NULL, NULL, 1, 0);
	}
}

static void
generate_dist_server_cert(struct vhd *vhd, const char *domain)
{
	char path_crt[1024], path_key[1024], path_dir[1024];
	char ca_crt[1024], ca_key[1024];

	lws_snprintf(path_dir, sizeof(path_dir), "%s/pki", vhd->base_dir);
	if (mkdir(path_dir, 0700) < 0 && errno != EEXIST)
		lwsl_notice("%s: Failed to create pki dir\n", __func__);

	lws_snprintf(path_crt, sizeof(path_crt), "%s/pki/distribution-server-%s.crt", vhd->base_dir, domain);
	lws_snprintf(path_key, sizeof(path_key), "%s/pki/distribution-server-%s.key", vhd->base_dir, domain);

	if (access(path_crt, F_OK) == 0) return;

	lws_snprintf(ca_crt, sizeof(ca_crt), "%s/pki/distribution-ca.crt", vhd->base_dir);
	lws_snprintf(ca_key, sizeof(ca_key), "%s/pki/distribution-ca.key", vhd->base_dir);

	lwsl_notice("%s: Generating Distribution Server Cert for %s (CN=%s)\n", __func__, domain, domain);
	generate_cert_internal(vhd, domain, path_crt, path_key, ca_crt, ca_key, 0, 1);
}

static void
generate_client_cert(struct vhd *vhd, const char *domain, const char *subdomain)
{
	char path_dir[1024], path_crt[1024], path_key[1024];
	char ca_crt[1024], ca_key[1024];

	lws_snprintf(path_dir, sizeof(path_dir), "%s/domains/%s/dist-client", vhd->base_dir, domain);
	if (mkdir(path_dir, 0700) < 0 && errno != EEXIST)
		lwsl_notice("%s: Failed to create dist-client dir\n", __func__);

	lws_snprintf(path_crt, sizeof(path_crt), "%s/distribution-client-%s.crt", path_dir, subdomain);
	lws_snprintf(path_key, sizeof(path_key), "%s/distribution-client-%s.key", path_dir, subdomain);

	if (access(path_crt, F_OK) == 0) return;

	lws_snprintf(ca_crt, sizeof(ca_crt), "%s/pki/distribution-ca.crt", vhd->base_dir);
	lws_snprintf(ca_key, sizeof(ca_key), "%s/pki/distribution-ca.key", vhd->base_dir);

	lwsl_notice("%s: Generating Client Cert for %s\n", __func__, subdomain);
	generate_cert_internal(vhd, subdomain, path_crt, path_key, ca_crt, ca_key, 0, 0);
}

static void
handle_req_status(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"status\",\"status\":\"ok\"}\n");
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_get_domains(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char path[1024];
	DIR *d;
	struct dirent *de;

	lws_snprintf(path, sizeof(path), "%s/domains", vhd->base_dir);
	d = opendir(path);
	if (!d) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"get_domains\",\"status\":\"error\",\"msg\":\"Cannot open base_dir\"}\n");
	} else {
		int first = 1;
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"get_domains\",\"status\":\"ok\",\"domains\":[");
		while ((de = readdir(d))) {
			if (de->d_name[0] == '.') continue;
			if (de->d_type == DT_DIR || de->d_type == DT_UNKNOWN) {
				char whois_path[1024], whois_buf[2048] = "{}";
				char dns_path[1024], dns_buf[1024] = "{}";
				char ds_path[1024], ds_buf[256] = "";
				char disabled_path[1024];
				int acme_enabled = 1;
				int fd;

				lws_snprintf(whois_path, sizeof(whois_path), "%s/domains/%s/whois.json", vhd->base_dir, de->d_name);
				if ((fd = open(whois_path, O_RDONLY)) >= 0) {
					ssize_t nw = read(fd, whois_buf, sizeof(whois_buf) - 1);
					if (nw > 0) whois_buf[nw] = '\0';
					close(fd);
				}

				lws_snprintf(dns_path, sizeof(dns_path), "%s/domains/%s/dns_state.json", vhd->base_dir, de->d_name);
				if ((fd = open(dns_path, O_RDONLY)) >= 0) {
					ssize_t nw = read(fd, dns_buf, sizeof(dns_buf) - 1);
					if (nw > 0) dns_buf[nw] = '\0';
					close(fd);
				}

				lws_snprintf(ds_path, sizeof(ds_path), "%s/domains/%s/dns_ds.txt", vhd->base_dir, de->d_name);
				if ((fd = open(ds_path, O_RDONLY)) >= 0) {
					ssize_t nw = read(fd, ds_buf, sizeof(ds_buf) - 1);
					if (nw > 0) {
						ds_buf[nw] = '\0';
						char *nl = strchr(ds_buf, '\n');
						if (nl) *nl = '\0';
					}
					close(fd);
				}

				lws_snprintf(disabled_path, sizeof(disabled_path), "%s/domains/%s/acme_disabled", vhd->base_dir, de->d_name);
				if (access(disabled_path, F_OK) == 0)
					acme_enabled = 0;

				if (!first) tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), ",");
				tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx),
					"{\"name\":\"%s\",\"whois\":%s,\"dns\":%s,\"local_ds\":\"%s\",\"acme_enabled\":%s}",
					de->d_name, whois_buf[0] ? whois_buf : "{}", dns_buf[0] ? dns_buf : "{}", ds_buf, acme_enabled ? "true" : "false");
				first = 0;
			}
		}
		closedir(d);
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "]}\n");
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_create_domain(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];
	int r = 0;

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s", vhd->base_dir, a->domain);
	if (mkdir(d_path, 0700) < 0 && errno != EEXIST) {
		lwsl_notice("%s: Failed to create domain dir\n", __func__);
		r = -1;
	}

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/conf.d", vhd->base_dir, a->domain);
	if (mkdir(d_path, 0700) < 0 && errno != EEXIST) {
		lwsl_notice("%s: Failed to create conf.d dir\n", __func__);
		r = -1;
	}

	if (r) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Failed making dirs\"}\n", a->req);
	} else {
		char buf[1024];
		int fd, n;

		/* Create minimal json */
		lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/conf.d/%s.json", vhd->base_dir, a->domain, a->domain);
		fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
		if (fd >= 0) {
			n = lws_snprintf(buf, sizeof(buf), "{\n  \"common-name\": \"%s\"\n}\n", a->domain);
			if (write(fd, buf, (size_t)n) < 0) {
				lwsl_err("%s: Failed to write conf.d\n", __func__);
			}
			close(fd);
		}

		/* Touch empty zone */
		lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/%s.zone", vhd->base_dir, a->domain, a->domain);
		fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
		if (fd >= 0) close(fd);

		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_delete_domain(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s", vhd->base_dir, a->domain);
	lws_dir(d_path, NULL, lws_dir_rm_rf_cb);
	rmdir(d_path);

	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_get_zone(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/%s.zone", vhd->base_dir, a->domain, a->domain);
	int fd = open(d_path, O_RDONLY);
	if (fd >= 0) {
		struct stat st;
		if (!fstat(fd, &st) && st.st_size >= 0) {
			size_t sz = (size_t)st.st_size;
			char *z = malloc(sz + 1);
			if (z) {
				if (read(fd, z, sz) == (ssize_t)sz) {
					z[sz] = '\0';
					tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\",\"zone\":\"", a->req);
					for (size_t i = 0; i < sz; i++) {
						if (tx >= tx_end - 6) break;
						if (z[i] == '\n') { *tx++ = '\\'; *tx++ = 'n'; }
						else if (z[i] == '\r') { *tx++ = '\\'; *tx++ = 'r'; }
						else if (z[i] == '"') { *tx++ = '\\'; *tx++ = '"'; }
						else if (z[i] == '\\') { *tx++ = '\\'; *tx++ = '\\'; }
						else if (z[i] == '\t') { *tx++ = '\\'; *tx++ = 't'; }
						else *tx++ = z[i];
					}
					tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\"}\n");
				}
				free(z);
			}
		}
		close(fd);
	} else {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Zone missing\"}\n", a->req);
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_get_ipv6_suffix(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char path[1024];
	char suffix[64] = {0};

	lws_snprintf(path, sizeof(path), "%s/domains/ipv6_suffix.txt", vhd->base_dir);
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		lws_snprintf(path, sizeof(path), "%s/domains/ipv6_suffix.txt", vhd->base_dir);
		fd = open(path, O_RDONLY);
	}
	if (fd >= 0) {
		ssize_t n = read(fd, suffix, sizeof(suffix) - 1);
		if (n > 0) suffix[n] = '\0';
		close(fd);
		/* Trim whitespace just in case */
		for (int i = (int)strlen(suffix) - 1; i >= 0 && (suffix[i] == '\n' || suffix[i] == '\r' || suffix[i] == ' '); i--)
			suffix[i] = '\0';
	}

	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\",\"suffix\":\"%s\"}\n", a->req, suffix);
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_set_ipv6_suffix(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char path[1024];

	lws_snprintf(path, sizeof(path), "%s/domains/ipv6_suffix.txt", vhd->base_dir);
	if (!a->suffix[0]) {
		unlink(path);
	} else {
		int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
		if (fd < 0 && errno == EACCES) {
			lws_snprintf(path, sizeof(path), "%s/domains/ipv6_suffix.txt", vhd->base_dir);
			fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
		}
		if (fd >= 0) {
			if (write(fd, a->suffix, strlen(a->suffix)) < 0) {
				lwsl_err("%s: Failed writing suffix\n", __func__);
			}
			close(fd);
		} else {
			lwsl_err("%s: Failed to open %s for suffix write (errno=%d)\n", __func__, path, errno);
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Failed to write configuration\"}\n", a->req);
			goto done;
		}
	}
	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);
done:
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_update_zone(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];

	if (!a->zone_buf) goto fail;

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/%s.zone", vhd->base_dir, a->domain, a->domain);
	int fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (fd >= 0) {
		if (write(fd, a->zone_buf, (size_t)a->zone_len) == (ssize_t)a->zone_len) {
			char signed_path[1024];
			lws_snprintf(signed_path, sizeof(signed_path), "%s/domains/%s/%s.zone.signed", vhd->base_dir, a->domain, a->domain);
			lwsl_user("%s: Unlinking signed zone %s to trigger resign\n", __func__, signed_path);
			unlink(signed_path);
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);
		} else {
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Partial write failure\"}\n", a->req);
		}
		close(fd);
	} else {
fail:
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Could not open zone for writing\"}\n", a->req);
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
get_dane_hash(const char *base_dir, const char *domain, const char *certs_dir, const char *root, int previous, char *out, size_t out_len)
{
	char cert_path[256];
	int cfd;
	struct lws_x509_cert *cert = NULL;

	out[0] = '\0';

	lws_snprintf(cert_path, sizeof(cert_path), "%s/domains/%s/certs/%s/crt/%s-%s.crt",
		base_dir, domain, certs_dir, root, previous ? "previous" : "latest");

	cfd = open(cert_path, LWS_O_RDONLY);
	if (cfd < 0) return;

	if (!lws_x509_create(&cert)) {
		struct stat st;
		if (!fstat(cfd, &st) && st.st_size > 0) {
			char *pembuf = malloc((size_t)st.st_size);
			if (pembuf && read(cfd, pembuf, (unsigned int)st.st_size) == st.st_size) {
				if (lws_x509_parse_from_pem(cert, pembuf, (size_t)st.st_size) >= 0) {
					union lws_tls_cert_info_results res1;
					union lws_tls_cert_info_results *res;
					res1.ns.len = 0;
					if (lws_x509_info(cert, LWS_TLS_CERT_INFO_DER_SPKI, &res1, 0) == -1 && res1.ns.len > 0) {
						size_t alloc_len = sizeof(*res) - sizeof(res1.ns.name) + (size_t)res1.ns.len;
						res = malloc(alloc_len);
						if (res) {
							res->ns.len = 0;
							if (lws_x509_info(cert, LWS_TLS_CERT_INFO_DER_SPKI, res, (size_t)res1.ns.len) == 0) {
								struct lws_genhash_ctx hash_ctx;
								uint8_t hash[32];
								if (!lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256)) {
									if (!lws_genhash_update(&hash_ctx, (uint8_t *)res->ns.name, (size_t)res->ns.len)) {
										if (!lws_genhash_destroy(&hash_ctx, hash)) {
											char hex[65];
											for (int i = 0; i < 32; i++) lws_snprintf(&hex[i * 2], 3, "%02X", hash[i]);
											lws_snprintf(out, out_len, "3 1 1 %s", hex);
										}
									}
								}
							}
							free(res);
						}
					}
				}
			}
			if (pembuf) free(pembuf);
		}
		lws_x509_destroy(&cert);
	}
	close(cfd);
}

static void
handle_req_get_tls(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];
	DIR *d;
	struct dirent *de;

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/conf.d", vhd->base_dir, a->domain);
	d = opendir(d_path);
	if (!d) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\",\"domain\":\"%s\",\"tls\":[]}\n", a->req, a->domain);
	} else {
		int first = 1;
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\",\"domain\":\"%s\",\"tls\":[", a->req, a->domain);
		while ((de = readdir(d))) {
			if (de->d_name[0] == '.') continue;
			if (strstr(de->d_name, ".port")) {
				char p_path[1024], sub[256];
				lws_strncpy(sub, de->d_name, sizeof(sub));
				char *ext = strstr(sub, ".port");
				if (ext) *ext = '\0';
				lws_snprintf(p_path, sizeof(p_path), "%s/%s", d_path, de->d_name);
				int fd = open(p_path, O_RDONLY);
				if (fd >= 0) {
					char buf[64];
					ssize_t n = read(fd, buf, sizeof(buf) - 1);
					if (n > 0) {
						buf[n] = '\0';
						char dane0[128] = {0}, dane1[128] = {0};
						get_dane_hash(vhd->base_dir, a->domain, vhd->acme_production ? "production" : "staging", sub, 0, dane0, sizeof(dane0));
						get_dane_hash(vhd->base_dir, a->domain, vhd->acme_production ? "production" : "staging", sub, 1, dane1, sizeof(dane1));
						if (!first) tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), ",");
						tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"fqdn\":\"%s\",\"port\":%d,\"dane0\":\"%s\",\"dane1\":\"%s\"}", sub, atoi(buf), dane0, dane1);
						first = 0;
					}
					close(fd);
				}
			}
		}
		closedir(d);
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "]}\n");
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_create_tls(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];
	char p1[1024];
	char buf[2048];
	int n, fd;

	lws_snprintf(p1, sizeof(p1), "%s/domains/%s", vhd->base_dir, a->domain);
	if (mkdir(p1, 0755) < 0 && errno != EEXIST)
		lwsl_notice("%s: Failed to create domain dir\n", __func__);

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/conf.d", vhd->base_dir, a->domain);
	if (mkdir(d_path, 0755) < 0 && errno != EEXIST)
		lwsl_notice("%s: Failed to create conf.d dir\n", __func__);

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/conf.d/%s.json", vhd->base_dir, a->domain, a->subdomain);
	fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (fd >= 0) {
		n = lws_snprintf(buf, sizeof(buf),
			"{\n  \"common-name\": \"%s\",\n  \"challenge-type\": \"dns-01\",\n"
			"  \"email\": \"%s\",\n  \"acme\": {\n"
			"    \"organization\": \"%s\",\n"
			"    \"directory-url\": \"%s\"\n  }\n}\n",
			a->subdomain,
			a->email[0] ? a->email : "",
			a->organization[0] ? a->organization : "",
			a->directory_url[0] ? a->directory_url : "https://acme-v02.api.letsencrypt.org/directory");

		if (write(fd, buf, (size_t)n) == (ssize_t)n) {
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);
		} else {
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Write failed\"}\n", a->req);
		}
		close(fd);
	} else {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Could not create TLS conf\"}\n", a->req);
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_delete_tls(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/conf.d/%s.json", vhd->base_dir, a->domain, a->subdomain);
	unlink(d_path);
	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_save_acme_file(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a, const char *dir_suffix)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];

	if (!a->zone_buf || !a->domain[0] || !a->subdomain[0]) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Missing payload, domain, or filename\"}\n", a->req);
		goto done;
	}

	if (strchr(a->domain, '/') || strstr(a->domain, "..") || strchr(a->domain, '\\') ||
	    strchr(a->subdomain, '/') || strstr(a->subdomain, "..") || strchr(a->subdomain, '\\')) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Path traversal\"}\n", a->req);
		goto done;
	}

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s", vhd->base_dir, a->domain);
	mkdir(d_path, 0755);

	if (dir_suffix[0]) {
		char p1[1024];
		char *p = (char *)dir_suffix;
		char *slash;
		lws_snprintf(p1, sizeof(p1), "%s", d_path);
		while ((slash = strchr(p, '/')) != NULL) {
			*slash = '\0';
			lws_snprintf(p1 + strlen(p1), sizeof(p1) - strlen(p1), "/%s", p);
			mkdir(p1, 0755);
			*slash = '/';
			p = slash + 1;
		}
		lws_snprintf(p1 + strlen(p1), sizeof(p1) - strlen(p1), "/%s", p);
		mkdir(p1, 0755);
	}

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/%s/%s", vhd->base_dir, a->domain, dir_suffix, a->subdomain);

	int perms = 0600;
	if (strstr(a->subdomain, ".crt"))
		perms = 0644;

	int fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, perms);
	if (fd >= 0) {
		if (write(fd, a->zone_buf, (size_t)a->zone_len) == (ssize_t)a->zone_len) {
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);

			if (strstr(a->subdomain, ".crt") || strstr(a->subdomain, ".key")) {
				char link_path[1024];
				lws_strncpy(link_path, d_path, sizeof(link_path));
				char *p = link_path + strlen(link_path);

				if (strstr(a->subdomain, "-fullchain.crt"))
					p -= 14; /* len("-fullchain.crt") */
				else
					p -= 4; /* len(".crt") or len(".key") */

				p -= 16; /* len("-YYYYMMDD-HHMMSS") */

				if (p > link_path && *p == '-') {
					if (strstr(a->subdomain, "-fullchain.crt"))
						lws_snprintf(p, sizeof(link_path) - (size_t)(p - link_path), "-latest-fullchain.crt");
					else if (strstr(a->subdomain, ".crt"))
						lws_snprintf(p, sizeof(link_path) - (size_t)(p - link_path), "-latest.crt");
					else if (strstr(a->subdomain, ".key"))
						lws_snprintf(p, sizeof(link_path) - (size_t)(p - link_path), "-latest.key");

					unlink(link_path);
					symlink(a->subdomain, link_path);
				}
			}
		} else {
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Partial write failure\"}\n", a->req);
		}
		close(fd);
	} else {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Could not open file for writing\"}\n", a->req);
	}
done:
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_save_auth_key(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	handle_req_save_acme_file(vhd, root_pss, a, "");
}

static void
handle_req_save_cert(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char dir_suffix[64];
	lws_snprintf(dir_suffix, sizeof(dir_suffix), "certs/%s/crt", vhd->acme_production ? "production" : "staging");
	handle_req_save_acme_file(vhd, root_pss, a, dir_suffix);
}

static void
handle_req_save_key(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char dir_suffix[64];
	lws_snprintf(dir_suffix, sizeof(dir_suffix), "certs/%s/key", vhd->acme_production ? "production" : "staging");
	handle_req_save_acme_file(vhd, root_pss, a, dir_suffix);
}

static void
handle_req_save_dns_challenge(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];

	if (!a->zone_buf || !a->domain[0]) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Missing payload or domain\"}\n", a->req);
		goto done;
	}

	if (strchr(a->domain, '/') || strstr(a->domain, "..") || strchr(a->domain, '\\')) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Path traversal\"}\n", a->req);
		goto done;
	}

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/dns/%s.zone.acme", vhd->base_dir, a->domain, a->domain);

	int fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd >= 0) {
		if (write(fd, a->zone_buf, (size_t)a->zone_len) == (ssize_t)a->zone_len) {
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);
		} else {
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Partial write failure\"}\n", a->req);
		}
		close(fd);

		/* Force resign */
		char zone_path[512];
		lws_snprintf(zone_path, sizeof(zone_path), "%s/domains/%s/dns/%s.zone.signed", vhd->base_dir, a->domain, a->domain);
		unlink(zone_path);

		char trigger_path[512];
		lws_snprintf(trigger_path, sizeof(trigger_path), "%s/domains/.acme_trigger_%s", vhd->base_dir, a->domain);
		int t_fd = open(trigger_path, O_CREAT | O_WRONLY, 0600);
		if (t_fd >= 0) close(t_fd);
		unlink(trigger_path);

	} else {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Could not open file for writing\"}\n", a->req);
	}
done:
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_cleanup_dns_challenge(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];

	if (!a->domain[0]) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Missing domain\"}\n", a->req);
		goto done;
	}

	if (strchr(a->domain, '/') || strstr(a->domain, "..") || strchr(a->domain, '\\')) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Path traversal\"}\n", a->req);
		goto done;
	}

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/dns/%s.zone.acme", vhd->base_dir, a->domain, a->domain);
	unlink(d_path);

	/* Force resign */
	char zone_path[512];
	lws_snprintf(zone_path, sizeof(zone_path), "%s/domains/%s/dns/%s.zone.signed", vhd->base_dir, a->domain, a->domain);
	unlink(zone_path);

	char trigger_path[512];
	lws_snprintf(trigger_path, sizeof(trigger_path), "%s/domains/.acme_trigger_%s", vhd->base_dir, a->domain);
	int t_fd = open(trigger_path, O_CREAT | O_WRONLY, 0600);
	if (t_fd >= 0) close(t_fd);
	unlink(trigger_path);

	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);
done:
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_get_all_tls(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];
	DIR *d, *d2;
	struct dirent *de, *de2;
	int first_dom = 1;

	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\",\"all_tls\":[", a->req);

	lws_snprintf(d_path, sizeof(d_path), "%s/domains", vhd->base_dir);
	d = opendir(d_path);
	if (d) {
		while ((de = readdir(d))) {
			if (de->d_name[0] == '.') continue;
			char conf_path[1024];
			lws_snprintf(conf_path, sizeof(conf_path), "%s/domains/%s/conf.d", vhd->base_dir, de->d_name);
			d2 = opendir(conf_path);
			if (d2) {
				if (!first_dom) tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), ",");
				tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"domain\":\"%s\",\"tls\":[", de->d_name);
				int first_tls = 1;
				while ((de2 = readdir(d2))) {
					if (de2->d_name[0] == '.') continue;
					if (strstr(de2->d_name, ".port")) {
						char p_path[1024], sub[256];
						lws_strncpy(sub, de2->d_name, sizeof(sub));
						char *ext = strstr(sub, ".port");
						if (ext) *ext = '\0';
						lws_snprintf(p_path, sizeof(p_path), "%s/%s", conf_path, de2->d_name);
						int fd = open(p_path, O_RDONLY);
						if (fd >= 0) {
							char buf[64];
							ssize_t n = read(fd, buf, sizeof(buf) - 1);
							if (n > 0) {
								buf[n] = '\0';
								char dane0[128] = {0}, dane1[128] = {0};
								get_dane_hash(vhd->base_dir, de->d_name, vhd->acme_production ? "production" : "staging", sub, 0, dane0, sizeof(dane0));
								get_dane_hash(vhd->base_dir, de->d_name, vhd->acme_production ? "production" : "staging", sub, 1, dane1, sizeof(dane1));
								if (!first_tls) tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), ",");
								tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"fqdn\":\"%s\",\"port\":%d,\"dane0\":\"%s\",\"dane1\":\"%s\"}", sub, atoi(buf), dane0, dane1);
								first_tls = 0;
							}
							close(fd);
						}
					}
				}
				tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "]}");
				first_dom = 0;
				closedir(d2);
			}
		}
		closedir(d);
	}

	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "]}\n");
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_get_cert_validity(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char cert_path[512];
	int days_left = 0, total_days = 0;

	if (!a->domain[0] || !a->subdomain[0]) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Missing domain or subdomain\"}\n", a->req);
		goto done;
	}

	if (strchr(a->domain, '/') || strstr(a->domain, "..") || strchr(a->domain, '\\') ||
	    strchr(a->subdomain, '/') || strstr(a->subdomain, "..") || strchr(a->subdomain, '\\')) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Path traversal\"}\n", a->req);
		goto done;
	}

	lws_snprintf(cert_path, sizeof(cert_path), "%s/domains/%s/certs/%s/crt/%s-latest.crt",
			vhd->base_dir, a->domain, vhd->acme_production ? "production" : "staging", a->subdomain);

	if (!lws_tls_cert_get_x509_remaining(vhd->context, cert_path, &days_left, &total_days)) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\",\"days_left\":%d,\"total_days\":%d}\n", a->req, days_left, total_days);
	} else {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Could not read certificate\"}\n", a->req);
	}

done:
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_get_acme_config(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];

	lws_snprintf(d_path, sizeof(d_path), "%s/acme_config.json", vhd->base_dir);
	int fd = open(d_path, O_RDONLY);
	if (fd >= 0) {
		char buf[4096];
		ssize_t n = read(fd, buf, sizeof(buf) - 1);
		if (n > 0) {
			buf[n] = '\0';
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"get_acme_config\",\"status\":\"ok\",\"config\":%s}\n", buf);
		} else {
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"get_acme_config\",\"status\":\"ok\",\"config\":{}}\n");
		}
		close(fd);
	} else {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"get_acme_config\",\"status\":\"ok\",\"config\":{}}\n");
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_set_acme_config(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];
	char buf[4096];
	int n, fd;

	lws_snprintf(d_path, sizeof(d_path), "%s/acme_config.json", vhd->base_dir);
	fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd >= 0) {
		if (vhd->proxy_uid != (uid_t)-1 || vhd->proxy_gid != (gid_t)-1)
			fchown(fd, vhd->proxy_uid, vhd->proxy_gid);
		n = lws_snprintf(buf, sizeof(buf),
			"{\n  \"enabled\": %s,\n  \"production\": %s,\n  \"email\": \"%s\",\n"
			"  \"organization\": \"%s\",\n  \"country\": \"%s\",\n  \"state\": \"%s\",\n"
			"  \"locality\": \"%s\",\n  \"profile\": \"%s\",\n  \"sign_validity_days\": %d\n}\n",
			a->enabled ? "true" : "false",
			a->production ? "true" : "false",
			a->email, a->organization, a->country, a->state, a->locality, a->profile,
			a->sign_validity_days ? a->sign_validity_days : 21);

		if (write(fd, buf, (size_t)n) == (ssize_t)n) {
			if (a->sign_validity_days > 0)
				vhd->signature_duration = (uint32_t)(a->sign_validity_days * 24 * 3600);
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"set_acme_config\",\"status\":\"ok\"}\n");
		} else {
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"set_acme_config\",\"status\":\"error\",\"msg\":\"Write failed\"}\n");
		}
		close(fd);
	} else {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"set_acme_config\",\"status\":\"error\",\"msg\":\"Could not open config\"}\n");
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_set_domain_acme(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/acme_disabled", vhd->base_dir, a->domain);
	if (a->enabled) {
		unlink(d_path);
	} else {
		int fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (fd >= 0) {
			if (vhd->proxy_uid != (uid_t)-1 || vhd->proxy_gid != (gid_t)-1)
				fchown(fd, vhd->proxy_uid, vhd->proxy_gid);
			close(fd);
		}
	}

	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"set_domain_acme\",\"status\":\"ok\"}\n");
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_get_acme_log(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];

	lws_snprintf(d_path, sizeof(d_path), "%s/acme.log", vhd->base_dir);
	int fd = open(d_path, O_RDONLY);
	if (fd >= 0) {
		char buf[4096];
		lws_filepos_t size = (lws_filepos_t)lseek(fd, 0, SEEK_END);
		lws_filepos_t start = 0;
		if (size > 4000) start = size - 4000;
		if (lseek(fd, (off_t)start, SEEK_SET) >= 0) {
			ssize_t n = read(fd, buf, sizeof(buf) - 1);
			if (n > 0) {
				buf[n] = '\0';
				tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"get_acme_log\",\"status\":\"ok\",\"log\":\"");
				for (ssize_t i = 0; i < n; i++) {
					if (buf[i] == '\n') tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\\n");
					else if (buf[i] == '"') tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\\\"");
					else if (buf[i] == '\\') tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\\\\");
					else if (buf[i] >= 32 && buf[i] <= 126) *tx++ = buf[i];
				}
				tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\"}\n");
			} else {
				tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"get_acme_log\",\"status\":\"ok\",\"log\":\"\"}\n");
			}
		}
		close(fd);
	} else {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"get_acme_log\",\"status\":\"ok\",\"log\":\"No log found.\"}\n");
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_trigger_resign(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;

	lwsl_notice("%s: ACME client triggered immediate re-sign for all zones\n", __func__);
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, parent_dnssec_monitor_timer_cb, 100 * LWS_US_PER_MS);

	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"trigger_resign\",\"status\":\"ok\"}\n");
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_update_whois(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	if (a->domain[0] && a->zone_buf) {
		char path[1024];
		lws_snprintf(path, sizeof(path), "%s/domains/%s/whois.json", vhd->base_dir, a->domain);
		int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (fd >= 0) {
			if (vhd->proxy_uid != (uid_t)-1 || vhd->proxy_gid != (gid_t)-1)
				fchown(fd, vhd->proxy_uid, vhd->proxy_gid);
			char decoded[8192];
			int n = lws_b64_decode_string(a->zone_buf, decoded, sizeof(decoded));
			if (n > 0) write(fd, decoded, (size_t)n);
			close(fd);
		}
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_regen_keys(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;

	if (vhd->ops && vhd->ops->keygen) {
		struct lws_dht_dnssec_keygen_args kargs;
		memset(&kargs, 0, sizeof(kargs));
		char wd[1024];
		lws_snprintf(wd, sizeof(wd), "%s/domains/%s", vhd->base_dir, a->domain);
		kargs.domain = a->domain;
		kargs.workdir = wd;

		if (!strcmp(a->key_type, "ES256")) { kargs.type = "EC"; kargs.curve = "P-256"; kargs.bits = 256; }
		else if (!strcmp(a->key_type, "ES384")) { kargs.type = "EC"; kargs.curve = "P-384"; kargs.bits = 384; }
		else if (!strcmp(a->key_type, "R1024")) { kargs.type = "RSA"; kargs.bits = 1024; }
		else if (!strcmp(a->key_type, "R2048")) { kargs.type = "RSA"; kargs.bits = 2048; }
		else { kargs.type = "EC"; kargs.curve = "P-256"; kargs.bits = 256; }

		if (!vhd->ops->keygen(vhd->context, &kargs)) {
			char signed_path[1024];
			lws_snprintf(signed_path, sizeof(signed_path), "%s/%s.zone.signed", wd, a->domain);
			unlink(signed_path);
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);
		} else {
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Key generation failed\"}\n", a->req);
		}
	} else {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Keygen unsupported\"}\n", a->req);
	}
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

struct lws * handle_req_get_acme_profiles(struct vhd *vhd, struct pss *root_pss, const char *directory_url)
{
	struct lws_client_connect_info i;
	memset(&i, 0, sizeof(i));
	i.context = vhd->context;
	struct lws_vhost *vh = lws_get_vhost_by_name(vhd->context, "root-monitor-dummy");
	i.vhost = vh ? vh : vhd->vhost;

	const char *url = (vhd->acme_production) ?
		"https://acme-v02.api.letsencrypt.org/directory" :
		"https://acme-staging-v02.api.letsencrypt.org/directory";

	i.address = vhd->acme_production ? "acme-v02.api.letsencrypt.org" : "acme-staging-v02.api.letsencrypt.org";
	i.port = 443;
	i.ssl_connection = LCCSCF_USE_SSL;
	i.alpn = "http/1.1";
	i.method = "GET";
	i.path = "/directory";
	i.host = i.address;
	i.origin = i.address;
	i.protocol = "lws-dht-dnssec-monitor";

	struct acme_profiles_fetch_info *afi = malloc(sizeof(*afi));
	if (afi) {
		memset(afi, 0, sizeof(*afi));
		afi->magic = ACME_PROFILES_MAGIC;
		afi->root_pss = root_pss;
		i.opaque_user_data = afi;
	}

	lwsl_notice("%s: Fetching ACME directory from %s\n", __func__, url);
	struct lws *wsi = lws_client_connect_via_info(&i);
	if (!wsi && afi) {
		free(afi);
		char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
		root_pss->tx_len += (size_t)lws_snprintf(tx, 65536 - root_pss->tx_len, "{\"req\":\"get_acme_profiles\",\"status\":\"error\",\"msg\":\"Failed to connect to ACME directory\"}\n");
		lws_callback_on_writable_all_protocol(vhd->context, lws_get_protocol(root_pss->wsi));
	}
	return wsi;
}

static void handle_get_acme_profiles_wrapper(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	handle_req_get_acme_profiles(vhd, root_pss, NULL);
}

static void
handle_req_get_dist_server_domain(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char path[1024];
	char domain[256] = "";
	int fd;

	lws_snprintf(path, sizeof(path), "%s/dist_server_domain.txt", vhd->base_dir);
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		ssize_t n = read(fd, domain, sizeof(domain) - 1);
		if (n > 0) {
			domain[n] = '\0';
			char *nl = strchr(domain, '\n');
			if (nl) *nl = '\0';
		}
		close(fd);
	}

	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\",\"domain\":\"%s\"}\n", a->req, domain);
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_set_dist_server_domain(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536 - 1;
	char path[1024];
	int fd;

	lws_snprintf(path, sizeof(path), "%s/dist_server_domain.txt", vhd->base_dir);

	if (!a->domain[0]) {
		unlink(path);
	} else {
		fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (fd >= 0) {
			if (write(fd, a->domain, strlen(a->domain)) < 0) {
				lwsl_err("%s: Failed writing dist server domain\n", __func__);
			}
			close(fd);
		} else {
			lwsl_err("%s: Failed to open %s for write (errno=%d)\n", __func__, path, errno);
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Failed to write configuration\"}\n", a->req);
			goto done;
		}
	}
	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);
done:
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_provisioning_bundle(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536;
	char path[512], *ca = NULL, *crt = NULL, *key = NULL;
	struct stat st;
	int fd;

	if (!a->domain[0] || !a->subdomain[0]) {
		root_pss->tx_len += (size_t)lws_snprintf(tx, 65536 - root_pss->tx_len, "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Missing domain or subdomain\"}\n", a->req);
		return;
	}

	generate_client_cert(vhd, a->domain, a->subdomain);

	lws_snprintf(path, sizeof(path), "%s/pki/distribution-ca.crt", vhd->base_dir);
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		if (fstat(fd, &st) == 0) {
			ca = malloc((size_t)st.st_size + 1);
			if (ca && read(fd, ca, (size_t)st.st_size) == (ssize_t)st.st_size) ca[st.st_size] = '\0';
			else { free(ca); ca = NULL; }
		}
		close(fd);
	}

	lws_snprintf(path, sizeof(path), "%s/domains/%s/dist-client/distribution-client-%s.crt", vhd->base_dir, a->domain, a->subdomain);
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		if (fstat(fd, &st) == 0) {
			crt = malloc((size_t)st.st_size + 1);
			if (crt && read(fd, crt, (size_t)st.st_size) == (ssize_t)st.st_size) crt[st.st_size] = '\0';
			else { free(crt); crt = NULL; }
		}
		close(fd);
	}

	lws_snprintf(path, sizeof(path), "%s/domains/%s/dist-client/distribution-client-%s.key", vhd->base_dir, a->domain, a->subdomain);
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		if (fstat(fd, &st) == 0) {
			key = malloc((size_t)st.st_size + 1);
			if (key && read(fd, key, (size_t)st.st_size) == (ssize_t)st.st_size) key[st.st_size] = '\0';
			else { free(key); key = NULL; }
		}
		close(fd);
	}

	if (!ca || !crt || !key) {
		root_pss->tx_len += (size_t)lws_snprintf(tx, 65536 - root_pss->tx_len, "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Certificate files not found on server\"}\n", a->req);
		goto bail;
	}

	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\",\"subdomain\":\"%s\",\"ca\":\"", a->req, a->subdomain);
	char *p = ca; while (p && *p) { if (*p == '\n') { *tx++ = '\\'; *tx++ = 'n'; } else if (*p != '\r') *tx++ = *p; p++; }
	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\",\"cert\":\"");
	p = crt; while (p && *p) { if (*p == '\n') { *tx++ = '\\'; *tx++ = 'n'; } else if (*p != '\r') *tx++ = *p; p++; }
	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\",\"key\":\"");
	p = key; while (p && *p) { if (*p == '\n') { *tx++ = '\\'; *tx++ = 'n'; } else if (*p != '\r') *tx++ = *p; p++; }
	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\"}\n");

bail:
	if (ca) free(ca);
	if (crt) free(crt);
	if (key) free(key);
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_download_dist_ca(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536;
	char path[512], *ca = NULL;
	struct stat st;
	int fd;

	lws_snprintf(path, sizeof(path), "%s/pki/distribution-ca.crt", vhd->base_dir);
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		if (fstat(fd, &st) == 0) {
			ca = malloc((size_t)st.st_size + 1);
			if (ca && read(fd, ca, (size_t)st.st_size) == (ssize_t)st.st_size) ca[st.st_size] = '\0';
			else { free(ca); ca = NULL; }
		}
		close(fd);
	}

	if (!ca) {
		root_pss->tx_len += (size_t)lws_snprintf(tx, 65536 - root_pss->tx_len, "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"CA not found\"}\n", a->req);
		return;
	}

	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\",\"ca\":\"", a->req);
	char *p = ca; while (p && *p) { if (*p == '\n') { *tx++ = '\\'; *tx++ = 'n'; } else if (*p != '\r') *tx++ = *p; p++; }
	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\"}\n");

	free(ca);
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_download_dist_server(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	char *tx_end = tx + 65536;
	char path[512], *ca = NULL, *crt = NULL, *key = NULL;
	struct stat st;
	int fd;

	if (!a->domain[0]) {
		root_pss->tx_len += (size_t)lws_snprintf(tx, 65536 - root_pss->tx_len, "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Missing domain parameter\"}\n", a->req);
		return;
	}

	generate_dist_server_cert(vhd, a->domain);

	lws_snprintf(path, sizeof(path), "%s/pki/distribution-ca.crt", vhd->base_dir);
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		if (fstat(fd, &st) == 0) {
			ca = malloc((size_t)st.st_size + 1);
			if (ca && read(fd, ca, (size_t)st.st_size) == (ssize_t)st.st_size) ca[st.st_size] = '\0';
			else { free(ca); ca = NULL; }
		}
		close(fd);
	}

	lws_snprintf(path, sizeof(path), "%s/pki/distribution-server-%s.crt", vhd->base_dir, a->domain);
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		if (fstat(fd, &st) == 0) {
			crt = malloc((size_t)st.st_size + 1);
			if (crt && read(fd, crt, (size_t)st.st_size) == (ssize_t)st.st_size) crt[st.st_size] = '\0';
			else { free(crt); crt = NULL; }
		}
		close(fd);
	}

	lws_snprintf(path, sizeof(path), "%s/pki/distribution-server-%s.key", vhd->base_dir, a->domain);
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		if (fstat(fd, &st) == 0) {
			key = malloc((size_t)st.st_size + 1);
			if (key && read(fd, key, (size_t)st.st_size) == (ssize_t)st.st_size) key[st.st_size] = '\0';
			else { free(key); key = NULL; }
		}
		close(fd);
	}

	if (!ca || !crt || !key) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Server cert/key not found\"}\n", a->req);
		goto bail;
	}

	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\",\"ca\":\"", a->req);
	char *p = ca; while (p && *p) { if (*p == '\n') { *tx++ = '\\'; *tx++ = 'n'; } else if (*p != '\r') *tx++ = *p; p++; }
	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\",\"cert\":\"");
	p = crt; while (p && *p) { if (*p == '\n') { *tx++ = '\\'; *tx++ = 'n'; } else if (*p != '\r') *tx++ = *p; p++; }
	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\",\"key\":\"");
	p = key; while (p && *p) { if (*p == '\n') { *tx++ = '\\'; *tx++ = 'n'; } else if (*p != '\r') *tx++ = *p; p++; }
	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\",\"domain\":\"%s\"}\n", a->domain);

bail:
	if (ca) free(ca);
	if (crt) free(crt);
	if (key) free(key);
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_check_cert(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	struct lws_client_connect_info i;
	memset(&i, 0, sizeof(i));
	i.context = vhd->context;
	struct lws_vhost *vh = lws_get_vhost_by_name(vhd->context, "root-monitor-dummy");
	i.vhost = vh ? vh : vhd->vhost;
	i.address = a->subdomain;
	i.port = a->port;
	i.ssl_connection = LCCSCF_ALLOW_SELFSIGNED | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	int starttls = (a->port == 25 || a->port == 587);
	if (!starttls) i.ssl_connection |= LCCSCF_USE_SSL;
	i.alpn = "http/1.1"; i.method = "RAW"; i.path = "/"; i.host = i.address; i.origin = i.address; i.protocol = "lws-dht-dnssec-monitor";
	struct cert_check_info *cci = malloc(sizeof(*cci));
	if (cci) {
		memset(cci, 0, sizeof(*cci));
		cci->magic = CERT_CHECK_MAGIC;
		lws_strncpy(cci->fqdn, a->subdomain, sizeof(cci->fqdn));
		lws_strncpy(cci->domain, a->domain, sizeof(cci->domain));
		cci->port = a->port; cci->starttls_state = starttls ? 1 : 0;
		i.opaque_user_data = cci;
	}
	if (!cci || !lws_client_connect_via_info(&i)) {
		if (cci) free(cci);
		struct cert_check_result *cr = malloc(sizeof(*cr));
		if (cr) {
			memset(cr, 0, sizeof(*cr));
			lws_strncpy(cr->fqdn, a->subdomain, sizeof(cr->fqdn));
			lws_strncpy(cr->msg, "Connection failed", sizeof(cr->msg));
			lws_strncpy(cr->local_msg, "Not Found", sizeof(cr->local_msg));
			lws_strncpy(cr->issuer, "Unknown", sizeof(cr->issuer));

			if (a->domain[0]) {
				char path[1024];
				lws_snprintf(path, sizeof(path), "%s/domains/%s/certs/%s/crt/%s-latest.crt", vhd->base_dir, a->domain, vhd->acme_production ? "production" : "staging", a->subdomain);
				lwsl_notice("%s: Checking local cert at %s\n", __func__, path);
				int fd = open(path, O_RDONLY);
				if (fd >= 0) {
					struct stat st;
					if (!fstat(fd, &st) && st.st_size > 0) {
						uint8_t *pem = malloc((size_t)st.st_size + 1);
						if (pem) {
							if (read(fd, pem, (size_t)st.st_size) == (ssize_t)st.st_size) {
								pem[st.st_size] = '\0';
								struct lws_x509_cert *x509 = NULL;
								if (!lws_x509_create(&x509)) {
									if (!lws_x509_parse_from_pem(x509, pem, (size_t)st.st_size + 1)) {
										union lws_tls_cert_info_results lci;
										if (!lws_x509_info(x509, LWS_TLS_CERT_INFO_ISSUER_NAME, &lci, 0))
											lws_strncpy(cr->issuer, lci.ns.name, sizeof(cr->issuer));
										if (!lws_x509_info(x509, LWS_TLS_CERT_INFO_VALIDITY_TO, &lci, 0)) {
											time_t now; time(&now);
											if (now > lci.time) lws_snprintf(cr->local_msg, sizeof(cr->local_msg), "Expired");
											else lws_snprintf(cr->local_msg, sizeof(cr->local_msg), "%d days", (int)((lci.time - now) / (24 * 3600)));
										}
									} else {
										lwsl_err("%s: Failed to parse PEM at %s\n", __func__, path);
									}
									lws_x509_destroy(&x509);
								}
							}
							free(pem);
						}
					}
					close(fd);
				} else {
					lwsl_err("%s: Failed to open %s: %d\n", __func__, path, errno);
				}
			}

			cr->port = a->port; cr->status_err = 1;

			char json[1024];
			int n = lws_snprintf(json, sizeof(json), "{\"req\":\"cert_status\",\"subdomain\":\"%s\",\"port\":%d,\"status\":\"error\",\"msg\":\"%s\",\"local_msg\":\"%s\",\"issuer\":\"%s\"}\n",
				cr->fqdn, cr->port, cr->msg, cr->local_msg, cr->issuer);

			struct vhd *target_vhd = global_root_vhd ? global_root_vhd : vhd;
			lws_start_foreach_dll(struct lws_dll2 *, p, target_vhd->clients.head) {
				struct pss *wpss = lws_container_of(p, struct pss, list);
				if (wpss->tx_len + (size_t)n < 65536 - LWS_PRE) {
					memcpy(&wpss->tx[LWS_PRE + wpss->tx_len], json, (size_t)n);
					wpss->tx_len += (size_t)n;
					lws_callback_on_writable(wpss->wsi);
				}
			} lws_end_foreach_dll(p);
			free(cr);
		}
	}
}

typedef void (*monitor_req_handler_t)(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a);

static const struct monitor_req_map {
	const char *name;
	monitor_req_handler_t cb;
} req_map[] = {
	{ "status", handle_req_status },
	{ "get_domains", handle_req_get_domains },
	{ "create_domain", handle_req_create_domain },
	{ "delete_domain", handle_req_delete_domain },
	{ "get_zone", handle_req_get_zone },
	{ "update_zone", handle_req_update_zone },
	{ "get_tls", handle_req_get_tls },
	{ "get_all_tls", handle_req_get_all_tls },
	{ "create_tls", handle_req_create_tls },
	{ "delete_tls", handle_req_delete_tls },
	{ "save_auth_key", handle_req_save_auth_key },
	{ "save_cert", handle_req_save_cert },
	{ "save_key", handle_req_save_key },
	{ "save_dns_challenge", handle_req_save_dns_challenge },
	{ "cleanup_dns_challenge", handle_req_cleanup_dns_challenge },
	{ "get_ipv6_suffix", handle_req_get_ipv6_suffix },
	{ "set_ipv6_suffix", handle_req_set_ipv6_suffix },
	{ "get_acme_config", handle_req_get_acme_config },
	{ "set_acme_config", handle_req_set_acme_config },
	{ "set_domain_acme", handle_req_set_domain_acme },
	{ "get_acme_profiles", handle_get_acme_profiles_wrapper },
	{ "get_acme_log", handle_req_get_acme_log },
	{ "trigger_resign", handle_req_trigger_resign },
	{ "update_whois", handle_req_update_whois },
	{ "regen_keys", handle_req_regen_keys },
	{ "provisioning_bundle", handle_req_provisioning_bundle },
	{ "download_dist_ca", handle_req_download_dist_ca },
	{ "download_dist_server", handle_req_download_dist_server },
	{ "get_dist_server_domain", handle_req_get_dist_server_domain },
	{ "set_dist_server_domain", handle_req_set_dist_server_domain },
	{ "check_cert", handle_req_check_cert },
	{ "get_cert_validity", handle_req_get_cert_validity }
};

static void
handle_monitor_request(struct vhd *vhd, struct pss *root_pss, const char *in, size_t len)
{
	struct monitor_req_args a;
	struct lejp_ctx jctx;
	char *tx = (char *)&root_pss->tx[LWS_PRE + root_pss->tx_len];
	const size_t req_map_size = LWS_ARRAY_SIZE(req_map);

	memset(&a, 0, sizeof(a));
	lejp_construct(&jctx, monitor_req_cb, &a, monitor_req_paths, LWS_ARRAY_SIZE(monitor_req_paths));
	int m = lejp_parse(&jctx, (uint8_t *)in, (int)len);
	lejp_destruct(&jctx);

	// lwsl_debug("[INSTRUMENT] handle_monitor_request: executed lejp_parse. len: %d, rc: %d. String: '%.*s'\n", (int)len, m, (int)len, in);

	if (m < 0 && m != LEJP_REJECT_UNKNOWN) {
		lwsl_notice("[INSTRUMENT] handle_monitor_request: JSON parser failed! Error %d, len %d, in:\n%.*s\n", m, (int)len, (int)len, in);
		root_pss->tx_len += (size_t)lws_snprintf(tx, 65536 - root_pss->tx_len, "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"JSON parse failed: %d\"}\n", a.req[0] ? a.req : "unknown", m);
		goto done;
	}

	if (!a.req[0]) {
		lwsl_notice("[INSTRUMENT] handle_monitor_request: Missing 'req' parameter in JSON payload!\n");
		root_pss->tx_len += (size_t)lws_snprintf(tx, 65536 - root_pss->tx_len, "{\"status\":\"error\",\"msg\":\"Missing req\"}\n");
		goto done;
	}

	lwsl_debug("[INSTRUMENT] handle_monitor_request: Routed valid requested endpoint: '%s'\n", a.req);

	if (vhd->auth_jwk.kty == LWS_GENCRYPTO_KTY_OCT) {
		char jwt_out[2048];
		size_t jwt_out_len = sizeof(jwt_out);
		char jwt_temp[2048];
		unsigned long exp_time;

		if (!a.jwt[0]) {
			lwsl_notice("[INSTRUMENT] Missing JWT preamble token\n");
			root_pss->tx_len += (size_t)lws_snprintf(tx, 65536 - root_pss->tx_len, "{\"status\":\"error\",\"msg\":\"Authentication Failed\"}\n");
			goto done;
		}

		if (lws_jwt_signed_validate(vhd->context, &vhd->auth_jwk, "HS256", a.jwt, strlen(a.jwt), jwt_temp, sizeof(jwt_temp), jwt_out, &jwt_out_len)) {
			lwsl_notice("[INSTRUMENT] Invalid/Forged JWT preamble token\n");
			root_pss->tx_len += (size_t)lws_snprintf(tx, 65536 - root_pss->tx_len, "{\"status\":\"error\",\"msg\":\"Authentication Failed\"}\n");
			goto done;
		}

		if (lws_jwt_token_sanity(jwt_out, jwt_out_len, "acme-ipc", "dnssec-monitor", NULL, NULL, 0, &exp_time)) {
			lwsl_notice("[INSTRUMENT] Expired/Invalid JWT claims\n");
			root_pss->tx_len += (size_t)lws_snprintf(tx, 65536 - root_pss->tx_len, "{\"status\":\"error\",\"msg\":\"Authentication Failed\"}\n");
			goto done;
		}
	} else {
		lwsl_notice("[INSTRUMENT] Warning: UDS monitor secret not bootstrapped, rejecting request!\n");
		root_pss->tx_len += (size_t)lws_snprintf(tx, 65536 - root_pss->tx_len, "{\"status\":\"error\",\"msg\":\"Authentication Failed\"}\n");
		goto done;
	}

	/* Prevent path traversal attacks */
	if (strchr(a.domain, '/') || strstr(a.domain, "..") || strchr(a.subdomain, '/') || strstr(a.subdomain, "..")) {
		lwsl_debug("[INSTRUMENT] handle_monitor_request: Path traversal parameters detected\n");
		root_pss->tx_len += (size_t)lws_snprintf(tx, 65536 - root_pss->tx_len, "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Invalid chars in domain\"}\n", a.req);
		goto done;
	}

	for (size_t i = 0; i < req_map_size; i++) {
		if (!strcmp(a.req, req_map[i].name)) {
			/* Enforce domain param if required by the handler */
			if (i > 0 && !a.domain[0] &&
				strcmp(req_map[i].name, "status") &&
				strcmp(req_map[i].name, "get_domains") &&
				strcmp(req_map[i].name, "get_ipv6_suffix") &&
				strcmp(req_map[i].name, "set_ipv6_suffix") &&
				strcmp(req_map[i].name, "get_all_tls") &&
				strcmp(req_map[i].name, "get_acme_config") &&
				strcmp(req_map[i].name, "set_acme_config") &&
				strcmp(req_map[i].name, "get_acme_profiles") &&
				strcmp(req_map[i].name, "get_acme_log") &&
				strcmp(req_map[i].name, "get_dist_server_domain") &&
				strcmp(req_map[i].name, "set_dist_server_domain") &&
				strcmp(req_map[i].name, "download_dist_ca")) {
				lwsl_notice("[INSTRUMENT] handle_monitor_request: Missing required 'domain' param for %s\n", a.req);
				root_pss->tx_len += (size_t)lws_snprintf(tx, 65536 - root_pss->tx_len, "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Missing arguments\"}\n", a.req);
				goto done;
			}
			lwsl_debug("[INSTRUMENT] handle_monitor_request: Calling map callback...\n");
			req_map[i].cb(vhd, root_pss, &a);
			lwsl_debug("[INSTRUMENT] handle_monitor_request: Callback generated response size %d\n", (int)root_pss->tx_len);
			goto done;
		}
	}

	lwsl_notice("[INSTRUMENT] handle_monitor_request: Unknown request parameter '%s'\n", a.req);
	root_pss->tx_len += (size_t)lws_snprintf(tx, 65536 - root_pss->tx_len, "{\"req\":\"unknown\",\"status\":\"error\",\"msg\":\"Unknown req %s\"}\n", a.req);

done:
	if (a.zone_buf) free(a.zone_buf);
}

static void
connect_retry_cb(lws_sorted_usec_list_t *sul)
{
	struct pss *pss = lws_container_of(sul, struct pss, sul);
	struct vhd *vhd = (struct vhd *)lws_protocol_vh_priv_get(lws_get_vhost(pss->wsi), lws_get_protocol(pss->wsi));
	if (!vhd && global_root_vhd)
		vhd = global_root_vhd;

	if (!vhd || !vhd->root_process_active)
		return;

	struct lws_client_connect_info i;
	char uds_path[1024];

	memset(&i, 0, sizeof(i));
	i.method = "RAW";
	i.context = vhd->context;
	i.vhost = lws_get_vhost(pss->wsi);

	/* LWS client connection paths prefix with '+' for Unix Domain Socket */
	lws_snprintf(uds_path, sizeof(uds_path), "+%s", vhd->uds_path);
	i.address = uds_path;
	i.port = 0;
	i.host = "localhost";
	i.origin = "localhost";
	i.method = "RAW";
	i.local_protocol_name = "lws-dht-dnssec-monitor";
	i.opaque_user_data = pss;
	i.pwsi = &pss->cwsi;

	if (!lws_client_connect_via_info(&i)) {
		pss->cwsi = NULL;
		if (++pss->retry_count < 20) {
			lwsl_notice("%s: UDS connection delayed, retrying (%d/20)\n", __func__, pss->retry_count);
			lws_sul_schedule(vhd->context, 0, &pss->sul, connect_retry_cb, 250 * LWS_US_PER_MS);
		} else {
			lwsl_err("%s: failed to connect UI WS proxy to UDS server after retries\n", __func__);
			lws_wsi_close(pss->wsi, LWS_TO_KILL_ASYNC);
		}
	}
}

static void extract_and_queue_cert_result(struct lws *wsi, struct vhd *vhd, struct cert_check_info *cci, const struct lws_protocols *protocol)
{
	union lws_tls_cert_info_results ci;
	char msg[128];
	int err = 0;
	if (!lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_VALIDITY_TO, &ci, 0)) {
		time_t now;
		time(&now);
		if (now > ci.time) {
			lws_snprintf(msg, sizeof(msg), "Expired");
		} else {
			int days = (int)((ci.time - now) / (24 * 3600));
			lws_snprintf(msg, sizeof(msg), "%d days", days);
		}
	} else {
		lws_snprintf(msg, sizeof(msg), "No cert info");
		err = 1;
	}

	struct cert_check_result *cr = malloc(sizeof(*cr));
	if (cr) {
		memset(cr, 0, sizeof(*cr));
		lws_strncpy(cr->fqdn, cci->fqdn, sizeof(cr->fqdn));
		char *colon = strchr(cr->fqdn, ':');
		if (colon) *colon = '\0';
		cr->port = cci->port;
		lws_strncpy(cr->msg, msg, sizeof(cr->msg));
		cr->status_err = err;

		if (!lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_ISSUER_NAME, &ci, 0)) {
			lws_strncpy(cr->issuer, ci.ns.name, sizeof(cr->issuer));
			for (int i = 0; cr->issuer[i]; i++) {
				if (cr->issuer[i] == '\n' || cr->issuer[i] == '\r') cr->issuer[i] = ' ';
				if (cr->issuer[i] == '"') cr->issuer[i] = '\'';
				if (cr->issuer[i] == '\\') cr->issuer[i] = '/';
			}
		} else {
			lws_strncpy(cr->issuer, "Unknown", sizeof(cr->issuer));
		}
		char json[1024];
		int n = lws_snprintf(json, sizeof(json), "{\"req\":\"cert_status\",\"subdomain\":\"%s\",\"port\":%d,\"status\":\"%s\",\"msg\":\"%s\",\"local_msg\":\"%s\",\"issuer\":\"%s\"}\n",
			cr->fqdn, cr->port, cr->status_err ? "error" : "ok", cr->msg, cr->local_msg, cr->issuer);

		struct vhd *target_vhd = global_root_vhd ? global_root_vhd : vhd;
		lws_start_foreach_dll(struct lws_dll2 *, p, target_vhd->clients.head) {
			struct pss *wpss = lws_container_of(p, struct pss, list);
			if (wpss->tx_len + (size_t)n < 65536 - LWS_PRE) {
				memcpy(&wpss->tx[LWS_PRE + wpss->tx_len], json, (size_t)n);
				wpss->tx_len += (size_t)n;
				lws_callback_on_writable(wpss->wsi);
			}
		} lws_end_foreach_dll(p);
		free(cr);
	}
}

static int
callback_dht_dnssec_monitor(struct lws *wsi, enum lws_callback_reasons reason,
			    void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	struct lws_vhost *vhost = lws_get_vhost(wsi);
	const struct lws_protocols *protocol = lws_get_protocol(wsi);
	struct vhd *vhd = (struct vhd *)lws_protocol_vh_priv_get(vhost, protocol);

	if (!vhd && global_root_vhd)
		vhd = global_root_vhd;

	const struct lws_protocol_vhost_options *pvo;

	switch (reason) {

	case LWS_CALLBACK_PROTOCOL_INIT:
		{
			struct lws_context *cx = lws_get_context(wsi);
			const char *p = lws_cmdline_option_cx(cx, "--lws-dht-dnssec-monitor-root");

			if (!p && !in)
				return 0;

			lwsl_vhost_notice(vhost, "dnssec_monitor: PROTOCOL_INIT called!\n");


			/* Root monitor spawned proxy branch */
			if (p) {
				/* Yes, we are the root spawned UDS process! */
				lwsl_notice("%s: Started as UDS root monitor\n", __func__);

				/* Privileges are seamlessly restricted via native LWS framework policies securely dropping after UDS setup */

				/* Only the FIRST protocol in the list handles this, so we don't duplicate vhosts
				 * We'll use vhd presence to guard it if needed. Actually we'll just check if we
				 * already created the UDS vhost to avoid doing it per-protocol INIT.
				 * lws_cmdline_option_cx requires us to look for uds-path.
				 */
				const char *uds_path = lws_cmdline_option_cx(cx, "--uds-path");
				if (!uds_path) uds_path = "/var/run/lws-dnssec-monitor.sock";

				struct lws_context_creation_info info;
				memset(&info, 0, sizeof(info));
				info.vhost_name = "dnssec_monitor_uds";
				info.port = 0; /* raw socket UDS */
				info.options = LWS_SERVER_OPTION_UNIX_SOCK | LWS_SERVER_OPTION_ONLY_RAW;
				info.iface = uds_path;

				const char *uds_perms = lws_cmdline_option_cx(cx, "--uds-perms");
				if (uds_perms)
					info.unix_socket_perms = uds_perms;

				/* We only want this protocol to run on the UDS */
				static const struct lws_protocols *pprotocols[] = {
					&lws_dht_dnssec_monitor_protocols[1],
					NULL
				};
				info.pprotocols = pprotocols;

				/* We need to ensure we don't loop indefinitely creating vhosts.
				 * If lws_get_vhost_by_name finds our vhost, we don't create it again.
				 */
				struct lws_vhost *vh = lws_get_vhost_by_name(cx, info.vhost_name);
				if (!vh) {
					unlink(uds_path);
					vh = lws_create_vhost(cx, &info);
					if (!vh) {
						lwsl_err("%s: Failed to create UDS vhost on %s\n", __func__, uds_path);
						return -1;
					}
					lwsl_notice("%s: Created UDS vhost on %s\n", __func__, uds_path);
				}

				static int timer_armed = 0;
				if (!timer_armed) {
					vhd = lws_protocol_vh_priv_zalloc(vhost, protocol, sizeof(*vhd));
					if (vhd) {
						lwsl_notice("%s: Successfully allocated vhd on %s\n", __func__, lws_get_vhost_name(vhost));
						vhd->context = cx;
						vhd->vhost = vhost;
						vhd->root_process_active = 1;

						{
							lws_system_policy_t *policy;
							if (lws_system_parse_policy(cx, "/etc/lwsws/policy", &policy)) {
								lwsl_vhost_notice(vh, "dnssec_monitor: couldn't parse policy.");
								return -1;
							}
							vhd->base_dir = strdup(policy->dns_base_dir);
							lws_system_policy_free(policy);
						}

						vhd->uds_path = uds_path;
						vhd->signature_duration = 31536000;

						const char *auth_token = lws_cmdline_option_cx(cx, "--auth-token");
						char buf[256];
						if (!auth_token) {
							int n, retries = 50;
							while (retries-- > 0) {
								n = (int)read(0, buf, sizeof(buf) - 1);
								if (n > 0 || (n < 0 && errno != EAGAIN)) break;
								usleep(100000);
							}
							if (n > 0) {
								buf[n] = '\0';
								char *p = strchr(buf, '\n'); if (p) *p = '\0';
								p = strchr(buf, '\r'); if (p) *p = '\0';
								auth_token = buf;
							}
						}

						if (auth_token) {
							lws_strncpy(vhd->auth_token, auth_token, sizeof(vhd->auth_token));
							vhd->auth_jwk.kty = LWS_GENCRYPTO_KTY_OCT;
							vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].len = 64;
							vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf = malloc(64);
							lws_hex_to_byte_array(auth_token, vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf, 64);
							lwsl_notice("%s: securely mapped symmetric daemon auth-token\n", __func__);
						}

						/* Borrow ops from the invoking vhost that originally had it configured */
						const struct lws_protocols *prot = lws_vhost_name_to_protocol(vhost, "lws-dht-dnssec");
						if (!prot) {
							struct lws_vhost *vhdflt = lws_get_vhost_by_name(cx, "default");
							if (vhdflt)
								prot = lws_vhost_name_to_protocol(vhdflt, "lws-dht-dnssec");
						}
						if (prot && prot->user)
							vhd->ops = (const struct lws_dht_dnssec_ops *)prot->user;

						/* Assign functional cross-vhost global routing directly for UDS channels */
						global_root_vhd = vhd;

						if (vhd->ops) {
							char scan_path[1024];
							lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);

							/* Guarantee absolute discovery independently of Unix kernel notify boundaries */
							/* Deferred to cleanly drop execution permissions naturally inside the loop */
							lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, dnssec_monitor_expiry_timer_cb, 1 * LWS_US_PER_SEC);
							timer_armed = 1;

#if defined(LWS_WITH_DIR)
							vhd->dn = lws_dir_notify_create(cx, scan_path, dir_notify_cb, vhd);
							if (!vhd->dn)
								lwsl_err("%s: Failed to attach lws_dir_notify to %s\n", __func__, scan_path);
#endif
						} else {
							lwsl_err("%s: Skipped scheduling timer on %s because vhd->ops is NULL!\n", __func__, lws_get_vhost_name(vhost));
							/* It will organically retry when the next vhost runs PROTOCOL_INIT */
						}
					} else {
						lwsl_err("%s: FAILED to allocate vhd on %s\n", __func__, lws_get_vhost_name(vhost));
					}
				}

				return 0;
			}

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
			const char *uid = "0", *gid = "0";

			if ((pvo = lws_pvo_search(in, "base-dir")))
				vhd->base_dir = strdup(pvo->value);
			else
				vhd->base_dir = strdup("/etc/dnssec");

			if ((pvo = lws_pvo_search(in, "uds-path")))
				vhd->uds_path = pvo->value;
			if ((pvo = lws_pvo_search(in, "signature-duration")))
				vhd->signature_duration = (uint32_t)atoi(pvo->value);
			if ((pvo = lws_pvo_search(in, "uid")))
				uid = pvo->value;
			if ((pvo = lws_pvo_search(in, "gid")))
				gid = pvo->value;

			if ((pvo = lws_pvo_search(in, "cookie-name")))
				lws_strncpy(vhd->cookie_name, pvo->value, sizeof(vhd->cookie_name));
			else
				lws_strncpy(vhd->cookie_name, "auth_session", sizeof(vhd->cookie_name));

			if ((pvo = lws_pvo_search(in, "jwk_path")))
				lws_strncpy(vhd->jwk_path, pvo->value, sizeof(vhd->jwk_path));
			else
				lws_strncpy(vhd->jwk_path, "/var/db/lws-auth.jwk", sizeof(vhd->jwk_path));

			if (lws_jwk_load(&vhd->jwk, vhd->jwk_path, NULL, NULL))
				lwsl_err("%s: Failed to load JWK from %s\n", __func__, vhd->jwk_path);

			if (!vhd->base_dir) {
				lwsl_err("%s: base-dir pvo is required\n", __func__);
				return -1;
			}
			if (!vhd->uds_path)
				vhd->uds_path = "/var/run/lws-dnssec-monitor.sock";

			{
				char d_path[1024];
				lws_snprintf(d_path, sizeof(d_path), "%s/acme_config.json", vhd->base_dir);
				int fd = open(d_path, O_RDONLY);
				if (fd >= 0) {
					char buf[4096];
					ssize_t n = read(fd, buf, sizeof(buf) - 1);
					if (n > 0) {
						struct monitor_req_args a;
						memset(&a, 0, sizeof(a));
						struct lejp_ctx jctx;
						lejp_construct(&jctx, monitor_req_cb, &a, monitor_req_paths, LWS_ARRAY_SIZE(monitor_req_paths));
						lejp_parse(&jctx, (uint8_t *)buf, (int)n);
						lejp_destruct(&jctx);
						if (a.sign_validity_days > 0)
							vhd->signature_duration = (uint32_t)(a.sign_validity_days * 24 * 3600);
					}
					close(fd);
				}
			}

			/* Locate the operational ops struct off the prerequisite plugin */
			const struct lws_protocols *prot = lws_vhost_name_to_protocol(vhd->vhost, "lws-dht-dnssec");
			if (!prot) {
				struct lws_vhost *vhdflt = lws_get_vhost_by_name(vhd->context, "default");
				if (vhdflt)
					prot = lws_vhost_name_to_protocol(vhdflt, "lws-dht-dnssec");
			}
			if (!prot || !prot->user) {
				lwsl_err("%s: prerequisite protocol lws-dht-dnssec is missing or has no ops exported! DHT sync will be bypassed.\n", __func__);
			} else {
				vhd->ops = (const struct lws_dht_dnssec_ops *)prot->user;
			}

			vhd->smd_peer = lws_smd_register(vhd->context, vhd, 0, LWSSMDCL_NETWORK, smd_cb_network);

			lwsl_notice("%s: initialized monitor proxy (base-dir: %s, uds-path: %s)\n", __func__, vhd->base_dir, vhd->uds_path);

			/* Spawn the root monitor process */
			struct lws_spawn_piped_info spawn_info;
			memset(&spawn_info, 0, sizeof(spawn_info));

			static const char *exec_array[15];
			static char arg_uds[1024];
			static char arg_uid[128];
			static char arg_gid[128];
			static char arg_proxy_perms[128];
			int n = 0;
			/* Rely on the original host application executable context path instead of
			 * guessing paths. `argv[0]` guarantees relative/absolute execution fidelity. */
#if defined(__linux__)
			static char plat_exe_buf[256];
#endif
			const char *exe_path = lws_cmdline_option_cx_argv0(vhd->context);

			if (!exe_path || exe_path[0] != '/') {
#if defined(__linux__)
				int m = (int)readlink("/proc/self/exe", plat_exe_buf, sizeof(plat_exe_buf) - 1);
				if (m > 0) {
					plat_exe_buf[m] = '\0';
					exe_path = plat_exe_buf;
				} else
#endif
				{
					exe_path = "/usr/local/bin/lwsws";
				}
			}

			if ((pvo = lws_pvo_search(in, "exe-path")))
				exe_path = pvo->value;

			exec_array[n++] = exe_path;
			exec_array[n++] = "--lws-dht-dnssec-monitor-root";

			const char *conf_dir = lws_cmdline_option_cx(vhd->context, "-c");
			if (conf_dir) {
				exec_array[n++] = "-c";
				exec_array[n++] = conf_dir;
			}

			const char *debug_lvl = lws_cmdline_option_cx(vhd->context, "-d");
			if (debug_lvl) {
				exec_array[n++] = "-d";
				exec_array[n++] = debug_lvl;
			}


			/* no --base-dir needed since the root spawnee will look up the policy itself! */
			if (vhd->uds_path) {
				lws_snprintf(arg_uds, sizeof(arg_uds), "--uds-path=%s", vhd->uds_path);
				exec_array[n++] = arg_uds;
			}
			uid_t target_uid = 0;
			if (uid) {
				if (!lws_plat_user_to_uid(uid, &target_uid))
					lws_snprintf(arg_uid, sizeof(arg_uid), "--uid=%u", (unsigned int)target_uid);
				else
					lws_snprintf(arg_uid, sizeof(arg_uid), "--uid=%s", uid);
				exec_array[n++] = arg_uid;
			}

			gid_t target_gid = 0;
			if (gid) {
				if (!lws_plat_group_to_gid(gid, &target_gid))
					lws_snprintf(arg_gid, sizeof(arg_gid), "--gid=%u", (unsigned int)target_gid);
				else
					lws_snprintf(arg_gid, sizeof(arg_gid), "--gid=%s", gid);
				exec_array[n++] = arg_gid;
			}

			uid_t eff_uid;
			gid_t eff_gid;
			lws_get_effective_uid_gid(vhd->context, &eff_uid, &eff_gid);

			if (uid && !lws_plat_user_to_uid(uid, &target_uid))
				lws_snprintf(arg_proxy_perms, sizeof(arg_proxy_perms), "--uds-perms=%u:%u", (unsigned int)target_uid, (unsigned int)eff_gid);
			else
				lws_snprintf(arg_proxy_perms, sizeof(arg_proxy_perms), "--uds-perms=%s:%u", uid ? uid : "lwsws-priv", (unsigned int)eff_gid);

			exec_array[n++] = arg_proxy_perms;

			for (int i = 0; i < n; i++)
				lwsl_notice("%s: exec_array[%d]: '%s'\n", __func__, i, exec_array[i]);

			if (exec_array[0]) {
				if (!global_root_vhd) {
					/* Generate secure HS256 auth token for UDS */
					uint8_t rand[64];
					char hex[129];
					lws_get_random(vhd->context, rand, sizeof(rand));
					lws_hex_from_byte_array(rand, sizeof(rand), hex, sizeof(hex));

					lws_strncpy(vhd->auth_token, hex, sizeof(vhd->auth_token));
					vhd->auth_jwk.kty = LWS_GENCRYPTO_KTY_OCT;
					vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].len = 64;
					vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf = malloc(64);
					memcpy(vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf, rand, 64);

					lws_system_blob_t *b = lws_system_get_blob(vhd->context, LWS_SYSBLOB_TYPE_EXT_AUTH1, 0);
					if (b) {
						lws_system_blob_direct_set(b, (uint8_t *)vhd->auth_token, strlen(vhd->auth_token));
					}

					/* Inject auth token over native stdin pipe instead of argv to prevent ps inspection */


					exec_array[n++] = NULL;

					spawn_info.exec_array = exec_array;
					spawn_info.timeout_us = 0; /* runs forever */
					spawn_info.plsp = &vhd->lsp;
					spawn_info.reap_cb = lws_dht_dnssec_monitor_reap_cb;
					spawn_info.protocol_name = "lws-dht-dnssec-stdwsi";
					spawn_info.vh = vhd->vhost;

					lwsl_notice("dnssec_monitor: Executing root process: %s\n", exec_array[0]);

					vhd->lsp = lws_spawn_piped(&spawn_info);
					if (!vhd->lsp) {
						lwsl_err("%s: Failed to spawn root monitor process\n", __func__);
						return -1;
					}

					int stdin_fd = (int)(intptr_t)lws_spawn_get_fd_stdxxx(vhd->lsp, 0);
					if (stdin_fd >= 0) {
						char token_buf[140];
						lws_snprintf(token_buf, sizeof(token_buf), "%s\n", hex);
						if (write(stdin_fd, token_buf, strlen(token_buf)) < 0) {
							lwsl_err("%s: Failed dropping token via stdin pipe\n", __func__);
						}
					}
					vhd->root_process_active = 1;
					global_root_vhd = vhd;
					lwsl_notice("%s: Spawned root monitor process successfully and assigned global_root_vhd=%p (fallback active)\n", __func__, global_root_vhd);

					/* Engage parent monitor to execute DHT publications off completed JWS child drops cleanly */
					vhd->proxy_uid = (uid_t)-1;
					vhd->proxy_gid = (gid_t)-1;
					const char *uid_opt = lws_cmdline_option_cx(vhd->context, "--uid");
					if (uid_opt && lws_plat_user_to_uid(uid_opt, &vhd->proxy_uid)) {
						lwsl_err("%s: unknown user %s\n", __func__, uid_opt);
					}
					const char *gid_opt = lws_cmdline_option_cx(vhd->context, "--gid");
					if (gid_opt && lws_plat_group_to_gid(gid_opt, &vhd->proxy_gid)) {
						lwsl_err("%s: unknown group %s\n", __func__, gid_opt);
					}

					generate_dist_pki(vhd);

					lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, parent_dnssec_monitor_timer_cb, 5 * LWS_US_PER_SEC);
				} else {
					/* Already globally spawned! Just map the auth context */
					lws_strncpy(vhd->auth_token, global_root_vhd->auth_token, sizeof(vhd->auth_token));
					vhd->auth_jwk.kty = LWS_GENCRYPTO_KTY_OCT;
					vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].len = 64;
					vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf = malloc(64);
					memcpy(vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf, global_root_vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf, 64);

					lws_system_blob_t *b = lws_system_get_blob(vhd->context, LWS_SYSBLOB_TYPE_EXT_AUTH1, 0);
					if (b) {
						lws_system_blob_direct_set(b, (uint8_t *)vhd->auth_token, strlen(vhd->auth_token));
					}

					vhd->root_process_active = 1;
					lwsl_notice("%s: Reusing globally spawned root monitor %p for vhost %s\n", __func__, global_root_vhd, lws_get_vhost_name(vhost));
				}
			} else {
				lwsl_err("%s: Cannot spawn argv[0] because it is NULL\n", __func__);
			}
		}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		/* Only tear down if this vhost natively owns the vhd */
		vhd = (struct vhd *)lws_protocol_vh_priv_get(vhost, protocol);
		if (!vhd)
			break;
		if (vhd->smd_peer) {
			lws_smd_unregister(vhd->smd_peer);
			vhd->smd_peer = NULL;
		}
		lws_jwk_destroy(&vhd->jwk);
		lws_sul_cancel(&vhd->sul_timer);
#if defined(LWS_WITH_DIR)
			if (vhd->dn) {
				lws_dir_notify_destroy(&vhd->dn);
			}
#endif
		if (vhd->lsp) {
			lws_spawn_piped_kill_child_process(vhd->lsp);
		}
		if (vhd->base_dir) {
			free(vhd->base_dir);
			vhd->base_dir = NULL;
		}

		if (global_root_vhd == vhd)
			global_root_vhd = NULL;
		break;

	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		if (vhd && vhd->root_process_active) {
			struct lws_jwt_auth *ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, NULL, NULL);
			if (!ja) {
				lwsl_notice("%s: No valid JWT found, bounced proxy UI connection\n", __func__);
				return -1;
			}
			int level = lws_jwt_auth_query_grant(ja, "domain-admin");
			lws_jwt_auth_destroy(&ja);
			if (level <= 0) {
				lwsl_notice("%s: JWT lacking 'domain-admin' grant, bounced proxy UI connection\n", __func__);
				return -1;
			}
		}
		break;

	case LWS_CALLBACK_ESTABLISHED:
		if (vhd && vhd->root_process_active) {
			/* We are the unprivileged proxy, and a UI WebSocket just connected.
			 * Establish onward Raw UDS connection */
			pss->magic = PSS_MAGIC;
			pss->wsi = wsi;
			pss->retry_count = 0;
			lws_dll2_add_tail(&pss->list, &vhd->ui_clients);
			if (vhd->ext_ips[0]) {
				pss->send_ext_ips = 1;
				lws_callback_on_writable(wsi);
			}
			connect_retry_cb(&pss->sul);
		}
		break;

	case LWS_CALLBACK_CLOSED:
		if (vhd && vhd->root_process_active) {
			lws_dll2_remove(&pss->list);
			lws_sul_cancel(&pss->sul);
			if (pss->cwsi) {
				lws_set_opaque_user_data(pss->cwsi, NULL);
				lws_wsi_close(pss->cwsi, LWS_TO_KILL_ASYNC);
				pss->cwsi = NULL;
			}
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		lwsl_debug("[INSTRUMENT] LWS_CALLBACK_RECEIVE: Browser UI triggered WS message (len: %d). Proxy cwsi=%p, root_process_active=%d\n", (int)len, pss->cwsi, vhd ? vhd->root_process_active : -1);
		if (vhd && vhd->root_process_active && pss->cwsi) {
			if (len > 65536) {
				lwsl_err("%s: WS UI request too large\n", __func__);
				return -1;
			}
			char jwt_buf[1024];
			size_t jwt_len = sizeof(jwt_buf);
			unsigned long long now = (unsigned long long)lws_now_secs();
			char claims[256];
			char temp[2048];
			char *first_brace;

			lws_snprintf(claims, sizeof(claims), "{\"iss\":\"acme-ipc\",\"aud\":\"dnssec-monitor\",\"iat\":%llu,\"nbf\":%llu,\"exp\":%llu}", now, now - 60, now + 60);

			if (!lws_jwt_sign_compact(vhd->context, &vhd->auth_jwk, "HS256", jwt_buf, &jwt_len, temp, sizeof(temp), "%s", claims)) {
				first_brace = memchr(in, '{', len);
				if (first_brace) {
					size_t offset = lws_ptr_diff_size_t(first_brace, in) + 1;
					size_t out_len = 0;
					size_t existing_len = pss->tx_len;

					if (existing_len + offset + 512 + (len - offset) + 1 >= 65536 - LWS_PRE) {
						lwsl_err("%s: WS UI request dropped, tx buffer full\n", __func__);
						return -1;
					}

					memcpy(&pss->tx[LWS_PRE + existing_len], in, offset);
					out_len += offset;

					int n = lws_snprintf((char *)&pss->tx[LWS_PRE + existing_len + out_len], 65536 - LWS_PRE - existing_len - out_len, "\"jwt\":\"%s\",", jwt_buf);
					out_len += (size_t)n;

					memcpy(&pss->tx[LWS_PRE + existing_len + out_len], first_brace + 1, len - offset);
					out_len += len - offset;
					pss->tx[LWS_PRE + existing_len + out_len] = '\n';
					out_len++;
					pss->tx_len += out_len;
					lws_callback_on_writable(pss->cwsi); /* Write proxy -> root */
					lwsl_debug("[INSTRUMENT] LWS_CALLBACK_RECEIVE: Enqueued proxy->root payload size %d with JWT (total: %d)\n", (int)out_len, (int)pss->tx_len);
				} else {
					goto fallback;
				}
			} else {
fallback:
				if (pss->tx_len + len + 1 < 65536 - LWS_PRE) {
					memcpy(&pss->tx[LWS_PRE + pss->tx_len], in, len);
					pss->tx_len += len;
					pss->tx[LWS_PRE + pss->tx_len] = '\n';
					pss->tx_len++;
					lws_callback_on_writable(pss->cwsi); /* Write proxy -> root */
					lwsl_debug("[INSTRUMENT] LWS_CALLBACK_RECEIVE: Enqueued proxy->root payload size %d (no JWT)\n", (int)len);
				}
			}
		} else {
			lwsl_notice("[INSTRUMENT] LWS_CALLBACK_RECEIVE: ABORTED! root_active=%d, pss->cwsi=%p\n", vhd?vhd->root_process_active:0, pss->cwsi);
		}
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (vhd && vhd->root_process_active) {
			if (pss->send_ext_ips) {
				pss->send_ext_ips = 0;
				uint8_t buf[LWS_PRE + 512];
				int n = lws_snprintf((char *)buf + LWS_PRE, 512, "{\"req\":\"extip_update\",\"data\":%s}\n", vhd->ext_ips);
				if (lws_write(wsi, buf + LWS_PRE, (size_t)n, LWS_WRITE_TEXT) < 0) {
					return -1;
				}
				if (pss->rx_len)
					lws_callback_on_writable(wsi);
				return 0;
			}
			if (pss->rx_len) {
				lwsl_debug("[INSTRUMENT] LWS_CALLBACK_SERVER_WRITEABLE: Translating %d bytes to final browser!\n", (int)pss->rx_len);
				int m = lws_write(wsi, &pss->rx[LWS_PRE], pss->rx_len, LWS_WRITE_TEXT);
				if (m < 0) {
					lwsl_err("%s: Failed writing to WS UI\n", __func__);
					return -1;
				}
				if (m < (int)pss->rx_len) {
					memmove(&pss->rx[LWS_PRE], &pss->rx[LWS_PRE + m], pss->rx_len - (size_t)m);
					pss->rx_len -= (size_t)m;
					lws_callback_on_writable(wsi);
				} else {
					pss->rx_len = 0;
				}
			}
		}
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		{
			uint32_t *magic = (uint32_t *)lws_get_opaque_user_data(wsi);
			if (magic && *magic == CERT_CHECK_MAGIC) {
				struct cert_check_info *cci = (struct cert_check_info *)magic;
				if (vhd) {
					struct cert_check_result *cr = malloc(sizeof(*cr));
					if (cr) {
						memset(cr, 0, sizeof(*cr));
						lws_strncpy(cr->fqdn, cci->fqdn, sizeof(cr->fqdn));
						char *colon = strchr(cr->fqdn, ':');
						if (colon) *colon = '\0';
						cr->port = cci->port;
						char *err_str = in ? (char *)in : "Connection failed";
						lws_snprintf(cr->msg, sizeof(cr->msg), "Error: %s", err_str);
						for (int i = 0; cr->msg[i]; i++) {
							if (cr->msg[i] == '\n' || cr->msg[i] == '\r') cr->msg[i] = ' ';
							if (cr->msg[i] == '"') cr->msg[i] = '\'';
							if (cr->msg[i] == '\\') cr->msg[i] = '/';
						}
						cr->status_err = 1;

						char json[1024];
						int n = lws_snprintf(json, sizeof(json), "{\"req\":\"cert_status\",\"subdomain\":\"%s\",\"port\":%d,\"status\":\"error\",\"msg\":\"%s\",\"local_msg\":\"%s\",\"issuer\":\"%s\"}\n",
							cr->fqdn, cr->port, cr->msg, cr->local_msg, cr->issuer);

						struct vhd *target_vhd = global_root_vhd ? global_root_vhd : vhd;
						lws_start_foreach_dll(struct lws_dll2 *, p, target_vhd->clients.head) {
							struct pss *wpss = lws_container_of(p, struct pss, list);
							if (wpss->tx_len + (size_t)n < 65536 - LWS_PRE) {
								memcpy(&wpss->tx[LWS_PRE + wpss->tx_len], json, (size_t)n);
								wpss->tx_len += (size_t)n;
								lws_callback_on_writable(wpss->wsi);
							}
						} lws_end_foreach_dll(p);
						free(cr);
					}
				}
				cci->magic = 0;
				free(cci);
				lws_set_opaque_user_data(wsi, NULL);
			} else if (magic && *magic == PSS_MAGIC) {
				struct pss *wpss = (struct pss *)magic;
				wpss->cwsi = NULL;
			}
		}
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		{
			struct acme_profiles_fetch_info *afi = (struct acme_profiles_fetch_info *)lws_get_opaque_user_data(wsi);
			if (afi && afi->magic == ACME_PROFILES_MAGIC) {
				lwsl_notice("%s: Connected to ACME directory\n", __func__);
			}
		}
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		{
			struct acme_profiles_fetch_info *afi = (struct acme_profiles_fetch_info *)lws_get_opaque_user_data(wsi);
			if (afi && afi->magic == ACME_PROFILES_MAGIC) {
				char buffer[2048 + LWS_PRE];
				char *px = buffer + LWS_PRE;
				int lenx = sizeof(buffer) - LWS_PRE;

				if (lws_http_client_read(wsi, &px, &lenx) < 0)
					return -1;
			}
		}
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		{
			struct acme_profiles_fetch_info *afi = (struct acme_profiles_fetch_info *)lws_get_opaque_user_data(wsi);
			if (afi && afi->magic == ACME_PROFILES_MAGIC) {
				lwsl_notice("%s: Received %zu bytes for ACME directory\n", __func__, len);

				if (!afi->json) {
					afi->json_alloc = 8192;
					afi->json = malloc(afi->json_alloc);
				}
				if (afi->json) {
					if (afi->json_len + len >= afi->json_alloc) {
						afi->json_alloc *= 2;
						char *nb = realloc(afi->json, afi->json_alloc);
						if (nb) afi->json = nb;
					}
					if (afi->json_len + len < afi->json_alloc) {
						memcpy(&afi->json[afi->json_len], in, len);
						afi->json_len += len;
						afi->json[afi->json_len] = '\0';
					} else {
						lwsl_err("%s: ACME directory JSON too large!\n", __func__);
					}
				}
			}
		}
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		{
			struct acme_profiles_fetch_info *afi = (struct acme_profiles_fetch_info *)lws_get_opaque_user_data(wsi);
			if (afi && afi->magic == ACME_PROFILES_MAGIC) {
				lwsl_notice("%s: Completed ACME directory fetch (%zu bytes)\n", __func__, afi->json_len);

				struct vhd *target_vhd = global_root_vhd ? global_root_vhd : vhd;
				int found = 0;
				lws_start_foreach_dll(struct lws_dll2 *, p, target_vhd->clients.head) {
					if (lws_container_of(p, struct pss, list) == afi->root_pss) found = 1;
				} lws_end_foreach_dll(p);
				lws_start_foreach_dll(struct lws_dll2 *, p, target_vhd->ui_clients.head) {
					if (lws_container_of(p, struct pss, list) == afi->root_pss) found = 1;
				} lws_end_foreach_dll(p);

				if (found) {
					struct pss *wpss = afi->root_pss;
					size_t existing_len = wpss->tx_len;
					if (existing_len + afi->json_len + 128 < 65536 - LWS_PRE) {
						int n = lws_snprintf((char *)&wpss->tx[LWS_PRE + existing_len], 65536 - LWS_PRE - existing_len,
							"{\"req\":\"get_acme_profiles\",\"status\":\"ok\",\"profiles\":");
						existing_len += (size_t)n;

						char *profiles_start = afi->json ? strstr(afi->json, "\"profiles\"") : NULL;
						if (profiles_start) {
							profiles_start += 10;
							while (*profiles_start && (*profiles_start == ' ' || *profiles_start == ':')) profiles_start++;
							char *profiles_end = profiles_start;
							int braces = 0;
							while (*profiles_end) {
								if (*profiles_end == '{') braces++;
								else if (*profiles_end == '}') {
									braces--;
									if (braces == 0) { profiles_end++; break; }
								}
								profiles_end++;
							}
							if (braces == 0 && profiles_end > profiles_start) {
								size_t plen = lws_ptr_diff_size_t(profiles_end, profiles_start);
								memcpy(&wpss->tx[LWS_PRE + existing_len], profiles_start, plen);
								existing_len += plen;
							} else {
								int k = lws_snprintf((char *)&wpss->tx[LWS_PRE + existing_len], 65536 - LWS_PRE - existing_len, "{}");
								existing_len += (size_t)k;
							}
						} else {
							int k = lws_snprintf((char *)&wpss->tx[LWS_PRE + existing_len], 65536 - LWS_PRE - existing_len, "{}");
							existing_len += (size_t)k;
						}

						int k = lws_snprintf((char *)&wpss->tx[LWS_PRE + existing_len], 65536 - LWS_PRE - existing_len, "}\n");
						wpss->tx_len = existing_len + (size_t)k;
						if (wpss->cwsi) lws_callback_on_writable(wpss->cwsi);
						if (wpss->wsi) lws_callback_on_writable(wpss->wsi);
					}
				}

				afi->magic = 0;
				if (afi->json) free(afi->json);
				free(afi);
				lws_set_opaque_user_data(wsi, NULL);
			}
		}
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		{
			struct acme_profiles_fetch_info *afi = (struct acme_profiles_fetch_info *)lws_get_opaque_user_data(wsi);
			if (afi && afi->magic == ACME_PROFILES_MAGIC) {
				lwsl_err("%s: ACME directory HTTP client connection closed before completion\n", __func__);
				afi->magic = 0;
				if (afi->json) free(afi->json);
				free(afi);
				lws_set_opaque_user_data(wsi, NULL);
			}
		}
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		{
			uint32_t *magic = (uint32_t *)lws_get_opaque_user_data(wsi);
			if (magic && *magic == CERT_CHECK_MAGIC) {
				struct cert_check_info *cci = (struct cert_check_info *)magic;
				if (vhd) {
					lwsl_notice("[INSTRUMENT] Probe %s RAW_CONNECTED successfully!\n", cci->fqdn);
					if (cci->starttls_state == 0 || cci->starttls_state == 4) {
						extract_and_queue_cert_result(wsi, vhd, cci, protocol);
						cci->magic = 0; free(cci); lws_set_opaque_user_data(wsi, NULL);
						return -1;
					}
				}
				/* Drop STARTTLS probe rx */
				return 0;
			}
		}
		break;

	case LWS_CALLBACK_RAW_ADOPT:
		{
			uint32_t *magic = (uint32_t *)lws_get_opaque_user_data(wsi);
			if (magic && *magic == PSS_MAGIC) {
				struct pss *wpss = (struct pss *)magic;
				lwsl_notice("%s: UDS proxy client connection established\n", __func__);
				wpss->cwsi = wsi;
			} else if (!magic) {
				lwsl_notice("%s: UDS connection established to server\n", __func__);
				if (vhd && vhd->root_process_active) {
					struct pss *root_pss = (struct pss *)user;
					root_pss->wsi = wsi;
					lws_dll2_add_head(&root_pss->list, &vhd->clients);
				}
			}
		}
		break;

	case LWS_CALLBACK_RAW_RX:
		{
			void *opaque = lws_get_opaque_user_data(wsi);
			struct cert_check_info *cci = (struct cert_check_info *)opaque;
			if (cci && cci->magic == CERT_CHECK_MAGIC) {
				if (cci->starttls_state == 4 && lws_is_ssl(wsi)) {
					if (vhd) extract_and_queue_cert_result(wsi, vhd, cci, protocol);
					cci->magic = 0; free(cci); lws_set_opaque_user_data(wsi, NULL); return -1;
				}
				if (cci->starttls_state == 1 && !strncmp((const char *)in, "220", 3)) {
					cci->starttls_state = 2; lws_callback_on_writable(wsi); return 0;
				}
				if (cci->starttls_state == 2 && !strncmp((const char *)in, "250", 3)) {
					int found_250_space = 0;
					for (size_t k = 0; k < len; k++) {
						if ((k == 0 || ((const char *)in)[k-1] == '\n') && len - k >= 4 && !strncmp((const char *)in + k, "250 ", 4)) {
							found_250_space = 1; break;
						}
					}
					if (found_250_space) { cci->starttls_state = 3; lws_callback_on_writable(wsi); }
					return 0;
				}
				if (cci->starttls_state == 3 && !strncmp((const char *)in, "220", 3)) {
					cci->starttls_state = 4;
					if (lws_tls_client_upgrade(wsi, LCCSCF_USE_SSL | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK | LCCSCF_ALLOW_SELFSIGNED | LCCSCF_ALLOW_EXPIRED) < 0) return -1;
					lws_callback_on_writable(wsi); return 0;
				}
				return 0;
			}
			uint32_t *magic = (uint32_t *)lws_get_opaque_user_data(wsi);
			lwsl_debug("[INSTRUMENT] LWS_CALLBACK_RAW_RX: UDS channel receiving %d bytes. Is Proxy? %d\n", (int)len, magic && *magic == PSS_MAGIC);

			if (magic && *magic == CERT_CHECK_MAGIC) {
				/* Drop STARTTLS probe rx */
				return 0;
			} else if (magic && *magic == PSS_MAGIC) {
				struct pss *wpss = (struct pss *)magic;
				/* 1: Proxy Unprivileged Client: root server just replied. */
				if (wpss->rx_len + len > 65536 - LWS_PRE) return -1;
				memcpy(&wpss->rx[LWS_PRE + wpss->rx_len], in, len);
				wpss->rx_len += len;
				lws_callback_on_writable(wpss->wsi); /* trigger WS write */
				lwsl_notice("[INSTRUMENT] LWS_CALLBACK_RAW_RX (PROXY): Appended response length %d and queued browser wsi ptr %p for writing\n", (int)len, wpss->wsi);
			} else {
				struct lws_vhost *vh = lws_get_vhost(wsi);
				if (!vh || strcmp(lws_get_vhost_name(vh), "dnssec_monitor_uds") != 0) {
					/* Drop anything not explicitly accepted on the UDS channel (e.g. child stream WSIs from probes) */
					return 0;
				}

				/* 2: Root Server: UI proxy just gave us a request. */
				if (vhd->rx_len + len > 65536 - 1) return -1;
				memcpy(&vhd->rx[LWS_PRE + vhd->rx_len], in, len);
				vhd->rx_len += len;
				vhd->rx[LWS_PRE + vhd->rx_len] = '\0';

				struct pss *root_pss = (struct pss *)user;
				/* root_pss->tx_len = 0; REMOVED to prevent overwriting batched responses */

				lwsl_debug("[INSTRUMENT] LWS_CALLBACK_RAW_RX (ROOT): Processing %d bytes buffer\n", (int)vhd->rx_len);

				char *p = (char *)&vhd->rx[LWS_PRE];
				char *start = p;
				while (p && *p) {
					char *nl = strchr(p, '\n');
					if (nl) {
						*nl = '\0';
						if (*p) {
							handle_monitor_request(vhd, root_pss, p, strlen(p));
						}
						p = nl + 1;
						start = p;
					} else {
						break;
					}
				}

				if (start > (char *)&vhd->rx[LWS_PRE]) {
					size_t unparsed = lws_ptr_diff_size_t((char *)&vhd->rx[LWS_PRE + vhd->rx_len], start);
					if (unparsed > 0) {
						memmove(&vhd->rx[LWS_PRE], start, unparsed);
					}
					vhd->rx_len = unparsed;
					vhd->rx[LWS_PRE + vhd->rx_len] = '\0';
				}

				if (root_pss->tx_len) {
					/* Tell server socket to reply */
					lws_callback_on_writable(wsi);
				}
			}
		}
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		{
			void *opaque = lws_get_opaque_user_data(wsi);
			struct cert_check_info *cci = (struct cert_check_info *)opaque;
			if (cci && cci->magic == CERT_CHECK_MAGIC) {
				if (cci->starttls_state == 4) {
					if (vhd) extract_and_queue_cert_result(wsi, vhd, cci, protocol);
					cci->magic = 0; free(cci); lws_set_opaque_user_data(wsi, NULL); return -1;
				}
				char buf[256]; int n = 0;
				if (cci->starttls_state == 2) n = lws_snprintf(buf, sizeof(buf), "EHLO %s\r\n", cci->fqdn);
				else if (cci->starttls_state == 3) n = lws_snprintf(buf, sizeof(buf), "STARTTLS\r\n");
				if (n > 0 && lws_write(wsi, (unsigned char *)buf, (size_t)n, LWS_WRITE_RAW) < 0) return -1;
				return 0;
			}
			uint32_t *magic = (uint32_t *)lws_get_opaque_user_data(wsi);
			if (magic && *magic == PSS_MAGIC) {
				struct pss *wpss = (struct pss *)magic;
				/* 1: Proxy Unprivileged Client: write queued UI data to Root Server */
				if (wpss->tx_len) {
					lwsl_notice("[INSTRUMENT] LWS_CALLBACK_RAW_WRITEABLE (PROXY): Driving %d bytes out over UDS IPC into Daemon\n", (int)wpss->tx_len);
					int m = lws_write(wsi, &wpss->tx[LWS_PRE], wpss->tx_len, LWS_WRITE_RAW);
					if (m < 0) return -1;
					if (m < (int)wpss->tx_len) {
						memmove(&wpss->tx[LWS_PRE], &wpss->tx[LWS_PRE + m], wpss->tx_len - (size_t)m);
						wpss->tx_len -= (size_t)m;
						lws_callback_on_writable(wsi);
					} else {
						wpss->tx_len = 0;
					}
				}
			} else {
				/* 2: Root Server sending response -> Proxy Client */
				struct pss *root_pss = (struct pss *)user;

				if (root_pss && root_pss->tx_len) {
					lwsl_notice("[INSTRUMENT] LWS_CALLBACK_RAW_WRITEABLE (ROOT): Dispatching %d byte JSON response natively to Proxy UDS caller\n", (int)root_pss->tx_len);
					int m = lws_write(wsi, &root_pss->tx[LWS_PRE], root_pss->tx_len, LWS_WRITE_RAW);
					if (m < 0) return -1;
					if (m < (int)root_pss->tx_len) {
						memmove(&root_pss->tx[LWS_PRE], &root_pss->tx[LWS_PRE + m], root_pss->tx_len - (size_t)m);
						root_pss->tx_len -= (size_t)m;
						lws_callback_on_writable(wsi);
					} else {
						root_pss->tx_len = 0;
					}
				}
			}
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		{
			uint32_t *magic = (uint32_t *)lws_get_opaque_user_data(wsi);
			if (magic && *magic == CERT_CHECK_MAGIC) {
				struct cert_check_info *cci = (struct cert_check_info *)magic;
				cci->magic = 0;
				free(cci);
				lws_set_opaque_user_data(wsi, NULL);
			} else if (magic && *magic == PSS_MAGIC) {
				struct pss *wpss = (struct pss *)magic;
				wpss->cwsi = NULL;
			} else if (!magic) {
				if (vhd && vhd->root_process_active) {
					struct pss *root_pss = (struct pss *)user;
					lws_dll2_remove(&root_pss->list);
				}
			}
			lwsl_notice("%s: UDS connection closed\n", __func__);
		}
		break;

	default:
		break;
	}

	return 0;
}

static int
callback_monitor_stdwsi(struct lws *wsi, enum lws_callback_reasons reason,
                    void *user, void *in, size_t len)
{
        uint8_t buf[2048];
        int ilen;

        switch (reason) {
        case LWS_CALLBACK_RAW_CLOSE_FILE:
                break;

        case LWS_CALLBACK_RAW_RX_FILE: {
                int _fd = (int)(intptr_t)lws_get_socket_fd(wsi);
                if (_fd < 0) return -1;
                ilen = (int)read(_fd, buf, sizeof(buf) - 1);
                if (ilen < 1) {
                        return -1;
                }
                buf[ilen] = '\0';

				char *b = (char *)buf;
				while (b && *b) {
					char *nl = strchr(b, '\n');
					if (nl) *nl++ = '\0';
					lwsl_notice("[PRIV-DAEMON] %s\n", b);
					b = nl;
				}
                return 0;
        }

        default:
                break;
        }

        return 0;
}

LWS_VISIBLE const struct lws_protocols lws_dht_dnssec_monitor_protocols[] = {
	{
		.name = "lws-dht-dnssec-stdwsi",
		.callback = callback_monitor_stdwsi,
	},
	{
		.name = "lws-dht-dnssec-monitor",
		.callback = callback_dht_dnssec_monitor,
		.per_session_data_size = sizeof(struct pss),
	},
};
LWS_VISIBLE const lws_plugin_protocol_t lws_dht_dnssec_monitor = {
	.hdr = {
		.name = "dht dnssec monitor",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC,
		.priority = 10 /* priority */
	},
	.protocols = lws_dht_dnssec_monitor_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_dht_dnssec_monitor_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
