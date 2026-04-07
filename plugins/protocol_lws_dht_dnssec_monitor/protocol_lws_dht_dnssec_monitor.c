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

#if defined(WIN32) || defined(_WIN32)
#else
#include <sys/wait.h>
#endif

struct pss {
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
};

static struct vhd *global_root_vhd = NULL;

extern const struct lws_protocols lws_dht_dnssec_monitor_protocols[];



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
scan_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
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

		/* Directory format requires <base_dir>/domains/<common_name>/dns/ */
		char key_path[1024];

		/* Check ZSK */
		lws_snprintf(key_path, sizeof(key_path), "%s/domains/%s/dns/%s.zsk.private.jwk", vhd->base_dir, pc.common_name, pc.common_name);
		int has_zsk = (access(key_path, F_OK) == 0);

		/* Check KSK */
		lws_snprintf(key_path, sizeof(key_path), "%s/domains/%s/dns/%s.ksk.private.jwk", vhd->base_dir, pc.common_name, pc.common_name);
		int has_ksk = (access(key_path, F_OK) == 0);

		if (!has_zsk || !has_ksk) {
			lwsl_notice("%s: Missing keys for %s, automatically generating...\n", __func__, pc.common_name);
			char wd[512];
			lws_snprintf(wd, sizeof(wd), "%s/domains/%s/dns", vhd->base_dir, pc.common_name);

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
		char jws_path[1024];
		char zsk_path[1024];
		char ksk_path[1024];

		lws_snprintf(input_path, sizeof(input_path), "%s/domains/%s/dns/%s.zone", vhd->base_dir, pc.common_name, pc.common_name);
		lws_snprintf(output_path, sizeof(output_path), "%s/domains/%s/dns/%s.zone.signed", vhd->base_dir, pc.common_name, pc.common_name);
		lws_snprintf(jws_path, sizeof(jws_path), "%s/domains/%s/dns/%s.zone.signed.jws", vhd->base_dir, pc.common_name, pc.common_name);
		lws_snprintf(zsk_path, sizeof(zsk_path), "%s/domains/%s/dns/%s.zsk.private.jwk", vhd->base_dir, pc.common_name, pc.common_name);
		lws_snprintf(ksk_path, sizeof(ksk_path), "%s/domains/%s/dns/%s.ksk.private.jwk", vhd->base_dir, pc.common_name, pc.common_name);

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
				/* TODO: 75% lifetime exhaustion check, but requires parsing the signature. */
			}
		} else {
			lwsl_info("%s: Missing domain %s base zone config, skipping resign\n", __func__, input_path);
		}

		if (needs_resign) {
			char wd[512];
			lws_snprintf(wd, sizeof(wd), "%s/domains/%s/dns", vhd->base_dir, pc.common_name);

			lwsl_user("%s: Signing zone for %s\n", __func__, pc.common_name);
			struct lws_dht_dnssec_signzone_args sargs;
			memset(&sargs, 0, sizeof(sargs));
			sargs.domain = pc.common_name;
			sargs.workdir = wd;
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

#if defined(LWS_WITH_DIR)
static void
dir_notify_cb(const char *path, int is_file, void *user)
{
	struct vhd *vhd = (struct vhd *)user;
	char scan_path[1024];

	lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);

	lwsl_user("%s: Detected inotify filesystem change %s (file: %d), manually rescanning domains: %s\n", __func__, path, is_file, scan_path);

	lws_dir(scan_path, vhd, scan_dir_cb);
}
#endif

static int
parent_scan_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
/* commented to pause log spew */
#if 0
	struct vhd *vhd = (struct vhd *)user;
	if (lde->type != LDOT_DIR || lde->name[0] == '.') return 0;

	char jws_path[1024], pub_path[1024];
	lws_snprintf(jws_path, sizeof(jws_path), "%s/domains/%s/dns/%s.zone.signed.jws", vhd->base_dir, lde->name, lde->name);
	lws_snprintf(pub_path, sizeof(pub_path), "%s.published", jws_path);

	struct stat st_jws, st_pub;
	if (stat(jws_path, &st_jws) == 0) {
		int fd_pub = open(pub_path, O_RDWR);
		int needs_pub = 0;

		if (fd_pub < 0) {
			fd_pub = open(pub_path, O_CREAT | O_RDWR, 0666);
			needs_pub = 1;
		} else if (fstat(fd_pub, &st_pub) == 0) {
			if (st_jws.st_mtime > st_pub.st_mtime)
				needs_pub = 1;
		}

		if (needs_pub) {
			lwsl_notice("%s: Parent detected new JWS for %s! Triggering DHT publication loop.\n", __func__, lde->name);
			if (vhd->ops && vhd->ops->publish_jws) {
				vhd->ops->publish_jws(vhd->vhost, jws_path);
				if (fd_pub >= 0) {
					if (write(fd_pub, "\n", 1) < 0) {}
				}
			}
		}
		if (fd_pub >= 0) close(fd_pub);
	}
#endif
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
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, parent_dnssec_monitor_timer_cb, 5 * LWS_US_PER_SEC);
}

static void
dnssec_monitor_timer_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_timer);
	char scan_path[1024];

	// lwsl_notice("%s: Child timer fired!\n", __func__);

	lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);
	lws_dir(scan_path, vhd, scan_dir_cb);

	lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, dnssec_monitor_timer_cb, 5 * LWS_US_PER_SEC);
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
};

static signed char
monitor_req_cb(struct lejp_ctx *ctx, char reason)
{
	struct monitor_req_args *a = (struct monitor_req_args *)ctx->user;

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
		}
	}

	return 0;
}


#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static void
handle_req_status(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"status\",\"status\":\"ok\"}\n");
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_get_domains(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
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
				if (!first) tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), ",");
				tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\"%s\"", de->d_name);
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
	char *tx = (char *)&root_pss->tx[LWS_PRE];
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
	char *tx = (char *)&root_pss->tx[LWS_PRE];
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
	char *tx = (char *)&root_pss->tx[LWS_PRE];
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
handle_req_update_zone(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];

	if (!a->zone_buf) goto fail;

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/%s.zone", vhd->base_dir, a->domain, a->domain);
	int fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (fd >= 0) {
		if (write(fd, a->zone_buf, (size_t)a->zone_len) == (ssize_t)a->zone_len) {
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
handle_req_get_tls(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];
	DIR *d;
	struct dirent *de;

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/conf.d", vhd->base_dir, a->domain);
	d = opendir(d_path);
	if (!d) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\",\"tls\":[]}\n", a->req);
	} else {
		int first = 1;
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\",\"tls\":[", a->req);
		while ((de = readdir(d))) {
			if (de->d_name[0] == '.') continue;
			if (strstr(de->d_name, ".json") && strncmp(de->d_name, a->domain, strlen(a->domain))) {
				if (!first) tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), ",");
				tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "\"%s\"", de->d_name);
				first = 0;
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
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];
	char p1[1024];
	char buf[2048];
	int n, fd;

	lws_snprintf(p1, sizeof(p1), "%s/domains/%s", vhd->base_dir, a->domain);
	if (mkdir(p1, 0700) < 0 && errno != EEXIST)
		lwsl_notice("%s: Failed to create domain dir\n", __func__);

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/conf.d", vhd->base_dir, a->domain);
	if (mkdir(d_path, 0700) < 0 && errno != EEXIST)
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
	char *tx = (char *)&root_pss->tx[LWS_PRE];
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
	char *tx = (char *)&root_pss->tx[LWS_PRE];
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

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/%s/%s", vhd->base_dir, a->domain, dir_suffix, a->subdomain);

	int fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (fd >= 0) {
		if (write(fd, a->zone_buf, (size_t)a->zone_len) == (ssize_t)a->zone_len) {
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);
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
	handle_req_save_acme_file(vhd, root_pss, a, "certs/crt");
}

static void
handle_req_save_key(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	handle_req_save_acme_file(vhd, root_pss, a, "certs/key");
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
	{ "create_tls", handle_req_create_tls },
	{ "delete_tls", handle_req_delete_tls },
	{ "save_auth_key", handle_req_save_auth_key },
	{ "save_cert", handle_req_save_cert },
	{ "save_key", handle_req_save_key }
};

static void
handle_monitor_request(struct vhd *vhd, struct pss *root_pss, const char *in, size_t len)
{
	struct monitor_req_args a;
	struct lejp_ctx jctx;
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	const size_t req_map_size = LWS_ARRAY_SIZE(req_map);

	memset(&a, 0, sizeof(a));
	lejp_construct(&jctx, monitor_req_cb, &a, monitor_req_paths, LWS_ARRAY_SIZE(monitor_req_paths));
	int m = lejp_parse(&jctx, (uint8_t *)in, (int)len);
	lejp_destruct(&jctx);

	// lwsl_debug("[INSTRUMENT] handle_monitor_request: executed lejp_parse. len: %d, rc: %d. String: '%.*s'\n", (int)len, m, (int)len, in);

	if (m < 0 && m != LEJP_REJECT_UNKNOWN) {
		lwsl_notice("[INSTRUMENT] handle_monitor_request: JSON parser failed! Error %d\n", m);
		root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"JSON parse failed: %d\"}\n", a.req[0] ? a.req : "unknown", m);
		goto done;
	}

	if (!a.req[0]) {
		lwsl_notice("[INSTRUMENT] handle_monitor_request: Missing 'req' parameter in JSON payload!\n");
		root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"status\":\"error\",\"msg\":\"Missing req\"}\n");
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
			root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"status\":\"error\",\"msg\":\"Authentication Failed\"}\n");
			goto done;
		}

		if (lws_jwt_signed_validate(vhd->context, &vhd->auth_jwk, "HS256", a.jwt, strlen(a.jwt), jwt_temp, sizeof(jwt_temp), jwt_out, &jwt_out_len)) {
			lwsl_notice("[INSTRUMENT] Invalid/Forged JWT preamble token\n");
			root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"status\":\"error\",\"msg\":\"Authentication Failed\"}\n");
			goto done;
		}

		if (lws_jwt_token_sanity(jwt_out, jwt_out_len, "acme-ipc", "dnssec-monitor", NULL, NULL, 0, &exp_time)) {
			lwsl_notice("[INSTRUMENT] Expired/Invalid JWT claims\n");
			root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"status\":\"error\",\"msg\":\"Authentication Failed\"}\n");
			goto done;
		}
	} else {
		lwsl_notice("[INSTRUMENT] Warning: UDS monitor secret not bootstrapped, rejecting request!\n");
		root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"status\":\"error\",\"msg\":\"Authentication Failed\"}\n");
		goto done;
	}

	/* Prevent path traversal attacks */
	if (strchr(a.domain, '/') || strstr(a.domain, "..") || strchr(a.subdomain, '/') || strstr(a.subdomain, "..")) {
		lwsl_debug("[INSTRUMENT] handle_monitor_request: Path traversal parameters detected\n");
		root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Invalid chars in domain\"}\n", a.req);
		goto done;
	}

	for (size_t i = 0; i < req_map_size; i++) {
		if (!strcmp(a.req, req_map[i].name)) {
			/* Enforce domain param if required by the handler */
			if (i > 0 && !a.domain[0] && strcmp(req_map[i].name, "status") && strcmp(req_map[i].name, "get_domains")) {
				lwsl_notice("[INSTRUMENT] handle_monitor_request: Missing required 'domain' param for %s\n", a.req);
				root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Missing arguments\"}\n", a.req);
				goto done;
			}
			lwsl_debug("[INSTRUMENT] handle_monitor_request: Calling map callback...\n");
			req_map[i].cb(vhd, root_pss, &a);
			lwsl_debug("[INSTRUMENT] handle_monitor_request: Callback generated response size %d\n", (int)root_pss->tx_len);
			goto done;
		}
	}

	lwsl_notice("[INSTRUMENT] handle_monitor_request: Unknown request parameter '%s'\n", a.req);
	root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"req\":\"unknown\",\"status\":\"error\",\"msg\":\"Unknown req %s\"}\n", a.req);

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
		lwsl_notice("dnssec_monitor: PROTOCOL_INIT called! (in=%p)\n", in);
		{
			struct lws_context *cx = lws_get_context(wsi);
			const char *p = lws_cmdline_option_cx(cx, "--lws-dht-dnssec-monitor-root");

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
							lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, dnssec_monitor_timer_cb, 1 * LWS_US_PER_SEC);
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

			/* Do not spawn root monitor if no pvos restrict it */
			if (!in)
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

			lwsl_notice("%s: initialized monitor proxy (base-dir: %s, uds-path: %s)\n", __func__, vhd->base_dir, vhd->uds_path);

			/* Spawn the root monitor process */
			struct lws_spawn_piped_info spawn_info;
			memset(&spawn_info, 0, sizeof(spawn_info));

			const char *exec_array[15];
			char arg_uds[1024];
			char arg_uid[128];
			char arg_gid[128];
			int n = 0;
			/* Rely on the original host application executable context path instead of
			 * guessing paths. `argv[0]` guarantees relative/absolute execution fidelity. */
#if defined(__linux__)
			char plat_exe_buf[256];
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
			if (uid) {
				lws_snprintf(arg_uid, sizeof(arg_uid), "--uid=%s", uid);
				exec_array[n++] = arg_uid;
			}
			if (gid) {
				lws_snprintf(arg_gid, sizeof(arg_gid), "--gid=%s", gid);
				exec_array[n++] = arg_gid;
			}

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
					lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, parent_dnssec_monitor_timer_cb, 1 * LWS_US_PER_SEC);
				} else {
					/* Already globally spawned! Just map the auth context */
					lws_strncpy(vhd->auth_token, global_root_vhd->auth_token, sizeof(vhd->auth_token));
					vhd->auth_jwk.kty = LWS_GENCRYPTO_KTY_OCT;
					vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].len = 64;
					vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf = malloc(64);
					memcpy(vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf, global_root_vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf, 64);

					vhd->root_process_active = 1;
					lwsl_notice("%s: Reusing globally spawned root monitor %p for vhost %s\n", __func__, global_root_vhd, lws_get_vhost_name(vhost));
				}
			} else {
				lwsl_err("%s: Cannot spawn argv[0] because it is NULL\n", __func__);
			}
		}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd)
			break;
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
			pss->wsi = wsi;
			pss->retry_count = 0;
			connect_retry_cb(&pss->sul);
		}
		break;

	case LWS_CALLBACK_CLOSED:
		if (vhd && vhd->root_process_active) {
			lws_sul_cancel(&pss->sul);
			if (pss->cwsi) {
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

					memcpy(&pss->tx[LWS_PRE], in, offset);
					out_len += offset;

					int n = lws_snprintf((char *)&pss->tx[LWS_PRE + out_len], 65536 - LWS_PRE - out_len, "\"jwt\":\"%s\",", jwt_buf);
					out_len += (size_t)n;

					if (len - offset < 65536 - LWS_PRE - out_len) {
						memcpy(&pss->tx[LWS_PRE + out_len], first_brace + 1, len - offset);
						out_len += len - offset;
						pss->tx_len = out_len;
						lws_callback_on_writable(pss->cwsi); /* Write proxy -> root */
						lwsl_debug("[INSTRUMENT] LWS_CALLBACK_RECEIVE: Enqueued proxy->root payload size %d with JWT\n", (int)out_len);
					}
				} else {
					goto fallback;
				}
			} else {
fallback:
				memcpy(&pss->tx[LWS_PRE], in, len);
				pss->tx_len = len;
				lws_callback_on_writable(pss->cwsi); /* Write proxy -> root */
				lwsl_debug("[INSTRUMENT] LWS_CALLBACK_RECEIVE: Enqueued proxy->root payload size %d (no JWT)\n", (int)len);
			}
		} else {
			lwsl_notice("[INSTRUMENT] LWS_CALLBACK_RECEIVE: ABORTED! root_active=%d, pss->cwsi=%p\n", vhd?vhd->root_process_active:0, pss->cwsi);
		}
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (vhd && vhd->root_process_active && pss->rx_len) {
			lwsl_debug("[INSTRUMENT] LWS_CALLBACK_SERVER_WRITEABLE: Translating %d bytes to final browser!\n", (int)pss->rx_len);
			if (lws_write(wsi, &pss->rx[LWS_PRE], pss->rx_len, LWS_WRITE_TEXT) < 0) {
				lwsl_err("%s: Failed writing to WS UI\n", __func__);
				return -1;
			}
			pss->rx_len = 0;
		}
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		{
			struct pss *wpss = (struct pss *)lws_get_opaque_user_data(wsi);
			if (wpss) {
				wpss->cwsi = NULL;
			}
		}
		break;

	case LWS_CALLBACK_RAW_ADOPT:
		{
			struct pss *wpss = (struct pss *)lws_get_opaque_user_data(wsi);
			if (wpss) {
				lwsl_notice("%s: UDS proxy client connection established\n", __func__);
				wpss->cwsi = wsi;
			} else {
				lwsl_notice("%s: UDS connection established to server\n", __func__);
			}
		}
		break;

	case LWS_CALLBACK_RAW_RX:
		{
			struct pss *wpss = (struct pss *)lws_get_opaque_user_data(wsi);
			lwsl_debug("[INSTRUMENT] LWS_CALLBACK_RAW_RX: UDS channel receiving %d bytes. Is Proxy? %d\n", (int)len, wpss != NULL);

			if (wpss) {
				/* 1: Proxy Unprivileged Client: root server just replied. */
				if (len > 65536) return -1;
				memcpy(&wpss->rx[LWS_PRE], in, len);
				wpss->rx_len = len;
				lws_callback_on_writable(wpss->wsi); /* trigger WS write */
				lwsl_notice("[INSTRUMENT] LWS_CALLBACK_RAW_RX (PROXY): Saved response length %d and queued browser wsi ptr %p for writing\n", (int)len, wpss->wsi);
			} else {
				/* 2: Root Server: UI proxy just gave us a request. */
				if (len > 65536 - 1) return -1;
				memcpy(&vhd->rx[LWS_PRE], in, len);
				vhd->rx[LWS_PRE + len] = '\0';
				vhd->rx_len = len;

				struct pss *root_pss = (struct pss *)user;
				lwsl_debug("[INSTRUMENT] LWS_CALLBACK_RAW_RX (ROOT): Sending %d bytes to monitor request router\n", (int)len);
				handle_monitor_request(vhd, root_pss, (const char *)&vhd->rx[LWS_PRE], len);

				/* Tell server socket to reply */
				lws_callback_on_writable(wsi);
			}
		}
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		{
			struct pss *wpss = (struct pss *)lws_get_opaque_user_data(wsi);

			if (wpss) {
				/* 1: Proxy Client sending request -> Root Server */
				if (wpss->tx_len) {
					lwsl_notice("[INSTRUMENT] LWS_CALLBACK_RAW_WRITEABLE (PROXY): Driving %d bytes out over UDS IPC into Daemon\n", (int)wpss->tx_len);
					if (lws_write(wsi, &wpss->tx[LWS_PRE], wpss->tx_len, LWS_WRITE_RAW) < 0) return -1;
					wpss->tx_len = 0;
				}
			} else {
				/* 2: Root Server sending response -> Proxy Client */
				struct pss *root_pss = (struct pss *)user;
				if (root_pss && root_pss->tx_len) {
					lwsl_notice("[INSTRUMENT] LWS_CALLBACK_RAW_WRITEABLE (ROOT): Dispatching %d byte JSON response natively to Proxy UDS caller\n", (int)root_pss->tx_len);
					if (lws_write(wsi, &root_pss->tx[LWS_PRE], root_pss->tx_len, LWS_WRITE_RAW) < 0) return -1;
					root_pss->tx_len = 0;
				}
			}
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		{
			struct pss *wpss = (struct pss *)lws_get_opaque_user_data(wsi);
			if (wpss) wpss->cwsi = NULL;
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
					lwsl_notice("[ROOT-DAEMON] %s\n", b);
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
