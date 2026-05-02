/*
 * libwebsockets - protocol - dht_dnssec_monitor
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 */

#include "private.h"

int
scan_whois_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct vhd *vhd = (struct vhd *)user;
	if (lde->name[0] == '.') return 0;
	if (lde->type == LDOT_DIR || lde->type == LDOT_UNKNOWN) {
		char path[1024];
		lws_snprintf(path, sizeof(path), "%s/%s/whois.json", dirpath, lde->name);
		struct stat st;
		if (stat(path, &st) < 0 || (lws_now_secs() - (unsigned long long)st.st_mtime) > 86400 * 7)
			whois_trigger(vhd, lde->name);
	}
	return 0;
}

static void
rescan_debounce_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_debounce_scan);
	char scan_path[1024];

	lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);
	lwsl_notice("%s: Debounced rescan of %s starting\n", __func__, scan_path);

	lws_dir(scan_path, vhd, scan_dir_cb);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->ui_clients.head) {
		struct pss *pss = lws_container_of(d, struct pss, list);
		pss->send_ext_ips = 1; lws_callback_on_writable(pss->wsi);
	} lws_end_foreach_dll_safe(d, d1);
}

void
dir_notify_cb(const char *path, int is_file, void *user)
{
	struct vhd *vhd = (struct vhd *)user;

	lwsl_notice("%s: Directory change at %s (is_file: %d), scheduling debounced rescan\n", __func__, path, is_file);

	lws_sul_schedule(vhd->context, 0, &vhd->sul_debounce_scan, rescan_debounce_cb, 500 * LWS_US_PER_MS);
}

signed char
tls_config_cb(struct lejp_ctx *ctx, char reason)
{
	struct monitor_req_args *a = (struct monitor_req_args *)ctx->user;
	if (reason == LEJPCB_VAL_NUM_INT && ctx->path_match - 1 == LRP_PORT) a->port = atoi(ctx->buf);
	return 0;
}

int
scan_tls_configs_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct scan_tls_ctx *ctx = (struct scan_tls_ctx *)user;
	if (lde->name[0] == '.' || !strstr(lde->name, ".json")) return 0;
	char path[1024]; lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);
	int fd = open(path, O_RDONLY);
	if (fd >= 0) {
		char buf[4096]; ssize_t n = read(fd, buf, sizeof(buf) - 1);
		if (n > 0) {
			buf[n] = '\0';
			struct monitor_req_args a; memset(&a, 0, sizeof(a));
			struct lejp_ctx jctx;
			lejp_construct(&jctx, tls_config_cb, &a, tls_config_paths, LWS_ARRAY_SIZE(tls_config_paths));
			lejp_parse(&jctx, (uint8_t *)buf, (int)n);
			lejp_destruct(&jctx);
			if (a.port > 0) {
				char sub[256]; lws_strncpy(sub, lde->name, sizeof(sub));
				char *ext = strstr(sub, ".json"); if (ext) *ext = '\0';
				char vh_name[256]; lws_snprintf(vh_name, sizeof(vh_name), "acme_%s", sub);
				if (!lws_get_vhost_by_name(ctx->vhd->context, vh_name))
					acme_vhost_spawn(ctx->vhd, ctx->domain, sub, NULL);
			}
		}
		close(fd);
	}
	return 0;
}

int
scan_tls_domains_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct vhd *vhd = (struct vhd *)user;
	if (lde->name[0] == '.') return 0;
	if (lde->type == LDOT_DIR || lde->type == LDOT_UNKNOWN) {
		char tls_path[1024]; lws_snprintf(tls_path, sizeof(tls_path), "%s/%s/tls", dirpath, lde->name);
		struct scan_tls_ctx ctx = { vhd, lde->name };
		lws_dir(tls_path, &ctx, scan_tls_configs_cb);
	}
	return 0;
}

void
proxy_dnssec_scan_timer_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_timer_proxy_scan);
	char scan_path[1024]; lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);
	lws_dir(scan_path, vhd, scan_tls_domains_cb);
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timer_proxy_scan, proxy_dnssec_scan_timer_cb, 300 * LWS_US_PER_SEC);
}

int
scan_jws_publish_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct vhd *vhd = (struct vhd *)user;
	if (lde->name[0] == '.') return 0;
	if (lde->type == LDOT_DIR || lde->type == LDOT_UNKNOWN) {
		char wd[1024]; lws_snprintf(wd, sizeof(wd), "%s/%s", dirpath, lde->name);
		if (vhd->ops && vhd->ops->publish_jws) vhd->ops->publish_jws(vhd->vhost, wd);
	}
	return 0;
}

void
parent_dnssec_monitor_timer_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_timer);
	char scan_path[1024]; lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);
	lws_dir(scan_path, vhd, scan_jws_publish_cb);
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, parent_dnssec_monitor_timer_cb, 300 * LWS_US_PER_SEC);
}
