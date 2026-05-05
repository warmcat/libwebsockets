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
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>

struct vhd *global_root_vhd = NULL;

extern const struct lws_protocols lws_dht_dnssec_monitor_protocols[];

#if defined(LWS_WITH_SYS_SMD)
static int
smd_cb_network(void *opaque, lws_smd_class_t c, lws_usec_t ts, void *buf, size_t len)
{
	struct vhd *vhd = (struct vhd *)opaque;

	// if (c & LWSSMDCL_NETWORK) {
	//	lwsl_notice("EXTIP_DEBUG: smd_cb_network received network event: %.*s\n", (int)len, (const char *)buf);
	// }
	if ((c & LWSSMDCL_NETWORK) && buf && strstr((const char *)buf, "\"ext-ips\"")) {
		lwsl_notice("EXTIP_DEBUG: Updating vhd->ext_ips\n");
		lws_strncpy(vhd->ext_ips, (const char *)buf, sizeof(vhd->ext_ips));

		if (vhd->root_process_active) {
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->ui_clients.head) {
				struct pss *pss = lws_container_of(d, struct pss, list);
				pss->send_ext_ips = 1;
				if (pss->wsi) lws_callback_on_writable(pss->wsi);
			} lws_end_foreach_dll_safe(d, d1);
		} else {
			/* In Root Daemon: Broadcast the IP to all connected proxy UDS clients */
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->ui_clients.head) {
				struct pss *root_pss = lws_container_of(d, struct pss, list);
				size_t current_len = root_pss->tx_len;
				int n = lws_snprintf((char *)&root_pss->tx[LWS_PRE + current_len], 65536 - LWS_PRE - current_len,
					"{\"req\":\"extip_update\",\"data\":%s}\n", vhd->ext_ips);
				if (n > 0) root_pss->tx_len += (size_t)n;
				if (root_pss->wsi) lws_callback_on_writable(root_pss->wsi);
			} lws_end_foreach_dll_safe(d, d1);
		}
	}
	return 0;
}
#endif

static void
lws_dht_dnssec_monitor_reap_cb(void *opaque, const struct lws_spawn_resource_us *res,
			       siginfo_t *si, int we_killed_him)
{
	struct vhd *vhd = (struct vhd *)opaque;
	lwsl_notice("%s: Spawned root monitor process terminated (killed: %d)\n", __func__, we_killed_him);
	vhd->root_process_active = 0;
	vhd->lsp = NULL;
}

static void
connect_retry_cb(lws_sorted_usec_list_t *sul)
{
	struct pss *pss = lws_container_of(sul, struct pss, sul);
	struct vhd *vhd = (struct vhd *)lws_protocol_vh_priv_get(lws_get_vhost(pss->wsi), lws_get_protocol(pss->wsi));
	if (!vhd && global_root_vhd) vhd = global_root_vhd;

	if (!vhd || !vhd->root_process_active) {
		lwsl_notice("[DEBUG] %s: aborting, vhd=%p, root_process_active=%d\n", __func__, vhd, vhd ? vhd->root_process_active : 0);
		return;
	}

	struct lws_client_connect_info i;
	char uds_path[1024];

	memset(&i, 0, sizeof(i));
	i.method = "RAW"; i.context = vhd->context; i.vhost = lws_get_vhost(pss->wsi);
	lws_snprintf(uds_path, sizeof(uds_path), "+%s", vhd->uds_path);
	i.address = uds_path; i.port = 0; i.host = "localhost"; i.origin = "localhost";
	i.local_protocol_name = "lws-dht-dnssec-monitor";
	i.opaque_user_data = pss; i.pwsi = &pss->cwsi;

	lwsl_notice("[DEBUG] %s: attempting lws_client_connect_via_info to %s (retry %d)\n", __func__, uds_path, pss->retry_count);
	lwsl_notice("[DEBUG] %s: Running as uid=%d, gid=%d\n", __func__, getuid(), getgid());

	if (!lws_client_connect_via_info(&i)) {
		pss->cwsi = NULL;
		lwsl_notice("[DEBUG] %s: lws_client_connect_via_info returned NULL\n", __func__);
		if (++pss->retry_count < 20)
			lws_sul_schedule(vhd->context, 0, &pss->sul, connect_retry_cb, 250 * LWS_US_PER_MS);
		else {
			lwsl_notice("[DEBUG] %s: retries exhausted, closing wsi\n", __func__);
			lws_wsi_close(pss->wsi, LWS_TO_KILL_ASYNC);
		}
	} else {
		lwsl_notice("[DEBUG] %s: lws_client_connect_via_info succeeded\n", __func__);
	}
}

static int
monitor_init_root_daemon(struct vhd *vhd, const struct lws_protocol_vhost_options *in, const char *uid, const char *gid)
{
	const struct lws_protocol_vhost_options *pvo1;
	lwsl_notice("[ROOT-DAEMON] init: Entering dnssec-priv root daemon mode\n");

	if (global_root_vhd) {
		vhd->root_daemon = 1;
		vhd->root_process_active = 1;
		lws_strncpy(vhd->auth_token, global_root_vhd->auth_token, sizeof(vhd->auth_token));
		return 0;
	}
	lwsl_user("[ROOT-DAEMON] init: Waiting for symmetric token on stdin\n");
	vhd->root_daemon = 1;
	global_root_vhd = vhd;

	if (vhd->uds_path) {
		struct lws_context_creation_info info;
		memset(&info, 0, sizeof(info));
		info.vhost_name = "root-monitor-uds";
		info.iface = vhd->uds_path;
		info.port = 0;
		info.protocols = lws_dht_dnssec_monitor_protocols;
		info.options = LWS_SERVER_OPTION_UNIX_SOCK | LWS_SERVER_OPTION_ONLY_RAW;

		lwsl_notice("[ROOT-DAEMON] init: Cleaning stale socket at %s\n", vhd->uds_path);
		unlink(vhd->uds_path);

		lwsl_notice("[ROOT-DAEMON] init: Creating Root UDS vhost at %s\n", vhd->uds_path);
		if (!lws_create_vhost(vhd->context, &info)) {
			lwsl_err("[ROOT-DAEMON] init: Failed to create Root UDS vhost at %s\n", vhd->uds_path);
			global_root_vhd = NULL;
			return -1;
		}

		uid_t u = (uid_t)-1; gid_t g = (gid_t)-1;
		if (uid) {
			if (isdigit(uid[0])) u = (uid_t)atoi(uid);
			else { struct passwd *pw = getpwnam(uid); if (pw) u = pw->pw_uid; }
		}

		const char *proxy_gid_str = lws_cmdline_option_cx(vhd->context, "--proxy-gid");
		struct group *gr_proxy = NULL;
		if (proxy_gid_str) {
			if (isdigit(proxy_gid_str[0])) {
				gr_proxy = getgrgid((gid_t)atoi(proxy_gid_str));
			} else {
				gr_proxy = getgrnam(proxy_gid_str);
			}
		}
		if (!gr_proxy) gr_proxy = getgrnam("lwsws");
		if (!gr_proxy) gr_proxy = getgrnam("apache");
		if (!gr_proxy) gr_proxy = getgrnam("www-data");

		if (gr_proxy) {
			g = gr_proxy->gr_gid;
		} else if (gid) {
			if (isdigit(gid[0])) g = (gid_t)atoi(gid);
			else { struct group *gr = getgrnam(gid); if (gr) g = gr->gr_gid; }
		}

		if (u != (uid_t)-1 || g != (gid_t)-1) {
			if (chown(vhd->uds_path, u, g))
				lwsl_err("[ROOT-DAEMON] init: Failed to chown UDS %s to %u:%u\n", vhd->uds_path, (unsigned int)u, (unsigned int)g);
			else
				lwsl_notice("[ROOT-DAEMON] init: Chowned UDS %s to %u:%u\n", vhd->uds_path, (unsigned int)u, (unsigned int)g);
		}
		chmod(vhd->uds_path, 0660);
	}

	int flags = fcntl(0, F_GETFL, 0);
	fcntl(0, F_SETFL, flags | O_NONBLOCK);

	lwsl_notice("[ROOT-DAEMON] init: Scheduling root_monitor_stdin_check_cb and root_dnssec_scan_timer_cb\n");
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, root_monitor_stdin_check_cb, 2 * LWS_US_PER_SEC);
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timer_scan, root_dnssec_scan_timer_cb, 5 * LWS_US_PER_SEC);

	pvo1 = lws_pvo_search(in, "ops");
	if (pvo1) vhd->ops = (const struct lws_dht_dnssec_ops *)pvo1->value;
	else {
		const struct lws_protocols *prot = lws_vhost_name_to_protocol(vhd->vhost, "lws-dht-dnssec");
		if (prot) vhd->ops = (const struct lws_dht_dnssec_ops *)prot->user;
	}

	pki_init(vhd);

#if defined(LWS_WITH_DIR)
	{
		char scan_path[1024];
		lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);
		vhd->dn = lws_dir_notify_create(vhd->context, scan_path, dir_notify_cb, vhd);
		if (vhd->dn) lwsl_notice("[ROOT-DAEMON] init: Attached directory monitor to %s\n", scan_path);
	}
#endif
	return 0;
}

struct global_conf_args { char proxy_gid[64]; };
static const char * const global_conf_paths[] = { "global.gid" };

static signed char
global_conf_cb(struct lejp_ctx *ctx, char reason)
{
	struct global_conf_args *a = (struct global_conf_args *)ctx->user;
	if (reason == LEJPCB_VAL_STR_END && ctx->path_match - 1 == 0)
		lws_strncpy(a->proxy_gid, ctx->buf, sizeof(a->proxy_gid));
	return 0;
}

static int
monitor_init_ui_stub(struct vhd *vhd, const struct lws_protocol_vhost_options *in, const char *uid, const char *gid)
{
	const struct lws_protocol_vhost_options *pvo;
	lwsl_notice("[UI-STUB] init: Entering UI Proxy initialization\n");
	char acme_path[1024];
	lws_snprintf(acme_path, sizeof(acme_path), "%s/acme_config.json", vhd->base_dir);
	int afd = open(acme_path, O_RDONLY);
	if (afd >= 0) {
		char abuf[4096]; ssize_t an = read(afd, abuf, sizeof(abuf) - 1);
		if (an > 0) {
			abuf[an] = '\0';
			struct monitor_req_args a; memset(&a, 0, sizeof(a));
			struct lejp_ctx jctx;
			lejp_construct(&jctx, monitor_req_cb, &a, monitor_req_paths, LWS_ARRAY_SIZE(monitor_req_paths));
			lejp_parse(&jctx, (uint8_t *)abuf, (int)an);
			lejp_destruct(&jctx);
			vhd->acme_enabled = a.enabled; vhd->acme_production = a.production;
			lws_strncpy(vhd->acme_email, a.email, sizeof(vhd->acme_email));
			lws_strncpy(vhd->acme_organization, a.organization, sizeof(vhd->acme_organization));
			lws_strncpy(vhd->acme_profile, a.profile, sizeof(vhd->acme_profile));
		}
		close(afd);
	}

	// force_external_dns(vhd->context, "8.8.8.8"); // Removed to use system resolver like DHT node

	if (!global_root_vhd) {
		uint8_t rand[64]; char hex[129];
		struct lws_spawn_piped_info spawn_info;
		memset(&spawn_info, 0, sizeof(spawn_info));
		const char *exec_array[30], *exe_path = lws_cmdline_option_cx_argv0(vhd->context);
		char exe_buf[1024]; char arg_proxy_gid[128];
		int n = 0;

		struct global_conf_args ga; memset(&ga, 0, sizeof(ga));
		int cfd = open("/etc/lwsws/conf", O_RDONLY);
		if (cfd >= 0) {
			char cbuf[4096]; ssize_t cn = read(cfd, cbuf, sizeof(cbuf) - 1);
			if (cn > 0) {
				cbuf[cn] = '\0'; struct lejp_ctx jctx;
				lejp_construct(&jctx, global_conf_cb, &ga, global_conf_paths, LWS_ARRAY_SIZE(global_conf_paths));
				lejp_parse(&jctx, (uint8_t *)cbuf, (int)cn); lejp_destruct(&jctx);
			}
			close(cfd);
		}
		if (!ga.proxy_gid[0]) lws_strncpy(ga.proxy_gid, "lwsws", sizeof(ga.proxy_gid));

		if (!exe_path || exe_path[0] != '/') {
			ssize_t rl = readlink("/proc/self/exe", exe_buf, sizeof(exe_buf) - 1);
			if (rl > 0) {
				exe_buf[rl] = '\0';
				exe_path = exe_buf;
			} else {
				exe_path = "/usr/local/bin/lwsws";
			}
		}
		if ((pvo = lws_pvo_search(in, "exe-path"))) exe_path = pvo->value;

		lwsl_notice("[UI-STUB] init: Preparing to spawn root daemon using %s\n", exe_path);

		exec_array[n++] = exe_path;
		exec_array[n++] = "--lws-stub=dnssec-priv";
		const char *c = lws_cmdline_option_cx(vhd->context, "-c"); if (c) { exec_array[n++] = "-c"; exec_array[n++] = c; }
		const char *d = lws_cmdline_option_cx(vhd->context, "-d"); if (d) { exec_array[n++] = "-d"; exec_array[n++] = d; }
		if (vhd->base_dir) { lws_snprintf(vhd->stub_base_dir, sizeof(vhd->stub_base_dir), "--base-dir=%s", vhd->base_dir); exec_array[n++] = vhd->stub_base_dir; }
		if (vhd->uds_path) { lws_snprintf(vhd->stub_uds_path, sizeof(vhd->stub_uds_path), "--uds-path=%s", vhd->uds_path); exec_array[n++] = vhd->stub_uds_path; }
		if (uid) { lws_snprintf(vhd->stub_uid, sizeof(vhd->stub_uid), "--uid=%s", uid); exec_array[n++] = vhd->stub_uid; }
		if (gid) { lws_snprintf(vhd->stub_gid, sizeof(vhd->stub_gid), "--gid=%s", gid); exec_array[n++] = vhd->stub_gid; }
		lws_snprintf(arg_proxy_gid, sizeof(arg_proxy_gid), "--proxy-gid=%s", ga.proxy_gid); exec_array[n++] = arg_proxy_gid;
		exec_array[n] = NULL;

		lwsl_notice("[UI-STUB] init: Executing spawn process...\n");
		n++;

		lws_get_random(vhd->context, rand, sizeof(rand));
		lws_hex_from_byte_array(rand, sizeof(rand), hex, sizeof(hex));
		lws_strncpy(vhd->auth_token, hex, sizeof(vhd->auth_token));
		vhd->auth_jwk.kty = LWS_GENCRYPTO_KTY_OCT;
		vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].len = 64;
		vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf = malloc(64);
		memcpy(vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf, rand, 64);

		if (!vhd->uds_path) {
			lwsl_err("[UI-STUB] init: Cannot spawn root daemon, uds-path is missing\n");
			return 0;
		}

		spawn_info.exec_array = exec_array; spawn_info.timeout_us = 0; spawn_info.plsp = &vhd->lsp;
		spawn_info.reap_cb = lws_dht_dnssec_monitor_reap_cb; spawn_info.protocol_name = "lws-dht-dnssec-stdwsi";
		spawn_info.vh = vhd->vhost;

		vhd->lsp = lws_spawn_piped(&spawn_info);
		if (vhd->lsp) {
			lwsl_notice("[UI-STUB] init: Successfully spawned Root Daemon child process\n");
			int stdin_fd = (int)(intptr_t)lws_spawn_get_fd_stdxxx(vhd->lsp, 0);
			if (stdin_fd >= 0) {
				char token_buf[140]; lws_snprintf(token_buf, sizeof(token_buf), "%s\n", hex);
				if (write(stdin_fd, token_buf, strlen(token_buf)) < 0) { }
			}
			vhd->root_process_active = 1; global_root_vhd = vhd;
			lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, parent_dnssec_monitor_timer_cb, 1 * LWS_US_PER_SEC);
			lws_sul_schedule(vhd->context, 0, &vhd->sul_timer_proxy_scan, proxy_dnssec_scan_timer_cb, 5 * LWS_US_PER_SEC);
		} else {
			lwsl_err("[UI-STUB] init: Failed to spawn root daemon process %s\n", exe_path);
		}
	} else {
		lwsl_notice("[UI-STUB] init: Linking to pre-existing global root daemon\n");
		lws_strncpy(vhd->auth_token, global_root_vhd->auth_token, sizeof(vhd->auth_token));
		vhd->auth_jwk.kty = LWS_GENCRYPTO_KTY_OCT;
		vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].len = 64;
		vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf = malloc(64);
		memcpy(vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf, global_root_vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf, 64);
		vhd->root_process_active = 1;
	}

	return 0;
}

static int
callback_dht_dnssec_monitor(struct lws *wsi, enum lws_callback_reasons reason,
			    void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	struct lws_vhost *vhost = lws_get_vhost(wsi);
	const struct lws_protocols *protocol = lws_get_protocol(wsi);
	struct vhd *vhd = (struct vhd *)lws_protocol_vh_priv_get(vhost, protocol);
	const struct lws_protocol_vhost_options *pvo;
	const char *uid = NULL, *gid = NULL;

	if (!vhd && global_root_vhd) vhd = global_root_vhd;

	const char *stub = lws_cmdline_option_cx(lws_get_context(wsi), "--lws-stub");

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		if (!in) return 0; /* Skip system vhost etc */
		lwsl_notice("%s: PROTOCOL_INIT (vhost %s, stub: %s)\n", __func__, lws_get_vhost_name(vhost), stub ? stub : "none");
		vhd = lws_protocol_vh_priv_zalloc(vhost, protocol, sizeof(struct vhd));
		if (!vhd) return -1;

		vhd->context = lws_get_context(wsi);
		vhd->vhost = vhost;
		lws_dll2_owner_clear(&vhd->whois_queries);
		lws_dll2_owner_clear(&vhd->dns_queries);
		lws_dll2_owner_clear(&vhd->ui_clients);
		lws_dll2_owner_clear(&vhd->completed_checks);
		lws_dll2_owner_clear(&vhd->active_probes);
		lws_dll2_owner_clear(&vhd->published_jws);

		if ((pvo = lws_pvo_search(in, "base-dir"))) vhd->base_dir = strdup(pvo->value);
		if ((pvo = lws_pvo_search(in, "uds-path"))) vhd->uds_path = pvo->value;

#if defined(LWS_WITH_SYS_SMD)
		vhd->smd_peer = lws_smd_register(vhd->context, vhd, 0, LWSSMDCL_NETWORK, smd_cb_network);
#endif

		if (stub) {
			const char *p;

			if (!vhd->base_dir && (p = lws_cmdline_option_cx(vhd->context, "--base-dir")))
				vhd->base_dir = strdup(p);
			if (!vhd->uds_path && (p = lws_cmdline_option_cx(vhd->context, "--uds-path")))
				vhd->uds_path = p;

			lwsl_notice("[ROOT-DAEMON] %s: Stub process starting with uds-path %s, base-dir %s\n", __func__, vhd->uds_path, vhd->base_dir);
		}

		if ((pvo = lws_pvo_search(in, "base-dir"))) vhd->base_dir = strdup(pvo->value);
		if (!vhd->base_dir) vhd->base_dir = strdup("/var/dnssec");

		if ((pvo = lws_pvo_search(in, "cookie-name")))
			lws_strncpy(vhd->cookie_name, pvo->value, sizeof(vhd->cookie_name));
		if (!vhd->cookie_name[0])
			lws_strncpy(vhd->cookie_name, "auth_session", sizeof(vhd->cookie_name));
		if ((pvo = lws_pvo_search(in, "uid"))) uid = pvo->value;
		if ((pvo = lws_pvo_search(in, "gid"))) gid = pvo->value;
		if ((pvo = lws_pvo_search(in, "signature-duration"))) vhd->signature_duration = (uint32_t)atoi(pvo->value);
		else vhd->signature_duration = 30 * 24 * 3600;

		if ((pvo = lws_pvo_search(in, "jwk_path")))
			lws_strncpy(vhd->jwk_path, pvo->value, sizeof(vhd->jwk_path));
		else
			lws_strncpy(vhd->jwk_path, "/var/db/lws-auth.jwk", sizeof(vhd->jwk_path));

		if (lws_jwk_load(&vhd->jwk, vhd->jwk_path, NULL, NULL))
			lwsl_err("%s: Failed to load JWK from %s\n", __func__, vhd->jwk_path);

		/* Stub check */
		if (stub && !strcmp(stub, "dnssec-priv")) {
			return monitor_init_root_daemon(vhd, in, uid, gid);
		} else {
			if (stub) return 0; /* Stubs don't spawn other stubs */
			return monitor_init_ui_stub(vhd, in, uid, gid);
		}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd || vhd->vhost != lws_get_vhost(wsi)) break;
#if defined(LWS_WITH_SYS_SMD)
		if (vhd->smd_peer) lws_smd_unregister(vhd->smd_peer);
#endif
		lws_jwk_destroy(&vhd->jwk); lws_sul_cancel(&vhd->sul_timer);
		lws_sul_cancel(&vhd->sul_timer_scan); lws_sul_cancel(&vhd->sul_timer_proxy_scan);
		lws_sul_cancel(&vhd->sul_debounce_scan);
		if (vhd->dn) lws_dir_notify_destroy(&vhd->dn);
		if (vhd->lsp) lws_spawn_piped_kill_child_process(vhd->lsp);
		if (vhd->base_dir) free((void *)vhd->base_dir);
		break;

	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		lwsl_notice("[DEBUG] %s: FILTER_PROTOCOL_CONNECTION called. vhd=%p, root_process_active=%d\n", __func__, vhd, vhd ? vhd->root_process_active : 0);
		if (vhd && vhd->root_process_active) {
			struct lws_jwt_auth *ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, NULL, NULL);
			if (!ja) {
				lwsl_err("%s: lws_jwt_auth_create failed! cookie_name='%s', jwk.kty=%d\n", __func__, vhd->cookie_name, vhd->jwk.kty);
				return -1;
			}
			int level = lws_jwt_auth_query_grant(ja, "domain-admin");
			lws_jwt_auth_destroy(&ja);
			if (level <= 0) {
				lwsl_err("%s: Grant level %d too low\n", __func__, level);
				return -1;
			}
			lwsl_notice("[DEBUG] %s: FILTER_PROTOCOL_CONNECTION auth success! level=%d\n", __func__, level);
		}
		break;

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_notice("[DEBUG] %s: ESTABLISHED called\n", __func__);
		if (vhd && vhd->root_process_active) {
			pss->wsi = wsi; pss->retry_count = 0;
			lws_dll2_add_tail(&pss->list, &vhd->ui_clients);
			lwsl_notice("EXTIP_DEBUG: ESTABLISHED UI client. vhd->ext_ips='%s'\n", vhd->ext_ips);
			if (vhd->ext_ips[0]) { pss->send_ext_ips = 1; lws_callback_on_writable(wsi); }
			connect_retry_cb(&pss->sul);
			lwsl_notice("[DEBUG] %s: ESTABLISHED scheduled connect_retry_cb\n", __func__);
		} else {
			lwsl_notice("[DEBUG] %s: ESTABLISHED but vhd is missing or root inactive\n", __func__);
		}
		break;

	case LWS_CALLBACK_CLOSED:
		if (vhd && vhd->root_process_active) {
			lws_dll2_remove(&pss->list); lws_sul_cancel(&pss->sul);
			if (pss->cwsi) { lws_set_opaque_user_data(pss->cwsi, NULL); lws_wsi_close(pss->cwsi, LWS_TO_KILL_ASYNC); pss->cwsi = NULL; }
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		if (vhd && vhd->root_process_active) {
			if (len < 1024) {
				if (strstr((const char *)in, "\"check_cert\"")) {
					struct monitor_req_args a; struct lejp_ctx jctx; memset(&a, 0, sizeof(a));
					lejp_construct(&jctx, monitor_req_cb, &a, monitor_req_paths, LWS_ARRAY_SIZE(monitor_req_paths));
					lejp_parse(&jctx, (uint8_t *)in, (int)len); lejp_destruct(&jctx);
					if (!strcmp(a.req, "check_cert")) {
						struct lws_client_connect_info i; memset(&i, 0, sizeof(i));
						i.context = vhd->context; struct lws_vhost *vh = lws_get_vhost_by_name(vhd->context, "root-monitor-dummy");
						i.vhost = vh ? vh : vhd->vhost; i.address = a.subdomain; i.port = a.port;
						i.ssl_connection = LCCSCF_ALLOW_SELFSIGNED | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
						if (a.port != 25 && a.port != 587) i.ssl_connection |= LCCSCF_USE_SSL;
						i.alpn = "http/1.1"; i.method = "RAW"; i.path = "/"; i.host = i.address; i.origin = i.address; i.protocol = "lws-dht-dnssec-monitor";
						struct cert_check_info *cci = malloc(sizeof(*cci));
						if (cci) {
							memset(cci, 0, sizeof(*cci)); cci->magic = CERT_CHECK_MAGIC;
							lws_strncpy(cci->fqdn, a.subdomain, sizeof(cci->fqdn)); lws_strncpy(cci->domain, a.domain, sizeof(cci->domain));
							cci->port = a.port; cci->starttls_state = (a.port == 25 || a.port == 587) ? 1 : 0; i.opaque_user_data = cci;
						}
						if (!cci || !lws_client_connect_via_info(&i)) {
							if (cci) free(cci);
							struct cert_check_result *cr = malloc(sizeof(*cr));
							if (cr) {
								memset(cr, 0, sizeof(*cr)); lws_strncpy(cr->fqdn, a.subdomain, sizeof(cr->fqdn));
								lws_strncpy(cr->msg, "Connection failed", sizeof(cr->msg)); cr->port = a.port; cr->status_err = 1;
								lws_dll2_add_tail(&cr->list, &vhd->completed_checks); lws_callback_on_writable_all_protocol(vhd->context, protocol);
							}
						}
						if (a.zone_buf)
							free(a.zone_buf);
						return 0;
					}
					if (a.zone_buf) free(a.zone_buf);
				}
				if (strstr((const char *)in, "\"get_domains\"")) {
					char scan_path[1024]; lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);
					lws_dir(scan_path, vhd, scan_whois_cb);
				}
			}

			if (len > 65536) return -1;
			char jwt_buf[1024] = ""; size_t jwt_len = sizeof(jwt_buf); unsigned long long now = (unsigned long long)lws_now_secs();
			char claims[256], temp[2048];
			lws_snprintf(claims, sizeof(claims), "{\"iss\":\"acme-ipc\",\"aud\":\"dnssec-monitor\",\"iat\":%llu,\"nbf\":%llu,\"exp\":%llu}", now, now - 60, now + 60);

			if (vhd->auth_jwk.kty == LWS_GENCRYPTO_KTY_OCT &&
			    !lws_jwt_sign_compact(vhd->context, &vhd->auth_jwk, "HS256", jwt_buf, &jwt_len, temp, sizeof(temp), "%s", claims)) {
				char *first_brace = memchr(in, '{', len);
				if (first_brace) {
					size_t offset = lws_ptr_diff_size_t(first_brace, in) + 1;
					size_t out_len = 0, existing_len = pss->tx_len;
					if (existing_len + offset < 65536 - LWS_PRE) {
						memcpy(&pss->tx[LWS_PRE + existing_len], in, offset); out_len += offset;
						int n = lws_snprintf((char *)&pss->tx[LWS_PRE + existing_len + out_len], 65536 - LWS_PRE - existing_len - out_len, "\"jwt\":\"%s\",", jwt_buf);
						out_len += (size_t)n;
						if (existing_len + out_len + len - offset + 1 < 65536 - LWS_PRE) {
							memcpy(&pss->tx[LWS_PRE + existing_len + out_len], first_brace + 1, len - offset);
							out_len += len - offset;
							pss->tx[LWS_PRE + existing_len + out_len] = '\n';
							out_len += 1;
							pss->tx_len += out_len;
							lwsl_notice("[PROXY] %s: Forwarding request to Root Daemon (tx_len: %zu)\n", __func__, pss->tx_len);
							if (pss->cwsi)
								lws_callback_on_writable(pss->cwsi);
						}
					}
					return 0;
				}
			}
			if (pss->tx_len + len + 1 < 65536 - LWS_PRE) {
				memcpy(&pss->tx[LWS_PRE + pss->tx_len], in, len); pss->tx_len += len;
				pss->tx[LWS_PRE + pss->tx_len] = '\n'; pss->tx_len += 1;
				if (pss->cwsi) lws_callback_on_writable(pss->cwsi);
			}
		}
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (vhd && vhd->completed_checks.head) {
			struct lws_dll2 *p = vhd->completed_checks.head;
			struct cert_check_result *cr = lws_container_of(p, struct cert_check_result, list);
			char *tx = (char *)&pss->tx[LWS_PRE];
			int n = lws_snprintf(tx, 65536 - LWS_PRE, "{\"req\":\"cert_status\",\"subdomain\":\"%s\",\"port\":%d,\"status\":\"%s\",\"msg\":\"%s\",\"local_msg\":\"%s\",\"issuer\":\"%s\"}\n",
				cr->fqdn, cr->port, cr->status_err ? "error" : "ok", cr->msg, cr->local_msg, cr->issuer);
			if (lws_write(wsi, (unsigned char *)tx, (size_t)n, LWS_WRITE_TEXT) < 0) return -1;
			lws_dll2_remove(&cr->list); free(cr);
			if (vhd->completed_checks.head) lws_callback_on_writable(wsi);
			return 0;
		}
		if (vhd && vhd->root_process_active) {
			if (pss->send_ext_ips) {
				lwsl_notice("EXTIP_DEBUG: SERVER_WRITEABLE sending extip_update: %s\n", vhd->ext_ips);
				pss->send_ext_ips = 0; uint8_t buf[LWS_PRE + 512];
				int n = lws_snprintf((char *)buf + LWS_PRE, 512, "{\"req\":\"extip_update\",\"data\":%s}\n", vhd->ext_ips);
				if (lws_write(wsi, buf + LWS_PRE, (size_t)n, LWS_WRITE_TEXT) < 0) return -1;
				if (pss->rx_len) lws_callback_on_writable(wsi);
				return 0;
			}
			if (pss->rx_len) {
				if (lws_write(wsi, &pss->rx[LWS_PRE], pss->rx_len, LWS_WRITE_TEXT) < 0) return -1;
				pss->rx_len = 0;
			}
		}
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		lwsl_notice("[DEBUG] %s: RAW_CONNECTED called\n", __func__);
		{
			struct cert_check_info *cci = (struct cert_check_info *)lws_get_opaque_user_data(wsi);
			if (cci && cci->magic == CERT_CHECK_MAGIC && vhd) {
				if (cci->starttls_state == 0 || cci->starttls_state == 4) {
					extract_and_queue_cert_result(wsi, vhd, cci, protocol);
					cci->magic = 0; lws_dll2_remove(&cci->active_list); free(cci);
					lws_set_opaque_user_data(wsi, NULL); return -1;
				}
			} else {
				lwsl_notice("[DEBUG] %s: RAW_CONNECTED success for non-cert_check_info (presumably UDS proxy)\n", __func__);
			}
		}
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_notice("[DEBUG] %s: CLIENT_CONNECTION_ERROR called, in=%s\n", __func__, in ? (char*)in : "none");
		{
			struct cert_check_info *cci = (struct cert_check_info *)lws_get_opaque_user_data(wsi);
			if (cci && cci->magic == CERT_CHECK_MAGIC && vhd) {
				struct cert_check_result *cr = malloc(sizeof(*cr));
				if (cr) {
					memset(cr, 0, sizeof(*cr)); lws_strncpy(cr->fqdn, cci->fqdn, sizeof(cr->fqdn));
					lws_snprintf(cr->msg, sizeof(cr->msg), "Error: %s", in ? (char *)in : "unknown");
					cr->status_err = 1; lws_dll2_add_tail(&cr->list, &vhd->completed_checks);
					lws_callback_on_writable_all_protocol(vhd->context, protocol);
				}
			}

			struct acme_profiles_fetch_info *afi = (struct acme_profiles_fetch_info *)lws_get_opaque_user_data(wsi);
			if (afi && afi->magic == ACME_PROFILES_MAGIC) {
				lwsl_err("%s: ACME directory HTTP client connection errored before completion\n", __func__);
				afi->magic = 0;
				free(afi);
				lws_set_opaque_user_data(wsi, NULL);
			}
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		{
			void *opaque = lws_get_opaque_user_data(wsi);
			struct cert_check_info *cci = (struct cert_check_info *)opaque;
			if (cci && cci->magic == CERT_CHECK_MAGIC) {
				cci->magic = 0; lws_dll2_remove(&cci->active_list); free(cci);
				lws_set_opaque_user_data(wsi, NULL);
			} else {
				struct pss *wpss = (struct pss *)opaque;
				if (wpss) wpss->cwsi = NULL;
				struct pss *root_pss = (struct pss *)user;
				if (root_pss && vhd && !vhd->root_process_active) {
					lws_dll2_remove(&root_pss->list);
				}
			}
		}
		break;

	case LWS_CALLBACK_RAW_ADOPT:
		lwsl_notice("[ROOT-DAEMON] %s: Adopting IPC connection at %llu\n", __func__, (unsigned long long)lws_now_usecs());
		{
			struct pss *root_pss = (struct pss *)user;
			if (root_pss) {
				root_pss->wsi = wsi;
				if (vhd && !vhd->root_process_active) {
					lws_dll2_add_tail(&root_pss->list, &vhd->ui_clients);
					if (vhd->ext_ips[0]) {
						int n = lws_snprintf((char *)&root_pss->tx[LWS_PRE + root_pss->tx_len], 65536 - LWS_PRE - root_pss->tx_len,
							"{\"req\":\"extip_update\",\"data\":%s}\n", vhd->ext_ips);
						if (n > 0) root_pss->tx_len += (size_t)n;
						lws_callback_on_writable(wsi);
					}
				}
			}
			struct pss *wpss = (struct pss *)lws_get_opaque_user_data(wsi);
			if (wpss) { wpss->cwsi = wsi; if (wpss->tx_len) lws_callback_on_writable(wsi); }
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

			struct pss *wpss = (struct pss *)opaque;
			if (wpss) {
				if (len > 65536) return -1;
				lwsl_notice("[PROXY] %s: Received %zu bytes response from Root Daemon\n", __func__, len);
				memcpy(&wpss->rx[LWS_PRE], in, len); wpss->rx_len = len;
				lws_callback_on_writable(wpss->wsi);
			} else {
				if (len > 65536 - 1) return -1;
				lwsl_notice("[ROOT-DAEMON] %s: Received %zu bytes from UDS proxy\n", __func__, len);
				memcpy(&vhd->rx[LWS_PRE], in, len); vhd->rx[LWS_PRE + len] = '\0'; vhd->rx_len = len;
				struct pss *root_pss = (struct pss *)user; root_pss->tx_len = 0;
				char *current = (char *)&vhd->rx[LWS_PRE], *end = current + len;
				while (current < end) {
					char *nl = strchr(current, '\n'); if (!nl) nl = end;
					size_t chunk_len = lws_ptr_diff_size_t(nl, current);
					if (chunk_len > 0) {
						char save = *nl; *nl = '\0';
						handle_monitor_request(vhd, root_pss, current, chunk_len);
						if (save != '\0') *nl = save;
					}
					current = nl + 1;
				}
				if (root_pss->tx_len) {
					lwsl_notice("[ROOT-DAEMON] %s: Request processed, signaling writable (tx_len: %zu)\n", __func__, root_pss->tx_len);
					lws_callback_on_writable(wsi);
				} else {
					lwsl_notice("[ROOT-DAEMON] %s: Request processed, but no response generated\n", __func__);
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
			struct pss *wpss = (struct pss *)opaque;
			if (wpss) {
				if (wpss->tx_len) {
					lwsl_notice("[PROXY] %s: Writing %zu bytes to Root Daemon\n", __func__, wpss->tx_len);
					if (lws_write(wsi, &wpss->tx[LWS_PRE], wpss->tx_len, LWS_WRITE_RAW) < 0) return -1;
					wpss->tx_len = 0;
				}
			} else {
				struct pss *root_pss = (struct pss *)user;
				if (root_pss && root_pss->tx_len) {
					lwsl_notice("[ROOT-DAEMON] %s: Sending IPC response (%zu bytes)\n", __func__, root_pss->tx_len);
					if (lws_write(wsi, &root_pss->tx[LWS_PRE], root_pss->tx_len, LWS_WRITE_RAW) < 0) return -1;
					root_pss->tx_len = 0;
				}
			}
		}
		break;

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
				if (afi->json_len + len < sizeof(afi->json) - 1) {
					memcpy(&afi->json[afi->json_len], in, len);
					afi->json_len += len;
					afi->json[afi->json_len] = '\0';
				} else {
					lwsl_err("%s: ACME directory JSON too large!\n", __func__);
				}
			}
		}
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		{
			struct acme_profiles_fetch_info *afi = (struct acme_profiles_fetch_info *)lws_get_opaque_user_data(wsi);
			if (afi && afi->magic == ACME_PROFILES_MAGIC) {
				lwsl_notice("%s: Completed ACME directory fetch (%zu bytes)\n", __func__, afi->json_len);
				// Send JSON to UI proxy client (afi->root_pss)
				// We broadcast it to be safe, because the original client might have disconnected.
				lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->ui_clients.head) {
					struct pss *wpss = lws_container_of(d, struct pss, list);
					size_t existing_len = wpss->tx_len;
					if (existing_len + afi->json_len + 128 < 65536 - LWS_PRE) {
						int n = lws_snprintf((char *)&wpss->tx[LWS_PRE + existing_len], 65536 - LWS_PRE - existing_len,
							"{\"req\":\"get_acme_profiles\",\"status\":\"ok\",\"profiles\":");
						existing_len += (size_t)n;

						// Try to extract just the profiles object from the json
						char *profiles_start = strstr(afi->json, "\"profiles\"");
						if (profiles_start) {
							profiles_start += 10; // skip "profiles"
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
								// fallback if parsing failed
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
				} lws_end_foreach_dll_safe(d, d1);

				afi->magic = 0;
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
				free(afi);
				lws_set_opaque_user_data(wsi, NULL);
			}
		}
		break;

	default: break;
	}
	return 0;
}

static int
callback_monitor_stdwsi(struct lws *wsi, enum lws_callback_reasons reason,
                    void *user, void *in, size_t len)
{
    uint8_t buf[2048]; int ilen;
	struct lws_vhost *vhost = lws_get_vhost(wsi);
	struct vhd *vhd = (struct vhd *)lws_protocol_vh_priv_get(vhost, lws_get_protocol(wsi));
	if (!vhd && global_root_vhd) vhd = global_root_vhd;

    switch (reason) {
    case LWS_CALLBACK_RAW_RX_FILE:
        {
            int _fd = (int)(intptr_t)lws_get_socket_fd(wsi);
            if (_fd < 0) return -1;
            ilen = (int)read(_fd, buf, sizeof(buf) - 1);
            if (ilen < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
                return -1;
            }
            if (ilen == 0) return -1;
            buf[ilen] = '\0';
			char *b = (char *)buf;
			while (b && *b) { char *nl = strchr(b, '\n'); if (nl) *nl++ = '\0'; lwsl_notice("[SYSTEM-LOG] %s\n", b); b = nl; }
            return 0;
        }
    default: break;
    }
    return 0;
}

LWS_VISIBLE const struct lws_protocols lws_dht_dnssec_monitor_protocols[] = {
	{ .name = "lws-dht-dnssec-monitor", .callback = callback_dht_dnssec_monitor, .per_session_data_size = sizeof(struct pss), },
	{ .name = "lws-dht-dnssec-stdwsi", .callback = callback_monitor_stdwsi, },
	LWS_PROTOCOL_LIST_TERM
};

LWS_VISIBLE const lws_plugin_protocol_t lws_dht_dnssec_monitor = {
	.hdr = { .name = "dht dnssec monitor", ._class = "lws_protocol_plugin", .lws_build_hash = LWS_BUILD_HASH, .api_magic = LWS_PLUGIN_API_MAGIC, .priority = 10 },
	.protocols = lws_dht_dnssec_monitor_protocols, .count_protocols = LWS_ARRAY_SIZE(lws_dht_dnssec_monitor_protocols),
};
