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

struct vhd *global_root_vhd = NULL;

extern const struct lws_protocols lws_dht_dnssec_monitor_protocols[];

#if defined(LWS_WITH_SYS_SMD)
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

	if (!vhd || !vhd->root_process_active) return;

	struct lws_client_connect_info i;
	char uds_path[1024];

	memset(&i, 0, sizeof(i));
	i.method = "RAW"; i.context = vhd->context; i.vhost = lws_get_vhost(pss->wsi);
	lws_snprintf(uds_path, sizeof(uds_path), "+%s", vhd->uds_path);
	i.address = uds_path; i.port = 0; i.host = "localhost"; i.origin = "localhost";
	i.local_protocol_name = "lws-dht-dnssec-monitor";
	i.opaque_user_data = pss; i.pwsi = &pss->cwsi;

	if (!lws_client_connect_via_info(&i)) {
		pss->cwsi = NULL;
		if (++pss->retry_count < 20)
			lws_sul_schedule(vhd->context, 0, &pss->sul, connect_retry_cb, 250 * LWS_US_PER_MS);
		else
			lws_wsi_close(pss->wsi, LWS_TO_KILL_ASYNC);
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
	const struct lws_protocol_vhost_options *pvo, *pvo1;
	const char *uid = NULL, *gid = NULL;

	if (!vhd && global_root_vhd) vhd = global_root_vhd;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
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
		if ((pvo = lws_pvo_search(in, "cookie-name"))) lws_strncpy(vhd->cookie_name, pvo->value, sizeof(vhd->cookie_name));
		if ((pvo = lws_pvo_search(in, "uid"))) uid = pvo->value;
		if ((pvo = lws_pvo_search(in, "gid"))) gid = pvo->value;
		if ((pvo = lws_pvo_search(in, "signature-duration"))) vhd->signature_duration = (uint32_t)atoi(pvo->value);
		else vhd->signature_duration = 30 * 24 * 3600;

		if ((pvo = lws_pvo_search(in, "auth-jwk"))) {
			if (lws_jwk_import(&vhd->jwk, NULL, NULL, pvo->value, strlen(pvo->value)) < 0)
				lwsl_err("%s: Failed to import auth-jwk\n", __func__);
		}

		/* Stub check */
		const char *stub = lws_cmdline_option_cx(vhd->context, "--lws-stub");
		if (stub && !strcmp(stub, "dnssec-priv")) {
			if (global_root_vhd) {
				vhd->root_daemon = 1;
				vhd->root_process_active = 1;
				lws_strncpy(vhd->auth_token, global_root_vhd->auth_token, sizeof(vhd->auth_token));
				return 0;
			}
			lwsl_notice("%s: Running in Root Daemon mode, waiting for token on stdin\n", __func__);
			vhd->root_daemon = 1;
			global_root_vhd = vhd;

			if (vhd->uds_path) {
				struct lws_context_creation_info info;
				memset(&info, 0, sizeof(info));
				info.vhost_name = "root-monitor-uds";
				info.iface = vhd->uds_path;
				info.port = CONTEXT_PORT_NO_LISTEN_SERVER;
				info.protocols = lws_dht_dnssec_monitor_protocols;
				info.options = LWS_SERVER_OPTION_UNIX_SOCK;
				if (!lws_create_vhost(vhd->context, &info)) {
					lwsl_err("%s: Failed to create root UDS vhost\n", __func__);
					global_root_vhd = NULL;
					return -1;
				}
				lwsl_notice("%s: Root UDS vhost created at %s\n", __func__, vhd->uds_path);
			}

			/* Non-blocking stdin for async token read */
			int flags = fcntl(0, F_GETFL, 0);
			fcntl(0, F_SETFL, flags | O_NONBLOCK);

			lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, root_monitor_stdin_check_cb, 2 * LWS_US_PER_SEC);
			lws_sul_schedule(vhd->context, 0, &vhd->sul_timer_scan, root_dnssec_scan_timer_cb, 5 * LWS_US_PER_SEC);

			pvo1 = lws_pvo_search(in, "ops");
			if (pvo1) vhd->ops = (const struct lws_dht_dnssec_ops *)pvo1->value;

			pki_init(vhd);
		} else {
#if defined(LWS_WITH_SYS_SMD)
			vhd->smd_peer = lws_smd_register(vhd->context, vhd, 0, LWSSMDCL_NETWORK, smd_cb_network);
#endif
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
					lws_strncpy(vhd->acme_country, a.country, sizeof(vhd->acme_country));
					lws_strncpy(vhd->acme_state, a.state, sizeof(vhd->acme_state));
					lws_strncpy(vhd->acme_locality, a.locality, sizeof(vhd->acme_locality));
				}
				close(afd);
			}

			force_external_dns(vhd->context, "8.8.8.8");

			struct lws_spawn_piped_info spawn_info;
			memset(&spawn_info, 0, sizeof(spawn_info));
			const char *exec_array[15], *exe_path = lws_cmdline_option_cx_argv0(vhd->context);
			char arg_uds[1024], arg_uid[128], arg_gid[128], arg_basedir[1024];
			int n = 0;

			if (!exe_path || exe_path[0] != '/') exe_path = "/usr/local/bin/lwsws";
			if ((pvo = lws_pvo_search(in, "exe-path"))) exe_path = pvo->value;

			exec_array[n++] = exe_path; exec_array[n++] = "--lws-stub=dnssec-priv";
			const char *c = lws_cmdline_option_cx(vhd->context, "-c"); if (c) { exec_array[n++] = "-c"; exec_array[n++] = c; }
			const char *d = lws_cmdline_option_cx(vhd->context, "-d"); if (d) { exec_array[n++] = "-d"; exec_array[n++] = d; }
			if (vhd->base_dir) { lws_snprintf(arg_basedir, sizeof(arg_basedir), "--base-dir=%s", vhd->base_dir); exec_array[n++] = arg_basedir; }
			if (vhd->uds_path) { lws_snprintf(arg_uds, sizeof(arg_uds), "--uds-path=%s", vhd->uds_path); exec_array[n++] = arg_uds; }
			if (uid) { lws_snprintf(arg_uid, sizeof(arg_uid), "--uid=%s", uid); exec_array[n++] = arg_uid; }
			if (gid) { lws_snprintf(arg_gid, sizeof(arg_gid), "--gid=%s", gid); exec_array[n++] = arg_gid; }
			exec_array[n++] = NULL;

			if (!global_root_vhd) {
				uint8_t rand[64]; char hex[129];
				lws_get_random(vhd->context, rand, sizeof(rand));
				lws_hex_from_byte_array(rand, sizeof(rand), hex, sizeof(hex));
				lws_strncpy(vhd->auth_token, hex, sizeof(vhd->auth_token));
				vhd->auth_jwk.kty = LWS_GENCRYPTO_KTY_OCT;
				vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].len = 64;
				vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf = malloc(64);
				memcpy(vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf, rand, 64);

				spawn_info.exec_array = exec_array; spawn_info.timeout_us = 0; spawn_info.plsp = &vhd->lsp;
				spawn_info.reap_cb = lws_dht_dnssec_monitor_reap_cb; spawn_info.protocol_name = "lws-dht-dnssec-stdwsi";
				spawn_info.vh = vhd->vhost;

				vhd->lsp = lws_spawn_piped(&spawn_info);
				if (vhd->lsp) {
					int stdin_fd = (int)(intptr_t)lws_spawn_get_fd_stdxxx(vhd->lsp, 0);
					if (stdin_fd >= 0) {
						char token_buf[140]; lws_snprintf(token_buf, sizeof(token_buf), "%s\n", hex);
						write(stdin_fd, token_buf, strlen(token_buf));
					}
					vhd->root_process_active = 1; global_root_vhd = vhd;
					lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, parent_dnssec_monitor_timer_cb, 1 * LWS_US_PER_SEC);
					lws_sul_schedule(vhd->context, 0, &vhd->sul_timer_proxy_scan, proxy_dnssec_scan_timer_cb, 5 * LWS_US_PER_SEC);
				}
			} else {
				lws_strncpy(vhd->auth_token, global_root_vhd->auth_token, sizeof(vhd->auth_token));
				vhd->auth_jwk.kty = LWS_GENCRYPTO_KTY_OCT;
				vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].len = 64;
				vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf = malloc(64);
				memcpy(vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf, global_root_vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf, 64);
				vhd->root_process_active = 1;
			}
		}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd || vhd->vhost != lws_get_vhost(wsi)) break;
#if defined(LWS_WITH_SYS_SMD)
		if (vhd->smd_peer) lws_smd_unregister(vhd->smd_peer);
#endif
		lws_jwk_destroy(&vhd->jwk); lws_sul_cancel(&vhd->sul_timer);
		lws_sul_cancel(&vhd->sul_timer_scan); lws_sul_cancel(&vhd->sul_timer_proxy_scan);
		if (vhd->lsp) lws_spawn_piped_kill_child_process(vhd->lsp);
		if (vhd->base_dir) free(vhd->base_dir);
		break;

	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		if (vhd && vhd->root_process_active) {
			struct lws_jwt_auth *ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, NULL, NULL);
			if (!ja) return -1;
			int level = lws_jwt_auth_query_grant(ja, "domain-admin");
			lws_jwt_auth_destroy(&ja);
			if (level <= 0) return -1;
		}
		break;

	case LWS_CALLBACK_ESTABLISHED:
		if (vhd && vhd->root_process_active) {
			pss->wsi = wsi; pss->retry_count = 0;
			lws_dll2_add_tail(&pss->list, &vhd->ui_clients);
			if (vhd->ext_ips[0]) { pss->send_ext_ips = 1; lws_callback_on_writable(wsi); }
			connect_retry_cb(&pss->sul);
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
		{
			struct cert_check_info *cci = (struct cert_check_info *)lws_get_opaque_user_data(wsi);
			if (cci && cci->magic == CERT_CHECK_MAGIC && vhd) {
				if (cci->starttls_state == 0 || cci->starttls_state == 4) {
					extract_and_queue_cert_result(wsi, vhd, cci, protocol);
					cci->magic = 0; lws_dll2_remove(&cci->active_list); free(cci);
					lws_set_opaque_user_data(wsi, NULL); return -1;
				}
			}
		}
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
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
			}
		}
		break;

	case LWS_CALLBACK_RAW_ADOPT:
		{
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
				memcpy(&wpss->rx[LWS_PRE], in, len); wpss->rx_len = len;
				lws_callback_on_writable(wpss->wsi);
			} else {
				if (len > 65536 - 1) return -1;
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
				if (root_pss->tx_len) lws_callback_on_writable(wsi);
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
				if (wpss->tx_len && lws_write(wsi, &wpss->tx[LWS_PRE], wpss->tx_len, LWS_WRITE_RAW) < 0) return -1;
				wpss->tx_len = 0;
			} else {
				struct pss *root_pss = (struct pss *)user;
				if (root_pss && root_pss->tx_len && lws_write(wsi, &root_pss->tx[LWS_PRE], root_pss->tx_len, LWS_WRITE_RAW) < 0) return -1;
				root_pss->tx_len = 0;
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
            if (ilen < 1) return -1;
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
	{ .name = "lws-dht-dnssec-stdwsi", .callback = callback_monitor_stdwsi, },
	{ .name = "lws-dht-dnssec-monitor", .callback = callback_dht_dnssec_monitor, .per_session_data_size = sizeof(struct pss), },
};

LWS_VISIBLE const lws_plugin_protocol_t lws_dht_dnssec_monitor = {
	.hdr = { .name = "dht dnssec monitor", ._class = "lws_protocol_plugin", .lws_build_hash = LWS_BUILD_HASH, .api_magic = LWS_PLUGIN_API_MAGIC, .priority = 10 },
	.protocols = lws_dht_dnssec_monitor_protocols, .count_protocols = LWS_ARRAY_SIZE(lws_dht_dnssec_monitor_protocols),
};
