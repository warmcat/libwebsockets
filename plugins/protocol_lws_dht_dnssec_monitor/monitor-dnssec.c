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



void
extract_and_queue_cert_result(struct lws *wsi, struct vhd *vhd, struct cert_check_info *cci, const struct lws_protocols *protocol)
{
	union lws_tls_cert_info_results ci;
	char msg[128], issuer[128] = "Unknown", local_msg[128] = "Not Found";
	int err = 0;

	if (!lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_ISSUER_NAME, &ci, 0))
		lws_strncpy(issuer, ci.ns.name, sizeof(issuer));

	if (!lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_VALIDITY_TO, &ci, 0)) {
		time_t now; time(&now);
		if (now > ci.time) lws_snprintf(msg, sizeof(msg), "Expired");
		else lws_snprintf(msg, sizeof(msg), "%d days", (int)((ci.time - now) / (24 * 3600)));
	} else {
		lws_snprintf(msg, sizeof(msg), "No cert info");
		err = 1;
	}

	int has_local_cert = 0;
	if (cci->domain[0]) {
		char path[1024];
		lws_snprintf(path, sizeof(path), "%s/domains/%s/certs/%s/crt/%s-latest.crt", vhd->base_dir, cci->domain, vhd->acme_production ? "production" : "staging", cci->fqdn);
		int fd = open(path, O_RDONLY);
		if (fd >= 0) {
			has_local_cert = 1;
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
								if (!lws_x509_info(x509, LWS_TLS_CERT_INFO_VALIDITY_TO, &lci, 0)) {
									time_t now; time(&now);
									if (now > lci.time) lws_snprintf(local_msg, sizeof(local_msg), "Expired");
									else lws_snprintf(local_msg, sizeof(local_msg), "%d days", (int)((lci.time - now) / (24 * 3600)));
								}
							}
							lws_x509_destroy(&x509);
						}
					}
					free(pem);
				}
			}
			close(fd);
		}
	}

	if (cci->is_automated) {
		int needs_acme = 0;
		if (err) {
			lwsl_notice("%s: [TLS-PROBE] %s:%d FAILED: %s (Triggering ACME)\n", __func__, cci->fqdn, cci->port, msg);
			append_acme_log(vhd, "TLS probe for %s:%d failed: %s. Triggering ACME renewal.", cci->fqdn, cci->port, msg);
			needs_acme = 1;
		} else {
			union lws_tls_cert_info_results ci_from;
			if (!lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_VALIDITY_FROM, &ci_from, 0)) {
				time_t now; time(&now);
				time_t total = ci.time - ci_from.time;
				time_t remaining = ci.time - now;
				if (total > 0 && remaining < (total / 5)) {
					lwsl_notice("%s: [TLS-PROBE] %s:%d SUCCESS: Cert served expires in %s (Triggering ACME - <20%% validity left)\n", __func__, cci->fqdn, cci->port, msg);
					append_acme_log(vhd, "TLS probe for %s:%d OK, but cert expires in %s (<20%% validity). Triggering ACME.", cci->fqdn, cci->port, msg);
					needs_acme = 1;
				} else if (!has_local_cert && !vhd->acme_production) {
					lwsl_notice("%s: [TLS-PROBE] %s:%d SUCCESS: Cert served expires in %s (Triggering ACME - no matching local staging cert)\n", __func__, cci->fqdn, cci->port, msg);
					append_acme_log(vhd, "TLS probe for %s:%d OK, but no local cert found. Triggering ACME.", cci->fqdn, cci->port);
					needs_acme = 1;
				}
			}
		}

		if (needs_acme && vhd->acme_enabled) {
			char vh_name[256];
			lws_snprintf(vh_name, sizeof(vh_name), "acme_%s", cci->fqdn);
			if (!lws_get_vhost_by_name(vhd->context, vh_name))
				acme_vhost_spawn(vhd, cci->fqdn, cci->fqdn, NULL);
		}
	} else {
		struct cert_check_result *cr = malloc(sizeof(*cr));
		if (cr) {
			memset(cr, 0, sizeof(*cr));
			lws_strncpy(cr->fqdn, cci->fqdn, sizeof(cr->fqdn));
			lws_strncpy(cr->msg, msg, sizeof(cr->msg));
			lws_strncpy(cr->local_msg, local_msg, sizeof(cr->local_msg));
			lws_strncpy(cr->issuer, issuer, sizeof(cr->issuer));
			cr->port = cci->port; cr->status_err = err;
			lws_dll2_add_tail(&cr->list, &vhd->completed_checks);
			lws_callback_on_writable_all_protocol(vhd->context, protocol);
		}
	}
}

struct lws *
dnssec_state_dns_cb(struct lws *wsi, const char *ads, const struct addrinfo *result, int n, void *opaque)
{
	struct dns_req *req = (struct dns_req *)opaque;
	struct vhd *vhd = req->vhd;

	lwsl_notice("%s: DNS query for %s returned %d\n", __func__, ads ? ads : "none", n);

	if (n <= 0) {
		lws_dll2_remove(&req->list);
		free(req);
		return wsi ? wsi : LADNS_NO_WSI_BUT_OK;
	}

	if (req->sent_probe)
		return wsi ? wsi : LADNS_NO_WSI_BUT_OK;

	req->sent_probe = 1;

	struct lws_client_connect_info i;
	memset(&i, 0, sizeof(i));
	i.context = vhd->context;
	struct lws_vhost *vh = lws_get_vhost_by_name(vhd->context, "root-monitor-dummy");
	i.vhost = vh ? vh : vhd->vhost;
	i.address = ads; i.port = req->port;
	i.ssl_connection = LCCSCF_ALLOW_SELFSIGNED | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	if (req->port != 25 && req->port != 587) i.ssl_connection |= LCCSCF_USE_SSL;
	i.alpn = "http/1.1"; i.method = "RAW"; i.path = "/"; i.host = i.address; i.origin = i.address;
	i.protocol = "lws-dht-dnssec-monitor";
	struct cert_check_info *cci = malloc(sizeof(*cci));
	if (cci) {
		memset(cci, 0, sizeof(*cci));
		cci->magic = CERT_CHECK_MAGIC;
		lws_strncpy(cci->fqdn, ads, sizeof(cci->fqdn));
		lws_strncpy(cci->domain, req->domain, sizeof(cci->domain));
		cci->port = req->port; cci->is_automated = 1;
		cci->starttls_state = (req->port == 25 || req->port == 587) ? 1 : 0;
		i.opaque_user_data = cci;
	}
	if (!cci || !lws_client_connect_via_info(&i)) if (cci) free(cci);

	return wsi ? wsi : LADNS_NO_WSI_BUT_OK;
}

struct lws *
dnssec_state_ds_cb(struct lws *wsi, const char *ads, const struct addrinfo *result, int n, void *opaque)
{
	struct dns_req *req = (struct dns_req *)opaque;
	struct vhd *vhd = req->vhd;
	uint16_t ds_paylen = 0;

	lwsl_info("%s: DS query for %s returned %d\n", __func__, req->domain, n);

	char debug_path[1024];
	lws_snprintf(debug_path, sizeof(debug_path), "%s/domains/%s/dns_ds_debug.txt", vhd->base_dir, req->domain);
	int fdd = open(debug_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
	if (fdd >= 0) {
		char dbuf[128];
		int dlen = lws_snprintf(dbuf, sizeof(dbuf), "Callback fired! n=%d\n", n);
		write(fdd, dbuf, (size_t)dlen);
		close(fdd);
	}

	char path[1024];
	if (vhd->scan_type == 1)
		lws_snprintf(path, sizeof(path), "%s/domains/%s/dns_ds_8888.txt", vhd->base_dir, req->domain);
	else
		lws_snprintf(path, sizeof(path), "%s/domains/%s/dns_ds.txt", vhd->base_dir, req->domain);

	if (n <= 0 || (n & ~LWS_ADNS_DNSSEC_VALID) != LADNS_RET_FOUND) {
		lwsl_notice("%s: query for %s failed with n=%d\n", __func__, req->domain, n);
		int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd >= 0) {
			write(fd, "FAILED", 6);
			close(fd);
		}
		goto drop;
	}

	const uint8_t *ds_payload = lws_async_dns_get_rr_cache(vhd->context, req->domain, LWS_ADNS_RECORD_DS, &ds_paylen);
	if (ds_payload && ds_paylen >= 4) {
		uint16_t key_tag = lws_ser_ru16be(&ds_payload[0]);
		uint8_t algo = ds_payload[2];
		uint8_t digest_type = ds_payload[3];
		int dlen = ds_paylen - 4;

		int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd >= 0) {
			char buf[512];
			int len = lws_snprintf(buf, sizeof(buf), "%u %d %d ", key_tag, algo, digest_type);
			for (int i = 0; i < dlen && (size_t)len < sizeof(buf) - 3; i++)
				len += lws_snprintf(buf + len, sizeof(buf) - (size_t)len, "%02X", ds_payload[4 + i]);
			write(fd, buf, (size_t)len);
			close(fd);
		}
	}

drop:
	lws_dll2_remove(&req->list);
	free(req);
	return wsi ? wsi : LADNS_NO_WSI_BUT_OK;
}

int
scan_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct vhd *vhd = (struct vhd *)user;
	char filepath[1024];
	struct stat st;

	lwsl_info("%s: Seen entry '%s' (type %d) in %s\n", __func__, lde->name, lde->type, dirpath);

	if (lde->name[0] == '.') return 0;
	if (lde->type != LDOT_DIR && lde->type != LDOT_UNKNOWN) return 0;

	if (vhd->scan_type == 1) {
		/* GLOBAL SCAN: Only do the DS query */
		struct dns_req *req_ds = malloc(sizeof(*req_ds));
		if (req_ds) {
			memset(req_ds, 0, sizeof(*req_ds));
			req_ds->vhd = vhd;
			lws_strncpy(req_ds->domain, lde->name, sizeof(req_ds->domain));
			lws_dll2_add_tail(&req_ds->list, &vhd->dns_queries);
			int ret = lws_async_dns_query(vhd->context, 0, lde->name, (adns_query_type_t)(LWS_ADNS_RECORD_DS | LWS_ADNS_NOCACHE), dnssec_state_ds_cb, NULL, req_ds, NULL);
			if (ret != LADNS_RET_FOUND && ret != LADNS_RET_CONTINUING) {
				int found = 0;
				lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp, vhd->dns_queries.head) {
					if (p == &req_ds->list) { found = 1; break; }
				} lws_end_foreach_dll_safe(p, tp);
				if (found) { lws_dll2_remove(&req_ds->list); free(req_ds); }
			}
		}
		return 0;
	}

	/* 1: Check for .port files for cert checks */
	char conf_path[1024];
	lws_snprintf(conf_path, sizeof(conf_path), "%s/%s/conf.d", dirpath, lde->name);
	DIR *d = opendir(conf_path);
	if (d) {
		struct dirent *de;
		while ((de = readdir(d))) {
			if (de->d_name[0] == '.') continue;
			if (strstr(de->d_name, ".port")) {
				char sub[256], p_path[1024];
				lws_strncpy(sub, de->d_name, sizeof(sub));
				char *ext = strstr(sub, ".port"); if (ext) *ext = '\0';
				lws_snprintf(p_path, sizeof(p_path), "%s/%s", conf_path, de->d_name);
				int fd_p = open(p_path, O_RDONLY);
				if (fd_p >= 0) {
					char b[64]; ssize_t n = read(fd_p, b, sizeof(b) - 1);
					if (n > 0) {
						b[n] = '\0';
						struct dns_req *req = malloc(sizeof(*req));
						if (req) {
							memset(req, 0, sizeof(*req));
							req->vhd = vhd; req->port = atoi(b);
							lws_strncpy(req->domain, lde->name, sizeof(req->domain));
							lws_dll2_add_tail(&req->list, &vhd->dns_queries);
							int ret = lws_async_dns_query(vhd->context, 0, sub, LWS_ADNS_RECORD_A, dnssec_state_dns_cb, NULL, req, NULL);
							if (ret != LADNS_RET_FOUND && ret != LADNS_RET_CONTINUING) {
								int found = 0;
								lwsl_notice("%s: DNS query failed to start for %s: %d\n", __func__, sub, ret);
								/*
								 * If it failed, it might have called the callback sync
								 * (e.g. LADNS_RET_NXDOMAIN). We check if it's still on our list
								 * before trying to free it ourselves.
								 */
								lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp, vhd->dns_queries.head) {
									if (p == &req->list) {
										found = 1;
										break;
									}
								} lws_end_foreach_dll_safe(p, tp);

								if (found) {
									lws_dll2_remove(&req->list);
									free(req);
								}
							}
						}
					}
					close(fd_p);
				}
			}
		}
		closedir(d);
	}

	/* 2: Check for re-signing needs */

	/* We now treat the directory name as the common name and look for the .zone file */
	lws_snprintf(filepath, sizeof(filepath), "%s/%s/%s.zone", dirpath, lde->name, lde->name);
	if (stat(filepath, &st) != 0) {
		lws_snprintf(filepath, sizeof(filepath), "%s/%s/dns/%s.zone", dirpath, lde->name, lde->name);
		if (stat(filepath, &st) != 0) return 0; /* No zone file found in root or dns/ */
	}

	const char *common_name = lde->name;

	if (common_name[0] && vhd->ops) {
		char zsk_path[1024], ksk_path[1024], wd[1024], sub[1024];
		struct stat st_acme, st_in, st_out;
		int has_acme = 0, has_zone = 0;

		lws_snprintf(wd, sizeof(wd), "%s/domains/%s", vhd->base_dir, common_name);

		/* Add a DS lookup request */
		struct dns_req *req_ds = malloc(sizeof(*req_ds));
		if (req_ds) {
			memset(req_ds, 0, sizeof(*req_ds));
			req_ds->vhd = vhd;
			lws_strncpy(req_ds->domain, lde->name, sizeof(req_ds->domain));
			lws_dll2_add_tail(&req_ds->list, &vhd->dns_queries);
			int ret = lws_async_dns_query(vhd->context, 0, lde->name, (adns_query_type_t)(LWS_ADNS_RECORD_DS | LWS_ADNS_NOCACHE), dnssec_state_ds_cb, NULL, req_ds, NULL);
			if (ret != LADNS_RET_FOUND && ret != LADNS_RET_CONTINUING) {
				int found = 0;
				lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp, vhd->dns_queries.head) {
					if (p == &req_ds->list) { found = 1; break; }
				} lws_end_foreach_dll_safe(p, tp);
				if (found) { lws_dll2_remove(&req_ds->list); free(req_ds); }
			}
		}

		/* 4: Find where the keys and zone actually are */
		lws_snprintf(sub, sizeof(sub), "%s/dns", wd);
		lws_snprintf(filepath, sizeof(filepath), "%s/%s.zone", wd, common_name);
		if (stat(filepath, &st_in) == 0) has_zone = 1;
		else {
			lws_snprintf(filepath, sizeof(filepath), "%s/%s.zone", sub, common_name);
			if (stat(filepath, &st_in) == 0) { has_zone = 1; lws_strncpy(wd, sub, sizeof(wd)); }
		}

		lws_snprintf(zsk_path, sizeof(zsk_path), "%s/%s.zsk.private.jwk", wd, common_name);
		lws_snprintf(ksk_path, sizeof(ksk_path), "%s/%s.ksk.private.jwk", wd, common_name);

		if (access(zsk_path, F_OK) != 0 || access(ksk_path, F_OK) != 0) {
			lwsl_notice("%s: Missing keys for %s at %s, automatically generating...\n", __func__, common_name, wd);
			struct lws_dht_dnssec_keygen_args kargs; memset(&kargs, 0, sizeof(kargs));
			kargs.domain = common_name; kargs.workdir = wd; kargs.curve = "P-384";
			vhd->ops->keygen(vhd->context, &kargs);
		}

		char input_path[1024], output_path[1024], acme_path[1024];
		lws_snprintf(input_path, sizeof(input_path), "%s/%s.zone", wd, common_name);
		lws_snprintf(output_path, sizeof(output_path), "%s/%s.zone.signed", wd, common_name);

		/* 5: Find where the .acme addon is */
		lws_snprintf(acme_path, sizeof(acme_path), "%s.acme", input_path);
		if (stat(acme_path, &st_acme) == 0) {
			has_acme = 1;
			lwsl_notice("%s: Found ACME addon at %s\n", __func__, acme_path);
		} else {
			lws_snprintf(sub, sizeof(sub), "%s/domains/%s/dns/%s.zone.acme", vhd->base_dir, common_name, common_name);
			if (stat(sub, &st_acme) == 0) {
				has_acme = 1;
				/* Alignment: symlink the addon to where do_signzone expects it */
				unlink(acme_path);
				if (symlink(sub, acme_path) < 0)
					lwsl_err("%s: Failed to symlink acme addon %s -> %s\n", __func__, sub, acme_path);
				else
					lwsl_notice("%s: Aligned ACME addon via symlink: %s -> %s\n", __func__, acme_path, sub);
			} else {
				lwsl_notice("%s: No ACME addon found for %s (checked %s and %s)\n", __func__, common_name, acme_path, sub);
			}
		}

		int needs_resign = 0;
		if (has_zone) {
			if (stat(output_path, &st_out) != 0) {
				needs_resign = 1;
			} else {
				if (st_in.st_mtime > st_out.st_mtime) needs_resign = 1;
				else if (has_acme && st_acme.st_mtime > st_out.st_mtime) needs_resign = 1;
			}
		}

		if (needs_resign) {
			lwsl_user("%s: Signing zone for %s (ops: %p, acme: %d, zone: %s)\n", __func__, common_name, vhd->ops, has_acme, input_path);
			append_acme_log(vhd, "Decided to resign zonefile for %s (has_acme: %d)", common_name, has_acme);
			struct lws_dht_dnssec_signzone_args sargs; memset(&sargs, 0, sizeof(sargs));
			sargs.domain = common_name; sargs.workdir = wd;
			sargs.sign_validity_duration = vhd->signature_duration;

			lws_sockaddr46 sa;
			if (!lws_extip_get_best(vhd->context, AF_INET, &sa))
				lws_sa46_write_numeric_address(&sa, sargs.ipv4, sizeof(sargs.ipv4));
#if defined(LWS_WITH_IPV6)
			if (!lws_extip_get_best(vhd->context, AF_INET6, &sa)) {
				lws_sa46_write_numeric_address(&sa, sargs.ipv6, sizeof(sargs.ipv6));

				char path[1024];
				lws_snprintf(path, sizeof(path), "%s/domains/ipv6_suffix.txt", vhd->base_dir);
				int fd = open(path, O_RDONLY);
				if (fd >= 0) {
					char suffix[64];
					ssize_t n = read(fd, suffix, sizeof(suffix) - 1);
					if (n > 0) {
						suffix[n] = '\0';
						for (int i = (int)strlen(suffix) - 1; i >= 0 && (suffix[i] == '\n' || suffix[i] == '\r' || suffix[i] == ' '); i--)
							suffix[i] = '\0';

						if (suffix[0]) {
							char *p = strrchr(sargs.ipv6, ':');
							if (p) {
								lws_strncpy(p + 1, suffix, sizeof(sargs.ipv6) - lws_ptr_diff_size_t(p + 1, sargs.ipv6));
							}
						}
					}
					close(fd);
				}
			}
#endif

			lwsl_notice("%s: IPs for signzone: ipv4='%s', ipv6='%s'\n", __func__, sargs.ipv4, sargs.ipv6);

			vhd->ops->signzone(vhd->context, &sargs);
			append_acme_log(vhd, "Signed zonefile for %s with ipv4=%s ipv6=%s", common_name, sargs.ipv4, sargs.ipv6);

			if (vhd->ops->publish_jws) {
				char jws_path[1024];
				lws_snprintf(jws_path, sizeof(jws_path), "%s/%s.zone.signed.jws", wd, common_name);
				lwsl_notice("%s: Triggering immediate DHT publication for %s\n", __func__, jws_path);
				vhd->ops->publish_jws(vhd->vhost, jws_path);
			}
		}
	}

	return 0;
}

void
global_dnssec_scan_timer_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_timer_global_scan);
	char scan_path[1024];

	// lwsl_notice("%s: Starting global DS scan on 8.8.8.8\n", __func__);
	force_external_dns(vhd->context, "8.8.8.8");
	vhd->scan_type = 1;

	lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);
	lws_dir(scan_path, vhd, scan_dir_cb);
}

void
root_dnssec_scan_timer_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_timer_scan);
	char scan_path[1024];

	lwsl_notice("%s: Starting local DS scan\n", __func__);
	lws_async_dns_server_reload(vhd->context);
	vhd->scan_type = 0;

	lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);
	lws_dir(scan_path, vhd, scan_dir_cb);

	lws_sul_schedule(vhd->context, 0, &vhd->sul_timer_global_scan, global_dnssec_scan_timer_cb, 15 * LWS_US_PER_SEC);
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timer_scan, root_dnssec_scan_timer_cb, 300 * LWS_US_PER_SEC);
}

void
root_monitor_stdin_check_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_timer);
	char buf[1024];
	ssize_t n = read(0, buf, sizeof(buf) - 1);

	if (n > 0) {
		buf[n] = '\0';
		char *nl = strchr(buf, '\n'); if (nl) *nl = '\0';
		lws_strncpy(vhd->auth_token, buf, sizeof(vhd->auth_token));
		lwsl_notice("%s: Received auth token from parent\n", __func__);

		if (!vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf) {
			uint8_t rand[64];
			lws_hex_to_byte_array(vhd->auth_token, rand, 64);
			vhd->auth_jwk.kty = LWS_GENCRYPTO_KTY_OCT;
			vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].len = 64;
			vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf = malloc(64);
			if (vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf)
				memcpy(vhd->auth_jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf, rand, 64);
		}
	}

	if (n < 0 && errno != EAGAIN) {
		lwsl_notice("%s: stdin closed, root monitor terminating\n", __func__);
		lws_context_destroy(vhd->context);
		return;
	}
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, root_monitor_stdin_check_cb, 1 * LWS_US_PER_SEC);
}
