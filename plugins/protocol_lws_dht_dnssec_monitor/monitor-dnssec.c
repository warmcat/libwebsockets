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
			needs_acme = 1;
		} else {
			union lws_tls_cert_info_results ci_from;
			if (!lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_VALIDITY_FROM, &ci_from, 0)) {
				time_t now; time(&now);
				time_t total = ci.time - ci_from.time;
				time_t remaining = ci.time - now;
				if (total > 0 && remaining < (total / 5)) {
					lwsl_notice("%s: [TLS-PROBE] %s:%d SUCCESS: Cert served expires in %s (Triggering ACME - <20%% validity left)\n", __func__, cci->fqdn, cci->port, msg);
					needs_acme = 1;
				} else if (!has_local_cert && !vhd->acme_production) {
					lwsl_notice("%s: [TLS-PROBE] %s:%d SUCCESS: Cert served expires in %s (Triggering ACME - no matching local staging cert)\n", __func__, cci->fqdn, cci->port, msg);
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

	lwsl_notice("%s: DNS query for %s returned %d\n", __func__, ads, n);

	if (n < 0) {
		lwsl_notice("%s: DNS query failed for %s, skipping cert check\n", __func__, ads);
		goto done;
	}

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

done:
	lws_dll2_remove(&req->list);
	free(req);

	return wsi;
}

int
scan_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct vhd *vhd = (struct vhd *)user;
	if (lde->name[0] == '.') return 0;
	if (lde->type == LDOT_DIR || lde->type == LDOT_UNKNOWN) {
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
					int fd = open(p_path, O_RDONLY);
					if (fd >= 0) {
						char buf[64]; ssize_t n = read(fd, buf, sizeof(buf) - 1);
						if (n > 0) {
							buf[n] = '\0';
							struct dns_req *req = malloc(sizeof(*req));
							if (req) {
								memset(req, 0, sizeof(*req));
								req->vhd = vhd; req->port = atoi(buf);
								lws_strncpy(req->domain, lde->name, sizeof(req->domain));
								lws_dll2_add_tail(&req->list, &vhd->dns_queries);
								if (lws_async_dns_query(vhd->context, 0, sub, LWS_ADNS_RECORD_A, dnssec_state_dns_cb, NULL, req, NULL) < 0) {
									lws_dll2_remove(&req->list); free(req);
								}
							}
						}
						close(fd);
					}
				}
			}
			closedir(d);
		}
	}
	return 0;
}

void
root_dnssec_scan_timer_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_timer_scan);
	char scan_path[1024];
	lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);
	lws_dir(scan_path, vhd, scan_dir_cb);
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
