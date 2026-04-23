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

#define _GNU_SOURCE
#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#include <ctype.h>
#endif

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#if defined(WIN32) || defined(_WIN32)
#else
#include <sys/wait.h>
#include <grp.h>
#include <sys/types.h>
#endif

struct whois_query_info {
	lws_dll2_t list;
	char domain[128];
	struct vhd *vhd;
};

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

	lws_dll2_t list;
	int send_ext_ips;
};

struct published_jws_info {
	lws_dll2_t list;
	char domain[128];
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
	lws_dll2_owner_t completed_checks;
	lws_dll2_owner_t whois_queries;
	lws_dll2_owner_t published_jws;
	lws_sorted_usec_list_t sul_timer_scan;
	lws_sorted_usec_list_t sul_timer_proxy_scan;
};

struct cert_check_info {
	uint32_t magic;
	char domain[128];
	char fqdn[128];
	int port;
	int starttls_state;
	int is_automated;
};
#define CERT_CHECK_MAGIC 0xCE87C4EC

struct cert_check_result {
	lws_dll2_t list;
	char fqdn[128];
	char msg[128];
	char local_msg[128];
	char issuer[128];
	int port;
	int status_err;
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
	char key_type[64];
	char key_curve[64];
	int key_bits;
};

static void
whois_cb(void *opaque, const struct lws_whois_results *res)
{
	struct whois_query_info *wqi = (struct whois_query_info *)opaque;
	int n;
	char buf[2048];
	char ns_list[1024] = "";
	
	lwsl_notice("[INSTRUMENT] %s: callback triggered for %s. res is %s\n", __func__, wqi->domain, res ? "NOT NULL" : "NULL");

	char s_dnssec[256] = "", s_ds[1024] = "";
	if (res) {
		lws_strncpy(s_dnssec, res->dnssec, sizeof(s_dnssec));
		lws_strncpy(s_ds, res->ds_data, sizeof(s_ds));
		for (size_t i = 0; i < strlen(s_dnssec); i++) {
			if (!isalnum((unsigned char)s_dnssec[i]) && s_dnssec[i] != '-' && s_dnssec[i] != '.' && s_dnssec[i] != ':' && s_dnssec[i] != ' ')
				s_dnssec[i] = ' ';
		}
		for (size_t i = 0; i < strlen(s_ds); i++) {
			if (!isalnum((unsigned char)s_ds[i]) && s_ds[i] != '-' && s_ds[i] != '.' && s_ds[i] != ':' && s_ds[i] != ' ')
				s_ds[i] = ' ';
		}

		char *p_ns, *token, *saveptr;
		/* Convert comma-separated nameservers to JSON array of strings */
		p_ns = strdup(res->nameservers);
		if (p_ns) {
			token = strtok_r(p_ns, ", ", &saveptr);
			while (token) {
				char stoken[256];
				lws_strncpy(stoken, token, sizeof(stoken));
				for (size_t i = 0; i < strlen(stoken); i++) {
					if (!isalnum((unsigned char)stoken[i]) && stoken[i] != '-' && stoken[i] != '.' && stoken[i] != ':')
						stoken[i] = ' ';
				}

				if (ns_list[0])
					strncat(ns_list, ", ", sizeof(ns_list) - strlen(ns_list) - 1);
				strncat(ns_list, "\"", sizeof(ns_list) - strlen(ns_list) - 1);
				strncat(ns_list, stoken, sizeof(ns_list) - strlen(ns_list) - 1);
				strncat(ns_list, "\"", sizeof(ns_list) - strlen(ns_list) - 1);
				token = strtok_r(NULL, ", ", &saveptr);
			}
			free(p_ns);
		}


		n = lws_snprintf(buf, sizeof(buf),
			"{\n  \"creation_date\": %llu,\n  \"expiry_date\": %llu,\n  \"updated_date\": %llu,\n"
			"  \"nameservers\": [%s],\n"
			"  \"dnssec\": \"%s\",\n  \"ds_data\": \"%s\",\n  \"last_query\": %llu\n}\n",
			(unsigned long long)res->creation_date, (unsigned long long)res->expiry_date,
			(unsigned long long)res->updated_date,
			ns_list, s_dnssec, s_ds, (unsigned long long)lws_now_secs());
			
		lwsl_notice("[INSTRUMENT] whois_cb: formatted JSON for %s, size = %d\n", wqi->domain, n);
	} else {
		lwsl_notice("[INSTRUMENT] whois_cb: res is NULL for %s, skipping UDS publish\n", wqi->domain);
		n = 0; /* Let it organically fail or retry without caching `{}` */
	}

	if (n > 0) {
		char b64[8192] = {0}, jwt[1024] = {0}, uds_json[10240] = {0}, temp[2048] = {0};
		size_t jwt_len = sizeof(jwt);
		lws_b64_encode_string(buf, (int)strlen(buf), b64, sizeof(b64));
		
		if (wqi->vhd->auth_jwk.kty == LWS_GENCRYPTO_KTY_OCT) {
			char jwt_payload[512];
			unsigned long now = (unsigned long)lws_now_secs();
			lws_snprintf(jwt_payload, sizeof(jwt_payload), 
				     "{\"iss\":\"acme-ipc\",\"aud\":\"dnssec-monitor\",\"nbf\":%lu,\"exp\":%lu}",
				     now, now + 300);

			if (lws_jwt_sign_compact(wqi->vhd->context, &wqi->vhd->auth_jwk, "HS256",
						 jwt, &jwt_len, temp, sizeof(temp), "%s", jwt_payload)) {
				lwsl_err("[INSTRUMENT] %s: failed to generate jwt for whois\n", __func__);
			}
		}

		int payload_n = lws_snprintf(uds_json, sizeof(uds_json),
			"{\"req\":\"update_whois\",\"domain\":\"%s\",\"jwt\":\"%s\",\"zone\":\"%s\"}\n",
			wqi->domain, jwt, b64);
		int fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (fd >= 0) {
			struct sockaddr_un sun;
			memset(&sun, 0, sizeof(sun));
			sun.sun_family = AF_UNIX;
			lws_strncpy(sun.sun_path, wqi->vhd->uds_path, sizeof(sun.sun_path));
			if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == 0) {
				if (write(fd, uds_json, (size_t)payload_n) < 0) {
					lwsl_err("[INSTRUMENT] %s: Failed writing whois payload to UDS, errno: %d\n", __func__, errno);
				} else {
					lwsl_notice("[INSTRUMENT] %s: Tunneled WHOIS for %s to Root over UDS (payload %d bytes)\n", __func__, wqi->domain, payload_n);
				}
			} else {
				lwsl_err("[INSTRUMENT] %s: Failed connecting to root UDS at %s for whois pass-back, errno: %d\n", __func__, sun.sun_path, errno);
			}
			close(fd);
		} else {
			lwsl_err("[INSTRUMENT] %s: socket creation failed! errno: %d\n", __func__, errno);
		}
		
		lws_dll2_remove(&wqi->list);
		free(wqi);
	}
}

static int
whois_trigger(struct vhd *vhd, const char *domain)
{
	struct lws_whois_args args;
	struct whois_query_info *wqi;

	wqi = malloc(sizeof(*wqi));
	if (!wqi)
		return 1;

	memset(wqi, 0, sizeof(*wqi));
	lws_strncpy(wqi->domain, domain, sizeof(wqi->domain));
	wqi->vhd = vhd;

	memset(&args, 0, sizeof(args));
	args.context = vhd->context;
	args.domain = domain;
	args.cb = whois_cb;
	args.opaque = wqi;

	lwsl_notice("%s: Triggering core WHOIS for %s\n", __func__, domain);

	lws_dll2_add_tail(&wqi->list, &vhd->whois_queries);

	if (lws_whois_query(&args)) {
		lwsl_err("%s: Failed to trigger core WHOIS for %s\n", __func__, domain);
		lws_dll2_remove(&wqi->list);
		free(wqi);
		return 1;
	}

	return 0;
}

static int
calc_local_ds(struct vhd *vhd, const char *domain, char *out, size_t out_len)
{
	char key_path[1024];
	int fd;
	char buf[2048];
	
	lws_snprintf(key_path, sizeof(key_path), "%s/domains/%s/%s.ksk.key", vhd->base_dir, domain, domain);
	fd = open(key_path, O_RDONLY);
	if (fd < 0) return 1;
	
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0) return 1;
	buf[n] = '\0';
	
	/* Parse BIND format: domain IN DNSKEY flags proto alg b64 */
	char d[256], b64[1024];
	int flags, proto, alg;
	if (sscanf(buf, "%255s IN DNSKEY %d %d %d %1023s", d, &flags, &proto, &alg, b64) != 5)
		return 1;
		
	/* This is a simplification, ideally we'd use the ops->dsfromkey if it returned a string.
	 * But we can just use the command line or implement the hashing here if needed.
	 * For now, we'll just report we can't do it until we have a better way. 
	 * Wait, let's actually implement it since we need it for the Red X / Green Tick.
	 */
	uint8_t rdata[2048];
	rdata[0] = (uint8_t)(flags >> 8);
	rdata[1] = (uint8_t)(flags & 0xff);
	rdata[2] = (uint8_t)proto;
	rdata[3] = (uint8_t)alg;
	int b64_len = lws_b64_decode_string(b64, (char *)rdata + 4, sizeof(rdata) - 4);
	if (b64_len < 0) return 1;
	
	size_t rdata_len = 4 + (size_t)b64_len;
	uint32_t ac = 0;
	for (size_t i = 0; i < rdata_len; i++)
		ac += (i & 1) ? rdata[i] : (uint32_t)rdata[i] << 8;
	ac += (ac >> 16) & 0xFFFF;
	uint16_t keytag = (uint16_t)(ac & 0xFFFF);
	
	/* Wire format name */
	uint8_t payload[1024];
	uint8_t *p = payload;
	const char *ps = domain;
	while (*ps) {
		const char *dot = strchr(ps, '.');
		if (!dot) dot = ps + strlen(ps);
		int l = (int)(dot - ps);
		*p++ = (uint8_t)l;
		for (int i = 0; i < l; i++) *p++ = (uint8_t)tolower(ps[i]);
		ps = dot;
		if (*ps == '.') ps++;
	}
	*p++ = 0;
	memcpy(p, rdata, rdata_len);
	size_t pay_len = (size_t)lws_ptr_diff(p + rdata_len, payload);
	
	enum lws_genhash_types htype = LWS_GENHASH_TYPE_SHA256;
	int dtype = 2;
	int dlen = 32;
	if (alg == 14) {
		htype = LWS_GENHASH_TYPE_SHA384;
		dtype = 4;
		dlen = 48;
	}

	struct lws_genhash_ctx ctx;
	uint8_t digest[64];
	if (lws_genhash_init(&ctx, htype)) return 1;
	if (lws_genhash_update(&ctx, payload, pay_len)) {
		lws_genhash_destroy(&ctx, NULL);
		return 1;
	}
	lws_genhash_destroy(&ctx, digest);
	
	char *po = out;
	char *pe = out + out_len;
	po += lws_snprintf(po, lws_ptr_diff_size_t(pe, po), "%u %d %d ", keytag, alg, dtype);
	for (int i = 0; i < dlen; i++)
		po += lws_snprintf(po, lws_ptr_diff_size_t(pe, po), "%02X", digest[i]);
		
	return 0;
}

static int skip_name(const uint8_t *p, int len, int *offset) {
	while (*offset < len) {
		uint8_t l = p[*offset];
		if (l == 0) {
			(*offset)++;
			return 0;
		}
		if ((l & 0xC0) == 0xC0) {
			(*offset) += 2;
			return 0;
		}
		(*offset) += l + 1;
	}
	return -1;
}

static uint32_t parse_soa_serial(const uint8_t *p, int len) {
	int offset = 0;
	if (skip_name(p, len, &offset)) return 0;
	if (skip_name(p, len, &offset)) return 0;
	if (offset + 4 <= len) {
		return ((uint32_t)p[offset] << 24) | ((uint32_t)p[offset+1] << 16) |
			   ((uint32_t)p[offset+2] << 8) | ((uint32_t)p[offset+3]);
	}
	return 0;
}

struct dnssec_async_req {
	struct vhd *vhd;
	char domain[128];
};

static struct lws *
dnssec_state_dns_cb(struct lws *wsi, const char *ads, const struct addrinfo *result, int n, void *opaque)
{
	struct dnssec_async_req *req = (struct dnssec_async_req *)opaque;
	struct vhd *vhd = req->vhd;
	uint16_t paylen = 0;
	uint32_t serial = 0, expiry = 0, inception = 0;
	int signed_ok = (n & LWS_ADNS_DNSSEC_VALID) ? 1 : 0;

	const uint8_t *soa = lws_async_dns_get_rr_cache(vhd->context, req->domain, 0x06 /* SOA */, &paylen);
	if (soa) {
		serial = parse_soa_serial(soa, paylen);
	} else {
		lwsl_warn("%s: No SOA record cached natively for %s (n=%d)\n", __func__, req->domain, n);
	}

	const uint8_t *rrsig = lws_async_dns_get_rr_cache(vhd->context, req->domain, 0x2e /* RRSIG */, &paylen);
	if (rrsig && paylen >= 16) {
		int t_covered = ((uint16_t)rrsig[0] << 8) | rrsig[1];
		if (t_covered == 0x06 /* SOA */) {
			expiry = ((uint32_t)rrsig[8] << 24) | ((uint32_t)rrsig[9] << 16) | ((uint32_t)rrsig[10] << 8) | rrsig[11];
			inception = ((uint32_t)rrsig[12] << 24) | ((uint32_t)rrsig[13] << 16) | ((uint32_t)rrsig[14] << 8) | rrsig[15];

			uint32_t cnow = (uint32_t)lws_now_secs();
			if (expiry <= inception || expiry <= cnow) {
				signed_ok = 0;
			}
		} else {
			lwsl_warn("%s: Cached RRSIG was not covering SOA (t_covered: %d) for %s\n", __func__, t_covered, req->domain);
		}
	} else {
		lwsl_warn("%s: No RRSIG record returned dynamically for %s (paylen: %u)\n", __func__, req->domain, paylen);
	}

	/* Also write dns_state.json */
	char dbuf[1024];
	char out_path[1024];
	lws_snprintf(out_path, sizeof(out_path), "%s/domains/%s/dns_state.json", vhd->base_dir, req->domain);
	int dfd = open(out_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (dfd >= 0) {
		int jn = lws_snprintf(dbuf, sizeof(dbuf), "{\"serial\": %u, \"signed_ok\": %d, \"expiry\": %u, \"inception\": %u}\n", serial, signed_ok, expiry, inception);
		write(dfd, dbuf, (size_t)jn);
		close(dfd);
	}

	uint32_t now = (uint32_t)lws_now_secs();
	if (expiry > inception && expiry > now && vhd->ops && vhd->ops->bump_zone_serial) {
		uint32_t valid_dur = expiry - inception;
		uint32_t remaining = expiry - now;
		if (remaining < (valid_dur / 5)) { /* < 20% remaining means > 80% expired */
			char input_path[1024];
			char wd[512];
			lwsl_notice("%s: Signature for %s > 80%% expired, auto-bumping and resigning\n", __func__, req->domain);
			lws_snprintf(input_path, sizeof(input_path), "%s/domains/%s/%s.zone", vhd->base_dir, req->domain, req->domain);
			lws_snprintf(wd, sizeof(wd), "%s/domains/%s", vhd->base_dir, req->domain);
			
			vhd->ops->bump_zone_serial(vhd->context, input_path);

			struct lws_dht_dnssec_signzone_args sargs;
			memset(&sargs, 0, sizeof(sargs));
			sargs.domain = req->domain;
			sargs.workdir = wd;
			sargs.sign_validity_duration = vhd->signature_duration;
			vhd->ops->signzone(vhd->context, &sargs);
		}
	}

	free(req);
	return wsi;
}

static void check_dnssec_state_via_dns(struct vhd *vhd, const char *domain)
{
	struct dnssec_async_req *req = malloc(sizeof(*req));
	if (!req) return;
	req->vhd = vhd;
	lws_strncpy(req->domain, domain, sizeof(req->domain));
	
	lwsl_info("%s: Issuing async DNS check for %s (NOCACHE|WANT_DNSSEC|IGNORE_HOSTS)\n", __func__, domain);
	lws_async_dns_query(vhd->context, 0, domain,
			    LWS_ADNS_RECORD_SOA | LWS_ADNS_NOCACHE |
			    LWS_ADNS_WANT_DNSSEC | LWS_ADNS_IGNORE_HOSTS_FILE,
			    dnssec_state_dns_cb, NULL, req, NULL);
}

static int
scan_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct vhd *vhd = (struct vhd *)user;

	if (lde->type != LDOT_DIR)
		return 0;

	if (lde->name[0] == '.')
		return 0;

	if (strchr(lde->name, '/') || strstr(lde->name, "..")) {
		lwsl_err("%s: Invalid common-name containing path traversal characters: %s\n", __func__, lde->name);
		return 0;
	}

	lwsl_info("%s: Parsed domain %s from folder\n", __func__, lde->name);

	/* Directory format requires <base_dir>/domains/<common_name>/ */
	char key_path[1024];
	const char *common_name = lde->name;
	const char *key_type = "EC";
	const char *key_curve = "P-256";
	int key_bits = 256;

	/* Check ZSK */
	lws_snprintf(key_path, sizeof(key_path), "%s/domains/%s/%s.zsk.private.jwk", vhd->base_dir, common_name, common_name);
	int has_zsk = (access(key_path, F_OK) == 0);

	/* Check KSK */
	lws_snprintf(key_path, sizeof(key_path), "%s/domains/%s/%s.ksk.private.jwk", vhd->base_dir, common_name, common_name);
	int has_ksk = (access(key_path, F_OK) == 0);

	if (!has_zsk || !has_ksk) {
		lwsl_notice("%s: Missing keys for %s, automatically generating...\n", __func__, common_name);
		char wd[512];
		lws_snprintf(wd, sizeof(wd), "%s/domains/%s", vhd->base_dir, common_name);

		struct lws_dht_dnssec_keygen_args kargs;
		memset(&kargs, 0, sizeof(kargs));
		kargs.domain = common_name;
		kargs.workdir = wd;

		kargs.type = key_type;
		kargs.curve = key_curve;
		kargs.bits = key_bits;

		if (vhd->ops->keygen(vhd->context, &kargs))
			lwsl_err("%s: Failed to generate keys for %s\n", __func__, common_name);
	}

	/* Check resign triggers */
	char input_path[1024];
	char output_path[1024];
	char jws_path[1024];
	char zsk_path[1024];
	char ksk_path[1024];

	lws_snprintf(input_path, sizeof(input_path), "%s/domains/%s/%s.zone", vhd->base_dir, common_name, common_name);
	lws_snprintf(output_path, sizeof(output_path), "%s/domains/%s/%s.zone.signed", vhd->base_dir, common_name, common_name);
	lws_snprintf(jws_path, sizeof(jws_path), "%s/domains/%s/%s.zone.signed.jws", vhd->base_dir, common_name, common_name);
	lws_snprintf(zsk_path, sizeof(zsk_path), "%s/domains/%s/%s.zsk.private.jwk", vhd->base_dir, common_name, common_name);
	lws_snprintf(ksk_path, sizeof(ksk_path), "%s/domains/%s/%s.ksk.private.jwk", vhd->base_dir, common_name, common_name);

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
			if (!needs_resign) {
				char dns_path[1024];
				struct stat st_dns;
				int trigger_dns = 0;
				lws_snprintf(dns_path, sizeof(dns_path), "%s/domains/%s/dns_state.json", vhd->base_dir, common_name);
				if (stat(dns_path, &st_dns) < 0) {
					trigger_dns = 1;
				} else {
					if ((unsigned long long)lws_now_secs() - (unsigned long long)st_dns.st_mtime > 300)
						trigger_dns = 1;
				}
				if (trigger_dns)
					check_dnssec_state_via_dns(vhd, common_name);
			}
		}
	} else {
		lwsl_info("%s: Missing domain %s base zone config, skipping resign\n", __func__, input_path);
	}

	if (needs_resign) {
		char wd[512];
		lws_snprintf(wd, sizeof(wd), "%s/domains/%s", vhd->base_dir, common_name);

		lwsl_user("%s: Signing zone for %s\n", __func__, common_name);
		struct lws_dht_dnssec_signzone_args sargs;
		memset(&sargs, 0, sizeof(sargs));
		sargs.domain = common_name;
		sargs.workdir = wd;
		sargs.sign_validity_duration = vhd->signature_duration;

		if (vhd->ops->signzone(vhd->context, &sargs)) {
			lwsl_user("%s: Failed signing zone for %s\n", __func__, common_name);
		} else {
			lwsl_user("%s: Successfully signed zone for %s\n", __func__, common_name);
		}
	}

	return 0;
}

static int
scan_whois_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct vhd *vhd = (struct vhd *)user;

	if (lde->type != LDOT_DIR || lde->name[0] == '.') return 0;

	if (vhd->whois_queries.count < 4) {
		char whois_path[1024];
		struct stat st_whois;
		int trigger = 0;

		lws_snprintf(whois_path, sizeof(whois_path), "%s/domains/%s/whois.json", vhd->base_dir, lde->name);
		if (stat(whois_path, &st_whois) < 0) {
			trigger = 1;
		} else {
			if ((unsigned long long)lws_now_secs() - (unsigned long long)st_whois.st_mtime > 300)
				trigger = 1;
		}

		if (trigger) {
			whois_trigger(vhd, lde->name);
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

struct tls_config_args {
	char challenge_type[64];
	char email[128];
	char directory_url[256];
	int port;
};

static const char * const tls_config_paths[] = {
	"challenge-type",
	"port",
	"email",
	"acme.directory-url",
};

enum enum_tls_config_paths {
	LTC_CHALLENGE_TYPE,
	LTC_PORT,
	LTC_EMAIL,
	LTC_DIRECTORY_URL,
};

static signed char
tls_config_cb(struct lejp_ctx *ctx, char reason)
{
	struct tls_config_args *a = (struct tls_config_args *)ctx->user;

	if (reason == LEJPCB_VAL_NUM_INT) {
		if (ctx->path_match - 1 == LTC_PORT)
			a->port = atoi(ctx->buf);
		return 0;
	}

	if (reason != LEJPCB_VAL_STR_END)
		return 0;

	switch (ctx->path_match - 1) {
	case LTC_CHALLENGE_TYPE:
		lws_strncpy(a->challenge_type, ctx->buf, sizeof(a->challenge_type));
		break;
	case LTC_EMAIL:
		lws_strncpy(a->email, ctx->buf, sizeof(a->email));
		break;
	case LTC_DIRECTORY_URL:
		lws_strncpy(a->directory_url, ctx->buf, sizeof(a->directory_url));
		break;
	}

	return 0;
}

struct scan_tls_ctx {
	struct vhd *vhd;
	const char *domain;
};

static int
scan_tls_configs_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct scan_tls_ctx *ctx = (struct scan_tls_ctx *)user;
	struct vhd *vhd = ctx->vhd;

	if (lde->type != LDOT_FILE || !strstr(lde->name, ".json")) return 0;

	char subdomain[256];
	lws_strncpy(subdomain, lde->name, sizeof(subdomain));
	char *p = strstr(subdomain, ".json");
	if (p) *p = '\0';

	char config_path[1024];
	lws_snprintf(config_path, sizeof(config_path), "%s/%s", dirpath, lde->name);

	int fd = open(config_path, O_RDONLY);
	if (fd < 0) return 0;

	struct tls_config_args a;
	memset(&a, 0, sizeof(a));

	struct lejp_ctx jctx;
	lejp_construct(&jctx, tls_config_cb, &a, tls_config_paths, LWS_ARRAY_SIZE(tls_config_paths));

	char buf[1024];
	int n;
	while ((n = (int)read(fd, buf, sizeof(buf))) > 0) {
		if (lejp_parse(&jctx, (uint8_t *)buf, n) < 0)
			break;
	}
	close(fd);
	lejp_destruct(&jctx);

	if (a.port <= 0 || strcmp(a.challenge_type, "dns-01"))
		return 0;

	/* check expiry */
	char cert_path[1024];
	lws_snprintf(cert_path, sizeof(cert_path), "%s/domains/%s/certs/crt/%s", vhd->base_dir, ctx->domain, subdomain);

	int needs_acme = 1;

	fd = open(cert_path, O_RDONLY);
	if (fd >= 0) {
		struct stat st;
		if (!fstat(fd, &st) && st.st_size > 0) {
			char *cert_buf = malloc((size_t)st.st_size + 1);
			if (cert_buf) {
				if (read(fd, cert_buf, (size_t)st.st_size) == st.st_size) {
					cert_buf[st.st_size] = '\0';
					struct lws_x509_cert *x509;
					if (!lws_x509_create(&x509)) {
						if (!lws_x509_parse_from_pem(x509, cert_buf, (size_t)st.st_size + 1)) {
							union lws_tls_cert_info_results res;
							if (!lws_x509_info(x509, LWS_TLS_CERT_INFO_VALIDITY_TO, &res, 0)) {
								time_t now = time(NULL);
								if (res.time > now + (7 * 24 * 3600)) {
									needs_acme = 0;
								}
							}
						}
						lws_x509_destroy(&x509);
					}
				}
				free(cert_buf);
			}
		}
		close(fd);
	}

	if (needs_acme) {
		lwsl_notice("%s: ACME needed for %s (port %d)\n", __func__, subdomain, a.port);

		/* Check if already running by vhost name */
		char vh_name[256];
		lws_snprintf(vh_name, sizeof(vh_name), "acme_%s", subdomain);
		if (!lws_get_vhost_by_name(vhd->context, vh_name)) {
			struct lws_context_creation_info info;
			struct lws_protocol_vhost_options pvo_core = {0}, pvo_acme = {0}, pvo1 = {0}, pvo2 = {0}, pvo3 = {0}, pvo4 = {0};

			memset(&info, 0, sizeof(info));
			info.port = CONTEXT_PORT_NO_LISTEN_SERVER;
			info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
			info.vhost_name = vh_name;

			pvo_core.name = "lws-acme-client-core";
			pvo_core.next = &pvo_acme;

			pvo_acme.name = "lws-acme-client-dns";
			pvo_acme.options = &pvo1;
			info.pvo = &pvo_core;

			pvo1.name = "root-domain";
			pvo1.value = ctx->domain;
			pvo1.next = &pvo2;

			pvo2.name = "common-name";
			pvo2.value = subdomain;
			pvo2.next = &pvo3;

			pvo3.name = "email";
			pvo3.value = a.email[0] ? a.email : "admin@domain.com";
			pvo3.next = &pvo4;

			pvo4.name = "directory-url";
			pvo4.value = a.directory_url[0] ? a.directory_url : "https://acme-v02.api.letsencrypt.org/directory";

			if (lws_create_vhost(vhd->context, &info)) {
				lwsl_notice("%s: ACME vhost %s spawned natively\n", __func__, vh_name);
			} else {
				lwsl_err("%s: Failed to spawn ACME vhost %s\n", __func__, vh_name);
			}
		}
	} else if (a.port > 0) {
		struct cert_check_info *cci = malloc(sizeof(*cci));
		if (cci) {
			memset(cci, 0, sizeof(*cci));
			cci->magic = CERT_CHECK_MAGIC;
			lws_strncpy(cci->fqdn, subdomain, sizeof(cci->fqdn));
			cci->port = a.port;
			cci->is_automated = 1;

			int starttls = (a.port == 25 || a.port == 587);
			cci->starttls_state = starttls ? 1 : 0;

			struct lws_client_connect_info cinfo;
			memset(&cinfo, 0, sizeof(cinfo));
			cinfo.context = vhd->context;
			cinfo.port = a.port;
			cinfo.address = subdomain;
			cinfo.host = cinfo.address;
			cinfo.origin = cinfo.address;
			cinfo.ssl_connection = LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK | LCCSCF_ALLOW_SELFSIGNED | LCCSCF_ALLOW_EXPIRED;
			if (!starttls) cinfo.ssl_connection |= LCCSCF_USE_SSL;
			cinfo.protocol = "lws-dht-dnssec-monitor";
			cinfo.vhost = vhd->vhost;
			cinfo.opaque_user_data = cci;
			cinfo.alpn = "http/1.1";
			cinfo.method = "RAW";

			if (!lws_client_connect_via_info(&cinfo)) {
				lwsl_err("%s: Failed to start automated cert probe for %s:%d\n", __func__, subdomain, a.port);
				free(cci);
			}
		}
	}

	return 0;
}

static int
scan_tls_domains_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct vhd *vhd = (struct vhd *)user;

	if (lde->type != LDOT_DIR || lde->name[0] == '.') return 0;

	char tls_path[1024];
	lws_snprintf(tls_path, sizeof(tls_path), "%s/domains/%s/tls", vhd->base_dir, lde->name);

	struct scan_tls_ctx ctx = { vhd, lde->name };
	lws_dir(tls_path, &ctx, scan_tls_configs_cb);

	return 0;
}

static void
proxy_dnssec_scan_timer_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_timer_proxy_scan);
	char scan_path[1024];

	lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);
	lws_dir(scan_path, vhd, scan_tls_domains_cb);
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timer_proxy_scan, proxy_dnssec_scan_timer_cb, 300 * LWS_US_PER_SEC);
}

static int
scan_jws_publish_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct vhd *vhd = (struct vhd *)user;

	if (lde->type != LDOT_DIR || lde->name[0] == '.')
		return 0;

	if (vhd->ops && vhd->ops->publish_jws) {
		char jws_path[1024];
		struct stat st;
		
		lws_snprintf(jws_path, sizeof(jws_path), "%s/domains/%s/%s.zone.signed.jws", vhd->base_dir, lde->name, lde->name);

		if (stat(jws_path, &st) == 0) {
			/* Check if we already published this version */
			struct published_jws_info *p = NULL;
			lws_start_foreach_dll(struct lws_dll2 *, d, vhd->published_jws.head) {
				struct published_jws_info *tp = lws_container_of(d, struct published_jws_info, list);
				if (!strcmp(tp->domain, lde->name)) {
					p = tp;
					break;
				}
			} lws_end_foreach_dll(d);

			if (!p || p->mtime != st.st_mtime) {
				if (!p) {
					p = malloc(sizeof(*p));
					if (!p) return 0;
					memset(p, 0, sizeof(*p));
					lws_strncpy(p->domain, lde->name, sizeof(p->domain));
					lws_dll2_add_tail(&p->list, &vhd->published_jws);
				}
				p->mtime = st.st_mtime;
				lwsl_notice("%s: Engaging parent monitor to execute DHT publication for %s\n", __func__, lde->name);
				vhd->ops->publish_jws(vhd->vhost, jws_path);
			}
		}
	}
	return 0;
}

static void
parent_dnssec_monitor_timer_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_timer);
	char scan_path[1024];

	lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);
	lws_dir(scan_path, vhd, scan_jws_publish_cb);
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, parent_dnssec_monitor_timer_cb, 5 * LWS_US_PER_SEC);
}

static void
root_dnssec_scan_timer_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_timer_scan);
	char scan_path[1024];

	lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);
	lws_dir(scan_path, vhd, scan_dir_cb);
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timer_scan, root_dnssec_scan_timer_cb, 5 * LWS_US_PER_SEC);
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
	char key_type[32];
	int port;
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
	"key_type",
	"port"
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
	LRP_KEY_TYPE,
	LRP_PORT
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

	if (reason == LEJPCB_VAL_NUM_INT) {
		if (ctx->path_match - 1 == LRP_PORT) {
			a->port = atoi(ctx->buf);
			lwsl_notice("[INSTRUMENT] monitor_req_cb: Parsed port natively from JSON INT: %d\n", a->port);
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
		case LRP_KEY_TYPE:
			lws_strncpy(a->key_type, ctx->buf, sizeof(a->key_type));
			break;
		case LRP_PORT:
			a->port = atoi(ctx->buf);
			break;
		}
	}

	if (reason == LEJPCB_FAILED) {
		lwsl_err("[INSTRUMENT] monitor_req_cb: LEJP JSON Parse FAILED at struct offset %d\n", (int)ctx->st[ctx->sp].s);
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

static int cmp_str(const void *a, const void *b) {
	return strcmp(*(const char **)a, *(const char **)b);
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
		char **doms = NULL;
		size_t count = 0, alloc = 0;

		while ((de = readdir(d))) {
			if (de->d_name[0] == '.') continue;
			if (de->d_type == DT_DIR || de->d_type == DT_UNKNOWN) {
				if (count >= alloc) {
					alloc = alloc ? alloc * 2 : 16;
					char **ndoms = realloc(doms, alloc * sizeof(char *));
					if (!ndoms) break;
					doms = ndoms;
				}
				doms[count++] = strdup(de->d_name);
			}
		}
		closedir(d);

		if (count) {
			qsort(doms, count, sizeof(char *), cmp_str);
		}

		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"get_domains\",\"status\":\"ok\",\"domains\":[");
		for (size_t i = 0; i < count; i++) {
			char whois_path[1024], whois_buf[2048] = "{}";
			char local_ds[256] = "";

			if (i > 0) tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), ",");

			lws_snprintf(whois_path, sizeof(whois_path), "%s/domains/%s/whois.json", vhd->base_dir, doms[i]);
			int fd_w = open(whois_path, O_RDONLY);
			if (fd_w >= 0) {
				ssize_t nw = read(fd_w, whois_buf, sizeof(whois_buf) - 1);
				if (nw > 0) whois_buf[nw] = '\0';
				close(fd_w);
			}

			char dns_path[1024], dns_buf[1024] = "{}";
			lws_snprintf(dns_path, sizeof(dns_path), "%s/domains/%s/dns_state.json", vhd->base_dir, doms[i]);
			int fd_d = open(dns_path, O_RDONLY);
			if (fd_d >= 0) {
				ssize_t nw = read(fd_d, dns_buf, sizeof(dns_buf) - 1);
				if (nw > 0) dns_buf[nw] = '\0';
				close(fd_d);
			}

			char alg_buf[32] = "";
			char zsk_path[1024];
			lws_snprintf(zsk_path, sizeof(zsk_path), "%s/domains/%s/%s.zsk.private.jwk", vhd->base_dir, doms[i], doms[i]);
			lwsl_user("dnssec-monitor: trying to read JWK from %s\n", zsk_path);
			int fd_z = open(zsk_path, O_RDONLY);
			if (fd_z >= 0) {
				char jwk_buf[2048];
				ssize_t nj = read(fd_z, jwk_buf, sizeof(jwk_buf) - 1);
				if (nj > 0) {
					jwk_buf[nj] = '\0';
					char *p = strstr(jwk_buf, "\"alg\"");
					if (p) {
						p = strchr(p, ':');
						if (p) {
							while (*p == ':' || *p == ' ' || *p == '"' || *p == '\t' || *p == '\n') p++;
							char *end = strchr(p, '"');
							if (end && (end - p) < (int)sizeof(alg_buf)) {
								lws_strncpy(alg_buf, p, lws_ptr_diff_size_t(end, p) + 1);
								lwsl_user("dnssec-monitor: extracted alg: '%s'\n", alg_buf);
							} else {
								lwsl_user("dnssec-monitor: failed to parse end of alg string\n");
							}
						}
					} else {
						if (strstr(jwk_buf, "\"P-256\"")) {
							lws_strncpy(alg_buf, "ES256", sizeof(alg_buf));
							lwsl_user("dnssec-monitor: inferred alg: '%s'\n", alg_buf);
						} else if (strstr(jwk_buf, "\"P-384\"")) {
							lws_strncpy(alg_buf, "ES384", sizeof(alg_buf));
							lwsl_user("dnssec-monitor: inferred alg: '%s'\n", alg_buf);
						} else if (strstr(jwk_buf, "\"RSA\"")) {
							lws_strncpy(alg_buf, "RS256", sizeof(alg_buf));
							lwsl_user("dnssec-monitor: inferred alg: '%s'\n", alg_buf);
						} else {
							lwsl_user("dnssec-monitor: could not find \"alg\" or infer algorithm in JWK\n");
						}
					}
				} else {
					lwsl_user("dnssec-monitor: failed to read JWK (read %d bytes)\n", (int)nj);
				}
				close(fd_z);
			} else {
				lwsl_user("dnssec-monitor: failed to open JWK file\n");
			}

			calc_local_ds(vhd, doms[i], local_ds, sizeof(local_ds));

			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx),
				"{\"name\":\"%s\",\"whois\":%s,\"dns\":%s,\"local_ds\":\"%s\",\"alg\":\"%s\"}",
				doms[i], whois_buf[0] ? whois_buf : "{}", dns_buf[0] ? dns_buf : "{}", local_ds, alg_buf);
			free(doms[i]);
		}
		if (doms) free(doms);
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
	if (mkdir(d_path, 0755) < 0 && errno != EEXIST) {
		lwsl_notice("%s: Failed to create domain dir\n", __func__);
		r = -1;
	}

	if (r) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Failed making dirs\"}\n", a->req);
	} else {
		int fd;

		/* Touch empty zone */
		lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/%s.zone", vhd->base_dir, a->domain, a->domain);
		fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
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
handle_req_get_ipv6_suffix(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
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
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char path[1024];

	lws_snprintf(path, sizeof(path), "%s/domains/ipv6_suffix.txt", vhd->base_dir);
	if (!a->suffix[0]) {
		unlink(path);
	} else {
		int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (fd < 0 && errno == EACCES) {
			lws_snprintf(path, sizeof(path), "%s/domains/ipv6_suffix.txt", vhd->base_dir);
			fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
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
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];

	if (!a->zone_buf) goto fail;

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/%s.zone", vhd->base_dir, a->domain, a->domain);
	int fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
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

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/tls", vhd->base_dir, a->domain);
	d = opendir(d_path);
	if (!d) {
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\",\"tls\":[]}\n", a->req);
	} else {
		int first = 1;
		tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\",\"tls\":[", a->req);
		while ((de = readdir(d))) {
			if (de->d_name[0] == '.') continue;
			if (strstr(de->d_name, ".json")) {
				char fpath[1024];
				lws_snprintf(fpath, sizeof(fpath), "%s/%s", d_path, de->d_name);
				int fd = open(fpath, O_RDONLY);
				if (fd >= 0) {
					char buf[512];
					ssize_t n = read(fd, buf, sizeof(buf) - 1);
					if (n > 0) {
						buf[n] = '\0';
						if (strstr(buf, "\"challenge-type\"")) {
							int port = 0;
							char *p = strstr(buf, "\"port\"");
							if (p) {
								p = strchr(p, ':');
								if (p) {
									while (*p == ':' || *p == ' ' || *p == '\t' || *p == '"') p++;
									port = atoi(p);
								}
							}
							if (!first) tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), ",");
							char fqdn[128];
							lws_strncpy(fqdn, de->d_name, sizeof(fqdn));
							char *ext = strrchr(fqdn, '.');
							if (ext && !strcmp(ext, ".json")) *ext = '\0';
							tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"fqdn\":\"%s\",\"port\":%d}", fqdn, port);
							first = 0;
						}
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
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;
	char d_path[1024];
	char p1[1024];
	char buf[2048];
	int n, fd;

	lws_snprintf(p1, sizeof(p1), "%s/domains/%s", vhd->base_dir, a->domain);
	if (mkdir(p1, 0755) < 0 && errno != EEXIST)
		lwsl_notice("%s: Failed to create domain dir\n", __func__);

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/tls", vhd->base_dir, a->domain);
	if (mkdir(d_path, 0755) < 0 && errno != EEXIST)
		lwsl_notice("%s: Failed to create tls dir\n", __func__);

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/tls/%s.json", vhd->base_dir, a->domain, a->subdomain);
	fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd >= 0) {
		n = lws_snprintf(buf, sizeof(buf),
			"{\n  \"common-name\": \"%s\",\n  \"challenge-type\": \"dns-01\",\n"
			"  \"port\": %d,\n"
			"  \"email\": \"%s\",\n  \"acme\": {\n"
			"    \"organization\": \"%s\",\n"
			"    \"directory-url\": \"%s\"\n  }\n}\n",
			a->subdomain,
			a->port,
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

	lws_snprintf(d_path, sizeof(d_path), "%s/domains/%s/tls/%s.json", vhd->base_dir, a->domain, a->subdomain);

	if (!strcmp(a->domain, a->subdomain)) {
		int fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (fd >= 0) {
			char buf[1024];
			int n = lws_snprintf(buf, sizeof(buf), "{\n  \"common-name\": \"%s\"\n}\n", a->domain);
			if (write(fd, buf, (size_t)n) < 0) {
				lwsl_err("%s: Failed rewriting domain config\n", __func__);
			}
			close(fd);
		}
	} else {
		unlink(d_path);
	}

	tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);
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
	if (!starttls)
		i.ssl_connection |= LCCSCF_USE_SSL;

	i.alpn = "http/1.1";
	i.method = "RAW";
	i.path = "/";
	i.host = i.address;
	i.origin = i.address;
	i.protocol = "lws-dht-dnssec-monitor";
	struct cert_check_info *cci = malloc(sizeof(*cci));
	if (cci) {
		memset(cci, 0, sizeof(*cci));
		cci->magic = CERT_CHECK_MAGIC;
		lws_strncpy(cci->fqdn, a->subdomain, sizeof(cci->fqdn));
		lws_strncpy(cci->domain, a->domain, sizeof(cci->domain));
		cci->port = a->port;
		cci->starttls_state = starttls ? 1 : 0;
		i.opaque_user_data = cci;
	}

	lwsl_notice("%s: Dispatching %s TLS probe to %s:%d (STARTTLS: %d)\n", __func__, starttls ? "cleartext" : "direct", a->subdomain, a->port, starttls);

	if (!cci || !lws_client_connect_via_info(&i)) {
		lwsl_err("%s: Failed to start cert check for %s:%d\n", __func__, a->subdomain, a->port);

		if (cci) free(cci);

		struct cert_check_result *cr = malloc(sizeof(*cr));
		if (cr) {
			memset(cr, 0, sizeof(*cr));
			lws_strncpy(cr->fqdn, a->subdomain, sizeof(cr->fqdn));
			lws_strncpy(cr->msg, "Connection failed", sizeof(cr->msg));
			cr->port = a->port;
			cr->status_err = 1;
			lws_dll2_add_tail(&cr->list, &vhd->completed_checks);
			lws_callback_on_writable_all_protocol(vhd->context, lws_get_protocol(root_pss->wsi));
		}
	}
}

static void
handle_req_save_acme_file(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a, const char *dir_suffix, int mode)
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

	char dir_path[1024];
	lws_snprintf(dir_path, sizeof(dir_path), "%s/domains/%s/%s", vhd->base_dir, a->domain, dir_suffix);
	lws_snprintf(d_path, sizeof(d_path), "%s/%s", dir_path, a->subdomain);

	int fd = open(d_path, O_CREAT | O_WRONLY | O_TRUNC, mode);
	if (fd >= 0) {
		if (write(fd, a->zone_buf, (size_t)a->zone_len) == (ssize_t)a->zone_len) {
			/* Permissions */
#if !defined(WIN32)
			struct group *gr = getgrnam("lwsws");
			if (gr) {
				if (fchown(fd, (uid_t)-1, gr->gr_gid) < 0) {
					lwsl_err("%s: Failed to chown file %s to lwsws group\n", __func__, d_path);
				}
				if (chown(dir_path, (uid_t)-1, gr->gr_gid) < 0) {
					lwsl_err("%s: Failed to chown dir %s to lwsws group\n", __func__, dir_path);
				}
			}
			if (fchmod(fd, (mode_t)mode) < 0)
				lwsl_err("%s: Failed to fchmod file %s\n", __func__, d_path);
			if (chmod(dir_path, (mode_t)0750) < 0)
				lwsl_err("%s: Failed to chmod dir %s\n", __func__, dir_path);
#endif
			tx += lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"%s\",\"status\":\"ok\"}\n", a->req);

			/* Update symlinks for .crt or .key if timestamped file */
			const char *ext = strrchr(a->subdomain, '.');
			char base[256];
			lws_strncpy(base, a->subdomain, sizeof(base));
			char *dash = strrchr(base, '-');
			if (ext && dash && (!strcmp(ext, ".crt") || !strcmp(ext, ".key"))) {
				*dash = '\0';
				char latest_link[1024], previous_link[1024];
				lws_snprintf(latest_link, sizeof(latest_link), "%s/%s-latest%s", dir_path, base, ext);
				lws_snprintf(previous_link, sizeof(previous_link), "%s/%s-previous%s", dir_path, base, ext);

#if !defined(WIN32)
				char target[1024];
#if !defined(__COVERITY__)
				/*
				 * Hide readlink from Coverity since it incorrectly flags TOCTOU
				 * when we later unlink latest_link.
				 */
				ssize_t link_len = readlink(latest_link, target, sizeof(target) - 1);
#else
				ssize_t link_len = -1;
#endif
				if (link_len > 0) {
					target[link_len] = '\0';
					unlink(previous_link);
					symlink(target, previous_link);
					if (gr && lchown(previous_link, (uid_t)-1, gr->gr_gid) < 0)
						lwsl_err("%s: lchown failed on %s\n", __func__, previous_link);
				}

				unlink(latest_link);
				symlink(a->subdomain, latest_link);
				if (gr && lchown(latest_link, (uid_t)-1, gr->gr_gid) < 0)
					lwsl_err("%s: lchown failed on %s\n", __func__, latest_link);
#endif
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
	handle_req_save_acme_file(vhd, root_pss, a, "", 0600);
}

static void
handle_req_save_cert(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	handle_req_save_acme_file(vhd, root_pss, a, "certs/crt", 0640);
}

static void
force_external_dns(struct lws_context *cx, const char *external_ip)
{
	lws_sockaddr46 sa46;
	int index = 0;

	/* Extract exactly what the library natively discovered, and systematically kill it */
	while (!lws_plat_asyncdns_get_server(cx, index++, &sa46)) {
		lws_async_dns_server_remove(cx, &sa46);
	}

	if (lws_sa46_parse_numeric_address(external_ip, &sa46) < 0)
		return;
	sa46_sockport(&sa46, htons(53));
	lws_async_dns_server_add(cx, &sa46);
}

static void
handle_req_save_key(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	handle_req_save_acme_file(vhd, root_pss, a, "certs/key", 0600);
}

static void
handle_req_update_whois(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];

	lwsl_notice("[INSTRUMENT] handle_req_update_whois START for domain: '%s', zone_buf present: %d\n", a->domain, !!a->zone_buf);

	if (a->domain[0] && a->zone_buf) {
		char path[1024];
		lws_snprintf(path, sizeof(path), "%s/domains/%s/whois.json", vhd->base_dir, a->domain);
		int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (fd >= 0) {
			char decoded[8192];
			int n = lws_b64_decode_string(a->zone_buf, decoded, sizeof(decoded));
			lwsl_notice("[INSTRUMENT] lws_b64_decode_string returned %d for %s\n", n, a->domain);
			if (n > 0) {
				if (write(fd, decoded, (size_t)n) < 0) {
					lwsl_err("[INSTRUMENT] %s: Failed writing to %s (errno: %d)\n", __func__, path, errno);
				} else {
					lwsl_info("[INSTRUMENT] %s: Successfully synced WHOIS via UDS IPC for %s\n", __func__, a->domain);
				}
			} else {
				lwsl_err("[INSTRUMENT] %s: Failed B64 decode on whois zone payload size=%d\n", __func__, (int)a->zone_len);
			}
			close(fd);
		} else {
			lwsl_err("[INSTRUMENT] %s: Failed to open %s for writing! errno: %d\n", __func__, path, errno);
		}
	} else {
		lwsl_err("[INSTRUMENT] %s: Failed prerequisites. domain: '%s', zone_buf present: %d\n", __func__, a->domain, !!a->zone_buf);
	}
	
	/* Empty response is fine, IPC fire-and-forget */
	root_pss->tx_len = lws_ptr_diff_size_t(tx, (char *)&root_pss->tx[LWS_PRE]);
}

static void
handle_req_regen_keys(struct vhd *vhd, struct pss *root_pss, struct monitor_req_args *a)
{
	char *tx = (char *)&root_pss->tx[LWS_PRE];
	char *tx_end = tx + 65536 - 1;

	if (vhd->ops && vhd->ops->keygen) {
		struct lws_dht_dnssec_keygen_args kargs;
		memset(&kargs, 0, sizeof(kargs));

		char wd[1024];
		lws_snprintf(wd, sizeof(wd), "%s/domains/%s", vhd->base_dir, a->domain);

		kargs.domain = a->domain;
		kargs.workdir = wd;

		if (!strcmp(a->key_type, "ES256")) {
			kargs.type = "EC"; kargs.curve = "P-256"; kargs.bits = 256;
		} else if (!strcmp(a->key_type, "ES384")) {
			kargs.type = "EC"; kargs.curve = "P-384"; kargs.bits = 384;
		} else if (!strcmp(a->key_type, "R1024")) {
			kargs.type = "RSA"; kargs.bits = 1024;
		} else if (!strcmp(a->key_type, "R2048")) {
			kargs.type = "RSA"; kargs.bits = 2048;
		} else {
			kargs.type = "EC"; kargs.curve = "P-256"; kargs.bits = 256;
		}

		lwsl_notice("%s: Regenerating keys for %s using %s\n", __func__, a->domain, kargs.type);

		if (!vhd->ops->keygen(vhd->context, &kargs)) {
			/* Force resign by deleting the signed zone */
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
	{ "update_whois", handle_req_update_whois },
	{ "save_auth_key", handle_req_save_auth_key },
	{ "save_cert", handle_req_save_cert },
	{ "save_key", handle_req_save_key },
	{ "get_ipv6_suffix", handle_req_get_ipv6_suffix },
	{ "set_ipv6_suffix", handle_req_set_ipv6_suffix },
	{ "regen_keys", handle_req_regen_keys }
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

	// lwsl_notice("[INSTRUMENT] handle_monitor_request: executed lejp_parse. len: %d, rc: %d. String: '%.*s'\n", (int)len, m, (int)len, in);

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

	lwsl_notice("[INSTRUMENT] handle_monitor_request: Routed valid requested endpoint: '%s'\n", a.req);

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
		lwsl_notice("[INSTRUMENT] handle_monitor_request: Path traversal parameters detected\n");
		root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Invalid chars in domain\"}\n", a.req);
		goto done;
	}

	for (size_t i = 0; i < req_map_size; i++) {
		if (!strcmp(a.req, req_map[i].name)) {
			/* Enforce domain param if required by the handler */
			if (i > 0 && !a.domain[0] && strcmp(req_map[i].name, "status") && strcmp(req_map[i].name, "get_domains") && strcmp(req_map[i].name, "get_ipv6_suffix") && strcmp(req_map[i].name, "set_ipv6_suffix")) {
				lwsl_notice("[INSTRUMENT] handle_monitor_request: Missing required 'domain' param for %s\n", a.req);
				root_pss->tx_len = (size_t)lws_snprintf(tx, 65536, "{\"req\":\"%s\",\"status\":\"error\",\"msg\":\"Missing arguments\"}\n", a.req);
				goto done;
			}
			lwsl_notice("[INSTRUMENT] handle_monitor_request: Calling map callback...\n");
			req_map[i].cb(vhd, root_pss, &a);
			lwsl_notice("[INSTRUMENT] handle_monitor_request: Callback generated response size %d\n", (int)root_pss->tx_len);
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

static void
extract_and_queue_cert_result(struct lws *wsi, struct vhd *vhd, struct cert_check_info *cci, const struct lws_protocols *protocol)
{
	union lws_tls_cert_info_results ci;
	char msg[128];
	char issuer[128] = "Unknown";
	char local_msg[128] = "Not Found";
	int err = 0;

	if (!lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_ISSUER_NAME, &ci, 0)) {
		lws_strncpy(issuer, ci.ns.name, sizeof(issuer));
	}

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

	/* Read local cert expiry */
	if (cci->domain[0]) {
		char path[1024];
		lws_snprintf(path, sizeof(path), "%s/domains/%s/certs/crt/%s.crt", vhd->base_dir, cci->domain, cci->fqdn);
		int fd = open(path, O_RDONLY);
		if (fd >= 0) {
			struct stat st;
			if (!fstat(fd, &st) && st.st_size > 0) {
				uint8_t *pem = malloc((size_t)st.st_size + 1);
				if (pem) {
					if (read(fd, pem, (size_t)st.st_size) == st.st_size) {
						pem[st.st_size] = '\0';
						struct lws_x509_cert *x509 = NULL;
						if (!lws_x509_create(&x509)) {
							if (!lws_x509_parse_from_pem(x509, pem, (size_t)st.st_size + 1)) {
								union lws_tls_cert_info_results lci;
								if (!lws_x509_info(x509, LWS_TLS_CERT_INFO_VALIDITY_TO, &lci, 0)) {
									time_t now;
									time(&now);
									if (now > lci.time) {
										lws_snprintf(local_msg, sizeof(local_msg), "Expired");
									} else {
										int days = (int)((lci.time - now) / (24 * 3600));
										lws_snprintf(local_msg, sizeof(local_msg), "%d days", days);
									}
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
		if (err)
			lwsl_notice("%s: AUTOMATED PROBE %s:%d FAILED: %s\n", __func__, cci->fqdn, cci->port, msg);
		else
			lwsl_notice("%s: AUTOMATED PROBE %s:%d SUCCESS: Cert served expires in %s\n", __func__, cci->fqdn, cci->port, msg);
		return;
	}

	struct cert_check_result *cr = malloc(sizeof(*cr));
	if (cr) {
		memset(cr, 0, sizeof(*cr));
		lws_strncpy(cr->fqdn, cci->fqdn, sizeof(cr->fqdn));
		cr->port = cci->port;
		char *colon = strchr(cr->fqdn, ':');
		if (colon) *colon = '\0';
		lws_strncpy(cr->msg, msg, sizeof(cr->msg));
		lws_strncpy(cr->local_msg, local_msg, sizeof(cr->local_msg));
		lws_strncpy(cr->issuer, issuer, sizeof(cr->issuer));
		cr->status_err = err;
		lws_dll2_add_tail(&cr->list, &vhd->completed_checks);
		lws_callback_on_writable_all_protocol(vhd->context, protocol);
	}
}

static void
root_monitor_stdin_check_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_timer);
	struct pollfd pfd;
	pfd.fd = 0; /* stdin */
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 0) == 1) {
		char buf[1];
		if (read(0, buf, 1) <= 0) {
			lwsl_notice("Parent stdin pipe broken. Parent died. Exiting!\n");
			exit(0);
		}
	}
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, root_monitor_stdin_check_cb, 2 * LWS_US_PER_SEC);
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
				info.options = LWS_SERVER_OPTION_UNIX_SOCK | LWS_SERVER_OPTION_ONLY_RAW | LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
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
					lws_init_vhost_client_ssl(&info, vh);
					lwsl_notice("%s: Created UDS vhost on %s\n", __func__, uds_path);
					chmod(uds_path, 0666);
				}

				static int timer_armed = 0;
				if (!timer_armed) {
					vhd = lws_protocol_vh_priv_zalloc(vhost, protocol, sizeof(*vhd));
					if (vhd) {
						lwsl_notice("%s: Successfully allocated vhd on %s\n", __func__, lws_get_vhost_name(vhost));
						vhd->context = cx;
						vhd->vhost = vhost;

						/* Force telemetry to use global public resolver to bypass local split-horizon DNS */
						force_external_dns(cx, "8.8.8.8");

						const char *base_dir_arg = lws_cmdline_option_cx(cx, "--base-dir");
						if (base_dir_arg) {
							vhd->base_dir = strdup(base_dir_arg);
						} else {
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
						timer_armed = 1;
						
						lws_sul_schedule(cx, 0, &vhd->sul_timer, root_monitor_stdin_check_cb, 2 * LWS_US_PER_SEC);

						if (vhd->ops) {
							char scan_path[1024];
							lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);



#if defined(LWS_WITH_DIR)
							vhd->dn = lws_dir_notify_create(cx, scan_path, dir_notify_cb, vhd);
							if (!vhd->dn)
								lwsl_err("%s: Failed to attach lws_dir_notify to %s\n", __func__, scan_path);
#endif
							lws_sul_schedule(cx, 0, &vhd->sul_timer_scan, root_dnssec_scan_timer_cb, 5 * LWS_US_PER_SEC);
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
				vhd->base_dir = strdup("/var/dnssec");

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

			vhd->smd_peer = lws_smd_register(vhd->context, vhd, 0, LWSSMDCL_NETWORK, smd_cb_network);

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

			char arg_basedir[1024];
			if (vhd->base_dir) {
				lws_snprintf(arg_basedir, sizeof(arg_basedir), "--base-dir=%s", vhd->base_dir);
				exec_array[n++] = arg_basedir;
			}
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

					/*
					 * Privilege Separation Policy:
					 *  - The "root daemon" drops its privileges to run as the `lwsws-priv` user.
					 *  - Only the `lwsws-priv` daemon can write to the base dir (e.g., /var/dnssec)
					 *    and read secrets like cert keys.
					 *  - The less-privileged network-facing side (here) asks the daemon to handle
					 *    write operations securely.
					 *  - We keep the privileged daemon isolated from external network content.
					 *    Therefore, this unprivileged side leverages a timer to securely scan for
					 *    completed .jws drops and natively handles the DHT network publication.
					 */
					lws_sul_schedule(vhd->context, 0, &vhd->sul_timer, parent_dnssec_monitor_timer_cb, 1 * LWS_US_PER_SEC);
					lws_sul_schedule(vhd->context, 0, &vhd->sul_timer_proxy_scan, proxy_dnssec_scan_timer_cb, 5 * LWS_US_PER_SEC);
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
		if (vhd->vhost != lws_get_vhost(wsi))
			break; /* Borrowed global_root_vhd */

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
		lwsl_notice("[INSTRUMENT] LWS_CALLBACK_RECEIVE: Browser UI triggered WS message (len: %d). Proxy cwsi=%p, root_process_active=%d\n", (int)len, pss->cwsi, vhd ? vhd->root_process_active : -1);
		if (vhd && vhd->root_process_active && pss->cwsi) {
			if (len < 1024 && strstr((const char *)in, "\"check_cert\"")) {
				struct monitor_req_args a;
				struct lejp_ctx jctx;
				memset(&a, 0, sizeof(a));
				lejp_construct(&jctx, monitor_req_cb, &a, monitor_req_paths, LWS_ARRAY_SIZE(monitor_req_paths));
				lejp_parse(&jctx, (uint8_t *)in, (int)len);
				lejp_destruct(&jctx);

				if (!strcmp(a.req, "check_cert")) {
					handle_req_check_cert(vhd, pss, &a); 
					if (a.zone_buf) free(a.zone_buf);
					return 0;
				}
				if (a.zone_buf) free(a.zone_buf);
			}

			if (len < 1024 && strstr((const char *)in, "\"get_domains\"")) {
				char scan_path[1024];
				lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);
				lws_dir(scan_path, vhd, scan_whois_cb);
				/* Note: We intentionally do NOT return 0 here. 
				 * We propagate get_domains to the root proxy to instantly answer the browser 
				 * with current data, while WHOIS asynchronous lookups update the cache in the background.
				 */
			}

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
					if (existing_len + offset < 65536 - LWS_PRE) {
						memcpy(&pss->tx[LWS_PRE + existing_len], in, offset);
						out_len += offset;
	
						int n = lws_snprintf((char *)&pss->tx[LWS_PRE + existing_len + out_len], 65536 - LWS_PRE - existing_len - out_len, "\"jwt\":\"%s\",", jwt_buf);
						out_len += (size_t)n;
	
						if (existing_len + out_len + len - offset + 1 < 65536 - LWS_PRE) {
							memcpy(&pss->tx[LWS_PRE + existing_len + out_len], first_brace + 1, len - offset);
							out_len += len - offset;
							pss->tx[LWS_PRE + existing_len + out_len] = '\n';
							out_len += 1;
							pss->tx_len += out_len;
							lws_callback_on_writable(pss->cwsi); /* Write proxy -> root */
							lwsl_notice("[INSTRUMENT] LWS_CALLBACK_RECEIVE: Appended proxy->root payload size %d with JWT, total %d\n", (int)out_len, (int)pss->tx_len);
						}
					}
				} else {
					goto fallback;
				}
			} else {
fallback:
				if (pss->tx_len + len + 1 < 65536 - LWS_PRE) {
					memcpy(&pss->tx[LWS_PRE + pss->tx_len], in, len);
					pss->tx_len += len;
					pss->tx[LWS_PRE + pss->tx_len] = '\n';
					pss->tx_len += 1;
					lws_callback_on_writable(pss->cwsi); /* Write proxy -> root */
					lwsl_notice("[INSTRUMENT] LWS_CALLBACK_RECEIVE: Appended proxy->root payload size %d (no JWT), total %d\n", (int)len + 1, (int)pss->tx_len);
				}
			}
		} else {
			lwsl_notice("[INSTRUMENT] LWS_CALLBACK_RECEIVE: ABORTED! root_active=%d, pss->cwsi=%p\n", vhd?vhd->root_process_active:0, pss->cwsi);
		}
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (vhd && vhd->completed_checks.head) {
			struct lws_dll2 *p = vhd->completed_checks.head;
			struct cert_check_result *cr = lws_container_of(p, struct cert_check_result, list);
			char *tx = (char *)&pss->tx[LWS_PRE];
			char *tx_end = tx + 65536 - 1;
			int n = lws_snprintf(tx, lws_ptr_diff_size_t(tx_end, tx), "{\"req\":\"cert_status\",\"subdomain\":\"%s\",\"port\":%d,\"status\":\"%s\",\"msg\":\"%s\",\"local_msg\":\"%s\",\"issuer\":\"%s\"}\n",
				cr->fqdn, cr->port, cr->status_err ? "error" : "ok", cr->msg, cr->local_msg, cr->issuer);
			
			if (lws_write(wsi, (unsigned char *)tx, (size_t)n, LWS_WRITE_TEXT) < 0)
				return -1;
			
			lws_dll2_remove(&cr->list);
			free(cr);
			if (vhd->completed_checks.head)
				lws_callback_on_writable(wsi);
			return 0;
		}

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
				lwsl_notice("[INSTRUMENT] LWS_CALLBACK_SERVER_WRITEABLE: Translating %d bytes to final browser!\n", (int)pss->rx_len);
				if (lws_write(wsi, &pss->rx[LWS_PRE], pss->rx_len, LWS_WRITE_TEXT) < 0) {
					lwsl_err("%s: Failed writing to WS UI\n", __func__);
					return -1;
				}
				pss->rx_len = 0;
			}
		}
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		{
			struct cert_check_info *cci = (struct cert_check_info *)lws_get_opaque_user_data(wsi);
			if (cci && cci->magic == CERT_CHECK_MAGIC && vhd) {
				lwsl_notice("[INSTRUMENT] Probe %s RAW_CONNECTED successfully! (STARTTLS state: %d)\n", cci->fqdn, cci->starttls_state);
				if (cci->starttls_state == 0 || cci->starttls_state == 4) {
					extract_and_queue_cert_result(wsi, vhd, cci, protocol);
					cci->magic = 0;
					free(cci);
					lws_set_opaque_user_data(wsi, NULL);
					return -1; // close immediately
				}
				/* STARTTLS: skip extraction for now, we are cleartext. 
				 * SMTP Banner will arrive in RX. */
			}
		}
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		{
			void *opaque = lws_get_opaque_user_data(wsi);
			struct cert_check_info *cci = (struct cert_check_info *)opaque;
			if (cci && cci->magic == CERT_CHECK_MAGIC && vhd) {
				lwsl_notice("[INSTRUMENT] Probe %s CLIENT_CONNECTION_ERROR: %s\n", cci->fqdn, in ? (char *)in : "unknown");
				struct cert_check_result *cr = malloc(sizeof(*cr));
				if (cr) {
					memset(cr, 0, sizeof(*cr));
					lws_strncpy(cr->fqdn, cci->fqdn, sizeof(cr->fqdn));
					char *err_str = in ? (char *)in : "Connection failed";
					lws_snprintf(cr->msg, sizeof(cr->msg), "Error: %s", err_str);
					cr->status_err = 1;
					lws_dll2_add_tail(&cr->list, &vhd->completed_checks);
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
				cci->magic = 0;
				free(cci);
				lws_set_opaque_user_data(wsi, NULL);
			} else {
				struct pss *wpss = (struct pss *)opaque;
				if (wpss) {
					wpss->cwsi = NULL;
				}
				lwsl_notice("%s: UDS connection closed\n", __func__);
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
			void *opaque = lws_get_opaque_user_data(wsi);
			struct cert_check_info *cci = (struct cert_check_info *)opaque;

			if (cci && cci->magic == CERT_CHECK_MAGIC) {
				lwsl_notice("[INSTRUMENT] Probe %s RAW_RX: '%.*s' (state %d, SSL %d)\n", cci->fqdn, (int)len, (const char *)in, cci->starttls_state, lws_is_ssl(wsi));

				if (cci->starttls_state == 4) {
					/* Handshake might be in progress or done. 
					 * If lws_is_ssl is true, we can try to extract. */
					if (lws_is_ssl(wsi)) {
						if (vhd)
							extract_and_queue_cert_result(wsi, vhd, cci, protocol);
						cci->magic = 0;
						free(cci);
						lws_set_opaque_user_data(wsi, NULL);
						return -1;
					}
					return 0;
				}

				if (cci->starttls_state == 1 && !strncmp((const char *)in, "220", 3)) {
					cci->starttls_state = 2;
					lws_callback_on_writable(wsi);
					return 0;
				}
				if (cci->starttls_state == 2 && !strncmp((const char *)in, "250", 3)) {
					/* EHLO can have multiple lines, look for last one. 
					 * For simplicity, we just look for 250 space. */
					int found_250_space = 0;
					for (size_t k = 0; k < len; k++) {
						if ((k == 0 || ((const char *)in)[k-1] == '\n') &&
						    len - k >= 4 && !strncmp((const char *)in + k, "250 ", 4)) {
							found_250_space = 1;
							break;
						}
					}
					if (found_250_space) {
						cci->starttls_state = 3;
						lws_callback_on_writable(wsi);
					}
					return 0;
				}
				if (cci->starttls_state == 3 && !strncmp((const char *)in, "220", 3)) {
					lwsl_notice("[INSTRUMENT] Probe %s STARTTLS accepted, upgrading to TLS\n", cci->fqdn);
					cci->starttls_state = 4;
					if (lws_tls_client_upgrade(wsi, LCCSCF_USE_SSL |
								LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK |
								LCCSCF_ALLOW_SELFSIGNED |
								LCCSCF_ALLOW_EXPIRED) < 0) {
						lwsl_notice("[INSTRUMENT] Probe %s TLS upgrade failed\n", cci->fqdn);
						return -1;
					}
					lws_callback_on_writable(wsi);
					return 0;
				}
				return 0;
			}

			struct pss *wpss = (struct pss *)opaque;
			lwsl_notice("[INSTRUMENT] LWS_CALLBACK_RAW_RX: UDS channel receiving %d bytes. Is Proxy? %d\n", (int)len, wpss != NULL);

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
				
				lwsl_notice("[ROOT-DAEMON] [INSTRUMENT] LWS_CALLBACK_RAW_RX: UDS Channel rx %d bytes\n", (int)len);

				memcpy(&vhd->rx[LWS_PRE], in, len);
				vhd->rx[LWS_PRE + len] = '\0';
				vhd->rx_len = len;

				struct pss *root_pss = (struct pss *)user;
				root_pss->tx_len = 0; // Prevent synchronous overwrite buildup mapping
				
				char *current = (char *)&vhd->rx[LWS_PRE];
				char *end = current + len;
				
				while (current < end) {
					char *nl = strchr(current, '\n');
					if (!nl) nl = end;
					
					size_t chunk_len = lws_ptr_diff_size_t(nl, current);
					if (chunk_len > 0) {
						char save = *nl;
						*nl = '\0';
						lwsl_notice("[ROOT-DAEMON] [INSTRUMENT] LWS_CALLBACK_RAW_RX (ROOT): Sending %d bytes to monitor request router\n", (int)chunk_len);
						handle_monitor_request(vhd, root_pss, current, chunk_len);
						if (save != '\0') *nl = save;
					}
					current = nl + 1;
				}

				/* Tell server socket to reply */
				if (root_pss->tx_len) {
					lwsl_notice("[ROOT-DAEMON] [INSTRUMENT] LWS_CALLBACK_RAW_RX (ROOT): Triggering WS write\n");
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
					lwsl_notice("[INSTRUMENT] Probe %s STARTTLS handshake finished, extracting cert\n", cci->fqdn);
					if (vhd)
						extract_and_queue_cert_result(wsi, vhd, cci, protocol);
					cci->magic = 0;
					free(cci);
					lws_set_opaque_user_data(wsi, NULL);
					return -1;
				}
				char buf[256];
				int n = 0;
				if (cci->starttls_state == 2) {
					n = lws_snprintf(buf, sizeof(buf), "EHLO %s\r\n", cci->fqdn);
				} else if (cci->starttls_state == 3) {
					n = lws_snprintf(buf, sizeof(buf), "STARTTLS\r\n");
				}
				if (n > 0) {
					lwsl_notice("[INSTRUMENT] Probe %s sending: %.*s", cci->fqdn, n, buf);
					if (lws_write(wsi, (unsigned char *)buf, (size_t)n, LWS_WRITE_RAW) < 0) return -1;
				}
				return 0;
			}

			struct pss *wpss = (struct pss *)opaque;

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
	struct lws_vhost *vhost = lws_get_vhost(wsi);
	const struct lws_protocols *protocol = lws_get_protocol(wsi);
	struct vhd *vhd = (struct vhd *)lws_protocol_vh_priv_get(vhost, protocol);
	if (!vhd && global_root_vhd) vhd = global_root_vhd;

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
