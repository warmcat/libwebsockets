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

static void
whois_cb(void *opaque, const struct lws_whois_results *res)
{
	struct whois_query_info *wqi = (struct whois_query_info *)opaque;
	int n;
	char buf[2048];
	char ns_list[1024] = "";

	lwsl_notice("[WHOIS] %s: callback triggered for %s. res is %s\n", __func__, wqi->domain, res ? "NOT NULL" : "NULL");

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

		lwsl_notice("[WHOIS] whois_cb: formatted JSON for %s, size = %d\n", wqi->domain, n);
	} else {
		lwsl_notice("[WHOIS] whois_cb: res is NULL for %s, skipping UDS publish\n", wqi->domain);
		n = 0;
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
				lwsl_err("[WHOIS] %s: failed to generate jwt for whois\n", __func__);
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
					lwsl_err("[WHOIS] %s: Failed writing whois payload to UDS, errno: %d\n", __func__, errno);
				} else {
					lwsl_notice("[WHOIS] %s: Tunneled WHOIS for %s to Root over UDS (payload %d bytes)\n", __func__, wqi->domain, payload_n);
				}
			} else {
				lwsl_err("[WHOIS] %s: Failed connecting to root UDS at %s for whois pass-back, errno: %d\n", __func__, sun.sun_path, errno);
			}
			close(fd);
		} else {
			lwsl_err("[WHOIS] %s: socket creation failed! errno: %d\n", __func__, errno);
		}
	}

	lws_dll2_remove(&wqi->list);
	free(wqi);
}

int
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
