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
force_external_dns(struct lws_context *cx, const char *external_ip)
{
	lws_sockaddr46 sa46;
	int index = 0;

	while (!lws_plat_asyncdns_get_server(cx, index++, &sa46)) {
		lws_async_dns_server_remove(cx, &sa46);
	}

	if (!external_ip) {
		index = 0;
		while (!lws_plat_asyncdns_get_server(cx, index++, &sa46)) {
			sa46_sockport(&sa46, htons(53));
			lws_async_dns_server_add(cx, &sa46);
		}
		return;
	}

	if (lws_sa46_parse_numeric_address(external_ip, &sa46) < 0)
		return;
	sa46_sockport(&sa46, htons(53));
	lws_async_dns_server_add(cx, &sa46);
}

int
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

	char d[256], b64[1024];
	int flags, proto, alg;
	if (sscanf(buf, "%255s IN DNSKEY %d %d %d %1023s", d, &flags, &proto, &alg, b64) != 5)
		return 1;

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

	struct lws_genhash_ctx hash_ctx;
	uint8_t digest[64];
	if (lws_genhash_init(&hash_ctx, htype)) return 1;
	if (lws_genhash_update(&hash_ctx, payload, pay_len)) {
		lws_genhash_destroy(&hash_ctx, NULL);
		return 1;
	}
	lws_genhash_destroy(&hash_ctx, digest);

	char *po = out;
	char *pe = out + out_len;
	po += lws_snprintf(po, lws_ptr_diff_size_t(pe, po), "%u %d %d ", keytag, alg, dtype);
	for (int i = 0; i < dlen; i++)
		po += lws_snprintf(po, lws_ptr_diff_size_t(pe, po), "%02X", digest[i]);

	return 0;
}
