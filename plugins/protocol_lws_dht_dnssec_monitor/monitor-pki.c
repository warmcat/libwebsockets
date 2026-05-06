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
#include <fcntl.h>
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
	info.curve_name = "P-521"; /* Force ECDSA P-521 for Distribution PKI */
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

	if (write_pem(out_key, "PRIVATE KEY", key_buf, key_len)) {
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

void
generate_dist_pki(struct vhd *vhd)
{
	char path_crt[1024], path_key[1024], path_dir[1024];

	lws_snprintf(path_dir, sizeof(path_dir), "%s/pki", vhd->base_dir);
	mkdir(path_dir, 0700);

	lws_snprintf(path_crt, sizeof(path_crt), "%s/pki/distribution-ca.crt", vhd->base_dir);
	lws_snprintf(path_key, sizeof(path_key), "%s/pki/distribution-ca.key", vhd->base_dir);

	if (access(path_crt, F_OK) != 0) {
		lwsl_notice("%s: Generating Distribution CA\n", __func__);
		generate_cert_internal(vhd, "dnssec-monitor-distribution-ca", path_crt, path_key, NULL, NULL, 1, 0);
	}

}

void
generate_dist_server_cert(struct vhd *vhd, const char *domain)
{
	char path_crt[1024], path_key[1024], path_dir[1024];
	char ca_crt[1024], ca_key[1024];

	lws_snprintf(path_dir, sizeof(path_dir), "%s/pki", vhd->base_dir);
	mkdir(path_dir, 0700);

	lws_snprintf(path_crt, sizeof(path_crt), "%s/pki/distribution-server-%s.crt", vhd->base_dir, domain);
	lws_snprintf(path_key, sizeof(path_key), "%s/pki/distribution-server-%s.key", vhd->base_dir, domain);

	if (access(path_crt, F_OK) == 0) return;

	lws_snprintf(ca_crt, sizeof(ca_crt), "%s/pki/distribution-ca.crt", vhd->base_dir);
	lws_snprintf(ca_key, sizeof(ca_key), "%s/pki/distribution-ca.key", vhd->base_dir);

	lwsl_notice("%s: Generating Distribution Server Cert for %s\n", __func__, domain);
	generate_cert_internal(vhd, domain, path_crt, path_key, ca_crt, ca_key, 0, 1);
}

void
generate_client_cert(struct vhd *vhd, const char *domain, const char *subdomain)
{
	char path_dir[1024], path_crt[1024], path_key[1024];
	char ca_crt[1024], ca_key[1024];

	lws_snprintf(path_dir, sizeof(path_dir), "%s/domains/%s/dist-client", vhd->base_dir, domain);
	mkdir(path_dir, 0700);

	lws_snprintf(path_crt, sizeof(path_crt), "%s/distribution-client-%s.crt", path_dir, subdomain);
	lws_snprintf(path_key, sizeof(path_key), "%s/distribution-client-%s.key", path_dir, subdomain);

	if (access(path_crt, F_OK) == 0) return;

	lws_snprintf(ca_crt, sizeof(ca_crt), "%s/pki/distribution-ca.crt", vhd->base_dir);
	lws_snprintf(ca_key, sizeof(ca_key), "%s/pki/distribution-ca.key", vhd->base_dir);

	lwsl_notice("%s: Generating Client Cert for %s\n", __func__, subdomain);
	generate_cert_internal(vhd, subdomain, path_crt, path_key, ca_crt, ca_key, 0, 0);
}

void
pki_init(struct vhd *vhd)
{
	generate_dist_pki(vhd);
}
