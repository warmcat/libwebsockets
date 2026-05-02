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
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>

static int
add_ext(X509 *cert, int nid, char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex) return 0;
	X509_add_ext(cert, ex, -1);
	X509_EXTENSION_free(ex);
	return 1;
}

static int
generate_cert_internal(struct vhd *vhd, const char *cn, const char *out_crt, const char *out_key,
		      const char *ca_crt_path, const char *ca_key_path, int is_ca)
{
	EVP_PKEY *pk = EVP_PKEY_new();
	X509 *x = X509_new();
	EVP_PKEY *ca_pk = NULL;
	X509 *ca_x = NULL;
	RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
	FILE *f;

	if (!rsa || !pk || !x) goto bail;
	EVP_PKEY_assign_RSA(pk, rsa);

	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), (long)lws_now_secs());
	X509_gmtime_adj(X509_get_notBefore(x), 0);
	X509_gmtime_adj(X509_get_notAfter(x), 315360000L); /* 10 years */
	X509_set_pubkey(x, pk);

	X509_NAME *name = X509_get_subject_name(x);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)cn, -1, -1, 0);

	if (is_ca) {
		X509_set_issuer_name(x, name);
		add_ext(x, NID_basic_constraints, "critical,CA:TRUE");
		add_ext(x, NID_key_usage, "critical,keyCertSign,cRLSign");
		if (!X509_sign(x, pk, EVP_sha256())) goto bail;
	} else {
		f = fopen(ca_crt_path, "r");
		if (f) { ca_x = PEM_read_X509(f, NULL, NULL, NULL); fclose(f); }
		f = fopen(ca_key_path, "r");
		if (f) { ca_pk = PEM_read_PrivateKey(f, NULL, NULL, NULL); fclose(f); }

		if (!ca_x || !ca_pk) goto bail;
		X509_set_issuer_name(x, X509_get_subject_name(ca_x));
		add_ext(x, NID_basic_constraints, "critical,CA:FALSE");
		if (strstr(cn, "server"))
			add_ext(x, NID_ext_key_usage, "serverAuth");
		else
			add_ext(x, NID_ext_key_usage, "clientAuth");

		if (!X509_sign(x, ca_pk, EVP_sha256())) goto bail;
	}

	f = fopen(out_key, "w");
	if (f) { PEM_write_PrivateKey(f, pk, NULL, NULL, 0, NULL, NULL); fclose(f); }
	f = fopen(out_crt, "w");
	if (f) { PEM_write_X509(f, x); fclose(f); }

	if (ca_x) X509_free(ca_x);
	if (ca_pk) EVP_PKEY_free(ca_pk);
	X509_free(x);
	EVP_PKEY_free(pk);
	return 0;

bail:
	if (ca_x) X509_free(ca_x);
	if (ca_pk) EVP_PKEY_free(ca_pk);
	if (x) X509_free(x);
	if (pk) EVP_PKEY_free(pk);
	return 1;
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
		generate_cert_internal(vhd, "dnssec-monitor-distribution-ca", path_crt, path_key, NULL, NULL, 1);
	}

	char srv_crt[1024], srv_key[1024];
	lws_snprintf(srv_crt, sizeof(srv_crt), "%s/pki/distribution-server.crt", vhd->base_dir);
	lws_snprintf(srv_key, sizeof(srv_key), "%s/pki/distribution-server.key", vhd->base_dir);

	if (access(srv_crt, F_OK) != 0) {
		lwsl_notice("%s: Generating Distribution Server Cert\n", __func__);
		generate_cert_internal(vhd, "distribution-server", srv_crt, srv_key, path_crt, path_key, 0);
	}
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
	generate_cert_internal(vhd, subdomain, path_crt, path_key, ca_crt, ca_key, 0);
}
