/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "private-lib-core.h"
#include "private-lib-tls.h"
#include "private.h"
#include <gnutls/x509.h>

int
lws_x509_create_self_signed(struct lws_context *context,
			    uint8_t **cert_buf, size_t *cert_len,
			    uint8_t **key_buf, size_t *key_len,
			    const char *san, int key_bits)
{
	gnutls_x509_privkey_t key;
	gnutls_x509_crt_t crt;
	int ret = 1;
	gnutls_datum_t data;
	const char *cn = san ? san : "localhost";

	(void)context;

	if (gnutls_x509_privkey_init(&key))
		return 1;
	if (gnutls_x509_crt_init(&crt)) {
		gnutls_x509_privkey_deinit(key);
		return 1;
	}

	if (gnutls_x509_privkey_generate(key, GNUTLS_PK_RSA, (unsigned int)key_bits, 0))
		goto bail;

	gnutls_x509_crt_set_key(crt, key);
	gnutls_x509_crt_set_version(crt, 3);
	gnutls_x509_crt_set_serial(crt, "\x01", 1);
	gnutls_x509_crt_set_activation_time(crt, time(NULL));
	gnutls_x509_crt_set_expiration_time(crt, time(NULL) + (365 * 24 * 3600));

	gnutls_x509_crt_set_dn_by_oid(crt, GNUTLS_OID_X520_COMMON_NAME, 0, cn, (unsigned int)strlen(cn));
	gnutls_x509_crt_set_issuer_dn_by_oid(crt, GNUTLS_OID_X520_COMMON_NAME, 0, cn, (unsigned int)strlen(cn));

	/* Extensions */
	gnutls_x509_crt_set_basic_constraints(crt, 0, -1);
	gnutls_x509_crt_set_key_usage(crt, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT);

	if (san)
		gnutls_x509_crt_set_subject_alt_name(crt, GNUTLS_SAN_DNSNAME, san, (unsigned int)strlen(san), 0);

	/* Self-sign */
	if (gnutls_x509_crt_sign2(crt, crt, key, GNUTLS_DIG_SHA256, 0))
		goto bail;

	/* Export Cert */
	if (gnutls_x509_crt_export2(crt, GNUTLS_X509_FMT_DER, &data))
		goto bail;

	*cert_buf = malloc((size_t)data.size);
	if (!*cert_buf) {
		gnutls_free(data.data);
		goto bail;
	}
	memcpy(*cert_buf, data.data, (size_t)data.size);
	*cert_len = (size_t)data.size;
	gnutls_free(data.data);

	/* Export Key */
	if (gnutls_x509_privkey_export2(key, GNUTLS_X509_FMT_DER, &data)) {
		free(*cert_buf);
		goto bail;
	}
	*key_buf = malloc((size_t)data.size);
	if (!*key_buf) {
		gnutls_free(data.data);
		free(*cert_buf);
		goto bail;
	}
	memcpy(*key_buf, data.data, (size_t)data.size);
	*key_len = (size_t)data.size;
	gnutls_free(data.data);

	ret = 0;

bail:
	gnutls_x509_crt_deinit(crt);
	gnutls_x509_privkey_deinit(key);

	return ret;
}

int
lws_x509_create(struct lws_x509_cert **x509)
{
	*x509 = lws_zalloc(sizeof(**x509), "x509");
	if (!*x509)
		return -1;
	if (gnutls_x509_crt_init(&(*x509)->cert)) {
		lws_free(*x509);
		*x509 = NULL;
		return -1;
	}
	return 0;
}

int
lws_x509_parse_from_pem(struct lws_x509_cert *x509, const void *pem, size_t len)
{
	gnutls_datum_t data;
	int ret;

	data.data = (unsigned char *)pem;
	data.size = (unsigned int)len;
	
	/* some backends like gnutls don't like trailing null bytes in PEM */
	if (len > 0 && data.data[len - 1] == '\0')
		data.size--;

	ret = gnutls_x509_crt_import(x509->cert, &data, GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		lwsl_err("%s: gnutls_x509_crt_import failed: %s\n", __func__, gnutls_strerror(ret));
		return -1;
	}
	return 0;
}

int
lws_x509_verify(struct lws_x509_cert *x509, struct lws_x509_cert *trusted,
		const char *common_name)
{
	unsigned int status = 0;
	int n;

	n = gnutls_x509_crt_verify(x509->cert, &trusted->cert, 1,
				   GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS, &status);
	if (n < 0)
		return -1;

	/* check host if provided */
	if (common_name) {
		if (!gnutls_x509_crt_check_hostname(x509->cert, common_name))
			return -1;
	}

	if (status != 0)
		return -1;

	return 0;
}

int
lws_x509_public_to_jwk(struct lws_jwk *jwk, struct lws_x509_cert *x509,
		       const char *curves, int rsa_min_bits)
{
	gnutls_datum_t pk_m, pk_e, pk_x, pk_y;
	gnutls_pubkey_t pubkey;
	int ret = -1;
	unsigned int bits;
	gnutls_pk_algorithm_t pk_algo;

	int alg;

	if (gnutls_pubkey_init(&pubkey) < 0)
		return -1;

	if (gnutls_pubkey_import_x509(pubkey, x509->cert, 0) < 0)
		goto bail1;

	alg = gnutls_pubkey_get_pk_algorithm(pubkey, &bits);
	if (alg < 0)
		goto bail1;
	pk_algo = (gnutls_pk_algorithm_t)alg;

	memset(jwk, 0, sizeof(*jwk));

	switch (pk_algo) {
	case GNUTLS_PK_RSA:
		jwk->kty = LWS_GENCRYPTO_KTY_RSA;
		if (gnutls_pubkey_export_rsa_raw(pubkey, &pk_m, &pk_e) < 0)
			goto bail1;

		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf = lws_malloc((size_t)pk_m.size, "certjwk");
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len = pk_m.size;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf, pk_m.data, pk_m.size);

		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf = lws_malloc((size_t)pk_e.size, "certjwk");
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].len = pk_e.size;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf, pk_e.data, pk_e.size);

		gnutls_free(pk_m.data);
		gnutls_free(pk_e.data);
		break;

	case GNUTLS_PK_ECC:
	{
		gnutls_ecc_curve_t curve;
		const char *c_name = NULL;
		int n = 0;

		jwk->kty = LWS_GENCRYPTO_KTY_EC;
		if (gnutls_pubkey_export_ecc_raw(pubkey, &curve, &pk_x, &pk_y) < 0)
			goto bail1;

		while (lws_ec_curves[n].name) {
			if (lws_ec_curves[n].tls_lib_nid == (int)curve) {
				c_name = lws_ec_curves[n].name;
				break;
			}
			n++;
		}

		if (!c_name) {
			gnutls_free(pk_x.data);
			gnutls_free(pk_y.data);
			goto bail1;
		}

		if (lws_genec_confirm_curve_allowed_by_tls_id(curves, (int)curve, jwk)) {
			gnutls_free(pk_x.data);
			gnutls_free(pk_y.data);
			goto bail1;
		}

		jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf = lws_malloc((size_t)pk_x.size, "certjwk");
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].len = pk_x.size;
		memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf, pk_x.data, pk_x.size);

		jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf = lws_malloc((size_t)pk_y.size, "certjwk");
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].len = pk_y.size;
		memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf, pk_y.data, pk_y.size);

		gnutls_free(pk_x.data);
		gnutls_free(pk_y.data);
		break;
	}

	default:
		goto bail1;
	}

	ret = 0;

bail1:
	gnutls_pubkey_deinit(pubkey);

	if (ret)
		lws_jwk_destroy(jwk);

	return ret;
}

int
lws_x509_jwk_privkey_pem(struct lws_context *cx, struct lws_jwk *jwk,
			 void *pem, size_t len, const char *passphrase)
{
	gnutls_datum_t data;
	gnutls_privkey_t pkey;
	gnutls_pk_algorithm_t pk_algo;
	int alg, ret = -1;

	data.data = (unsigned char *)pem;
	data.size = (unsigned int)len;

	if (gnutls_privkey_init(&pkey) < 0)
		return -1;

	if (gnutls_privkey_import_x509_raw(pkey, &data, GNUTLS_X509_FMT_PEM,
					   passphrase, 0) < 0)
		goto bail;

	alg = gnutls_privkey_get_pk_algorithm(pkey, NULL);
	if (alg < 0)
		goto bail;
	pk_algo = (gnutls_pk_algorithm_t)alg;

	switch (pk_algo) {
	case GNUTLS_PK_RSA:
	{
		gnutls_datum_t m, e, d, p, q, u, exp1, exp2;

		if (jwk->kty != LWS_GENCRYPTO_KTY_RSA)
			goto bail;

		if (gnutls_privkey_export_rsa_raw(pkey, &m, &e, &d, &p, &q, &u, &exp1, &exp2) < 0)
			goto bail;

		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf = lws_malloc((size_t)d.size, "certjwk");
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].len = d.size;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf, d.data, d.size);

		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf = lws_malloc((size_t)p.size, "certjwk");
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].len = p.size;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf, p.data, p.size);

		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf = lws_malloc((size_t)q.size, "certjwk");
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].len = q.size;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf, q.data, q.size);

		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_QI].buf = lws_malloc((size_t)u.size, "certjwk");
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_QI].len = u.size;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_QI].buf, u.data, u.size);

		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DP].buf = lws_malloc((size_t)exp1.size, "certjwk");
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DP].len = exp1.size;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DP].buf, exp1.data, exp1.size);

		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf = lws_malloc((size_t)exp2.size, "certjwk");
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DQ].len = exp2.size;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf, exp2.data, exp2.size);

		gnutls_free(m.data); gnutls_free(e.data); gnutls_free(d.data);
		gnutls_free(p.data); gnutls_free(q.data); gnutls_free(u.data);
		gnutls_free(exp1.data); gnutls_free(exp2.data);
		break;
	}
	case GNUTLS_PK_ECC:
	{
		gnutls_ecc_curve_t curve;
		gnutls_datum_t x, y, k;

		if (jwk->kty != LWS_GENCRYPTO_KTY_EC)
			goto bail;

		if (gnutls_privkey_export_ecc_raw(pkey, &curve, &x, &y, &k) < 0)
			goto bail;

		jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].buf = lws_malloc((size_t)k.size, "certjwk");
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].len = k.size;
		memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].buf, k.data, k.size);

		gnutls_free(x.data); gnutls_free(y.data); gnutls_free(k.data);
		break;
	}
	default:
		goto bail;
	}

	ret = 0;
bail:
	gnutls_privkey_deinit(pkey);

	if (ret)
		lws_jwk_destroy(jwk);

	return ret;
}

int
lws_x509_info(struct lws_x509_cert *x509, enum lws_tls_cert_info type,
	      union lws_tls_cert_info_results *buf, size_t len)
{
	size_t s = len;

	switch (type) {
	case LWS_TLS_CERT_INFO_COMMON_NAME:
		if (gnutls_x509_crt_get_dn_by_oid(x509->cert, GNUTLS_OID_X520_COMMON_NAME,
						  0, 0, buf->ns.name, &s) < 0)
			return -1;
		buf->ns.len = (int)s;
		break;

	case LWS_TLS_CERT_INFO_VALIDITY_FROM:
		buf->time = gnutls_x509_crt_get_activation_time(x509->cert);
		if (buf->time == (time_t)-1)
			return -1;
		break;

	case LWS_TLS_CERT_INFO_VALIDITY_TO:
		buf->time = gnutls_x509_crt_get_expiration_time(x509->cert);
		if (buf->time == (time_t)-1)
			return -1;
		break;

	case LWS_TLS_CERT_INFO_DER_RAW:
	{
		gnutls_datum_t der;
		if (gnutls_x509_crt_export2(x509->cert, GNUTLS_X509_FMT_DER, &der) < 0)
			return -1;

		buf->ns.len = (int)der.size;
		if (len < der.size) {
			gnutls_free(der.data);
			return -1;
		}

		memcpy(buf->ns.name, der.data, der.size);
		gnutls_free(der.data);
		break;
	}

	default:
		return -1;
	}

	return 0;
}

void
lws_x509_destroy(struct lws_x509_cert **x509)
{
	if (!*x509)
		return;
	gnutls_x509_crt_deinit((*x509)->cert);
	lws_free(*x509);
	*x509 = NULL;
}
