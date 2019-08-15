/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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
#include "private-lib-tls-mbedtls.h"
#include <mbedtls/oid.h>

#if defined(LWS_PLAT_OPTEE) || defined(OPTEE_DEV_KIT)
struct tm {
int    tm_sec; //   seconds [0,61]
int    tm_min; //   minutes [0,59]
int    tm_hour; //  hour [0,23]
int    tm_mday; //  day of month [1,31]
int    tm_mon; //   month of year [0,11]
int    tm_year; //  years since 1900
int    tm_wday; //  day of week [0,6] (Sunday = 0)
int    tm_yday; //  day of year [0,365]
int    tm_isdst; // daylight savings flag
};
time_t mktime(struct tm *t)
{
	return (time_t)0;
}
#endif

static time_t
lws_tls_mbedtls_time_to_unix(mbedtls_x509_time *xtime)
{
	struct tm t;

	if (!xtime || !xtime->year || xtime->year < 0)
		return (time_t)(long long)-1;

	memset(&t, 0, sizeof(t));

	t.tm_year = xtime->year - 1900;
	t.tm_mon = xtime->mon - 1; /* mbedtls months are 1+, tm are 0+ */
	t.tm_mday = xtime->day - 1; /* mbedtls days are 1+, tm are 0+ */
	t.tm_hour = xtime->hour;
	t.tm_min = xtime->min;
	t.tm_sec = xtime->sec;
	t.tm_isdst = -1;

	return mktime(&t);
}

static int
lws_tls_mbedtls_get_x509_name(mbedtls_x509_name *name,
			      union lws_tls_cert_info_results *buf, size_t len)
{
	while (name) {
		if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &name->oid)) {
			name = name->next;
			continue;
		}

		if (len - 1 < name->val.len)
			return -1;

		memcpy(&buf->ns.name[0], name->val.p, name->val.len);
		buf->ns.name[name->val.len] = '\0';
		buf->ns.len = name->val.len;

		return 0;
	}

	return -1;
}

static int
lws_tls_mbedtls_cert_info(mbedtls_x509_crt *x509, enum lws_tls_cert_info type,
			  union lws_tls_cert_info_results *buf, size_t len)
{
	if (!x509)
		return -1;

	switch (type) {
	case LWS_TLS_CERT_INFO_VALIDITY_FROM:
		buf->time = lws_tls_mbedtls_time_to_unix(&x509->valid_from);
		if (buf->time == (time_t)(long long)-1)
			return -1;
		break;

	case LWS_TLS_CERT_INFO_VALIDITY_TO:
		buf->time = lws_tls_mbedtls_time_to_unix(&x509->valid_to);
		if (buf->time == (time_t)(long long)-1)
			return -1;
		break;

	case LWS_TLS_CERT_INFO_COMMON_NAME:
		return lws_tls_mbedtls_get_x509_name(&x509->subject, buf, len);

	case LWS_TLS_CERT_INFO_ISSUER_NAME:
		return lws_tls_mbedtls_get_x509_name(&x509->issuer, buf, len);

	case LWS_TLS_CERT_INFO_USAGE:
		buf->usage = x509->key_usage;
		break;

	case LWS_TLS_CERT_INFO_OPAQUE_PUBLIC_KEY:
	{
		char *p = buf->ns.name;
		size_t r = len, u;

		switch (mbedtls_pk_get_type(&x509->pk)) {
		case MBEDTLS_PK_RSA:
		{
			mbedtls_rsa_context *rsa = mbedtls_pk_rsa(x509->pk);

			if (mbedtls_mpi_write_string(&rsa->N, 16, p, r, &u))
				return -1;
			r -= u;
			p += u;
			if (mbedtls_mpi_write_string(&rsa->E, 16, p, r, &u))
				return -1;

			p += u;
			buf->ns.len = lws_ptr_diff(p, buf->ns.name);
			break;
		}
		case MBEDTLS_PK_ECKEY:
		{
			mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(x509->pk);

			if (mbedtls_mpi_write_string(&ecp->Q.X, 16, p, r, &u))
				 return -1;
			r -= u;
			p += u;
			if (mbedtls_mpi_write_string(&ecp->Q.Y, 16, p, r, &u))
				 return -1;
			r -= u;
			p += u;
			if (mbedtls_mpi_write_string(&ecp->Q.Z, 16, p, r, &u))
				 return -1;
			p += u;
			buf->ns.len = lws_ptr_diff(p, buf->ns.name);
			break;
		}
		default:
			lwsl_notice("%s: x509 has unsupported pubkey type %d\n",
				    __func__,
				    mbedtls_pk_get_type(&x509->pk));

			return -1;
		}
		break;
	}

	default:
		return -1;
	}

	return 0;
}

#if defined(LWS_WITH_NETWORK)
int
lws_tls_vhost_cert_info(struct lws_vhost *vhost, enum lws_tls_cert_info type,
		        union lws_tls_cert_info_results *buf, size_t len)
{
	mbedtls_x509_crt *x509;

	x509 = ssl_ctx_get_mbedtls_x509_crt(vhost->tls.ssl_ctx);

	return lws_tls_mbedtls_cert_info(x509, type, buf, len);
}

int
lws_tls_peer_cert_info(struct lws *wsi, enum lws_tls_cert_info type,
		       union lws_tls_cert_info_results *buf, size_t len)
{
	mbedtls_x509_crt *x509;

	wsi = lws_get_network_wsi(wsi);

	x509 = ssl_get_peer_mbedtls_x509_crt(wsi->tls.ssl);

	if (!x509)
		return -1;

	switch (type) {
	case LWS_TLS_CERT_INFO_VERIFIED:
		buf->verified = SSL_get_verify_result(wsi->tls.ssl) == X509_V_OK;
		return 0;
	default:
		return lws_tls_mbedtls_cert_info(x509, type, buf, len);
	}

	return -1;
}
#endif

int
lws_x509_info(struct lws_x509_cert *x509, enum lws_tls_cert_info type,
	      union lws_tls_cert_info_results *buf, size_t len)
{
	return lws_tls_mbedtls_cert_info(&x509->cert, type, buf, len);
}

int
lws_x509_create(struct lws_x509_cert **x509)
{
	*x509 = lws_malloc(sizeof(**x509), __func__);

	return !(*x509);
}

/*
 * Parse one DER-encoded or one or more concatenated PEM-encoded certificates
 * and add them to the chained list.
 */

int
lws_x509_parse_from_pem(struct lws_x509_cert *x509, const void *pem, size_t len)
{
	int ret;

	mbedtls_x509_crt_init(&x509->cert);

	ret = mbedtls_x509_crt_parse(&x509->cert, pem, len);
	if (ret) {
		mbedtls_x509_crt_free(&x509->cert);
		lwsl_err("%s: unable to parse PEM cert: -0x%x\n",
			 __func__, -ret);

		return -1;
	}

	return 0;
}

int
lws_x509_verify(struct lws_x509_cert *x509, struct lws_x509_cert *trusted,
		const char *common_name)
{
	uint32_t flags = 0;
	int ret;

	ret = mbedtls_x509_crt_verify_with_profile(&x509->cert, &trusted->cert,
						   NULL,
						   &mbedtls_x509_crt_profile_next,
						   common_name, &flags, NULL,
						   NULL);

	if (ret) {
		lwsl_err("%s: unable to parse PEM cert: -0x%x\n",
			 __func__, -ret);

		return -1;
	}

	return 0;
}

#if defined(LWS_WITH_JOSE)

int
lws_x509_public_to_jwk(struct lws_jwk *jwk, struct lws_x509_cert *x509,
		       const char *curves, int rsa_min_bits)
{
	int kt = mbedtls_pk_get_type(&x509->cert.pk), n, count = 0, ret = -1;
	mbedtls_rsa_context *rsactx;
	mbedtls_ecp_keypair *ecpctx;
	mbedtls_mpi *mpi[LWS_GENCRYPTO_RSA_KEYEL_COUNT];

	memset(jwk, 0, sizeof(*jwk));

	switch (kt) {
	case MBEDTLS_PK_RSA:
		lwsl_notice("%s: RSA key\n", __func__);
		jwk->kty = LWS_GENCRYPTO_KTY_RSA;
		rsactx = mbedtls_pk_rsa(x509->cert.pk);

		mpi[LWS_GENCRYPTO_RSA_KEYEL_E] = &rsactx->E;
		mpi[LWS_GENCRYPTO_RSA_KEYEL_N] = &rsactx->N;
		mpi[LWS_GENCRYPTO_RSA_KEYEL_D] = &rsactx->D;
		mpi[LWS_GENCRYPTO_RSA_KEYEL_P] = &rsactx->P;
		mpi[LWS_GENCRYPTO_RSA_KEYEL_Q] = &rsactx->Q;
		mpi[LWS_GENCRYPTO_RSA_KEYEL_DP] = &rsactx->DP;
		mpi[LWS_GENCRYPTO_RSA_KEYEL_DQ] = &rsactx->DQ;
		mpi[LWS_GENCRYPTO_RSA_KEYEL_QI] = &rsactx->QP;

		count = LWS_GENCRYPTO_RSA_KEYEL_COUNT;
		n = LWS_GENCRYPTO_RSA_KEYEL_E;
		break;

	case MBEDTLS_PK_ECKEY:
		lwsl_notice("%s: EC key\n", __func__);
		jwk->kty = LWS_GENCRYPTO_KTY_EC;
		ecpctx = mbedtls_pk_ec(x509->cert.pk);
		mpi[LWS_GENCRYPTO_EC_KEYEL_X] = &ecpctx->Q.X;
		mpi[LWS_GENCRYPTO_EC_KEYEL_D] = &ecpctx->d;
		mpi[LWS_GENCRYPTO_EC_KEYEL_Y] = &ecpctx->Q.Y;

		if (lws_genec_confirm_curve_allowed_by_tls_id(curves,
				ecpctx->grp.id, jwk))
			/* already logged */
			goto bail;

		count = LWS_GENCRYPTO_EC_KEYEL_COUNT;
		n = LWS_GENCRYPTO_EC_KEYEL_X;
		break;
	default:
		lwsl_err("%s: key type %d not supported\n", __func__, kt);

		return -1;
	}

	for (; n < count; n++) {
		if (!mbedtls_mpi_size(mpi[n]))
			continue;

		jwk->e[n].buf = lws_malloc(mbedtls_mpi_size(mpi[n]), "certjwk");
		if (!jwk->e[n].buf)
			goto bail;
		jwk->e[n].len = mbedtls_mpi_size(mpi[n]);
		mbedtls_mpi_write_binary(mpi[n], jwk->e[n].buf, jwk->e[n].len);
	}

	ret = 0;

bail:
	/* jwk destroy will clean up partials */
	if (ret)
		lws_jwk_destroy(jwk);

	return ret;
}

int
lws_x509_jwk_privkey_pem(struct lws_jwk *jwk, void *pem, size_t len,
			 const char *passphrase)
{
	mbedtls_rsa_context *rsactx;
	mbedtls_ecp_keypair *ecpctx;
	mbedtls_pk_context pk;
	mbedtls_mpi *mpi[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
	int n, ret = -1, count = 0;

	mbedtls_pk_init(&pk);

	n = 0;
	if (passphrase)
		n = strlen(passphrase);
	n = mbedtls_pk_parse_key(&pk, pem, len, (uint8_t *)passphrase, n);
	if (n) {
		lwsl_err("%s: parse PEM key failed: -0x%x\n", __func__, -n);

		return -1;
	}

	/* the incoming private key type */
	switch (mbedtls_pk_get_type(&pk)) {
	case MBEDTLS_PK_RSA:
		if (jwk->kty != LWS_GENCRYPTO_KTY_RSA) {
			lwsl_err("%s: RSA privkey, non-RSA jwk\n", __func__);
			goto bail;
		}
		rsactx = mbedtls_pk_rsa(pk);
		mpi[LWS_GENCRYPTO_RSA_KEYEL_D] = &rsactx->D;
		mpi[LWS_GENCRYPTO_RSA_KEYEL_P] = &rsactx->P;
		mpi[LWS_GENCRYPTO_RSA_KEYEL_Q] = &rsactx->Q;
		n = LWS_GENCRYPTO_RSA_KEYEL_D;
		count = LWS_GENCRYPTO_RSA_KEYEL_Q + 1;
		break;
	case MBEDTLS_PK_ECKEY:
		if (jwk->kty != LWS_GENCRYPTO_KTY_EC) {
			lwsl_err("%s: EC privkey, non-EC jwk\n", __func__);
			goto bail;
		}
		ecpctx = mbedtls_pk_ec(pk);
		mpi[LWS_GENCRYPTO_EC_KEYEL_D] = &ecpctx->d;
		n = LWS_GENCRYPTO_EC_KEYEL_D;
		count = n + 1;
		break;
	default:
		lwsl_err("%s: unusable key type %d\n", __func__,
				mbedtls_pk_get_type(&pk));
		goto bail;
	}

	for (; n < count; n++) {
		if (!mbedtls_mpi_size(mpi[n])) {
			lwsl_err("%s: empty privkey\n", __func__);
			goto bail;
		}

		jwk->e[n].buf = lws_malloc(mbedtls_mpi_size(mpi[n]), "certjwk");
		if (!jwk->e[n].buf)
			goto bail;
		jwk->e[n].len = mbedtls_mpi_size(mpi[n]);
		mbedtls_mpi_write_binary(mpi[n], jwk->e[n].buf, jwk->e[n].len);
	}

	ret = 0;

bail:
	mbedtls_pk_free(&pk);

	return ret;
}
#endif

void
lws_x509_destroy(struct lws_x509_cert **x509)
{
	if (!*x509)
		return;

	mbedtls_x509_crt_free(&(*x509)->cert);

	lws_free_set_NULL(*x509);
}
