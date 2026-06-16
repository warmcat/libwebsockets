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
#if !defined(LWS_HAVE_MBEDTLS_V4)
#include <mbedtls/asn1write.h>
#endif
#include <mbedtls/x509_csr.h>
#if defined(LWS_HAVE_MBEDTLS_V4)
#include <psa/crypto.h>
#include <mbedtls/pk.h>
#include <mbedtls/private/pk_private.h>
#endif

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

	if (!xtime || !xtime->MBEDTLS_PRIVATE_V30_ONLY(year) || xtime->MBEDTLS_PRIVATE_V30_ONLY(year) < 0)
		return (time_t)(long long)-1;

	memset(&t, 0, sizeof(t));

	t.tm_year = xtime->MBEDTLS_PRIVATE_V30_ONLY(year) - 1900;
	t.tm_mon = xtime->MBEDTLS_PRIVATE_V30_ONLY(mon) - 1; /* mbedtls months are 1+, tm are 0+ */
	t.tm_mday = xtime->MBEDTLS_PRIVATE_V30_ONLY(day) - 1; /* mbedtls days are 1+, tm are 0+ */
	t.tm_hour = xtime->MBEDTLS_PRIVATE_V30_ONLY(hour);
	t.tm_min = xtime->MBEDTLS_PRIVATE_V30_ONLY(min);
	t.tm_sec = xtime->MBEDTLS_PRIVATE_V30_ONLY(sec);
	t.tm_isdst = -1;

	return mktime(&t);
}

static int
lws_tls_mbedtls_get_x509_name(mbedtls_x509_name *name,
			      union lws_tls_cert_info_results *buf, size_t len)
{
	int r = -1;

	buf->ns.len = 0;

	while (name) {
		/*
		if (MBEDTLS_OID_CMP(type, &name->oid)) {
			name = name->next;
			continue;
		}
*/
		lws_strnncpy(&buf->ns.name[buf->ns.len],
			     (const char *)name->MBEDTLS_PRIVATE_V30_ONLY(val).MBEDTLS_PRIVATE_V30_ONLY(p),
			     name->MBEDTLS_PRIVATE_V30_ONLY(val).MBEDTLS_PRIVATE_V30_ONLY(len),
			     len - (size_t)buf->ns.len);
		buf->ns.len = (int)strlen(buf->ns.name);

		r = 0;
		name = name->MBEDTLS_PRIVATE_V30_ONLY(next);
	}

	return r;
}


int
lws_tls_mbedtls_cert_info(mbedtls_x509_crt *x509, enum lws_tls_cert_info type,
			  union lws_tls_cert_info_results *buf, size_t len)
{
	mbedtls_x509_buf skid;
	lws_mbedtls_x509_authority akid;

	if (!x509)
		return -1;

	if (!len)
		len = sizeof(buf->ns.name);

	switch (type) {
	case LWS_TLS_CERT_INFO_VALIDITY_FROM:
		buf->time = lws_tls_mbedtls_time_to_unix(&x509->MBEDTLS_PRIVATE_V30_ONLY(valid_from));
		if (buf->time == (time_t)(long long)-1)
			return -1;
		break;

	case LWS_TLS_CERT_INFO_VALIDITY_TO:
		buf->time = lws_tls_mbedtls_time_to_unix(&x509->MBEDTLS_PRIVATE_V30_ONLY(valid_to));
		if (buf->time == (time_t)(long long)-1)
			return -1;
		break;

	case LWS_TLS_CERT_INFO_COMMON_NAME:
		return lws_tls_mbedtls_get_x509_name(&x509->MBEDTLS_PRIVATE_V30_ONLY(subject), buf, len);

	case LWS_TLS_CERT_INFO_ISSUER_NAME:
		return lws_tls_mbedtls_get_x509_name(&x509->MBEDTLS_PRIVATE_V30_ONLY(issuer), buf, len);

	case LWS_TLS_CERT_INFO_USAGE:
		buf->usage = x509->MBEDTLS_PRIVATE(key_usage);
		break;

	case LWS_TLS_CERT_INFO_OPAQUE_PUBLIC_KEY:
	{
#if defined(LWS_HAVE_MBEDTLS_V4)
		lwsl_err("LWS_TLS_CERT_INFO_OPAQUE_PUBLIC_KEY not yet implemented for MbedTLS v4\n");
		return -1;
#else
		char *p = buf->ns.name;
		size_t r = len, u;

		switch (mbedtls_pk_get_type(&x509->MBEDTLS_PRIVATE_V30_ONLY(pk))) {
		case MBEDTLS_PK_RSA:
		{
			mbedtls_rsa_context *rsa = mbedtls_pk_rsa(x509->MBEDTLS_PRIVATE_V30_ONLY(pk));

			if (mbedtls_mpi_write_string(&rsa->MBEDTLS_PRIVATE(N), 16, p, r, &u))
				return -1;
			r -= u;
			p += u;
			if (mbedtls_mpi_write_string(&rsa->MBEDTLS_PRIVATE(E), 16, p, r, &u))
				return -1;

			p += u;
			buf->ns.len = lws_ptr_diff(p, buf->ns.name);
			break;
		}
		case MBEDTLS_PK_ECKEY:
		{
			mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(x509->MBEDTLS_PRIVATE_V30_ONLY(pk));

			if (mbedtls_mpi_write_string(&ecp->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), 16, p, r, &u))
				 return -1;
			r -= u;
			p += u;
			if (mbedtls_mpi_write_string(&ecp->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y), 16, p, r, &u))
				 return -1;
			r -= u;
			p += u;
			if (mbedtls_mpi_write_string(&ecp->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Z), 16, p, r, &u))
				 return -1;
			p += u;
			buf->ns.len = lws_ptr_diff(p, buf->ns.name);
			break;
		}
		default:
			lwsl_notice("%s: x509 has unsupported pubkey type %d\n",
				    __func__,
				    mbedtls_pk_get_type(&x509->MBEDTLS_PRIVATE_V30_ONLY(pk)));

			return -1;
		}
		break;
#endif
	}
	case LWS_TLS_CERT_INFO_DER_RAW:

		buf->ns.len = (int)x509->MBEDTLS_PRIVATE_V30_ONLY(raw).MBEDTLS_PRIVATE_V30_ONLY(len);

		if (len < x509->MBEDTLS_PRIVATE_V30_ONLY(raw).MBEDTLS_PRIVATE_V30_ONLY(len))
			/*
			 * The buffer is too small and the attempt failed, but
			 * the required object length is in buf->ns.len
			 */
			return -1;

		memcpy(buf->ns.name, x509->MBEDTLS_PRIVATE_V30_ONLY(raw).MBEDTLS_PRIVATE_V30_ONLY(p),
				x509->MBEDTLS_PRIVATE_V30_ONLY(raw).MBEDTLS_PRIVATE_V30_ONLY(len));
		break;

	case LWS_TLS_CERT_INFO_DER_SPKI:
	{
		uint8_t *tmp;
		int ret;
		
		/* mbedtls writes to the end of the buffer, so allocate a temporary one */
		/* SPKI won't exceed a few KB */
		tmp = lws_malloc(4096, "mbedtls_spki_der");
		if (!tmp)
			return -1;

		ret = mbedtls_pk_write_pubkey_der(&x509->MBEDTLS_PRIVATE_V30_ONLY(pk), tmp, 4096);
		if (ret < 0) {
			lws_free(tmp);
			return -1;
		}

		buf->ns.len = ret;

		if (len < (size_t)ret) {
			lws_free(tmp);
			return -1;
		}

		/* the result is written backwards, ending at tmp + 4096 */
		memcpy(buf->ns.name, tmp + 4096 - ret, (size_t)ret);
		lws_free(tmp);
		break;
	}

	case LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID:

		memset(&akid, 0, sizeof(akid));
		memset(&skid, 0, sizeof(skid));

		lws_x509_get_crt_ext(x509, &skid, &akid);
		if (akid.keyIdentifier.MBEDTLS_PRIVATE_V30_ONLY(tag) != MBEDTLS_ASN1_OCTET_STRING)
			return 1;
		buf->ns.len = (int)akid.keyIdentifier.MBEDTLS_PRIVATE_V30_ONLY(len);
		if (!akid.keyIdentifier.MBEDTLS_PRIVATE_V30_ONLY(p) ||
		    len < (size_t)buf->ns.len)
			return -1;
		memcpy(buf->ns.name, akid.keyIdentifier.MBEDTLS_PRIVATE_V30_ONLY(p), (size_t)buf->ns.len);
		break;

	case LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_ISSUER: {
		mbedtls_x509_sequence * ip;

		memset(&akid, 0, sizeof(akid));
		memset(&skid, 0, sizeof(skid));

		lws_x509_get_crt_ext(x509, &skid, &akid);

		ip = &akid.authorityCertIssuer;

		buf->ns.len = 0;

		while (ip) {
			if (akid.keyIdentifier.MBEDTLS_PRIVATE_V30_ONLY(tag) != MBEDTLS_ASN1_OCTET_STRING ||
			    !ip->MBEDTLS_PRIVATE_V30_ONLY(buf).MBEDTLS_PRIVATE_V30_ONLY(p) ||
			    ip->MBEDTLS_PRIVATE_V30_ONLY(buf).MBEDTLS_PRIVATE_V30_ONLY(len) < 9 ||
			    len < (size_t)ip->MBEDTLS_PRIVATE_V30_ONLY(buf).MBEDTLS_PRIVATE_V30_ONLY(len) - 9u)
			break;

			memcpy(buf->ns.name + buf->ns.len, ip->MBEDTLS_PRIVATE_V30_ONLY(buf).MBEDTLS_PRIVATE_V30_ONLY(p),
					(size_t)ip->MBEDTLS_PRIVATE_V30_ONLY(buf).MBEDTLS_PRIVATE_V30_ONLY(len) - 9);
			buf->ns.len = buf->ns.len + (int)ip->MBEDTLS_PRIVATE_V30_ONLY(buf).MBEDTLS_PRIVATE_V30_ONLY(len) - 9;

			ip = ip->MBEDTLS_PRIVATE_V30_ONLY(next);
		}
		break;
	}
	case LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_SERIAL:

		memset(&akid, 0, sizeof(akid));
		memset(&skid, 0, sizeof(skid));

		lws_x509_get_crt_ext(x509, &skid, &akid);

		if (akid.authorityCertSerialNumber.MBEDTLS_PRIVATE_V30_ONLY(tag) != MBEDTLS_ASN1_OCTET_STRING)
			return 1;
		buf->ns.len = (int)akid.authorityCertSerialNumber.MBEDTLS_PRIVATE_V30_ONLY(len);
		if (!akid.authorityCertSerialNumber.MBEDTLS_PRIVATE_V30_ONLY(p) ||
		    len < (size_t)buf->ns.len)
			return -1;
		memcpy(buf->ns.name, akid.authorityCertSerialNumber.
				MBEDTLS_PRIVATE_V30_ONLY(p), (size_t)buf->ns.len);
		break;

	case LWS_TLS_CERT_INFO_SUBJECT_KEY_ID:

		memset(&akid, 0, sizeof(akid));
		memset(&skid, 0, sizeof(skid));

		lws_x509_get_crt_ext(x509, &skid, &akid);

		if (skid.MBEDTLS_PRIVATE_V30_ONLY(tag) != MBEDTLS_ASN1_OCTET_STRING)
			return 1;
		buf->ns.len = (int)skid.MBEDTLS_PRIVATE_V30_ONLY(len);
		if (len < (size_t)buf->ns.len)
			return -1;
		memcpy(buf->ns.name, skid.MBEDTLS_PRIVATE_V30_ONLY(p), (size_t)buf->ns.len);
		break;
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

	if (!vhost->tls.ssl_ctx)
		return -1;

	x509 = vhost->tls.ssl_ctx->chain;

	return lws_tls_mbedtls_cert_info(x509, type, buf, len);
}

int
lws_tls_peer_cert_info(struct lws *wsi, enum lws_tls_cert_info type,
		       union lws_tls_cert_info_results *buf, size_t len)
{
	mbedtls_x509_crt *x509;

	wsi = lws_get_network_wsi(wsi);

	if (!wsi->tls.ssl)
		return -1;

	x509 = (mbedtls_x509_crt *)mbedtls_ssl_get_peer_cert(&wsi->tls.ssl->ssl);

	if (!x509)
		return -1;

	switch (type) {
	case LWS_TLS_CERT_INFO_VERIFIED:
		buf->verified = mbedtls_ssl_get_verify_result(&wsi->tls.ssl->ssl) == 0;
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
		if (ret > 0)
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
#if defined(LWS_HAVE_MBEDTLS_V4)
	int ret = -1;
	unsigned char der[4096];
	int der_len = mbedtls_pk_write_pubkey_der(&x509->cert.pk, der, sizeof(der));
	if (der_len < 0) {
		lwsl_err("%s: write pubkey der failed\n", __func__);
		return -1;
	}
	unsigned char *p = der + sizeof(der) - der_len;
	const unsigned char *end = der + sizeof(der);
	size_t asn1_len;

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	mbedtls_pk_get_psa_attributes(&x509->cert.pk, PSA_KEY_USAGE_VERIFY_HASH, &attr);
	psa_key_type_t type = psa_get_key_type(&attr);

	memset(jwk, 0, sizeof(*jwk));

	/* SubjectPublicKeyInfo ::= SEQUENCE */
	if (mbedtls_asn1_get_tag(&p, end, &asn1_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) goto bail;
	/* algorithm AlgorithmIdentifier ::= SEQUENCE */
	if (mbedtls_asn1_get_tag(&p, end, &asn1_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) goto bail;
	p += asn1_len; /* skip algorithm details */
	
	/* subjectPublicKey BIT STRING */
	if (mbedtls_asn1_get_tag(&p, end, &asn1_len, MBEDTLS_ASN1_BIT_STRING)) goto bail;
	if (*p == 0x00) { p++; asn1_len--; } /* Skip unused bits */

	if (PSA_KEY_TYPE_IS_RSA(type)) {
		jwk->kty = LWS_GENCRYPTO_KTY_RSA;
		/* RSAPublicKey ::= SEQUENCE */
		if (mbedtls_asn1_get_tag(&p, end, &asn1_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) goto bail;
		/* Modulus N */
		if (mbedtls_asn1_get_tag(&p, end, &asn1_len, MBEDTLS_ASN1_INTEGER)) goto bail;
		if (*p == 0x00) { p++; asn1_len--; }
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf = lws_malloc(asn1_len, "jwk_N");
		if (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf) goto bail;
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len = (uint32_t)asn1_len;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf, p, asn1_len);
		p += asn1_len;
		
		/* Exponent E */
		if (mbedtls_asn1_get_tag(&p, end, &asn1_len, MBEDTLS_ASN1_INTEGER)) goto bail;
		if (*p == 0x00) { p++; asn1_len--; }
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf = lws_malloc(asn1_len, "jwk_E");
		if (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf) goto bail;
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].len = (uint32_t)asn1_len;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf, p, asn1_len);
	} else if (PSA_KEY_TYPE_IS_ECC(type)) {
		jwk->kty = LWS_GENCRYPTO_KTY_EC;
		
		if (asn1_len < 1 || *p != 0x04) {
			lwsl_err("Only uncompressed EC points supported\n");
			goto bail;
		}
		p++; asn1_len--;
		if (asn1_len % 2 != 0) goto bail;
		size_t coord_len = asn1_len / 2;
		
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf = lws_malloc(coord_len, "jwk_X");
		if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf) goto bail;
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].len = (uint32_t)coord_len;
		memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf, p, coord_len);
		p += coord_len;
		
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf = lws_malloc(coord_len, "jwk_Y");
		if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf) goto bail;
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].len = (uint32_t)coord_len;
		memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf, p, coord_len);

		psa_ecc_family_t family = PSA_KEY_TYPE_ECC_GET_FAMILY(type);
		size_t bits = psa_get_key_bits(&attr);
		const char *crv = NULL;

		if (family == PSA_ECC_FAMILY_SECP_R1) {
			if (bits == 256) crv = "P-256";
			else if (bits == 384) crv = "P-384";
			else if (bits == 521) crv = "P-521";
		}
		
		if (!crv) {
			lwsl_err("Unsupported curve family=%d bits=%u\n", (int)family, (unsigned)bits);
			goto bail;
		}

		jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf = lws_malloc(strlen(crv) + 1, "jwk_crv");
		if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf) goto bail;
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].len = (uint32_t)strlen(crv);
		memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf, crv, strlen(crv) + 1);
	} else {
		lwsl_err("%s: key type %d not supported\n", __func__, (int)type);
		return -1;
	}

	ret = 0;

bail:
	if (ret) lws_jwk_destroy(jwk);
	return ret;
#else
	int kt = (int)mbedtls_pk_get_type(&x509->cert.MBEDTLS_PRIVATE_V30_ONLY(pk)),
			n, count = 0, ret = -1;
	mbedtls_rsa_context *rsactx;
	mbedtls_ecp_keypair *ecpctx;
	mbedtls_mpi *mpi[LWS_GENCRYPTO_RSA_KEYEL_COUNT];

	memset(jwk, 0, sizeof(*jwk));

	switch (kt) {
	case MBEDTLS_PK_RSA:
		lwsl_notice("%s: RSA key\n", __func__);
		jwk->kty = LWS_GENCRYPTO_KTY_RSA;
		rsactx = mbedtls_pk_rsa(x509->cert.MBEDTLS_PRIVATE_V30_ONLY(pk));

		mpi[LWS_GENCRYPTO_RSA_KEYEL_E] = &rsactx->MBEDTLS_PRIVATE(E);
		mpi[LWS_GENCRYPTO_RSA_KEYEL_N] = &rsactx->MBEDTLS_PRIVATE(N);
		mpi[LWS_GENCRYPTO_RSA_KEYEL_D] = &rsactx->MBEDTLS_PRIVATE(D);
		mpi[LWS_GENCRYPTO_RSA_KEYEL_P] = &rsactx->MBEDTLS_PRIVATE(P);
		mpi[LWS_GENCRYPTO_RSA_KEYEL_Q] = &rsactx->MBEDTLS_PRIVATE(Q);
		mpi[LWS_GENCRYPTO_RSA_KEYEL_DP] = &rsactx->MBEDTLS_PRIVATE(DP);
		mpi[LWS_GENCRYPTO_RSA_KEYEL_DQ] = &rsactx->MBEDTLS_PRIVATE(DQ);
		mpi[LWS_GENCRYPTO_RSA_KEYEL_QI] = &rsactx->MBEDTLS_PRIVATE(QP);

		count = LWS_GENCRYPTO_RSA_KEYEL_QI + 1;
		n = LWS_GENCRYPTO_RSA_KEYEL_E;
		break;

	case MBEDTLS_PK_ECKEY:
		lwsl_notice("%s: EC key\n", __func__);
		jwk->kty = LWS_GENCRYPTO_KTY_EC;
		ecpctx = mbedtls_pk_ec(x509->cert.MBEDTLS_PRIVATE_V30_ONLY(pk));
		mpi[LWS_GENCRYPTO_EC_KEYEL_X] = &ecpctx->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X);
		mpi[LWS_GENCRYPTO_EC_KEYEL_D] = &ecpctx->MBEDTLS_PRIVATE(d);
		mpi[LWS_GENCRYPTO_EC_KEYEL_Y] = &ecpctx->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y);

		if (lws_genec_confirm_curve_allowed_by_tls_id(curves,
				(int)ecpctx->MBEDTLS_PRIVATE(grp).id, jwk))
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
		jwk->e[n].len = (uint32_t)mbedtls_mpi_size(mpi[n]);
		mbedtls_mpi_write_binary(mpi[n], jwk->e[n].buf, jwk->e[n].len);
	}

	ret = 0;

bail:
	/* jwk destroy will clean up partials */
	if (ret)
		lws_jwk_destroy(jwk);

	return ret;
#endif
}

int
lws_x509_jwk_privkey_pem(struct lws_context *cx, struct lws_jwk *jwk,
			 void *pem, size_t len, const char *passphrase)
{
#if defined(LWS_HAVE_MBEDTLS_V4)
	mbedtls_pk_context pk;
	int n, ret = -1;
	unsigned char der[4096];
	int der_len;

	mbedtls_pk_init(&pk);
	n = passphrase ? (int)strlen(passphrase) : 0;
	n = mbedtls_pk_parse_key(&pk, pem, len, (uint8_t *)passphrase, (size_t)n);
	if (n) {
		lwsl_err("%s: parse PEM key failed: -0x%x\n", __func__, -n);
		return -1;
	}

	der_len = mbedtls_pk_write_key_der(&pk, der, sizeof(der));
	if (der_len < 0) {
		lwsl_err("%s: write key der failed\n", __func__);
		goto bail;
	}

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	mbedtls_pk_get_psa_attributes(&pk, PSA_KEY_USAGE_SIGN_HASH, &attr);
	psa_key_type_t type = psa_get_key_type(&attr);

	unsigned char *p = der + sizeof(der) - der_len;
	const unsigned char *end = der + sizeof(der);
	size_t asn1_len;

	if (PSA_KEY_TYPE_IS_RSA(type)) {
		if (jwk->kty != LWS_GENCRYPTO_KTY_RSA) {
			lwsl_err("%s: RSA privkey, non-RSA jwk\n", __func__);
			goto bail;
		}
		
		/* RSAPrivateKey ::= SEQUENCE */
		if (mbedtls_asn1_get_tag(&p, end, &asn1_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) goto bail;
		/* version Version */
		if (mbedtls_asn1_get_tag(&p, end, &asn1_len, MBEDTLS_ASN1_INTEGER)) goto bail;
		p += asn1_len;
		
		/* Modulus N */
		if (mbedtls_asn1_get_tag(&p, end, &asn1_len, MBEDTLS_ASN1_INTEGER)) goto bail;
		p += asn1_len;
		/* Exponent E */
		if (mbedtls_asn1_get_tag(&p, end, &asn1_len, MBEDTLS_ASN1_INTEGER)) goto bail;
		p += asn1_len;

		/* Exponent D */
		if (mbedtls_asn1_get_tag(&p, end, &asn1_len, MBEDTLS_ASN1_INTEGER)) goto bail;
		if (*p == 0x00) { p++; asn1_len--; }
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf = lws_malloc(asn1_len, "jwk_D");
		if (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf) goto bail;
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].len = (uint32_t)asn1_len;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf, p, asn1_len);
		p += asn1_len;

		/* Prime P */
		if (mbedtls_asn1_get_tag(&p, end, &asn1_len, MBEDTLS_ASN1_INTEGER)) goto bail;
		if (*p == 0x00) { p++; asn1_len--; }
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf = lws_malloc(asn1_len, "jwk_P");
		if (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf) goto bail;
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].len = (uint32_t)asn1_len;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf, p, asn1_len);
		p += asn1_len;

		/* Prime Q */
		if (mbedtls_asn1_get_tag(&p, end, &asn1_len, MBEDTLS_ASN1_INTEGER)) goto bail;
		if (*p == 0x00) { p++; asn1_len--; }
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf = lws_malloc(asn1_len, "jwk_Q");
		if (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf) goto bail;
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].len = (uint32_t)asn1_len;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf, p, asn1_len);
		p += asn1_len;

		/* Exponent DP */
		if (mbedtls_asn1_get_tag(&p, end, &asn1_len, MBEDTLS_ASN1_INTEGER)) goto bail;
		if (*p == 0x00) { p++; asn1_len--; }
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DP].buf = lws_malloc(asn1_len, "jwk_DP");
		if (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DP].buf) goto bail;
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DP].len = (uint32_t)asn1_len;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DP].buf, p, asn1_len);
		p += asn1_len;

		/* Exponent DQ */
		if (mbedtls_asn1_get_tag(&p, end, &asn1_len, MBEDTLS_ASN1_INTEGER)) goto bail;
		if (*p == 0x00) { p++; asn1_len--; }
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf = lws_malloc(asn1_len, "jwk_DQ");
		if (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf) goto bail;
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DQ].len = (uint32_t)asn1_len;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf, p, asn1_len);
		p += asn1_len;

		/* Coefficient QI */
		if (mbedtls_asn1_get_tag(&p, end, &asn1_len, MBEDTLS_ASN1_INTEGER)) goto bail;
		if (*p == 0x00) { p++; asn1_len--; }
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_QI].buf = lws_malloc(asn1_len, "jwk_QI");
		if (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_QI].buf) goto bail;
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_QI].len = (uint32_t)asn1_len;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_QI].buf, p, asn1_len);
		p += asn1_len;

	} else if (PSA_KEY_TYPE_IS_ECC(type)) {
		if (jwk->kty != LWS_GENCRYPTO_KTY_EC) {
			lwsl_err("%s: EC privkey, non-EC jwk\n", __func__);
			goto bail;
		}

		/* ECPrivateKey ::= SEQUENCE */
		if (mbedtls_asn1_get_tag(&p, end, &asn1_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) goto bail;
		/* version Version */
		if (mbedtls_asn1_get_tag(&p, end, &asn1_len, MBEDTLS_ASN1_INTEGER)) goto bail;
		p += asn1_len;
		/* privateKey OCTET STRING */
		if (mbedtls_asn1_get_tag(&p, end, &asn1_len, MBEDTLS_ASN1_OCTET_STRING)) goto bail;
		
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].buf = lws_malloc(asn1_len, "jwk_D");
		if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].buf) goto bail;
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].len = (uint32_t)asn1_len;
		memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].buf, p, asn1_len);
		p += asn1_len;

	} else {
		lwsl_err("%s: key type %d not supported\n", __func__, (int)type);
		goto bail;
	}

	ret = 0;

bail:
	mbedtls_pk_free(&pk);
	return ret;
#else
	mbedtls_rsa_context *rsactx;
	mbedtls_ecp_keypair *ecpctx;
	mbedtls_pk_context pk;
	mbedtls_mpi *mpi[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
	int n, ret = -1, count = 0;

	mbedtls_pk_init(&pk);

	n = 0;
	if (passphrase)
		n = (int)strlen(passphrase);
	n = mbedtls_pk_parse_key(&pk, pem, len, (uint8_t *)passphrase, (unsigned int)n
#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000 && !defined(LWS_HAVE_MBEDTLS_V4)
					, mbedtls_ctr_drbg_random, &cx->mcdc
#endif
			);
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
		mpi[LWS_GENCRYPTO_RSA_KEYEL_D] = &rsactx->MBEDTLS_PRIVATE(D);
		mpi[LWS_GENCRYPTO_RSA_KEYEL_P] = &rsactx->MBEDTLS_PRIVATE(P);
		mpi[LWS_GENCRYPTO_RSA_KEYEL_Q] = &rsactx->MBEDTLS_PRIVATE(Q);
		n = LWS_GENCRYPTO_RSA_KEYEL_D;
		count = LWS_GENCRYPTO_RSA_KEYEL_Q + 1;
		break;
	case MBEDTLS_PK_ECKEY:
		if (jwk->kty != LWS_GENCRYPTO_KTY_EC) {
			lwsl_err("%s: EC privkey, non-EC jwk\n", __func__);
			goto bail;
		}
		ecpctx = mbedtls_pk_ec(pk);
		mpi[LWS_GENCRYPTO_EC_KEYEL_D] = &ecpctx->MBEDTLS_PRIVATE(d);
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
		jwk->e[n].len = (uint32_t)mbedtls_mpi_size(mpi[n]);
		mbedtls_mpi_write_binary(mpi[n], jwk->e[n].buf, jwk->e[n].len);
	}

	ret = 0;

bail:
	mbedtls_pk_free(&pk);

	return ret;
#endif
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

int
lws_x509_create_cert(struct lws_context *context,
		     uint8_t **cert_buf, size_t *cert_len,
		     uint8_t **key_buf, size_t *key_len,
		     const struct lws_x509_cert_gen_info *info)
{
	int ret = 1;
#if defined(LWS_HAVE_MBEDTLS_V4)
	lwsl_err("Self-signed cert generation not yet implemented for MbedTLS v4\n");
	return ret;
#else
	mbedtls_x509write_cert crt;
	mbedtls_pk_context key;
	mbedtls_mpi serial;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_context *pdrbg = &ctr_drbg;
	mbedtls_x509_crt issuer_crt;
	mbedtls_pk_context issuer_key;
	unsigned char buf[4096];
	char name[128];
	int len;

	if (!info || !info->san)
		return 1;

	mbedtls_x509write_crt_init(&crt);
	mbedtls_pk_init(&key);
	mbedtls_mpi_init(&serial);
	mbedtls_x509_crt_init(&issuer_crt);
	mbedtls_pk_init(&issuer_key);

	if (context) {
		pdrbg = &context->mcdc;
	} else {
		mbedtls_ctr_drbg_init(&ctr_drbg);
		mbedtls_entropy_init(&entropy);
		if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
					  (const unsigned char *)"lws_cert_gen", 12))
			goto bail;
	}

	if (info->curve_name) {
		mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_NONE;
		if (!strcmp(info->curve_name, "P-521")) grp_id = MBEDTLS_ECP_DP_SECP521R1;
		else if (!strcmp(info->curve_name, "P-384")) grp_id = MBEDTLS_ECP_DP_SECP384R1;
		else if (!strcmp(info->curve_name, "P-256")) grp_id = MBEDTLS_ECP_DP_SECP256R1;

		if (grp_id == MBEDTLS_ECP_DP_NONE) {
			lwsl_err("%s: unknown curve %s\n", __func__, info->curve_name);
			goto bail;
		}

		ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
		if (ret) goto bail;

		ret = mbedtls_ecp_gen_key(grp_id, mbedtls_pk_ec(key), mbedtls_ctr_drbg_random, pdrbg);
		if (ret) goto bail;
	} else {
		ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
		if (ret) goto bail;

		ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, pdrbg,
					(unsigned int)(info->key_bits ? info->key_bits : 2048), 65537);
		if (ret) goto bail;
	}

	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
	mbedtls_x509write_crt_set_subject_key(&crt, &key);

#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000
	{
		uint8_t serial_val[8];
		mbedtls_ctr_drbg_random(pdrbg, serial_val, sizeof(serial_val));
		serial_val[0] &= 0x7f; /* Positive */
		if (mbedtls_x509write_crt_set_serial_raw(&crt, serial_val, sizeof(serial_val)))
			goto bail;
	}
#else
	{
		unsigned char rnd[8];
		mbedtls_ctr_drbg_random(pdrbg, rnd, sizeof(rnd));
		rnd[0] &= 0x7f; /* Positive */
		if (mbedtls_mpi_read_binary(&serial, rnd, sizeof(rnd)))
			goto bail;
		mbedtls_x509write_crt_set_serial(&crt, &serial);
	}
#endif

	lws_snprintf(name, sizeof(name), "CN=%s", info->san);
	if (mbedtls_x509write_crt_set_subject_name(&crt, name))
		goto bail;

	if (info->ca_cert_pem && info->ca_key_pem) {
		char issuer_name[256];
		ret = mbedtls_x509_crt_parse(&issuer_crt, (const unsigned char *)info->ca_cert_pem, strlen(info->ca_cert_pem) + 1);
		if (ret) goto bail;

		ret = mbedtls_pk_parse_key(&issuer_key, (const unsigned char *)info->ca_key_pem, strlen(info->ca_key_pem) + 1, NULL, 0
#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000
					, mbedtls_ctr_drbg_random, pdrbg
#endif
		);
		if (ret) goto bail;

		mbedtls_x509write_crt_set_issuer_key(&crt, &issuer_key);

		ret = mbedtls_x509_dn_gets(issuer_name, sizeof(issuer_name), &issuer_crt.MBEDTLS_PRIVATE_V30_ONLY(subject));
		if (ret < 0) goto bail;
		if (mbedtls_x509write_crt_set_issuer_name(&crt, issuer_name))
			goto bail;
	} else {
		mbedtls_x509write_crt_set_issuer_key(&crt, &key);
		if (mbedtls_x509write_crt_set_issuer_name(&crt, name))
			goto bail;
	}

	{
		char not_before[16], not_after[16];
		time_t t;
		struct tm *tm;

		time(&t);
		t -= 86400;
		tm = gmtime(&t);
		lws_snprintf(not_before, sizeof(not_before), "%04d%02d%02d%02d%02d%02d",
			tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec);

		t += 86400;
		t += (time_t)(info->validity_days ? info->validity_days : 365) * 24 * 3600;
		tm = gmtime(&t);
		lws_snprintf(not_after, sizeof(not_after), "%04d%02d%02d%02d%02d%02d",
			tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec);

		if (mbedtls_x509write_crt_set_validity(&crt, not_before, not_after))
			goto bail;
	}

	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);

	/* Extensions */
	mbedtls_x509write_crt_set_basic_constraints(&crt, info->is_ca ? 1 : 0, -1);

	if (info->is_ca) {
		mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN);
	} else {
		mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
							  MBEDTLS_X509_KU_KEY_ENCIPHERMENT);
	}

#if defined(MBEDTLS_OID_SERVER_AUTH) && defined(MBEDTLS_OID_CLIENT_AUTH)
	{
		const char *serverAuth = MBEDTLS_OID_SERVER_AUTH;
		const char *clientAuth = MBEDTLS_OID_CLIENT_AUTH;
		mbedtls_asn1_named_data *ext_key_usage = NULL;

		if (info->is_server) {
			if (mbedtls_asn1_store_named_data(&ext_key_usage, serverAuth, strlen(serverAuth), NULL, 0) == NULL)
				goto bail;
		}
		if (mbedtls_asn1_store_named_data(&ext_key_usage, clientAuth, strlen(clientAuth), NULL, 0) == NULL)
			goto bail;
	}
#endif

	/* Cert Output */
	len = mbedtls_x509write_crt_der(&crt, buf, sizeof(buf), mbedtls_ctr_drbg_random, pdrbg);
	if (len < 0) {
		lwsl_err("%s: crt_der failed %d\n", __func__, len);
		goto bail;
	}

	/* mbedtls writes to end of buffer */
	*cert_buf = malloc((size_t)len);
	if (!*cert_buf) goto bail;
	memcpy(*cert_buf, buf + sizeof(buf) - len, (size_t)len);
	*cert_len = (size_t)len;

	/* Key Output - writes to end of buffer */
	len = mbedtls_pk_write_key_der(&key, buf, sizeof(buf));
	if (len < 0) {
		free(*cert_buf);
		goto bail;
	}

	*key_buf = malloc((size_t)len);
	if (!*key_buf) {
		free(*cert_buf);
		goto bail;
	}
	memcpy(*key_buf, buf + sizeof(buf) - len, (size_t)len);
	*key_len = (size_t)len;

	ret = 0;

bail:
	mbedtls_x509write_crt_free(&crt);
	mbedtls_pk_free(&key);
	mbedtls_mpi_free(&serial);
	mbedtls_x509_crt_free(&issuer_crt);
	mbedtls_pk_free(&issuer_key);
	if (!context) {
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);
	}

	return ret;
#endif
}

int
lws_x509_create_self_signed(struct lws_context *context,
			    uint8_t **cert_buf, size_t *cert_len,
			    uint8_t **key_buf, size_t *key_len,
			    const char *san, int key_bits)
{
	struct lws_x509_cert_gen_info info;

	memset(&info, 0, sizeof(info));
	info.san = san ? san : "localhost";
	info.key_bits = key_bits;
	info.is_server = 1;

	return lws_x509_create_cert(context, cert_buf, cert_len, key_buf, key_len, &info);
}
