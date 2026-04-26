/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
#include "private-lib-tls-bearssl.h"


int lws_x509_create(struct lws_x509_cert **x509) {
	*x509 = lws_zalloc(sizeof(**x509), "x509_create");
	return !(*x509);
}

void lws_x509_destroy(struct lws_x509_cert **x509) {
	if (!*x509)
		return;
	if ((*x509)->der)
		lws_free((*x509)->der);
	lws_free(*x509);
	*x509 = NULL;
}

int lws_x509_parse_from_pem(struct lws_x509_cert *x509, const void *pem, size_t len) {
	lws_filepos_t amount;
	/* lws_tls_alloc_pem_to_der_file handles the base64/PEM decoding for us */
	if (!lws_tls_alloc_pem_to_der_file(NULL, NULL, pem, len, &x509->der, &amount)) {
		x509->der_len = (size_t)amount;
		return 0;
	}
	return -1;
}

/* Secure ASN.1 TLV parser. Returns 0 on success, -1 on bounds error/invalid */
static int
lws_asn1_get_tlv(const uint8_t **p, const uint8_t *end, int *tag, size_t *len)
{
	if (*p >= end) return -1;
	*tag = *(*p)++;
	if (*p >= end) return -1;
	size_t l = *(*p)++;
	if (l & 0x80) {
		int bytes = l & 0x7F;
		if (bytes == 0 || bytes > 4 || *p + bytes > end) return -1;
		l = 0;
		while (bytes--)
			l = (l << 8) | *(*p)++;
	}
	if (*p + l > end || *p + l < *p) return -1; /* Overflow check */
	*len = l;
	return 0;
}

/* Extracts Common Name (2.5.4.3) or Issuer string from a Name SEQUENCE */
static int
lws_x509_extract_name(const uint8_t *name, size_t name_len, int get_cn, union lws_tls_cert_info_results *buf, size_t max_len)
{
	const uint8_t *p = name, *end = name + name_len;
	int tag; size_t len;
	int found_cn = 0;

	/*
	 * JIT_TRUST logs the ISSUER_NAME. Returning the CN from the issuer is
	 * usually sufficient for logging if a full stringizer isn't available.
	 */

	while (p < end) {
		/* SET */
		if (lws_asn1_get_tlv(&p, end, &tag, &len) || tag != 0x31) return -1;
		const uint8_t *s_end = p + len;
		while (p < s_end) {
			/* SEQUENCE */
			if (lws_asn1_get_tlv(&p, s_end, &tag, &len) || tag != 0x30) return -1;
			const uint8_t *sq_end = p + len;
			/* OID */
			if (lws_asn1_get_tlv(&p, sq_end, &tag, &len) || tag != 0x06) return -1;
			const uint8_t *oid = p; size_t oid_len = len; p += len;
			/* Value */
			if (lws_asn1_get_tlv(&p, sq_end, &tag, &len)) return -1;
			const uint8_t *val = p; size_t val_len = len; p += len;

			/* OID 2.5.4.3 -> 55 04 03 (Common Name) */
			if (oid_len == 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x03) {
				if (val_len >= max_len) return -1;
				memcpy(buf->ns.name, val, val_len);
				buf->ns.name[val_len] = '\0';
				buf->ns.len = (int)val_len;
				found_cn = 1;
				if (get_cn) return 0;
			}
		}
	}
	/* If we were asked for Issuer and couldn't format it nicely, we can return the CN we found,
	 * or return -1. Since JIT_TRUST only logs it, returning the CN of the issuer is helpful. */
	if (!get_cn && found_cn) return 0;
	return -1;
}

int lws_x509_info(struct lws_x509_cert *x509, enum lws_tls_cert_info type, union lws_tls_cert_info_results *buf, size_t len) {
	if (!x509 || !x509->der) return -1;

	if (type == LWS_TLS_CERT_INFO_DER_RAW) {
		if (x509->der_len > len) {
			buf->ns.len = (int)x509->der_len;
			return -1;
		}
		memcpy(buf->ns.name, x509->der, x509->der_len);
		buf->ns.len = (int)x509->der_len;
		return 0;
	}

	if (type == LWS_TLS_CERT_INFO_VALIDITY_FROM || type == LWS_TLS_CERT_INFO_VALIDITY_TO || type == LWS_TLS_CERT_INFO_OPAQUE_PUBLIC_KEY) {
		br_x509_decoder_context dc;
		br_x509_decoder_init(&dc, NULL, NULL);
		br_x509_decoder_push(&dc, x509->der, x509->der_len);
		if (br_x509_decoder_last_error(&dc) != 0) return -1;

		if (type == LWS_TLS_CERT_INFO_VALIDITY_FROM) {
			buf->time = (time_t)(((uint64_t)dc.notbefore_days - 719528) * 86400ull + dc.notbefore_seconds);
			return 0;
		}
		if (type == LWS_TLS_CERT_INFO_VALIDITY_TO) {
			buf->time = (time_t)(((uint64_t)dc.notafter_days - 719528) * 86400ull + dc.notafter_seconds);
			return 0;
		}
		if (type == LWS_TLS_CERT_INFO_OPAQUE_PUBLIC_KEY) {
			br_x509_pkey *pk = br_x509_decoder_get_pkey(&dc);
			if (!pk) return -1;
			if (pk->key_type == BR_KEYTYPE_RSA) {
				/* Fake an opaque representation for LWS compatibility.
				 * OpenSSL exports N and E as hex. Here we can just dump the raw N and E, but
				 * BearSSL has no native opaque comparison. JIT_TRUST just memcmps them if they are identical. */
				if (pk->key.rsa.nlen + pk->key.rsa.elen > len) return -1;
				memcpy(buf->ns.name, pk->key.rsa.n, pk->key.rsa.nlen);
				memcpy(buf->ns.name + pk->key.rsa.nlen, pk->key.rsa.e, pk->key.rsa.elen);
				buf->ns.len = (int)(pk->key.rsa.nlen + pk->key.rsa.elen);
				return 0;
			}
			return -1;
		}
	}

	/* Custom ASN.1 extraction for CN, Issuer, AKID, SKID */
	const uint8_t *p = x509->der, *end = x509->der + x509->der_len;
	int tag; size_t tlen;

	if (lws_asn1_get_tlv(&p, end, &tag, &tlen) || tag != 0x30) return -1;
	end = p + tlen;

	if (lws_asn1_get_tlv(&p, end, &tag, &tlen) || tag != 0x30) return -1;
	const uint8_t *tbs_end = p + tlen;

	/* 1. Version [0] EXPLICIT INTEGER OPTIONAL */
	if (p < tbs_end && (*p & 0xDF) == 0x80) {
		if (lws_asn1_get_tlv(&p, tbs_end, &tag, &tlen)) return -1;
		p += tlen;
	}
	/* 2. SerialNumber INTEGER */
	if (lws_asn1_get_tlv(&p, tbs_end, &tag, &tlen) || tag != 0x02) return -1;
	p += tlen;
	/* 3. Signature AlgorithmIdentifier */
	if (lws_asn1_get_tlv(&p, tbs_end, &tag, &tlen) || tag != 0x30) return -1;
	p += tlen;
	/* 4. Issuer Name */
	if (lws_asn1_get_tlv(&p, tbs_end, &tag, &tlen) || tag != 0x30) return -1;
	if (type == LWS_TLS_CERT_INFO_ISSUER_NAME) return lws_x509_extract_name(p, tlen, 0, buf, len);
	p += tlen;

	/* 5. Validity SEQUENCE */
	if (lws_asn1_get_tlv(&p, tbs_end, &tag, &tlen) || tag != 0x30) return -1;
	p += tlen;
	/* 6. Subject Name */
	if (lws_asn1_get_tlv(&p, tbs_end, &tag, &tlen) || tag != 0x30) return -1;
	if (type == LWS_TLS_CERT_INFO_COMMON_NAME) return lws_x509_extract_name(p, tlen, 1, buf, len);
	p += tlen;

	/* 7. SubjectPublicKeyInfo SEQUENCE */
	const uint8_t *spki = p;
	if (lws_asn1_get_tlv(&p, tbs_end, &tag, &tlen) || tag != 0x30) return -1;
	if (type == LWS_TLS_CERT_INFO_DER_SPKI) {
		size_t spki_len = (size_t)(p - spki) + tlen;
		if (spki_len > len) return -1;
		memcpy(buf->ns.name, spki, spki_len);
		buf->ns.len = (int)spki_len;
		return 0;
	}
	p += tlen;

	/* 8. IssuerUniqueID [1] IMPLICIT BIT STRING OPTIONAL */
	if (p < tbs_end && (*p & 0xDF) == 0x81) {
		if (lws_asn1_get_tlv(&p, tbs_end, &tag, &tlen)) return -1;
		p += tlen;
	}
	/* 9. SubjectUniqueID [2] IMPLICIT BIT STRING OPTIONAL */
	if (p < tbs_end && (*p & 0xDF) == 0x82) {
		if (lws_asn1_get_tlv(&p, tbs_end, &tag, &tlen)) return -1;
		p += tlen;
	}
	/* 10. Extensions [3] EXPLICIT Extensions OPTIONAL */
	if (p < tbs_end && (*p & 0xDF) == 0x83) {
		if (lws_asn1_get_tlv(&p, tbs_end, &tag, &tlen)) return -1;
		if (lws_asn1_get_tlv(&p, p + tlen, &tag, &tlen) || tag != 0x30) return -1;
		const uint8_t *ext_end = p + tlen;
		while (p < ext_end) {
			if (lws_asn1_get_tlv(&p, ext_end, &tag, &tlen) || tag != 0x30) return -1;
			const uint8_t *e_end = p + tlen;
			if (lws_asn1_get_tlv(&p, e_end, &tag, &tlen) || tag != 0x06) return -1;
			const uint8_t *oid = p; size_t oid_len = tlen; p += tlen;
			if (p < e_end && *p == 0x01) {
				if (lws_asn1_get_tlv(&p, e_end, &tag, &tlen)) return -1;
				p += tlen;
			}
			if (lws_asn1_get_tlv(&p, e_end, &tag, &tlen) || tag != 0x04) return -1;
			const uint8_t *val = p; size_t val_len = tlen; p += tlen;

			if (type == LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID && oid_len == 3 && oid[0]==0x55 && oid[1]==0x1d && oid[2]==0x23) {
				const uint8_t *v = val, *v_end = val + val_len;
				if (lws_asn1_get_tlv(&v, v_end, &tag, &tlen) || tag != 0x30) return -1;
				v_end = v + tlen;
				while (v < v_end) {
					if (lws_asn1_get_tlv(&v, v_end, &tag, &tlen)) return -1;
					if ((tag & 0x1F) == 0) { /* keyIdentifier [0] */
						if (tlen > len) return -1;
						memcpy(buf->ns.name, v, tlen);
						buf->ns.len = (int)tlen;
						return 0;
					}
					v += tlen;
				}
			}
			if (type == LWS_TLS_CERT_INFO_SUBJECT_KEY_ID && oid_len == 3 && oid[0]==0x55 && oid[1]==0x1d && oid[2]==0x0E) {
				const uint8_t *v = val, *v_end = val + val_len;
				if (lws_asn1_get_tlv(&v, v_end, &tag, &tlen) || tag != 0x04) return -1;
				if (tlen > len) return -1;
				memcpy(buf->ns.name, v, tlen);
				buf->ns.len = (int)tlen;
				return 0;
			}
		}
	}
	return -1;
}

int lws_x509_verify(struct lws_x509_cert *x509, struct lws_x509_cert *trusted, const char *common_name) { return -1; }

#if defined(LWS_WITH_JOSE)
int lws_x509_public_to_jwk(struct lws_jwk *jwk, struct lws_x509_cert *x509,
			   const char *curves, int rsa_min_bits)
{
	br_x509_decoder_context dc;
	br_x509_pkey *pk;
	size_t coord_len;

	memset(jwk, 0, sizeof(*jwk));

	br_x509_decoder_init(&dc, 0, 0);
	br_x509_decoder_push(&dc, x509->der, x509->der_len);
	pk = br_x509_decoder_get_pkey(&dc);

	if (!pk) {
		lwsl_err("%s: cert decoding failed\n", __func__);
		return -1;
	}

	switch (pk->key_type) {
	case BR_KEYTYPE_RSA:
		lwsl_notice("%s: RSA key\n", __func__);
		jwk->kty = LWS_GENCRYPTO_KTY_RSA;

		if (rsa_min_bits && pk->key.rsa.nlen * 8 < (unsigned int)rsa_min_bits) {
			lwsl_err("%s: RSA key size %d < %d\n", __func__,
				 (int)(pk->key.rsa.nlen * 8), rsa_min_bits);
			goto bail;
		}

		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf = lws_malloc(pk->key.rsa.elen, "certjwk");
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf = lws_malloc(pk->key.rsa.nlen, "certjwk");
		if (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf || !jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf)
			goto bail;

		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].len = (uint32_t)pk->key.rsa.elen;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf, pk->key.rsa.e, pk->key.rsa.elen);

		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len = (uint32_t)pk->key.rsa.nlen;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf, pk->key.rsa.n, pk->key.rsa.nlen);
		break;

	case BR_KEYTYPE_EC:
		lwsl_notice("%s: EC key\n", __func__);
		jwk->kty = LWS_GENCRYPTO_KTY_EC;

		if (lws_genec_confirm_curve_allowed_by_tls_id(curves, pk->key.ec.curve, jwk))
			goto bail;

		if (pk->key.ec.qlen < 1 || pk->key.ec.q[0] != 0x04) {
			lwsl_err("%s: Unsupported EC point format\n", __func__);
			goto bail;
		}

		coord_len = (pk->key.ec.qlen - 1) / 2;

		jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf = lws_malloc(coord_len, "certjwk");
		jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf = lws_malloc(coord_len, "certjwk");
		if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf || !jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf)
			goto bail;

		jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].len = (uint32_t)coord_len;
		memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf, pk->key.ec.q + 1, coord_len);

		jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].len = (uint32_t)coord_len;
		memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf, pk->key.ec.q + 1 + coord_len, coord_len);
		break;

	default:
		lwsl_err("%s: key type %d not supported\n", __func__, pk->key_type);
		return -1;
	}

	return 0;

bail:
	lws_jwk_destroy(jwk);
	return -1;
}

int lws_x509_jwk_privkey_pem(struct lws_context *cx, struct lws_jwk *jwk,
			     void *pem, size_t len, const char *passphrase)
{
	br_pem_decoder_context pc;
	br_skey_decoder_context sc;
	const br_rsa_private_key *rsa;
	const br_ec_private_key *ec;
	const uint8_t *p = (const uint8_t *)pem;
	size_t remaining = len;
	int found = 0;

	memset(jwk, 0, sizeof(*jwk));

	br_pem_decoder_init(&pc);
	br_skey_decoder_init(&sc);
	br_pem_decoder_setdest(&pc, (void (*)(void *, const void *, size_t))br_skey_decoder_push, &sc);

	while (remaining > 0) {
		size_t pushed = br_pem_decoder_push(&pc, p, remaining);
		p += pushed;
		remaining -= pushed;

		int ev = br_pem_decoder_event(&pc);
		if (ev == BR_PEM_END_OBJ) {
			if (br_skey_decoder_last_error(&sc) == 0 &&
			    br_skey_decoder_key_type(&sc) != 0) {
				found = 1;
				break;
			}
			br_skey_decoder_init(&sc);
		}
	}

	if (!found) {
		lwsl_err("%s: privkey decode failed\n", __func__);
		return -1;
	}

	switch (br_skey_decoder_key_type(&sc)) {
	case BR_KEYTYPE_RSA:
		if (jwk->kty != LWS_GENCRYPTO_KTY_RSA) {
			lwsl_err("%s: RSA privkey, non-RSA jwk\n", __func__);
			goto bail;
		}
		rsa = br_skey_decoder_get_rsa(&sc);
		if (!rsa) goto bail;

		uint32_t pubexp = br_rsa_compute_pubexp_get_default()(rsa);
		size_t dlen = br_rsa_compute_privexp_get_default()(NULL, rsa, pubexp);

		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf = lws_malloc(dlen, "certjwk");
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf = lws_malloc(rsa->plen, "certjwk");
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf = lws_malloc(rsa->qlen, "certjwk");
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DP].buf = lws_malloc(rsa->dplen, "certjwk");
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf = lws_malloc(rsa->dqlen, "certjwk");
		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_QI].buf = lws_malloc(rsa->iqlen, "certjwk");

		if (!jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf || !jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf ||
		    !jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf || !jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DP].buf ||
		    !jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf || !jwk->e[LWS_GENCRYPTO_RSA_KEYEL_QI].buf)
			goto bail;

		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].len = (uint32_t)dlen;
		br_rsa_compute_privexp_get_default()(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_D].buf, rsa, pubexp);

		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].len = (uint32_t)rsa->plen;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_P].buf, rsa->p, rsa->plen);

		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].len = (uint32_t)rsa->qlen;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_Q].buf, rsa->q, rsa->qlen);

		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DP].len = (uint32_t)rsa->dplen;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DP].buf, rsa->dp, rsa->dplen);

		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DQ].len = (uint32_t)rsa->dqlen;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_DQ].buf, rsa->dq, rsa->dqlen);

		jwk->e[LWS_GENCRYPTO_RSA_KEYEL_QI].len = (uint32_t)rsa->iqlen;
		memcpy(jwk->e[LWS_GENCRYPTO_RSA_KEYEL_QI].buf, rsa->iq, rsa->iqlen);
		break;

	case BR_KEYTYPE_EC:
		if (jwk->kty != LWS_GENCRYPTO_KTY_EC) {
			lwsl_err("%s: EC privkey, non-EC jwk\n", __func__);
			goto bail;
		}
		ec = br_skey_decoder_get_ec(&sc);
		if (!ec) goto bail;

		jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].buf = lws_malloc(ec->xlen, "certjwk");
		if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].buf)
			goto bail;

		jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].len = (uint32_t)ec->xlen;
		memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].buf, ec->x, ec->xlen);
		break;

	default:
		lwsl_err("%s: unusable key type %d\n", __func__, br_skey_decoder_key_type(&sc));
		goto bail;
	}

	return 0;

bail:
	lws_jwk_destroy(jwk);
	return -1;
}
#endif

static void
wrap_start_chain(const br_x509_class **ctx, const char *server_name)
{
	lws_tls_conn *conn = lws_container_of((br_x509_minimal_context *)ctx, lws_tls_conn, x509_ctx);
	conn->capturing_peer_cert = 1;
	if (conn->peer_cert) lws_x509_destroy(&conn->peer_cert);
	br_x509_minimal_vtable.start_chain(ctx, server_name);
}

static void
wrap_start_cert(const br_x509_class **ctx, uint32_t length)
{
	lws_tls_conn *conn = lws_container_of((br_x509_minimal_context *)ctx, lws_tls_conn, x509_ctx);
	if (conn->capturing_peer_cert) {
		if (!lws_x509_create(&conn->peer_cert)) {
			conn->peer_cert->der = lws_malloc(length, "peer_cert");
			if (!conn->peer_cert->der)
				lws_x509_destroy(&conn->peer_cert);
			else
				conn->peer_cert->der_len = 0;
		}
	}
#if defined(LWS_WITH_TLS_JIT_TRUST)
	if (!lws_x509_create(&conn->temp_cert)) {
		conn->temp_cert->der = lws_malloc(length, "temp_cert");
		if (!conn->temp_cert->der)
			lws_x509_destroy(&conn->temp_cert);
		else
			conn->temp_cert->der_len = 0;
	}
#endif
	br_x509_minimal_vtable.start_cert(ctx, length);
}

static void
wrap_append(const br_x509_class **ctx, const unsigned char *buf, size_t len)
{
	lws_tls_conn *conn = lws_container_of((br_x509_minimal_context *)ctx, lws_tls_conn, x509_ctx);
	if (conn->capturing_peer_cert && conn->peer_cert && conn->peer_cert->der) {
		memcpy(conn->peer_cert->der + conn->peer_cert->der_len, buf, len);
		conn->peer_cert->der_len += len;
	}
#if defined(LWS_WITH_TLS_JIT_TRUST)
	if (conn->temp_cert && conn->temp_cert->der) {
		memcpy(conn->temp_cert->der + conn->temp_cert->der_len, buf, len);
		conn->temp_cert->der_len += len;
	}
#endif
	br_x509_minimal_vtable.append(ctx, buf, len);
}

static void
wrap_end_cert(const br_x509_class **ctx)
{
	lws_tls_conn *conn = lws_container_of((br_x509_minimal_context *)ctx, lws_tls_conn, x509_ctx);
	if (conn->capturing_peer_cert) {
		conn->capturing_peer_cert = 0; /* EE cert is the first one, stop capturing after it ends */
	}
#if defined(LWS_WITH_TLS_JIT_TRUST)
	if (conn->wsi && conn->temp_cert && conn->wsi->tls.kid_chain.count < LWS_ARRAY_SIZE(conn->wsi->tls.kid_chain.akid)) {
		union lws_tls_cert_info_results ci;
		if (!lws_x509_info(conn->temp_cert, LWS_TLS_CERT_INFO_SUBJECT_KEY_ID, &ci, 0))
			lws_tls_kid_copy(&ci, &conn->wsi->tls.kid_chain.skid[conn->wsi->tls.kid_chain.count]);
		if (!lws_x509_info(conn->temp_cert, LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID, &ci, 0))
			lws_tls_kid_copy(&ci, &conn->wsi->tls.kid_chain.akid[conn->wsi->tls.kid_chain.count]);
		conn->wsi->tls.kid_chain.count++;
	}
	if (conn->temp_cert) lws_x509_destroy(&conn->temp_cert);
#endif
	br_x509_minimal_vtable.end_cert(ctx);
}

static unsigned
wrap_end_chain(const br_x509_class **ctx)
{
	lws_tls_conn *conn = lws_container_of((br_x509_minimal_context *)ctx, lws_tls_conn, x509_ctx);
	unsigned err = br_x509_minimal_vtable.end_chain(ctx);

	if (err == BR_ERR_X509_NOT_TRUSTED && (conn->tls_use_ssl & (LCCSCF_ALLOW_SELFSIGNED | LCCSCF_ALLOW_INSECURE))) {
		lwsl_notice("%s: bypassing validation err %u due to ALLOW_SELFSIGNED/INSECURE\n", __func__, err);
		return 0;
	}

	return err;
}

static const br_x509_pkey *
wrap_get_pkey(const br_x509_class *const *ctx, unsigned *usages)
{
	lws_tls_conn *conn = lws_container_of((br_x509_minimal_context *)ctx, lws_tls_conn, x509_ctx);
	const br_x509_pkey *pkey = br_x509_minimal_vtable.get_pkey(ctx, usages);

	if (!pkey && (conn->tls_use_ssl & (LCCSCF_ALLOW_SELFSIGNED | LCCSCF_ALLOW_INSECURE))) {
		if (usages)
			*usages = conn->x509_ctx.key_usages;
		return &conn->x509_ctx.pkey;
	}

	return pkey;
}

void lws_bearssl_x509_wrap_conn(lws_tls_conn *conn)
{
	memcpy(&conn->x509_vtable, &br_x509_minimal_vtable, sizeof(br_x509_class));
	conn->x509_vtable.start_chain = wrap_start_chain;
	conn->x509_vtable.start_cert = wrap_start_cert;
	conn->x509_vtable.append = wrap_append;
	conn->x509_vtable.end_cert = wrap_end_cert;
	conn->x509_vtable.end_chain = wrap_end_chain;
	conn->x509_vtable.get_pkey = wrap_get_pkey;
	conn->x509_ctx.vtable = &conn->x509_vtable;
}

int lws_tls_server_certs_load(struct lws_vhost *vhost, struct lws *wsi, const char *cert, const char *private_key, const char *mem_cert, size_t len_mem_cert, const char *mem_privkey, size_t mem_privkey_len)

{
	struct lws_tls_ctx *ctx;
	int err;

	if (!vhost->tls.ssl_ctx) {
		ctx = lws_zalloc(sizeof(*ctx), "bearssl server ctx");
		if (!ctx)
			return 1;
		vhost->tls.ssl_ctx = ctx;
	} else {
		ctx = (struct lws_tls_ctx *)vhost->tls.ssl_ctx;
	}

	/*
	 * We use lws_tls_alloc_pem_to_der_file to get the DER representation
	 * and then allocate it into ctx->chain and ctx->rsa_key / ctx->ec_key
	 */
	if (cert || mem_cert) {
		uint8_t *buf;
		lws_filepos_t amount;
		lwsl_notice("%s: cert=%s\n", __func__, cert ? cert : "null");
		if (!lws_tls_alloc_pem_to_der_file(vhost->context, cert, mem_cert, len_mem_cert, &buf, &amount)) {
			ctx->chain = lws_zalloc(sizeof(br_x509_certificate), "bearssl chain");
			if (!ctx->chain) {
				lws_free(buf);
				return 1;
			}
			ctx->chain[0].data = buf;
			ctx->chain[0].data_len = (size_t)amount;
			ctx->chain_len = 1;
			lwsl_notice("%s: cert loaded ok, chain=%p\n", __func__, ctx->chain);
		} else {
			lwsl_err("%s: failed to load cert\n", __func__);
			return 1;
		}
	}

	if (private_key || mem_privkey) {
		uint8_t *buf;
		lws_filepos_t amount;
		if (!lws_tls_alloc_pem_to_der_file(vhost->context, private_key, mem_privkey, mem_privkey_len, &buf, &amount)) {
			br_skey_decoder_init(&ctx->skc);
			br_skey_decoder_push(&ctx->skc, buf, amount);
			err = br_skey_decoder_last_error(&ctx->skc);
			if (err == 0) {
				int type = br_skey_decoder_key_type(&ctx->skc);
				if (type == BR_KEYTYPE_RSA) {
					const br_rsa_private_key *rk = br_skey_decoder_get_rsa(&ctx->skc);
					ctx->is_rsa = 1;
					ctx->rsa_key = *rk;
				} else if (type == BR_KEYTYPE_EC) {
					const br_ec_private_key *ek = br_skey_decoder_get_ec(&ctx->skc);
					ctx->is_rsa = 0;
					ctx->ec_key = *ek;
				}
			} else {
				lwsl_err("%s: failed to decode private key: %d\n", __func__, err);
				return 1;
			}
		} else {
			lwsl_err("%s: failed to load private key\n", __func__);
			return 1;
		}
	}

	return 0;
}
int lws_tls_server_client_cert_verify_config(struct lws_vhost *vh) { return 0; }
int lws_tls_vhost_cert_info(struct lws_vhost *vhost, enum lws_tls_cert_info type, union lws_tls_cert_info_results *buf, size_t len) { return -1; }

struct dn_append_ctx {
	uint8_t *data;
	size_t len;
	size_t size;
};

static void
append_dn(void *ctx, const void *buf, size_t len)
{
	struct dn_append_ctx *dn_ctx = ctx;
	if (dn_ctx->len + len > dn_ctx->size) {
		size_t new_size = dn_ctx->size ? dn_ctx->size * 2 : 128;
		while (dn_ctx->len + len > new_size)
			new_size *= 2;
		uint8_t *new_data = lws_realloc(dn_ctx->data, new_size, "ta_dn");
		if (!new_data)
			return; /* out of memory */
		dn_ctx->data = new_data;
		dn_ctx->size = new_size;
	}
	memcpy(dn_ctx->data + dn_ctx->len, buf, len);
	dn_ctx->len += len;
}

int lws_tls_client_vhost_extra_cert_mem(struct lws_vhost *vh, const uint8_t *der, size_t der_len) {
	br_x509_decoder_context dc;
	br_x509_pkey *pk;
	br_x509_trust_anchor ta;
	struct lws_tls_ctx *ctx = vh->tls.ssl_client_ctx;
	br_x509_trust_anchor *new_ta;
	struct dn_append_ctx dn_ctx;

	if (!ctx)
		return 1;

	memset(&dn_ctx, 0, sizeof(dn_ctx));
	br_x509_decoder_init(&dc, append_dn, &dn_ctx);
	br_x509_decoder_push(&dc, der, der_len);
	pk = br_x509_decoder_get_pkey(&dc);
	if (pk == NULL) {
		lwsl_err("%s: CA decoding failed (der_len %zu) (err %d)\n", __func__, der_len, br_x509_decoder_last_error(&dc));
		if (dn_ctx.data)
			lws_free(dn_ctx.data);
		return 1;
	}

	memset(&ta, 0, sizeof(ta));
	ta.flags = 0;
	ta.dn.data = dn_ctx.data;
	ta.dn.len = dn_ctx.len;
	if (br_x509_decoder_isCA(&dc)) {
		ta.flags |= BR_X509_TA_CA;
	}

	switch (pk->key_type) {
	case BR_KEYTYPE_RSA:
		ta.pkey.key_type = BR_KEYTYPE_RSA;
		ta.pkey.key.rsa.n = lws_malloc(pk->key.rsa.nlen, "bearssl ta rsa n");
		ta.pkey.key.rsa.e = lws_malloc(pk->key.rsa.elen, "bearssl ta rsa e");
		if (!ta.pkey.key.rsa.n || !ta.pkey.key.rsa.e)
			goto fail_ta;
		memcpy((void *)ta.pkey.key.rsa.n, pk->key.rsa.n, pk->key.rsa.nlen);
		ta.pkey.key.rsa.nlen = pk->key.rsa.nlen;
		memcpy((void *)ta.pkey.key.rsa.e, pk->key.rsa.e, pk->key.rsa.elen);
		ta.pkey.key.rsa.elen = pk->key.rsa.elen;
		break;
	case BR_KEYTYPE_EC:
		ta.pkey.key_type = BR_KEYTYPE_EC;
		ta.pkey.key.ec.curve = pk->key.ec.curve;
		ta.pkey.key.ec.q = lws_malloc(pk->key.ec.qlen, "bearssl ta ec q");
		if (!ta.pkey.key.ec.q)
			goto fail_ta;
		memcpy((void *)ta.pkey.key.ec.q, pk->key.ec.q, pk->key.ec.qlen);
		ta.pkey.key.ec.qlen = pk->key.ec.qlen;
		break;
	default:
		lwsl_err("%s: unsupported CA public key type\n", __func__);
		return 1;
	}

	new_ta = lws_realloc(ctx->trust_anchors, sizeof(br_x509_trust_anchor) * (ctx->num_trust_anchors + 1), "bearssl ta list");
	if (!new_ta)
		goto fail_ta;

	ctx->trust_anchors = new_ta;
	ctx->trust_anchors[ctx->num_trust_anchors++] = ta;

	return 0;

fail_ta:
	if (ta.dn.data) lws_free(ta.dn.data);
	if (ta.pkey.key_type == BR_KEYTYPE_RSA) {
		if (ta.pkey.key.rsa.n) lws_free((void *)ta.pkey.key.rsa.n);
		if (ta.pkey.key.rsa.e) lws_free((void *)ta.pkey.key.rsa.e);
	} else if (ta.pkey.key_type == BR_KEYTYPE_EC) {
		if (ta.pkey.key.ec.q) lws_free((void *)ta.pkey.key.ec.q);
	}
	return 1;
}

int lws_tls_peer_cert_info(struct lws *wsi, enum lws_tls_cert_info type, union lws_tls_cert_info_results *buf, size_t len)
{
	lws_tls_conn *conn = wsi->tls.ssl;
	if (!conn || !conn->peer_cert) return -1;
	return lws_x509_info(conn->peer_cert, type, buf, len);
}
