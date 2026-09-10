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
	br_x509_decoder_context dc;
	/* lws_tls_alloc_pem_to_der_file handles the base64/PEM decoding for us */
	if (!lws_tls_alloc_pem_to_der_file(NULL, NULL, pem, len, &x509->der, &amount)) {
		x509->der_len = (size_t)amount;
		br_x509_decoder_init(&dc, NULL, NULL);
		br_x509_decoder_push(&dc, x509->der, x509->der_len);
		if (br_x509_decoder_last_error(&dc) != 0) {
			lws_free(x509->der);
			x509->der = NULL;
			return -1;
		}
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

/*
 * Render an X.501 Name SEQUENCE as "C=US,O=Let's Encrypt,CN=R11", the same
 * shape gnutls produces, so consumers see one format from either backend.
 * Multi-valued RDNs are joined with '+', unknown attribute types are shown
 * as dotted OIDs, and RFC 4514 special characters in values are escaped.
 *
 * With get_cn set, only the value of the (last) CN attribute is returned.
 *
 * Returns 0 with buf->ns.name / len filled, -1 on malformed input or if
 * the caller's buffer is too small.
 */
static const struct {
	const char *oid;
	size_t oid_len;
	const char *name;
} lws_x501_attr_names[] = {
	{ "\x55\x04\x03", 3, "CN" },
	{ "\x55\x04\x06", 3, "C" },
	{ "\x55\x04\x07", 3, "L" },
	{ "\x55\x04\x08", 3, "ST" },
	{ "\x55\x04\x0a", 3, "O" },
	{ "\x55\x04\x0b", 3, "OU" },
	{ "\x55\x04\x05", 3, "serialNumber" },
	{ "\x55\x04\x0c", 3, "title" },
	{ "\x55\x04\x2a", 3, "GN" },
	{ "\x55\x04\x04", 3, "SN" },
	{ "\x55\x04\x09", 3, "street" },
	{ "\x55\x04\x11", 3, "postalCode" },
	{ "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01", 9, "emailAddress" },
	{ "\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x19", 10, "DC" },
	{ "\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x01", 10, "UID" },
};

static int
lws_x509_dn_put(char *out, size_t max, size_t *pos, const char *str, size_t n)
{
	if (*pos + n >= max)
		return -1;
	memcpy(out + *pos, str, n);
	*pos += n;
	return 0;
}

static int
lws_x509_dn_put_oid(char *out, size_t max, size_t *pos, const uint8_t *oid,
		    size_t oid_len)
{
	char tmp[16];
	size_t i;
	unsigned int v = 0;
	int first = 1, n;

	for (i = 0; i < oid_len; i++) {
		v = (v << 7) | (oid[i] & 0x7f);
		if (oid[i] & 0x80)
			continue;
		if (first) {
			n = lws_snprintf(tmp, sizeof(tmp), "%u.%u", v / 40 > 2 ? 2 : v / 40,
					 v / 40 > 2 ? v - 80 : v % 40);
			first = 0;
		} else
			n = lws_snprintf(tmp, sizeof(tmp), ".%u", v);
		if (lws_x509_dn_put(out, max, pos, tmp, (size_t)n))
			return -1;
		v = 0;
	}

	return first ? -1 : 0;
}

static int
lws_x509_dn_put_value(char *out, size_t max, size_t *pos, const uint8_t *val,
		      size_t val_len)
{
	size_t i;

	for (i = 0; i < val_len; i++) {
		char c = (char)val[i];

		if (c == ',' || c == '+' || c == '"' || c == '\\' || c == '<' ||
		    c == '>' || c == ';' || (c == '#' && !i) ||
		    (c == ' ' && (!i || i == val_len - 1)))
			if (lws_x509_dn_put(out, max, pos, "\\", 1))
				return -1;
		if (!c)
			c = '?';
		if (lws_x509_dn_put(out, max, pos, &c, 1))
			return -1;
	}

	return 0;
}

static int
lws_x509_render_name(const uint8_t *name, size_t name_len, int get_cn,
		     char *out, size_t max_len, size_t *ppos)
{
	const uint8_t *p = name, *end = name + name_len;
	size_t len, pos = *ppos, i;
	int tag, found_cn = 0, first_rdn = 1;

	while (p < end) {
		const uint8_t *s_end;
		int first_atv = 1;

		/* RelativeDistinguishedName ::= SET OF AttributeTypeAndValue */
		if (lws_asn1_get_tlv(&p, end, &tag, &len) || tag != 0x31)
			return -1;
		s_end = p + len;

		if (!get_cn && !first_rdn &&
		    lws_x509_dn_put(out, max_len, &pos, ",", 1))
			return -1;
		first_rdn = 0;

		while (p < s_end) {
			const uint8_t *sq_end, *oid, *val;
			size_t oid_len, val_len;

			if (lws_asn1_get_tlv(&p, s_end, &tag, &len) || tag != 0x30)
				return -1;
			sq_end = p + len;
			if (lws_asn1_get_tlv(&p, sq_end, &tag, &len) || tag != 0x06)
				return -1;
			oid = p; oid_len = len; p += len;
			if (lws_asn1_get_tlv(&p, sq_end, &tag, &len))
				return -1;
			val = p; val_len = len; p += len;

			if (get_cn) {
				if (oid_len == 3 && oid[0] == 0x55 &&
				    oid[1] == 0x04 && oid[2] == 0x03) {
					if (val_len >= max_len)
						return -1;
					memcpy(out, val, val_len);
					out[val_len] = '\0';
					pos = val_len;
					found_cn = 1;
				}
				continue;
			}

			if (!first_atv &&
			    lws_x509_dn_put(out, max_len, &pos, "+", 1))
				return -1;
			first_atv = 0;

			for (i = 0; i < LWS_ARRAY_SIZE(lws_x501_attr_names); i++)
				if (oid_len == lws_x501_attr_names[i].oid_len &&
				    !memcmp(oid, lws_x501_attr_names[i].oid, oid_len))
					break;

			if (i < LWS_ARRAY_SIZE(lws_x501_attr_names)) {
				if (lws_x509_dn_put(out, max_len, &pos,
						    lws_x501_attr_names[i].name,
						    strlen(lws_x501_attr_names[i].name)))
					return -1;
			} else
				if (lws_x509_dn_put_oid(out, max_len, &pos,
							oid, oid_len))
					return -1;

			if (lws_x509_dn_put(out, max_len, &pos, "=", 1) ||
			    lws_x509_dn_put_value(out, max_len, &pos,
						  val, val_len))
				return -1;
		}
	}

	if (get_cn && !found_cn)
		return -1;

	out[pos] = '\0';
	*ppos = pos;

	return 0;
}

static int
lws_x509_extract_name(const uint8_t *name, size_t name_len, int get_cn,
		      union lws_tls_cert_info_results *buf, size_t max_len)
{
	size_t pos = 0;

	buf->ns.len = 0;
	if (lws_x509_render_name(name, name_len, get_cn, buf->ns.name, max_len, &pos))
		return -1;
	buf->ns.len = (int)pos;

	return 0;
}

/*
 * Walk the AuthorityKeyIdentifier extension value.  Returns 0 with buf
 * filled, 1 if the wanted component isn't present, -1 on malformed input
 * or if the caller's buffer is too small.
 */
static int
lws_x509_akid_component(const uint8_t *val, size_t val_len,
			enum lws_tls_cert_info type,
			union lws_tls_cert_info_results *buf, size_t len)
{
	const uint8_t *v = val, *v_end = val + val_len;
	size_t tlen;
	int tag;

	if (lws_asn1_get_tlv(&v, v_end, &tag, &tlen) || tag != 0x30)
		return -1;
	v_end = v + tlen;

	while (v < v_end) {
		if (lws_asn1_get_tlv(&v, v_end, &tag, &tlen))
			return -1;

		switch (tag & 0x1f) {
		case 0: /* keyIdentifier [0] IMPLICIT OCTET STRING */
			if (type != LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID)
				break;
			if (tlen > len)
				return -1;
			memcpy(buf->ns.name, v, tlen);
			buf->ns.len = (int)tlen;
			return 0;

		case 1: /* authorityCertIssuer [1] IMPLICIT GeneralNames */
		{
			const uint8_t *g = v, *g_end = v + tlen;
			size_t pos = 0;

			if (type != LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_ISSUER)
				break;

			/*
			 * Like the other backends, concatenate whatever
			 * GeneralNames are there; a directoryName is
			 * rendered as a DN, string forms are copied
			 */
			while (g < g_end) {
				size_t glen;
				int gtag;

				if (lws_asn1_get_tlv(&g, g_end, &gtag, &glen))
					return -1;

				if ((gtag & 0x1f) == 4) { /* directoryName [4] EXPLICIT Name */
					const uint8_t *d = g;
					size_t dlen;
					int dtag;

					if (lws_asn1_get_tlv(&d, g + glen, &dtag, &dlen) ||
					    dtag != 0x30)
						return -1;
					if (lws_x509_render_name(d, dlen, 0, buf->ns.name,
								 len, &pos))
						return -1;
				} else if ((gtag & 0x1f) == 1 || (gtag & 0x1f) == 2 ||
					   (gtag & 0x1f) == 6) {
					/* rfc822Name, dNSName, uniformResourceIdentifier */
					if (lws_x509_dn_put(buf->ns.name, len, &pos,
							    (const char *)g, glen))
						return -1;
				}
				g += glen;
			}

			if (!pos)
				return 1;
			buf->ns.name[pos] = '\0';
			buf->ns.len = (int)pos;
			return 0;
		}

		case 2: /* authorityCertSerialNumber [2] IMPLICIT INTEGER */
			if (type != LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_SERIAL)
				break;
			if (tlen > len)
				return -1;
			memcpy(buf->ns.name, v, tlen);
			buf->ns.len = (int)tlen;
			return 0;

		default:
			break;
		}
		v += tlen;
	}

	return 1;
}

/*
 * BearSSL gives cert validity times as a day count from year 0 plus seconds
 * in the day, both taken from the (attacker-chosen) cert.  Converting to a
 * unix time_t is only meaningful inside a sane window: before the epoch the
 * unsigned subtraction wraps, and absurdly distant dates overflow a 32-bit
 * time_t.  Refuse both rather than report an arbitrary time
 */

#define LWS_X509_DAYS_TO_EPOCH	719528	/* 0000-01-01 .. 1970-01-01 */
#define LWS_X509_DAYS_MAX	3652060	/* .. 9999-12-31 */

static int
lws_x509_days_to_time(uint32_t days, uint32_t seconds,
		      union lws_tls_cert_info_results *buf)
{
	int64_t t;

	if (days < LWS_X509_DAYS_TO_EPOCH ||
	    days > LWS_X509_DAYS_TO_EPOCH + LWS_X509_DAYS_MAX ||
	    seconds >= 86400)
		return -1;

	t = (int64_t)(days - LWS_X509_DAYS_TO_EPOCH) * 86400ll +
	    (int64_t)seconds;

	/* and it has to survive the platform's time_t */
	if ((int64_t)(time_t)t != t)
		return -1;

	buf->time = (time_t)t;

	return 0;
}

int lws_x509_info(struct lws_x509_cert *x509, enum lws_tls_cert_info type, union lws_tls_cert_info_results *buf, size_t len) {
	buf->ns.len = 0;

	if (!x509 || !x509->der) return -1;

	/*
	 * Same contract as the openssl / mbedtls / openhitls backends: a zero
	 * len means the caller is using the union's own 64-byte name field
	 */
	if (!len)
		len = sizeof(buf->ns.name);

	if (type == LWS_TLS_CERT_INFO_DER_RAW) {
		buf->ns.len = (int)x509->der_len;
		if (x509->der_len > len)
			return -1;
		memcpy(buf->ns.name, x509->der, x509->der_len);
		return 0;
	}

	if (type == LWS_TLS_CERT_INFO_VALIDITY_FROM || type == LWS_TLS_CERT_INFO_VALIDITY_TO || type == LWS_TLS_CERT_INFO_OPAQUE_PUBLIC_KEY) {
		br_x509_decoder_context dc;
		br_x509_decoder_init(&dc, NULL, NULL);
		br_x509_decoder_push(&dc, x509->der, x509->der_len);
		if (br_x509_decoder_last_error(&dc) != 0) return -1;

		if (type == LWS_TLS_CERT_INFO_VALIDITY_FROM)
			return lws_x509_days_to_time(dc.notbefore_days,
						     dc.notbefore_seconds, buf);
		if (type == LWS_TLS_CERT_INFO_VALIDITY_TO)
			return lws_x509_days_to_time(dc.notafter_days,
						     dc.notafter_seconds, buf);
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
			if (pk->key_type == BR_KEYTYPE_EC) {
				if (pk->key.ec.qlen > len) return -1;
				memcpy(buf->ns.name, pk->key.ec.q, pk->key.ec.qlen);
				buf->ns.len = (int)pk->key.ec.qlen;
				return 0;
			}
			return -1;
		}
	}

	/* Custom ASN.1 extraction for CN, Issuer, SPKI, usage, AKID, SKID */
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

		/* documented size-query: report the needed size on too-small */
		buf->ns.len = (int)spki_len;
		if (spki_len > len) return -1;
		memcpy(buf->ns.name, spki, spki_len);
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

			if (oid_len != 3 || oid[0] != 0x55 || oid[1] != 0x1d)
				continue;

			switch (oid[2]) {
			case 0x0f: /* keyUsage: BIT STRING */
			{
				const uint8_t *v = val;
				int vtag; size_t vlen;

				if (type != LWS_TLS_CERT_INFO_USAGE)
					break;
				if (lws_asn1_get_tlv(&v, val + val_len, &vtag, &vlen) ||
				    vtag != 0x03 || vlen < 2)
					return -1;
				/*
				 * v[0] is the unused-bits count; the flag bytes
				 * that follow are already in the layout openssl
				 * and mbedtls expose (digitalSignature = 0x80,
				 * ... decipherOnly = 0x8000)
				 */
				buf->usage = v[1];
				if (vlen > 2)
					buf->usage |= (unsigned int)v[2] << 8;
				return 0;
			}

			case 0x23: /* authorityKeyIdentifier */
				if (type != LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID &&
				    type != LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_ISSUER &&
				    type != LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_SERIAL)
					break;
				return lws_x509_akid_component(val, val_len, type, buf, len);

			case 0x0e: /* subjectKeyIdentifier: OCTET STRING */
			{
				const uint8_t *v = val;
				int vtag; size_t vlen;

				if (type != LWS_TLS_CERT_INFO_SUBJECT_KEY_ID)
					break;
				if (lws_asn1_get_tlv(&v, val + val_len, &vtag, &vlen) ||
				    vtag != 0x04)
					return -1;
				if (vlen > len) return -1;
				memcpy(buf->ns.name, v, vlen);
				buf->ns.len = (int)vlen;
				return 0;
			}

			default:
				break;
			}
		}
	}

	switch (type) {
	case LWS_TLS_CERT_INFO_USAGE:
	case LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID:
	case LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_ISSUER:
	case LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_SERIAL:
	case LWS_TLS_CERT_INFO_SUBJECT_KEY_ID:
		/* the extension isn't there: "not present", as openssl says */
		return 1;
	case LWS_TLS_CERT_INFO_VERIFIED:
		/*
		 * a bare cert carries no chain result... it is the connection
		 * that knows, so lws_tls_peer_cert_info() answers this one.
		 * Leave the union in a fail-closed state for any caller that
		 * ignores our return
		 */
		buf->verified = 0;
		return -1;
	default:
		return -1;
	}
}

int lws_x509_verify(struct lws_x509_cert *x509, struct lws_x509_cert *trusted, const char *common_name);

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

		if (!curves) {
			lwsl_err("%s: ec curves not allowed\n", __func__);
			goto bail;
		}

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

struct der_buf {
	unsigned char buf[4096];
	size_t len;
	unsigned char overflow;
};

static void
pem_der_dest(void *dest_ctx, const void *data, size_t len)
{
	struct der_buf *db = (struct der_buf *)dest_ctx;

	if (db->len + len > sizeof(db->buf)) {
		db->overflow = 1;
		return;
	}

	memcpy(db->buf + db->len, data, len);
	db->len += len;
}

/*
 * Walk the eight INTEGERs of an RSAPrivateKey SEQUENCE with the bounded
 * TLV walker; the returned element pointers aim into the DER buffer, in
 * DER order n, e, d, p, q, dp, dq, qinv
 */
static int
rsa_der_walk_seq(const uint8_t *seq, size_t seq_len,
		 const uint8_t *els[8], size_t el_lens[8])
{
	const uint8_t *p = seq, *end = seq + seq_len;
	int tag, i;

	/* version */
	if (lws_asn1_get_tlv(&p, end, &tag, &el_lens[0]) || tag != 0x02)
		return -1;
	p += el_lens[0];

	for (i = 0; i < 8; i++) {
		if (lws_asn1_get_tlv(&p, end, &tag, &el_lens[i]) || tag != 0x02)
			return -1;
		els[i] = p;
		p += el_lens[i];
	}

	/*
	 * canonical unsigned-minimal form (DER INTEGERs may carry sign
	 * padding zeros), as the cert side and bearssl key ops expect
	 */
	for (i = 0; i < 8; i++)
		while (el_lens[i] > 1 && els[i][0] == 0) {
			els[i]++;
			el_lens[i]--;
		}

	return 0;
}

/*
 * Walk an RSAPrivateKey, either raw or PKCS#8-wrapped; anything else
 * (including an EC key) is rejected
 */
static int
rsa_der_walk(const uint8_t *der, size_t der_len,
	     const uint8_t *els[8], size_t el_lens[8])
{
	const uint8_t *p = der, *end = der + der_len, *seq;
	size_t n, seq_len;
	int tag;

	if (lws_asn1_get_tlv(&p, end, &tag, &seq_len) || tag != 0x30)
		return -1;
	seq = p;

	/* version */
	if (lws_asn1_get_tlv(&p, end, &tag, &n) || tag != 0x02)
		return -1;
	p += n;

	if (p < end && *p == 0x30) {
		/* PKCS#8 OneAsymmetricKey: SEQUENCE algid, OCTET STRING key */

		if (lws_asn1_get_tlv(&p, end, &tag, &n) || tag != 0x30)
			return -1;
		p += n;

		if (lws_asn1_get_tlv(&p, end, &tag, &n) || tag != 0x04 ||
		    n < 2)
			return -1;

		/* the wrapped key is itself a DER SEQUENCE */
		return rsa_der_walk(p, n, els, el_lens);
	}

	return rsa_der_walk_seq(seq, seq_len, els, el_lens);
}

int lws_x509_jwk_privkey_pem(struct lws_context *cx, struct lws_jwk *jwk,
			     void *pem, size_t len, const char *passphrase)
{
	static const int rsa_el_map[8] = {
		LWS_GENCRYPTO_RSA_KEYEL_N, LWS_GENCRYPTO_RSA_KEYEL_E,
		LWS_GENCRYPTO_RSA_KEYEL_D, LWS_GENCRYPTO_RSA_KEYEL_P,
		LWS_GENCRYPTO_RSA_KEYEL_Q, LWS_GENCRYPTO_RSA_KEYEL_DP,
		LWS_GENCRYPTO_RSA_KEYEL_DQ, LWS_GENCRYPTO_RSA_KEYEL_QI,
	};
	struct der_buf db;
	br_pem_decoder_context pc;
	const uint8_t *p = (const uint8_t *)pem;
	size_t remaining = len;

	/*
	 * The caller's jwk already carries the matching public parts from
	 * lws_x509_public_to_jwk(); we add the private elements to it
	 */

	memset(&db, 0, sizeof(db));

	br_pem_decoder_init(&pc);
	br_pem_decoder_setdest(&pc, pem_der_dest, &db);

	while (remaining > 0) {
		size_t pushed = br_pem_decoder_push(&pc, p, remaining);

		p += pushed;
		remaining -= pushed;

		switch (br_pem_decoder_event(&pc)) {
		case BR_PEM_BEGIN_OBJ:
			if (!strncmp(br_pem_decoder_name(&pc),
				     "ENCRYPTED PRIVATE KEY", 21)) {
				lwsl_err("%s: BearSSL provides no encrypted "
					 "private key PEM pieces\n", __func__);
				return -1;
			}
			break;

		case BR_PEM_END_OBJ:
			goto done;

		default:
			break;
		}
	}

done:
	if (db.overflow || db.len < 8) {
		lwsl_err("%s: privkey decode failed\n", __func__);
		return -1;
	}

	/* RSA: the DER carries n and e too, so the key can be confirmed
	 * against the jwk's public parts exactly */

	{
		const uint8_t *els[8];
		size_t el_lens[8];
		int n;

		if (!rsa_der_walk(db.buf, db.len, els, el_lens)) {
			if (jwk->kty != LWS_GENCRYPTO_KTY_RSA) {
				lwsl_err("%s: RSA privkey, non-RSA jwk\n", __func__);
				goto bail;
			}

			if (el_lens[1] != jwk->e[rsa_el_map[1]].len ||
			    lws_timingsafe_bcmp(els[1],
					jwk->e[rsa_el_map[1]].buf,
					(unsigned int)el_lens[1]) ||
			    el_lens[0] != jwk->e[rsa_el_map[0]].len ||
			    lws_timingsafe_bcmp(els[0],
					jwk->e[rsa_el_map[0]].buf,
					(unsigned int)el_lens[0])) {
				lwsl_err("%s: privkey doesn't match jwk pubkey\n",
					 __func__);
				goto bail;
			}

			for (n = 2; n < 8; n++) {
				jwk->e[rsa_el_map[n]].buf =
						lws_malloc(el_lens[n], "certjwk");
				if (!jwk->e[rsa_el_map[n]].buf)
					goto bail;
				jwk->e[rsa_el_map[n]].len = (uint32_t)el_lens[n];
				memcpy(jwk->e[rsa_el_map[n]].buf, els[n],
				       el_lens[n]);
			}

			return 0;
		}
	}

	/* EC */

	{
		br_skey_decoder_context sc;
		const br_ec_private_key *ec;

		br_skey_decoder_init(&sc);
		br_skey_decoder_push(&sc, db.buf, db.len);
		if (br_skey_decoder_last_error(&sc) ||
		    br_skey_decoder_key_type(&sc) != BR_KEYTYPE_EC) {
			lwsl_err("%s: privkey decode failed\n", __func__);
			return -1;
		}

		if (jwk->kty != LWS_GENCRYPTO_KTY_EC) {
			lwsl_err("%s: EC privkey, non-EC jwk\n", __func__);
			goto bail;
		}

		ec = br_skey_decoder_get_ec(&sc);
		if (!ec)
			goto bail;

		{
			unsigned char kbuf[BR_EC_KBUF_PUB_MAX_SIZE];
			br_ec_public_key pub;
			size_t coord_len;

			/*
			 * Confirm the private key belongs to the cert...
			 * without deriving the public point from the scalar,
			 * any other key on the same curve is accepted, since
			 * every P-256 x is 32 bytes
			 */

			memset(&pub, 0, sizeof(pub));
			if (!br_ec_compute_pub(br_ec_get_default(), &pub, kbuf,
					       ec) ||
			    pub.qlen < 3 || !(pub.qlen & 1) ||
			    pub.q[0] != 0x04) {
				lwsl_err("%s: unable to derive EC pubkey\n",
					 __func__);
				goto bail;
			}

			coord_len = (pub.qlen - 1) / 2;

			if (coord_len != jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].len ||
			    !jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf ||
			    lws_timingsafe_bcmp(pub.q + 1,
					jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf,
					(unsigned int)coord_len) ||
			    coord_len != jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].len ||
			    !jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf ||
			    lws_timingsafe_bcmp(pub.q + 1 + coord_len,
					jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf,
					(unsigned int)coord_len)) {
				lwsl_err("%s: EC privkey doesn't match jwk "
					 "pubkey\n", __func__);
				goto bail;
			}
		}

		jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].buf = lws_malloc(ec->xlen, "certjwk");
		if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].buf)
			goto bail;

		jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].len = (uint32_t)ec->xlen;
		memcpy(jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].buf, ec->x, ec->xlen);

		return 0;
	}

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

/*
 * length here is the 24-bit per-certificate length announced in the peer's
 * Certificate message, ie, up to 16MB, and it arrives before any of the
 * certificate body does.  Our copy of the cert is a convenience for
 * lws_tls_peer_cert_info() and JIT trust, so simply decline to capture
 * anything implausibly large rather than let an unauthenticated peer direct
 * tens of MB of heap per connection.  Real leaf certs are 1 - 2KB
 */

#define LWS_BEARSSL_MAX_CAPTURED_CERT 32768

static void
wrap_start_cert(const br_x509_class **ctx, uint32_t length)
{
	lws_tls_conn *conn = lws_container_of((br_x509_minimal_context *)ctx, lws_tls_conn, x509_ctx);

	if (length && length <= LWS_BEARSSL_MAX_CAPTURED_CERT) {
		if (conn->capturing_peer_cert) {
			if (!lws_x509_create(&conn->peer_cert)) {
				conn->peer_cert->der = lws_malloc(length, "peer_cert");
				if (!conn->peer_cert->der)
					lws_x509_destroy(&conn->peer_cert);
				else {
					conn->peer_cert->der_len = 0;
					conn->peer_cert->der_max = length;
				}
			}
		}
#if defined(LWS_WITH_TLS_JIT_TRUST)
		if (!lws_x509_create(&conn->temp_cert)) {
			conn->temp_cert->der = lws_malloc(length, "temp_cert");
			if (!conn->temp_cert->der)
				lws_x509_destroy(&conn->temp_cert);
			else {
				conn->temp_cert->der_len = 0;
				conn->temp_cert->der_max = length;
			}
		}
#endif
	} else
		if (length)
			lwsl_notice("%s: declining to capture %u byte cert\n",
				    __func__, (unsigned int)length);

	br_x509_minimal_vtable.start_cert(ctx, length);
}

static void
wrap_append(const br_x509_class **ctx, const unsigned char *buf, size_t len)
{
	lws_tls_conn *conn = lws_container_of((br_x509_minimal_context *)ctx, lws_tls_conn, x509_ctx);

	/*
	 * BearSSL only appends the number of bytes it announced at
	 * start_cert(), but the buffer size is derived from a peer-controlled
	 * length, so confirm it rather than trust it
	 */

	if (conn->capturing_peer_cert && conn->peer_cert && conn->peer_cert->der &&
	    conn->peer_cert->der_len + len <= conn->peer_cert->der_max) {
		memcpy(conn->peer_cert->der + conn->peer_cert->der_len, buf, len);
		conn->peer_cert->der_len += len;
	}
#if defined(LWS_WITH_TLS_JIT_TRUST)
	if (conn->temp_cert && conn->temp_cert->der &&
	    conn->temp_cert->der_len + len <= conn->temp_cert->der_max) {
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
		/*
		 * len is the usable size of ci.ns.name[]... passing 0 makes the
		 * backend's "does it fit" test fail for every real key
		 * identifier, so no KID would ever be captured and JIT trust
		 * could never engage
		 */
		if (!lws_x509_info(conn->temp_cert, LWS_TLS_CERT_INFO_SUBJECT_KEY_ID, &ci, sizeof(ci.ns.name)))
			lws_tls_kid_copy(&ci, &conn->wsi->tls.kid_chain.skid[conn->wsi->tls.kid_chain.count]);
		if (!lws_x509_info(conn->temp_cert, LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID, &ci, sizeof(ci.ns.name)))
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

	/*
	 * record the real chain result for LWS_TLS_CERT_INFO_VERIFIED; the
	 * LCCSCF_ALLOW_* bypasses below let the connection continue, but they
	 * do not make the peer "verified"
	 */
	conn->peer_cert_verified = !err;

	if (!err)
		return 0;

	if (err == BR_ERR_X509_EXPIRED && (conn->tls_use_ssl & LCCSCF_ALLOW_EXPIRED)) {
		lwsl_notice("%s: bypassing validation err %u due to ALLOW_EXPIRED\n", __func__, err);
		return 0;
	}

	/*
	 * LCCSCF_ALLOW_INSECURE means we don't care about the trust status of
	 * the peer cert at all, eg, we are probing it to report on it; any
	 * validation result is acceptable
	 */
	if (conn->tls_use_ssl & LCCSCF_ALLOW_INSECURE) {
		lwsl_notice("%s: bypassing validation err %u due to ALLOW_INSECURE\n", __func__, err);
		return 0;
	}

	if (err == BR_ERR_X509_NOT_TRUSTED && (conn->tls_use_ssl & LCCSCF_ALLOW_SELFSIGNED)) {
		lwsl_notice("%s: bypassing validation err %u due to ALLOW_SELFSIGNED\n", __func__, err);
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

	if (!vhost->tls.ssl_ctx)
		return 1;

	ctx = (struct lws_tls_ctx *)vhost->tls.ssl_ctx;

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
			/*
			 * the decoder does not copy; rsa_key / ec_key point
			 * into buf, so the ctx takes ownership of it
			 */
			ctx->key_buf = buf;
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
/*
 * Client-certificate (mutual TLS) support on the server side is NOT
 * implemented on this backend: nothing here arms a CertificateRequest, and
 * BearSSL's server engine is built with br_ssl_server_init_full_{rsa,ec}(),
 * which installs no client-certificate policy.
 *
 * So the only safe thing to do with a vhost that asks for client certs is
 * refuse it, rather than silently accept every anonymous client on a vhost
 * the app believes is mTLS-protected.  lws_tls_server_vhost_backend_init()
 * refuses vhost creation, and lws_tls_server_accept() refuses the handshake
 * as a backstop.
 *
 * Supported here: server cert + key (ssl_cert_filepath /
 * ssl_private_key_filepath and the _mem forms).
 * Not supported here: LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT,
 * LWS_SERVER_OPTION_MBEDTLS_VERIFY_CLIENT_CERT_POST_HANDSHAKE,
 * client_ssl_ca_filepath for verifying client certs.
 */

/*
 * Parity with the openssl server / client ctxs (C-406): put the protocol
 * floor at TLS 1.2.  br_ssl_{client,server}_init_full() leave the engine
 * offering TLS 1.0 and 1.1, which RFC 8996 deprecates and which are a
 * downgrade target.
 *
 * OVERRIDE: BearSSL has no SSL_CTX_set_options(), so the same public info
 * members the openssl backend uses are honoured here directly, carried on the
 * ctx as .options_clear: .ssl_options_clear (server) /
 * .ssl_client_options_clear (client).
 *
 *  - SSL_OP_NO_TLSv1 in _clear   lowers the floor to TLS 1.0
 *  - SSL_OP_NO_TLSv1_1 in _clear lowers the floor to TLS 1.1
 *
 * There is no renegotiation half to this: BearSSL implements no
 * renegotiation at all, in either direction, so SSL_OP_NO_RENEGOTIATION is
 * already unconditionally in force here.  BearSSL also implements no TLS 1.3,
 * so BR_TLS12 is both floor and ceiling by default.
 */

void
lws_bearssl_engine_set_floor(br_ssl_engine_context *eng, long options_clear)
{
	unsigned long long oc = (unsigned long long)options_clear;
	uint16_t min = BR_TLS12;

	if (oc & (unsigned long long)SSL_OP_NO_TLSv1)
		min = BR_TLS10;
	else
		if (oc & (unsigned long long)SSL_OP_NO_TLSv1_1)
			min = BR_TLS11;

	br_ssl_engine_set_versions(eng, min, BR_TLS12);
}

int
lws_tls_bearssl_vh_wants_client_certs(struct lws_vhost *vh)
{
	return !!lws_check_opt(vh->options,
			LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT) ||
	       !!lws_check_opt(vh->options,
			LWS_SERVER_OPTION_MBEDTLS_VERIFY_CLIENT_CERT_POST_HANDSHAKE);
}

int
lws_tls_server_client_cert_verify_config(struct lws_vhost *vh)
{
	if (!lws_tls_bearssl_vh_wants_client_certs(vh))
		return 0;

	lwsl_err("%s: vh %s: BearSSL backend cannot verify client certs\n",
		 __func__, vh->name);

	return 1;
}
int lws_tls_vhost_cert_info(struct lws_vhost *vhost, enum lws_tls_cert_info type, union lws_tls_cert_info_results *buf, size_t len)
{
	struct lws_tls_ctx *ctx = vhost->tls.ssl_ctx;
	struct lws_x509_cert leaf;

	if (!ctx || !ctx->chain || !ctx->chain_len)
		return -1;

	/* the leaf is chain[0]; wrap its DER without copying it */
	leaf.der = ctx->chain[0].data;
	leaf.der_len = ctx->chain[0].data_len;

	return lws_x509_info(&leaf, type, buf, len);
}

struct dn_append_ctx {
	uint8_t *data;
	size_t len;
	size_t size;
	char failed;
};

static void
append_dn(void *ctx, const void *buf, size_t len)
{
	struct dn_append_ctx *dn_ctx = ctx;

	/*
	 * a chunk we could not store would leave a hole in the middle of the
	 * DN, ie, a trust anchor that silently matches nothing... once we
	 * have missed anything, the whole DN is useless
	 */

	if (dn_ctx->failed)
		return;

	if (dn_ctx->len + len > dn_ctx->size) {
		size_t new_size = dn_ctx->size ? dn_ctx->size * 2 : 128;
		while (dn_ctx->len + len > new_size)
			new_size *= 2;
		uint8_t *new_data = lws_realloc(dn_ctx->data, new_size, "ta_dn");
		if (!new_data) {
			dn_ctx->failed = 1;
			return;
		}
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
	if (pk == NULL || dn_ctx.failed) {
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
		goto fail_ta;
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

	if (!conn)
		return -1;

	if (type == LWS_TLS_CERT_INFO_VERIFIED) {
		/* the result the wrapped validator recorded at end of chain */
		buf->verified = (unsigned int)(conn->peer_cert_verified & 1);

		return 0;
	}

	if (!conn->peer_cert)
		return -1;

	return lws_x509_info(conn->peer_cert, type, buf, len);
}

int
lws_x509_create_cert(struct lws_context *context,
		     uint8_t **cert_buf, size_t *cert_len,
		     uint8_t **key_buf, size_t *key_len,
		     const struct lws_x509_cert_gen_info *info)
{
	lwsl_err("%s: not supported on bearssl\n", __func__);
	return 1;
}

int
lws_x509_create_self_signed(struct lws_context *context,
			    uint8_t **cert_buf, size_t *cert_len,
			    uint8_t **key_buf, size_t *key_len,
			    const char *san, int key_bits)
{
	lwsl_err("%s: not supported on bearssl\n", __func__);
	return 1;
}

int lws_x509_verify(struct lws_x509_cert *x509, struct lws_x509_cert *trusted, const char *common_name) {
	br_x509_minimal_context mc;
	br_x509_trust_anchor ta;
	br_x509_decoder_context dc;
	br_x509_pkey *pk;
	struct dn_append_ctx dn_ctx;
	int err;

	memset(&dn_ctx, 0, sizeof(dn_ctx));
	br_x509_decoder_init(&dc, append_dn, &dn_ctx);
	br_x509_decoder_push(&dc, trusted->der, trusted->der_len);
	pk = br_x509_decoder_get_pkey(&dc);
	if (!pk || dn_ctx.failed) {
		if (dn_ctx.data) lws_free(dn_ctx.data);
		return -1;
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
		ta.pkey.key.rsa.n = pk->key.rsa.n;
		ta.pkey.key.rsa.nlen = pk->key.rsa.nlen;
		ta.pkey.key.rsa.e = pk->key.rsa.e;
		ta.pkey.key.rsa.elen = pk->key.rsa.elen;
		break;
	case BR_KEYTYPE_EC:
		ta.pkey.key_type = BR_KEYTYPE_EC;
		ta.pkey.key.ec.curve = pk->key.ec.curve;
		ta.pkey.key.ec.q = pk->key.ec.q;
		ta.pkey.key.ec.qlen = pk->key.ec.qlen;
		break;
	default:
		if (dn_ctx.data) lws_free(dn_ctx.data);
		return -1;
	}

	br_x509_minimal_init(&mc, &br_sha256_vtable, &ta, 1);
	br_x509_minimal_set_rsa(&mc, br_rsa_pkcs1_vrfy_get_default());
	br_x509_minimal_set_ecdsa(&mc, br_ec_get_default(), br_ecdsa_vrfy_asn1_get_default());

	br_x509_minimal_set_hash(&mc, br_sha256_ID, &br_sha256_vtable);
	br_x509_minimal_set_hash(&mc, br_sha384_ID, &br_sha384_vtable);
	br_x509_minimal_set_hash(&mc, br_sha512_ID, &br_sha512_vtable);
	br_x509_minimal_set_hash(&mc, br_sha1_ID, &br_sha1_vtable);

	if (common_name) {
		static const unsigned char OID_CN[] = { 3, 0x55, 0x04, 0x03 };
		br_name_element name_elts[1];
		char name_buf[256];

		name_elts[0].oid = OID_CN;
		name_elts[0].buf = name_buf;
		name_elts[0].len = sizeof(name_buf);
		name_elts[0].status = 0;

		br_x509_minimal_set_name_elements(&mc, name_elts, 1);
		mc.vtable->start_chain(&mc.vtable, common_name);
		mc.vtable->start_cert(&mc.vtable, (uint32_t)x509->der_len);
		mc.vtable->append(&mc.vtable, x509->der, x509->der_len);
		mc.vtable->end_cert(&mc.vtable);
		err = (int)mc.vtable->end_chain(&mc.vtable);
	} else {
		mc.vtable->start_chain(&mc.vtable, NULL);
		mc.vtable->start_cert(&mc.vtable, (uint32_t)x509->der_len);
		mc.vtable->append(&mc.vtable, x509->der, x509->der_len);
		mc.vtable->end_cert(&mc.vtable);
		err = (int)mc.vtable->end_chain(&mc.vtable);
	}

	if (dn_ctx.data) lws_free(dn_ctx.data);

	if (err == 0 || err == BR_ERR_X509_OK)
		return 0;

	return -1;
}
