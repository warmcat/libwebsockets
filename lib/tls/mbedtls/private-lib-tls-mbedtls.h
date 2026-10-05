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
 *
 *  gencrypto mbedtls-specific helper declarations
 */

#ifndef LWS_PRIVATE_LIB_TLS_MBEDTLS_H
#define LWS_PRIVATE_LIB_TLS_MBEDTLS_H

#include <mbedtls/x509_crl.h>
#include <mbedtls/net_sockets.h>
#include <errno.h>

/*
 * The f_rng / p_rng pair the mbedtls 3.x apis take (mbedtls 4 apis take
 * none, so neither is used there).  See LWS_MBEDTLS_PSA_RNG in
 * private-lib-tls.h for when the RNG is PSA's.
 *
 * Every p_rng comes from one of two places:
 *
 *  - the context's RNG: lws_mbedtls_cx_p_rng(cx).  That's the one place that
 *    knows the context only has a DRBG (cx->mcdc) without
 *    LWS_MBEDTLS_PSA_RNG, so nothing else names cx->mcdc for an RNG
 *
 *  - a DRBG of the caller's own, eg, gendtls' ctx->ctr_drbg, which exists in
 *    every build that uses it but is only seeded without
 *    LWS_MBEDTLS_PSA_RNG: LWS_MBEDTLS_P_RNG(&own_drbg).  The argument is
 *    still evaluated (and so type checked) in PSA RNG builds, and then not
 *    used
 */
#if defined(LWS_MBEDTLS_PSA_RNG)
#define LWS_MBEDTLS_F_RNG		mbedtls_psa_get_random
#define LWS_MBEDTLS_P_RNG(_drbg)	((void)(_drbg), MBEDTLS_PSA_RANDOM_STATE)
#else
#define LWS_MBEDTLS_F_RNG		mbedtls_ctr_drbg_random
#define LWS_MBEDTLS_P_RNG(_drbg)	(_drbg)
#endif

struct lws_x509_cert {
	mbedtls_x509_crt cert; /* has a .next for linked-list / chain */
};
typedef struct lws_x509_cert lws_tls_x509;

/*
 * How many ciphersuites a vhost's configured cipher list may resolve to.
 * mbedtls_ssl_conf_ciphersuites() keeps the array by pointer, so it lives in
 * the ctx it belongs to; a configured list is a restriction, if it needs more
 * entries than this it is not restricting anything useful.
 */

#define LWS_MBEDTLS_CS_MAX 40

struct lws_tls_ctx {
	mbedtls_ssl_config conf;
	mbedtls_x509_crt *chain;
	mbedtls_x509_crt *ca_chain;
	mbedtls_pk_context *key;
	char alpn_strings[128];
	const char *alpn_protocols[8];
	int ciphersuites[LWS_MBEDTLS_CS_MAX + 1]; /* 0-terminated */
};

struct lws_tls_conn {
	mbedtls_ssl_context ssl; /* first: callbacks given &ssl find the conn */
	mbedtls_net_context net;
	struct lws_tls_ctx *ctx;
	/*
	 * The wsi the session belongs to, for our mbedtls callbacks that are
	 * only given the ssl context (lws_container_of() gets the conn from
	 * that).  mbedtls' own user data pointer is 3.2+ only.  Kept current
	 * across a hand-off by lws_tls_conn_set_wsi().
	 */
	struct lws *wsi;
	/*
	 * Some things mbedtls only takes on the ssl config are actually
	 * per-connection: the client ALPN list (which it stores by pointer,
	 * without copying), and the QUIC transport mode.  ctx->conf is shared
	 * by every connection on the vhost, so when we have any of those, conf
	 * is a private, shallow copy of ctx->conf that carries them (it
	 * aliases ctx->conf's contents and must never be passed to
	 * mbedtls_ssl_config_free()).
	 */
	mbedtls_ssl_config conf;
#if defined(LWS_WITH_SERVER)
	/*
	 * A server connection whose ClientHello named a vhost in SNI: our
	 * reference on the ctx of that vhost, whose cert, key and client CA
	 * chain the handshake uses.  mbedtls only takes them as per-handshake
	 * overrides by pointer (ssl->conf stays the listening vhost's), so the
	 * reference is what stops a cert renewal of that vhost freeing them
	 * under the handshake.  Held until the session is freed, see
	 * lws_mbedtls_conn_destroy().
	 */
	struct lws_tls_ctx_ref *sni_ref;
#endif
	uint8_t own_conf;
#if defined(LWS_WITH_CLIENT)
	char alpn_strings[128];
	const char *alpn_protocols[8];
#endif
};

typedef struct lws_tls_conn lws_tls_conn;
typedef struct lws_tls_ctx lws_tls_ctx;
typedef void lws_tls_bio;

typedef struct lws_mbedtls_x509_authority
{
	mbedtls_x509_buf	keyIdentifier;
	mbedtls_x509_sequence 	authorityCertIssuer;
	mbedtls_x509_buf	authorityCertSerialNumber;
	mbedtls_x509_buf	raw;
}
lws_mbedtls_x509_authority;


#if !defined(LWS_HAVE_MBEDTLS_V4)
/*
 * p_rng for the context's RNG, to go with LWS_MBEDTLS_F_RNG.  Without
 * LWS_MBEDTLS_PSA_RNG it's the context's DRBG, so cx must not be NULL
 */
void *
lws_mbedtls_cx_p_rng(struct lws_context *cx);
#endif

mbedtls_md_type_t
lws_gencrypto_mbedtls_hash_to_MD_TYPE(enum lws_genhash_types hash_type);

int
lws_gencrypto_mbedtls_rngf(void *context, unsigned char *buf, size_t len);

void mbedtls_quic_bio_free(struct lws *wsi);
void lws_mbedtls_conn_destroy(struct lws *wsi);
void lws_mbedtls_set_alpn(struct lws_tls_ctx *ctx, const char *alpn_comma);

void
lws_mbedtls_conf_floor(mbedtls_ssl_config *conf, long options_clear);

int
lws_mbedtls_conf_ciphers(struct lws_tls_ctx *ctx, const char *vhname,
			 const char *iana, const char *list12,
			 const char *list13);

#if defined(LWS_WITH_CLIENT)
int
lws_mbedtls_conn_set_alpn(struct lws_tls_conn *conn, const char *alpn_comma);
#if defined(LWS_WITH_TLS_JIT_TRUST) && defined(LWS_HAVE_mbedtls_ssl_set_verify)
void
lws_mbedtls_client_set_verify(struct lws *wsi);
#endif
#endif

int
lws_mbedtls_x509_crt_parse_mem(mbedtls_x509_crt *crt, const void *mem,
			       size_t len);

int
lws_mbedtls_pk_parse_key_mem(struct lws_context *cx, mbedtls_pk_context *key,
			     const void *mem, size_t len);

int
lws_tls_session_new_mbedtls(struct lws *wsi);

int
lws_tls_mbedtls_cert_info(mbedtls_x509_crt *x509, enum lws_tls_cert_info type,
			  union lws_tls_cert_info_results *buf, size_t len);

int
lws_x509_get_crt_ext(mbedtls_x509_crt *crt, mbedtls_x509_buf *skid,
		     lws_mbedtls_x509_authority *akid);

#if defined(LWS_HAVE_MBEDTLS_V4)
#define MBEDTLS_ASN1_BOOLEAN                 0x01
#define MBEDTLS_ASN1_INTEGER                 0x02
#define MBEDTLS_ASN1_BIT_STRING              0x03
#define MBEDTLS_ASN1_OCTET_STRING            0x04
#define MBEDTLS_ASN1_NULL                    0x05
#define MBEDTLS_ASN1_OID                     0x06
#define MBEDTLS_ASN1_UTF8_STRING             0x0C
#define MBEDTLS_ASN1_SEQUENCE                0x10
#define MBEDTLS_ASN1_SET                     0x11
#define MBEDTLS_ASN1_PRINTABLE_STRING        0x13
#define MBEDTLS_ASN1_T61_STRING              0x14
#define MBEDTLS_ASN1_IA5_STRING              0x16
#define MBEDTLS_ASN1_UTC_TIME                0x17
#define MBEDTLS_ASN1_GENERALIZED_TIME        0x18
#define MBEDTLS_ASN1_UNIVERSAL_STRING        0x1C
#define MBEDTLS_ASN1_BMP_STRING              0x1E
#define MBEDTLS_ASN1_PRIMITIVE               0x00
#define MBEDTLS_ASN1_CONSTRUCTED             0x20
#define MBEDTLS_ASN1_CONTEXT_SPECIFIC        0x80

int mbedtls_asn1_get_len(unsigned char **p, const unsigned char *end, size_t *len);
int mbedtls_asn1_get_tag(unsigned char **p, const unsigned char *end, size_t *len, int tag);
int mbedtls_asn1_get_bool(unsigned char **p, const unsigned char *end, int *val);
int mbedtls_asn1_get_int(unsigned char **p, const unsigned char *end, int *val);
int mbedtls_asn1_get_bitstring_null(unsigned char **p, const unsigned char *end, size_t *len);

/* 0 if PSA has no such hash */
psa_algorithm_t
lws_genhash_to_psa_alg(enum lws_genhash_types type);
#endif

#if defined(LWS_HAVE_MBEDTLS_V4) || ((MBEDTLS_VERSION_MAJOR == 3) && (MBEDTLS_VERSION_MINOR >= 5))
	int mbedtls_x509_get_name(unsigned char **p, const unsigned char *end,
						  mbedtls_x509_name *cur);
#endif

#endif
