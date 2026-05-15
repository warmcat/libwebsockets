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
#include "private-lib-tls-openssl.h"

#if defined(LWS_WITH_TLS) && !defined(LWS_WITH_MBEDTLS) && !defined(LWS_WITH_WOLFSSL) && !defined(LWS_WITH_SCHANNEL)

static uint8_t
from_hex(char c)
{
	if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
	if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
	if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
	return 0;
}

#define TLSEXT_TYPE_quic_transport_parameters 57

static int
openssl_quic_ext_add_cb(SSL *ssl, unsigned int ext_type,
			unsigned int context,
			const unsigned char **out, size_t *outlen,
			X509 *x, size_t chainidx,
			int *al, void *add_arg)
{
	struct lws *wsi = (struct lws *)SSL_get_app_data(ssl);

	if (!wsi || !wsi->tls.quic_tp_send)
		return 0; /* do not add the extension if no params to send */

	*out = wsi->tls.quic_tp_send;
	*outlen = wsi->tls.quic_tp_send_len;

	return 1;
}

static void
openssl_quic_ext_free_cb(SSL *ssl, unsigned int ext_type,
			 unsigned int context,
			 const unsigned char *out, void *add_arg)
{
	/* nothing to free, memory is managed by LWS */
}

static int
openssl_quic_ext_parse_cb(SSL *ssl, unsigned int ext_type,
			  unsigned int context,
			  const unsigned char *in, size_t inlen,
			  X509 *x, size_t chainidx, int *al,
			  void *parse_arg)
{
	struct lws *wsi = (struct lws *)SSL_get_app_data(ssl);

	if (!wsi)
		return 1;

	wsi->tls.quic_tp_recv = lws_malloc(inlen, "quic_tp_recv");
	if (!wsi->tls.quic_tp_recv) {
		*al = SSL_AD_INTERNAL_ERROR;
		return 0;
	}

	memcpy(wsi->tls.quic_tp_recv, in, inlen);
	wsi->tls.quic_tp_recv_len = inlen;

	return 1;
}

static void
openssl_quic_keylog_cb(const SSL *ssl, const char *line)
{
	struct lws *wsi = (struct lws *)SSL_get_app_data(ssl);
	enum lws_tls_quic_secret_type type;
	const char *secret_hex = NULL;
	uint8_t secret[64];
	size_t len = 0;

	if (!wsi || !wsi->tls.quic_secret_cb || !line)
		return;

	if (!strncmp(line, "CLIENT_EARLY_TRAFFIC_SECRET ", 28)) {
		type = LWS_TLS_QUIC_SECRET_CLIENT_EARLY;
		secret_hex = strchr(line + 28, ' ');
	} else if (!strncmp(line, "CLIENT_HANDSHAKE_TRAFFIC_SECRET ", 32)) {
		type = LWS_TLS_QUIC_SECRET_CLIENT_HANDSHAKE;
		secret_hex = strchr(line + 32, ' ');
	} else if (!strncmp(line, "SERVER_HANDSHAKE_TRAFFIC_SECRET ", 32)) {
		type = LWS_TLS_QUIC_SECRET_SERVER_HANDSHAKE;
		secret_hex = strchr(line + 32, ' ');
	} else if (!strncmp(line, "CLIENT_TRAFFIC_SECRET_0 ", 24)) {
		type = LWS_TLS_QUIC_SECRET_CLIENT_APPLICATION;
		secret_hex = strchr(line + 24, ' ');
	} else if (!strncmp(line, "SERVER_TRAFFIC_SECRET_0 ", 24)) {
		type = LWS_TLS_QUIC_SECRET_SERVER_APPLICATION;
		secret_hex = strchr(line + 24, ' ');
	}

	if (!secret_hex)
		return;

	secret_hex++; /* skip space */

	while (*secret_hex && *(secret_hex + 1) && len < sizeof(secret)) {
		secret[len++] = (uint8_t)((from_hex(secret_hex[0]) << 4) | from_hex(secret_hex[1]));
		secret_hex += 2;
	}

	wsi->tls.quic_secret_cb(wsi, type, secret, len);
}

int
lws_tls_quic_vhost_init(SSL_CTX *ctx)
{
	/* Ignore failure if already added */
	SSL_CTX_add_custom_ext(ctx, TLSEXT_TYPE_quic_transport_parameters,
			       SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
			       openssl_quic_ext_add_cb,
			       openssl_quic_ext_free_cb, NULL,
			       openssl_quic_ext_parse_cb, NULL);
	return 0;
}

int
lws_tls_quic_init(struct lws *wsi, lws_tls_quic_secret_cb cb)
{
	BIO *rbio, *wbio;
	SSL_CTX *ctx;

	if (!wsi->tls.ssl)
		return -1;

	ctx = SSL_get_SSL_CTX(wsi->tls.ssl);

	rbio = BIO_new(BIO_s_mem());
	wbio = BIO_new(BIO_s_mem());

	if (!rbio || !wbio) {
		if (rbio) BIO_free(rbio);
		if (wbio) BIO_free(wbio);
		return -1;
	}

	BIO_set_nbio(rbio, 1);
	BIO_set_nbio(wbio, 1);

	SSL_set_bio(wsi->tls.ssl, rbio, wbio);

	wsi->tls.quic_secret_cb = cb;
	SSL_set_app_data(wsi->tls.ssl, wsi);

	SSL_CTX_set_keylog_callback(ctx, openssl_quic_keylog_cb);

	return 0;
}

int
lws_tls_quic_advance_handshake(struct lws *wsi,
			       const uint8_t *in, size_t in_len,
			       uint8_t *out, size_t *out_len)
{
	BIO *rbio = SSL_get_rbio(wsi->tls.ssl);
	BIO *wbio = SSL_get_wbio(wsi->tls.ssl);
	int n;
	size_t written = 0;

	if (!rbio || !wbio)
		return -1;

	if (in && in_len)
		BIO_write(rbio, in, (int)in_len);

	n = SSL_do_handshake(wsi->tls.ssl);

	if (out && out_len) {
		n = BIO_read(wbio, out, (int)*out_len);
		if (n > 0)
			written = (size_t)n;
		*out_len = written;
	}

	return n <= 0 && SSL_get_error(wsi->tls.ssl, n) == SSL_ERROR_WANT_READ ? 1 : 0;
}

int
lws_tls_quic_set_transport_parameters(struct lws *wsi, const uint8_t *tp, size_t tp_len)
{
	wsi->tls.quic_tp_send = tp;
	wsi->tls.quic_tp_send_len = tp_len;
	return 0;
}

int
lws_tls_quic_get_transport_parameters(struct lws *wsi, const uint8_t **tp, size_t *tp_len)
{
	if (!wsi->tls.quic_tp_recv)
		return -1;

	*tp = wsi->tls.quic_tp_recv;
	*tp_len = wsi->tls.quic_tp_recv_len;
	return 0;
}

static int test_secrets_extracted = 0;

static int
test_secret_cb(struct lws *wsi, enum lws_tls_quic_secret_type type,
	       const uint8_t *secret, size_t secret_len)
{
	lwsl_notice("%s: extracted type %d, len %d\n", __func__, type, (int)secret_len);
	test_secrets_extracted++;
	return 0;
}

int
lws_tls_quic_api_test(void)
{
	struct lws wsi_client, wsi_server;
	SSL_CTX *cctx = NULL, *sctx = NULL;
	uint8_t c2s[4096], s2c[4096];
	size_t c2s_len = 0, s2c_len = 0;
	int iter = 0;
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;
	BIGNUM *e = NULL;
	RSA *rsa = NULL;

	const uint8_t *recvd;
	size_t recvd_len;
	uint8_t ctp[] = { 0x01, 0x02, 0x03, 0x04 };
	uint8_t stp[] = { 0x05, 0x06, 0x07, 0x08 };

	memset(&wsi_client, 0, sizeof(wsi_client));
	memset(&wsi_server, 0, sizeof(wsi_server));

	cctx = SSL_CTX_new(TLS_client_method());
	sctx = SSL_CTX_new(TLS_server_method());

	if (!cctx || !sctx)
		goto fail;

	SSL_CTX_set_min_proto_version(cctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(cctx, TLS1_3_VERSION);
	SSL_CTX_set_min_proto_version(sctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(sctx, TLS1_3_VERSION);

	lws_tls_quic_vhost_init(cctx);
	lws_tls_quic_vhost_init(sctx);

	/* Generate a quick temporary cert for the server */
	pkey = EVP_PKEY_new();
	e = BN_new();
	rsa = RSA_new();
	if (!pkey || !e || !rsa || !BN_set_word(e, RSA_F4) ||
	    !RSA_generate_key_ex(rsa, 2048, e, NULL) ||
	    !EVP_PKEY_assign_RSA(pkey, rsa)) {
		if (rsa) RSA_free(rsa);
		goto fail;
	}

	x509 = X509_new();
	X509_set_version(x509, 2);
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
	X509_set_pubkey(x509, pkey);
	X509_sign(x509, pkey, EVP_sha256());

	SSL_CTX_use_certificate(sctx, x509);
	SSL_CTX_use_PrivateKey(sctx, pkey);

	wsi_client.tls.ssl = SSL_new(cctx);
	wsi_server.tls.ssl = SSL_new(sctx);

	if (!wsi_client.tls.ssl || !wsi_server.tls.ssl)
		goto fail;

	SSL_set_connect_state(wsi_client.tls.ssl);
	SSL_set_accept_state(wsi_server.tls.ssl);

	if (lws_tls_quic_init(&wsi_client, test_secret_cb))
		goto fail;
	if (lws_tls_quic_init(&wsi_server, test_secret_cb))
		goto fail;

	lws_tls_quic_set_transport_parameters(&wsi_client, ctp, sizeof(ctp));
	lws_tls_quic_set_transport_parameters(&wsi_server, stp, sizeof(stp));

	/* Start the handshake by advancing the client with no input */
	c2s_len = sizeof(c2s);
	lws_tls_quic_advance_handshake(&wsi_client, NULL, 0, c2s, &c2s_len);

	while (iter++ < 10) {
		if (c2s_len) {
			lwsl_notice("C -> S: %d bytes\n", (int)c2s_len);
			s2c_len = sizeof(s2c);
			(void)lws_tls_quic_advance_handshake(&wsi_server, c2s, c2s_len, s2c, &s2c_len);
			c2s_len = 0;
		}

		if (s2c_len) {
			lwsl_notice("S -> C: %d bytes\n", (int)s2c_len);
			c2s_len = sizeof(c2s);
			(void)lws_tls_quic_advance_handshake(&wsi_client, s2c, s2c_len, c2s, &c2s_len);
			s2c_len = 0;
		}

		if (SSL_is_init_finished(wsi_client.tls.ssl) && SSL_is_init_finished(wsi_server.tls.ssl))
			break;
	}

	lwsl_notice("Handshake finished, secrets extracted: %d\n", test_secrets_extracted);

	if (!SSL_is_init_finished(wsi_client.tls.ssl))
		goto fail;

	if (test_secrets_extracted < 4) /* Early, C_Handshake, S_Handshake, C_App, S_App */
		goto fail;

	if (lws_tls_quic_get_transport_parameters(&wsi_client, &recvd, &recvd_len) ||
	    recvd_len != sizeof(stp) || memcmp(recvd, stp, sizeof(stp))) {
		lwsl_err("Client failed to receive Server TP\n");
		goto fail;
	}

	if (lws_tls_quic_get_transport_parameters(&wsi_server, &recvd, &recvd_len) ||
	    recvd_len != sizeof(ctp) || memcmp(recvd, ctp, sizeof(ctp))) {
		lwsl_err("Server failed to receive Client TP\n");
		goto fail;
	}

	lwsl_notice("Transport parameters successfully exchanged\n");

	SSL_free(wsi_client.tls.ssl);
	SSL_free(wsi_server.tls.ssl);
	X509_free(x509);
	EVP_PKEY_free(pkey);
	BN_free(e);
	SSL_CTX_free(cctx);
	SSL_CTX_free(sctx);
	return 0;

fail:
	if (wsi_client.tls.ssl) SSL_free(wsi_client.tls.ssl);
	if (wsi_server.tls.ssl) SSL_free(wsi_server.tls.ssl);
	if (x509) X509_free(x509);
	if (pkey) EVP_PKEY_free(pkey);
	if (e) BN_free(e);
	if (cctx) SSL_CTX_free(cctx);
	if (sctx) SSL_CTX_free(sctx);
	return -1;
}

#endif
