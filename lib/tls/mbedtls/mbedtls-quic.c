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
#include "private-lib-tls-mbedtls.h"

#if defined(LWS_ROLE_QUIC) && defined(LWS_WITH_TLS) && defined(LWS_WITH_MBEDTLS)

static void
mbedtls_quic_export_keys_cb(void *p_expkey,
			    mbedtls_ssl_key_export_type type,
			    const unsigned char *secret,
			    size_t secret_len,
			    const unsigned char client_random[32],
			    const unsigned char server_random[32],
			    mbedtls_tls_prf_types tls_prf_type)
{
	struct lws *wsi = (struct lws *)p_expkey;
	enum lws_tls_quic_secret_type qtype;

	if (!wsi || !wsi->tls.quic_secret_cb)
		return;

	switch (type) {
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_EARLY_SECRET:
		qtype = LWS_TLS_QUIC_SECRET_CLIENT_EARLY;
		break;
	case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_HANDSHAKE_TRAFFIC_SECRET:
		qtype = LWS_TLS_QUIC_SECRET_CLIENT_HANDSHAKE;
		break;
	case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_HANDSHAKE_TRAFFIC_SECRET:
		qtype = LWS_TLS_QUIC_SECRET_SERVER_HANDSHAKE;
		break;
	case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_APPLICATION_TRAFFIC_SECRET:
		qtype = LWS_TLS_QUIC_SECRET_CLIENT_APPLICATION;
		break;
	case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_APPLICATION_TRAFFIC_SECRET:
		qtype = LWS_TLS_QUIC_SECRET_SERVER_APPLICATION;
		break;
#endif
	default:
		return; /* Not a QUIC relevant secret */
	}

	wsi->tls.quic_secret_cb(wsi, qtype, secret, secret_len);
}

struct mbedtls_quic_bio {
	const uint8_t *in;
	size_t in_len;
	size_t in_pos;

	uint8_t *out;
	size_t out_max;
	size_t out_len;
};

static int
mbedtls_quic_bio_send(void *ctx, const unsigned char *buf, size_t len)
{
	struct mbedtls_quic_bio *b = (struct mbedtls_quic_bio *)ctx;

	if (!b->out || b->out_len + len > b->out_max)
		return MBEDTLS_ERR_SSL_WANT_WRITE;

	memcpy(b->out + b->out_len, buf, len);
	b->out_len += len;

	return (int)len;
}

static int
mbedtls_quic_bio_recv(void *ctx, unsigned char *buf, size_t len)
{
	struct mbedtls_quic_bio *b = (struct mbedtls_quic_bio *)ctx;
	size_t avail;

	if (!b->in)
		return MBEDTLS_ERR_SSL_WANT_READ;

	avail = b->in_len - b->in_pos;
	if (avail == 0)
		return MBEDTLS_ERR_SSL_WANT_READ;

	if (len > avail)
		len = avail;

	memcpy(buf, b->in + b->in_pos, len);
	b->in_pos += len;

	return (int)len;
}

int
lws_tls_quic_init(struct lws *wsi, lws_tls_quic_secret_cb cb)
{
	struct mbedtls_quic_bio *b;
	mbedtls_ssl_context *msc;

	if (!wsi->tls.ssl)
		return -1;

	msc = SSL_mbedtls_ssl_context_from_SSL(wsi->tls.ssl);
	if (!msc)
		return -1;

	wsi->tls.quic_secret_cb = cb;

	b = lws_zalloc(sizeof(*b), "quic bio");
	if (!b)
		return -1;

	/* Save bio ctx in a free member. We don't have one in tls,
	   but we can just store it in client_bio which is currently unused. */
	wsi->tls.client_bio = (lws_tls_bio *)b;

	mbedtls_ssl_set_bio(msc, b, mbedtls_quic_bio_send, mbedtls_quic_bio_recv, NULL);
	mbedtls_ssl_set_export_keys_cb(msc, mbedtls_quic_export_keys_cb, wsi);

	return 0;
}

int
lws_tls_quic_advance_handshake(struct lws *wsi, int level,
			       const uint8_t *in, size_t in_len,
			       uint8_t *out, size_t *out_len)
{
	int hs_n, err;
	struct mbedtls_quic_bio *b;

	if (!wsi->tls.client_bio)
		return -1;

	b = (struct mbedtls_quic_bio *)wsi->tls.client_bio;

	b->in = in;
	b->in_len = in_len;
	b->in_pos = 0;

	b->out = out;
	b->out_max = out ? *out_len : 0;
	b->out_len = 0;

	if (in_len > 0) {
		lwsl_debug("%s: feeding %d bytes to MbedTLS (is_server=%d)\n", __func__, (int)in_len, wsi->quic.qn ? wsi->quic.qn->is_server : -1);
	}

	hs_n = SSL_do_handshake(wsi->tls.ssl);

	if (out_len)
		*out_len = b->out_len;

	if (hs_n != 1) {
		err = SSL_get_error(wsi->tls.ssl, hs_n);
		/* The MbedTLS wrapper returns 0 for WANT_READ/WANT_WRITE, and SSL_get_error doesn't map it if hs_n == 0. */
		if (hs_n == 0 && (wsi->tls.ssl->err == MBEDTLS_ERR_SSL_WANT_READ || wsi->tls.ssl->err == MBEDTLS_ERR_SSL_WANT_WRITE))
			return 1; /* wanting more */

		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
			return 1; /* wanting more */

		lwsl_wsi_err(wsi, "SSL_do_handshake failed: hs_n %d, err %d", hs_n, err);
		return -1;
	}

	if (wsi->quic.qn && !wsi->quic.qn->handshake_done)
		return 0;

	return 0;
}

int
lws_tls_quic_set_transport_parameters(struct lws *wsi, const uint8_t *tp, size_t tp_len)
{
	wsi->tls.quic_tp_send = tp;
	wsi->tls.quic_tp_send_len = tp_len;
	return 0; /* MbedTLS has no custom extension API yet */
}

int
lws_tls_quic_get_transport_parameters(struct lws *wsi, const uint8_t **tp, size_t *tp_len)
{
	return -1; /* MbedTLS has no custom extension API yet */
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
	SSL *cctx = NULL, *sctx = NULL;
	SSL_CTX *c_ssl_ctx = NULL, *s_ssl_ctx = NULL;
	mbedtls_ssl_context *msc_client, *msc_server;
	uint8_t c2s[4096], s2c[4096];
	size_t c2s_len = 0, s2c_len = 0;
	int iter = 0;

	memset(&wsi_client, 0, sizeof(wsi_client));
	memset(&wsi_server, 0, sizeof(wsi_server));

	c_ssl_ctx = SSL_CTX_new(TLS_client_method());
	s_ssl_ctx = SSL_CTX_new(TLS_server_method());

	if (!c_ssl_ctx || !s_ssl_ctx)
		goto fail;

	SSL_CTX_set_verify(c_ssl_ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_verify(s_ssl_ctx, SSL_VERIFY_NONE, NULL);

	cctx = SSL_new(c_ssl_ctx);
	sctx = SSL_new(s_ssl_ctx);

	if (!cctx || !sctx)
		goto fail;

	msc_client = SSL_mbedtls_ssl_context_from_SSL(cctx);
	msc_server = SSL_mbedtls_ssl_context_from_SSL(sctx);

	wsi_client.tls.ssl = cctx;
	wsi_server.tls.ssl = sctx;

	if (lws_tls_quic_init(&wsi_client, test_secret_cb))
		goto fail;
	if (lws_tls_quic_init(&wsi_server, test_secret_cb))
		goto fail;

	/* Start the handshake by advancing the client with no input */
	c2s_len = sizeof(c2s);
	lws_tls_quic_advance_handshake(&wsi_client, 0, NULL, 0, c2s, &c2s_len);

	while (iter++ < 10) {
		if (c2s_len) {
			lwsl_notice("C -> S: %d bytes\n", (int)c2s_len);
			s2c_len = sizeof(s2c);
			(void)lws_tls_quic_advance_handshake(&wsi_server, 0, c2s, c2s_len, s2c, &s2c_len);
			c2s_len = 0;
		}

		if (s2c_len) {
			lwsl_notice("S -> C: %d bytes\n", (int)s2c_len);
			c2s_len = sizeof(c2s);
			(void)lws_tls_quic_advance_handshake(&wsi_client, 0, s2c, s2c_len, c2s, &c2s_len);
			s2c_len = 0;
		}

		if (msc_client->MBEDTLS_PRIVATE(state) == MBEDTLS_SSL_HANDSHAKE_OVER &&
		    msc_server->MBEDTLS_PRIVATE(state) == MBEDTLS_SSL_HANDSHAKE_OVER)
			break;
	}

	lwsl_notice("Handshake finished, secrets extracted: %d\n", test_secrets_extracted);

fail:
	if (cctx) SSL_free(cctx);
	if (sctx) SSL_free(sctx);
	if (c_ssl_ctx) SSL_CTX_free(c_ssl_ctx);
	if (s_ssl_ctx) SSL_CTX_free(s_ssl_ctx);

	if (wsi_client.tls.client_bio) lws_free(wsi_client.tls.client_bio);
	if (wsi_server.tls.client_bio) lws_free(wsi_server.tls.client_bio);

	return 0;
}

#endif
