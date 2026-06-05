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

void
mbedtls_quic_bio_free(struct lws *wsi);

#if defined(LWS_ROLE_QUIC) && defined(LWS_WITH_TLS) && defined(LWS_WITH_MBEDTLS)

#if defined(LWS_HAVE_mbedtls_ssl_set_quic_transport_ops)

struct mbedtls_quic_buf {
	uint8_t *rx_buf;
	size_t rx_len;

	uint8_t *out;
	size_t out_max;
	size_t out_len;
};

static int
mbedtls_quic_write_handshake_msg(mbedtls_ssl_context *ssl, mbedtls_ssl_quic_enc_level_t level, const unsigned char *buf, size_t len)
{
	struct lws *wsi = (struct lws *)mbedtls_ssl_get_user_data_p(ssl);
	if (!wsi)
		return MBEDTLS_ERR_SSL_INTERNAL_ERROR;

	if (wsi->tls.quic_secret_cb == (lws_tls_quic_secret_cb)1) {
		/* Used during api test */
		struct mbedtls_quic_buf *b = (struct mbedtls_quic_buf *)wsi->tls.client_bio;
		if (b && b->out && b->out_len + len <= b->out_max) {
			memcpy(b->out + b->out_len, buf, len);
			b->out_len += len;
		}
		return 0;
	}

	int lws_level;
	switch (level) {
	case MBEDTLS_SSL_QUIC_ENC_LEVEL_INITIAL: lws_level = 0; break;
	case MBEDTLS_SSL_QUIC_ENC_LEVEL_EARLY_DATA: lws_level = 1; break;
	case MBEDTLS_SSL_QUIC_ENC_LEVEL_HANDSHAKE: lws_level = 2; break;
	case MBEDTLS_SSL_QUIC_ENC_LEVEL_APPLICATION: lws_level = 3; break;
	default: return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
	}

	lws_tls_quic_tx_crypto_cb(wsi, lws_level, buf, len);
	return 0;
}

static int
mbedtls_quic_read_handshake_msg(mbedtls_ssl_context *ssl,
				mbedtls_ssl_quic_enc_level_t level,
				unsigned char *buf, size_t len)
{
	struct lws *wsi = (struct lws *)mbedtls_ssl_get_user_data_p(ssl);
	struct mbedtls_quic_buf *b;
	size_t msg_len, total_len;

	if (!wsi || !wsi->tls.client_bio)
		return MBEDTLS_ERR_SSL_INTERNAL_ERROR;

	b = (struct mbedtls_quic_buf *)wsi->tls.client_bio;

	if (b->rx_len < 4)
		return MBEDTLS_ERR_SSL_WANT_READ;

	msg_len = ((size_t)b->rx_buf[1] << 16) | ((size_t)b->rx_buf[2] << 8) | b->rx_buf[3];
	total_len = msg_len + 4;

	if (b->rx_len < total_len)
		return MBEDTLS_ERR_SSL_WANT_READ;

	if (len < total_len)
		return MBEDTLS_ERR_SSL_INTERNAL_ERROR;

	memcpy(buf, b->rx_buf, total_len);

	if (b->rx_len > total_len)
		memmove(b->rx_buf, b->rx_buf + total_len, b->rx_len - total_len);
	b->rx_len -= total_len;

	lwsl_notice("%s: returning %d bytes (level %d)\n", __func__, (int)total_len, (int)level);
	return (int)total_len;
}


static int
mbedtls_quic_set_traffic_secrets(mbedtls_ssl_context *ssl,
			    mbedtls_ssl_secret_type_t type,
			    const unsigned char *client_secret,
			    const unsigned char *server_secret,
			    size_t secret_len)
{
	struct lws *wsi = (struct lws *)mbedtls_ssl_get_user_data_p(ssl);
	enum lws_tls_quic_secret_type ct, st;

	if (!wsi || !wsi->tls.quic_secret_cb)
		return 0;

	if (wsi->tls.quic_secret_cb == (lws_tls_quic_secret_cb)1)
		return 0;

	switch (type) {
	case MBEDTLS_SSL_SECRET_TYPE_EARLY:
		ct = st = LWS_TLS_QUIC_SECRET_CLIENT_EARLY;
		break;
	case MBEDTLS_SSL_SECRET_TYPE_HANDSHAKE:
		ct = LWS_TLS_QUIC_SECRET_CLIENT_HANDSHAKE;
		st = LWS_TLS_QUIC_SECRET_SERVER_HANDSHAKE;
		break;
	case MBEDTLS_SSL_SECRET_TYPE_APPLICATION:
		ct = LWS_TLS_QUIC_SECRET_CLIENT_APPLICATION;
		st = LWS_TLS_QUIC_SECRET_SERVER_APPLICATION;
		break;
	default:
		return 0;
	}

	if (client_secret)
		wsi->tls.quic_secret_cb(wsi, ct, client_secret, secret_len);
	if (server_secret)
		wsi->tls.quic_secret_cb(wsi, st, server_secret, secret_len);

	return 0;
}

static int
mbedtls_quic_notify_alert(mbedtls_ssl_context *ssl, unsigned char level, unsigned char description)
{
	struct lws *wsi = (struct lws *)mbedtls_ssl_get_user_data_p(ssl);
	if (wsi)
		wsi->tls.quic_alert = description;
	return 0;
}

static const mbedtls_ssl_transport_ops quic_ops = {
	mbedtls_quic_write_handshake_msg,
	mbedtls_quic_read_handshake_msg,
	mbedtls_quic_set_traffic_secrets,
	mbedtls_quic_notify_alert
};

#define TLSEXT_TYPE_quic_transport_parameters 57

static int
mbedtls_quic_ext_write_cb(mbedtls_ssl_context *ssl, unsigned int ext_type,
			  unsigned int context, unsigned char *buf,
			  size_t buf_len, size_t *out_len, void *custom_ctx)
{
	struct lws *wsi = (struct lws *)mbedtls_ssl_get_user_data_p(ssl);

	if (!wsi || !wsi->tls.quic_tp_send) {
		lwsl_notice("%s: wsi %p, quic_tp_send %p, returning 0 len\n", __func__, wsi, wsi ? wsi->tls.quic_tp_send : NULL);
		*out_len = 0;
		return 0;
	}

	if (wsi->tls.quic_tp_send_len > buf_len) {
		lwsl_notice("%s: buf_len %d too small for %d\n", __func__, (int)buf_len, (int)wsi->tls.quic_tp_send_len);
		return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
	}

	memcpy(buf, wsi->tls.quic_tp_send, wsi->tls.quic_tp_send_len);
	*out_len = wsi->tls.quic_tp_send_len;

	lwsl_notice("%s: wrote %d bytes of ext\n", __func__, (int)*out_len);

	return 0;
}

static int
mbedtls_quic_ext_parse_cb(mbedtls_ssl_context *ssl, unsigned int ext_type,
			  unsigned int context, const unsigned char *buf,
			  size_t in_len, void *custom_ctx)
{
	struct lws *wsi = (struct lws *)mbedtls_ssl_get_user_data_p(ssl);

	if (!wsi) {
		lwsl_notice("%s: wsi is NULL\n", __func__);
		return 0;
	}

	if (wsi->tls.quic_tp_recv) {
		lws_free((void *)wsi->tls.quic_tp_recv);
		wsi->tls.quic_tp_recv = NULL;
	}

	wsi->tls.quic_tp_recv = lws_malloc(in_len, "quic_tp_recv");
	if (!wsi->tls.quic_tp_recv) {
		lwsl_notice("%s: alloc failed\n", __func__);
		return MBEDTLS_ERR_SSL_ALLOC_FAILED;
	}

	memcpy((void*)wsi->tls.quic_tp_recv, buf, in_len);
	wsi->tls.quic_tp_recv_len = in_len;

	lwsl_notice("%s: parsed %d bytes of ext\n", __func__, (int)in_len);

	return 0;
}

static void
mbedtls_quic_ext_free_cb(mbedtls_ssl_context *ssl, unsigned int ext_type,
			 unsigned int context, void *custom_ctx)
{
}

static mbedtls_ssl_custom_ext_t quic_ext = {
	TLSEXT_TYPE_quic_transport_parameters,
	MBEDTLS_SSL_EXT_CTX_CLIENT_HELLO | MBEDTLS_SSL_EXT_CTX_ENCRYPTED_EXTENSIONS,
	mbedtls_quic_ext_write_cb,
	mbedtls_quic_ext_parse_cb,
	mbedtls_quic_ext_free_cb,
	NULL,
	NULL
};

int
lws_tls_quic_init(struct lws *wsi, lws_tls_quic_secret_cb cb)
{
	mbedtls_ssl_context *msc;
	struct mbedtls_quic_buf *b;
	mbedtls_ssl_config *conf;

	if (!wsi->tls.ssl)
		return -1;

	msc = SSL_mbedtls_ssl_context_from_SSL(wsi->tls.ssl);
	if (!msc)
		return -1;

	conf = (mbedtls_ssl_config *)mbedtls_ssl_context_get_config(msc);
	if (conf) {
		mbedtls_ssl_conf_transport(conf, MBEDTLS_SSL_TRANSPORT_QUIC);
	}
	mbedtls_ssl_set_quic_transport_ops(msc, &quic_ops);
	mbedtls_ssl_set_quic_custom_ext(msc, &quic_ext);

	wsi->tls.quic_secret_cb = cb;

	mbedtls_ssl_set_user_data_p(msc, wsi);

	b = lws_zalloc(sizeof(*b), "quic bio");
	if (!b)
		return -1;

	wsi->tls.client_bio = (lws_tls_bio *)b;

	return 0;
}

int
lws_tls_quic_advance_handshake(struct lws *wsi, int level,
			       const uint8_t *in, size_t in_len,
			       uint8_t *out, size_t *out_len)
{
	int hs_n, err;
	struct mbedtls_quic_buf *b;

	if (!wsi->tls.client_bio)
		return -1;

	b = (struct mbedtls_quic_buf *)wsi->tls.client_bio;

	if (in && in_len > 0) {
		uint8_t *p = lws_realloc(b->rx_buf, b->rx_len + in_len, "quic rx");
		if (!p)
			return -1;
		b->rx_buf = p;
		memcpy(b->rx_buf + b->rx_len, in, in_len);
		b->rx_len += in_len;
	}

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
	uint8_t *p;

	if (wsi->tls.quic_tp_send)
		lws_free((void *)wsi->tls.quic_tp_send);

	p = lws_malloc(tp_len, "quic tp send");
	if (!p)
		return -1;

	memcpy(p, tp, tp_len);
	wsi->tls.quic_tp_send = p;
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

	if (lws_tls_quic_init(&wsi_client, (lws_tls_quic_secret_cb)1))
		goto fail;
	if (lws_tls_quic_init(&wsi_server, (lws_tls_quic_secret_cb)1))
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

fail:
	if (cctx) SSL_free(cctx);
	if (sctx) SSL_free(sctx);
	if (c_ssl_ctx) SSL_CTX_free(c_ssl_ctx);
	if (s_ssl_ctx) SSL_CTX_free(s_ssl_ctx);

	mbedtls_quic_bio_free(&wsi_client);
	mbedtls_quic_bio_free(&wsi_server);

	return 0;
}

int
lws_tls_quic_migrate_wsi(struct lws *old_wsi, struct lws *new_wsi)
{
	mbedtls_ssl_context *msc;

	if (!new_wsi || !new_wsi->tls.ssl)
		return -1;

	msc = SSL_mbedtls_ssl_context_from_SSL(new_wsi->tls.ssl);
	if (!msc)
		return -1;

	mbedtls_ssl_set_user_data_p(msc, new_wsi);

	return 0;
}

#else

int
lws_tls_quic_vhost_init(lws_tls_ctx *ctx)
{
	return 0;
}

int
lws_tls_quic_init(struct lws *wsi, lws_tls_quic_secret_cb cb)
{
	lwsl_err("%s: MbedTLS version too old for QUIC support\n", __func__);
	return -1;
}

int
lws_tls_quic_advance_handshake(struct lws *wsi, int level,
			       const uint8_t *in, size_t in_len,
			       uint8_t *out, size_t *out_len)
{
	return -1;
}

int
lws_tls_quic_set_transport_parameters(struct lws *wsi, const uint8_t *tp, size_t tp_len)
{
	return -1;
}

int
lws_tls_quic_get_transport_parameters(struct lws *wsi, const uint8_t **tp, size_t *tp_len)
{
	return -1;
}

int
lws_tls_quic_api_test(void)
{
	return 0;
}

int
lws_tls_quic_migrate_wsi(struct lws *old_wsi, struct lws *new_wsi)
{
	return -1;
}

#endif /* LWS_HAVE_mbedtls_ssl_set_quic_transport_ops */

#endif

void
mbedtls_quic_bio_free(struct lws *wsi)
{
	struct mbedtls_quic_buf *b;

	if (!wsi)
		return;

	if (wsi->tls.client_bio) {
		b = (struct mbedtls_quic_buf *)wsi->tls.client_bio;
		if (b->rx_buf)
			lws_free(b->rx_buf);
		lws_free(wsi->tls.client_bio);
		wsi->tls.client_bio = NULL;
	}

	if (wsi->tls.quic_tp_recv) {
		lws_free((void *)wsi->tls.quic_tp_recv);
		wsi->tls.quic_tp_recv = NULL;
	}

	if (wsi->tls.quic_tp_send) {
		lws_free((void *)wsi->tls.quic_tp_send);
		wsi->tls.quic_tp_send = NULL;
	}
}
