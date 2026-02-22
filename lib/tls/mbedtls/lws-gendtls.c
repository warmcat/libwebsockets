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

#if defined(LWS_WITH_MBEDTLS)
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl_cookie.h>
#elif defined(LWS_WITH_GNUTLS)
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#endif

/*
 * This is a minimal stub for mbedTLS support.
 * The user indicated OpenSSL is the primary target for now (implied by context),
 * but we must provide the file to satisfy the plan.
 * A full implementation requires ringbuffers for BIO callbacks.
 */


static int
lws_gendtls_mbedtls_bio_send(void *ctx, const unsigned char *buf, size_t len)
{
	struct lws_gendtls_ctx *gctx = (struct lws_gendtls_ctx *)ctx;

	if (lws_buflist_append_segment(&gctx->tx_head, (uint8_t *)buf, len) < 0)
		return MBEDTLS_ERR_SSL_INTERNAL_ERROR;

	return (int)len;
}

static int
lws_gendtls_mbedtls_bio_recv(void *ctx, unsigned char *buf, size_t len)
{
	struct lws_gendtls_ctx *gctx = (struct lws_gendtls_ctx *)ctx;
	const uint8_t *p;
	size_t avail;

	if (!gctx->rx_head)
		return MBEDTLS_ERR_SSL_WANT_READ;

	avail = lws_buflist_next_segment_len(&gctx->rx_head, (uint8_t **)&p);
	if (!avail)
		return MBEDTLS_ERR_SSL_WANT_READ;

	if (len > avail)
		len = avail;

	memcpy(buf, p, len);
	lws_buflist_use_segment(&gctx->rx_head, len);

	return (int)len;
}

static int
lws_gendtls_mbedtls_bio_recv_timeout(void *ctx, unsigned char *buf, size_t len,
				     uint32_t timeout)
{
	(void)timeout;
	return lws_gendtls_mbedtls_bio_recv(ctx, buf, len);
}

static void
lws_gendtls_mbedtls_set_timer(void *ctx, uint32_t int_ms, uint32_t fin_ms)
{
	struct lws_gendtls_ctx *gctx = (struct lws_gendtls_ctx *)ctx;

	gctx->timer_set_us = lws_now_usecs();
	gctx->timer_int_ms = int_ms;
	gctx->timer_fin_ms = fin_ms;
}

static int
lws_gendtls_mbedtls_get_timer(void *ctx)
{
	struct lws_gendtls_ctx *gctx = (struct lws_gendtls_ctx *)ctx;
	lws_usec_t now_us;
	uint32_t diff_ms;

	if (!gctx->timer_fin_ms)
		return -1; /* cancelled */

	now_us = lws_now_usecs();
	diff_ms = (uint32_t)((now_us - gctx->timer_set_us) / 1000);

	if (diff_ms >= gctx->timer_fin_ms)
		return 2;
	if (diff_ms >= gctx->timer_int_ms)
		return 1;

	return 0;
}

int
lws_gendtls_create(struct lws_gendtls_ctx *ctx,
		   const struct lws_gendtls_creation_info *info)
{
	struct lws_context *context = info->context;
	enum lws_gendtls_conn_mode mode = info->mode;
	unsigned int mtu = info->mtu ? info->mtu : 1400;
	int ret;

	(void)context;

	memset(ctx, 0, sizeof(*ctx));

	mbedtls_ssl_init(&ctx->ssl);
	mbedtls_ssl_config_init(&ctx->conf);
	mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
	mbedtls_entropy_init(&ctx->entropy);
	mbedtls_x509_crt_init(&ctx->cacert);
	mbedtls_pk_init(&ctx->pkey);
	mbedtls_ssl_cookie_init(&ctx->cookie_ctx);

	if (mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func,
				  &ctx->entropy, (const unsigned char *)"lws_gendtls", 11) != 0) {
		lwsl_err("mbedtls_ctr_drbg_seed failed\n");
		goto bail;
	}

	if ((ret = mbedtls_ssl_config_defaults(&ctx->conf,
					(mode == LWS_GENDTLS_MODE_SERVER) ?
						MBEDTLS_SSL_IS_SERVER :
						MBEDTLS_SSL_IS_CLIENT,
					MBEDTLS_SSL_TRANSPORT_DATAGRAM,
					MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		lwsl_err("mbedtls_ssl_config_defaults failed: -0x%x\n", -ret);
		goto bail;
	}

	if (mode == LWS_GENDTLS_MODE_SERVER) {
		if ((ret = mbedtls_ssl_cookie_setup(&ctx->cookie_ctx,
						    mbedtls_ctr_drbg_random,
						    &ctx->ctr_drbg)) != 0) {
			lwsl_err("mbedtls_ssl_cookie_setup failed: -0x%x\n", -ret);
			goto bail;
		}

		mbedtls_ssl_conf_dtls_cookies(&ctx->conf,
					      mbedtls_ssl_cookie_write,
					      mbedtls_ssl_cookie_check,
					      &ctx->cookie_ctx);
	}

	mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_NONE);

	mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);

	if ((ret = mbedtls_ssl_setup(&ctx->ssl, &ctx->conf)) != 0) {
		lwsl_err("mbedtls_ssl_setup failed: -0x%x\n", -ret);
		goto bail;
	}

	if (mode == LWS_GENDTLS_MODE_SERVER) {
		/* Mandatory for DTLS cookies to have some client ID */
		mbedtls_ssl_set_client_transport_id(&ctx->ssl,
						    (const unsigned char *)&ctx,
						    sizeof(ctx));
	}

#if defined(MBEDTLS_SSL_DTLS_SRTP)
	if (info->use_srtp) {
		int n = 0;
		if (strstr(info->use_srtp, "SRTP_AES128_CM_SHA1_80"))
			ctx->srtp_profiles[n++] = MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80;
		if (strstr(info->use_srtp, "SRTP_AES128_CM_SHA1_32"))
			ctx->srtp_profiles[n++] = MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_32;
		if (strstr(info->use_srtp, "SRTP_NULL_HMAC_SHA1_80"))
			ctx->srtp_profiles[n++] = MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_80;
		if (strstr(info->use_srtp, "SRTP_NULL_HMAC_SHA1_32"))
			ctx->srtp_profiles[n++] = MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_32;

		ctx->srtp_profiles[n] = MBEDTLS_TLS_SRTP_UNSET;

		if (n) {
			mbedtls_ssl_conf_dtls_srtp_protection_profiles(&ctx->conf, ctx->srtp_profiles);
		}
	}
#endif

	mbedtls_ssl_set_bio(&ctx->ssl, ctx,
			    lws_gendtls_mbedtls_bio_send,
			    lws_gendtls_mbedtls_bio_recv,
			    lws_gendtls_mbedtls_bio_recv_timeout);

	mbedtls_ssl_set_mtu(&ctx->ssl, (uint16_t)mtu);

	mbedtls_ssl_set_timer_cb(&ctx->ssl, ctx,
				 lws_gendtls_mbedtls_set_timer,
				 lws_gendtls_mbedtls_get_timer);



	return 0;

bail:
	lws_gendtls_destroy(ctx);
	return -1;
}

int
lws_gendtls_handshake_done(struct lws_gendtls_ctx *ctx)
{
	return mbedtls_ssl_is_handshake_over(&ctx->ssl);
}

void
lws_gendtls_destroy(struct lws_gendtls_ctx *ctx)
{
	mbedtls_ssl_free(&ctx->ssl);
	mbedtls_ssl_config_free(&ctx->conf);
	mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
	mbedtls_entropy_free(&ctx->entropy);
	mbedtls_x509_crt_free(&ctx->cacert);
	mbedtls_pk_free(&ctx->pkey);
	mbedtls_ssl_cookie_free(&ctx->cookie_ctx);

	lws_buflist_destroy_all_segments(&ctx->rx_head);
	lws_buflist_destroy_all_segments(&ctx->tx_head);
}

int
lws_gendtls_set_cert_mem(struct lws_gendtls_ctx *ctx, const uint8_t *cert, size_t len)
{
	int ret;
	if ((ret = mbedtls_x509_crt_parse(&ctx->cacert, cert, len)) != 0) {
		printf("mbedtls_x509_crt_parse failed: -0x%x\n", -ret);
		return -1;
	}

	mbedtls_ssl_conf_ca_chain(&ctx->conf, &ctx->cacert, NULL);
	return 0;
}

int
lws_gendtls_set_key_mem(struct lws_gendtls_ctx *ctx, const uint8_t *key, size_t len)
{
	int ret;

	if ((ret = mbedtls_pk_parse_key(&ctx->pkey, (const unsigned char *)key, len,
				 NULL, 0,
				 mbedtls_ctr_drbg_random, &ctx->ctr_drbg)) != 0) {
		printf("mbedtls_pk_parse_key failed: -0x%x\n", -ret);
		return -1;
	}

	if ((ret = mbedtls_ssl_conf_own_cert(&ctx->conf, &ctx->cacert, &ctx->pkey)) != 0) {
		printf("mbedtls_ssl_conf_own_cert failed: -0x%x\n", -ret);
		return -1;
	}

	return 0;
}

int
lws_gendtls_put_rx(struct lws_gendtls_ctx *ctx, const uint8_t *in, size_t len)
{
	if (lws_buflist_append_segment(&ctx->rx_head, in, len) < 0)
		return -1;
	return 0;
}

int
lws_gendtls_get_rx(struct lws_gendtls_ctx *ctx, uint8_t *out, size_t max_len)
{
	int ret = mbedtls_ssl_read(&ctx->ssl, out, max_len);

	if (ret > 0)
		return ret;

	if (ret < 0) {
		if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
		    ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
		    ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED)
			return 0;

		lwsl_err("mbedtls_ssl_read failed: -0x%x\n", -ret);
		return -1;
	}

	if (ret == 0) /* EOF */
		return -1;

	return -1;
}

int
lws_gendtls_put_tx(struct lws_gendtls_ctx *ctx, const uint8_t *in, size_t len)
{
	int ret;

	while (len) {
		ret = mbedtls_ssl_write(&ctx->ssl, in, len);
		if (ret > 0) {
			in += ret;
			len -= (size_t)ret;
			continue;
		}

		if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
			return 0;

		return -1;
	}

	return 0;
}

int
lws_gendtls_get_tx(struct lws_gendtls_ctx *ctx, uint8_t *out, size_t max_len)
{
	size_t avail;
	const uint8_t *p;

	if (!ctx->tx_head) {
		/* Drive the handshake state machine if needed, even if no app data written */
		if (!lws_gendtls_handshake_done(ctx)) {
			int ret = mbedtls_ssl_handshake(&ctx->ssl);
			if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
				mbedtls_ssl_session_reset(&ctx->ssl);
				mbedtls_ssl_set_client_transport_id(&ctx->ssl, (const unsigned char *)"dummy", 5);
			} else if (ret != 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
				lwsl_err("mbedtls_ssl_handshake failed: -0x%x\n", -ret);
		}
	}

	if (!ctx->tx_head)
		return 0;

	avail = lws_buflist_next_segment_len(&ctx->tx_head, (uint8_t **)&p);
	if (max_len > avail)
		max_len = avail;

	memcpy(out, p, max_len);
	lws_buflist_use_segment(&ctx->tx_head, max_len);

	return (int)max_len;
}

int
lws_gendtls_export_keying_material(struct lws_gendtls_ctx *ctx, const char *label,
				   size_t label_len, const uint8_t *context,
				   size_t context_len, uint8_t *out, size_t out_len)
{
	int use_context = (context != NULL);

	if (mbedtls_ssl_export_keying_material(&ctx->ssl, out, out_len,
					       label, label_len,
					       context, context_len,
					       use_context))
		return -1;

	return 0;
}

int
lws_gendtls_is_clean(struct lws_gendtls_ctx *ctx)
{
	if (ctx->tx_head || ctx->rx_head)
		return 0;

	return 1;
}

const char *
lws_gendtls_get_srtp_profile(struct lws_gendtls_ctx *ctx)
{
#if defined(MBEDTLS_SSL_DTLS_SRTP)
	mbedtls_ssl_srtp_profile profile = mbedtls_ssl_get_dtls_srtp_protection_profile(&ctx->ssl);

	switch (profile) {
	case MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80:
		return "SRTP_AES128_CM_SHA1_80";
	case MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_32:
		return "SRTP_AES128_CM_SHA1_32";
	case MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_80:
		return "SRTP_NULL_HMAC_SHA1_80";
	case MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_32:
		return "SRTP_NULL_HMAC_SHA1_32";
	default:
		return NULL;
	}
#else
	return NULL;
#endif
}
