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
#include "private-lib-tls.h"
#include <errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/dtls.h>
#include <sys/time.h>
#include <unistd.h>

/* Custom push/pull functions to use memory buffers */

static ssize_t
lws_gendtls_gnutls_pull(gnutls_transport_ptr_t ptr, void *data, size_t len)
{
	struct lws_gendtls_ctx *ctx = (struct lws_gendtls_ctx *)ptr;
	struct lws_buflist *head = ctx->rx_head;
	size_t avail;
	const uint8_t *p;

	if (!head) {
		errno = EAGAIN;
		return -1;
	}

	avail = lws_buflist_next_segment_len(&head, (uint8_t **)&p);
	if (len > avail)
		len = avail;

	memcpy(data, p, len);
	lws_buflist_use_segment(&ctx->rx_head, len);

	return (ssize_t)len;
}

static time_t
lws_gendtls_gnutls_time_func(time_t *t)
{
	time_t now = time(NULL);

	if (t)
		*t = now;

	return now;
}

static int
lws_gendtls_gnutls_timeout(gnutls_transport_ptr_t ptr, unsigned int ms)
{
	struct lws_gendtls_ctx *ctx = (struct lws_gendtls_ctx *)ptr;

	return !!ctx->rx_head; /* 1 = Data available, 0 = timeout / no data */
}

static int
lws_gendtls_gnutls_errno(gnutls_transport_ptr_t ptr)
{
	return errno;
}


static ssize_t
lws_gendtls_gnutls_push(gnutls_transport_ptr_t ptr, const void *data, size_t len)
{
	struct lws_gendtls_ctx *ctx = (struct lws_gendtls_ctx *)ptr;

	if (lws_buflist_append_segment(&ctx->tx_head, data, len) < 0) {
		errno = ENOMEM; /* Revert to system errno */

		return -1;
	}

	return (ssize_t)len;
}

int
lws_gendtls_create(struct lws_gendtls_ctx *ctx,
		const struct lws_gendtls_creation_info *info)
{
	struct lws_context *context = info->context;
	enum lws_gendtls_conn_mode mode = info->mode;
	unsigned int mtu = info->mtu ? info->mtu : 1400;
	unsigned int timeout_ms = info->timeout_ms ? info->timeout_ms : 1000;
	unsigned int flags = GNUTLS_DATAGRAM | GNUTLS_NONBLOCK;
	int ret;

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;

	if (mode == LWS_GENDTLS_MODE_SERVER)
		flags |= GNUTLS_SERVER;
	else
		flags |= GNUTLS_CLIENT;

	ret = gnutls_init(&ctx->session, flags);
	if (ret != GNUTLS_E_SUCCESS) {
		lwsl_err("%s: gnutls_init failed: %s\n", __func__,
				gnutls_strerror(ret));
		return -1;
	}

	if (mode == LWS_GENDTLS_MODE_CLIENT)
		gnutls_server_name_set(ctx->session, GNUTLS_NAME_DNS, "localhost", 9);

	gnutls_dtls_set_mtu(ctx->session, mtu);

	/* Set default priorities */
	ret = gnutls_priority_set_direct(ctx->session, "NORMAL", NULL);
	if (ret != GNUTLS_E_SUCCESS) {
		lwsl_err("%s: gnutls_priority_set_direct failed\n", __func__);
		goto bail;
	}

#if defined(GNUTLS_SRTP_AES128_CM_HMAC_SHA1_80) /* SRTP is supported in GnuTLS >= 3.1.4 */
	if (info->use_srtp) {
		gnutls_srtp_profile_t profiles[4];
		int n = 0;

		if (strstr(info->use_srtp, "SRTP_AES128_CM_SHA1_80"))
			profiles[n++] = GNUTLS_SRTP_AES128_CM_HMAC_SHA1_80;
		if (strstr(info->use_srtp, "SRTP_AES128_CM_SHA1_32"))
			profiles[n++] = GNUTLS_SRTP_AES128_CM_HMAC_SHA1_32;
		if (strstr(info->use_srtp, "SRTP_NULL_HMAC_SHA1_80"))
			profiles[n++] = GNUTLS_SRTP_NULL_HMAC_SHA1_80;
		if (strstr(info->use_srtp, "SRTP_NULL_HMAC_SHA1_32"))
			profiles[n++] = GNUTLS_SRTP_NULL_HMAC_SHA1_32;

		if (n) {
			ret = gnutls_srtp_set_profile_direct(ctx->session, profiles, n);
			if (ret != GNUTLS_E_SUCCESS) {
				lwsl_err("%s: gnutls_srtp_set_profile_direct failed: %s\n",
					 __func__, gnutls_strerror(ret));
				goto bail;
			}
		}
	}
#endif

	/* Allocate credentials structure */
	ret = gnutls_certificate_allocate_credentials(&ctx->cred);
	if (ret < 0) {
		lwsl_err("%s: gnutls_certificate_allocate_credentials failed\n",
				__func__);
		goto bail;
	}

	if (gnutls_credentials_set(ctx->session, GNUTLS_CRD_CERTIFICATE,
				ctx->cred) < 0) {
		lwsl_err("%s: gnutls_credentials_set failed\n", __func__);
		goto bail;
	}

	if (mode == LWS_GENDTLS_MODE_SERVER) {
		ret = gnutls_key_generate(&ctx->cookie_key, GNUTLS_COOKIE_KEY_SIZE);
		if (ret < 0) {
			lwsl_err("%s: gnutls_key_generate failed\n", __func__);
			goto bail;
		}
	}

	/* Set custom transport callbacks */
	gnutls_global_set_time_function(lws_gendtls_gnutls_time_func);

	gnutls_transport_set_ptr(ctx->session, (gnutls_transport_ptr_t)ctx);

	gnutls_transport_set_push_function(ctx->session,
			lws_gendtls_gnutls_push);
	gnutls_transport_set_pull_function(ctx->session,
			lws_gendtls_gnutls_pull);
	gnutls_transport_set_pull_timeout_function(ctx->session,
			lws_gendtls_gnutls_timeout);
	gnutls_transport_set_errno_function(ctx->session,
			lws_gendtls_gnutls_errno);

	gnutls_dtls_set_timeouts(ctx->session, timeout_ms, 60000);

	return 0;

bail:
	if (ctx->cred)
		gnutls_certificate_free_credentials(ctx->cred);
	if (ctx->session)
		gnutls_deinit(ctx->session);

	return -1;
}

void
lws_gendtls_destroy(struct lws_gendtls_ctx *ctx)
{
	if (ctx->session) {
		lwsl_notice("%s: Destroying session %p\n", __func__, ctx->session);
		gnutls_bye(ctx->session, GNUTLS_SHUT_WR);
		gnutls_deinit(ctx->session);
	}
	if (ctx->cred)
		gnutls_certificate_free_credentials(ctx->cred);

	if (ctx->cookie_key.data)
		gnutls_free(ctx->cookie_key.data);

	lws_buflist_destroy_all_segments(&ctx->rx_head);
	lws_buflist_destroy_all_segments(&ctx->tx_head);
}

LWS_VISIBLE int
lws_gendtls_set_cert_mem(struct lws_gendtls_ctx *ctx, const uint8_t *cert, size_t len)
{
	/* Store certificate until key is available */

	if (ctx->cert_mem)
		lws_free(ctx->cert_mem);
	ctx->cert_mem = lws_malloc(len + 1, "gendtls_cert");
	if (!ctx->cert_mem)
		return -1;
	memcpy(ctx->cert_mem, cert, len);
	ctx->cert_mem[len] = '\0';
	ctx->cert_len = len + 1;

	/* If we have both, apply them */
	if (ctx->key_mem) {
		gnutls_datum_t c = { ctx->cert_mem, (unsigned int)ctx->cert_len - 1 };
		gnutls_datum_t k = { ctx->key_mem, (unsigned int)ctx->key_len - 1 };

		if (gnutls_certificate_set_x509_key_mem(ctx->cred, &c, &k, GNUTLS_X509_FMT_PEM) < 0) {
			lwsl_err("%s: failed to set cert/key\n", __func__);
			return -1;
		}
	}
	return 0;
}

LWS_VISIBLE int
lws_gendtls_set_key_mem(struct lws_gendtls_ctx *ctx, const uint8_t *key, size_t len)
{
	if (ctx->key_mem)
		lws_free(ctx->key_mem);

	ctx->key_mem = lws_malloc(len + 1, "gendtls_key");
	if (!ctx->key_mem)
		return -1;

	memcpy(ctx->key_mem, key, len);
	ctx->key_mem[len] = '\0';
	ctx->key_len = len + 1;

	/* If we have both, apply them */
	if (ctx->cert_mem) {
		gnutls_datum_t c = { ctx->cert_mem, (unsigned int)ctx->cert_len - 1 };
		gnutls_datum_t k = { ctx->key_mem, (unsigned int)ctx->key_len - 1 };

		if (gnutls_certificate_set_x509_key_mem(ctx->cred, &c, &k, GNUTLS_X509_FMT_PEM) < 0) {
			lwsl_err("%s: failed to set cert/key\n", __func__);
			return -1;
		}
	}
	return 0;
}

int
lws_gendtls_put_rx(struct lws_gendtls_ctx *ctx, const uint8_t *in, size_t len)
{
	/* Append data to the rx_head buflist, which pull() reads from */
	if (lws_buflist_append_segment(&ctx->rx_head, in, len) < 0)
		return -1;

	return 0;
}

int
lws_gendtls_get_rx(struct lws_gendtls_ctx *ctx, uint8_t *out, size_t max_len)
{
	/*
	 * GnuTLS handles cookies strictly outside the handshake state machine,
	 * so we must intercept the first ClientHello and issue HelloVerifyRequest
	 * manually via gnutls_dtls_cookie_verify / gnutls_dtls_cookie_send.
	 */
	if (!ctx->handshake_done && !ctx->cookie_read && ctx->cookie_key.data) {
		/* Peek the first datagram buffer to see if it's a ClientHello */
		size_t avail = lws_buflist_total_len(&ctx->rx_head);
		if (avail > 0) {
			uint8_t *flat_rx = lws_malloc(avail, "cookie_rx");
			if (!flat_rx) return -1;

			lws_buflist_linear_copy(&ctx->rx_head, 0, flat_rx, avail);

			gnutls_dtls_prestate_st prestate;
			memset(&prestate, 0, sizeof(prestate));

			/* Provide a dummy client IP as discriminator (since we don't have peer IP via info)
			   Using the ctx memory address allows multiplexing */
			void *client_data = (void *)&ctx;
			size_t client_data_size = sizeof(ctx);

			int ret = gnutls_dtls_cookie_verify(&ctx->cookie_key, client_data, client_data_size,
							    flat_rx, avail, &prestate);

			if (ret < 0) {
				/* Invalid or absent cookie, send HelloVerifyRequest */
				ret = gnutls_dtls_cookie_send(&ctx->cookie_key, client_data, client_data_size,
							      &prestate, (gnutls_transport_ptr_t)ctx,
							      lws_gendtls_gnutls_push);
				lws_free(flat_rx);
				/* Consume incoming packet so we can wait for response */
				lws_buflist_use_segment(&ctx->rx_head, avail);

				if (ret < 0) {
					lwsl_err("%s: gnutls_dtls_cookie_send failed: %s\n",
						 __func__, gnutls_strerror(ret));
					return -1;
				}
				/* Need to wait for next ClientHello */
				return 0;
			}

			/* Valid cookie! Setup session pre-state to accept ClientHello internally */
			gnutls_dtls_prestate_set(ctx->session, &prestate);
			ctx->cookie_read = 1;
			lws_free(flat_rx);
		}
	}

	/* If handshake is not complete, try to advance it */
	if (!ctx->handshake_done) {
		int ret = gnutls_handshake(ctx->session);
		if (ret < 0) {
			if (!gnutls_error_is_fatal(ret))
				return 0; /* Non-fatal, retry */

			lwsl_err("%s: Handshake failed: %s\n", __func__, gnutls_strerror(ret));

			return -1;
		}
		ctx->handshake_done = 1;
	}

	/* Try to read app data */
	ssize_t n = gnutls_record_recv(ctx->session, out, max_len);
	if (n < 0) {
		if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED)
			return 0;
		lwsl_err("%s: Recv failed: %s\n", __func__, gnutls_strerror((int)n));
		return -1;
	}

	return (int)n;
}

int
lws_gendtls_put_tx(struct lws_gendtls_ctx *ctx, const uint8_t *in, size_t len)
{
	/* Encrypts data and queues it to tx_head via push() */
	ssize_t n = gnutls_record_send(ctx->session, in, len);

	if (n < 0) {
		if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED)
			return 0; /* Retry / buffer full */
		return -1;
	}
	return 0;
}

int
lws_gendtls_get_tx(struct lws_gendtls_ctx *ctx, uint8_t *out, size_t max_len)
{
	/* Read from tx_head buflist where push() wrote encrypted data */
	if (!ctx->tx_head)
		return 0;

	size_t avail;
	const uint8_t *p;

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
	if (gnutls_prf_rfc5705(ctx->session, label_len, label,
				context_len, (const char *)context,
				out_len, (char *)out) < 0)
		return -1;

	return 0;
}

int
lws_gendtls_handshake_done(struct lws_gendtls_ctx *ctx)
{
	return ctx->handshake_done;
}

int
lws_gendtls_is_clean(struct lws_gendtls_ctx *ctx)
{
	return !(ctx->tx_head || ctx->rx_head || gnutls_record_check_pending(ctx->session));
}

const char *
lws_gendtls_get_srtp_profile(struct lws_gendtls_ctx *ctx)
{
#if defined(GNUTLS_SRTP_AES128_CM_HMAC_SHA1_80)
	gnutls_srtp_profile_t profile = 0;

	if (gnutls_srtp_get_profile(ctx->session, &profile) != GNUTLS_E_SUCCESS)
		return NULL;

	switch (profile) {
	case GNUTLS_SRTP_AES128_CM_HMAC_SHA1_80:
		return "SRTP_AES128_CM_SHA1_80";
	case GNUTLS_SRTP_AES128_CM_HMAC_SHA1_32:
		return "SRTP_AES128_CM_SHA1_32";
	case GNUTLS_SRTP_NULL_HMAC_SHA1_80:
		return "SRTP_NULL_HMAC_SHA1_80";
	case GNUTLS_SRTP_NULL_HMAC_SHA1_32:
		return "SRTP_NULL_HMAC_SHA1_32";
	default:
		return NULL;
	}
#else
	return NULL;
#endif
}
