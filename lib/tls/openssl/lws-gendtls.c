/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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

#include <libwebsockets.h>

#include "private-lib-core.h"
#include "private-lib-tls-openssl.h"

static void
ssl_info_cb(const SSL *ssl, int where, int ret)
{
	/*
	 * Everything here is driven by an unauthenticated peer, so it must not
	 * be able to produce err- or notice-level log traffic on demand.
	 */
	if (where & SSL_CB_ALERT)
		lwsl_info("SSL_CB_ALERT: %s: %s: %s\n",
			  where & SSL_CB_READ ? "read" : "write",
			  SSL_alert_type_string_long(ret),
			  SSL_alert_desc_string_long(ret));
	else if (where & SSL_CB_LOOP)
		lwsl_debug("SSL_CB_LOOP: %s\n", SSL_state_string_long(ssl));
	else if (where & SSL_CB_HANDSHAKE_DONE)
		lwsl_info("SSL_CB_HANDSHAKE_DONE: %s\n",
			  SSL_state_string_long(ssl));
}

static int
lws_gendtls_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
	/*
	 * RFC 5763: a DTLS-SRTP peer certificate is self-signed by design, the
	 * trust anchor is the a=fingerprint from the signalling channel which
	 * the caller compares against the peer certificate once the handshake
	 * completes.  So we deliberately accept any chain here; the point of
	 * SSL_VERIFY_PEER is only to make the server ask for, and keep, a
	 * certificate for the caller to fingerprint.
	 */
	(void)preverify_ok;
	(void)x509_ctx;

	return 1;
}

int
lws_gendtls_create(struct lws_gendtls_ctx *ctx,
		   const struct lws_gendtls_creation_info *info)
{
	enum lws_gendtls_conn_mode mode = info->mode;
	unsigned int mtu = info->mtu ? info->mtu : 1400;
	SSL_CTX *ssl_ctx;
	BIO *rbio, *wbio;

	memset(ctx, 0, sizeof(*ctx));

	ctx->timeout_ms = info->timeout_ms ? info->timeout_ms :
					     LWS_GENDTLS_TIMEOUT_DEFAULT_MS;
	ctx->created_us = lws_now_usecs();

	/* Create DTLS context */
	ssl_ctx = SSL_CTX_new(mode == LWS_GENDTLS_MODE_SERVER ?
			       DTLS_server_method() : DTLS_client_method());
	if (!ssl_ctx) {
		lwsl_err("%s: SSL_CTX_new failed\n", __func__);
		return -1;
	}

	/*
	 * RFC 8827 6: DTLS 1.2 or later only.  DTLS 1.0 drags in the TLS
	 * 1.0-era CBC / SHA1 record layer and is a downgrade target.
	 */
	SSL_CTX_set_min_proto_version(ssl_ctx, DTLS1_2_VERSION);

	if (mode == LWS_GENDTLS_MODE_SERVER)
		/*
		 * As the DTLS server we must send a CertificateRequest, else
		 * the peer sends no certificate and there is nothing for the
		 * caller's a=fingerprint check to bind the media to.
		 */
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER,
				   lws_gendtls_verify_cb);

	/* We need to set the read ahead for DTLS to work with BIO pairs/mem */
	SSL_CTX_set_read_ahead(ssl_ctx, 1);

	if (info->use_srtp) {
		if (SSL_CTX_set_tlsext_use_srtp(ssl_ctx, info->use_srtp)) {
			lwsl_err("%s: SSL_CTX_set_tlsext_use_srtp failed\n", __func__);
			SSL_CTX_free(ssl_ctx);
			return -1;
		}
	}

	ctx->ssl = SSL_new(ssl_ctx);
	if (!ctx->ssl) {
		lwsl_err("%s: SSL_new failed\n", __func__);
		SSL_CTX_free(ssl_ctx);
		return -1;
	}

	/*
	 * RFC 8827 6.5 forbids renegotiation for WebRTC, and the caller's
	 * fingerprint check is a one-shot latch, so a renegotiation presenting
	 * a different certificate would never be rechecked.  It is also a cheap
	 * asymmetric CPU amplifier (one small datagram in, a signature and a
	 * certificate flight out).
	 */
	SSL_set_options((SSL *)ctx->ssl, SSL_OP_NO_QUERY_MTU
#if defined(SSL_OP_NO_RENEGOTIATION)
					 | SSL_OP_NO_RENEGOTIATION
#endif
			);
	DTLS_set_link_mtu((SSL *)ctx->ssl, (long)mtu);
	lwsl_info("%s: DTLS MTU set to %u (OP_NO_QUERY_MTU set)\n", __func__, mtu);

	/* Create memory BIOs for input/output */
	rbio = BIO_new(BIO_s_mem());
	wbio = BIO_new(BIO_s_mem());

	if (!rbio || !wbio) {
		lwsl_err("%s: BIO_new failed\n", __func__);
		if (rbio) BIO_free(rbio);
		if (wbio) BIO_free(wbio);
		SSL_free((SSL *)ctx->ssl);
		SSL_CTX_free(ssl_ctx);
		return -1;
	}

	BIO_set_mem_eof_return(rbio, -1);
	BIO_set_mem_eof_return(wbio, -1);

	SSL_set_bio((SSL *)ctx->ssl, rbio, wbio);

	/* We own the SSL object, which owns the BIOs and holds a ref to SSL_CTX */
    /* We can decrease the ref count on SSL_CTX so it gets freed when SSL is freed */
	SSL_CTX_free(ssl_ctx);

	if (mode == LWS_GENDTLS_MODE_CLIENT)
		SSL_set_connect_state((SSL *)ctx->ssl);
	else
		SSL_set_accept_state((SSL *)ctx->ssl);

	SSL_set_info_callback((SSL *)ctx->ssl, ssl_info_cb);

	return 0;
}

void
lws_gendtls_destroy(struct lws_gendtls_ctx *ctx)
{
	if (ctx->ssl) {
		SSL_free((SSL *)ctx->ssl);
		ctx->ssl = NULL;
	}
}

int
lws_gendtls_set_cert_mem(struct lws_gendtls_ctx *ctx, const uint8_t *cert, size_t len)
{
	SSL *ssl = (SSL *)ctx->ssl;
	BIO *bio = BIO_new_mem_buf(cert, (int)len);
	X509 *x509;
	int ret = -1;

	if (!bio)
		return -1;

	x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!x509) {
		/* Try DER */
		(void)BIO_reset(bio);
		x509 = d2i_X509_bio(bio, NULL);
	}
	if (!x509) {
		lwsl_err("%s: Failed to parse cert\n", __func__);
		goto bail;
	}

	if (SSL_use_certificate(ssl, x509) != 1) {
		lwsl_err("%s: Failed to use cert\n", __func__);
		goto bail;
	}

	ret = 0;
bail:
	if (x509)
		X509_free(x509);
	BIO_free(bio);
	return ret;
}

int
lws_gendtls_set_key_mem(struct lws_gendtls_ctx *ctx, const uint8_t *key, size_t len)
{
	SSL *ssl = (SSL *)ctx->ssl;
	BIO *bio = BIO_new_mem_buf(key, (int)len);
	EVP_PKEY *pkey;
	int ret = -1;

	if (!bio)
		return -1;

	pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (!pkey) {
		/* Try DER */
		(void)BIO_reset(bio);
		pkey = d2i_PrivateKey_bio(bio, NULL);
	}
	if (!pkey) {
		lwsl_err("%s: Failed to parse key\n", __func__);
		goto bail;
	}

	if (SSL_use_PrivateKey(ssl, pkey) != 1) {
		lwsl_err("%s: Failed to use key\n", __func__);
		goto bail;
	}

	ret = 0;
bail:
	if (pkey)
		EVP_PKEY_free(pkey);
	BIO_free(bio);
	return ret;
}

int
lws_gendtls_put_rx(struct lws_gendtls_ctx *ctx, const uint8_t *in, size_t len)
{
	SSL *ssl = (SSL *)ctx->ssl;
	BIO *rbio = SSL_get_rbio(ssl);

	int n = BIO_write(rbio, in, (int)len);
	if (n <= 0)
		return -1;

	return 0;
}

/*
 * Both directions call this before they touch the SSL object.
 *
 * DTLS handshake flights are retransmitted by our own timer, so if nothing
 * calls DTLSv1_handle_timeout() a lost ServerHello / Certificate flight is
 * never resent.  OpenSSL keeps the deadline and the exponential backoff
 * itself and returns 0 if it has not expired, so it is safe to poll here; the
 * retransmitted flight lands in the wbio the caller is about to drain.
 *
 * It also enforces info->timeout_ms as the overall handshake deadline, so an
 * abandoned handshake becomes visible to the caller as an error rather than
 * sitting there until the caller's own lifetime ends.
 *
 * Returns 0 to continue, or -1 if the handshake must be abandoned.
 */

static int
lws_gendtls_check_timeout(struct lws_gendtls_ctx *ctx)
{
	SSL *ssl = (SSL *)ctx->ssl;

	if (ctx->failed)
		return -1;

	if (SSL_is_init_finished(ssl))
		return 0;

	if ((lws_usec_t)(lws_now_usecs() - ctx->created_us) >
				(lws_usec_t)ctx->timeout_ms * LWS_US_PER_MS) {
		lwsl_info("%s: DTLS handshake incomplete after %ums\n",
			  __func__, ctx->timeout_ms);
		ctx->failed = 1;

		return -1;
	}

	(void)DTLSv1_handle_timeout(ssl);

	return 0;
}

int
lws_gendtls_get_rx(struct lws_gendtls_ctx *ctx, uint8_t *out, size_t max_len)
{
	SSL *ssl = (SSL *)ctx->ssl;
	int n;

	if (lws_gendtls_check_timeout(ctx))
		return -1;

	if (max_len > INT_MAX)
		max_len = INT_MAX;

	n = SSL_read(ssl, out, (int)max_len);
	if (n <= 0) {
		int err = SSL_get_error(ssl, n);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
			return 0; /* No data available yet */
		/*
		 * Peer-driven: a garbage record or an alert must not be able to
		 * generate notice-level log traffic on demand.
		 */
		lwsl_info("%s: SSL_read error %d (%s)\n", __func__, err,
			  ERR_error_string(LWS_TLS_ERR_CAST(ERR_get_error()),
					   NULL));
		return -1;
	}

	return n;
}

int
lws_gendtls_put_tx(struct lws_gendtls_ctx *ctx, const uint8_t *in, size_t len)
{
	SSL *ssl = (SSL *)ctx->ssl;
	int n;

	if (len > INT_MAX)
		len = INT_MAX;

	n = SSL_write(ssl, in, (int)len);
	if (n <= 0) {
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            return 0; // Should retry
		return -1;
    }

	return 0;
}


int
lws_gendtls_get_tx(struct lws_gendtls_ctx *ctx, uint8_t *out, size_t max_len)
{
	SSL *ssl = (SSL *)ctx->ssl;
	BIO *wbio = SSL_get_wbio(ssl);
	int rlen;

	uint8_t *p;
	long avail;

	if (lws_gendtls_check_timeout(ctx))
		return -1;

	/* Check if there is enough for a DTLS record header */
	avail = BIO_get_mem_data(wbio, &p);
	if (avail < 13)
		return 0;

	/*
	 * Extract record length.  RTP/UDP needs record boundaries
	 * preserved, we must not bunch records into one sendto().
	 */
	rlen = (p[11] << 8) | p[12];
	if (rlen + 13 > (int)max_len) {
		lwsl_err("%s: Record %d too big for %zu\n", __func__, rlen + 13, max_len);
		return -1;
	}

	if (avail < rlen + 13)
		return 0;

	return BIO_read(wbio, out, rlen + 13);
}

int
lws_gendtls_export_keying_material(struct lws_gendtls_ctx *ctx, const char *label,
				   size_t label_len, const uint8_t *context,
				   size_t context_len, uint8_t *out, size_t out_len)
{
    SSL *ssl = (SSL *)ctx->ssl;
    if (SSL_export_keying_material(ssl, out, out_len, label, label_len,
                                   context, context_len, 0) != 1) {
        return -1;
    }
    return 0;
}

int
lws_gendtls_handshake_done(struct lws_gendtls_ctx *ctx)
{
    SSL *ssl = (SSL *)ctx->ssl;
    return SSL_is_init_finished(ssl);
}

const char *
lws_gendtls_get_srtp_profile(struct lws_gendtls_ctx *ctx)
{
	SSL *ssl = (SSL *)ctx->ssl;
	SRTP_PROTECTION_PROFILE *profile = SSL_get_selected_srtp_profile(ssl);

	return profile ? profile->name : NULL;
}

int
lws_gendtls_is_clean(struct lws_gendtls_ctx *ctx)
{
	SSL *ssl = (SSL *)ctx->ssl;
	BIO *rbio = SSL_get_rbio(ssl);
	BIO *wbio = SSL_get_wbio(ssl);

	if (BIO_ctrl_pending(rbio) || BIO_ctrl_pending(wbio) || SSL_pending(ssl))
		return 0;

	return 1;
}
