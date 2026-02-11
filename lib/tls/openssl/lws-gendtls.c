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
	if (where & SSL_CB_ALERT)
		lwsl_notice("SSL_CB_ALERT: %s: %s: %s\n",
			    where & SSL_CB_READ ? "read" : "write",
			    SSL_alert_type_string_long(ret),
			    SSL_alert_desc_string_long(ret));
	else if (where & SSL_CB_LOOP)
		lwsl_debug("SSL_CB_LOOP: %s\n", SSL_state_string_long(ssl));
	else if (where & SSL_CB_HANDSHAKE_DONE)
		lwsl_notice("SSL_CB_HANDSHAKE_DONE: %s\n", SSL_state_string_long(ssl));
}

int
lws_gendtls_create(struct lws_gendtls_ctx *ctx,
		   const struct lws_gendtls_creation_info *info)
{
	enum lws_gendtls_conn_mode mode = info->mode;
	unsigned int mtu = info->mtu ? info->mtu : 1400;
	unsigned int timeout_ms = info->timeout_ms ? info->timeout_ms : 1000;
	SSL_CTX *ssl_ctx;
	BIO *rbio, *wbio;

	(void)timeout_ms;


	/* Create DTLS context */
	ssl_ctx = SSL_CTX_new(mode == LWS_GENDTLS_MODE_SERVER ?
			       DTLS_server_method() : DTLS_client_method());
	if (!ssl_ctx) {
		lwsl_err("%s: SSL_CTX_new failed\n", __func__);
		return -1;
	}

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

	SSL_set_options((SSL *)ctx->ssl, SSL_OP_NO_QUERY_MTU);
	DTLS_set_link_mtu((SSL *)ctx->ssl, (long)mtu);
	lwsl_notice("%s: DTLS MTU set to %u (OP_NO_QUERY_MTU set)\n", __func__, mtu);

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

int
lws_gendtls_get_rx(struct lws_gendtls_ctx *ctx, uint8_t *out, size_t max_len)
{
	SSL *ssl = (SSL *)ctx->ssl;
	int n;

	if (max_len > INT_MAX)
		max_len = INT_MAX;

	n = SSL_read(ssl, out, (int)max_len);
	if (n <= 0) {
		int err = SSL_get_error(ssl, n);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
			return 0; /* No data available yet */
		lwsl_notice("%s: SSL_read error %d (%s)\n", __func__, err, ERR_error_string(ERR_get_error(), NULL));
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
