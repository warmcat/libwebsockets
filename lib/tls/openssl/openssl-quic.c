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

#if defined(LWS_ROLE_QUIC) && defined(LWS_WITH_TLS) && !defined(LWS_WITH_MBEDTLS) && !defined(LWS_WITH_SCHANNEL)

#if defined(LWS_WITH_BORINGSSL) || defined(LWS_WITH_AWSLC) || defined(LWS_WITH_AWSLC) || defined(USE_WOLFSSL) || defined(LIBRESSL_VERSION_NUMBER)
#define LWS_HAVE_BORINGSSL_QUIC_API
#endif

#if defined(LWS_HAVE_BORINGSSL_QUIC_API)

#if defined(USE_WOLFSSL)

static int
set_encryption_secrets(WOLFSSL *ssl, enum wolfssl_encryption_level_t level,
                       const uint8_t *read_secret,
                       const uint8_t *write_secret,
                       size_t secret_len)
{
	struct lws *wsi = (struct lws *)SSL_get_app_data((SSL *)ssl);
	enum lws_tls_quic_secret_type rt, wt;

	if (!wsi)
		return 1;

	switch (level) {
	case wolfssl_encryption_early_data:
		rt = LWS_TLS_QUIC_SECRET_CLIENT_EARLY;
		wt = LWS_TLS_QUIC_SECRET_CLIENT_EARLY;
		break;
	case wolfssl_encryption_handshake:
		rt = lwsi_role_client(wsi) ? LWS_TLS_QUIC_SECRET_SERVER_HANDSHAKE : LWS_TLS_QUIC_SECRET_CLIENT_HANDSHAKE;
		wt = lwsi_role_client(wsi) ? LWS_TLS_QUIC_SECRET_CLIENT_HANDSHAKE : LWS_TLS_QUIC_SECRET_SERVER_HANDSHAKE;
		break;
	case wolfssl_encryption_application:
		rt = lwsi_role_client(wsi) ? LWS_TLS_QUIC_SECRET_SERVER_APPLICATION : LWS_TLS_QUIC_SECRET_CLIENT_APPLICATION;
		wt = lwsi_role_client(wsi) ? LWS_TLS_QUIC_SECRET_CLIENT_APPLICATION : LWS_TLS_QUIC_SECRET_SERVER_APPLICATION;
		break;
	default:
		return 1;
	}

	if (read_secret && wsi->tls.quic_secret_cb)
		wsi->tls.quic_secret_cb(wsi, rt, read_secret, secret_len);

	if (write_secret && wsi->tls.quic_secret_cb)
		wsi->tls.quic_secret_cb(wsi, wt, write_secret, secret_len);

	return 1;
}

static int
test_secret_cb(struct lws *wsi, enum lws_tls_quic_secret_type type,
	       const uint8_t *secret, size_t secret_len);

static int
add_handshake_data(WOLFSSL *ssl, enum wolfssl_encryption_level_t level,
		   const uint8_t *data, size_t len)
{
	struct lws *wsi = (struct lws *)SSL_get_app_data((SSL *)ssl);
	int lws_level;

	if (!wsi)
		return 1;

	switch (level) {
	case wolfssl_encryption_initial: lws_level = 0; break;
	case wolfssl_encryption_early_data: lws_level = 1; break;
	case wolfssl_encryption_handshake: lws_level = 2; break;
	case wolfssl_encryption_application: lws_level = 3; break;
	default: return 0;
	}

	if (wsi->tls.quic_secret_cb == test_secret_cb) {
		uint8_t *out = (uint8_t *)wsi->tls.quic_tp_send;
		size_t written = (size_t)(uintptr_t)wsi->tls.quic_tp_recv;
		size_t capacity = wsi->tls.quic_tp_recv_len;

		if (out && written + 3 + len <= capacity) {
			out[written] = (uint8_t)level;
			out[written + 1] = (uint8_t)((len >> 8) & 0xff);
			out[written + 2] = (uint8_t)(len & 0xff);
			memcpy(out + written + 3, data, len);
			wsi->tls.quic_tp_recv = (uint8_t *)(uintptr_t)(written + 3 + len);
		}
		return 1;
	}

	lws_tls_quic_tx_crypto_cb(wsi, lws_level, data, len);

	return 1;
}

static int
flush_flight(WOLFSSL *ssl)
{
	return 1;
}

static int
send_alert(WOLFSSL *ssl, enum wolfssl_encryption_level_t level, uint8_t alert)
{
	struct lws *wsi = (struct lws *)SSL_get_app_data((SSL *)ssl);
	if (wsi)
		wsi->tls.quic_alert = alert;
	return 1;
}

static const WOLFSSL_QUIC_METHOD quic_method = {
	set_encryption_secrets,
	add_handshake_data,
	flush_flight,
	send_alert,
};

#else /* BoringSSL / AWS-LC */

static int
set_read_secret(SSL *ssl, enum ssl_encryption_level_t level,
		const SSL_CIPHER *cipher, const uint8_t *secret,
		size_t secret_len)
{
	struct lws *wsi = (struct lws *)SSL_get_app_data(ssl);
	enum lws_tls_quic_secret_type t;

	if (!wsi)
		return 1;

	switch (level) {
	case ssl_encryption_early_data:
		t = LWS_TLS_QUIC_SECRET_CLIENT_EARLY;
		break;
	case ssl_encryption_handshake:
		t = lwsi_role_client(wsi) ? LWS_TLS_QUIC_SECRET_SERVER_HANDSHAKE : LWS_TLS_QUIC_SECRET_CLIENT_HANDSHAKE;
		break;
	case ssl_encryption_application:
		t = lwsi_role_client(wsi) ? LWS_TLS_QUIC_SECRET_SERVER_APPLICATION : LWS_TLS_QUIC_SECRET_CLIENT_APPLICATION;
		break;
	default:
		return 1;
	}

	if (wsi->tls.quic_secret_cb)
		wsi->tls.quic_secret_cb(wsi, t, secret, secret_len);

	return 1;
}

static int
set_write_secret(SSL *ssl, enum ssl_encryption_level_t level,
		 const SSL_CIPHER *cipher, const uint8_t *secret,
		 size_t secret_len)
{
	struct lws *wsi = (struct lws *)SSL_get_app_data(ssl);
	enum lws_tls_quic_secret_type t;

	if (!wsi)
		return 1;

	switch (level) {
	case ssl_encryption_early_data:
		t = LWS_TLS_QUIC_SECRET_CLIENT_EARLY;
		break;
	case ssl_encryption_handshake:
		t = lwsi_role_client(wsi) ? LWS_TLS_QUIC_SECRET_CLIENT_HANDSHAKE : LWS_TLS_QUIC_SECRET_SERVER_HANDSHAKE;
		break;
	case ssl_encryption_application:
		t = lwsi_role_client(wsi) ? LWS_TLS_QUIC_SECRET_CLIENT_APPLICATION : LWS_TLS_QUIC_SECRET_SERVER_APPLICATION;
		break;
	default:
		return 1;
	}

	if (wsi->tls.quic_secret_cb)
		wsi->tls.quic_secret_cb(wsi, t, secret, secret_len);

	return 1;
}

static int
test_secret_cb(struct lws *wsi, enum lws_tls_quic_secret_type type,
	       const uint8_t *secret, size_t secret_len);

static int
add_handshake_data(SSL *ssl, enum ssl_encryption_level_t level,
		   const uint8_t *data, size_t len)
{
	struct lws *wsi = (struct lws *)SSL_get_app_data(ssl);
	int lws_level;

	if (!wsi)
		return 1;

	switch (level) {
	case ssl_encryption_initial: lws_level = 0; break;
	case ssl_encryption_early_data: lws_level = 1; break;
	case ssl_encryption_handshake: lws_level = 2; break;
	case ssl_encryption_application: lws_level = 3; break;
	default: return 0;
	}

	if (wsi->tls.quic_secret_cb == test_secret_cb) {
		uint8_t *out = (uint8_t *)wsi->tls.quic_tp_send;
		size_t written = (size_t)(uintptr_t)wsi->tls.quic_tp_recv;
		size_t capacity = wsi->tls.quic_tp_recv_len;

		if (out && written + 3 + len <= capacity) {
			out[written] = (uint8_t)level;
			out[written + 1] = (uint8_t)((len >> 8) & 0xff);
			out[written + 2] = (uint8_t)(len & 0xff);
			memcpy(out + written + 3, data, len);
			wsi->tls.quic_tp_recv = (uint8_t *)(uintptr_t)(written + 3 + len);
		}
		return 1;
	}

	lws_tls_quic_tx_crypto_cb(wsi, lws_level, data, len);

	return 1;
}

static int
flush_flight(SSL *ssl)
{
	return 1;
}

static int
send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert)
{
	struct lws *wsi = (struct lws *)SSL_get_app_data(ssl);
	lwsl_err("send_alert called with alert %d, wsi %p\n", alert, wsi);
	if (wsi)
		wsi->tls.quic_alert = alert;
	return 1;
}

static const SSL_QUIC_METHOD quic_method = {
	.set_read_secret	= set_read_secret,
	.set_write_secret	= set_write_secret,
	.add_handshake_data	= add_handshake_data,
	.flush_flight		= flush_flight,
	.send_alert		= send_alert,
};

#endif /* USE_WOLFSSL */

int
lws_tls_quic_vhost_init(SSL_CTX *ctx)
{
	return 0;
}

int
lws_tls_quic_init(struct lws *wsi, lws_tls_quic_secret_cb cb)
{
	if (!wsi->tls.ssl)
		return -1;

	wsi->tls.quic_secret_cb = cb;
	SSL_set_app_data(wsi->tls.ssl, wsi);

#if defined(USE_WOLFSSL)
	wolfSSL_set_quic_method(wsi->tls.ssl, &quic_method);
#else
	SSL_set_quic_method(wsi->tls.ssl, &quic_method);
#endif

	if (lwsi_role_client(wsi)) {
		if (wsi->flags & LCCSCF_ALLOW_EARLY_DATA) {
#if !defined(USE_WOLFSSL) && !defined(LWS_WITH_MBEDTLS)
			SSL_set_early_data_enabled(wsi->tls.ssl, 1);
#endif
		}
		SSL_set_connect_state(wsi->tls.ssl);
	} else {
		if (wsi->a.vhost && (wsi->a.vhost->options & LWS_SERVER_OPTION_ALLOW_EARLY_DATA)) {
#if !defined(USE_WOLFSSL) && !defined(LWS_WITH_MBEDTLS)
			SSL_set_early_data_enabled(wsi->tls.ssl, 1);
#endif
		}
		SSL_set_accept_state(wsi->tls.ssl);
	}

	if (!wsi->tls.quic_tp_send) {
		const uint8_t dummy_tp[] = {
			0x04, 0x04, 0x00, 0x00, 0x00, 0x00
		};
#if defined(USE_WOLFSSL)
		wolfSSL_set_quic_transport_params(wsi->tls.ssl, dummy_tp, sizeof(dummy_tp));
#else
		SSL_set_quic_transport_params(wsi->tls.ssl, dummy_tp, sizeof(dummy_tp));
#endif
	} else {
#if defined(USE_WOLFSSL)
		wolfSSL_set_quic_transport_params(wsi->tls.ssl, wsi->tls.quic_tp_send, wsi->tls.quic_tp_send_len);
#else
		SSL_set_quic_transport_params(wsi->tls.ssl, wsi->tls.quic_tp_send, wsi->tls.quic_tp_send_len);
#endif
	}

	return 0;
}

int
lws_tls_quic_advance_handshake(struct lws *wsi, int level,
			       const uint8_t *in, size_t in_len,
			       uint8_t *out, size_t *out_len)
{
#if defined(USE_WOLFSSL)
	enum wolfssl_encryption_level_t bssl_level;
#else
	enum ssl_encryption_level_t bssl_level;
#endif
	int hs_n;

	if (wsi->tls.quic_secret_cb == test_secret_cb) {
		wsi->tls.quic_tp_send = out;
		wsi->tls.quic_tp_recv_len = *out_len;
		wsi->tls.quic_tp_recv = NULL;
	} else {
		if (out_len)
			*out_len = 0;
	}

	if (in && in_len) {
		if (wsi->tls.quic_secret_cb == test_secret_cb) {
			size_t offset = 0;
			int fed_any;
			do {
				fed_any = 0;
				size_t chunk_offset = offset;
				while (chunk_offset + 3 <= in_len) {
#if defined(USE_WOLFSSL)
					enum wolfssl_encryption_level_t chunk_level = (enum wolfssl_encryption_level_t)in[chunk_offset];
#else
					enum ssl_encryption_level_t chunk_level = (enum ssl_encryption_level_t)in[chunk_offset];
#endif
					size_t chunk_len = (size_t)((in[chunk_offset + 1] << 8) | in[chunk_offset + 2]);
					if (chunk_offset + 3 + chunk_len > in_len)
						break;

#if defined(USE_WOLFSSL)
					if (wolfSSL_provide_quic_data(wsi->tls.ssl, chunk_level, in + chunk_offset + 3, chunk_len) == 1) {
						wolfSSL_quic_do_handshake(wsi->tls.ssl);
#else
					if (SSL_provide_quic_data(wsi->tls.ssl, chunk_level, in + chunk_offset + 3, chunk_len) == 1) {
						SSL_do_handshake(wsi->tls.ssl);
#endif
						fed_any = 1;
						offset = chunk_offset + 3 + chunk_len;
						break;
					}
					chunk_offset += 3 + chunk_len;
				}
			} while (fed_any);
		} else {
			switch (level) {
#if defined(USE_WOLFSSL)
			case 0: bssl_level = wolfssl_encryption_initial; break;
			case 1: bssl_level = wolfssl_encryption_early_data; break;
			case 2: bssl_level = wolfssl_encryption_handshake; break;
			case 3: bssl_level = wolfssl_encryption_application; break;
#else
			case 0: bssl_level = ssl_encryption_initial; break;
			case 1: bssl_level = ssl_encryption_early_data; break;
			case 2: bssl_level = ssl_encryption_handshake; break;
			case 3: bssl_level = ssl_encryption_application; break;
#endif
			default: return -1;
			}

#if defined(USE_WOLFSSL)
			if (wolfSSL_provide_quic_data(wsi->tls.ssl, bssl_level, in, in_len) != 1)
#else
			if (SSL_provide_quic_data(wsi->tls.ssl, bssl_level, in, in_len) != 1)
#endif
				return -1;
		}
	}

#if defined(USE_WOLFSSL)
	hs_n = wolfSSL_quic_do_handshake(wsi->tls.ssl);
#else
	hs_n = SSL_do_handshake(wsi->tls.ssl);
#endif

	if (wsi->tls.quic_secret_cb == test_secret_cb) {
		*out_len = (size_t)(uintptr_t)wsi->tls.quic_tp_recv;
	}

	if (hs_n <= 0) {
		int err = SSL_get_error(wsi->tls.ssl, hs_n);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
			return 1;

		unsigned long e = ERR_get_error();
		lwsl_wsi_err(wsi, "SSL_do_handshake failed: hs_n %d, err %d, openssl err %lu (%s)",
			hs_n, err, e, ERR_error_string((uint32_t)e, NULL));
		ERR_print_errors_fp(stderr);
		return -1;
	}

	return 0;
}

int
lws_tls_quic_set_transport_parameters(struct lws *wsi, const uint8_t *tp, size_t tp_len)
{
	wsi->tls.quic_tp_send = tp;
	wsi->tls.quic_tp_send_len = tp_len;

	if (!wsi->tls.ssl)
		return 0;

#if defined(USE_WOLFSSL)
	if (wolfSSL_set_quic_transport_params(wsi->tls.ssl, tp, tp_len) != 1)
		return -1;
#else
	if (SSL_set_quic_transport_params(wsi->tls.ssl, tp, tp_len) != 1)
		return -1;
#endif
	return 0;
}

int
lws_tls_quic_get_transport_parameters(struct lws *wsi, const uint8_t **tp, size_t *tp_len)
{
#if defined(USE_WOLFSSL)
	wolfSSL_get_peer_quic_transport_params(wsi->tls.ssl, tp, tp_len);
#else
	SSL_get_peer_quic_transport_params(wsi->tls.ssl, tp, tp_len);
#endif
	if (!*tp || !*tp_len)
		return -1;
	return 0;
}

#else

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

	lwsl_wsi_notice(wsi, "openssl_quic_ext_parse_cb: ext_type %u, inlen %zu", ext_type, inlen);

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
		secret_hex = (char *)strchr(line + 28, ' ');
	} else if (!strncmp(line, "CLIENT_HANDSHAKE_TRAFFIC_SECRET ", 32)) {
		type = LWS_TLS_QUIC_SECRET_CLIENT_HANDSHAKE;
		secret_hex = (char *)strchr(line + 32, ' ');
	} else if (!strncmp(line, "SERVER_HANDSHAKE_TRAFFIC_SECRET ", 32)) {
		type = LWS_TLS_QUIC_SECRET_SERVER_HANDSHAKE;
		secret_hex = (char *)strchr(line + 32, ' ');
	} else if (!strncmp(line, "CLIENT_TRAFFIC_SECRET_0 ", 24)) {
		type = LWS_TLS_QUIC_SECRET_CLIENT_APPLICATION;
		secret_hex = (char *)strchr(line + 24, ' ');
	} else if (!strncmp(line, "SERVER_TRAFFIC_SECRET_0 ", 24)) {
		type = LWS_TLS_QUIC_SECRET_SERVER_APPLICATION;
		secret_hex = (char *)strchr(line + 24, ' ');
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

	if (lwsi_role_client(wsi)) {
		if (wsi->flags & LCCSCF_ALLOW_EARLY_DATA) {
#if !defined(USE_WOLFSSL) && !defined(LWS_WITH_MBEDTLS)
			SSL_set_early_data_enabled(wsi->tls.ssl, 1);
#endif
		}
		SSL_set_connect_state(wsi->tls.ssl);
	} else {
		if (wsi->a.vhost && (wsi->a.vhost->options & LWS_SERVER_OPTION_ALLOW_EARLY_DATA)) {
#if !defined(USE_WOLFSSL) && !defined(LWS_WITH_MBEDTLS)
			SSL_set_early_data_enabled(wsi->tls.ssl, 1);
#endif
		}
		SSL_set_accept_state(wsi->tls.ssl);
	}

	SSL_CTX_set_keylog_callback(ctx, openssl_quic_keylog_cb);

	return 0;
}

int
lws_tls_quic_advance_handshake(struct lws *wsi, int level,
			       const uint8_t *in, size_t in_len,
			       uint8_t *out, size_t *out_len)
{
	BIO *rbio = SSL_get_rbio(wsi->tls.ssl);
	BIO *wbio = SSL_get_wbio(wsi->tls.ssl);
	int hs_n;
	size_t written = 0;

	if (!rbio || !wbio)
		return -1;

	if (in && in_len)
		BIO_write(rbio, in, (int)in_len);
	lwsl_info("QUIC TLS: SSL_do_handshake starting (in_len=%d)\n", (int)in_len);
	hs_n = SSL_do_handshake(wsi->tls.ssl);
	lwsl_info("QUIC TLS: SSL_do_handshake returned %d\n", hs_n);

	if (out && out_len) {
		int read_n = BIO_read(wbio, out, (int)*out_len);
		if (read_n > 0)
			written = (size_t)read_n;
		*out_len = written;
		lwsl_info("QUIC TLS: BIO_read extracted %d bytes of TX data\n", (int)written);
	}

	if (hs_n <= 0) {
		int err = SSL_get_error(wsi->tls.ssl, hs_n);
		lwsl_info("QUIC TLS: SSL_get_error returned %d\n", err);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
			return 1; /* In progress */

		unsigned long e = ERR_get_error();
		lwsl_wsi_err(wsi, "SSL_do_handshake failed: hs_n %d, err %d, openssl err %lu (%s)",
			hs_n, err, e, ERR_error_string((uint32_t)e, NULL));
		ERR_print_errors_fp(stderr);
		return -1;
	}

	return 0; /* Complete */
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

#endif /* LWS_HAVE_BORINGSSL_QUIC_API */

static int test_secrets_extracted = 0;

static int
test_secret_cb(struct lws *wsi, enum lws_tls_quic_secret_type type,
	       const uint8_t *secret, size_t secret_len)
{
	lwsl_notice("%s: extracted type %d, len %d\n", __func__, type, (int)secret_len);
	test_secrets_extracted++;
	return 0;
}

#if defined(LWS_HAVE_BORINGSSL_QUIC_API)
static int
test_alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                    const unsigned char *in, unsigned int inlen, void *arg)
{
	*out = (const unsigned char *)"test";
	*outlen = 4;
	return SSL_TLSEXT_ERR_OK;
}
#endif

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
	wsi_client.wsistate = LWSIFR_CLIENT;
	memset(&wsi_server, 0, sizeof(wsi_server));
	wsi_server.wsistate = LWSIFR_SERVER;

	cctx = SSL_CTX_new(TLS_client_method());
	sctx = SSL_CTX_new(TLS_server_method());

	if (!cctx || !sctx)
		goto fail;

	SSL_CTX_set_min_proto_version(cctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(cctx, TLS1_3_VERSION);
	SSL_CTX_set_min_proto_version(sctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(sctx, TLS1_3_VERSION);

	SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);

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

#if defined(LWS_HAVE_BORINGSSL_QUIC_API)
	SSL_set_alpn_protos(wsi_client.tls.ssl, (const unsigned char *)"\x04test", 5);
	SSL_CTX_set_alpn_select_cb(sctx, test_alpn_select_cb, NULL);
#endif

	if (lws_tls_quic_init(&wsi_client, test_secret_cb))
		goto fail;
	if (lws_tls_quic_init(&wsi_server, test_secret_cb))
		goto fail;

	lws_tls_quic_set_transport_parameters(&wsi_client, ctp, sizeof(ctp));
	lws_tls_quic_set_transport_parameters(&wsi_server, stp, sizeof(stp));

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

int
lws_tls_quic_migrate_wsi(struct lws *old_wsi, struct lws *new_wsi)
{
	if (!new_wsi || !new_wsi->tls.ssl)
		return -1;

	SSL_set_app_data(new_wsi->tls.ssl, new_wsi);

	return 0;
}

#endif
