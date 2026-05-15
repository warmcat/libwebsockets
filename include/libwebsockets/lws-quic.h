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

/** \defgroup quic QUIC Transport APIs
 * ##QUIC Transport APIs
 *
 * These APIs abstract the underlying TLS library to provide the memory BIO
 * and traffic secret extraction capabilities required for QUIC.
 */
///@{

enum lws_tls_quic_secret_type {
	LWS_TLS_QUIC_SECRET_CLIENT_EARLY,
	LWS_TLS_QUIC_SECRET_CLIENT_HANDSHAKE,
	LWS_TLS_QUIC_SECRET_SERVER_HANDSHAKE,
	LWS_TLS_QUIC_SECRET_CLIENT_APPLICATION,
	LWS_TLS_QUIC_SECRET_SERVER_APPLICATION,
};

/**
 * lws_tls_quic_secret_cb() - Callback for QUIC traffic secret derivation
 *
 * \param wsi: the wsi
 * \param type: the type of secret derived
 * \param secret: the raw secret bytes
 * \param secret_len: length of the secret
 *
 * This callback is fired by the underlying TLS library (OpenSSL, mbedTLS, etc)
 * when a new traffic secret is derived during the QUIC TLS 1.3 handshake.
 */
typedef int (*lws_tls_quic_secret_cb)(struct lws *wsi,
				      enum lws_tls_quic_secret_type type,
				      const uint8_t *secret, size_t secret_len);

/**
 * lws_tls_quic_init() - Initialize QUIC TLS state for a wsi
 *
 * \param wsi: the wsi
 * \param cb: the traffic secret callback
 *
 * Enables QUIC mode on the TLS connection.
 */
LWS_VISIBLE LWS_EXTERN int
lws_tls_quic_init(struct lws *wsi, lws_tls_quic_secret_cb cb);

/**
 * lws_tls_quic_advance_handshake() - Feed QUIC CRYPTO frame data to TLS
 *
 * \param wsi: the wsi
 * \param in: incoming CRYPTO frame payload (or NULL)
 * \param in_len: length of incoming data
 * \param out: buffer for outgoing CRYPTO frame payload
 * \param out_len: on entry, max size of out; on exit, bytes written
 *
 * Feeds TLS handshake bytes into the memory BIO and retrieves the output
 * to be sent in the next QUIC CRYPTO frame.
 */
LWS_VISIBLE LWS_EXTERN int
lws_tls_quic_advance_handshake(struct lws *wsi,
			       const uint8_t *in, size_t in_len,
			       uint8_t *out, size_t *out_len);

/**
 * lws_tls_quic_set_transport_parameters() - Set QUIC transport parameters extension
 *
 * \param wsi: the wsi
 * \param tp: the transport parameters payload
 * \param tp_len: length of the payload
 */
LWS_VISIBLE LWS_EXTERN int
lws_tls_quic_set_transport_parameters(struct lws *wsi, const uint8_t *tp, size_t tp_len);

/**
 * lws_tls_quic_get_transport_parameters() - Get peer's QUIC transport parameters
 *
 * \param wsi: the wsi
 * \param tp: pointer to receive the transport parameters payload
 * \param tp_len: pointer to receive the length
 */
LWS_VISIBLE LWS_EXTERN int
lws_tls_quic_get_transport_parameters(struct lws *wsi, const uint8_t **tp, size_t *tp_len);

/**
 * lws_tls_quic_api_test() - Internal API test for QUIC TLS 1.3 memory BIOs
 */
LWS_VISIBLE LWS_EXTERN int
lws_tls_quic_api_test(void);

///@}
