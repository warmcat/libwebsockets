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

/*! \defgroup genericDTLS Generic DTLS
 * ## Generic DTLS related functions
 *
 * Lws provides generic DTLS functions that abstract the ones
 * provided by whatever tls library you are linking against.
 *
 * It lets you use the same code if you build against mbedtls or OpenSSL
 * for example.
 */
///@{

#if defined(LWS_WITH_DTLS)

#if defined(LWS_WITH_MBEDTLS)
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl_cookie.h>
#elif defined(LWS_WITH_GNUTLS)
#include <gnutls/gnutls.h>
#elif defined(LWS_WITH_SCHANNEL)
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#else /* OpenSSL */
#include <openssl/ssl.h>
#endif

struct lws_gendtls_ctx {
#if defined(LWS_WITH_MBEDTLS)
	mbedtls_ssl_context			ssl;
	mbedtls_ssl_config			conf;
	mbedtls_ctr_drbg_context		ctr_drbg;
	mbedtls_entropy_context			entropy;
	mbedtls_x509_crt			cacert;
	mbedtls_pk_context			pkey;
	mbedtls_ssl_cookie_ctx			cookie_ctx;
	struct lws_buflist			*rx_head;
	struct lws_buflist			*tx_head;
#elif defined(LWS_WITH_GNUTLS)
	gnutls_session_t			session;
	gnutls_certificate_credentials_t	cred;
	gnutls_datum_t				cookie_key;
	struct lws_buflist			*rx_head;
	struct lws_buflist			*tx_head;
	int					handshake_done;
	int					cookie_read;
	/* Temporary storage for certificates/keys until both are present */
	uint8_t					*cert_mem;
	size_t					cert_len;
	uint8_t					*key_mem;
	size_t					key_len;
	struct lws_context			*context;
#elif defined(LWS_WITH_SCHANNEL)
	CredHandle				cred;
	CtxtHandle				ctxt;
	struct lws_buflist			*rx_head;
	struct lws_buflist			*tx_head;
	struct lws_context			*context;
	int					mode;
	int					handshake_done;
	/* Windows handles */
	HCERTSTORE				store;
	PCCERT_CONTEXT				cert_ctxt;
	SCHANNEL_CRED				schannel_cred;
	int					cred_init;
	/* Temporary storage for certificates/keys until both are present */
	uint8_t					*cert_mem;
	size_t					cert_len;
	uint8_t					*key_mem;
	size_t					key_len;
#else /* OpenSSL */
	void					*ssl; /* SSL * */
	/* OpenSSL Bio mems are handled internally via SSL_set_bio */
#endif
};

enum lws_gendtls_conn_mode {
	LWS_GENDTLS_MODE_CLIENT,
	LWS_GENDTLS_MODE_SERVER
};

struct lws_gendtls_creation_info {
	struct lws_context			*context;
	enum lws_gendtls_conn_mode		mode;
	unsigned int				mtu;
	unsigned int				timeout_ms;
	const char				*use_srtp;
};

/** lws_gendtls_create() - Create gendtls context
 *
 * \param ctx: your struct lws_gendtls_ctx
 * \param info: creation info struct
 *
 * Creates a DTLS context.
 *
 * Returns 0 for OK or nonzero for error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_gendtls_create(struct lws_gendtls_ctx *ctx,
		   const struct lws_gendtls_creation_info *info);

/** lws_gendtls_destroy() - Destroy gendtls context
 *
 * \param ctx: your struct lws_gendtls_ctx
 *
 * Destroys any allocations related to \p ctx.
 */
LWS_VISIBLE LWS_EXTERN void
lws_gendtls_destroy(struct lws_gendtls_ctx *ctx);

/** lws_gendtls_set_cert_mem() - Set certificate from memory
 *
 * \param ctx: your struct lws_gendtls_ctx
 * \param cert: pointer to certificate data
 * \param len: length of certificate data
 *
 * Returns 0 for OK or nonzero for error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_gendtls_set_cert_mem(struct lws_gendtls_ctx *ctx, const uint8_t *cert, size_t len);

/** lws_gendtls_set_key_mem() - Set private key from memory
 *
 * \param ctx: your struct lws_gendtls_ctx
 * \param key: pointer to key data
 * \param len: length of key data
 *
 * Returns 0 for OK or nonzero for error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_gendtls_set_key_mem(struct lws_gendtls_ctx *ctx, const uint8_t *key, size_t len);

/** lws_gendtls_put_rx() - Ingest encrypted data from transport
 *
 * \param ctx: your struct lws_gendtls_ctx
 * \param in: pointer to encrypted data
 * \param len: length of encrypted data
 *
 * Returns 0 for OK or nonzero for error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_gendtls_put_rx(struct lws_gendtls_ctx *ctx, const uint8_t *in, size_t len);

/** lws_gendtls_get_rx() - Retrieve decrypted data for application
 *
 * \param ctx: your struct lws_gendtls_ctx
 * \param out: buffer to store decrypted data
 * \param max_len: maximum length of buffer
 *
 * Returns number of bytes read (>=0) or negative for error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_gendtls_get_rx(struct lws_gendtls_ctx *ctx, uint8_t *out, size_t max_len);

/** lws_gendtls_put_tx() - Ingest plaintext data from application
 *
 * \param ctx: your struct lws_gendtls_ctx
 * \param in: pointer to plaintext data
 * \param len: length of plaintext data
 *
 * Returns 0 for OK or nonzero for error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_gendtls_put_tx(struct lws_gendtls_ctx *ctx, const uint8_t *in, size_t len);

/** lws_gendtls_get_tx() - Retrieve encrypted data for transport
 *
 * \param ctx: your struct lws_gendtls_ctx
 * \param out: buffer to store encrypted data
 * \param max_len: maximum length of buffer
 *
 * Returns number of bytes read (>=0) or negative for error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_gendtls_get_tx(struct lws_gendtls_ctx *ctx, uint8_t *out, size_t max_len);

/** lws_gendtls_export_keying_material() - Export keying material (RFC 5705)
 *
 * \param ctx: your struct lws_gendtls_ctx
 * \param label: label string
 * \param label_len: length of label (excluding null terminator)
 * \param context: context value (optional)
 * \param context_len: length of context value
 * \param out: buffer to store exported keying material
 * \param out_len: length of keying material required
 *
 * Returns 0 for OK or nonzero for error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_gendtls_export_keying_material(struct lws_gendtls_ctx *ctx, const char *label,
				   size_t label_len, const uint8_t *context,
				   size_t context_len, uint8_t *out, size_t out_len);

/** lws_gendtls_handshake_done() - Check if handshake is completed
 *
 * \param ctx: your struct lws_gendtls_ctx
 *
 * Returns 1 if handshake is completed, 0 if not.
 */
LWS_VISIBLE LWS_EXTERN int
lws_gendtls_handshake_done(struct lws_gendtls_ctx *ctx);

/** lws_gendtls_get_srtp_profile() - Get negotiated SRTP profile
 *
 * \param ctx: your struct lws_gendtls_ctx
 *
 * Returns name of negotiated SRTP profile or NULL.
 */
LWS_VISIBLE LWS_EXTERN const char *
lws_gendtls_get_srtp_profile(struct lws_gendtls_ctx *ctx);

#endif /* LWS_WITH_DTLS */

///@}
