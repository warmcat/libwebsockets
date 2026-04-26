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

#if !defined(__LWS_TLS_BEARSSL_H__)
#define __LWS_TLS_BEARSSL_H__

#include <bearssl.h>

struct lws_tls_ctx {
	br_x509_trust_anchor *trust_anchors;
	size_t num_trust_anchors;

	/* Server specifics */
	br_x509_certificate *chain;
	size_t chain_len;
	br_rsa_private_key rsa_key;
	br_ec_private_key ec_key;
	int is_rsa;
	br_skey_decoder_context skc;
#if defined(LWS_WITH_TLS_SESSIONS)
	br_ssl_session_cache_lru lru;
	uint8_t *lru_buffer;
#endif
};

struct lws_tls_conn {
	union {
		br_ssl_client_context client;
		br_ssl_server_context server;
		br_ssl_engine_context engine;
	} u;

	br_x509_minimal_context x509_ctx;

	unsigned char iobuf_in[BR_SSL_BUFSIZE_BIDI];
	unsigned char iobuf_out[BR_SSL_BUFSIZE_BIDI];

	int is_client;
	char initialized;

	struct lws_x509_cert *peer_cert;
	br_x509_class x509_vtable;
	int capturing_peer_cert;

#if defined(LWS_WITH_TLS_JIT_TRUST)
	struct lws_x509_cert *temp_cert;
	struct lws *wsi;
#endif

	char *client_hostname;
	size_t pending_app_data_len;
	struct lws_tls_ctx *ctx;
	unsigned int tls_use_ssl;
};

typedef struct lws_tls_conn lws_tls_conn;
typedef struct lws_tls_ctx lws_tls_ctx;
typedef void lws_tls_bio;

struct lws_x509_cert {
	uint8_t *der;
	size_t der_len;
};
typedef struct lws_x509_cert lws_tls_x509;

int lws_bearssl_pump(struct lws *wsi);
void lws_bearssl_x509_wrap_conn(lws_tls_conn *conn);
int lws_tls_session_new_bearssl(struct lws *wsi);

#endif
