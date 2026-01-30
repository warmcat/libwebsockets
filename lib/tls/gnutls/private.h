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

#ifndef __LWS_TLS_GNUTLS_PRIVATE_H__
#define __LWS_TLS_GNUTLS_PRIVATE_H__

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

struct lws_tls_gnutls_ctx {
	gnutls_certificate_credentials_t creds;
	gnutls_priority_t priority;
};

/* Connection is just the session pointer itself to match SSL* return of lws_get_ssl */
typedef SSL lws_tls_conn;
typedef SSL_CTX lws_tls_ctx;
typedef BIO lws_tls_bio;
typedef X509 lws_tls_x509;

#endif
