/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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

int
lws_context_init_ssl_library(struct lws_context *cx,
			     const struct lws_context_creation_info *info)
{
	/* stub */
	return 0;
}

void
lws_context_deinit_ssl_library(struct lws_context *context)
{
	/* stub */
}

int
lws_tls_check_all_cert_lifetimes(struct lws_context *context)
{
	/* stub */
	return 0;
}

int
lws_tls_server_certs_load(struct lws_vhost *vhost, struct lws *wsi,
			  const char *cert, const char *private_key,
			  const char *mem_cert, size_t len_mem_cert,
			  const char *mem_privkey, size_t mem_privkey_len)
{
	/* stub */
	return 0;
}

enum lws_tls_extant
lws_tls_generic_cert_checks(struct lws_vhost *vhost, const char *cert,
			    const char *private_key)
{
	/* stub */
	return LWS_TLS_EXTANT_NO;
}

int
lws_context_init_server_ssl(const struct lws_context_creation_info *info,
			    struct lws_vhost *vhost)
{
	/* stub */
	return 0;
}

void
lws_tls_acme_sni_cert_destroy(struct lws_vhost *vhost)
{
	/* stub */
}

void
lws_ssl_destroy(struct lws_vhost *vhost)
{
	/* stub */
}

void
lws_ssl_SSL_CTX_destroy(struct lws_vhost *vhost)
{
	/* stub */
}

void
lws_ssl_context_destroy(struct lws_context *context)
{
	/* stub */
}

lws_tls_ctx *
lws_tls_ctx_from_wsi(struct lws *wsi)
{
	/* stub */
	return NULL;
}

int
lws_tls_client_create_vhost_context(struct lws_vhost *vh,
				    const struct lws_context_creation_info *info,
				    const char *cipher_list,
				    const char *ca_filepath,
				    const void *ca_mem,
				    unsigned int ca_mem_len,
				    const char *cert_filepath,
				    const void *cert_mem,
				    unsigned int cert_mem_len,
				    const char *private_key_filepath,
				    const void *key_mem,
				    unsigned int key_mem_len)
{
	/* stub */
	return 0;
}

int
lws_context_init_client_ssl(const struct lws_context_creation_info *info,
			    struct lws_vhost *vhost)
{
	/* stub */
	return 0;
}

void
lws_ssl_info_callback(const lws_tls_conn *ssl, int where, int ret)
{
	/* stub */
}

int
lws_tls_fake_POLLIN_for_buffered(struct lws_context_per_thread *pt)
{
	/* stub */
	return 0;
}

int
lws_tls_server_vhost_backend_init(const struct lws_context_creation_info *info,
				  struct lws_vhost *vhost, struct lws *wsi)
{
	/* stub */
	return 0;
}
