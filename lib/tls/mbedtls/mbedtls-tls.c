/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

void
lws_tls_err_describe_clear(void)
{
}

int
lws_context_init_ssl_library(struct lws_context *cx,
			     const struct lws_context_creation_info *info)
{

	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT))
		lwsl_info(" SSL disabled: no "
			  "LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT");

	return 0;
}

void
lws_context_deinit_ssl_library(struct lws_context *context)
{

}

/*
 * mbedtls only considers a memory buffer to be PEM if it is NUL-terminated
 * and the length passed in includes that NUL; otherwise it goes straight to
 * DER and a PEM buffer fails with MBEDTLS_ERR_X509_INVALID_FORMAT.  Callers
 * naturally hand us the strlen() of a PEM without the terminator, so if the
 * buffer parses as neither, retry it as a NUL-terminated copy.
 */

int
lws_mbedtls_x509_crt_parse_mem(mbedtls_x509_crt *crt, const void *mem,
			       size_t len)
{
	uint8_t *tmp;
	int n;

	if (!mem || !len)
		return MBEDTLS_ERR_X509_BAD_INPUT_DATA;

	n = mbedtls_x509_crt_parse(crt, mem, len);
	if (!n || !((const uint8_t *)mem)[len - 1])
		return n;

	tmp = lws_malloc(len + 1, __func__);
	if (!tmp)
		return n;

	memcpy(tmp, mem, len);
	tmp[len] = '\0';
	n = mbedtls_x509_crt_parse(crt, tmp, len + 1);
	lws_free(tmp);

	return n;
}

int
lws_mbedtls_pk_parse_key_mem(struct lws_context *cx, mbedtls_pk_context *key,
			     const void *mem, size_t len)
{
	uint8_t *tmp;
	int n;

	(void)cx;

#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000 && \
    !defined(LWS_HAVE_MBEDTLS_V4)
#define lws_mbedtls_pkpk(_k, _b, _l) \
	mbedtls_pk_parse_key(_k, _b, _l, NULL, 0, \
			     lws_gencrypto_mbedtls_rngf, cx)
#else
#define lws_mbedtls_pkpk(_k, _b, _l) \
	mbedtls_pk_parse_key(_k, _b, _l, NULL, 0)
#endif

	if (!mem || !len)
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

	n = lws_mbedtls_pkpk(key, mem, len);
	if (!n || !((const uint8_t *)mem)[len - 1])
		return n;

	tmp = lws_malloc(len + 1, __func__);
	if (!tmp)
		return n;

	memcpy(tmp, mem, len);
	tmp[len] = '\0';
	n = lws_mbedtls_pkpk(key, tmp, len + 1);
	lws_explicit_bzero(tmp, len + 1); /* it's private key material */
	lws_free(tmp);

	return n;

#undef lws_mbedtls_pkpk
}

#if defined(LWS_HAVE_mbedtls_ssl_conf_alpn_protocols)

/*
 * mbedtls_ssl_conf_alpn_protocols() stores the array of pointers we give it,
 * it does not copy anything... so the strings and the pointer array have to
 * live as long as the config does, and only the owner of that config may
 * write them.
 */

static int
lws_mbedtls_alpn_list(mbedtls_ssl_config *conf, char *strings, size_t strings_len,
		      const char **protocols, size_t protocols_len,
		      const char *alpn_comma)
{
	int count = 0, r;
	char *p, *start;

	lws_strncpy(strings, alpn_comma, strings_len);
	start = strings;

	while (count < (int)protocols_len - 1) {
		p = strchr(start, ',');
		if (p)
			*p = '\0';

		if (*start)
			protocols[count++] = start;

		if (!p)
			break;
		start = p + 1;
	}

	protocols[count] = NULL;

	if (!count)
		return 1;

	r = mbedtls_ssl_conf_alpn_protocols(conf, protocols);
	if (r) {
		lwsl_err("%s: mbedtls_ssl_conf_alpn_protocols: %d\n",
			 __func__, r);

		return 1;
	}

	lwsl_info("%s: set %d ALPN protocols (first: %s)\n", __func__, count,
		  protocols[0]);

	return 0;
}

void lws_mbedtls_set_alpn(struct lws_tls_ctx *ctx, const char *alpn_comma)
{
	/*
	 * the vhost may legitimately have no ctx, eg, it was created with
	 * LWS_SERVER_OPTION_IGNORE_MISSING_CERT and the cert has not turned
	 * up yet
	 */
	if (!ctx || !alpn_comma)
		return;

	lws_mbedtls_alpn_list(&ctx->conf, ctx->alpn_strings,
			      sizeof(ctx->alpn_strings), ctx->alpn_protocols,
			      LWS_ARRAY_SIZE(ctx->alpn_protocols), alpn_comma);
}

#if defined(LWS_WITH_CLIENT)
int
lws_mbedtls_conn_set_alpn(struct lws_tls_conn *conn, const char *alpn_comma)
{
	if (!conn || !conn->ctx || !alpn_comma)
		return 1;

	/*
	 * The ALPN list is per-connection, but the vhost's mbedtls_ssl_config
	 * is shared by every client connection on the vhost... writing the
	 * list into that would let one connection change what another one
	 * offers, and change what a completed connection reads back as the
	 * negotiated protocol (which selects the h1 / h2 / h3 role).
	 *
	 * mbedtls only ever reads ssl->conf, so give this connection a
	 * private copy of the config to hang its own list on.  It aliases the
	 * vhost config's contents by design and must never be freed with
	 * mbedtls_ssl_config_free().
	 */

	conn->conf = conn->ctx->conf;

	if (lws_mbedtls_alpn_list(&conn->conf, conn->alpn_strings,
				  sizeof(conn->alpn_strings),
				  conn->alpn_protocols,
				  LWS_ARRAY_SIZE(conn->alpn_protocols),
				  alpn_comma))
		return 1;

	conn->own_conf = 1;

	return 0;
}
#endif

#else
void lws_mbedtls_set_alpn(struct lws_tls_ctx *ctx, const char *alpn_comma)
{
	(void)ctx;
	(void)alpn_comma;
}
#if defined(LWS_WITH_CLIENT)
int
lws_mbedtls_conn_set_alpn(struct lws_tls_conn *conn, const char *alpn_comma)
{
	(void)conn;
	(void)alpn_comma;

	return 1;
}
#endif
#endif
