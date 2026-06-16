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
	lwsl_info(" Compiled with MbedTLS support");

	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT))
		lwsl_info(" SSL disabled: no "
			  "LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT");

	return 0;
}

void
lws_context_deinit_ssl_library(struct lws_context *context)
{

}

#if defined(LWS_HAVE_mbedtls_ssl_conf_alpn_protocols)
void lws_mbedtls_set_alpn(struct lws_tls_ctx *ctx, const char *alpn_comma)
{
	int count = 0;
	char *p, *start;

	if (!alpn_comma)
		return;

	lws_strncpy(ctx->alpn_strings, alpn_comma, sizeof(ctx->alpn_strings));
	start = ctx->alpn_strings;

	while (count < (int)LWS_ARRAY_SIZE(ctx->alpn_protocols) - 1) {
		p = strchr(start, ',');
		if (p)
			*p = '\0';

		if (*start)
			ctx->alpn_protocols[count++] = start;

		if (!p)
			break;
		start = p + 1;
	}

	ctx->alpn_protocols[count] = NULL;

	if (count) {
		int r = mbedtls_ssl_conf_alpn_protocols(&ctx->conf, ctx->alpn_protocols);
		lwsl_notice("%s: set %d ALPN protocols (first: %s), ret %d\n", __func__, count, ctx->alpn_protocols[0], r);
	}
}
#else
void lws_mbedtls_set_alpn(struct lws_tls_ctx *ctx, const char *alpn_comma)
{
}
#endif
