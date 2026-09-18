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
 *
 * Streaming syntax highlighting core
 */

#include "private-lib-core.h"
#include <string.h>

int
lws_hl_construct(lws_hl_ctx_t *ctx, const lws_hl_ops_t *lang,
		 lws_hl_token_cb cb, void *user)
{
	if (!ctx || !lang || !lang->parse || !lang->finish || !cb)
		return 1;

	memset(ctx, 0, sizeof(*ctx));
	ctx->ops	= lang;
	ctx->cb		= cb;
	ctx->user	= user;

	if (lang->construct && lang->construct(ctx))
		return 1;

	return 0;
}

lws_stateful_ret_t
lws_hl_parse(lws_hl_ctx_t *ctx, const uint8_t **buf, size_t *len)
{
	if (!ctx || !buf || !len)
		return LWS_SRET_FATAL;

	if (!*len)
		return LWS_SRET_OK;

	return ctx->ops->parse(ctx, buf, len);
}

lws_stateful_ret_t
lws_hl_finish(lws_hl_ctx_t *ctx)
{
	if (!ctx)
		return LWS_SRET_FATAL;

	return ctx->ops->finish(ctx);
}
