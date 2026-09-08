/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2025 Andy Green <andy@warmcat.com>
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
#include "private.h"

void
lws_tls_session_vh_destroy(struct lws_vhost *vh)
{
	/* TBD */
}

int
lws_tls_client_vhost_extra_cert_mem(struct lws_vhost *vh,
                const uint8_t *der, size_t der_len)
{
	struct lws_tls_schannel_ctx *ctx = vh->tls.ssl_client_ctx;

	if (!ctx)
		return 1;

	/*
	 * This is a CA the caller wants trusted (JIT trust, ca_mem, an SS
	 * policy's trust store), so it belongs in the pinned CA store that
	 * becomes the exclusive trust root, not in the "extra certs to build
	 * a chain out of" store
	 */

	return lws_tls_schannel_ca_add(ctx, der, der_len);
}


