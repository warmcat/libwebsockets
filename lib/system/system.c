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

#include <private-lib-core.h>

static const char *hex = "0123456789ABCDEF";

int
lws_system_get_info(struct lws_context *context, lws_system_item_t item,
		    lws_system_arg_t *arg)
{
	if (!context->system_ops || !context->system_ops->get_info)
		return 1;

	return context->system_ops->get_info(item, arg);
}

const lws_system_ops_t *
lws_system_get_ops(struct lws_context *context)
{
	return context->system_ops;
}

int
lws_system_get_auth(struct lws_context *context, int idx, uint8_t *buf, size_t buflen, int flags)
{
	size_t bl = buflen;
	uint8_t *p, b;
	int n;

	if (!context->system_ops || !context->system_ops->auth) {
		lwsl_err("%s: add auth system op\n", __func__);
		return -1;
	}

	if (context->system_ops->auth(idx, buf, &buflen, 0)) {
		lwsl_err("%s: auth get failed\n", __func__);
		return -1;
	}

	if (flags & LWSSYSGAUTH_HEX) {
		if (bl < (buflen * 2) + 1) {
			lwsl_err("%s: auth in hex oversize\n", __func__);
			return -1;
		}

		/* convert to ascii hex inplace, backwards */

		p = buf + (buflen * 2);
		*p = '\0'; /* terminating NUL */

		for (n = (int)buflen - 1; n >= 0; n--) {
			p -= 2;
			b = buf[n];
			p[0] = hex[(b >> 4) & 0xf];
			p[1] = hex[b & 0xf];
		}

		buflen = (buflen * 2);
	}

	return (int)buflen;
}

