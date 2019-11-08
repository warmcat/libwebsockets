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

#if defined(LWS_WITH_NETWORK)
static const char *hex = "0123456789ABCDEF";
#endif

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

#if defined(LWS_WITH_NETWORK)
int
lws_system_auth_default_cb(struct lws_context *context, int idx, size_t ofs,
			   uint8_t *buf, size_t *plen, lws_system_auth_op_t op)
{
	int n;

	if (idx >= (int)LWS_ARRAY_SIZE(context->auth_token))
		return -1;

	switch (op) {
	case LWSSYS_AUTH_GET:
		if (!context->auth_token[idx]) {
			lwsl_notice("%s: token %d not set\n", __func__, idx);
			return -1;
		}

		if (!buf) /* we just need to tell him that it exists */
			return -2;

		n = lws_buflist_linear_copy(&context->auth_token[idx], ofs, buf,
					    *plen);
		if (n < 0)
			return -2;

		*plen = (size_t)n;

		return 0;

	case LWSSYS_AUTH_TOTAL_LENGTH:
		*plen = lws_buflist_total_len(&context->auth_token[idx]);
		return 0;

	case LWSSYS_AUTH_APPEND:
		if (lws_buflist_append_segment(&context->auth_token[idx], buf,
					       *plen) < 0)
			return -1;

		return 0;

	case LWSSYS_AUTH_FREE:
		lws_buflist_destroy_all_segments(&context->auth_token[idx]);
		return 0;

	default:
		break;
	}

	return -1;
}

int
lws_system_get_auth(struct lws_context *context, int idx, size_t ofs,
		    uint8_t *buf, size_t buflen, int flags)
{
	size_t bl = buflen;
	uint8_t *p, b;
	int n;

	if (!context->system_ops || !context->system_ops->auth)
		n = lws_system_auth_default_cb(context, idx, ofs, buf, &buflen,
						LWSSYS_AUTH_GET);
	else
		n = context->system_ops->auth(context, idx, ofs, buf, &buflen,
						LWSSYS_AUTH_GET);

	if (n < 0) {
		if (buf)
			lwsl_err("%s: auth %d get failed %d, space %d\n",
					__func__, idx, n, (int)bl);
		return n;
	}

	if (buf && (flags & LWSSYSGAUTH_HEX)) {
		if (bl < (buflen * 2) + 1) {
			lwsl_err("%s: auth in hex oversize %d\n", __func__,
					(int)bl);

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
#endif
