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

#ifndef _PRIVATE_LIB_ROLES_H3_H_
#define _PRIVATE_LIB_ROLES_H3_H_

extern const struct lws_role_ops role_ops_h3;
#define lwsi_role_h3(wsi) (wsi->role_ops == &role_ops_h3)



/* Internal QPACK API */
int
lws_qpack_dynamic_size(struct lws_qpack_context *ctx, int size);

LWS_VISIBLE int
lws_add_http3_header_by_name(struct lws *wsi, const unsigned char *name,
			     const unsigned char *value, int length,
			     unsigned char **p, unsigned char *end);

LWS_VISIBLE int
lws_add_http3_header_by_token(struct lws *wsi, enum lws_token_indexes token,
			      const unsigned char *value, int length,
			      unsigned char **p, unsigned char *end);

LWS_VISIBLE int
lws_add_http3_header_status(struct lws *wsi, unsigned int code,
			    unsigned char **p, unsigned char *end);



#endif /* _PRIVATE_LIB_ROLES_H3_H_ */
