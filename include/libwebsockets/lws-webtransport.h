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

#ifndef _LWS_WEBTRANSPORT_H
#define _LWS_WEBTRANSPORT_H

#if defined(LWS_ROLE_WT)

/* WebTransport Stream Types (RFC 9297) */
#define LWS_WT_STREAM_TYPE_BIDI  0x41
#define LWS_WT_STREAM_TYPE_UNIDI 0x54

/*
 * WebTransport API
 */

LWS_VISIBLE LWS_EXTERN struct lws *
lws_wt_create_stream(struct lws *wsi_session, int unidi);

LWS_VISIBLE LWS_EXTERN int
lws_wt_is_session(struct lws *wsi);

LWS_VISIBLE LWS_EXTERN int
lws_wt_is_unidi(struct lws *wsi);

LWS_VISIBLE LWS_EXTERN struct lws *
lws_wt_create_stream_from_child(struct lws *child_wsi, int unidi);

LWS_VISIBLE LWS_EXTERN struct lws *
lws_wt_get_session_wsi(struct lws *wsi);

#endif /* LWS_ROLE_WT */
#endif /* _LWS_WEBTRANSPORT_H */
