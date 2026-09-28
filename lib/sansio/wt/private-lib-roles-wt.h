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

#ifndef _PRIVATE_LIB_ROLES_WT_H_
#define _PRIVATE_LIB_ROLES_WT_H_

extern const struct lws_role_ops role_ops_wt;

struct lws_wt_netconn {
	struct lws *nwsi; /* the parent H3 connection wsi */
};

struct _lws_wt_related {
	struct lws_wt_netconn *wtn; /* allocated for session WSI */
	/*
	 * For a WT stream, the session wsi whose id the stream carried in its
	 * header, ie, the session that owns it.  NULL on the session wsi
	 * itself, and cleared on every associated stream when the session is
	 * closed, so it can never dangle.  Streams are siblings of the session
	 * under the QUIC network wsi, not its children, so this is the only
	 * record of the association.
	 */
	struct lws *session_wsi;
	uint8_t is_session:1;
	uint8_t is_unidi:1;
};

#endif /* _PRIVATE_LIB_ROLES_WT_H_ */
