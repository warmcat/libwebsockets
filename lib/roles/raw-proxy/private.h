/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2018 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 *  This is included from core/private.h if LWS_ROLE_RAW_PROXY
 */

extern struct lws_role_ops role_ops_raw_proxy;

#define lwsi_role_raw_proxy(wsi) (wsi->role_ops == &role_ops_raw_proxy)

#if 0
struct lws_vhost_role_ws {
	const struct lws_extension *extensions;
};

struct lws_pt_role_ws {
	struct lws *rx_draining_ext_list;
	struct lws *tx_draining_ext_list;
};

struct _lws_raw_proxy_related {
	struct lws *wsi_onward;
};
#endif
