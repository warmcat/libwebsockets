/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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
 */

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#include "core/private.h"

int
lws_plat_plugins_init(struct lws_context * context, const char * const *d)
{
#if defined(LWS_WITH_PLUGINS) && (UV_VERSION_MAJOR > 0)
	if (lws_check_opt(context->options, LWS_SERVER_OPTION_LIBUV))
		return lws_uv_plugins_init(context, d);
#endif

	return 0;
}

int
lws_plat_plugins_destroy(struct lws_context * context)
{
#if defined(LWS_WITH_PLUGINS) && (UV_VERSION_MAJOR > 0)
	if (lws_check_opt(context->options, LWS_SERVER_OPTION_LIBUV))
		return lws_uv_plugins_destroy(context);
#endif

	return 0;
}
