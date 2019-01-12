/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2019 Andy Green <andy@warmcat.com>
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

#include "core/private.h"


LWS_VISIBLE int
lws_set_proxy(struct lws_vhost *vhost, const char *proxy)
{
	char *p;
	char authstring[96];

	if (!proxy)
		return -1;

	/* we have to deal with a possible redundant leading http:// */
	if (!strncmp(proxy, "http://", 7))
		proxy += 7;

	p = strrchr(proxy, '@');
	if (p) { /* auth is around */

		if ((unsigned int)(p - proxy) > sizeof(authstring) - 1)
			goto auth_too_long;

		lws_strncpy(authstring, proxy, p - proxy + 1);
		// null termination not needed on input
		if (lws_b64_encode_string(authstring, lws_ptr_diff(p, proxy),
				vhost->proxy_basic_auth_token,
		    sizeof vhost->proxy_basic_auth_token) < 0)
			goto auth_too_long;

		lwsl_info(" Proxy auth in use\n");

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
		proxy = p + 1;
#endif
	} else
		vhost->proxy_basic_auth_token[0] = '\0';

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	lws_strncpy(vhost->http.http_proxy_address, proxy,
		    sizeof(vhost->http.http_proxy_address));

	p = strchr(vhost->http.http_proxy_address, ':');
	if (!p && !vhost->http.http_proxy_port) {
		lwsl_err("http_proxy needs to be ads:port\n");

		return -1;
	} else {
		if (p) {
			*p = '\0';
			vhost->http.http_proxy_port = atoi(p + 1);
		}
	}

	lwsl_info(" Proxy %s:%u\n", vhost->http.http_proxy_address,
			vhost->http.http_proxy_port);
#endif
	return 0;

auth_too_long:
	lwsl_err("proxy auth too long\n");

	return -1;
}

