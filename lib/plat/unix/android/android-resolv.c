/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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
#include "private-lib-async-dns.h"
#include <sys/system_properties.h>

lws_async_dns_server_check_t
lws_plat_asyncdns_init(struct lws_context *context, lws_async_dns_t *dns)
{
	lws_async_dns_server_check_t s = LADNS_CONF_SERVER_SAME;
	char prop[PROP_VALUE_MAX], netdns[9];
	lws_async_dns_server_t *dsrv;
	lws_sockaddr46 sa46t;
	int n;

	strcpy(netdns, "net.dns1");
	for (n = 0; n < 4; n++) {

		prop[0] = '\0';
		if (__system_property_get(netdns, prop) <= 0)
			continue;

		netdns[7]++; /* net.dns2... etc */

		memset(&sa46t, 0, sizeof(sa46t));
		if (lws_sa46_parse_numeric_address(prop, &sa46t) < 0)
			continue;

		dsrv = __lws_async_dns_server_find(dns, &sa46t);
		if (!dsrv) {
			__lws_async_dns_server_add(dns, &sa46t);
			s = LADNS_CONF_SERVER_CHANGED;
		}
	}

	return s;
}
