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

int
lws_plat_asyncdns_get_server(struct lws_context *context, int index,
			     lws_sockaddr46 *sa46)
{
	char prop[PROP_VALUE_MAX], netdns[9];

	if (index < 0 || index >= 4)
		return -1;

	lws_snprintf(netdns, sizeof(netdns), "net.dns%d", index + 1);

	prop[0] = '\0';
	if (__system_property_get(netdns, prop) <= 0)
		return -1;

	memset(sa46, 0, sizeof(*sa46));
	if (lws_sa46_parse_numeric_address(prop, sa46) < 0)
		return -1;

	return 0;
}

lws_async_dns_server_check_t
lws_plat_asyncdns_init(struct lws_context *context, lws_async_dns_t *dns)
{
	lws_async_dns_server_check_t s = LADNS_CONF_SERVER_SAME;
	lws_async_dns_server_t *dsrv;
	lws_sockaddr46 sa46t;
	int n = 0;

	while (lws_plat_asyncdns_get_server(context, n++, &sa46t) == 0) {
		dsrv = __lws_async_dns_server_find(dns, &sa46t);
		if (!dsrv) {
			__lws_async_dns_server_add(dns, &sa46t);
			s = LADNS_CONF_SERVER_CHANGED;
		}
	}

	return s;
}
