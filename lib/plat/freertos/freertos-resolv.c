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

#include "private-lib-core.h"
#include "private-lib-async-dns.h"

#if defined(LWS_WITH_SYS_ASYNC_DNS)
lws_async_dns_server_check_t
lws_plat_asyncdns_init(struct lws_context *context, lws_async_dns_t *dns)
{
	lws_sockaddr46 sa46t;
	uint32_t ipv4;
	lws_async_dns_server_check_t s = LADNS_CONF_SERVER_SAME;
	lws_async_dns_server_t *dsrv;

	FreeRTOS_GetAddressConfiguration(NULL, NULL, NULL, &ipv4);

	memset(&sa46t, 0, sizeof(sa46t));

	sa46t.sa4.sin_family = AF_INET;
	sa46t.sa4.sin_addr.s_addr = ipv4;

	dsrv = __lws_async_dns_server_find(dns, &sa46t);
	if (!dsrv) {
		__lws_async_dns_server_add(dns, &sa46t);
		s = LADNS_CONF_SERVER_CHANGED;
	}

	return s;
}
#endif

int
lws_plat_ntpclient_config(struct lws_context *context)
{
	lws_system_blob_heap_append(lws_system_get_blob(context,
				    LWS_SYSBLOB_TYPE_NTP_SERVER, 0),
				    (const uint8_t *)"pool.ntp.org", 13);

	return 0;
}
