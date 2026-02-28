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
#include <iphlpapi.h>

int
lws_plat_asyncdns_get_server(struct lws_context *context, int index,
			     lws_sockaddr46 *sa46)
{
	unsigned long ul;
	FIXED_INFO *fi;
	int n = 0, current = 0, ret = -1;
	DWORD dw;

	ul = sizeof(fi);

	do {
		fi = (FIXED_INFO *)lws_malloc(ul, __func__);
		if (!fi)
			return -1;

		dw = GetNetworkParams(fi, &ul);
		if (dw == NO_ERROR)
			break;
		if (dw != ERROR_BUFFER_OVERFLOW) {
			lwsl_err("%s: GetNetworkParams says 0x%x\n", __func__,
				 (unsigned int)dw);
			lws_free(fi);
			return -1;
		}

		lws_free(fi);
		if (n++)
			return -1;

	} while (1);

	IP_ADDR_STRING *pip = &fi->DnsServerList;
	while (pip) {
		if (current++ == index) {
			if (!lws_sa46_parse_numeric_address(pip->IpAddress.String, sa46))
				ret = 0;
			break;
		}
		pip = pip->Next;
	}

	lws_free(fi);
	return ret;
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

int
lws_plat_ntpclient_config(struct lws_context *context)
{
#if defined(LWS_HAVE_GETENV)
	char *ntpsrv = getenv("LWS_NTP_SERVER");

	if (ntpsrv && strlen(ntpsrv) < 64) {
		lws_system_blob_heap_append(lws_system_get_blob(context,
					    LWS_SYSBLOB_TYPE_NTP_SERVER, 0),
					    (const uint8_t *)ntpsrv,
					    strlen(ntpsrv));
		return 1;
	}
#endif
	return 0;
}
