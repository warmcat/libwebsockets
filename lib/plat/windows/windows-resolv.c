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
#include <iphlpapi.h>

lws_async_dns_server_check_t
lws_plat_asyncdns_init(struct lws_context *context, lws_sockaddr46 *sa46)
{
	unsigned long ul;
	FIXED_INFO fi;
	int n;

	ul = sizeof(fi);
	if (GetNetworkParams(&fi, &ul) != NO_ERROR) {
		lwsl_err("%s: can't get dns servers\n", __func__);

		return LADNS_CONF_SERVER_UNKNOWN;
	}

	lwsl_info("%s: trying %s\n", __func__,
			fi.DnsServerList.IpAddress.String);
	n = lws_sa46_parse_numeric_address(
			fi.DnsServerList.IpAddress.String, sa46);

	return n == 0 ? LADNS_CONF_SERVER_CHANGED :
			LADNS_CONF_SERVER_UNKNOWN;
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
