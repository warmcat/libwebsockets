/*
 * Adapted from tadns 1.1, from http://adns.sourceforge.net/
 * Original license -->
 *
 * Copyright (c) 2004-2005 Sergey Lyubka <valenok@gmail.com>
 *
 * "THE BEER-WARE LICENSE" (Revision 42):
 * Sergey Lyubka wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.
 *
 * Integrated into lws, largely rewritten and relicensed (as allowed above)
 *
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

lws_async_dns_server_check_t
lws_plat_asyncdns_init(struct lws_context *context, lws_sockaddr46 *sa46)
{
	char	subkey[512], dhcpns[512], ns[512], value[128], *key =
	"SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces";
	HKEY	hKey, hSub;
	LONG	err;
	int	i, n;

	if ((err = RegOpenKey(HKEY_LOCAL_MACHINE, key, &hKey)) != ERROR_SUCCESS) {
		lwsl_err("%s: cannot open reg key %s: %d\n", __func__, key, err);

		return 1;
	}

	for (i = 0; RegEnumKey(hKey, i, subkey, sizeof(subkey)) == ERROR_SUCCESS; i++) {
		DWORD type, len = sizeof(value);

		if (RegOpenKey(hKey, subkey, &hSub) == ERROR_SUCCESS &&
		    (RegQueryValueEx(hSub, "NameServer", 0,
		    &type, value, &len) == ERROR_SUCCESS ||
		    RegQueryValueEx(hSub, "DhcpNameServer", 0,
		    &type, value, &len) == ERROR_SUCCESS)) {
			n = lws_sa46_parse_numeric_address(value, sa46)
			RegCloseKey(hSub);
			RegCloseKey(hKey);
			return n == 0 ? LADNS_CONF_SERVER_CHANGED :
					LADNS_CONF_SERVER_UNKNOWN;
		}
	}
	RegCloseKey(hKey);

	return LADNS_CONF_SERVER_UNKNOWN;
}

