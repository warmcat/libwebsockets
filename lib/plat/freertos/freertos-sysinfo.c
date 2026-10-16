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

#include "private-lib-core.h"
#include "private-lib-system-sysinfo.h"

#if defined(LWS_WITH_ESP32)
#include <esp_system.h>
#include <esp_timer.h>
#include <lwip/netif.h>
#endif

void
lws_plat_sysinfo_fill(struct lws_sysinfo *si)
{
#if defined(LWS_WITH_ESP32)
	struct netif *nif;

	lws_sysinfo_add(si, LWS_SYSINFO_OS, NULL, "esp-idf", 0);
	lws_sysinfo_add(si, LWS_SYSINFO_UPTIME, NULL, NULL,
			(uint64_t)(esp_timer_get_time() / 1000000));
	lws_sysinfo_add(si, LWS_SYSINFO_RAM_FREE, NULL, NULL,
			(uint64_t)esp_get_free_heap_size());

	/* lwip's interfaces and their addresses */

	for (nif = netif_list; nif; nif = nif->next) {
		uint32_t flags = 0;
		char name[8];

		lws_snprintf(name, sizeof(name), "%c%c%u", nif->name[0],
			     nif->name[1], (unsigned int)nif->num);

		if (netif_is_up(nif))
			flags |= LWS_SYSINFO_IF_UP;
		if (netif_is_link_up(nif))
			flags |= LWS_SYSINFO_IF_RUNNING;

#if defined(LWS_WITH_IPV4)
		if (!ip4_addr_isany(netif_ip4_addr(nif))) {
			struct sockaddr_in sa, mask;

			memset(&sa, 0, sizeof(sa));
			memset(&mask, 0, sizeof(mask));
			sa.sin_family = mask.sin_family = AF_INET;
			sa.sin_addr.s_addr = ip4_addr_get_u32(netif_ip4_addr(nif));
			mask.sin_addr.s_addr =
				ip4_addr_get_u32(netif_ip4_netmask(nif));
			lws_sysinfo_add_iface(si, name, (struct sockaddr *)&sa,
					      (struct sockaddr *)&mask, -1,
					      flags);
		}
#endif
#if defined(LWS_WITH_IPV6) && LWIP_IPV6
		{
			int n;

			for (n = 0; n < LWIP_IPV6_NUM_ADDRESSES; n++) {
				struct sockaddr_in6 sa;

				if (!ip6_addr_isvalid(netif_ip6_addr_state(nif, n)))
					continue;

				memset(&sa, 0, sizeof(sa));
				sa.sin6_family = AF_INET6;
				memcpy(&sa.sin6_addr,
				       netif_ip6_addr(nif, n)->addr, 16);
				lws_sysinfo_add_iface(si, name,
						      (struct sockaddr *)&sa,
						      NULL, 64, flags);
			}
		}
#endif
	}
#else
	(void)si;
#endif
}
