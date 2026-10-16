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
#if defined(LWS_WITH_SYS_ASYNC_DNS)
#include "private-lib-async-dns.h"
#endif

#include <time.h>

static const char * const lws_sysinfo_type_names[] = {
	"lws version",
	"lws build",
	"hostname",
	"os",
	"arch",
	"pid",
	"time",
	"uptime",
	"cpus",
	"ram total",
	"ram free",
	"iface",
	"dns server",
	"dns search",
};

const char *
lws_sysinfo_type_name(lws_sysinfo_type_t type)
{
	if ((unsigned int)type >= LWS_ARRAY_SIZE(lws_sysinfo_type_names))
		return "?";

	return lws_sysinfo_type_names[type];
}

lws_sysinfo_item_t *
lws_sysinfo_add(struct lws_sysinfo *si, lws_sysinfo_type_t type,
		const char *name, const char *s, uint64_t u)
{
	size_t nl = name ? strlen(name) + 1 : 0, sl = s ? strlen(s) + 1 : 0;
	lws_sysinfo_item_t *it;
	char *p;

	it = lwsac_use_zero(&si->ac, sizeof(*it) + nl + sl, 1024);
	if (!it)
		return NULL;

	p = (char *)&it[1];
	it->type = type;
	it->u = u;
	if (name) {
		memcpy(p, name, nl);
		it->name = p;
		p += nl;
	}
	if (s) {
		memcpy(p, s, sl);
		it->s = p;
	}

	lws_dll2_add_tail(&it->list, &si->items);

	return it;
}

/* the prefix length a netmask says, eg, 255.255.0.0 is 16 */

static int
lws_sysinfo_mask_prefix(const uint8_t *m, size_t len)
{
	int bits = 0;
	size_t n;

	for (n = 0; n < len; n++) {
		uint8_t b = m[n];

		if (b == 0xff) {
			bits += 8;
			continue;
		}
		while (b & 0x80) {
			bits++;
			b = (uint8_t)(b << 1);
		}
		break;
	}

	return bits;
}

lws_sysinfo_item_t *
lws_sysinfo_add_iface(struct lws_sysinfo *si, const char *name,
		      const struct sockaddr *sa, const struct sockaddr *mask,
		      int prefix, uint32_t flags)
{
	lws_sysinfo_item_t *it;

	if (!sa)
		return NULL;

	switch (sa->sa_family) {
#if defined(LWS_WITH_IPV4)
	case AF_INET:
		if (prefix < 0 && mask && mask->sa_family == AF_INET)
			prefix = lws_sysinfo_mask_prefix((const uint8_t *)
				&((const struct sockaddr_in *)mask)->sin_addr, 4);
		it = lws_sysinfo_add(si, LWS_SYSINFO_IFACE_ADDR, name, NULL,
				     prefix < 0 ? 32 : (uint64_t)prefix);
		if (!it)
			return NULL;
		memcpy(&it->sa46.sa4, sa, sizeof(it->sa46.sa4));
		it->sa46.sa4.sin_port = 0;
		break;
#endif
#if defined(LWS_WITH_IPV6)
	case AF_INET6:
		if (prefix < 0 && mask && mask->sa_family == AF_INET6)
			prefix = lws_sysinfo_mask_prefix((const uint8_t *)
				&((const struct sockaddr_in6 *)mask)->sin6_addr, 16);
		it = lws_sysinfo_add(si, LWS_SYSINFO_IFACE_ADDR, name, NULL,
				     prefix < 0 ? 128 : (uint64_t)prefix);
		if (!it)
			return NULL;
		memcpy(&it->sa46.sa6, sa, sizeof(it->sa46.sa6));
		it->sa46.sa6.sin6_port = 0;
		break;
#endif
	default:
		return NULL;
	}

	it->flags = flags;

	return it;
}

struct lws_sysinfo *
lws_sysinfo_create(struct lws_context *cx)
{
	struct lws_sysinfo *si = lws_zalloc(sizeof(*si), __func__);
	char tb[40];
	time_t t;
	struct tm tm;

	if (!si)
		return NULL;

	si->cx = cx;

	/* what lws this is */

	lws_sysinfo_add(si, LWS_SYSINFO_LWS_VERSION, NULL, LWS_LIBRARY_VERSION, 0);
	lws_sysinfo_add(si, LWS_SYSINFO_LWS_BUILD, NULL, LWS_BUILD_HASH, 0);

	/* what time it is, as the system sees it */

	t = (time_t)lws_now_secs();
#if defined(WIN32)
	if (!gmtime_s(&tm, &t))
#else
	if (gmtime_r(&t, &tm))
#endif
	{
		lws_snprintf(tb, sizeof(tb), "%04d-%02d-%02dT%02d:%02d:%02dZ",
			     tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			     tm.tm_hour, tm.tm_min, tm.tm_sec);
		lws_sysinfo_add(si, LWS_SYSINFO_TIME, NULL, tb, (uint64_t)t);
	}

	/* what the platform knows: hostname, OS, RAM, interfaces... */

	lws_plat_sysinfo_fill(si);

#if defined(LWS_WITH_SYS_ASYNC_DNS)
	{
		char search[256], *sd = search;
		lws_sockaddr46 sa46;
		int n = 0, ndots = 1, count;

		while (!lws_plat_asyncdns_get_server(cx, n++, &sa46)) {
			lws_sysinfo_item_t *it;

			it = lws_sysinfo_add(si, LWS_SYSINFO_DNS_SERVER, NULL,
					     NULL, 0);
			if (it)
				it->sa46 = sa46;
		}

		count = lws_plat_asyncdns_get_search(cx, search, sizeof(search),
						     &ndots);
		for (n = 0; n < count; n++) {
			lws_sysinfo_add(si, LWS_SYSINFO_DNS_SEARCH, NULL, sd,
					(uint64_t)ndots);
			sd += strlen(sd) + 1;
		}
	}
#endif

	return si;
}

const lws_sysinfo_item_t *
lws_sysinfo_next(struct lws_sysinfo *si, const lws_sysinfo_item_t *prev)
{
	lws_dll2_t *d = prev ? prev->list.next : si->items.head;

	if (!d)
		return NULL;

	return lws_container_of(d, lws_sysinfo_item_t, list);
}

void
lws_sysinfo_destroy(struct lws_sysinfo **psi)
{
	struct lws_sysinfo *si = *psi;

	if (!si)
		return;

	lws_dll2_owner_clear(&si->items);
	lwsac_free(&si->ac);
	lws_free(si);
	*psi = NULL;
}

static int
lws_sysinfo_describe_bytes(char *buf, size_t len, uint64_t b)
{
	if (b >= 1024ull * 1024 * 1024)
		return lws_snprintf(buf, len, "%llu MiB (%llu)",
				    (unsigned long long)(b >> 20),
				    (unsigned long long)b);

	return lws_snprintf(buf, len, "%llu KiB (%llu)",
			    (unsigned long long)(b >> 10),
			    (unsigned long long)b);
}

int
lws_sysinfo_describe(const lws_sysinfo_item_t *it, char *buf, size_t len)
{
	const char *tn = lws_sysinfo_type_name(it->type);
	lws_sockaddr46 sa46 = it->sa46; /* the writer wants it non-const */
	char ads[64];
	int n;

	switch (it->type) {
	case LWS_SYSINFO_IFACE_ADDR:
		lws_sa46_write_numeric_address(&sa46, ads, sizeof(ads));
		n = lws_snprintf(buf, len, "%s %s: %s/%u%s%s%s%s", tn,
				 it->name ? it->name : "?", ads,
				 (unsigned int)it->u,
				 it->flags & LWS_SYSINFO_IF_UP ? " up" : "",
				 it->flags & LWS_SYSINFO_IF_RUNNING ? " running" : "",
				 it->flags & LWS_SYSINFO_IF_LOOPBACK ? " loopback" : "",
				 it->flags & LWS_SYSINFO_IF_P2P ? " p2p" : "");
		break;

	case LWS_SYSINFO_DNS_SERVER:
		lws_sa46_write_numeric_address(&sa46, ads, sizeof(ads));
		n = lws_snprintf(buf, len, "%s: %s", tn, ads);
		break;

	case LWS_SYSINFO_DNS_SEARCH:
		n = lws_snprintf(buf, len, "%s: %s (ndots %u)", tn,
				 it->s ? it->s : "?", (unsigned int)it->u);
		break;

	case LWS_SYSINFO_TIME:
		n = lws_snprintf(buf, len, "%s: %s (unix %llu)", tn,
				 it->s ? it->s : "?",
				 (unsigned long long)it->u);
		break;

	case LWS_SYSINFO_UPTIME:
		n = lws_snprintf(buf, len, "%s: %llud %lluh %llum %llus", tn,
				 (unsigned long long)(it->u / 86400),
				 (unsigned long long)((it->u / 3600) % 24),
				 (unsigned long long)((it->u / 60) % 60),
				 (unsigned long long)(it->u % 60));
		break;

	case LWS_SYSINFO_RAM_TOTAL:
	case LWS_SYSINFO_RAM_FREE:
		n = lws_snprintf(buf, len, "%s: ", tn);
		n += lws_sysinfo_describe_bytes(buf + n, len - (size_t)n,
						it->u);
		break;

	case LWS_SYSINFO_PID:
	case LWS_SYSINFO_CPUS:
		n = lws_snprintf(buf, len, "%s: %llu", tn,
				 (unsigned long long)it->u);
		break;

	default:
		n = lws_snprintf(buf, len, "%s: %s", tn, it->s ? it->s : "?");
		break;
	}

	return n;
}
