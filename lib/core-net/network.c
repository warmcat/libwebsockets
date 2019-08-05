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

#if !defined(LWS_WITH_ESP32) && !defined(LWS_PLAT_OPTEE)
static int
interface_to_sa(struct lws_vhost *vh, const char *ifname,
		struct sockaddr_in *addr, size_t addrlen, int allow_ipv6)
{
	int ipv6 = 0;
#ifdef LWS_WITH_IPV6
	if (allow_ipv6)
		ipv6 = LWS_IPV6_ENABLED(vh);
#endif
	(void)vh;

	return lws_interface_to_sa(ipv6, ifname, addr, addrlen);
}
#endif

#ifndef LWS_PLAT_OPTEE
static int
lws_get_addresses(struct lws_vhost *vh, void *ads, char *name,
		  int name_len, char *rip, int rip_len)
{
	struct addrinfo ai, *res;
	struct sockaddr_in addr4;

	rip[0] = '\0';
	name[0] = '\0';
	addr4.sin_family = AF_UNSPEC;

#ifdef LWS_WITH_IPV6
	if (LWS_IPV6_ENABLED(vh)) {
		if (!lws_plat_inet_ntop(AF_INET6,
					&((struct sockaddr_in6 *)ads)->sin6_addr,
					rip, rip_len)) {
			lwsl_err("inet_ntop: %s", strerror(LWS_ERRNO));
			return -1;
		}

		// Strip off the IPv4 to IPv6 header if one exists
		if (strncmp(rip, "::ffff:", 7) == 0)
			memmove(rip, rip + 7, strlen(rip) - 6);

		getnameinfo((struct sockaddr *)ads, sizeof(struct sockaddr_in6),
			    name, name_len, NULL, 0, 0);

		return 0;
	} else
#endif
	{
		struct addrinfo *result;

		memset(&ai, 0, sizeof ai);
		ai.ai_family = PF_UNSPEC;
		ai.ai_socktype = SOCK_STREAM;
#if !defined(LWS_WITH_ESP32)
		if (getnameinfo((struct sockaddr *)ads,
				sizeof(struct sockaddr_in),
				name, name_len, NULL, 0, 0))
			return -1;
#endif

		if (getaddrinfo(name, NULL, &ai, &result))
			return -1;

		res = result;
		while (addr4.sin_family == AF_UNSPEC && res) {
			switch (res->ai_family) {
			case AF_INET:
				addr4.sin_addr =
				 ((struct sockaddr_in *)res->ai_addr)->sin_addr;
				addr4.sin_family = AF_INET;
				break;
			}

			res = res->ai_next;
		}
		freeaddrinfo(result);
	}

	if (addr4.sin_family == AF_UNSPEC)
		return -1;

	if (lws_plat_inet_ntop(AF_INET, &addr4.sin_addr, rip, rip_len) == NULL)
		return -1;

	return 0;
}


LWS_VISIBLE const char *
lws_get_peer_simple(struct lws *wsi, char *name, int namelen)
{
	socklen_t len, olen;
#ifdef LWS_WITH_IPV6
	struct sockaddr_in6 sin6;
#endif
	struct sockaddr_in sin4;
	int af = AF_INET;
	void *p, *q;

	wsi = lws_get_network_wsi(wsi);

#ifdef LWS_WITH_IPV6
	if (LWS_IPV6_ENABLED(wsi->vhost)) {
		len = sizeof(sin6);
		p = &sin6;
		af = AF_INET6;
		q = &sin6.sin6_addr;
	} else
#endif
	{
		len = sizeof(sin4);
		p = &sin4;
		q = &sin4.sin_addr;
	}

	olen = len;
	if (getpeername(wsi->desc.sockfd, p, &len) < 0 || len > olen) {
		lwsl_warn("getpeername: %s\n", strerror(LWS_ERRNO));
		return NULL;
	}

	return lws_plat_inet_ntop(af, q, name, namelen);
}
#endif

LWS_VISIBLE void
lws_get_peer_addresses(struct lws *wsi, lws_sockfd_type fd, char *name,
		       int name_len, char *rip, int rip_len)
{
#ifndef LWS_PLAT_OPTEE
	socklen_t len;
#ifdef LWS_WITH_IPV6
	struct sockaddr_in6 sin6;
#endif
	struct sockaddr_in sin4;
	struct lws_context *context = wsi->context;
	int ret = -1;
	void *p;

	rip[0] = '\0';
	name[0] = '\0';

	lws_latency_pre(context, wsi);

#ifdef LWS_WITH_IPV6
	if (LWS_IPV6_ENABLED(wsi->vhost)) {
		len = sizeof(sin6);
		p = &sin6;
	} else
#endif
	{
		len = sizeof(sin4);
		p = &sin4;
	}

	if (getpeername(fd, p, &len) < 0) {
		lwsl_warn("getpeername: %s\n", strerror(LWS_ERRNO));
		goto bail;
	}

	ret = lws_get_addresses(wsi->vhost, p, name, name_len, rip, rip_len);

bail:
	lws_latency(context, wsi, "lws_get_peer_addresses", ret, 1);
#endif
	(void)wsi;
	(void)fd;
	(void)name;
	(void)name_len;
	(void)rip;
	(void)rip_len;
}



/* note: this returns a random port, or one of these <= 0 return codes:
 *
 * LWS_ITOSA_USABLE:     the interface is usable, returned if so and sockfd invalid
 * LWS_ITOSA_NOT_EXIST:  the requested iface does not even exist
 * LWS_ITOSA_NOT_USABLE: the requested iface exists but is not usable (eg, no IP)
 * LWS_ITOSA_BUSY:       the port at the requested iface + port is already in use
 */

LWS_EXTERN int
lws_socket_bind(struct lws_vhost *vhost, lws_sockfd_type sockfd, int port,
		const char *iface, int ipv6_allowed)
{
#ifdef LWS_WITH_UNIX_SOCK
	struct sockaddr_un serv_unix;
#endif
#ifdef LWS_WITH_IPV6
	struct sockaddr_in6 serv_addr6;
#endif
	struct sockaddr_in serv_addr4;
#ifndef LWS_PLAT_OPTEE
	socklen_t len = sizeof(struct sockaddr_storage);
#endif
	int n;
#if !defined(LWS_WITH_ESP32) && !defined(LWS_PLAT_OPTEE)
	int m;
#endif
	struct sockaddr_storage sin;
	struct sockaddr *v;

	memset(&sin, 0, sizeof(sin));

#if defined(LWS_WITH_UNIX_SOCK)
	if (LWS_UNIX_SOCK_ENABLED(vhost)) {
		v = (struct sockaddr *)&serv_unix;
		n = sizeof(struct sockaddr_un);
		memset(&serv_unix, 0, sizeof(serv_unix));
		serv_unix.sun_family = AF_UNIX;
		if (!iface)
			return LWS_ITOSA_NOT_EXIST;
		if (sizeof(serv_unix.sun_path) <= strlen(iface)) {
			lwsl_err("\"%s\" too long for UNIX domain socket\n",
			         iface);
			return LWS_ITOSA_NOT_EXIST;
		}
		strcpy(serv_unix.sun_path, iface);
		if (serv_unix.sun_path[0] == '@')
			serv_unix.sun_path[0] = '\0';
		else
			unlink(serv_unix.sun_path);

	} else
#endif
#if defined(LWS_WITH_IPV6) && !defined(LWS_WITH_ESP32)
	if (ipv6_allowed && LWS_IPV6_ENABLED(vhost)) {
		v = (struct sockaddr *)&serv_addr6;
		n = sizeof(struct sockaddr_in6);
		memset(&serv_addr6, 0, sizeof(serv_addr6));
		if (iface) {
			m = interface_to_sa(vhost, iface,
				    (struct sockaddr_in *)v, n, 1);
			if (m == LWS_ITOSA_NOT_USABLE) {
				lwsl_info("%s: netif %s: Not usable\n",
					 __func__, iface);
				return m;
			}
			if (m == LWS_ITOSA_NOT_EXIST) {
				lwsl_info("%s: netif %s: Does not exist\n",
					 __func__, iface);
				return m;
			}
			serv_addr6.sin6_scope_id = lws_get_addr_scope(iface);
		}

		serv_addr6.sin6_family = AF_INET6;
		serv_addr6.sin6_port = htons(port);
	} else
#endif
	{
		v = (struct sockaddr *)&serv_addr4;
		n = sizeof(serv_addr4);
		memset(&serv_addr4, 0, sizeof(serv_addr4));
		serv_addr4.sin_addr.s_addr = INADDR_ANY;
		serv_addr4.sin_family = AF_INET;

#if !defined(LWS_WITH_ESP32) && !defined(LWS_PLAT_OPTEE)
		if (iface) {
		    m = interface_to_sa(vhost, iface,
				    (struct sockaddr_in *)v, n, 0);
			if (m == LWS_ITOSA_NOT_USABLE) {
				lwsl_info("%s: netif %s: Not usable\n",
					 __func__, iface);
				return m;
			}
			if (m == LWS_ITOSA_NOT_EXIST) {
				lwsl_info("%s: netif %s: Does not exist\n",
					 __func__, iface);
				return m;
			}
		}
#endif
		serv_addr4.sin_port = htons(port);
	} /* ipv4 */

	/* just checking for the interface extant */
	if (sockfd == LWS_SOCK_INVALID)
		return LWS_ITOSA_USABLE;

	n = bind(sockfd, v, n);
#ifdef LWS_WITH_UNIX_SOCK
	if (n < 0 && LWS_UNIX_SOCK_ENABLED(vhost)) {
		lwsl_err("ERROR on binding fd %d to \"%s\" (%d %d)\n",
			 sockfd, iface, n, LWS_ERRNO);
		return LWS_ITOSA_NOT_EXIST;
	} else
#endif
	if (n < 0) {
		lwsl_err("ERROR on binding fd %d to port %d (%d %d)\n",
			 sockfd, port, n, LWS_ERRNO);

		/* if something already listening, tell caller to fail permanently */

		if (LWS_ERRNO == LWS_EADDRINUSE)
			return LWS_ITOSA_BUSY;

		/* otherwise ask caller to retry later */

		return LWS_ITOSA_NOT_EXIST;
	}

#if defined(LWS_WITH_UNIX_SOCK)
	if (LWS_UNIX_SOCK_ENABLED(vhost)) {
		uid_t uid = vhost->context->uid;
		gid_t gid = vhost->context->gid;

		if (vhost->unix_socket_perms) {
			if (lws_plat_user_colon_group_to_ids(
				vhost->unix_socket_perms, &uid, &gid)) {
				lwsl_err("%s: Failed to translate %s\n",
					  __func__, vhost->unix_socket_perms);
				return LWS_ITOSA_NOT_EXIST;
			}
		}
		if (uid && gid) {
			if (chown(serv_unix.sun_path, uid, gid)) {
				lwsl_err("%s: failed to set %s perms %u:%u\n",
					 __func__, serv_unix.sun_path,
					 (unsigned int)uid, (unsigned int)gid);

				return LWS_ITOSA_NOT_EXIST;
			}
			lwsl_notice("%s: vh %s unix skt %s perms %u:%u\n",
				    __func__, vhost->name, serv_unix.sun_path,
				    (unsigned int)uid, (unsigned int)gid);

			if (chmod(serv_unix.sun_path, 0660)) {
				lwsl_err("%s: failed to set %s to 0600 mode\n",
					 __func__, serv_unix.sun_path);

				return LWS_ITOSA_NOT_EXIST;
			}
		}
	}
#endif

#ifndef LWS_PLAT_OPTEE
	if (getsockname(sockfd, (struct sockaddr *)&sin, &len) == -1)
		lwsl_warn("getsockname: %s\n", strerror(LWS_ERRNO));
	else
#endif
#if defined(LWS_WITH_IPV6)
		port = (sin.ss_family == AF_INET6) ?
			ntohs(((struct sockaddr_in6 *) &sin)->sin6_port) :
			ntohs(((struct sockaddr_in *) &sin)->sin_port);
#else
		{
			struct sockaddr_in sain;
			memcpy(&sain, &sin, sizeof(sain));
			port = ntohs(sain.sin_port);
		}
#endif

	return port;
}

static const lws_retry_range_t default_bo = { 3000, 7000 };

unsigned int
lws_retry_get_delay_ms(struct lws_context *context,
		       const lws_retry_bo_t *retry, uint16_t *ctry, char *conceal)
{
	const lws_retry_range_t *r = &default_bo;
	unsigned int ms;
	uint16_t ra;

	if (conceal)
		*conceal = 0;

	if (retry) {
		if (*ctry < retry->retry_ms_table_count)
			r = &retry->retry_ms_table[*ctry];
		else
			r = &retry->retry_ms_table[
				retry->retry_ms_table_count - 1];
	}

	ms = r->min_ms;
	if (lws_get_random(context, &ra, sizeof(ra)) == sizeof(ra))
		ms += ((r->max_ms - ms) * ra) / 65535;

	if (*ctry < 0xffff)
		(*ctry)++;

	if (retry && conceal)
		*conceal = (int)*ctry <= retry->conceal_count;

	return ms;
}

#if defined(LWS_WITH_IPV6)
LWS_EXTERN unsigned long
lws_get_addr_scope(const char *ipaddr)
{
	unsigned long scope = 0;

#ifndef WIN32
	struct ifaddrs *addrs, *addr;
	char ip[NI_MAXHOST];
	unsigned int i;

	getifaddrs(&addrs);
	for (addr = addrs; addr; addr = addr->ifa_next) {
		if (!addr->ifa_addr ||
			addr->ifa_addr->sa_family != AF_INET6)
			continue;

		getnameinfo(addr->ifa_addr,
				sizeof(struct sockaddr_in6),
				ip, sizeof(ip),
				NULL, 0, NI_NUMERICHOST);

		i = 0;
		while (ip[i])
			if (ip[i++] == '%') {
				ip[i - 1] = '\0';
				break;
			}

		if (!strcmp(ip, ipaddr)) {
			scope = if_nametoindex(addr->ifa_name);
			break;
		}
	}
	freeifaddrs(addrs);
#else
	PIP_ADAPTER_ADDRESSES adapter, addrs = NULL;
	PIP_ADAPTER_UNICAST_ADDRESS addr;
	ULONG size = 0;
	DWORD ret;
	struct sockaddr_in6 *sockaddr;
	char ip[NI_MAXHOST];
	unsigned int i;
	int found = 0;

	for (i = 0; i < 5; i++)
	{
		ret = GetAdaptersAddresses(AF_INET6, GAA_FLAG_INCLUDE_PREFIX,
					   NULL, addrs, &size);
		if ((ret == NO_ERROR) || (ret == ERROR_NO_DATA)) {
			break;
		} else if (ret == ERROR_BUFFER_OVERFLOW)
		{
			if (addrs)
				free(addrs);
			addrs = (IP_ADAPTER_ADDRESSES *)malloc(size);
		} else
		{
			if (addrs)
			{
				free(addrs);
				addrs = NULL;
			}
			lwsl_err("Failed to get IPv6 address table (%d)", ret);
			break;
		}
	}

	if ((ret == NO_ERROR) && (addrs)) {
		adapter = addrs;
		while (adapter && !found) {
			addr = adapter->FirstUnicastAddress;
			while (addr && !found) {
				if (addr->Address.lpSockaddr->sa_family ==
				    AF_INET6) {
					sockaddr = (struct sockaddr_in6 *)
						(addr->Address.lpSockaddr);

					lws_plat_inet_ntop(sockaddr->sin6_family,
							&sockaddr->sin6_addr,
							ip, sizeof(ip));

					if (!strcmp(ip, ipaddr)) {
						scope = sockaddr->sin6_scope_id;
						found = 1;
						break;
					}
				}
				addr = addr->Next;
			}
			adapter = adapter->Next;
		}
	}
	if (addrs)
		free(addrs);
#endif

	return scope;
}
#endif



