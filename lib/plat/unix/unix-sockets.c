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

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "private-lib-core.h"

#include <sys/ioctl.h>

#if !defined(LWS_DETECTED_PLAT_IOS)
#include <net/route.h>
#endif

#include <net/if.h>

#include <pwd.h>
#include <grp.h>

#if defined(LWS_WITH_MBEDTLS)
#if defined(LWS_HAVE_MBEDTLS_NET_SOCKETS)
#include "mbedtls/net_sockets.h"
#else
#include "mbedtls/net.h"
#endif
#endif

int
lws_send_pipe_choked(struct lws *wsi)
{
	struct lws_pollfd fds;
	struct lws *wsi_eff;

#if !defined(LWS_WITHOUT_EXTENSIONS)
	if (wsi->ws && wsi->ws->tx_draining_ext)
		return 1;
#endif

#if defined(LWS_WITH_HTTP2)
	wsi_eff = lws_get_network_wsi(wsi);
#else
	wsi_eff = wsi;
#endif

	/* the fact we checked implies we avoided back-to-back writes */
	wsi_eff->could_have_pending = 0;

	/* treat the fact we got a truncated send pending as if we're choked */
	if (lws_has_buffered_out(wsi_eff)
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	    ||wsi->http.comp_ctx.buflist_comp ||
	    wsi->http.comp_ctx.may_have_more
#endif
	    )
		return 1;

	fds.fd = wsi_eff->desc.sockfd;
	fds.events = POLLOUT;
	fds.revents = 0;

	if (poll(&fds, 1, 0) != 1)
		return 1;

	if ((fds.revents & POLLOUT) == 0)
		return 1;

	/* okay to send another packet without blocking */

	return 0;
}

int
lws_plat_set_nonblocking(lws_sockfd_type fd)
{
	return fcntl(fd, F_SETFL, O_NONBLOCK) < 0;
}

int
lws_plat_set_socket_options(struct lws_vhost *vhost, int fd, int unix_skt)
{
	int optval = 1;
	socklen_t optlen = sizeof(optval);

#if defined(__APPLE__) || \
    defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || \
    defined(__NetBSD__) || \
    defined(__OpenBSD__) || \
    defined(__HAIKU__)
	struct protoent *tcp_proto;
#endif

	(void)fcntl(fd, F_SETFD, FD_CLOEXEC);

	if (!unix_skt && vhost->ka_time) {
		/* enable keepalive on this socket */
		optval = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
			       (const void *)&optval, optlen) < 0)
			return 1;

#if defined(__APPLE__) || \
    defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || \
    defined(__NetBSD__) || \
    defined(__CYGWIN__) || defined(__OpenBSD__) || defined (__sun) || \
    defined(__HAIKU__)

		/*
		 * didn't find a way to set these per-socket, need to
		 * tune kernel systemwide values
		 */
#else
		/* set the keepalive conditions we want on it too */

#if defined(LWS_HAVE_TCP_USER_TIMEOUT)
		optval = 1000 * (vhost->ka_time +
				 (vhost->ka_interval * vhost->ka_probes));
		if (setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT,
			       (const void *)&optval, optlen) < 0)
			return 1;
#endif
		optval = vhost->ka_time;
		if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,
			       (const void *)&optval, optlen) < 0)
			return 1;

		optval = vhost->ka_interval;
		if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL,
			       (const void *)&optval, optlen) < 0)
			return 1;

		optval = vhost->ka_probes;
		if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,
			       (const void *)&optval, optlen) < 0)
			return 1;
#endif
	}

#if defined(SO_BINDTODEVICE)
	if (!unix_skt && vhost->bind_iface && vhost->iface) {
		lwsl_info("binding listen skt to %s using SO_BINDTODEVICE\n", vhost->iface);
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, vhost->iface,
				strlen(vhost->iface)) < 0) {
			lwsl_warn("Failed to bind to device %s\n", vhost->iface);
			return 1;
		}
	}
#endif

	/* Disable Nagle */
	optval = 1;
#if defined (__sun) || defined(__QNX__)
	if (!unix_skt && setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const void *)&optval, optlen) < 0)
		return 1;
#elif !defined(__APPLE__) && \
      !defined(__FreeBSD__) && !defined(__FreeBSD_kernel__) &&        \
      !defined(__NetBSD__) && \
      !defined(__OpenBSD__) && \
      !defined(__HAIKU__)
	if (!unix_skt && setsockopt(fd, SOL_TCP, TCP_NODELAY, (const void *)&optval, optlen) < 0)
		return 1;
#else
	tcp_proto = getprotobyname("TCP");
	if (!unix_skt && setsockopt(fd, tcp_proto->p_proto, TCP_NODELAY, &optval, optlen) < 0)
		return 1;
#endif

	return lws_plat_set_nonblocking(fd);
}


/* cast a struct sockaddr_in6 * into addr for ipv6 */

int
lws_interface_to_sa(int ipv6, const char *ifname, struct sockaddr_in *addr,
		    size_t addrlen)
{
	int rc = LWS_ITOSA_NOT_EXIST;

	struct ifaddrs *ifr;
	struct ifaddrs *ifc;
#ifdef LWS_WITH_IPV6
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
#endif

	if (getifaddrs(&ifr)) {
		lwsl_err("%s: unable to getifaddrs: errno %d\n", __func__, errno);

		return LWS_ITOSA_USABLE;
	}
	for (ifc = ifr; ifc != NULL && rc; ifc = ifc->ifa_next) {
		if (!ifc->ifa_addr || !ifc->ifa_name)
			continue;

		lwsl_debug(" interface %s vs %s (fam %d) ipv6 %d\n",
			   ifc->ifa_name, ifname,
			   ifc->ifa_addr->sa_family, ipv6);

		if (strcmp(ifc->ifa_name, ifname))
			continue;

		switch (ifc->ifa_addr->sa_family) {
#if defined(AF_PACKET)
		case AF_PACKET:
			/* interface exists but is not usable */
			rc = LWS_ITOSA_NOT_USABLE;
			continue;
#endif

		case AF_INET:
#ifdef LWS_WITH_IPV6
			if (ipv6) {
				/* map IPv4 to IPv6 */
				memset((char *)&addr6->sin6_addr, 0,
						sizeof(struct in6_addr));
				addr6->sin6_addr.s6_addr[10] = 0xff;
				addr6->sin6_addr.s6_addr[11] = 0xff;
				memcpy(&addr6->sin6_addr.s6_addr[12],
				       &((struct sockaddr_in *)ifc->ifa_addr)->sin_addr,
							sizeof(struct in_addr));
				lwsl_debug("%s: uplevelling ipv4 bind to ipv6\n", __func__);
			} else
#endif
				memcpy(addr,
					(struct sockaddr_in *)ifc->ifa_addr,
						    sizeof(struct sockaddr_in));
			break;
#ifdef LWS_WITH_IPV6
		case AF_INET6:
			memcpy(&addr6->sin6_addr,
			  &((struct sockaddr_in6 *)ifc->ifa_addr)->sin6_addr,
						       sizeof(struct in6_addr));
			break;
#endif
		default:
			continue;
		}
		rc = LWS_ITOSA_USABLE;
	}

	freeifaddrs(ifr);

	if (rc) {
		/* check if bind to IP address */
#ifdef LWS_WITH_IPV6
		if (inet_pton(AF_INET6, ifname, &addr6->sin6_addr) == 1)
			rc = LWS_ITOSA_USABLE;
		else
#endif
		if (inet_pton(AF_INET, ifname, &addr->sin_addr) == 1)
			rc = LWS_ITOSA_USABLE;
	}

	return rc;
}


const char *
lws_plat_inet_ntop(int af, const void *src, char *dst, int cnt)
{
	return inet_ntop(af, src, dst, cnt);
}

int
lws_plat_inet_pton(int af, const char *src, void *dst)
{
	return inet_pton(af, src, dst);
}

int
lws_plat_ifname_to_hwaddr(int fd, const char *ifname, uint8_t *hwaddr, int len)
{
#if defined(__linux__)
	struct ifreq i;

	memset(&i, 0, sizeof(i));
	lws_strncpy(i.ifr_name, ifname, sizeof(i.ifr_name));

	if (ioctl(fd, SIOCGIFHWADDR, &i) < 0)
		return -1;

	memcpy(hwaddr, &i.ifr_hwaddr.sa_data, 6);

	return 6;
#else
	lwsl_err("%s: UNIMPLEMENTED on this platform\n", __func__);

	return -1;
#endif
}

int
lws_plat_rawudp_broadcast(uint8_t *p, const uint8_t *canned, int canned_len,
			  int n, int fd, const char *iface)
{
#if defined(__linux__)
	struct sockaddr_ll sll;
	uint16_t *p16 = (uint16_t *)p;
	uint32_t ucs = 0;

	memcpy(p, canned, canned_len);

	p[2] = n >> 8;
	p[3] = n;

	while (p16 < (uint16_t *)(p + 20))
		ucs += ntohs(*p16++);

	ucs += ucs >> 16;
	ucs ^= 0xffff;

	p[10] = ucs >> 8;
	p[11] = ucs;
	p[24] = (n - 20) >> 8;
	p[25] = (n - 20);

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(0x800);
	sll.sll_halen = 6;
	sll.sll_ifindex = if_nametoindex(iface);
	memset(sll.sll_addr, 0xff, 6);

	return sendto(fd, p, n, 0, (struct sockaddr *)&sll, sizeof(sll));
#else
	lwsl_err("%s: UNIMPLEMENTED on this platform\n", __func__);

	return -1;
#endif
}

int
lws_plat_if_up(const char *ifname, int fd, int up)
{
#if defined(__linux__)
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	lws_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		lwsl_err("%s: SIOCGIFFLAGS fail\n", __func__);
		return 1;
	}

	if (up)
		ifr.ifr_flags |= IFF_UP;
	else
		ifr.ifr_flags &= ~IFF_UP;

	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		lwsl_err("%s: SIOCSIFFLAGS fail\n", __func__);
		return 1;
	}

	return 0;
#else
	lwsl_err("%s: UNIMPLEMENTED on this platform\n", __func__);

	return -1;
#endif
}

int
lws_plat_BINDTODEVICE(lws_sockfd_type fd, const char *ifname)
{
#if defined(__linux__)
	struct ifreq i;

	memset(&i, 0, sizeof(i));
	i.ifr_addr.sa_family = AF_INET;
	lws_strncpy(i.ifr_ifrn.ifrn_name, ifname,
		    sizeof(i.ifr_ifrn.ifrn_name));
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &i, sizeof(i)) < 0) {
		lwsl_notice("%s: failed %d\n", __func__, LWS_ERRNO);
		return 1;
	}

	return 0;
#else
	lwsl_err("%s: UNIMPLEMENTED on this platform\n", __func__);

	return -1;
#endif
}

int
lws_plat_ifconfig_ip(const char *ifname, int fd, uint8_t *ip, uint8_t *mask_ip,
			uint8_t *gateway_ip)
{
#if defined(__linux__)
	struct sockaddr_in sin;
	struct rtentry route;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	memset(&route, 0, sizeof(route));
	memset(&sin, 0, sizeof(sin));

	lws_strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	lws_plat_if_up(ifname, fd, 0);

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(*(uint32_t *)ip);

	memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
	if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
		lwsl_err("%s: SIOCSIFADDR fail\n", __func__);
		return 1;
	}

	sin.sin_addr.s_addr = htonl(*(uint32_t *)mask_ip);
	memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
	if (ioctl(fd, SIOCSIFNETMASK, &ifr) < 0) {
		lwsl_err("%s: SIOCSIFNETMASK fail\n", __func__);
		return 1;
	}

	lws_plat_if_up(ifname, fd, 1);

	sin.sin_addr.s_addr = htonl(*(uint32_t *)gateway_ip);
	memcpy(&route.rt_gateway, &sin, sizeof(struct sockaddr));

	sin.sin_addr.s_addr = 0;
	memcpy(&route.rt_dst, &sin, sizeof(struct sockaddr));
	memcpy(&route.rt_genmask, &sin, sizeof(struct sockaddr));

	route.rt_flags = RTF_UP | RTF_GATEWAY;
	route.rt_metric = 100;
	route.rt_dev = (char *)ifname;

	if (ioctl(fd, SIOCADDRT, &route) < 0) {
		lwsl_err("%s: SIOCADDRT 0x%x fail: %d\n", __func__,
			(unsigned int)htonl(*(uint32_t *)gateway_ip), LWS_ERRNO);
		return 1;
	}

	return 0;
#else
	lwsl_err("%s: UNIMPLEMENTED on this platform\n", __func__);

	return -1;
#endif
}

#if defined(LWS_WITH_MBEDTLS)
int
lws_plat_mbedtls_net_send(void *ctx, const uint8_t *buf, size_t len)
{
	int fd = ((mbedtls_net_context *) ctx)->fd;
	int ret;

	if (fd < 0)
		return MBEDTLS_ERR_NET_INVALID_CONTEXT;

	ret = write(fd, buf, len);
	if (ret >= 0)
		return ret;

	if (errno == EAGAIN || errno == EWOULDBLOCK)
		return MBEDTLS_ERR_SSL_WANT_WRITE;

	if (errno == EPIPE || errno == ECONNRESET)
		return MBEDTLS_ERR_NET_CONN_RESET;

	if( errno == EINTR )
		return MBEDTLS_ERR_SSL_WANT_WRITE;

	return MBEDTLS_ERR_NET_SEND_FAILED;
}

int
lws_plat_mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len)
{
	int fd = ((mbedtls_net_context *) ctx)->fd;
	int ret;

	if (fd < 0)
		return MBEDTLS_ERR_NET_INVALID_CONTEXT;

	ret = (int)read(fd, buf, len);
	if (ret >= 0)
		return ret;

	if (errno == EAGAIN || errno == EWOULDBLOCK)
		return MBEDTLS_ERR_SSL_WANT_READ;

	if (errno == EPIPE || errno == ECONNRESET)
		return MBEDTLS_ERR_NET_CONN_RESET;

	if (errno == EINTR)
		return MBEDTLS_ERR_SSL_WANT_READ;

	return MBEDTLS_ERR_NET_RECV_FAILED;
}
#endif
