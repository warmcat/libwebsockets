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

int
lws_send_pipe_choked(struct lws *wsi)
{
	struct lws *wsi_eff = wsi;
	fd_set writefds;
	struct timeval tv = { 0, 0 };
	int n;
#if defined(LWS_WITH_HTTP2)
	wsi_eff = lws_get_network_wsi(wsi);
#endif

	/* the fact we checked implies we avoided back-to-back writes */
	wsi_eff->could_have_pending = 0;

	/* treat the fact we got a truncated send pending as if we're choked */
	if (lws_has_buffered_out(wsi)
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	    || wsi->http.comp_ctx.buflist_comp ||
	       wsi->http.comp_ctx.may_have_more
#endif
	)
		return 1;

	FD_ZERO(&writefds);
	FD_SET(wsi_eff->desc.sockfd, &writefds);

	n = select(wsi_eff->desc.sockfd + 1, NULL, &writefds, NULL, &tv);
	if (n < 0)
		return 1; /* choked */

	return !n; /* n = 0 = not writable = choked */
}

int
lws_poll_listen_fd(struct lws_pollfd *fd)
{
	fd_set readfds;
	struct timeval tv = { 0, 0 };

	FD_ZERO(&readfds);
	FD_SET(fd->fd, &readfds);

	return select(fd->fd + 1, &readfds, NULL, NULL, &tv);
}

int
lws_plat_check_connection_error(struct lws *wsi)
{
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
    defined(__OpenBSD__)
	struct protoent *tcp_proto;
#endif

	if (vhost->ka_time) {
		/* enable keepalive on this socket */
		optval = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
			       (const void *)&optval, optlen) < 0)
			return 1;

#if defined(__APPLE__) || \
    defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || \
    defined(__NetBSD__) || \
        defined(__CYGWIN__) || defined(__OpenBSD__) || defined (__sun)

		/*
		 * didn't find a way to set these per-socket, need to
		 * tune kernel systemwide values
		 */
#else
		/* set the keepalive conditions we want on it too */
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

	/* Disable Nagle */
	optval = 1;
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &optval, optlen) < 0)
		return 1;

	return lws_plat_set_nonblocking(fd);
}

/* cast a struct sockaddr_in6 * into addr for ipv6 */

int
lws_interface_to_sa(int ipv6, const char *ifname, struct sockaddr_in *addr,
		    size_t addrlen)
{
#if 0
	int rc = LWS_ITOSA_NOT_EXIST;

	struct ifaddrs *ifr;
	struct ifaddrs *ifc;
#ifdef LWS_WITH_IPV6
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
#endif

	getifaddrs(&ifr);
	for (ifc = ifr; ifc != NULL && rc; ifc = ifc->ifa_next) {
		if (!ifc->ifa_addr)
			continue;

		lwsl_info(" interface %s vs %s\n", ifc->ifa_name, ifname);

		if (strcmp(ifc->ifa_name, ifname))
			continue;

		switch (ifc->ifa_addr->sa_family) {
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

	if (rc == LWS_ITOSA_NOT_EXIST) {
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
#endif

	return LWS_ITOSA_NOT_EXIST;
}

const char *
lws_plat_inet_ntop(int af, const void *src, char *dst, int cnt)
{
	return inet_ntop(af, src, dst, cnt);
}

int
lws_plat_inet_pton(int af, const char *src, void *dst)
{
	return 1; //  inet_pton(af, src, dst);
}

int
lws_plat_ifname_to_hwaddr(int fd, const char *ifname, uint8_t *hwaddr, int len)
{
	lwsl_err("%s: UNIMPLEMENTED on this platform\n", __func__);

	return -1;
}

int
lws_plat_rawudp_broadcast(uint8_t *p, const uint8_t *canned, int canned_len,
			  int n, int fd, const char *iface)
{
	lwsl_err("%s: UNIMPLEMENTED on this platform\n", __func__);

	return -1;
}

int
lws_plat_if_up(const char *ifname, int fd, int up)
{
	lwsl_err("%s: UNIMPLEMENTED on this platform\n", __func__);

	return -1;
}

int
lws_plat_BINDTODEVICE(lws_sockfd_type fd, const char *ifname)
{
	lwsl_err("%s: UNIMPLEMENTED on this platform\n", __func__);

	return -1;
}

int
lws_plat_ifconfig_ip(const char *ifname, int fd, uint8_t *ip, uint8_t *mask_ip,
			uint8_t *gateway_ip)
{
	lwsl_err("%s: UNIMPLEMENTED on this platform\n", __func__);

	return -1;
}
