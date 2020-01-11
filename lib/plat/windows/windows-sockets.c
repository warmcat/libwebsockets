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

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#include "private-lib-core.h"


int
lws_send_pipe_choked(struct lws *wsi)
{	struct lws *wsi_eff;

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

	return (int)wsi_eff->sock_send_blocking;
}

int
lws_poll_listen_fd(struct lws_pollfd *fd)
{
	fd_set readfds;
	struct timeval tv = { 0, 0 };

	assert((fd->events & LWS_POLLIN) == LWS_POLLIN);

	FD_ZERO(&readfds);
	FD_SET(fd->fd, &readfds);

	return select(((int)fd->fd) + 1, &readfds, NULL, NULL, &tv);
}

int
lws_plat_set_nonblocking(lws_sockfd_type fd)
{
	u_long optl = 1;
	int result = !!ioctlsocket(fd, FIONBIO, &optl);
	if (result)
	{
		int error = LWS_ERRNO;
		lwsl_err("ioctlsocket FIONBIO 1 failed with error %d\n", error);
	}
	return result;
}

int
lws_plat_set_socket_options(struct lws_vhost *vhost, lws_sockfd_type fd,
			    int unix_skt)
{
	int optval = 1;
	int optlen = sizeof(optval);
	DWORD dwBytesRet;
	struct tcp_keepalive alive;
	int protonbr;
#ifndef _WIN32_WCE
	struct protoent *tcp_proto;
#endif

	if (vhost->ka_time) {
		/* enable keepalive on this socket */
		optval = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
			       (const char *)&optval, optlen) < 0) {
			int error = LWS_ERRNO;
			lwsl_err("setsockopt SO_KEEPALIVE 1 failed with error %d\n", error);
			return 1;
		}

		alive.onoff = TRUE;
		alive.keepalivetime = vhost->ka_time * 1000;
		alive.keepaliveinterval = vhost->ka_interval * 1000;

		if (WSAIoctl(fd, SIO_KEEPALIVE_VALS, &alive, sizeof(alive),
			     NULL, 0, &dwBytesRet, NULL, NULL)) {
			int error = LWS_ERRNO;
			lwsl_err("WSAIoctl SIO_KEEPALIVE_VALS 1 %lu %lu failed with error %d\n", alive.keepalivetime, alive.keepaliveinterval, error);
			return 1;
		}
	}

	/* Disable Nagle */
	optval = 1;
#ifndef _WIN32_WCE
	tcp_proto = getprotobyname("TCP");
	if (!tcp_proto) {
		int error = LWS_ERRNO;
		lwsl_warn("getprotobyname(\"TCP\") failed with error, falling back to 6 %d\n", error);
		protonbr = 6;  /* IPPROTO_TCP */
	} else
		protonbr = tcp_proto->p_proto;
#else
	protonbr = 6;
#endif

	if (setsockopt(fd, protonbr, TCP_NODELAY, (const char *)&optval, optlen) ) {
		int error = LWS_ERRNO;
		lwsl_warn("setsockopt TCP_NODELAY 1 failed with error %d\n", error);
	}


	return lws_plat_set_nonblocking(fd);
}


int
lws_interface_to_sa(int ipv6,
		const char *ifname, struct sockaddr_in *addr, size_t addrlen)
{
#ifdef LWS_WITH_IPV6
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;

	if (ipv6) {
		if (lws_plat_inet_pton(AF_INET6, ifname, &addr6->sin6_addr) == 1) {
			return LWS_ITOSA_USABLE;
		}
	}
#endif

	long long address = inet_addr(ifname);

	if (address == INADDR_NONE) {
		struct hostent *entry = gethostbyname(ifname);
		if (entry)
			address = ((struct in_addr *)entry->h_addr_list[0])->s_addr;
	}

	if (address == INADDR_NONE)
		return LWS_ITOSA_NOT_EXIST;

	addr->sin_addr.s_addr = (unsigned long)(lws_intptr_t)address;

	return LWS_ITOSA_USABLE;
}

void
lws_plat_insert_socket_into_fds(struct lws_context *context, struct lws *wsi)
{
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	int n = LWS_POLLIN | LWS_POLLHUP | FD_CONNECT;

	if (wsi->udp) {
		lwsl_info("%s: UDP\n", __func__);
		n = LWS_POLLIN;
	}

	pt->fds[pt->fds_count++].revents = 0;
	WSAEventSelect(wsi->desc.sockfd, pt->events, n);
}

void
lws_plat_delete_socket_from_fds(struct lws_context *context,
						struct lws *wsi, int m)
{
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

	pt->fds_count--;
}


int
lws_plat_check_connection_error(struct lws *wsi)
{
	int optVal;
	int optLen = sizeof(int);

	if (getsockopt(wsi->desc.sockfd, SOL_SOCKET, SO_ERROR,
			   (char*)&optVal, &optLen) != SOCKET_ERROR && optVal &&
		optVal != LWS_EALREADY && optVal != LWS_EINPROGRESS &&
		optVal != LWS_EWOULDBLOCK && optVal != WSAEINVAL) {
		   lwsl_debug("Connect failed SO_ERROR=%d\n", optVal);
		   return 1;
	}

	return 0;
}

int
lws_plat_change_pollfd(struct lws_context *context,
			  struct lws *wsi, struct lws_pollfd *pfd)
{
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	long e = LWS_POLLHUP | FD_CONNECT;

	if ((pfd->events & LWS_POLLIN))
		e |= LWS_POLLIN;

	if ((pfd->events & LWS_POLLOUT))
		e |= LWS_POLLOUT;

	if (WSAEventSelect(wsi->desc.sockfd, pt->events, e) != SOCKET_ERROR)
		return 0;

	lwsl_err("WSAEventSelect() failed with error %d\n", LWS_ERRNO);

	return 1;
}

const char *
lws_plat_inet_ntop(int af, const void *src, char *dst, int cnt)
{
	WCHAR *buffer;
	DWORD bufferlen = cnt;
	BOOL ok = FALSE;

	buffer = lws_malloc(bufferlen * 2, "inet_ntop");
	if (!buffer) {
		lwsl_err("Out of memory\n");
		return NULL;
	}

	if (af == AF_INET) {
		struct sockaddr_in srcaddr;
		memset(&srcaddr, 0, sizeof(srcaddr));
		srcaddr.sin_family = AF_INET;
		memcpy(&(srcaddr.sin_addr), src, sizeof(srcaddr.sin_addr));

		if (!WSAAddressToStringW((struct sockaddr*)&srcaddr, sizeof(srcaddr), 0, buffer, &bufferlen))
			ok = TRUE;
#ifdef LWS_WITH_IPV6
	} else if (af == AF_INET6) {
		struct sockaddr_in6 srcaddr;
		memset(&srcaddr, 0, sizeof(srcaddr));
		srcaddr.sin6_family = AF_INET6;
		memcpy(&(srcaddr.sin6_addr), src, sizeof(srcaddr.sin6_addr));

		if (!WSAAddressToStringW((struct sockaddr*)&srcaddr, sizeof(srcaddr), 0, buffer, &bufferlen))
			ok = TRUE;
#endif
	} else
		lwsl_err("Unsupported type\n");

	if (!ok) {
		int rv = WSAGetLastError();
		lwsl_err("WSAAddressToString() : %d\n", rv);
	} else {
		if (WideCharToMultiByte(CP_ACP, 0, buffer, bufferlen, dst, cnt, 0, NULL) <= 0)
			ok = FALSE;
	}

	lws_free(buffer);
	return ok ? dst : NULL;
}

int
lws_plat_inet_pton(int af, const char *src, void *dst)
{
	WCHAR *buffer;
	DWORD bufferlen = (int)strlen(src) + 1;
	BOOL ok = FALSE;

	buffer = lws_malloc(bufferlen * 2, "inet_pton");
	if (!buffer) {
		lwsl_err("Out of memory\n");
		return -1;
	}

	if (MultiByteToWideChar(CP_ACP, 0, src, bufferlen, buffer, bufferlen) <= 0) {
		lwsl_err("Failed to convert multi byte to wide char\n");
		lws_free(buffer);
		return -1;
	}

	if (af == AF_INET) {
		struct sockaddr_in dstaddr;
		int dstaddrlen = sizeof(dstaddr);

		memset(&dstaddr, 0, sizeof(dstaddr));
		dstaddr.sin_family = AF_INET;

		if (!WSAStringToAddressW(buffer, af, 0, (struct sockaddr *) &dstaddr, &dstaddrlen)) {
			ok = TRUE;
			memcpy(dst, &dstaddr.sin_addr, sizeof(dstaddr.sin_addr));
		}
#ifdef LWS_WITH_IPV6
	} else if (af == AF_INET6) {
		struct sockaddr_in6 dstaddr;
		int dstaddrlen = sizeof(dstaddr);

		memset(&dstaddr, 0, sizeof(dstaddr));
		dstaddr.sin6_family = AF_INET6;

		if (!WSAStringToAddressW(buffer, af, 0, (struct sockaddr *) &dstaddr, &dstaddrlen)) {
			ok = TRUE;
			memcpy(dst, &dstaddr.sin6_addr, sizeof(dstaddr.sin6_addr));
		}
#endif
	} else
		lwsl_err("Unsupported type\n");

	if (!ok) {
		int rv = WSAGetLastError();
		lwsl_err("WSAAddressToString() : %d\n", rv);
	}

	lws_free(buffer);
	return ok ? 1 : -1;
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

