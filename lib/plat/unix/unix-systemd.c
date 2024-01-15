/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2024 Andy Green <andy@warmcat.com>
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

#include <sys/socket.h>
#include <systemd/sd-daemon.h>

#include "private-lib-core.h"


int
lws_systemd_inherited_fd(unsigned int index,
			 struct lws_context_creation_info *info)
{
	unsigned int inherited = (unsigned int)sd_listen_fds(0);

	if (index >= inherited)
		return -1;

	info->vh_listen_sockfd = (int)(SD_LISTEN_FDS_START + index);

	if (sd_is_socket_unix(info->vh_listen_sockfd, 0, 0, NULL, 0)) {
		info->options |= LWS_SERVER_OPTION_UNIX_SOCK;
		info->port = 0;
	}

	if (sd_is_socket_inet(info->vh_listen_sockfd, AF_UNSPEC, 0, 1, 0)) {
		struct sockaddr_storage addr;
		socklen_t addrlen = sizeof(addr);

		if (getsockname(info->vh_listen_sockfd,
				(struct sockaddr *)&addr, &addrlen)) {
			lwsl_err("%s: getsockname failed for fd %d\n",
				 __func__, info->vh_listen_sockfd);
			return -1;
		}

		switch (((struct sockaddr *)&addr)->sa_family) {
		case AF_INET:
			info->port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
			lwsl_info("%s: inet socket %d\n", __func__, info->port);
			break;
		case AF_INET6:
			info->port = ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
			lwsl_info("%s: inet6 socket %d\n", __func__, info->port);
			break;
		}

		if (sd_is_socket_inet(info->vh_listen_sockfd, AF_INET6, 0, 1, 0))
			info->options |= LWS_SERVER_OPTION_IPV6_V6ONLY_MODIFY |
				         LWS_SERVER_OPTION_IPV6_V6ONLY_VALUE;

		if (sd_is_socket_inet(info->vh_listen_sockfd, AF_INET, 0, 1, 0)) {
			info->options &= (uint64_t)~(LWS_SERVER_OPTION_IPV6_V6ONLY_MODIFY |
				         LWS_SERVER_OPTION_IPV6_V6ONLY_VALUE);
			info->options |= LWS_SERVER_OPTION_DISABLE_IPV6;
		}
	}

	return 0;
}
