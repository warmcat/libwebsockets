/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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

#include <lwip/sockets.h>

int
lws_plat_pipe_create(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
#if defined(LWS_WITH_IPV4)
	struct sockaddr_in *si = &wsi->a.context->frt_pipe_si;
#else
	struct sockaddr_in6 *si = &wsi->a.context->frt_pipe_si;
#endif
	lws_sockfd_type *fd = pt->dummy_pipe_fds;
	socklen_t sl;

	/*
	 * There's no pipe abstraction on lwip / freertos... use a UDP socket
	 * listening on 127.0.0.1:xxxx and send a byte to it from a second UDP
	 * socket to cancel the wait.
	 *
	 * Set the port to 0 at the bind, so lwip will choose a free one in the
	 * ephemeral range for us.
	 */

#if defined(LWS_WITH_IPV4)
	fd[0] = lwip_socket(AF_INET, SOCK_DGRAM, 0);
	if (fd[0] < 0)
		goto bail;

	fd[1] = lwip_socket(AF_INET, SOCK_DGRAM, 0);
	if (fd[1] < 0)
		goto bail;

	/*
	 * No need for memset since it's in zalloc'd context... it's in the
	 * context so we can reuse the prepared sockaddr to send tp fd[0] whem
	 * we want to cancel the wait
	 */

	si->sin_family = AF_INET;
	si->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	si->sin_port = 0;

	if (lwip_bind(fd[1], (const struct sockaddr *)si, sizeof(*si)) < 0)
		goto bail;

	si->sin_port = 0;

	if (lwip_bind(fd[0], (const struct sockaddr *)si, sizeof(*si)) < 0)
		goto bail;
#else
	fd[0] = lwip_socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd[0] < 0)
		goto bail;

	fd[1] = lwip_socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd[1] < 0)
		goto bail;

	si->sin6_family = AF_INET6;
	si->sin6_addr = in6addr_loopback;
	si->sin6_port = 0;

	if (lwip_bind(fd[1], (const struct sockaddr *)si, sizeof(*si)) < 0)
		goto bail;

	si->sin6_port = 0;

	if (lwip_bind(fd[0], (const struct sockaddr *)si, sizeof(*si)) < 0)
		goto bail;
#endif

	/*
	 * Query the socket to find the full sockaddr it wants to be addressed
	 * by, including the port that lwip chose, and connect() the sending
	 * socket to it.
	 *
	 * The sockaddr itself must not be stashed anywhere per-context: this
	 * is called once per pt and each pt has its own dummy_pipe_fds[], so a
	 * single context-level copy would just hold whichever pt was created
	 * last and lws_cancel_service_pt() would then wake the wrong thread.
	 * connect()ing binds the peer to the socket instead, which is
	 * inherently per-pt (and also stops any other local socket being able
	 * to deliver to our wait socket).
	 */

	sl = sizeof(*si);
	if (lwip_getsockname(fd[0], (struct sockaddr *)si, &sl))
		goto bail;

	if (lwip_connect(fd[1], (const struct sockaddr *)si, sizeof(*si)) < 0)
		goto bail;

#if defined(LWS_WITH_IPV4)
	lwsl_info("%s: cancel UDP skt port %d\n", __func__,
		  ntohs(si->sin_port));
#else
	lwsl_info("%s: cancel UDP skt port %d\n", __func__,
		  ntohs(si->sin6_port));
#endif

	return 0;

bail:
	lwsl_err("%s: failed\n", __func__);

	return 1;
}

int
lws_plat_pipe_signal(struct lws_context *ctx, int tsi)
{
	struct lws_context_per_thread *pt = &ctx->pt[tsi];
	lws_sockfd_type *fd = pt->dummy_pipe_fds;
	uint8_t u = 0;
	int n;

	/*
	 * Send a single UDP byte payload to this pt's listening socket fd[0],
	 * forcing the event loop wait to wake.  fd[1] was connect()ed to it at
	 * pt creation, so no address is needed here and there is no shared
	 * context-level state to get confused between pts.  The UDP send is
	 * supposed to be threadsafe for lwip:
	 *
	 * https://lwip.fandom.com/wiki/LwIP_and_multithreading
	 *
	 * Sockets generally can't be used by more than one application thread
	 * (on udp/raw netconn, doing a sendto/recv is currently possible).
	 */

	n = lwip_send(fd[1], &u, 1, 0);

	return n != 1;
}

void
lws_plat_pipe_close(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	lws_sockfd_type *fd = pt->dummy_pipe_fds;

	if (fd[0] != LWS_SOCK_INVALID)
		close(fd[0]);
	if (fd[1] != LWS_SOCK_INVALID)
		close(fd[1]);

	fd[0] = fd[1] = LWS_SOCK_INVALID;
}

int
lws_plat_pipe_is_fd_assocated(struct lws_context *cx, int tsi, lws_sockfd_type fd)
{
	struct lws_context_per_thread *pt = &cx->pt[tsi];

	return fd == pt->dummy_pipe_fds[0] || fd == pt->dummy_pipe_fds[1];
}
