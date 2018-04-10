/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2018 Andy Green <andy@warmcat.com>
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

#include <private-libwebsockets.h>

static int
wops_handle_POLLIN_pipe(struct lws_context_per_thread *pt, struct lws *wsi,
			struct lws_pollfd *pollfd)
{
#if !defined(WIN32) && !defined(_WIN32)
	char s[10];
	int n;

	/*
	 * discard the byte(s) that signaled us
	 * We really don't care about the number of bytes, but coverity
	 * thinks we should.
	 */
	n = read(wsi->desc.sockfd, s, sizeof(s));
	(void)n;
	if (n < 0)
		return LWS_HPI_RET_CLOSE_HANDLED;
#endif
	/*
	 * the poll() wait, or the event loop for libuv etc is a
	 * process-wide resource that we interrupted.  So let every
	 * protocol that may be interested in the pipe event know that
	 * it happened.
	 */
	if (lws_broadcast(wsi->context, LWS_CALLBACK_EVENT_WAIT_CANCELLED,
			  NULL, 0)) {
		lwsl_info("closed in event cancel\n");
		return LWS_HPI_RET_CLOSE_HANDLED;
	}

	return LWS_HPI_RET_HANDLED;
}

static int
wops_handle_POLLOUT_pipe(struct lws *wsi)
{
	return LWS_HP_RET_USER_SERVICE;
}

struct lws_protocol_ops wire_ops_pipe = {
	"pipe",
	wops_handle_POLLIN_pipe,
	wops_handle_POLLOUT_pipe,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};
