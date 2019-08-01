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

#define _GNU_SOURCE
#include "core/private.h"

struct lws *
wsi_from_fd(const struct lws_context *context, int fd)
{
	struct lws **p, **done;

	if (!context->max_fds_unrelated_to_ulimit)
		return context->lws_lookup[fd - lws_plat_socket_offset()];

	/* slow fds handling */

	p = context->lws_lookup;
	done = &p[context->max_fds];

	while (p != done) {
		if (*p && (*p)->desc.sockfd == fd)
			return *p;
		p++;
	}

	return NULL;
}

int
insert_wsi(const struct lws_context *context, struct lws *wsi)
{
	struct lws **p, **done;

	if (!context->max_fds_unrelated_to_ulimit) {
		assert(context->lws_lookup[wsi->desc.sockfd -
		                           lws_plat_socket_offset()] == 0);

		context->lws_lookup[wsi->desc.sockfd - \
				  lws_plat_socket_offset()] = wsi;

		return 0;
	}

	/* slow fds handling */

	p = context->lws_lookup;
	done = &p[context->max_fds];

#if defined(_DEBUG)

	/* confirm it doesn't already exist */

	while (p != done && *p != wsi)
		p++;

	assert(p == done);
	p = context->lws_lookup;

	/* confirm fd doesn't already exist */

	while (p != done && (!*p || (*p && (*p)->desc.sockfd != wsi->desc.sockfd)))
		p++;

	if (p != done) {
		lwsl_err("%s: wsi %p already says it has fd %d\n",
				__func__, *p, wsi->desc.sockfd);
		assert(0);
	}
	p = context->lws_lookup;
#endif

	/* find an empty slot */

	while (p != done && *p)
		p++;

	if (p == done) {
		lwsl_err("%s: reached max fds\n", __func__);
		return 1;
	}

	*p = wsi;

	return 0;
}

void
delete_from_fd(const struct lws_context *context, int fd)
{

	struct lws **p, **done;

	if (!context->max_fds_unrelated_to_ulimit) {
		context->lws_lookup[fd - lws_plat_socket_offset()] = NULL;

		return;
	}

	/* slow fds handling */

	p = context->lws_lookup;
	done = &p[context->max_fds];

	/* find the match */

	while (p != done && (!*p || (*p && (*p)->desc.sockfd != fd)))
		p++;

	if (p == done)
		lwsl_err("%s: fd %d not found\n", __func__, fd);
	else
		*p = NULL;

#if defined(_DEBUG)
	p = context->lws_lookup;
	while (p != done && (!*p || (*p && (*p)->desc.sockfd != fd)))
		p++;

	if (p != done) {
		lwsl_err("%s: fd %d in lws_lookup again at %d\n", __func__,
				fd, (int)(p - context->lws_lookup));
		assert(0);
	}
#endif
}

void
lws_plat_insert_socket_into_fds(struct lws_context *context, struct lws *wsi)
{
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

	if (context->event_loop_ops->io)
		context->event_loop_ops->io(wsi, LWS_EV_START | LWS_EV_READ);

	pt->fds[pt->fds_count++].revents = 0;
}

void
lws_plat_delete_socket_from_fds(struct lws_context *context,
						struct lws *wsi, int m)
{
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

	if (context->event_loop_ops->io)
		context->event_loop_ops->io(wsi,
				LWS_EV_STOP | LWS_EV_READ | LWS_EV_WRITE);

	pt->fds_count--;
}

int
lws_plat_change_pollfd(struct lws_context *context,
		      struct lws *wsi, struct lws_pollfd *pfd)
{
	return 0;
}
