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

void
lws_plat_insert_socket_into_fds(struct lws_context *context, struct lws *wsi)
{
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

	pt->fds[pt->fds_count++].revents = 0;
}

void
lws_plat_delete_socket_from_fds(struct lws_context *context,
						struct lws *wsi, int m)
{
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

	pt->fds_count--;
}

int
lws_plat_change_pollfd(struct lws_context *context,
		      struct lws *wsi, struct lws_pollfd *pfd)
{
	return 0;
}

/*
 * The lws_lookup[] index is the lwip socket slot number, which lwip hands out
 * globally and independently of anything lws knows about... so it must be
 * range-checked here, it cannot be inferred from context->max_fds.
 */

static int
lws_plat_lookup_index(const struct lws_context *context, int fd)
{
	int idx = fd - lws_plat_socket_offset();

	if (!context->lws_lookup || idx < 0 ||
	    (unsigned int)idx >= lws_plat_lookup_entries())
		return -1;

	return idx;
}

int
insert_wsi(const struct lws_context *context, struct lws *wsi)
{
	int idx = lws_plat_lookup_index(context, wsi->desc.sockfd);

	if (idx < 0) {
		lwsl_err("%s: socket fd %d outside lookup table\n", __func__,
			 wsi->desc.sockfd);

		return 1;
	}

	assert(context->lws_lookup[idx] == 0);

	context->lws_lookup[idx] = wsi;

	return 0;
}

struct lws *
wsi_from_fd(const struct lws_context *context, int fd)
{
	int idx = lws_plat_lookup_index(context, fd);

	if (idx < 0)
		return NULL;

	return context->lws_lookup[idx];
}

int
delete_from_fd(const struct lws_context *context, int fd)
{
	int idx = lws_plat_lookup_index(context, fd);

	if (idx < 0)
		return 1;

	context->lws_lookup[idx] = NULL;

	return 0;
}
