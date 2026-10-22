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

/*
 * The small lookup scheme's slots: all of them, or with tsi >= 0, only
 * service thread tsi's
 */

static struct lws_fd_slot *
lookup_slots(const struct lws_context *cx, int tsi, struct lws_fd_slot **done)
{
	struct lws_fd_slot *s = cx->lws_lookup_slots;

	if (tsi < 0) {
		*done = s + (size_t)cx->count_threads * cx->fd_limit_per_thread;

		return s;
	}

	s += (size_t)tsi * cx->fd_limit_per_thread;
	*done = s + cx->fd_limit_per_thread;

	return s;
}

struct lws *
wsi_from_fd(const struct lws_context *context, int fd)
{
	struct lws_fd_slot *s, *done;

	if (!context->max_fds_unrelated_to_ulimit)
		return context->lws_lookup[fd - lws_plat_socket_offset()];

	/*
	 * slow fds handling: an fd is open in only one thread's table at a
	 * time, the one its wsi is serviced on, so the first match is it
	 */

	if (fd < 0)
		return NULL;

	for (s = lookup_slots(context, -1, &done); s < done; s++)
		if (s->fd == fd)
			return s->wsi;

	return NULL;
}

#if defined(_DEBUG)
int
sanity_assert_no_wsi_traces(const struct lws_context *context, struct lws *wsi)
{
	struct lws_fd_slot *s, *done;
	int occurrences = 0;
	int expected = 0;

#if defined(LWS_WITH_CLIENT)
	if (lws_socket_is_valid(wsi->io->desc.sockfd))
		expected++;
	/*
	 * parallel_count is only ever nonzero while parallel_conns is
	 * allocated, but we are also called from the client connect
	 * failure paths, ie, from the OOM path where the racer array
	 * allocation itself just failed
	 */
	if (wsi->io->parallel_conns)
		for (int i = 0; i < wsi->io->parallel_count; i++)
			if (wsi->io->parallel_conns[i].is_valid)
				expected++;
#endif

	if (!context->max_fds_unrelated_to_ulimit)
		/* can't tell */
		return 0;

	/* slow fds handling: a wsi is only ever in its own thread's slots */

	for (s = lookup_slots(context, wsi->tsi, &done); s < done; s++)
		if (s->wsi == wsi)
			occurrences++;

	if (occurrences <= expected)
		return 0;

	assert(0); /* this wsi is still mentioned inside lws too many times */

	return 1;
}

int
sanity_assert_no_sockfd_traces(const struct lws_context *context,
			       lws_sockfd_type sfd)
{
#if LWS_MAX_SMP > 1
	/*
	 * We can't really do this test... another thread can accept and
	 * reuse the closed fd
	 */
	return 0;
#else
	struct lws_fd_slot *s, *done;

	if (sfd == LWS_SOCK_INVALID)
		return 0;

	if (!context->max_fds_unrelated_to_ulimit) {
		struct lws *w;

		if (!context->lws_lookup)
			return 0;

		w = context->lws_lookup[sfd - lws_plat_socket_offset()];
		if (!w)
			return 0;

		lwsl_err("%s: fd %d still in lws_lookup as %s (wsistate 0x%x, "
			 "fds pos %d, its sockfd %d)\n", __func__, (int)sfd,
			 lws_wsi_tag(w), (unsigned int)w->wsistate,
			 w->io->position_in_fds_table, (int)w->io->desc.sockfd);
		assert(0); /* the fd is still in use */
		return 1;
	}

	/* slow fds handling: confirm the sfd not already in use */

	if (!context->lws_lookup_slots)
		return 0;

	for (s = lookup_slots(context, -1, &done); s < done; s++)
		if (s->fd == sfd)
			break;

	if (s == done)
		return 0;

	lwsl_err("%s: fd %d still in lws_lookup_slots[%d] as %s (wsistate "
		 "0x%x, fds pos %d)\n", __func__, (int)sfd,
		 (int)(s - context->lws_lookup_slots), lws_wsi_tag(s->wsi),
		 (unsigned int)s->wsi->wsistate,
		 s->wsi->io->position_in_fds_table);
	assert(0); /* this fd is still in the tables */

	return 1;
#endif
}
#endif

/*
 * Enter wsi in the table for its current io->desc.sockfd: a client racing
 * connects is entered once for each of its racer sockets, with the racer fd
 * swapped into desc while it is.  The caller holds the wsi's pt lock.
 */

int
insert_wsi(const struct lws_context *context, struct lws *wsi)
{
	struct lws_fd_slot *s, *done;

	if (sanity_assert_no_wsi_traces(context, wsi))
		return 0;

	if (!context->max_fds_unrelated_to_ulimit) {
		assert(context->lws_lookup[wsi->io->desc.sockfd -
		                           lws_plat_socket_offset()] == 0);

		context->lws_lookup[wsi->io->desc.sockfd - \
				  lws_plat_socket_offset()] = wsi;

		return 0;
	}

	/* slow fds handling: confirm fd isn't already in use by a wsi */

	if (sanity_assert_no_sockfd_traces(context, wsi->io->desc.sockfd))
		return 0;

	/* find an empty slot of the wsi's own thread */

	for (s = lookup_slots(context, wsi->tsi, &done); s < done; s++)
		if (s->fd == LWS_SOCK_INVALID)
			break;

	if (s == done) {
		lwsl_err("%s: reached max fds\n", __func__);
		return 1;
	}

	s->wsi = wsi;
	s->fd = wsi->io->desc.sockfd;

	return 0;
}

/* the caller holds the pt lock of the wsi the fd was entered for */

void
delete_from_fd(const struct lws_context *context, int fd)
{
	struct lws_fd_slot *s, *done;

	if (!context->max_fds_unrelated_to_ulimit) {
		if (context->lws_lookup) {
			assert((int)context->max_fds > fd - lws_plat_socket_offset());
			context->lws_lookup[fd - lws_plat_socket_offset()] = NULL;
		}

		return;
	}

	/*
	 * slow fds handling: the fd is still open, so it is only in the
	 * slots of the thread whose wsi it is
	 */

	assert(context->lws_lookup_slots);

	if (fd < 0)
		return;

	for (s = lookup_slots(context, -1, &done); s < done; s++)
		if (s->fd == fd) {
			s->fd = LWS_SOCK_INVALID;
			s->wsi = NULL;
			break;
		}

#if defined(_DEBUG)
	while (s < done) {
		if (s->fd == fd) {
			lwsl_err("%s: fd %d in lws_lookup_slots again at %d\n",
				 __func__, fd,
				 (int)(s - context->lws_lookup_slots));
			assert(0);
		}
		s++;
	}
#endif
}

/* the caller holds the wsi's pt lock */

void
delete_from_fdwsi(const struct lws_context *context, struct lws *wsi)
{
	struct lws_fd_slot *s, *done;

	if (!context->max_fds_unrelated_to_ulimit)
		return;

	/* slow fds handling: a wsi is only ever in its own thread's slots */

	for (s = lookup_slots(context, wsi->tsi, &done); s < done; s++)
		if (s->wsi == wsi) {
			s->fd = LWS_SOCK_INVALID;
			s->wsi = NULL;
		}
}

void
lws_plat_insert_socket_into_fds(struct lws_context *context, struct lws *wsi)
{
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

	if (context->event_loop_ops->io || context->event_loop_ops->io_parallel)
		_lws_event_loop_ops_io(wsi, LWS_EV_START | LWS_EV_READ);

	pt->fds[pt->fds_count++].revents = 0;
}

void
lws_plat_delete_socket_from_fds(struct lws_context *context,
						struct lws *wsi, int m)
{
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

	if (context->event_loop_ops->io || context->event_loop_ops->io_parallel)
		_lws_event_loop_ops_io(wsi,
				LWS_EV_STOP | LWS_EV_READ | LWS_EV_WRITE);

	pt->fds_count--;
}

int
lws_plat_change_pollfd(struct lws_context *context,
		      struct lws *wsi, struct lws_pollfd *pfd)
{
	return 0;
}
