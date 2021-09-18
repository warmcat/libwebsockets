/*
 * lws-minimal-secure-streams-custom-proxy-transport
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *                         Kutoga <kutoga@user.github.invalid>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 *
 * This represents some existing application event loop that liblws-sspc must
 * cooperate with.
 */

#include "private.h"

custom_poll_ctx_t a_cpcx;

static struct pollfd *
custom_poll_find_fd(custom_poll_ctx_t *cpcx, lws_sockfd_type fd)
{
	int n;

	for (n = 0; n < cpcx->count_pollfds; n++)
		if (cpcx->pollfds[n].fd == fd)
			return &cpcx->pollfds[n];

	return NULL;
}

int
custom_poll_add_fd(custom_poll_ctx_t *cpcx, lws_sockfd_type fd, int events,
		   void *priv)
{
	struct pollfd *pfd;

	lwsl_info("%s: ADD fd %d, ev %d\n", __func__, fd, events);

	pfd = custom_poll_find_fd(cpcx, fd);
	if (pfd) {
		lwsl_err("%s: ADD fd %d already in ext table\n", __func__, fd);
		return 1;
	}

	if (cpcx->count_pollfds == LWS_ARRAY_SIZE(cpcx->pollfds)) {
		lwsl_err("%s: no room left\n", __func__);
		return 1;
	}

	cpcx->priv[cpcx->count_pollfds] = priv;
	pfd = &cpcx->pollfds[cpcx->count_pollfds++];
	pfd->fd = fd;
	pfd->events = (short)events;
	pfd->revents = 0;

	return 0;
}

int
custom_poll_del_fd(custom_poll_ctx_t *cpcx, lws_sockfd_type fd)
{
	struct pollfd *pfd;

	lwsl_info("%s: DEL fd %d\n", __func__, fd);

	pfd = custom_poll_find_fd(cpcx, fd);
	if (!pfd) {
		lwsl_err("%s: DEL fd %d missing in ext table\n", __func__, fd);
		return 1;
	}

	if (cpcx->count_pollfds > 1)
		*pfd = cpcx->pollfds[cpcx->count_pollfds - 1];

	cpcx->count_pollfds--;

	return 0;
}

int
custom_poll_change_fd(custom_poll_ctx_t *cpcx, lws_sockfd_type fd,
		     int events_add, int events_remove)
{
	struct pollfd *pfd;

	lwsl_info("%s: CHG fd %d, ev_add %d, ev_rem %d\n", __func__, fd,
			events_add, events_remove);

	pfd = custom_poll_find_fd(cpcx, fd);
	if (!pfd)
		return 1;

	pfd->events = (short)((pfd->events & (~events_remove)) | events_add);

	return 0;
}

int
custom_poll_run(custom_poll_ctx_t *cpcx)
{
	int n;

	while (!interrupted) {

		lws_usec_t timeout_us = 2000000000, now = lws_now_usecs();

		if (cpcx->scheduler.count) {
			lws_sorted_usec_list_t *sul = (lws_sorted_usec_list_t *)
					lws_dll2_get_head(&cpcx->scheduler);
			if (sul->us < now)
				timeout_us = 0;
			else
				timeout_us = sul->us - now;
		}

//		lwsl_notice("%s: entering poll wait %dms\n", __func__, (int)(timeout_us / 1000));

		n = poll(cpcx->pollfds, (nfds_t)cpcx->count_pollfds, (int)(timeout_us / 1000));

//		lwsl_notice("%s: exiting poll after %lluus\n", __func__,
//				(unsigned long long)(lws_now_usecs() - now));

		do {
			lws_sorted_usec_list_t *sul = (lws_sorted_usec_list_t *)
				lws_dll2_get_head(&cpcx->scheduler);

			if (!sul)
				break;

			if (sul->us > now)
				break;

			lws_dll2_remove(&sul->list);
			sul->cb(sul);
		} while (1);

		if (n <= 0)
			continue;

		/* service anything that has active revents */

		for (n = 0; n < cpcx->count_pollfds; n++) {
			int m;

			if (!cpcx->pollfds[n].revents)
				continue;

			/*
			 * the only fd we registered in this example is the
			 * transport fd, so we miss out the code to match the
			 * fd to the right callback
			 */

			m = custom_transport_event(&cpcx->pollfds[n], cpcx->priv[n]);
			if (m < 0) {
				custom_poll_del_fd(cpcx, cpcx->pollfds[n].fd);
			}
		}
	}

	return 0;
}
