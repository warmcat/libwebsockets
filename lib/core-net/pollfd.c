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

int
_lws_change_pollfd(struct lws *wsi, int _and, int _or, struct lws_pollargs *pa)
{
#if !defined(LWS_WITH_EVENT_LIBS)
	volatile struct lws_context_per_thread *vpt;
#endif
	struct lws_context_per_thread *pt;
	struct lws_context *context;
	int ret = 0, pa_events;
	struct lws_pollfd *pfd;
	int sampled_tid, tid;

	if (!wsi)
		return 0;

	assert(wsi->position_in_fds_table == LWS_NO_FDS_POS ||
	       wsi->position_in_fds_table >= 0);

	if (wsi->position_in_fds_table == LWS_NO_FDS_POS)
		return 0;

	if (((volatile struct lws *)wsi)->handling_pollout &&
	    !_and && _or == LWS_POLLOUT) {
		/*
		 * Happening alongside service thread handling POLLOUT.
		 * The danger is when he is finished, he will disable POLLOUT,
		 * countermanding what we changed here.
		 *
		 * Instead of changing the fds, inform the service thread
		 * what happened, and ask it to leave POLLOUT active on exit
		 */
		((volatile struct lws *)wsi)->leave_pollout_active = 1;
		/*
		 * by definition service thread is not in poll wait, so no need
		 * to cancel service
		 */

		lwsl_debug("%s: using leave_pollout_active\n", __func__);

		return 0;
	}

	context = wsi->a.context;
	pt = &context->pt[(int)wsi->tsi];

	assert(wsi->position_in_fds_table < (int)pt->fds_count);

#if !defined(LWS_WITH_EVENT_LIBS)
	/*
	 * This only applies when we use the default poll() event loop.
	 *
	 * BSD can revert pa->events at any time, when the kernel decides to
	 * exit from poll().  We can't protect against it using locking.
	 *
	 * Therefore we must check first if the service thread is in poll()
	 * wait; if so, we know we must be being called from a foreign thread,
	 * and we must keep a strictly ordered list of changes we made instead
	 * of trying to apply them, since when poll() exits, which may happen
	 * at any time it would revert our changes.
	 *
	 * The plat code will apply them when it leaves the poll() wait
	 * before doing anything else.
	 */

	vpt = (volatile struct lws_context_per_thread *)pt;

	vpt->foreign_spinlock = 1;
	lws_memory_barrier();

	if (vpt->inside_poll) {
		struct lws_foreign_thread_pollfd *ftp, **ftp1;
		/*
		 * We are certainly a foreign thread trying to change events
		 * while the service thread is in the poll() wait.
		 *
		 * Create a list of changes to be applied after poll() exit,
		 * instead of trying to apply them now.
		 */
		ftp = lws_malloc(sizeof(*ftp), "ftp");
		if (!ftp) {
			vpt->foreign_spinlock = 0;
			lws_memory_barrier();
			ret = -1;
			goto bail;
		}

		ftp->_and = _and;
		ftp->_or = _or;
		ftp->fd_index = wsi->position_in_fds_table;
		ftp->next = NULL;

		lws_pt_lock(pt, __func__);

		/* place at END of list to maintain order */
		ftp1 = (struct lws_foreign_thread_pollfd **)
						&vpt->foreign_pfd_list;
		while (*ftp1)
			ftp1 = &((*ftp1)->next);

		*ftp1 = ftp;
		vpt->foreign_spinlock = 0;
		lws_memory_barrier();

		lws_pt_unlock(pt);

		lws_cancel_service_pt(wsi);

		return 0;
	}

	vpt->foreign_spinlock = 0;
	lws_memory_barrier();
#endif

#if !defined(__linux__)
	/* OSX couldn't see close on stdin pipe side otherwise */
	_or |= LWS_POLLHUP;
#endif

	pfd = &pt->fds[wsi->position_in_fds_table];
	pa->fd = wsi->desc.sockfd;
	lwsl_debug("%s: wsi %p: fd %d events %d -> %d\n", __func__, wsi,
		   pa->fd, pfd->events, (pfd->events & ~_and) | _or);
	pa->prev_events = pfd->events;
	pa->events = pfd->events = (pfd->events & ~_and) | _or;

	if (wsi->mux_substream)
		return 0;

#if defined(LWS_WITH_EXTERNAL_POLL)

	if (wsi->a.vhost &&
	    wsi->a.vhost->protocols[0].callback(wsi,
			    	    	      LWS_CALLBACK_CHANGE_MODE_POLL_FD,
					      wsi->user_space, (void *)pa, 0)) {
		ret = -1;
		goto bail;
	}
#endif

	if (context->event_loop_ops->io) {
		if (_and & LWS_POLLIN)
			context->event_loop_ops->io(wsi,
					LWS_EV_STOP | LWS_EV_READ);

		if (_or & LWS_POLLIN)
			context->event_loop_ops->io(wsi,
					LWS_EV_START | LWS_EV_READ);

		if (_and & LWS_POLLOUT)
			context->event_loop_ops->io(wsi,
					LWS_EV_STOP | LWS_EV_WRITE);

		if (_or & LWS_POLLOUT)
			context->event_loop_ops->io(wsi,
					LWS_EV_START | LWS_EV_WRITE);
	}

	/*
	 * if we changed something in this pollfd...
	 *   ... and we're running in a different thread context
	 *     than the service thread...
	 *       ... and the service thread is waiting ...
	 *         then cancel it to force a restart with our changed events
	 */
	pa_events = pa->prev_events != pa->events;

	if (pa_events) {
		if (lws_plat_change_pollfd(context, wsi, pfd)) {
			lwsl_info("%s failed\n", __func__);
			ret = -1;
			goto bail;
		}
		sampled_tid = pt->service_tid;
		if (sampled_tid && wsi->a.vhost) {
			tid = wsi->a.vhost->protocols[0].callback(wsi,
				     LWS_CALLBACK_GET_THREAD_ID, NULL, NULL, 0);
			if (tid == -1) {
				ret = -1;
				goto bail;
			}
			if (tid != sampled_tid)
				lws_cancel_service_pt(wsi);
		}
	}

bail:
	return ret;
}

#if defined(LWS_WITH_SERVER)
/*
 * Enable or disable listen sockets on this pt globally...
 * it's modulated according to the pt having space for a new accept.
 */
static void
lws_accept_modulation(struct lws_context *context,
		      struct lws_context_per_thread *pt, int allow)
{
	struct lws_vhost *vh = context->vhost_list;
	struct lws_pollargs pa1;

	while (vh) {
		if (vh->lserv_wsi) {
			if (allow)
				_lws_change_pollfd(vh->lserv_wsi,
					   0, LWS_POLLIN, &pa1);
			else
				_lws_change_pollfd(vh->lserv_wsi,
					   LWS_POLLIN, 0, &pa1);
		}
		vh = vh->vhost_next;
	}
}
#endif

#if _LWS_ENABLED_LOGS & LLL_WARN
void
__dump_fds(struct lws_context_per_thread *pt, const char *s)
{
	unsigned int n;

	lwsl_warn("%s: fds_count %u, %s\n", __func__, pt->fds_count, s);

	for (n = 0; n < pt->fds_count; n++) {
		struct lws *wsi = wsi_from_fd(pt->context, pt->fds[n].fd);

		lwsl_warn("  %d: fd %d, wsi %p, pos_in_fds: %d\n",
			n + 1, pt->fds[n].fd, wsi,
			wsi ? wsi->position_in_fds_table : -1);
	}
}
#else
#define __dump_fds(x, y)
#endif

int
__insert_wsi_socket_into_fds(struct lws_context *context, struct lws *wsi)
{
#if defined(LWS_WITH_EXTERNAL_POLL)
	struct lws_pollargs pa = { wsi->desc.sockfd, LWS_POLLIN, 0 };
#endif
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	int ret = 0;

//	__dump_fds(pt, "pre insert");

	lws_pt_assert_lock_held(pt);

	lwsl_debug("%s: %p: tsi=%d, sock=%d, pos-in-fds=%d\n",
		  __func__, wsi, wsi->tsi, wsi->desc.sockfd, pt->fds_count);

	if ((unsigned int)pt->fds_count >= context->fd_limit_per_thread) {
		lwsl_err("Too many fds (%d vs %d)\n", context->max_fds,
				context->fd_limit_per_thread	);
		return 1;
	}

#if !defined(_WIN32)
	if (!wsi->a.context->max_fds_unrelated_to_ulimit &&
	    wsi->desc.sockfd - lws_plat_socket_offset() >= context->max_fds) {
		lwsl_err("Socket fd %d is too high (%d) offset %d\n",
			 wsi->desc.sockfd, context->max_fds,
			 lws_plat_socket_offset());
		return 1;
	}
#endif

	assert(wsi);

#if defined(LWS_WITH_NETLINK)
	assert(wsi->event_pipe || wsi->a.vhost || wsi == pt->netlink);
#else
	assert(wsi->event_pipe || wsi->a.vhost);
#endif
	assert(lws_socket_is_valid(wsi->desc.sockfd));

#if defined(LWS_WITH_EXTERNAL_POLL)

	if (wsi->a.vhost &&
	    wsi->a.vhost->protocols[0].callback(wsi, LWS_CALLBACK_LOCK_POLL,
					   wsi->user_space, (void *) &pa, 1))
		return -1;
#endif

	if (insert_wsi(context, wsi))
		return -1;
	pt->count_conns++;
	wsi->position_in_fds_table = pt->fds_count;

	pt->fds[wsi->position_in_fds_table].fd = wsi->desc.sockfd;
	pt->fds[wsi->position_in_fds_table].events = LWS_POLLIN;
#if defined(LWS_WITH_EXTERNAL_POLL)
	pa.events = pt->fds[pt->fds_count].events;
#endif

	lws_plat_insert_socket_into_fds(context, wsi);

#if defined(LWS_WITH_EXTERNAL_POLL)

	/* external POLL support via protocol 0 */
	if (wsi->a.vhost &&
	    wsi->a.vhost->protocols[0].callback(wsi, LWS_CALLBACK_ADD_POLL_FD,
					   wsi->user_space, (void *) &pa, 0))
		ret =  -1;
#endif
#if defined(LWS_WITH_SERVER)
	/* if no more room, defeat accepts on this service thread */
	if ((unsigned int)pt->fds_count == context->fd_limit_per_thread - 1)
		lws_accept_modulation(context, pt, 0);
#endif

#if defined(LWS_WITH_EXTERNAL_POLL)
	if (wsi->a.vhost &&
	    wsi->a.vhost->protocols[0].callback(wsi, LWS_CALLBACK_UNLOCK_POLL,
					   wsi->user_space, (void *)&pa, 1))
		ret = -1;
#endif

//	__dump_fds(pt, "post insert");

	return ret;
}

int
__remove_wsi_socket_from_fds(struct lws *wsi)
{
	struct lws_context *context = wsi->a.context;
#if defined(LWS_WITH_EXTERNAL_POLL)
	struct lws_pollargs pa = { wsi->desc.sockfd, 0, 0 };
#endif
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	struct lws *end_wsi;
	int v, m, ret = 0;

	lws_pt_assert_lock_held(pt);

//	__dump_fds(pt, "pre remove");

#if !defined(_WIN32)
	if (!wsi->a.context->max_fds_unrelated_to_ulimit &&
	    wsi->desc.sockfd - lws_plat_socket_offset() > context->max_fds) {
		lwsl_err("fd %d too high (%d)\n", wsi->desc.sockfd,
			 context->max_fds);

		return 1;
	}
#endif
#if defined(LWS_WITH_EXTERNAL_POLL)
	if (wsi->a.vhost && wsi->a.vhost->protocols &&
	    wsi->a.vhost->protocols[0].callback(wsi, LWS_CALLBACK_LOCK_POLL,
					   wsi->user_space, (void *)&pa, 1))
		return -1;
#endif

	__lws_same_vh_protocol_remove(wsi);

	/* the guy who is to be deleted's slot index in pt->fds */
	m = wsi->position_in_fds_table;
	
	/* these are the only valid possibilities for position_in_fds_table */
	assert(m == LWS_NO_FDS_POS || (m >= 0 && (unsigned int)m < pt->fds_count));

	if (context->event_loop_ops->io)
		context->event_loop_ops->io(wsi,
				  LWS_EV_STOP | LWS_EV_READ | LWS_EV_WRITE |
				  LWS_EV_PREPARE_DELETION);
/*
	lwsl_notice("%s: wsi=%p, skt=%d, fds pos=%d, end guy pos=%d, endfd=%d\n",
		  __func__, wsi, wsi->desc.sockfd, wsi->position_in_fds_table,
		  pt->fds_count, pt->fds[pt->fds_count - 1].fd); */

	if (m != LWS_NO_FDS_POS) {
		char fixup = 0;

		assert(pt->fds_count && (unsigned int)m != pt->fds_count);

		/* deletion guy's lws_lookup entry needs nuking */
		delete_from_fd(context, wsi->desc.sockfd);

		if ((unsigned int)m != pt->fds_count - 1) {
			/* have the last guy take up the now vacant slot */
			pt->fds[m] = pt->fds[pt->fds_count - 1];
			fixup = 1;
		}

		pt->fds[pt->fds_count - 1].fd = -1;

		/* this decrements pt->fds_count */
		lws_plat_delete_socket_from_fds(context, wsi, m);
		pt->count_conns--;
		if (fixup) {
			v = (int) pt->fds[m].fd;
			/* old end guy's "position in fds table" is now the
			 * deletion guy's old one */
			end_wsi = wsi_from_fd(context, v);
			if (!end_wsi) {
				lwsl_err("no wsi for fd %d pos %d, "
					 "pt->fds_count=%d\n",
					 (int)pt->fds[m].fd, m, pt->fds_count);
				// assert(0);
			} else
				end_wsi->position_in_fds_table = m;
		}

		/* removed wsi has no position any more */
		wsi->position_in_fds_table = LWS_NO_FDS_POS;
	}

#if defined(LWS_WITH_EXTERNAL_POLL)
	/* remove also from external POLL support via protocol 0 */
	if (lws_socket_is_valid(wsi->desc.sockfd) && wsi->a.vhost &&
	    wsi->a.vhost->protocols[0].callback(wsi, LWS_CALLBACK_DEL_POLL_FD,
					      wsi->user_space, (void *) &pa, 0))
		ret = -1;
#endif

#if defined(LWS_WITH_SERVER)
	if (!context->being_destroyed &&
	    /* if this made some room, accept connects on this thread */
	    (unsigned int)pt->fds_count < context->fd_limit_per_thread - 1)
		lws_accept_modulation(context, pt, 1);
#endif

#if defined(LWS_WITH_EXTERNAL_POLL)
	if (wsi->a.vhost &&
	    wsi->a.vhost->protocols[0].callback(wsi, LWS_CALLBACK_UNLOCK_POLL,
					      wsi->user_space, (void *) &pa, 1))
		ret = -1;
#endif

//	__dump_fds(pt, "post remove");

	return ret;
}

int
__lws_change_pollfd(struct lws *wsi, int _and, int _or)
{
	struct lws_context *context;
	struct lws_pollargs pa;
	int ret = 0;

	if (!wsi || (!wsi->a.protocol && !wsi->event_pipe) ||
	    wsi->position_in_fds_table == LWS_NO_FDS_POS)
		return 0;

	context = lws_get_context(wsi);
	if (!context)
		return 1;

#if defined(LWS_WITH_EXTERNAL_POLL)
	if (wsi->a.vhost &&
	    wsi->a.vhost->protocols[0].callback(wsi, LWS_CALLBACK_LOCK_POLL,
					      wsi->user_space, (void *) &pa, 0))
		return -1;
#endif

	ret = _lws_change_pollfd(wsi, _and, _or, &pa);

#if defined(LWS_WITH_EXTERNAL_POLL)
	if (wsi->a.vhost &&
	    wsi->a.vhost->protocols[0].callback(wsi, LWS_CALLBACK_UNLOCK_POLL,
					   wsi->user_space, (void *) &pa, 0))
		ret = -1;
#endif

	return ret;
}

int
lws_change_pollfd(struct lws *wsi, int _and, int _or)
{
	struct lws_context_per_thread *pt;
	int ret = 0;

	pt = &wsi->a.context->pt[(int)wsi->tsi];

	lws_pt_lock(pt, __func__);
	ret = __lws_change_pollfd(wsi, _and, _or);
	lws_pt_unlock(pt);

	return ret;
}

int
lws_callback_on_writable(struct lws *wsi)
{
	struct lws_context_per_thread *pt;
	struct lws *w = wsi;

	if (lwsi_state(wsi) == LRS_SHUTDOWN)
		return 0;

	if (wsi->socket_is_permanently_unusable)
		return 0;

	pt = &wsi->a.context->pt[(int)wsi->tsi];

#if defined(LWS_WITH_DETAILED_LATENCY)
	if (!wsi->detlat.earliest_write_req)
		wsi->detlat.earliest_write_req = lws_now_usecs();
#endif

	lws_stats_bump(pt, LWSSTATS_C_WRITEABLE_CB_REQ, 1);
#if defined(LWS_WITH_STATS)
	if (!wsi->active_writable_req_us) {
		wsi->active_writable_req_us = lws_now_usecs();
		lws_stats_bump(pt, LWSSTATS_C_WRITEABLE_CB_EFF_REQ, 1);
	}
#endif

	if (lws_rops_fidx(wsi->role_ops, LWS_ROPS_callback_on_writable)) {
		int q = lws_rops_func_fidx(wsi->role_ops,
					   LWS_ROPS_callback_on_writable).
						      callback_on_writable(wsi);
		//lwsl_notice("%s: rops_cow says %d\n", __func__, q);
		if (q)
			return 1;
		w = lws_get_network_wsi(wsi);
	} else

		if (w->position_in_fds_table == LWS_NO_FDS_POS) {
			lwsl_debug("%s: failed to find socket %d\n", __func__,
				   wsi->desc.sockfd);
			return -1;
		}

	//lwsl_notice("%s: marking for POLLOUT %p (wsi %p)\n", __func__, w, wsi);

	if (__lws_change_pollfd(w, 0, LWS_POLLOUT))
		return -1;

	return 1;
}


/*
 * stitch protocol choice into the vh protocol linked list
 * We always insert ourselves at the start of the list
 *
 * X <-> B
 * X <-> pAn <-> pB
 *
 * Illegal to attach more than once without detach inbetween
 */
void
lws_same_vh_protocol_insert(struct lws *wsi, int n)
{
	lws_vhost_lock(wsi->a.vhost);

	lws_dll2_remove(&wsi->same_vh_protocol);
	lws_dll2_add_head(&wsi->same_vh_protocol,
			  &wsi->a.vhost->same_vh_protocol_owner[n]);

	wsi->bound_vhost_index = n;

	lws_vhost_unlock(wsi->a.vhost);
}

void
__lws_same_vh_protocol_remove(struct lws *wsi)
{
	if (wsi->a.vhost && wsi->a.vhost->same_vh_protocol_owner)
		lws_dll2_remove(&wsi->same_vh_protocol);
}

void
lws_same_vh_protocol_remove(struct lws *wsi)
{
	if (!wsi->a.vhost)
		return;

	lws_vhost_lock(wsi->a.vhost);

	__lws_same_vh_protocol_remove(wsi);

	lws_vhost_unlock(wsi->a.vhost);
}


int
lws_callback_on_writable_all_protocol_vhost(const struct lws_vhost *vhost,
				           const struct lws_protocols *protocol)
{
	struct lws *wsi;
	int n;

	if (protocol < vhost->protocols ||
	    protocol >= (vhost->protocols + vhost->count_protocols)) {
		lwsl_err("%s: protocol %p is not from vhost %p (%p - %p)\n",
			__func__, protocol, vhost->protocols, vhost,
			(vhost->protocols + vhost->count_protocols));

		return -1;
	}

	n = (int)(protocol - vhost->protocols);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
			lws_dll2_get_head(&vhost->same_vh_protocol_owner[n])) {
		wsi = lws_container_of(d, struct lws, same_vh_protocol);

		assert(wsi->a.protocol == protocol);
		lws_callback_on_writable(wsi);

	} lws_end_foreach_dll_safe(d, d1);

	return 0;
}

int
lws_callback_on_writable_all_protocol(const struct lws_context *context,
				      const struct lws_protocols *protocol)
{
	struct lws_vhost *vhost;
	int n;

	if (!context)
		return 0;

	vhost = context->vhost_list;

	while (vhost) {
		for (n = 0; n < vhost->count_protocols; n++)
			if (protocol->callback ==
			     vhost->protocols[n].callback &&
			    !strcmp(protocol->name, vhost->protocols[n].name))
				break;
		if (n != vhost->count_protocols)
			lws_callback_on_writable_all_protocol_vhost(
				vhost, &vhost->protocols[n]);

		vhost = vhost->vhost_next;
	}

	return 0;
}
