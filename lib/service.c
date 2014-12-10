/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2014 Andy Green <andy@warmcat.com>
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

#include "private-libwebsockets.h"

static int
lws_calllback_as_writeable(struct libwebsocket_context *context,
		   struct libwebsocket *wsi)
{
	int n;

	switch (wsi->mode) {
	case LWS_CONNMODE_WS_CLIENT:
		n = LWS_CALLBACK_CLIENT_WRITEABLE;
		break;
	case LWS_CONNMODE_WS_SERVING:
		n = LWS_CALLBACK_SERVER_WRITEABLE;
		break;
	default:
		n = LWS_CALLBACK_HTTP_WRITEABLE;
		break;
	}
	lwsl_info("%s: %p (user=%p)\n", __func__, wsi, wsi->user_space);
	return user_callback_handle_rxflow(wsi->protocol->callback, context,
			wsi, (enum libwebsocket_callback_reasons) n,
						      wsi->user_space, NULL, 0);
}

int
lws_handle_POLLOUT_event(struct libwebsocket_context *context,
		   struct libwebsocket *wsi, struct libwebsocket_pollfd *pollfd)
{
	int n;
	struct lws_tokens eff_buf;
#ifdef LWS_USE_HTTP2
	struct libwebsocket *wsi2;
#endif
	int ret;
	int m;

	/* pending truncated sends have uber priority */

	if (wsi->truncated_send_len) {
		if (lws_issue_raw(wsi, wsi->truncated_send_malloc +
				wsi->truncated_send_offset,
						wsi->truncated_send_len) < 0) {
			lwsl_info("lws_handle_POLLOUT_event signalling to close\n");
			return -1;
		}
		/* leave POLLOUT active either way */
		return 0;
	} else
		if (wsi->state == WSI_STATE_FLUSHING_STORED_SEND_BEFORE_CLOSE) {
			lwsl_info("***** %x signalling to close in POLLOUT handler\n", wsi);
			return -1; /* retry closing now */
		}
#ifdef LWS_USE_HTTP2
	/* protocol packets are next */
	if (wsi->pps) {
		lwsl_info("servicing pps %d\n", wsi->pps);
		switch (wsi->pps) {
		case LWS_PPS_HTTP2_MY_SETTINGS:
		case LWS_PPS_HTTP2_ACK_SETTINGS:
			lws_http2_do_pps_send(context, wsi);
			break;
		default:
			break;
		}
		wsi->pps = LWS_PPS_NONE;
		libwebsocket_rx_flow_control(wsi, 1);
		
		return 0; /* leave POLLOUT active */
	}
#endif
	/* pending control packets have next priority */
	
	if (wsi->state == WSI_STATE_ESTABLISHED && wsi->u.ws.ping_payload_len) {
		n = libwebsocket_write(wsi, 
				&wsi->u.ws.ping_payload_buf[
					LWS_SEND_BUFFER_PRE_PADDING],
					wsi->u.ws.ping_payload_len,
							       LWS_WRITE_PONG);
		if (n < 0)
			return -1;
		/* well he is sent, mark him done */
		wsi->u.ws.ping_payload_len = 0;
		/* leave POLLOUT active either way */
		return 0;
	}

	/* if nothing critical, user can get the callback */
	
	m = lws_ext_callback_for_each_active(wsi, LWS_EXT_CALLBACK_IS_WRITEABLE,
								       NULL, 0);
#ifndef LWS_NO_EXTENSIONS
	if (!wsi->extension_data_pending)
		goto user_service;
#endif
	/*
	 * check in on the active extensions, see if they
	 * had pending stuff to spill... they need to get the
	 * first look-in otherwise sequence will be disordered
	 *
	 * NULL, zero-length eff_buf means just spill pending
	 */

	ret = 1;
	while (ret == 1) {

		/* default to nobody has more to spill */

		ret = 0;
		eff_buf.token = NULL;
		eff_buf.token_len = 0;

		/* give every extension a chance to spill */
		
		m = lws_ext_callback_for_each_active(wsi,
					LWS_EXT_CALLBACK_PACKET_TX_PRESEND,
							           &eff_buf, 0);
		if (m < 0) {
			lwsl_err("ext reports fatal error\n");
			return -1;
		}
		if (m)
			/*
			 * at least one extension told us he has more
			 * to spill, so we will go around again after
			 */
			ret = 1;

		/* assuming they gave us something to send, send it */

		if (eff_buf.token_len) {
			n = lws_issue_raw(wsi, (unsigned char *)eff_buf.token,
							     eff_buf.token_len);
			if (n < 0) {
				lwsl_info("closing from POLLOUT spill\n");
				return -1;
			}
			/*
			 * Keep amount spilled small to minimize chance of this
			 */
			if (n != eff_buf.token_len) {
				lwsl_err("Unable to spill ext %d vs %s\n",
							  eff_buf.token_len, n);
				return -1;
			}
		} else
			continue;

		/* no extension has more to spill */

		if (!ret)
			continue;

		/*
		 * There's more to spill from an extension, but we just sent
		 * something... did that leave the pipe choked?
		 */

		if (!lws_send_pipe_choked(wsi))
			/* no we could add more */
			continue;

		lwsl_info("choked in POLLOUT service\n");

		/*
		 * Yes, he's choked.  Leave the POLLOUT masked on so we will
		 * come back here when he is unchoked.  Don't call the user
		 * callback to enforce ordering of spilling, he'll get called
		 * when we come back here and there's nothing more to spill.
		 */

		return 0;
	}
#ifndef LWS_NO_EXTENSIONS
	wsi->extension_data_pending = 0;

user_service:
#endif
	/* one shot */

	if (pollfd) {
		if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
			lwsl_info("failled at set pollfd\n");
			return 1;
		}

		lws_libev_io(context, wsi, LWS_EV_STOP | LWS_EV_WRITE);
	}

#ifdef LWS_USE_HTTP2
	/* 
	 * we are the 'network wsi' for potentially many muxed child wsi with
	 * no network connection of their own, who have to use us for all their
	 * network actions.  So we use a round-robin scheme to share out the
	 * POLLOUT notifications to our children.
	 * 
	 * But because any child could exhaust the socket's ability to take
	 * writes, we can only let one child get notified each time.
	 * 
	 * In addition children may be closed / deleted / added between POLLOUT
	 * notifications, so we can't hold pointers
	 */
	
	if (wsi->mode != LWS_CONNMODE_HTTP2_SERVING) {
		lwsl_info("%s: non http2\n", __func__);
		goto notify;
	}

	wsi->u.http2.requested_POLLOUT = 0;
	if (!wsi->u.http2.initialized) {
		lwsl_info("pollout on uninitialized http2 conn\n");
		return 0;
	}
	
	lwsl_info("%s: doing children\n", __func__);

	wsi2 = wsi;
	do {
		wsi2 = wsi2->u.http2.next_child_wsi;
		lwsl_info("%s: child %p\n", __func__, wsi2);
		if (!wsi2)
			continue;
		if (!wsi2->u.http2.requested_POLLOUT)
			continue;
		wsi2->u.http2.requested_POLLOUT = 0;
		if (lws_calllback_as_writeable(context, wsi2)) {
			lwsl_debug("Closing POLLOUT child\n");
			libwebsocket_close_and_free_session(context, wsi2,
						LWS_CLOSE_STATUS_NOSTATUS);
		}
		wsi2 = wsi;
	} while (wsi2 != NULL && !lws_send_pipe_choked(wsi));
	
	lwsl_info("%s: completed\n", __func__);
	
	return 0;
notify:
#endif
	return lws_calllback_as_writeable(context, wsi);
}



int
libwebsocket_service_timeout_check(struct libwebsocket_context *context,
				     struct libwebsocket *wsi, unsigned int sec)
{
	/*
	 * if extensions want in on it (eg, we are a mux parent)
	 * give them a chance to service child timeouts
	 */
	if (lws_ext_callback_for_each_active(wsi, LWS_EXT_CALLBACK_1HZ, NULL, sec) < 0)
		return 0;

	if (!wsi->pending_timeout)
		return 0;

	/*
	 * if we went beyond the allowed time, kill the
	 * connection
	 */
	if (sec > wsi->pending_timeout_limit) {
		lwsl_info("TIMEDOUT WAITING on %d\n", wsi->pending_timeout);
		libwebsocket_close_and_free_session(context,
						wsi, LWS_CLOSE_STATUS_NOSTATUS);
		return 1;
	}

	return 0;
}

int lws_rxflow_cache(struct libwebsocket *wsi, unsigned char *buf, int n, int len)
{
	/* his RX is flowcontrolled, don't send remaining now */
	if (wsi->rxflow_buffer) {
		/* rxflow while we were spilling prev rxflow */
		lwsl_info("stalling in existing rxflow buf\n");
		return 1;
	}

	/* a new rxflow, buffer it and warn caller */
	lwsl_info("new rxflow input buffer len %d\n", len - n);
	wsi->rxflow_buffer = lws_malloc(len - n);
	wsi->rxflow_len = len - n;
	wsi->rxflow_pos = 0;
	memcpy(wsi->rxflow_buffer, buf + n, len - n);

	return 0;
}

/**
 * libwebsocket_service_fd() - Service polled socket with something waiting
 * @context:	Websocket context
 * @pollfd:	The pollfd entry describing the socket fd and which events
 *		happened.
 *
 *	This function takes a pollfd that has POLLIN or POLLOUT activity and
 *	services it according to the state of the associated
 *	struct libwebsocket.
 *
 *	The one call deals with all "service" that might happen on a socket
 *	including listen accepts, http files as well as websocket protocol.
 *
 *	If a pollfd says it has something, you can just pass it to
 *	libwebsocket_serice_fd() whether it is a socket handled by lws or not.
 *	If it sees it is a lws socket, the traffic will be handled and
 *	pollfd->revents will be zeroed now.
 *
 *	If the socket is foreign to lws, it leaves revents alone.  So you can
 *	see if you should service yourself by checking the pollfd revents
 *	after letting lws try to service it.
 */

LWS_VISIBLE int
libwebsocket_service_fd(struct libwebsocket_context *context,
							  struct libwebsocket_pollfd *pollfd)
{
	struct libwebsocket *wsi;
	int n;
	int m;
	int listen_socket_fds_index = 0;
	time_t now;
	int timed_out = 0;
	int our_fd = 0;
	char draining_flow = 0;
	int more;
	struct lws_tokens eff_buf;

	if (context->listen_service_fd)
		listen_socket_fds_index = context->lws_lookup[
			     context->listen_service_fd]->position_in_fds_table;

	/*
	 * you can call us with pollfd = NULL to just allow the once-per-second
	 * global timeout checks; if less than a second since the last check
	 * it returns immediately then.
	 */

	time(&now);

	/* TODO: if using libev, we should probably use timeout watchers... */
	if (context->last_timeout_check_s != now) {
		context->last_timeout_check_s = now;

		lws_plat_service_periodic(context);

		/* global timeout check once per second */

		if (pollfd)
			our_fd = pollfd->fd;

		for (n = 0; n < context->fds_count; n++) {
			m = context->fds[n].fd;
			wsi = context->lws_lookup[m];
			if (!wsi)
				continue;

			if (libwebsocket_service_timeout_check(context, wsi, now))
				/* he did time out... */
				if (m == our_fd) {
					/* it was the guy we came to service! */
					timed_out = 1;
					/* mark as handled */
					if (pollfd)
						pollfd->revents = 0;
				}
		}
	}

	/* the socket we came to service timed out, nothing to do */
	if (timed_out)
		return 0;

	/* just here for timeout management? */
	if (pollfd == NULL)
		return 0;

	/* no, here to service a socket descriptor */
	wsi = context->lws_lookup[pollfd->fd];
	if (wsi == NULL)
		/* not lws connection ... leave revents alone and return */
		return 0;

	/*
	 * so that caller can tell we handled, past here we need to
	 * zero down pollfd->revents after handling
	 */

	/*
	 * deal with listen service piggybacking
	 * every listen_service_modulo services of other fds, we
	 * sneak one in to service the listen socket if there's anything waiting
	 *
	 * To handle connection storms, as found in ab, if we previously saw a
	 * pending connection here, it causes us to check again next time.
	 */

	if (context->listen_service_fd && pollfd !=
				       &context->fds[listen_socket_fds_index]) {
		context->listen_service_count++;
		if (context->listen_service_extraseen ||
				context->listen_service_count ==
					       context->listen_service_modulo) {
			context->listen_service_count = 0;
			m = 1;
			if (context->listen_service_extraseen > 5)
				m = 2;
			while (m--) {
				/*
				 * even with extpoll, we prepared this
				 * internal fds for listen
				 */
				n = lws_poll_listen_fd(&context->fds[listen_socket_fds_index]);
				if (n > 0) { /* there's a conn waiting for us */
					libwebsocket_service_fd(context,
						&context->
						  fds[listen_socket_fds_index]);
					context->listen_service_extraseen++;
				} else {
					if (context->listen_service_extraseen)
						context->
						     listen_service_extraseen--;
					break;
				}
			}
		}

	}

	/* handle session socket closed */

	if ((!(pollfd->revents & LWS_POLLIN)) &&
			(pollfd->revents & LWS_POLLHUP)) {

		lwsl_debug("Session Socket %p (fd=%d) dead\n",
						       (void *)wsi, pollfd->fd);

		goto close_and_handled;
	}

	/* okay, what we came here to do... */

	switch (wsi->mode) {
	case LWS_CONNMODE_HTTP_SERVING:
	case LWS_CONNMODE_HTTP_SERVING_ACCEPTED:
	case LWS_CONNMODE_SERVER_LISTENER:
	case LWS_CONNMODE_SSL_ACK_PENDING:
		n = lws_server_socket_service(context, wsi, pollfd);
		if (n < 0)
			goto close_and_handled;
		goto handled;

	case LWS_CONNMODE_WS_SERVING:
	case LWS_CONNMODE_WS_CLIENT:
	case LWS_CONNMODE_HTTP2_SERVING:

		/* the guy requested a callback when it was OK to write */

		if ((pollfd->revents & LWS_POLLOUT) &&
			(wsi->state == WSI_STATE_ESTABLISHED || wsi->state == WSI_STATE_HTTP2_ESTABLISHED || wsi->state == WSI_STATE_HTTP2_ESTABLISHED_PRE_SETTINGS ||
				wsi->state == WSI_STATE_FLUSHING_STORED_SEND_BEFORE_CLOSE) &&
			   lws_handle_POLLOUT_event(context, wsi, pollfd)) {
			lwsl_info("libwebsocket_service_fd: closing\n");
			goto close_and_handled;
		}

		if (wsi->rxflow_buffer &&
			      (wsi->rxflow_change_to & LWS_RXFLOW_ALLOW)) {
			lwsl_info("draining rxflow\n");
			/* well, drain it */
			eff_buf.token = (char *)wsi->rxflow_buffer +
						wsi->rxflow_pos;
			eff_buf.token_len = wsi->rxflow_len - wsi->rxflow_pos;
			draining_flow = 1;
			goto drain;
		}

		/* any incoming data ready? */

		if (!(pollfd->revents & LWS_POLLIN))
			break;

		eff_buf.token_len = lws_ssl_capable_read(context, wsi,
				context->service_buffer,
					       sizeof(context->service_buffer));
		switch (eff_buf.token_len) {
		case 0:
			lwsl_info("service_fd: closing due to 0 length read\n");
			goto close_and_handled;
		case LWS_SSL_CAPABLE_MORE_SERVICE:
			lwsl_info("SSL Capable more service\n");
			n = 0;
			goto handled;
		case LWS_SSL_CAPABLE_ERROR:
			lwsl_info("Closing when error\n");
			goto close_and_handled;
		}

		/*
		 * give any active extensions a chance to munge the buffer
		 * before parse.  We pass in a pointer to an lws_tokens struct
		 * prepared with the default buffer and content length that's in
		 * there.  Rather than rewrite the default buffer, extensions
		 * that expect to grow the buffer can adapt .token to
		 * point to their own per-connection buffer in the extension
		 * user allocation.  By default with no extensions or no
		 * extension callback handling, just the normal input buffer is
		 * used then so it is efficient.
		 */

		eff_buf.token = (char *)context->service_buffer;
drain:

		do {

			more = 0;
			
			m = lws_ext_callback_for_each_active(wsi,
				LWS_EXT_CALLBACK_PACKET_RX_PREPARSE, &eff_buf, 0);
			if (m < 0)
				goto close_and_handled;
			if (m)
				more = 1;

			/* service incoming data */

			if (eff_buf.token_len) {
				n = libwebsocket_read(context, wsi,
					(unsigned char *)eff_buf.token,
							    eff_buf.token_len);
				if (n < 0) {
					/* we closed wsi */
					n = 0;
					goto handled;
				}
			}

			eff_buf.token = NULL;
			eff_buf.token_len = 0;
		} while (more);

		if (draining_flow && wsi->rxflow_buffer &&
				 wsi->rxflow_pos == wsi->rxflow_len) {
			lwsl_info("flow buffer: drained\n");
			lws_free2(wsi->rxflow_buffer);
			/* having drained the rxflow buffer, can rearm POLLIN */
#ifdef LWS_NO_SERVER
			n =
#endif
			_libwebsocket_rx_flow_control(wsi); /* n ignored, needed for NO_SERVER case */
		}

		break;

	default:
#ifdef LWS_NO_CLIENT
		break;
#else
		n = lws_client_socket_service(context, wsi, pollfd);
		goto handled;
#endif
	}

	n = 0;
	goto handled;

close_and_handled:
	lwsl_debug("Close and handled\n");
	libwebsocket_close_and_free_session(context, wsi,
						LWS_CLOSE_STATUS_NOSTATUS);
	n = 1;

handled:
	pollfd->revents = 0;
	return n;
}

/**
 * libwebsocket_service() - Service any pending websocket activity
 * @context:	Websocket context
 * @timeout_ms:	Timeout for poll; 0 means return immediately if nothing needed
 *		service otherwise block and service immediately, returning
 *		after the timeout if nothing needed service.
 *
 *	This function deals with any pending websocket traffic, for three
 *	kinds of event.  It handles these events on both server and client
 *	types of connection the same.
 *
 *	1) Accept new connections to our context's server
 *
 *	2) Call the receive callback for incoming frame data received by
 *	    server or client connections.
 *
 *	You need to call this service function periodically to all the above
 *	functions to happen; if your application is single-threaded you can
 *	just call it in your main event loop.
 *
 *	Alternatively you can fork a new process that asynchronously handles
 *	calling this service in a loop.  In that case you are happy if this
 *	call blocks your thread until it needs to take care of something and
 *	would call it with a large nonzero timeout.  Your loop then takes no
 *	CPU while there is nothing happening.
 *
 *	If you are calling it in a single-threaded app, you don't want it to
 *	wait around blocking other things in your loop from happening, so you
 *	would call it with a timeout_ms of 0, so it returns immediately if
 *	nothing is pending, or as soon as it services whatever was pending.
 */

LWS_VISIBLE int
libwebsocket_service(struct libwebsocket_context *context, int timeout_ms)
{
	return lws_plat_service(context, timeout_ms);
}

