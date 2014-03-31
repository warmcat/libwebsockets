/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 Andy Green <andy@warmcat.com>
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

#if defined(WIN32) || defined(_WIN32)
#include <tchar.h>
#include <mstcpip.h>
#ifdef _WIN32_WCE
#define vsnprintf _vsnprintf
#endif
#else
#ifdef LWS_BUILTIN_GETIFADDRS
#include <getifaddrs.h>
#else
#include <ifaddrs.h>
#endif
#include <syslog.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef LWS_OPENSSL_SUPPORT
int openssl_websocket_private_data_index;
#endif

#ifndef LWS_BUILD_HASH
#define LWS_BUILD_HASH "unknown-build-hash"
#endif

static int log_level = LLL_ERR | LLL_WARN | LLL_NOTICE;
static void lwsl_emit_stderr(int level, const char *line);
static void (*lwsl_emit)(int level, const char *line) = lwsl_emit_stderr;

#ifdef LWS_USE_LIBEV
#define _LWS_EV_TAG " libev"
#else
#define _LWS_EV_TAG
#endif /* LWS_USE_LIBEV */
static const char *library_version =
			LWS_LIBRARY_VERSION " " LWS_BUILD_HASH _LWS_EV_TAG;

static const char * const log_level_names[] = {
	"ERR",
	"WARN",
	"NOTICE",
	"INFO",
	"DEBUG",
	"PARSER",
	"HEADER",
	"EXTENSION",
	"CLIENT",
	"LATENCY",
};

#ifndef LWS_NO_CLIENT
	extern int lws_client_socket_service(
		struct libwebsocket_context *context,
		struct libwebsocket *wsi, struct libwebsocket_pollfd *pollfd);
#endif
#ifndef LWS_NO_SERVER
	extern int lws_server_socket_service(
		struct libwebsocket_context *context,
		struct libwebsocket *wsi, struct libwebsocket_pollfd *pollfd);
#endif



#if defined(WIN32) || defined(_WIN32)
#include "lws-plat-win.c"
#else
#include "lws-plat-unix.c"
#endif

/**
 * lws_get_library_version: get version and git hash library built from
 *
 *	returns a const char * to a string like "1.1 178d78c"
 *	representing the library version followed by the git head hash it
 *	was built from
 */

LWS_VISIBLE const char *
lws_get_library_version(void)
{
	return library_version;
}

int
insert_wsi_socket_into_fds(struct libwebsocket_context *context,
						       struct libwebsocket *wsi)
{
	struct libwebsocket_pollargs pa = { wsi->sock, LWS_POLLIN, 0 };

	if (context->fds_count >= context->max_fds) {
		lwsl_err("Too many fds (%d)\n", context->max_fds);
		return 1;
	}

	if (wsi->sock >= context->max_fds) {
		lwsl_err("Socket fd %d is too high (%d)\n",
						wsi->sock, context->max_fds);
		return 1;
	}

	assert(wsi);
	assert(wsi->sock >= 0);

	lwsl_info("insert_wsi_socket_into_fds: wsi=%p, sock=%d, fds pos=%d\n",
					    wsi, wsi->sock, context->fds_count);

	context->protocols[0].callback(context, wsi,
		LWS_CALLBACK_LOCK_POLL,
		wsi->user_space, (void *) &pa, 0);

	context->lws_lookup[wsi->sock] = wsi;
	wsi->position_in_fds_table = context->fds_count;
	context->fds[context->fds_count].fd = wsi->sock;
	context->fds[context->fds_count].events = LWS_POLLIN;
#ifdef LWS_USE_LIBEV
	if (context && context->io_loop && LWS_LIBEV_ENABLED(context))
		ev_io_start(context->io_loop, (struct ev_io *)&wsi->w_read);

#endif /* LWS_USE_LIBEV */
	context->fds[context->fds_count++].revents = 0;
#ifdef _WIN32
	context->events[context->fds_count] = WSACreateEvent();
	WSAEventSelect(wsi->sock, context->events[context->fds_count], LWS_POLLIN);
#endif

	/* external POLL support via protocol 0 */
	context->protocols[0].callback(context, wsi,
		LWS_CALLBACK_ADD_POLL_FD,
		wsi->user_space, (void *) &pa, 0);

	context->protocols[0].callback(context, wsi,
		LWS_CALLBACK_UNLOCK_POLL,
		wsi->user_space, (void *)&pa, 0);

	return 0;
}

static int
remove_wsi_socket_from_fds(struct libwebsocket_context *context,
						      struct libwebsocket *wsi)
{
	int m;
	struct  libwebsocket_pollargs pa = { wsi->sock, 0, 0};

#ifdef LWS_USE_LIBEV
	if (LWS_LIBEV_ENABLED(context)) {
		ev_io_stop(context->io_loop, (struct ev_io *)&wsi->w_read);
		ev_io_stop(context->io_loop, (struct ev_io *)&wsi->w_write);
	}
#endif /* LWS_USE_LIBEV */

	if (!--context->fds_count) {
		context->protocols[0].callback(context, wsi,
			LWS_CALLBACK_LOCK_POLL,
			wsi->user_space, (void *) &pa, 0);
		goto do_ext;
	}

	if (wsi->sock > context->max_fds) {
		lwsl_err("Socket fd %d too high (%d)\n",
						   wsi->sock, context->max_fds);
		return 1;
	}

	lwsl_info("%s: wsi=%p, sock=%d, fds pos=%d\n", __func__,
				    wsi, wsi->sock, wsi->position_in_fds_table);

	context->protocols[0].callback(context, wsi,
		LWS_CALLBACK_LOCK_POLL,
		wsi->user_space, (void *)&pa, 0);

	m = wsi->position_in_fds_table; /* replace the contents for this */

	/* have the last guy take up the vacant slot */
	context->fds[m] = context->fds[context->fds_count];
#ifdef _WIN32
	WSACloseEvent(context->events[m + 1]);
	context->events[m + 1] = context->events[context->fds_count + 1];
#endif
	/*
	 * end guy's fds_lookup entry remains unchanged
	 * (still same fd pointing to same wsi)
	 */
	/* end guy's "position in fds table" changed */
	context->lws_lookup[context->fds[context->fds_count].fd]->
						position_in_fds_table = m;
	/* deletion guy's lws_lookup entry needs nuking */
	context->lws_lookup[wsi->sock] = NULL;
	/* removed wsi has no position any more */
	wsi->position_in_fds_table = -1;

do_ext:
	/* remove also from external POLL support via protocol 0 */
	if (wsi->sock) {
		context->protocols[0].callback(context, wsi,
		    LWS_CALLBACK_DEL_POLL_FD, wsi->user_space,
		    (void *) &pa, 0);
	}
	context->protocols[0].callback(context, wsi,
				       LWS_CALLBACK_UNLOCK_POLL,
				       wsi->user_space, (void *) &pa, 0);
	return 0;
}


void
libwebsocket_close_and_free_session(struct libwebsocket_context *context,
			 struct libwebsocket *wsi, enum lws_close_status reason)
{
	int n;
	int old_state;
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 2 +
						  LWS_SEND_BUFFER_POST_PADDING];
#ifndef LWS_NO_EXTENSIONS
	int ret;
	int m;
	struct lws_tokens eff_buf;
	struct libwebsocket_extension *ext;
#endif

	if (!wsi)
		return;

	old_state = wsi->state;

	if (old_state == WSI_STATE_DEAD_SOCKET)
		return;

	/* we tried the polite way... */
	if (old_state == WSI_STATE_AWAITING_CLOSE_ACK)
		goto just_kill_connection;

	wsi->u.ws.close_reason = reason;

	if (wsi->mode == LWS_CONNMODE_WS_CLIENT_WAITING_CONNECT ||
			wsi->mode == LWS_CONNMODE_WS_CLIENT_ISSUE_HANDSHAKE) {

		context->protocols[0].callback(context, wsi,
			LWS_CALLBACK_CLIENT_CONNECTION_ERROR, NULL, NULL, 0);

		free(wsi->u.hdr.ah);
		goto just_kill_connection;
	}


	if (wsi->mode == LWS_CONNMODE_HTTP_SERVING_ACCEPTED) {
		if (wsi->u.http.post_buffer) {
			free(wsi->u.http.post_buffer);
			wsi->u.http.post_buffer = NULL;
		}
		if (wsi->u.http.fd != LWS_INVALID_FILE) {
			lwsl_debug("closing http file\n");
#if defined(WIN32) || defined(_WIN32)
			CloseHandle(wsi->u.http.fd);
#else
			close(wsi->u.http.fd);
#endif
			wsi->u.http.fd = LWS_INVALID_FILE;
			context->protocols[0].callback(context, wsi,
				LWS_CALLBACK_CLOSED_HTTP, wsi->user_space, NULL, 0);
		}
	}

#ifndef LWS_NO_EXTENSIONS
	/*
	 * are his extensions okay with him closing?  Eg he might be a mux
	 * parent and just his ch1 aspect is closing?
	 */

	for (n = 0; n < wsi->count_active_extensions; n++) {
		if (!wsi->active_extensions[n]->callback)
			continue;

		m = wsi->active_extensions[n]->callback(context,
			wsi->active_extensions[n], wsi,
			LWS_EXT_CALLBACK_CHECK_OK_TO_REALLY_CLOSE,
				       wsi->active_extensions_user[n], NULL, 0);

		/*
		 * if somebody vetoed actually closing him at this time....
		 * up to the extension to track the attempted close, let's
		 * just bail
		 */

		if (m) {
			lwsl_ext("extension vetoed close\n");
			return;
		}
	}

	/*
	 * flush any tx pending from extensions, since we may send close packet
	 * if there are problems with send, just nuke the connection
	 */

	ret = 1;
	while (ret == 1) {

		/* default to nobody has more to spill */

		ret = 0;
		eff_buf.token = NULL;
		eff_buf.token_len = 0;

		/* show every extension the new incoming data */

		for (n = 0; n < wsi->count_active_extensions; n++) {
			m = wsi->active_extensions[n]->callback(
					wsi->protocol->owning_server,
					wsi->active_extensions[n], wsi,
					LWS_EXT_CALLBACK_FLUSH_PENDING_TX,
				   wsi->active_extensions_user[n], &eff_buf, 0);
			if (m < 0) {
				lwsl_ext("Extension reports fatal error\n");
				goto just_kill_connection;
			}
			if (m)
				/*
				 * at least one extension told us he has more
				 * to spill, so we will go around again after
				 */
				ret = 1;
		}

		/* assuming they left us something to send, send it */

		if (eff_buf.token_len)
			if (lws_issue_raw(wsi, (unsigned char *)eff_buf.token,
				      eff_buf.token_len) != eff_buf.token_len) {
				lwsl_debug("close: ext spill failed\n");
				goto just_kill_connection;
			}
	}
#endif

	/*
	 * signal we are closing, libsocket_write will
	 * add any necessary version-specific stuff.  If the write fails,
	 * no worries we are closing anyway.  If we didn't initiate this
	 * close, then our state has been changed to
	 * WSI_STATE_RETURNED_CLOSE_ALREADY and we will skip this.
	 *
	 * Likewise if it's a second call to close this connection after we
	 * sent the close indication to the peer already, we are in state
	 * WSI_STATE_AWAITING_CLOSE_ACK and will skip doing this a second time.
	 */

	if (old_state == WSI_STATE_ESTABLISHED &&
					  reason != LWS_CLOSE_STATUS_NOSTATUS) {

		lwsl_debug("sending close indication...\n");

		/* make valgrind happy */
		memset(buf, 0, sizeof(buf));
		n = libwebsocket_write(wsi,
				&buf[LWS_SEND_BUFFER_PRE_PADDING + 2],
							    0, LWS_WRITE_CLOSE);
		if (n >= 0) {
			/*
			 * we have sent a nice protocol level indication we
			 * now wish to close, we should not send anything more
			 */

			wsi->state = WSI_STATE_AWAITING_CLOSE_ACK;

			/*
			 * ...and we should wait for a reply for a bit
			 * out of politeness
			 */

			libwebsocket_set_timeout(wsi,
						  PENDING_TIMEOUT_CLOSE_ACK, 1);

			lwsl_debug("sent close indication, awaiting ack\n");

			return;
		}

		lwsl_info("close: sending close packet failed, hanging up\n");

		/* else, the send failed and we should just hang up */
	}

just_kill_connection:

	lwsl_debug("close: just_kill_connection\n");

	/*
	 * we won't be servicing or receiving anything further from this guy
	 * delete socket from the internal poll list if still present
	 */

	remove_wsi_socket_from_fds(context, wsi);

	wsi->state = WSI_STATE_DEAD_SOCKET;

	if ((old_state == WSI_STATE_ESTABLISHED ||
	     wsi->mode == LWS_CONNMODE_WS_SERVING ||
	     wsi->mode == LWS_CONNMODE_WS_CLIENT)) {

		if (wsi->u.ws.rx_user_buffer) {
			free(wsi->u.ws.rx_user_buffer);
			wsi->u.ws.rx_user_buffer = NULL;
		}
		if (wsi->u.ws.rxflow_buffer) {
			free(wsi->u.ws.rxflow_buffer);
			wsi->u.ws.rxflow_buffer = NULL;
		}
		if (wsi->truncated_send_malloc) {
			/* not going to be completed... nuke it */
			free(wsi->truncated_send_malloc);
			wsi->truncated_send_malloc = NULL;
			wsi->truncated_send_len = 0;
		}
	}

	/* tell the user it's all over for this guy */

	if (wsi->protocol && wsi->protocol->callback &&
			((old_state == WSI_STATE_ESTABLISHED) ||
			 (old_state == WSI_STATE_RETURNED_CLOSE_ALREADY) ||
			 (old_state == WSI_STATE_AWAITING_CLOSE_ACK))) {
		lwsl_debug("calling back CLOSED\n");
		wsi->protocol->callback(context, wsi, LWS_CALLBACK_CLOSED,
						      wsi->user_space, NULL, 0);
	} else if ( wsi->mode == LWS_CONNMODE_HTTP_SERVING_ACCEPTED ) {
		lwsl_debug("calling back CLOSED_HTTP\n");
		context->protocols[0].callback(context, wsi,
			LWS_CALLBACK_CLOSED_HTTP, wsi->user_space, NULL, 0 );
	} else
		lwsl_debug("not calling back closed\n");

#ifndef LWS_NO_EXTENSIONS
	/* deallocate any active extension contexts */

	for (n = 0; n < wsi->count_active_extensions; n++) {
		if (!wsi->active_extensions[n]->callback)
			continue;

		wsi->active_extensions[n]->callback(context,
			wsi->active_extensions[n], wsi,
				LWS_EXT_CALLBACK_DESTROY,
				       wsi->active_extensions_user[n], NULL, 0);

		free(wsi->active_extensions_user[n]);
	}

	/*
	 * inform all extensions in case they tracked this guy out of band
	 * even though not active on him specifically
	 */

	ext = context->extensions;
	while (ext && ext->callback) {
		ext->callback(context, ext, wsi,
				LWS_EXT_CALLBACK_DESTROY_ANY_WSI_CLOSING,
				       NULL, NULL, 0);
		ext++;
	}
#endif

/*	lwsl_info("closing fd=%d\n", wsi->sock); */

#ifdef LWS_OPENSSL_SUPPORT
	if (wsi->ssl) {
		n = SSL_get_fd(wsi->ssl);
		SSL_shutdown(wsi->ssl);
		compatible_close(n);
		SSL_free(wsi->ssl);
	} else {
#endif
		if (wsi->sock) {
			n = shutdown(wsi->sock, SHUT_RDWR);
			if (n)
				lwsl_debug("closing: shutdown returned %d\n",
									LWS_ERRNO);

			n = compatible_close(wsi->sock);
			if (n)
				lwsl_debug("closing: close returned %d\n",
									LWS_ERRNO);
		}
#ifdef LWS_OPENSSL_SUPPORT
	}
#endif

	/* outermost destroy notification for wsi (user_space still intact) */
	context->protocols[0].callback(context, wsi,
			LWS_CALLBACK_WSI_DESTROY, wsi->user_space, NULL, 0);

	if (wsi->protocol && wsi->protocol->per_session_data_size &&
					wsi->user_space) /* user code may own */
		free(wsi->user_space);

	free(wsi);
}

/**
 * libwebsockets_get_peer_addresses() - Get client address information
 * @context:	Libwebsockets context
 * @wsi:	Local struct libwebsocket associated with
 * @fd:		Connection socket descriptor
 * @name:	Buffer to take client address name
 * @name_len:	Length of client address name buffer
 * @rip:	Buffer to take client address IP qotted quad
 * @rip_len:	Length of client address IP buffer
 *
 *	This function fills in @name and @rip with the name and IP of
 *	the client connected with socket descriptor @fd.  Names may be
 *	truncated if there is not enough room.  If either cannot be
 *	determined, they will be returned as valid zero-length strings.
 */

LWS_VISIBLE void
libwebsockets_get_peer_addresses(struct libwebsocket_context *context,
	struct libwebsocket *wsi, int fd, char *name, int name_len,
					char *rip, int rip_len)
{
	socklen_t len;
#ifdef LWS_USE_IPV6
	struct sockaddr_in6 sin6;
#endif
	struct sockaddr_in sin4;
	struct hostent *host;
	struct hostent *host1;
	char ip[128];
	unsigned char *p;
	int n;
#ifdef AF_LOCAL
	struct sockaddr_un *un;
#endif
	int ret = -1;

	rip[0] = '\0';
	name[0] = '\0';

	lws_latency_pre(context, wsi);

#ifdef LWS_USE_IPV6
	if (LWS_IPV6_ENABLED(context)) {

		len = sizeof(sin6);
		if (getpeername(fd, (struct sockaddr *) &sin6, &len) < 0) {
			lwsl_warn("getpeername: %s\n", strerror(LWS_ERRNO));
			goto bail;
		}

		if (inet_ntop(AF_INET6, &sin6.sin6_addr, rip, rip_len) == NULL) {
			perror("inet_ntop");
			goto bail;
		}

		// Strip off the IPv4 to IPv6 header if one exists
		if (strncmp(rip, "::ffff:", 7) == 0) {
			memmove(rip, rip + 7, strlen(rip) - 6);
		}

		getnameinfo((struct sockaddr *)&sin6,
				sizeof(struct sockaddr_in6), name,
							name_len, NULL, 0, 0);

	} else
#endif
	{
		len = sizeof(sin4);
		if (getpeername(fd, (struct sockaddr *) &sin4, &len) < 0) {
			lwsl_warn("getpeername: %s\n", strerror(LWS_ERRNO));
			goto bail;
		}
		host = gethostbyaddr((char *) &sin4.sin_addr,
						sizeof(sin4.sin_addr), AF_INET);
		if (host == NULL) {
			lwsl_warn("gethostbyaddr: %s\n", strerror(LWS_ERRNO));
			goto bail;
		}

		strncpy(name, host->h_name, name_len);
		name[name_len - 1] = '\0';

		host1 = gethostbyname(host->h_name);
		if (host1 == NULL)
			goto bail;
		p = (unsigned char *)host1;
		n = 0;
		while (p != NULL) {
			p = (unsigned char *)host1->h_addr_list[n++];
			if (p == NULL)
				continue;
			if ((host1->h_addrtype != AF_INET)
	#ifdef AF_LOCAL
				&& (host1->h_addrtype != AF_LOCAL)
	#endif
				)
				continue;

			if (host1->h_addrtype == AF_INET)
				sprintf(ip, "%u.%u.%u.%u",
						p[0], p[1], p[2], p[3]);
	#ifdef AF_LOCAL
			else {
				un = (struct sockaddr_un *)p;
				strncpy(ip, un->sun_path, sizeof(ip) - 1);
				ip[sizeof(ip) - 1] = '\0';
			}
	#endif
			p = NULL;
			strncpy(rip, ip, rip_len);
			rip[rip_len - 1] = '\0';
		}
	}

	ret = 0;
bail:
	lws_latency(context, wsi, "libwebsockets_get_peer_addresses", ret, 1);
}

int lws_set_socket_options(struct libwebsocket_context *context, int fd)
{
	int optval = 1;
	socklen_t optlen = sizeof(optval);
#if defined(WIN32) || defined(_WIN32)
	u_long optl = 1;
#endif
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__)
	struct protoent *tcp_proto;
#endif

	if (context->ka_time) {
		/* enable keepalive on this socket */
		optval = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
					     (const void *)&optval, optlen) < 0)
			return 1;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__CYGWIN__)

		/*
		 * didn't find a way to set these per-socket, need to
		 * tune kernel systemwide values
		 */
#elif WIN32
		{
			DWORD dwBytesRet;
			struct tcp_keepalive alive;
			alive.onoff = TRUE;
			alive.keepalivetime = context->ka_time;
			alive.keepaliveinterval = context->ka_interval;

			if (WSAIoctl(fd, SIO_KEEPALIVE_VALS, &alive, sizeof(alive), 
									NULL, 0, &dwBytesRet, NULL, NULL))
				return 1;
		}
#else
		/* set the keepalive conditions we want on it too */
		optval = context->ka_time;
		if (setsockopt(fd, IPPROTO_IP, TCP_KEEPIDLE,
					     (const void *)&optval, optlen) < 0)
			return 1;

		optval = context->ka_interval;
		if (setsockopt(fd, IPPROTO_IP, TCP_KEEPINTVL,
					     (const void *)&optval, optlen) < 0)
			return 1;

		optval = context->ka_probes;
		if (setsockopt(fd, IPPROTO_IP, TCP_KEEPCNT,
					     (const void *)&optval, optlen) < 0)
			return 1;
#endif
	}

	/* Disable Nagle */
	optval = 1;
#if !defined(__APPLE__) && !defined(__FreeBSD__) && !defined(__NetBSD__)
	setsockopt(fd, SOL_TCP, TCP_NODELAY, (const void *)&optval, optlen);
#else
	tcp_proto = getprotobyname("TCP");
	setsockopt(fd, tcp_proto->p_proto, TCP_NODELAY, &optval, optlen);
#endif

	/* We are nonblocking... */
#if defined(WIN32) || defined(_WIN32)
	ioctlsocket(fd, FIONBIO, &optl);
#else
	fcntl(fd, F_SETFL, O_NONBLOCK);
#endif

	return 0;
}

int
lws_handle_POLLOUT_event(struct libwebsocket_context *context,
		   struct libwebsocket *wsi, struct libwebsocket_pollfd *pollfd)
{
	int n;

#ifndef LWS_NO_EXTENSIONS
	struct lws_tokens eff_buf;
	int ret;
	int m;
	int handled = 0;

	/* pending truncated sends have uber priority */

	if (wsi->truncated_send_len) {
		lws_issue_raw(wsi, wsi->truncated_send_malloc +
				wsi->truncated_send_offset,
						wsi->truncated_send_len);
		/* leave POLLOUT active either way */
		return 0;
	}

	for (n = 0; n < wsi->count_active_extensions; n++) {
		if (!wsi->active_extensions[n]->callback)
			continue;

		m = wsi->active_extensions[n]->callback(context,
			wsi->active_extensions[n], wsi,
			LWS_EXT_CALLBACK_IS_WRITEABLE,
				       wsi->active_extensions_user[n], NULL, 0);
		if (m > handled)
			handled = m;
	}

	if (handled == 1)
		goto notify_action;

	if (!wsi->extension_data_pending || handled == 2)
		goto user_service;

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

		for (n = 0; n < wsi->count_active_extensions; n++) {
			m = wsi->active_extensions[n]->callback(
				wsi->protocol->owning_server,
				wsi->active_extensions[n], wsi,
					LWS_EXT_CALLBACK_PACKET_TX_PRESEND,
				   wsi->active_extensions_user[n], &eff_buf, 0);
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
		}

		/* assuming they gave us something to send, send it */

		if (eff_buf.token_len) {
			n = lws_issue_raw(wsi, (unsigned char *)eff_buf.token,
							     eff_buf.token_len);
			if (n < 0)
				return -1;
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

	wsi->extension_data_pending = 0;

user_service:
#endif
	/* one shot */

	if (pollfd) {
		lws_change_pollfd(wsi, LWS_POLLOUT, 0);
#ifdef LWS_USE_LIBEV
		if (LWS_LIBEV_ENABLED(context))
			ev_io_stop(context->io_loop,
				(struct ev_io *)&wsi->w_write);
#endif /* LWS_USE_LIBEV */
	}
#ifndef LWS_NO_EXTENSIONS
notify_action:
#endif

	if (wsi->mode == LWS_CONNMODE_WS_CLIENT)
		n = LWS_CALLBACK_CLIENT_WRITEABLE;
	else
		n = LWS_CALLBACK_SERVER_WRITEABLE;

	return user_callback_handle_rxflow(wsi->protocol->callback, context,
			wsi, (enum libwebsocket_callback_reasons) n,
						      wsi->user_space, NULL, 0);
}



int
libwebsocket_service_timeout_check(struct libwebsocket_context *context,
				     struct libwebsocket *wsi, unsigned int sec)
{
#ifndef LWS_NO_EXTENSIONS
	int n;

	/*
	 * if extensions want in on it (eg, we are a mux parent)
	 * give them a chance to service child timeouts
	 */

	for (n = 0; n < wsi->count_active_extensions; n++)
		wsi->active_extensions[n]->callback(
				    context, wsi->active_extensions[n],
				    wsi, LWS_EXT_CALLBACK_1HZ,
				    wsi->active_extensions_user[n], NULL, sec);

#endif
	if (!wsi->pending_timeout)
		return 0;

	/*
	 * if we went beyond the allowed time, kill the
	 * connection
	 */

	if (sec > wsi->pending_timeout_limit) {
		lwsl_info("TIMEDOUT WAITING\n");
		libwebsocket_close_and_free_session(context,
				wsi, LWS_CLOSE_STATUS_NOSTATUS);
		return 1;
	}

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

#ifndef LWS_NO_EXTENSIONS
	int more = 1;
#endif
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

#ifndef WIN32
		/* if our parent went down, don't linger around */
		if (context->started_with_parent &&
				      kill(context->started_with_parent, 0) < 0)
			kill(getpid(), SIGTERM);
#endif

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

#ifndef LWS_NO_SERVER
	case LWS_CONNMODE_HTTP_SERVING:
	case LWS_CONNMODE_HTTP_SERVING_ACCEPTED:
	case LWS_CONNMODE_SERVER_LISTENER:
	case LWS_CONNMODE_SSL_ACK_PENDING:
		n = lws_server_socket_service(context, wsi, pollfd);
		goto handled;
#endif

	case LWS_CONNMODE_WS_SERVING:
	case LWS_CONNMODE_WS_CLIENT:

		/* the guy requested a callback when it was OK to write */

		if ((pollfd->revents & LWS_POLLOUT) &&
			wsi->state == WSI_STATE_ESTABLISHED &&
			   lws_handle_POLLOUT_event(context, wsi, pollfd) < 0) {
			lwsl_info("libwebsocket_service_fd: closing\n");
			goto close_and_handled;
		}

		if (wsi->u.ws.rxflow_buffer &&
			      (wsi->u.ws.rxflow_change_to & LWS_RXFLOW_ALLOW)) {
			lwsl_info("draining rxflow\n");
			/* well, drain it */
			eff_buf.token = (char *)wsi->u.ws.rxflow_buffer +
						wsi->u.ws.rxflow_pos;
			eff_buf.token_len = wsi->u.ws.rxflow_len -
						wsi->u.ws.rxflow_pos;
			draining_flow = 1;
			goto drain;
		}

		/* any incoming data ready? */

		if (!(pollfd->revents & LWS_POLLIN))
			break;

#ifdef LWS_OPENSSL_SUPPORT
read_pending:
		if (wsi->ssl) {
			eff_buf.token_len = SSL_read(wsi->ssl,
					context->service_buffer,
					       sizeof(context->service_buffer));
			if (!eff_buf.token_len) {
				n = SSL_get_error(wsi->ssl, eff_buf.token_len);
				lwsl_err("SSL_read returned 0 with reason %s\n",
				  ERR_error_string(n,
					      (char *)context->service_buffer));
			}
		} else
#endif
			eff_buf.token_len = recv(pollfd->fd,
				context->service_buffer,
					    sizeof(context->service_buffer), 0);

		if (eff_buf.token_len < 0) {
			lwsl_debug("service_fd read ret = %d, errno = %d\n",
						  eff_buf.token_len, LWS_ERRNO);
			if (LWS_ERRNO != LWS_EINTR && LWS_ERRNO != LWS_EAGAIN)
				goto close_and_handled;
			n = 0;
			goto handled;
		}
		if (!eff_buf.token_len) {
			lwsl_info("service_fd: closing due to 0 length read\n");
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
#ifndef LWS_NO_EXTENSIONS
		more = 1;
		while (more) {

			more = 0;

			for (n = 0; n < wsi->count_active_extensions; n++) {
				m = wsi->active_extensions[n]->callback(context,
					wsi->active_extensions[n], wsi,
					LWS_EXT_CALLBACK_PACKET_RX_PREPARSE,
					wsi->active_extensions_user[n],
								   &eff_buf, 0);
				if (m < 0) {
					lwsl_ext(
					    "Extension reports fatal error\n");
					goto close_and_handled;
				}
				if (m)
					more = 1;
			}
#endif
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
#ifndef LWS_NO_EXTENSIONS
			eff_buf.token = NULL;
			eff_buf.token_len = 0;
		}
#endif
		if (draining_flow && wsi->u.ws.rxflow_buffer &&
				 wsi->u.ws.rxflow_pos == wsi->u.ws.rxflow_len) {
			lwsl_info("flow buffer: drained\n");
			free(wsi->u.ws.rxflow_buffer);
			wsi->u.ws.rxflow_buffer = NULL;
			/* having drained the rxflow buffer, can rearm POLLIN */
			_libwebsocket_rx_flow_control(wsi);
		}

#ifdef LWS_OPENSSL_SUPPORT
		if (wsi->ssl && SSL_pending(wsi->ssl))
			goto read_pending;
#endif
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
	libwebsocket_close_and_free_session(context, wsi,
						LWS_CLOSE_STATUS_NOSTATUS);
	n = 1;

handled:
	pollfd->revents = 0;
	return n;
}

/**
 * libwebsocket_context_destroy() - Destroy the websocket context
 * @context:	Websocket context
 *
 *	This function closes any active connections and then frees the
 *	context.  After calling this, any further use of the context is
 *	undefined.
 */
LWS_VISIBLE void
libwebsocket_context_destroy(struct libwebsocket_context *context)
{
	int n;
#ifndef LWS_NO_EXTENSIONS
	int m;
	struct libwebsocket_extension *ext;
#endif /* ndef LWS_NO_EXTENSIONS */
	struct libwebsocket_protocols *protocol = context->protocols;

#ifdef LWS_LATENCY
	if (context->worst_latency_info[0])
		lwsl_notice("Worst latency: %s\n", context->worst_latency_info);
#endif

	for (n = 0; n < context->fds_count; n++) {
		struct libwebsocket *wsi =
					context->lws_lookup[context->fds[n].fd];
		if (!wsi)
			continue;
		libwebsocket_close_and_free_session(context,
			wsi, LWS_CLOSE_STATUS_NOSTATUS /* no protocol close */);
		n--;
	}

#ifndef LWS_NO_EXTENSIONS
	/*
	 * give all extensions a chance to clean up any per-context
	 * allocations they might have made
	 */

	ext = context->extensions;
	m = LWS_EXT_CALLBACK_CLIENT_CONTEXT_DESTRUCT;
	if (context->listen_port)
		m = LWS_EXT_CALLBACK_SERVER_CONTEXT_DESTRUCT;
	while (ext && ext->callback) {
		ext->callback(context, ext, NULL,
			(enum libwebsocket_extension_callback_reasons)m,
								 NULL, NULL, 0);
		ext++;
	}
#endif /* ndef LWS_NO_EXTENSIONS */

	/*
	 * inform all the protocols that they are done and will have no more
	 * callbacks
	 */

	while (protocol->callback) {
		protocol->callback(context, NULL, LWS_CALLBACK_PROTOCOL_DESTROY,
				NULL, NULL, 0);
		protocol++;
	}


#if defined(WIN32) || defined(_WIN32)
	if (context->events) {
		WSACloseEvent(context->events[0]);
		free(context->events);
	}
#else
	close(context->dummy_pipe_fds[0]);
	close(context->dummy_pipe_fds[1]);
	close(context->fd_random);
#endif

#ifdef LWS_OPENSSL_SUPPORT
	if (context->ssl_ctx)
		SSL_CTX_free(context->ssl_ctx);
	if (context->ssl_client_ctx)
		SSL_CTX_free(context->ssl_client_ctx);

	ERR_remove_state(0);
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
#endif

	if (context->fds)
		free(context->fds);
	if (context->lws_lookup)
		free(context->lws_lookup);

	free(context);

#if defined(WIN32) || defined(_WIN32)
	WSACleanup();
#endif
}

/**
 * libwebsocket_context_user() - get the user data associated with the context
 * @context: Websocket context
 *
 *	This returns the optional user allocation that can be attached to
 *	the context the sockets live in at context_create time.  It's a way
 *	to let all sockets serviced in the same context share data without
 *	using globals statics in the user code.
 */
LWS_EXTERN void *
libwebsocket_context_user(struct libwebsocket_context *context)
{
	return context->user_space;
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
	int n;
#ifdef _WIN32
	int i;
	DWORD ev;
	WSANETWORKEVENTS networkevents;
	struct libwebsocket_pollfd *pfd;
#else
	int m;
	char buf;
#endif

	/* stay dead once we are dead */

	if (context == NULL)
		return 1;

#ifdef LWS_USE_LIBEV
	if (context->io_loop && LWS_LIBEV_ENABLED(context))
		ev_run(context->io_loop, 0);
#endif /* LWS_USE_LIBEV */
	context->service_tid = context->protocols[0].callback(context, NULL,
				     LWS_CALLBACK_GET_THREAD_ID, NULL, NULL, 0);

#ifdef _WIN32
	for (i = 0; i < context->fds_count; ++i) {
		pfd = &context->fds[i];
		if (pfd->fd == context->listen_service_fd)
			continue;
		if (pfd->events & LWS_POLLOUT) {
			if (context->lws_lookup[pfd->fd]->sock_send_blocking)
				continue;
			pfd->revents = LWS_POLLOUT;
			n = libwebsocket_service_fd(context, pfd);
			if (n < 0)
				return n;
		}
	}

	ev = WSAWaitForMultipleEvents(context->fds_count + 1,
				     context->events, FALSE, timeout_ms, FALSE);
	context->service_tid = 0;

	if (ev == WSA_WAIT_TIMEOUT) {
		libwebsocket_service_fd(context, NULL);
		return 0;
	}

	if (ev == WSA_WAIT_EVENT_0) {
		WSAResetEvent(context->events[0]);
		return 0;
	}

	if (ev < WSA_WAIT_EVENT_0 || ev > WSA_WAIT_EVENT_0 + context->fds_count)
		return -1;

	pfd = &context->fds[ev - WSA_WAIT_EVENT_0 - 1];

	if (WSAEnumNetworkEvents(pfd->fd, context->events[ev - WSA_WAIT_EVENT_0],
			&networkevents) == SOCKET_ERROR) {
		lwsl_err("WSAEnumNetworkEvents() failed with error %d\n", LWS_ERRNO);
		return -1;
	}

	pfd->revents = networkevents.lNetworkEvents;

	if (pfd->revents & LWS_POLLOUT)
		context->lws_lookup[pfd->fd]->sock_send_blocking = FALSE;

	return libwebsocket_service_fd(context, pfd);
#else
	n = poll(context->fds, context->fds_count, timeout_ms);
	context->service_tid = 0;

	if (n == 0) /* poll timeout */ {
		libwebsocket_service_fd(context, NULL);
		return 0;
	}

	if (n < 0) {
		if (LWS_ERRNO != LWS_EINTR)
			return -1;
		else
			return 0;
	}

	/* any socket with events to service? */

	for (n = 0; n < context->fds_count; n++) {
		if (!context->fds[n].revents)
			continue;

		if (context->fds[n].fd == context->dummy_pipe_fds[0]) {
			if (read(context->fds[n].fd, &buf, 1) != 1)
				lwsl_err("Cannot read from dummy pipe.");
			continue;
		}

		m = libwebsocket_service_fd(context, &context->fds[n]);
		if (m < 0)
			return -1;
		/* if something closed, retry this slot */
		if (m)
			n--;
	}

	return 0;
#endif
}




#ifndef LWS_NO_EXTENSIONS
int
lws_any_extension_handled(struct libwebsocket_context *context,
			  struct libwebsocket *wsi,
			  enum libwebsocket_extension_callback_reasons r,
						       void *v, size_t len)
{
	int n;
	int handled = 0;

	/* maybe an extension will take care of it for us */

	for (n = 0; n < wsi->count_active_extensions && !handled; n++) {
		if (!wsi->active_extensions[n]->callback)
			continue;

		handled |= wsi->active_extensions[n]->callback(context,
			wsi->active_extensions[n], wsi,
			r, wsi->active_extensions_user[n], v, len);
	}

	return handled;
}


void *
lws_get_extension_user_matching_ext(struct libwebsocket *wsi,
					   struct libwebsocket_extension *ext)
{
	int n = 0;

	if (wsi == NULL)
		return NULL;

	while (n < wsi->count_active_extensions) {
		if (wsi->active_extensions[n] != ext) {
			n++;
			continue;
		}
		return wsi->active_extensions_user[n];
	}

	return NULL;
}
#endif

void
lws_change_pollfd(struct libwebsocket *wsi, int _and, int _or)
{
	struct libwebsocket_context *context = wsi->protocol->owning_server;
	int tid;
	int sampled_tid;
	struct libwebsocket_pollfd *pfd;
	struct libwebsocket_pollargs pa;
#ifdef _WIN32
	long networkevents = LWS_POLLOUT | LWS_POLLHUP;
#endif

	pfd = &context->fds[wsi->position_in_fds_table];
	pa.fd = wsi->sock;

	context->protocols[0].callback(context, wsi,
		LWS_CALLBACK_LOCK_POLL,
		wsi->user_space,  (void *) &pa, 0);

	pa.prev_events = pfd->events;

	pa.events = pfd->events = (pfd->events & ~_and) | _or;

	context->protocols[0].callback(context, wsi,
			LWS_CALLBACK_CHANGE_MODE_POLL_FD,
			wsi->user_space, (void *) &pa, 0);

	/*
	 * if we changed something in this pollfd...
	 *   ... and we're running in a different thread context
	 *     than the service thread...
	 *       ... and the service thread is waiting ...
	 *         then cancel it to force a restart with our changed events
	 */
	if (pa.prev_events != pa.events) {
#ifdef _WIN32
		if ((pfd->events & LWS_POLLIN))
			networkevents |= LWS_POLLIN;

		if (WSAEventSelect(wsi->sock,
			context->events[wsi->position_in_fds_table + 1],
			networkevents) == SOCKET_ERROR) {
			lwsl_err("WSAEventSelect() failed with error %d\n",
								     LWS_ERRNO);
		}
#endif

		sampled_tid = context->service_tid;
		if (sampled_tid) {
			tid = context->protocols[0].callback(context, NULL,
				     LWS_CALLBACK_GET_THREAD_ID, NULL, NULL, 0);
			if (tid != sampled_tid)
				libwebsocket_cancel_service(context);
		}
	}

	context->protocols[0].callback(context, wsi,
		LWS_CALLBACK_UNLOCK_POLL,
		wsi->user_space, (void *) &pa, 0);
}


/**
 * libwebsocket_callback_on_writable() - Request a callback when this socket
 *					 becomes able to be written to without
 *					 blocking
 *
 * @context:	libwebsockets context
 * @wsi:	Websocket connection instance to get callback for
 */

LWS_VISIBLE int
libwebsocket_callback_on_writable(struct libwebsocket_context *context,
						      struct libwebsocket *wsi)
{
#ifndef LWS_NO_EXTENSIONS
	int n;
	int handled = 0;

	/* maybe an extension will take care of it for us */

	for (n = 0; n < wsi->count_active_extensions; n++) {
		if (!wsi->active_extensions[n]->callback)
			continue;

		handled |= wsi->active_extensions[n]->callback(context,
			wsi->active_extensions[n], wsi,
			LWS_EXT_CALLBACK_REQUEST_ON_WRITEABLE,
				       wsi->active_extensions_user[n], NULL, 0);
	}

	if (handled)
		return 1;
#endif
	if (wsi->position_in_fds_table < 0) {
		lwsl_err("%s: failed to find socket %d\n", __func__, wsi->sock);
		return -1;
	}

	lws_change_pollfd(wsi, 0, LWS_POLLOUT);
#ifdef LWS_USE_LIBEV
	if (LWS_LIBEV_ENABLED(context))
		ev_io_start(context->io_loop, (struct ev_io *)&wsi->w_write);
#endif /* LWS_USE_LIBEV */

	return 1;
}

/**
 * libwebsocket_callback_on_writable_all_protocol() - Request a callback for
 *			all connections using the given protocol when it
 *			becomes possible to write to each socket without
 *			blocking in turn.
 *
 * @protocol:	Protocol whose connections will get callbacks
 */

LWS_VISIBLE int
libwebsocket_callback_on_writable_all_protocol(
				  const struct libwebsocket_protocols *protocol)
{
	struct libwebsocket_context *context = protocol->owning_server;
	int n;
	struct libwebsocket *wsi;

	for (n = 0; n < context->fds_count; n++) {
		wsi = context->lws_lookup[context->fds[n].fd];
		if (!wsi)
			continue;
		if (wsi->protocol == protocol)
			libwebsocket_callback_on_writable(context, wsi);
	}

	return 0;
}

/**
 * libwebsocket_callback_all_protocol() - Callback all connections using
 *				the given protocol with the given reason
 *
 * @protocol:	Protocol whose connections will get callbacks
 * @reason:	Callback reason index
 */

LWS_VISIBLE int
libwebsocket_callback_all_protocol(
		const struct libwebsocket_protocols *protocol, int reason)
{
	struct libwebsocket_context *context = protocol->owning_server;
	int n;
	struct libwebsocket *wsi;

	for (n = 0; n < context->fds_count; n++) {
		wsi = context->lws_lookup[context->fds[n].fd];
		if (!wsi)
			continue;
		if (wsi->protocol == protocol)
			protocol->callback(context, wsi,
					reason, wsi->user_space, NULL, 0);
	}

	return 0;
}

/**
 * libwebsocket_set_timeout() - marks the wsi as subject to a timeout
 *
 * You will not need this unless you are doing something special
 *
 * @wsi:	Websocket connection instance
 * @reason:	timeout reason
 * @secs:	how many seconds
 */

LWS_VISIBLE void
libwebsocket_set_timeout(struct libwebsocket *wsi,
					  enum pending_timeout reason, int secs)
{
	time_t now;

	time(&now);

	wsi->pending_timeout_limit = now + secs;
	wsi->pending_timeout = reason;
}


/**
 * libwebsocket_get_socket_fd() - returns the socket file descriptor
 *
 * You will not need this unless you are doing something special
 *
 * @wsi:	Websocket connection instance
 */

LWS_VISIBLE int
libwebsocket_get_socket_fd(struct libwebsocket *wsi)
{
	return wsi->sock;
}

#ifdef LWS_LATENCY
void
lws_latency(struct libwebsocket_context *context, struct libwebsocket *wsi,
				     const char *action, int ret, int completed)
{
	unsigned long long u;
	char buf[256];

	u = time_in_microseconds();

	if (!action) {
		wsi->latency_start = u;
		if (!wsi->action_start)
			wsi->action_start = u;
		return;
	}
	if (completed) {
		if (wsi->action_start == wsi->latency_start)
			sprintf(buf,
			  "Completion first try lat %luus: %p: ret %d: %s\n",
					u - wsi->latency_start,
						      (void *)wsi, ret, action);
		else
			sprintf(buf,
			  "Completion %luus: lat %luus: %p: ret %d: %s\n",
				u - wsi->action_start,
					u - wsi->latency_start,
						      (void *)wsi, ret, action);
		wsi->action_start = 0;
	} else
		sprintf(buf, "lat %luus: %p: ret %d: %s\n",
			      u - wsi->latency_start, (void *)wsi, ret, action);

	if (u - wsi->latency_start > context->worst_latency) {
		context->worst_latency = u - wsi->latency_start;
		strcpy(context->worst_latency_info, buf);
	}
	lwsl_latency("%s", buf);
}
#endif

#ifdef LWS_NO_SERVER
int
_libwebsocket_rx_flow_control(struct libwebsocket *wsi)
{
	return 0;
}
#else
int
_libwebsocket_rx_flow_control(struct libwebsocket *wsi)
{
	struct libwebsocket_context *context = wsi->protocol->owning_server;

	/* there is no pending change */
	if (!(wsi->u.ws.rxflow_change_to & LWS_RXFLOW_PENDING_CHANGE))
		return 0;

	/* stuff is still buffered, not ready to really accept new input */
	if (wsi->u.ws.rxflow_buffer) {
		/* get ourselves called back to deal with stashed buffer */
		libwebsocket_callback_on_writable(context, wsi);
		return 0;
	}

	/* pending is cleared, we can change rxflow state */

	wsi->u.ws.rxflow_change_to &= ~LWS_RXFLOW_PENDING_CHANGE;

	lwsl_info("rxflow: wsi %p change_to %d\n", wsi,
			      wsi->u.ws.rxflow_change_to & LWS_RXFLOW_ALLOW);

	/* adjust the pollfd for this wsi */

	if (wsi->u.ws.rxflow_change_to & LWS_RXFLOW_ALLOW)
		lws_change_pollfd(wsi, 0, LWS_POLLIN);
	else
		lws_change_pollfd(wsi, LWS_POLLIN, 0);

	return 1;
}
#endif

/**
 * libwebsocket_rx_flow_control() - Enable and disable socket servicing for
 *				receieved packets.
 *
 * If the output side of a server process becomes choked, this allows flow
 * control for the input side.
 *
 * @wsi:	Websocket connection instance to get callback for
 * @enable:	0 = disable read servicing for this connection, 1 = enable
 */

LWS_VISIBLE int
libwebsocket_rx_flow_control(struct libwebsocket *wsi, int enable)
{
	if (enable == (wsi->u.ws.rxflow_change_to & LWS_RXFLOW_ALLOW))
		return 0;

	lwsl_info("libwebsocket_rx_flow_control(0x%p, %d)\n", wsi, enable);
	wsi->u.ws.rxflow_change_to = LWS_RXFLOW_PENDING_CHANGE | !!enable;

	return 0;
}

/**
 * libwebsocket_rx_flow_allow_all_protocol() - Allow all connections with this protocol to receive
 *
 * When the user server code realizes it can accept more input, it can
 * call this to have the RX flow restriction removed from all connections using
 * the given protocol.
 *
 * @protocol:	all connections using this protocol will be allowed to receive
 */

LWS_VISIBLE void
libwebsocket_rx_flow_allow_all_protocol(
				const struct libwebsocket_protocols *protocol)
{
	struct libwebsocket_context *context = protocol->owning_server;
	int n;
	struct libwebsocket *wsi;

	for (n = 0; n < context->fds_count; n++) {
		wsi = context->lws_lookup[context->fds[n].fd];
		if (!wsi)
			continue;
		if (wsi->protocol == protocol)
			libwebsocket_rx_flow_control(wsi, LWS_RXFLOW_ALLOW);
	}
}


/**
 * libwebsocket_canonical_hostname() - returns this host's hostname
 *
 * This is typically used by client code to fill in the host parameter
 * when making a client connection.  You can only call it after the context
 * has been created.
 *
 * @context:	Websocket context
 */
LWS_VISIBLE extern const char *
libwebsocket_canonical_hostname(struct libwebsocket_context *context)
{
	return (const char *)context->canonical_hostname;
}


static void sigpipe_handler(int x)
{
}

#ifdef LWS_OPENSSL_SUPPORT
static int
OpenSSL_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{

	SSL *ssl;
	int n;
	struct libwebsocket_context *context;

	ssl = X509_STORE_CTX_get_ex_data(x509_ctx,
		SSL_get_ex_data_X509_STORE_CTX_idx());

	/*
	 * !!! nasty openssl requires the index to come as a library-scope
	 * static
	 */
	context = SSL_get_ex_data(ssl, openssl_websocket_private_data_index);

	n = context->protocols[0].callback(NULL, NULL,
		LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION,
						   x509_ctx, ssl, preverify_ok);

	/* convert return code from 0 = OK to 1 = OK */

	if (!n)
		n = 1;
	else
		n = 0;

	return n;
}
#endif

int user_callback_handle_rxflow(callback_function callback_function,
		struct libwebsocket_context *context,
			struct libwebsocket *wsi,
			 enum libwebsocket_callback_reasons reason, void *user,
							  void *in, size_t len)
{
	int n;

	n = callback_function(context, wsi, reason, user, in, len);
	if (!n)
		n = _libwebsocket_rx_flow_control(wsi);

	return n;
}

/*
 * This is just used to interrupt poll waiting
 * we don't have to do anything with it.
 */
#ifdef LWS_OPENSSL_SUPPORT
static void lws_sigusr2(int sig)
{
}
#endif

/**
 * libwebsocket_create_context() - Create the websocket handler
 * @info:	pointer to struct with parameters
 *
 *	This function creates the listening socket (if serving) and takes care
 *	of all initialization in one step.
 *
 *	After initialization, it returns a struct libwebsocket_context * that
 *	represents this server.  After calling, user code needs to take care
 *	of calling libwebsocket_service() with the context pointer to get the
 *	server's sockets serviced.  This can be done in the same process context
 *	or a forked process, or another thread,
 *
 *	The protocol callback functions are called for a handful of events
 *	including http requests coming in, websocket connections becoming
 *	established, and data arriving; it's also called periodically to allow
 *	async transmission.
 *
 *	HTTP requests are sent always to the FIRST protocol in @protocol, since
 *	at that time websocket protocol has not been negotiated.  Other
 *	protocols after the first one never see any HTTP callack activity.
 *
 *	The server created is a simple http server by default; part of the
 *	websocket standard is upgrading this http connection to a websocket one.
 *
 *	This allows the same server to provide files like scripts and favicon /
 *	images or whatever over http and dynamic data over websockets all in
 *	one place; they're all handled in the user callback.
 */

LWS_VISIBLE struct libwebsocket_context *
libwebsocket_create_context(struct lws_context_creation_info *info)
{
	struct libwebsocket_context *context = NULL;
	char *p;
	int n;
#ifndef LWS_NO_SERVER
	int opt = 1;
	struct libwebsocket *wsi;
#ifdef LWS_USE_IPV6
	struct sockaddr_in6 serv_addr6;
#endif
	struct sockaddr_in serv_addr4;
	struct sockaddr *v;
#endif
#ifndef LWS_NO_EXTENSIONS
	int m;
	struct libwebsocket_extension *ext;
#endif

#ifdef LWS_OPENSSL_SUPPORT
	SSL_METHOD *method;
#endif

#ifndef LWS_NO_DAEMONIZE
	int pid_daemon = get_daemonize_pid();
#endif

	lwsl_notice("Initial logging level %d\n", log_level);
	lwsl_notice("Library version: %s\n", library_version);
#ifdef LWS_USE_IPV6
	if (!(info->options & LWS_SERVER_OPTION_DISABLE_IPV6))
		lwsl_notice("IPV6 compiled in and enabled\n");
	else
		lwsl_notice("IPV6 compiled in but disabled\n");
#else
	lwsl_notice("IPV6 not compiled in\n");
#endif
#ifdef LWS_USE_LIBEV
	if (info->options & LWS_SERVER_OPTION_LIBEV)
		lwsl_notice("libev support compiled in and enabled\n");
	else
		lwsl_notice("libev support compiled in but disabled\n");
#else
	lwsl_notice("libev support not compiled in\n");
#endif
	lwsl_info(" LWS_MAX_HEADER_LEN: %u\n", LWS_MAX_HEADER_LEN);
	lwsl_info(" LWS_MAX_PROTOCOLS: %u\n", LWS_MAX_PROTOCOLS);
#ifndef LWS_NO_EXTENSIONS
	lwsl_info(" LWS_MAX_EXTENSIONS_ACTIVE: %u\n",
						LWS_MAX_EXTENSIONS_ACTIVE);
#else
	lwsl_notice(" Configured without extension support\n");
#endif
	lwsl_info(" SPEC_LATEST_SUPPORTED: %u\n", SPEC_LATEST_SUPPORTED);
	lwsl_info(" AWAITING_TIMEOUT: %u\n", AWAITING_TIMEOUT);
	if (info->ssl_cipher_list)
		lwsl_info(" SSL ciphers: '%s'\n", info->ssl_cipher_list);
	lwsl_info(" SYSTEM_RANDOM_FILEPATH: '%s'\n", SYSTEM_RANDOM_FILEPATH);
	lwsl_info(" LWS_MAX_ZLIB_CONN_BUFFER: %u\n", LWS_MAX_ZLIB_CONN_BUFFER);

#ifdef _WIN32
	{
		WORD wVersionRequested;
		WSADATA wsaData;
		int err;

		/* Use the MAKEWORD(lowbyte, highbyte) macro from Windef.h */
		wVersionRequested = MAKEWORD(2, 2);

		err = WSAStartup(wVersionRequested, &wsaData);
		if (err) {
			/*
			 * Tell the user that we could not find a usable
			 * Winsock DLL
			 */
			lwsl_err("WSAStartup failed with error: %d\n", err);
			return NULL;
		}
	}
#endif

	context = (struct libwebsocket_context *)
				malloc(sizeof(struct libwebsocket_context));
	if (!context) {
		lwsl_err("No memory for websocket context\n");
		return NULL;
	}
	memset(context, 0, sizeof(*context));
#ifndef LWS_NO_DAEMONIZE
	context->started_with_parent = pid_daemon;
	lwsl_notice(" Started with daemon pid %d\n", pid_daemon);
#endif

	context->listen_service_extraseen = 0;
	context->protocols = info->protocols;
	context->listen_port = info->port;
	context->http_proxy_port = 0;
	context->http_proxy_address[0] = '\0';
	context->options = info->options;
	context->iface = info->iface;
	/* to reduce this allocation, */
	context->max_fds = getdtablesize();
	lwsl_notice(" static allocation: %u + (%u x %u fds) = %u bytes\n",
		sizeof(struct libwebsocket_context),
		sizeof(struct libwebsocket_pollfd) +
					sizeof(struct libwebsocket *),
		context->max_fds,
		sizeof(struct libwebsocket_context) +
		((sizeof(struct libwebsocket_pollfd) +
					sizeof(struct libwebsocket *)) *
							     context->max_fds));

	context->fds = (struct libwebsocket_pollfd *)
				malloc(sizeof(struct libwebsocket_pollfd) *
							      context->max_fds);
	if (context->fds == NULL) {
		lwsl_err("Unable to allocate fds array for %d connections\n",
							      context->max_fds);
		free(context);
		return NULL;
	}

#ifdef LWS_USE_LIBEV
	if (LWS_LIBEV_ENABLED(context)) {
		context->w_accept.context = context;
		context->w_sigint.context = context;
	}
#endif /* LWS_USE_LIBEV */

	context->lws_lookup = (struct libwebsocket **)
		      malloc(sizeof(struct libwebsocket *) * context->max_fds);
	if (context->lws_lookup == NULL) {
		lwsl_err(
		  "Unable to allocate lws_lookup array for %d connections\n",
							      context->max_fds);
		free(context->fds);
		free(context);
		return NULL;
	}
	memset(context->lws_lookup, 0, sizeof(struct libwebsocket *) *
							context->max_fds);

#ifdef _WIN32
	context->events = (WSAEVENT *)malloc(sizeof(WSAEVENT) *
		(context->max_fds + 1));
	if (context->events == NULL) {
		lwsl_err("Unable to allocate events array for %d connections\n",
			context->max_fds);
		free(context->lws_lookup);
		free(context->fds);
		free(context);
		return NULL;
	}
#endif

	if (!LWS_LIBEV_ENABLED(context)) {
	#ifdef _WIN32
		context->fds_count = 0;
		context->events[0] = WSACreateEvent();
	#else
		if (pipe(context->dummy_pipe_fds)) {
			lwsl_err("Unable to create pipe\n");
			free(context->lws_lookup);
			free(context->fds);
			free(context);
			return NULL;
		}

		/* use the read end of pipe as first item */
		context->fds[0].fd = context->dummy_pipe_fds[0];
		context->fds[0].events = LWS_POLLIN;
		context->fds[0].revents = 0;
		context->fds_count = 1;
	#endif
	}

#ifndef LWS_NO_EXTENSIONS
	context->extensions = info->extensions;
#endif
	context->last_timeout_check_s = 0;
	context->user_space = info->user;

#if defined(WIN32) || defined(_WIN32)
	context->fd_random = 0;
#else
	context->fd_random = open(SYSTEM_RANDOM_FILEPATH, O_RDONLY);
	if (context->fd_random < 0) {
		lwsl_err("Unable to open random device %s %d\n",
				    SYSTEM_RANDOM_FILEPATH, context->fd_random);
		goto bail;
	}
#endif

#ifdef LWS_OPENSSL_SUPPORT
	context->use_ssl = 0;
	context->allow_non_ssl_on_ssl_port = 0;
	context->ssl_ctx = NULL;
	context->ssl_client_ctx = NULL;
	openssl_websocket_private_data_index = 0;
#endif

	strcpy(context->canonical_hostname, "unknown");

#ifndef LWS_NO_SERVER
	if (!(info->options & LWS_SERVER_OPTION_SKIP_SERVER_CANONICAL_NAME)) {
		/* find canonical hostname */
		gethostname((char *)context->canonical_hostname,
				       sizeof(context->canonical_hostname) - 1);

		lwsl_notice(" canonical_hostname = %s\n",
					context->canonical_hostname);
	}
#endif

	/* split the proxy ads:port if given */

	if (info->http_proxy_address) {
		strncpy(context->http_proxy_address, info->http_proxy_address,
				      sizeof(context->http_proxy_address) - 1);
		context->http_proxy_address[
				sizeof(context->http_proxy_address) - 1] = '\0';
		context->http_proxy_port = info->http_proxy_port;
	} else {
#ifdef HAVE_GETENV
		p = getenv("http_proxy");
		if (p) {
			strncpy(context->http_proxy_address, p,
				       sizeof(context->http_proxy_address) - 1);
			context->http_proxy_address[
				sizeof(context->http_proxy_address) - 1] = '\0';

			p = strchr(context->http_proxy_address, ':');
			if (p == NULL) {
				lwsl_err("http_proxy needs to be ads:port\n");
				goto bail;
			}
			*p = '\0';
			context->http_proxy_port = atoi(p + 1);
		}
#endif
	}

	if (context->http_proxy_address[0]) {
		lwsl_notice(" Proxy %s:%u\n",
				context->http_proxy_address,
						      context->http_proxy_port);
	}

#ifndef LWS_NO_SERVER
	if (info->port != CONTEXT_PORT_NO_LISTEN) {

#ifdef LWS_OPENSSL_SUPPORT
		context->use_ssl = info->ssl_cert_filepath != NULL &&
					 info->ssl_private_key_filepath != NULL;
#ifdef USE_CYASSL
		lwsl_notice(" Compiled with CYASSL support\n");
#else
		lwsl_notice(" Compiled with OpenSSL support\n");
#endif
		if (context->use_ssl)
			lwsl_notice(" Using SSL mode\n");
		else
			lwsl_notice(" Using non-SSL mode\n");

#else
		if (info->ssl_cert_filepath != NULL &&
				       info->ssl_private_key_filepath != NULL) {
			lwsl_notice(" Not compiled for OpenSSl support!\n");
			goto bail;
		}
		lwsl_notice(" Compiled without SSL support\n");
#endif

		lwsl_notice(
			" per-conn mem: %u + %u headers + protocol rx buf\n",
				sizeof(struct libwebsocket),
					      sizeof(struct allocated_headers));
	}
#endif

	/* ignore SIGPIPE */
#if defined(WIN32) || defined(_WIN32)
#else
	signal(SIGPIPE, sigpipe_handler);
#endif


#ifdef LWS_OPENSSL_SUPPORT

	/* basic openssl init */

	SSL_library_init();

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	openssl_websocket_private_data_index =
		SSL_get_ex_new_index(0, "libwebsockets", NULL, NULL, NULL);

	/*
	 * Firefox insists on SSLv23 not SSLv3
	 * Konq disables SSLv2 by default now, SSLv23 works
	 */

	method = (SSL_METHOD *)SSLv23_server_method();
	if (!method) {
        int error = ERR_get_error();
		lwsl_err("problem creating ssl method %lu: %s\n", 
			error,
			ERR_error_string(error,
					      (char *)context->service_buffer));
		goto bail;
	}
	context->ssl_ctx = SSL_CTX_new(method);	/* create context */
	if (!context->ssl_ctx) {
        int error = ERR_get_error();
		lwsl_err("problem creating ssl context %lu: %s\n",
                 error,
                 ERR_error_string(error,
                                  (char *)context->service_buffer));
		goto bail;
	}

#if defined(WIN32) || defined(_WIN32)
#else
	signal(SIGUSR2, lws_sigusr2);
	{
		sigset_t mask;
		sigemptyset (&mask);
		sigaddset (&mask, SIGUSR2);

		sigprocmask(SIG_BLOCK, &mask, NULL);
	}
#endif

#ifdef SSL_OP_NO_COMPRESSION
	SSL_CTX_set_options(context->ssl_ctx, SSL_OP_NO_COMPRESSION);
#endif
	SSL_CTX_set_options(context->ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	if (info->ssl_cipher_list)
		SSL_CTX_set_cipher_list(context->ssl_ctx,
						info->ssl_cipher_list);

#ifndef LWS_NO_CLIENT

	/* client context */

	if (info->port == CONTEXT_PORT_NO_LISTEN) {
		method = (SSL_METHOD *)SSLv23_client_method();
		if (!method) {
            int error = ERR_get_error();
			lwsl_err("problem creating ssl method %lu: %s\n",
                     error,
                     ERR_error_string(error,
					      (char *)context->service_buffer));
			goto bail;
		}
		/* create context */
		context->ssl_client_ctx = SSL_CTX_new(method);
		if (!context->ssl_client_ctx) {
            int error = ERR_get_error();
			lwsl_err("problem creating ssl context %lu: %s\n",
                     error,
                     ERR_error_string(error,
					      (char *)context->service_buffer));
			goto bail;
		}

#ifdef SSL_OP_NO_COMPRESSION
		SSL_CTX_set_options(context->ssl_client_ctx,
							 SSL_OP_NO_COMPRESSION);
#endif
		SSL_CTX_set_options(context->ssl_client_ctx,
					       SSL_OP_CIPHER_SERVER_PREFERENCE);
		if (info->ssl_cipher_list)
			SSL_CTX_set_cipher_list(context->ssl_client_ctx,
							info->ssl_cipher_list);

#ifdef LWS_SSL_CLIENT_USE_OS_CA_CERTS
		/* loads OS default CA certs */
		SSL_CTX_set_default_verify_paths(context->ssl_client_ctx);
#endif

		/* openssl init for cert verification (for client sockets) */
		if (!info->ssl_ca_filepath) {
			if (!SSL_CTX_load_verify_locations(
				context->ssl_client_ctx, NULL,
						     LWS_OPENSSL_CLIENT_CERTS))
				lwsl_err(
				    "Unable to load SSL Client certs from %s "
				    "(set by --with-client-cert-dir= "
				    "in configure) --  client ssl isn't "
				    "going to work", LWS_OPENSSL_CLIENT_CERTS);
		} else
			if (!SSL_CTX_load_verify_locations(
				context->ssl_client_ctx, info->ssl_ca_filepath,
								  NULL))
				lwsl_err(
					"Unable to load SSL Client certs "
					"file from %s -- client ssl isn't "
					"going to work", info->ssl_ca_filepath);

		/*
		 * callback allowing user code to load extra verification certs
		 * helping the client to verify server identity
		 */

		/* support for client-side certificate authentication */
		if (info->ssl_cert_filepath) {
			n = SSL_CTX_use_certificate_chain_file(
				context->ssl_client_ctx,
						info->ssl_cert_filepath);
			if (n != 1) {
				lwsl_err("problem getting cert '%s' %lu: %s\n",
					info->ssl_cert_filepath,
					ERR_get_error(),
					ERR_error_string(ERR_get_error(),
					(char *)context->service_buffer));
				goto bail;
			}
		} 
		if (info->ssl_private_key_filepath) {
			/* set the private key from KeyFile */
			if (SSL_CTX_use_PrivateKey_file(context->ssl_client_ctx,
				     info->ssl_private_key_filepath,
						       SSL_FILETYPE_PEM) != 1) {
				lwsl_err("use_PrivateKey_file '%s' %lu: %s\n",
					info->ssl_private_key_filepath,
					ERR_get_error(),
					ERR_error_string(ERR_get_error(),
					      (char *)context->service_buffer));
				goto bail;
			}

			/* verify private key */
			if (!SSL_CTX_check_private_key(
						context->ssl_client_ctx)) {
				lwsl_err("Private SSL key doesn't match cert\n");
				goto bail;
			}
		} 

		context->protocols[0].callback(context, NULL,
			LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS,
			context->ssl_client_ctx, NULL, 0);
	}
#endif

	/* as a server, are we requiring clients to identify themselves? */

	if (info->options &
			LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT) {

		/* absolutely require the client cert */

		SSL_CTX_set_verify(context->ssl_ctx,
		       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
						       OpenSSL_verify_callback);

		/*
		 * give user code a chance to load certs into the server
		 * allowing it to verify incoming client certs
		 */

		context->protocols[0].callback(context, NULL,
			LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS,
						     context->ssl_ctx, NULL, 0);
	}

	if (info->options & LWS_SERVER_OPTION_ALLOW_NON_SSL_ON_SSL_PORT) {
		/* Normally SSL listener rejects non-ssl, optionally allow */
		context->allow_non_ssl_on_ssl_port = 1;
	}

	if (context->use_ssl) {

		/* openssl init for server sockets */

		/* set the local certificate from CertFile */
		n = SSL_CTX_use_certificate_chain_file(context->ssl_ctx,
					info->ssl_cert_filepath);
		if (n != 1) {
            int error = ERR_get_error();
			lwsl_err("problem getting cert '%s' %lu: %s\n",
				info->ssl_cert_filepath,
				error,
				ERR_error_string(error,
					      (char *)context->service_buffer));
			goto bail;
		}
		/* set the private key from KeyFile */
		if (SSL_CTX_use_PrivateKey_file(context->ssl_ctx,
			     info->ssl_private_key_filepath,
						       SSL_FILETYPE_PEM) != 1) {
            int error = ERR_get_error();
			lwsl_err("ssl problem getting key '%s' %lu: %s\n",
				info->ssl_private_key_filepath,
					error,
					ERR_error_string(error,
					      (char *)context->service_buffer));
			goto bail;
		}
		/* verify private key */
		if (!SSL_CTX_check_private_key(context->ssl_ctx)) {
			lwsl_err("Private SSL key doesn't match cert\n");
			goto bail;
		}

		/* SSL is happy and has a cert it's content with */
	}
#endif

#ifndef LWS_NO_SERVER
	/* set up our external listening socket we serve on */

	if (info->port != CONTEXT_PORT_NO_LISTEN) {
		int sockfd;
		struct sockaddr_in sin;
		socklen_t len = sizeof(sin);

#ifdef LWS_USE_IPV6
		if (LWS_IPV6_ENABLED(context))
			sockfd = socket(AF_INET6, SOCK_STREAM, 0);
		else
#endif
			sockfd = socket(AF_INET, SOCK_STREAM, 0);

		if (sockfd < 0) {
			lwsl_err("ERROR opening socket\n");
			goto bail;
		}

		/*
		 * allow us to restart even if old sockets in TIME_WAIT
		 */
		setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
					      (const void *)&opt, sizeof(opt));

		lws_set_socket_options(context, sockfd);

#ifdef LWS_USE_IPV6
		if (LWS_IPV6_ENABLED(context)) {
			v = (struct sockaddr *)&serv_addr6;
			n = sizeof(struct sockaddr_in6);
			bzero((char *) &serv_addr6, sizeof(serv_addr6));
			serv_addr6.sin6_addr = in6addr_any;
			serv_addr6.sin6_family = AF_INET6;
			serv_addr6.sin6_port = htons(info->port);
		} else
#endif
		{
			v = (struct sockaddr *)&serv_addr4;
			n = sizeof(serv_addr4);
			bzero((char *) &serv_addr4, sizeof(serv_addr4));
			serv_addr4.sin_addr.s_addr = INADDR_ANY;
			serv_addr4.sin_family = AF_INET;
			serv_addr4.sin_port = htons(info->port);

			if (info->iface) {
				if (interface_to_sa(context, info->iface,
					   (struct sockaddr_in *)v, n) < 0) {
					lwsl_err("Unable to find interface %s\n",
								info->iface);
					compatible_close(sockfd);
					goto bail;
				}
			}
		} /* ipv4 */

		n = bind(sockfd, v, n);
		if (n < 0) {
			lwsl_err("ERROR on binding to port %d (%d %d)\n",
						      info->port, n, LWS_ERRNO);
			compatible_close(sockfd);
			goto bail;
		}
		
		if (getsockname(sockfd, (struct sockaddr *)&sin, &len) == -1)
			lwsl_warn("getsockname: %s\n", strerror(LWS_ERRNO));
		else
			info->port = ntohs(sin.sin_port);
	
		context->listen_port = info->port;

		wsi = (struct libwebsocket *)malloc(
					sizeof(struct libwebsocket));
		if (wsi == NULL) {
			lwsl_err("Out of mem\n");
			compatible_close(sockfd);
			goto bail;
		}
		memset(wsi, 0, sizeof(struct libwebsocket));
		wsi->sock = sockfd;
#ifndef LWS_NO_EXTENSIONS
		wsi->count_active_extensions = 0;
#endif
		wsi->mode = LWS_CONNMODE_SERVER_LISTENER;

		insert_wsi_socket_into_fds(context, wsi);

		context->listen_service_modulo = LWS_LISTEN_SERVICE_MODULO;
		context->listen_service_count = 0;
		context->listen_service_fd = sockfd;

		listen(sockfd, LWS_SOMAXCONN);
		lwsl_notice(" Listening on port %d\n", info->port);
	}
#endif

	/*
	 * drop any root privs for this process
	 * to listen on port < 1023 we would have needed root, but now we are
	 * listening, we don't want the power for anything else
	 */
#if defined(WIN32) || defined(_WIN32)
#else
	if (info->gid != -1)
		if (setgid(info->gid))
			lwsl_warn("setgid: %s\n", strerror(LWS_ERRNO));
	if (info->uid != -1)
		if (setuid(info->uid))
			lwsl_warn("setuid: %s\n", strerror(LWS_ERRNO));
#endif

	/* initialize supported protocols */

	for (context->count_protocols = 0;
		info->protocols[context->count_protocols].callback;
						   context->count_protocols++) {

		lwsl_parser("  Protocol: %s\n",
				info->protocols[context->count_protocols].name);

		info->protocols[context->count_protocols].owning_server =
									context;
		info->protocols[context->count_protocols].protocol_index =
						       context->count_protocols;

		/*
		 * inform all the protocols that they are doing their one-time
		 * initialization if they want to
		 */
		info->protocols[context->count_protocols].callback(context,
			       NULL, LWS_CALLBACK_PROTOCOL_INIT, NULL, NULL, 0);
	}

#ifndef LWS_NO_EXTENSIONS
	/*
	 * give all extensions a chance to create any per-context
	 * allocations they need
	 */

	m = LWS_EXT_CALLBACK_CLIENT_CONTEXT_CONSTRUCT;
	if (info->port != CONTEXT_PORT_NO_LISTEN)
		m = LWS_EXT_CALLBACK_SERVER_CONTEXT_CONSTRUCT;

	if (info->extensions) {
		ext = info->extensions;
		while (ext->callback) {
			lwsl_ext("  Extension: %s\n", ext->name);
			ext->callback(context, ext, NULL,
			(enum libwebsocket_extension_callback_reasons)m,
								NULL, NULL, 0);
			ext++;
		}
	}
#endif

	return context;

bail:
	libwebsocket_context_destroy(context);
	return NULL;
}

/**
 * libwebsocket_set_proxy() - Setups proxy to libwebsocket_context.
 * @context:	pointer to struct libwebsocket_context you want set proxy to
 * @proxy: pointer to c string containing proxy in format address:port
 *
 * Returns 0 if proxy string was parsed and proxy was setup. 
 * Returns -1 if @proxy is NULL or has incorrect format.
 *
 * This is only required if your OS does not provide the http_proxy
 * enviroment variable (eg, OSX)
 *
 *   IMPORTANT! You should call this function right after creation of the
 *   libwebsocket_context and before call to connect. If you call this
 *   function after connect behavior is undefined.
 *   This function will override proxy settings made on libwebsocket_context
 *   creation with genenv() call.
 */

LWS_VISIBLE int
libwebsocket_set_proxy(struct libwebsocket_context *context, const char *proxy)
{
	char *p;
	
	if (!proxy)
		return -1;

	strncpy(context->http_proxy_address, proxy,
				sizeof(context->http_proxy_address) - 1);
	context->http_proxy_address[
				sizeof(context->http_proxy_address) - 1] = '\0';
	
	p = strchr(context->http_proxy_address, ':');
	if (!p) {
		lwsl_err("http_proxy needs to be ads:port\n");

		return -1;
	}
	*p = '\0';
	context->http_proxy_port = atoi(p + 1);
	
	lwsl_notice(" Proxy %s:%u\n", context->http_proxy_address,
						context->http_proxy_port);

	return 0;
}

/**
 * libwebsockets_get_protocol() - Returns a protocol pointer from a websocket
 *				  connection.
 * @wsi:	pointer to struct websocket you want to know the protocol of
 *
 *
 *	Some apis can act on all live connections of a given protocol,
 *	this is how you can get a pointer to the active protocol if needed.
 */

LWS_VISIBLE const struct libwebsocket_protocols *
libwebsockets_get_protocol(struct libwebsocket *wsi)
{
	return wsi->protocol;
}

LWS_VISIBLE int
libwebsocket_is_final_fragment(struct libwebsocket *wsi)
{
	return wsi->u.ws.final;
}

LWS_VISIBLE unsigned char
libwebsocket_get_reserved_bits(struct libwebsocket *wsi)
{
	return wsi->u.ws.rsv;
}

int
libwebsocket_ensure_user_space(struct libwebsocket *wsi)
{
	if (!wsi->protocol)
		return 1;

	/* allocate the per-connection user memory (if any) */

	if (wsi->protocol->per_session_data_size && !wsi->user_space) {
		wsi->user_space = malloc(
				  wsi->protocol->per_session_data_size);
		if (wsi->user_space  == NULL) {
			lwsl_err("Out of memory for conn user space\n");
			return 1;
		}
		memset(wsi->user_space, 0,
					 wsi->protocol->per_session_data_size);
	}
	return 0;
}

static void lwsl_emit_stderr(int level, const char *line)
{
	char buf[300];
	unsigned long long now;
	int n;

	buf[0] = '\0';
	for (n = 0; n < LLL_COUNT; n++)
		if (level == (1 << n)) {
			now = time_in_microseconds() / 100;
			sprintf(buf, "[%lu:%04d] %s: ", (unsigned long) now / 10000,
				(int)(now % 10000), log_level_names[n]);
			break;
		}

	fprintf(stderr, "%s%s", buf, line);
}


LWS_VISIBLE void _lws_log(int filter, const char *format, ...)
{
	char buf[256];
	va_list ap;

	if (!(log_level & filter))
		return;

	va_start(ap, format);
	vsnprintf(buf, sizeof(buf), format, ap);
	buf[sizeof(buf) - 1] = '\0';
	va_end(ap);

	lwsl_emit(filter, buf);
}

/**
 * lws_set_log_level() - Set the logging bitfield
 * @level:	OR together the LLL_ debug contexts you want output from
 * @log_emit_function:	NULL to leave it as it is, or a user-supplied
 *			function to perform log string emission instead of
 *			the default stderr one.
 *
 *	log level defaults to "err", "warn" and "notice" contexts enabled and
 *	emission on stderr.
 */

LWS_VISIBLE void lws_set_log_level(int level, void (*log_emit_function)(int level,
							      const char *line))
{
	log_level = level;
	if (log_emit_function)
		lwsl_emit = log_emit_function;
}

/* cast a struct sockaddr_in6 * into addr for ipv6 */

int
interface_to_sa(struct libwebsocket_context *context,
		const char *ifname, struct sockaddr_in *addr, size_t addrlen)
{
	int rc = -1;
#if defined(WIN32) || defined(_WIN32)
	/* TODO */
#else
	struct ifaddrs *ifr;
	struct ifaddrs *ifc;
#ifdef LWS_USE_IPV6
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
#endif

	getifaddrs(&ifr);
	for (ifc = ifr; ifc != NULL && rc; ifc = ifc->ifa_next) {
		if (!ifc->ifa_addr)
			continue;

		lwsl_info(" interface %s vs %s\n", ifc->ifa_name, ifname);

		if (strcmp(ifc->ifa_name, ifname))
			continue;

		switch (ifc->ifa_addr->sa_family) {
		case AF_INET:
#ifdef LWS_USE_IPV6
			if (LWS_IPV6_ENABLED(context)) {
				/* map IPv4 to IPv6 */
				bzero((char *)&addr6->sin6_addr,
						sizeof(struct in6_addr));
				addr6->sin6_addr.s6_addr[10] = 0xff;
				addr6->sin6_addr.s6_addr[11] = 0xff;
				memcpy(&addr6->sin6_addr.s6_addr[12],
					&((struct sockaddr_in *)ifc->ifa_addr)->sin_addr,
							sizeof(struct in_addr));
			} else
#endif
				memcpy(addr,
					(struct sockaddr_in *)ifc->ifa_addr,
						    sizeof(struct sockaddr_in));
			break;
#ifdef LWS_USE_IPV6
		case AF_INET6:
			if (rc >= 0)
				break;
			memcpy(&addr6->sin6_addr,
			  &((struct sockaddr_in6 *)ifc->ifa_addr)->sin6_addr,
						       sizeof(struct in6_addr));
			break;
#endif
		default:
			continue;
		}
		rc = 0;
	}

	freeifaddrs(ifr);
#endif
	return rc;
}

