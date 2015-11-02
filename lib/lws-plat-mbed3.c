#include "private-libwebsockets.h"

/*
 * included from libwebsockets.c for MBED3 builds
 * MBED3 is an "OS" for very small embedded systems.
 * He doesn't have Posix semantics or apis.
 * But he has things like TCP sockets.
 */

unsigned long long time_in_microseconds(void)
{
	return 0;
}

LWS_VISIBLE int libwebsockets_get_random(struct libwebsocket_context *context,
							     void *buf, int len)
{
	(void)context;
	int n = len;
	unsigned char *b = (unsigned char *)buf;
	while (n--)
		b[n]= rand();
	return len;
}

/*
 * MBED3 does not have a 'kernel' which takes copies of what userland wants
 * to send.  The user application must hold the tx buffer until it is informed
 * that send of the user buffer was complete.
 * 
 * So as soon as you send something the pipe is globally choked.
 * 
 * There is no concept of additional sent things being maybe acceptable.
 * You can send one thing up to 64KB at a time and may not try to send
 * anything else until that is completed.
 * 
 * You can send things on other sockets, but they cannot complete until they
 * get their turn at the network device.
 */

LWS_VISIBLE int lws_send_pipe_choked(struct libwebsocket *wsi)
{
#if 0
	struct libwebsocket_pollfd fds;

	/* treat the fact we got a truncated send pending as if we're choked */
	if (wsi->truncated_send_len)
		return 1;

	fds.fd = wsi->sock;
	fds.events = POLLOUT;
	fds.revents = 0;

	if (poll(&fds, 1, 0) != 1)
		return 1;

	if ((fds.revents & POLLOUT) == 0)
		return 1;

	/* okay to send another packet without blocking */
#endif
	(void)wsi;
	return 0;
}

LWS_VISIBLE int
lws_poll_listen_fd(struct libwebsocket_pollfd *fd)
{
	(void)fd;
	return -1;
}

/**
 * libwebsocket_cancel_service() - Cancel servicing of pending websocket activity
 * @context:	Websocket context
 *
 *	This function let a call to libwebsocket_service() waiting for a timeout
 *	immediately return.
 * 
 *	There is no poll() in MBED3, he will fire callbacks when he feels like
 *	it.
 */
LWS_VISIBLE void
libwebsocket_cancel_service(struct libwebsocket_context *context)
{
	(void)context;
}

LWS_VISIBLE void lwsl_emit_syslog(int level, const char *line)
{
	printf("%d: %s", level, line);
}

LWS_VISIBLE int
lws_plat_service(struct libwebsocket_context *context, int timeout_ms)
{
	(void)context;
	(void)timeout_ms;
#if 0
	int n;
	int m;
	char buf;
#ifdef LWS_OPENSSL_SUPPORT
	struct libwebsocket *wsi, *wsi_next;
#endif

	/* stay dead once we are dead */

	if (!context)
		return 1;

	lws_libev_run(context);

	context->service_tid = context->protocols[0].callback(context, NULL,
				     LWS_CALLBACK_GET_THREAD_ID, NULL, NULL, 0);

#ifdef LWS_OPENSSL_SUPPORT
	/* if we know we have non-network pending data, do not wait in poll */
	if (lws_ssl_anybody_has_buffered_read(context))
		timeout_ms = 0;
#endif
	n = poll(context->fds, context->fds_count, timeout_ms);
	context->service_tid = 0;

#ifdef LWS_OPENSSL_SUPPORT
	if (!lws_ssl_anybody_has_buffered_read(context) && n == 0) {
#else
	if (n == 0) /* poll timeout */ {
#endif
		libwebsocket_service_fd(context, NULL);
		return 0;
	}

	if (n < 0) {
		if (LWS_ERRNO != LWS_EINTR)
			return -1;
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
#endif
	return 0;
}

LWS_VISIBLE int
lws_plat_set_socket_options(struct libwebsocket_context *context, lws_sockfd_type fd)
{
	(void)context;
	(void)fd;
	return 0;
}

LWS_VISIBLE void
lws_plat_drop_app_privileges(struct lws_context_creation_info *info)
{
	(void)info;
}

LWS_VISIBLE int
lws_plat_init_lookup(struct libwebsocket_context *context)
{
	(void)context;
	return 0;
}

LWS_VISIBLE int
lws_plat_init_fd_tables(struct libwebsocket_context *context)
{
	(void)context;
	return 0;
}


LWS_VISIBLE int
lws_plat_context_early_init(void)
{
	return 0;
}

LWS_VISIBLE void
lws_plat_context_early_destroy(struct libwebsocket_context *context)
{
	(void)context;
}

LWS_VISIBLE void
lws_plat_context_late_destroy(struct libwebsocket_context *context)
{
	(void)context;
}


LWS_VISIBLE void
lws_plat_service_periodic(struct libwebsocket_context *context)
{
	(void)context;
}

LWS_VISIBLE int
lws_plat_change_pollfd(struct libwebsocket_context *context,
		      struct libwebsocket *wsi, struct libwebsocket_pollfd *pfd)
{
	(void)context;
	(void)wsi;
	(void)pfd;
	
	return 0;
}

LWS_VISIBLE int
lws_plat_open_file(const char* filename, unsigned long* filelen)
{
	(void)filename;
	(void)filelen;
	return LWS_INVALID_FILE;
}

LWS_VISIBLE const char *
lws_plat_inet_ntop(int af, const void *src, char *dst, int cnt)
{
	(void)af;
	(void)src;
	(void)dst;
	(void)cnt;
	return "unsupported";
}

LWS_VISIBLE int
insert_wsi(struct libwebsocket_context *context, struct libwebsocket *wsi)
{
	(void)context;
	(void)wsi;

	return 0;
}

LWS_VISIBLE int
delete_from_fd(struct libwebsocket_context *context, lws_sockfd_type fd)
{
	(void)context;
	(void)fd;

	return 1;
}