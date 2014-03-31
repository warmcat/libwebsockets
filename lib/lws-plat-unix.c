/*
 * included from libwebsockets.c for unix builds
 */

static unsigned long long time_in_microseconds(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000000) + tv.tv_usec;
}

LWS_VISIBLE int libwebsockets_get_random(struct libwebsocket_context *context,
							     void *buf, int len)
{
	return read(context->fd_random, (char *)buf, len);
}

LWS_VISIBLE int lws_send_pipe_choked(struct libwebsocket *wsi)
{
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

	return 0;
}

static int lws_poll_listen_fd(struct libwebsocket_pollfd *fd)
{
	return poll(fd, 1, 0);
}


#ifdef LWS_USE_LIBEV
LWS_VISIBLE void 
libwebsocket_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	struct libwebsocket_pollfd eventfd;
	struct lws_io_watcher *lws_io = (struct lws_io_watcher*)watcher;
	struct libwebsocket_context *context = lws_io->context;

	if (revents & EV_ERROR)
		return;

	eventfd.fd = watcher->fd;
	eventfd.revents = EV_NONE;
	if (revents & EV_READ)
		eventfd.revents |= LWS_POLLIN;

	if (revents & EV_WRITE)
		eventfd.revents |= LWS_POLLOUT;

	libwebsocket_service_fd(context,&eventfd);
}

LWS_VISIBLE void
libwebsocket_sigint_cb(
    struct ev_loop *loop, struct ev_signal* watcher, int revents)
{
    ev_break(loop, EVBREAK_ALL);
}

LWS_VISIBLE int
libwebsocket_initloop(
	struct libwebsocket_context *context,
	struct ev_loop *loop)
{
	int status = 0;
	int backend;
	const char * backend_name;
	struct ev_io *w_accept = (ev_io *)&context->w_accept;
	struct ev_signal *w_sigint = (ev_signal *)&context->w_sigint;

	if (!loop)
		loop = ev_default_loop(0);

	context->io_loop = loop;
   
	/*
	 * Initialize the accept w_accept with the listening socket
	 * and register a callback for read operations:
	 */
	ev_io_init(w_accept, libwebsocket_accept_cb,
					context->listen_service_fd, EV_READ);
	ev_io_start(context->io_loop,w_accept);
	ev_signal_init(w_sigint, libwebsocket_sigint_cb, SIGINT);
	ev_signal_start(context->io_loop,w_sigint);
	backend = ev_backend(loop);

	switch (backend) {
	case EVBACKEND_SELECT:
		backend_name = "select";
		break;
	case EVBACKEND_POLL:
		backend_name = "poll";
		break;
	case EVBACKEND_EPOLL:
		backend_name = "epoll";
		break;
	case EVBACKEND_KQUEUE:
		backend_name = "kqueue";
		break;
	case EVBACKEND_DEVPOLL:
		backend_name = "/dev/poll";
		break;
	case EVBACKEND_PORT:
		backend_name = "Solaris 10 \"port\"";
		break;
	default:
		backend_name = "Unknown libev backend";
		break;
	};

	lwsl_notice(" libev backend: %s\n", backend_name);

	return status;
}

#endif /* LWS_USE_LIBEV */

/**
 * libwebsocket_cancel_service() - Cancel servicing of pending websocket activity
 * @context:	Websocket context
 *
 *	This function let a call to libwebsocket_service() waiting for a timeout
 *	immediately return.
 */
LWS_VISIBLE void
libwebsocket_cancel_service(struct libwebsocket_context *context)
{
	char buf = 0;

	if (write(context->dummy_pipe_fds[1], &buf, sizeof(buf)) != 1)
		lwsl_err("Cannot write to dummy pipe");
}

LWS_VISIBLE void lwsl_emit_syslog(int level, const char *line)
{
	int syslog_level = LOG_DEBUG;

	switch (level) {
	case LLL_ERR:
		syslog_level = LOG_ERR;
		break;
	case LLL_WARN:
		syslog_level = LOG_WARNING;
		break;
	case LLL_NOTICE:
		syslog_level = LOG_NOTICE;
		break;
	case LLL_INFO:
		syslog_level = LOG_INFO;
		break;
	}
	syslog(syslog_level, "%s", line);
}