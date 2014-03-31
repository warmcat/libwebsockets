static unsigned long long
time_in_microseconds()
{
#define DELTA_EPOCH_IN_MICROSECS 11644473600000000ULL
	FILETIME filetime;
	ULARGE_INTEGER datetime;

#ifdef _WIN32_WCE
	GetCurrentFT(&filetime);
#else
	GetSystemTimeAsFileTime(&filetime);
#endif

	/*
	 * As per Windows documentation for FILETIME, copy the resulting FILETIME structure to a
	 * ULARGE_INTEGER structure using memcpy (using memcpy instead of direct assignment can
	 * prevent alignment faults on 64-bit Windows).
	 */
	memcpy(&datetime, &filetime, sizeof(datetime));

	/* Windows file times are in 100s of nanoseconds. */
	return (datetime.QuadPart - DELTA_EPOCH_IN_MICROSECS) / 10;
}

#ifdef _WIN32_WCE
static inline time_t time(time_t *t)
{
	time_t ret = time_in_microseconds() / 1000000;
	*t = ret;
	return ret;
}
#endif

LWS_VISIBLE int libwebsockets_get_random(struct libwebsocket_context *context,
							     void *buf, int len)
{
	int n;
	char *p = (char *)buf;

	for (n = 0; n < len; n++)
		p[n] = (unsigned char)rand();

	return n;
}

LWS_VISIBLE int lws_send_pipe_choked(struct libwebsocket *wsi)
{
	return wsi->sock_send_blocking;
}

static int lws_poll_listen_fd(struct libwebsocket_pollfd *fd)
{
	fd_set readfds;
	struct timeval tv = { 0, 0 };

	assert(fd->events == LWS_POLLIN);

	FD_ZERO(&readfds);
	FD_SET(fd->fd, &readfds);

	return select(fd->fd + 1, &readfds, NULL, NULL, &tv);
}

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
	WSASetEvent(context->events[0]);
}

LWS_VISIBLE void lwsl_emit_syslog(int level, const char *line)
{
	lwsl_emit_stderr(level, line);
}
