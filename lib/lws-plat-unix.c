#include "private-libwebsockets.h"

#include <pwd.h>
#include <grp.h>

/*
 * included from libwebsockets.c for unix builds
 */

unsigned long long time_in_microseconds(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((unsigned long long)tv.tv_sec * 1000000LL) + tv.tv_usec;
}

LWS_VISIBLE int
lws_get_random(struct lws_context *context, void *buf, int len)
{
	return read(context->fd_random, (char *)buf, len);
}

LWS_VISIBLE int
lws_send_pipe_choked(struct lws *wsi)
{
	struct lws_pollfd fds;

	/* treat the fact we got a truncated send pending as if we're choked */
	if (wsi->trunc_len)
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

LWS_VISIBLE int
lws_poll_listen_fd(struct lws_pollfd *fd)
{
	return poll(fd, 1, 0);
}

/*
 * This is just used to interrupt poll waiting
 * we don't have to do anything with it.
 */
static void
lws_sigusr2(int sig)
{
}

/**
 * lws_cancel_service_pt() - Cancel servicing of pending socket activity
 *				on one thread
 * @wsi:	Cancel service on the thread this wsi is serviced by
 *
 *	This function let a call to lws_service() waiting for a timeout
 *	immediately return.
 */
LWS_VISIBLE void
lws_cancel_service_pt(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	char buf = 0;

	if (write(pt->dummy_pipe_fds[1], &buf, sizeof(buf)) != 1)
		lwsl_err("Cannot write to dummy pipe");
}

/**
 * lws_cancel_service() - Cancel ALL servicing of pending socket activity
 * @context:	Websocket context
 *
 *	This function let a call to lws_service() waiting for a timeout
 *	immediately return.
 */
LWS_VISIBLE void
lws_cancel_service(struct lws_context *context)
{
	struct lws_context_per_thread *pt = &context->pt[0];
	char buf = 0, m = context->count_threads;

	while (m--) {
		if (write(pt->dummy_pipe_fds[1], &buf, sizeof(buf)) != 1)
			lwsl_err("Cannot write to dummy pipe");
		pt++;
	}
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

LWS_VISIBLE int
lws_plat_service_tsi(struct lws_context *context, int timeout_ms, int tsi)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct lws *wsi;
	int n, m, c;
	char buf;
#ifdef LWS_OPENSSL_SUPPORT
	struct lws *wsi_next;
#endif

	/* stay dead once we are dead */

	if (!context)
		return 1;

	lws_libev_run(context);

	if (!context->service_tid_detected) {
		struct lws _lws;

		memset(&_lws, 0, sizeof(_lws));
		_lws.context = context;

		context->service_tid_detected = context->protocols[0].callback(
			&_lws, LWS_CALLBACK_GET_THREAD_ID, NULL, NULL, 0);
	}
	context->service_tid = context->service_tid_detected;

	/* if we know we are draining rx ext, do not wait in poll */
	if (pt->rx_draining_ext_list)
		timeout_ms = 0;

#ifdef LWS_OPENSSL_SUPPORT
	/* if we know we have non-network pending data, do not wait in poll */
	if (lws_ssl_anybody_has_buffered_read_tsi(context, tsi)) {
		timeout_ms = 0;
		lwsl_err("ssl buffered read\n");
	}
#endif

	n = poll(pt->fds, pt->fds_count, timeout_ms);

#ifdef LWS_OPENSSL_SUPPORT
	if (!pt->rx_draining_ext_list &&
	    !lws_ssl_anybody_has_buffered_read_tsi(context, tsi) && !n) {
#else
	if (!pt->rx_draining_ext_list && !n) /* poll timeout */ {
#endif
		lws_service_fd_tsi(context, NULL, tsi);
		return 0;
	}

	if (n < 0) {
		if (LWS_ERRNO != LWS_EINTR)
			return -1;
		return 0;
	}

	/*
	 * For all guys with already-available ext data to drain, if they are
	 * not flowcontrolled, fake their POLLIN status
	 */
	wsi = pt->rx_draining_ext_list;
	while (wsi) {
		pt->fds[wsi->position_in_fds_table].revents |=
			pt->fds[wsi->position_in_fds_table].events & POLLIN;
		wsi = wsi->u.ws.rx_draining_ext_list;
	}

#ifdef LWS_OPENSSL_SUPPORT
	/*
	 * For all guys with buffered SSL read data already saved up, if they
	 * are not flowcontrolled, fake their POLLIN status so they'll get
	 * service to use up the buffered incoming data, even though their
	 * network socket may have nothing
	 */

	wsi = pt->pending_read_list;
	while (wsi) {
		wsi_next = wsi->pending_read_list_next;
		pt->fds[wsi->position_in_fds_table].revents |=
			pt->fds[wsi->position_in_fds_table].events & POLLIN;
		if (pt->fds[wsi->position_in_fds_table].revents & POLLIN)
			/*
			 * he's going to get serviced now, take him off the
			 * list of guys with buffered SSL.  If he still has some
			 * at the end of the service, he'll get put back on the
			 * list then.
			 */
			lws_ssl_remove_wsi_from_buffered_list(wsi);

		wsi = wsi_next;
	}
#endif

	/* any socket with events to service? */

	c = n;
	for (n = 0; n < pt->fds_count && c; n++) {
		if (!pt->fds[n].revents)
			continue;

		c--;

		if (pt->fds[n].fd == pt->dummy_pipe_fds[0]) {
			if (read(pt->fds[n].fd, &buf, 1) != 1)
				lwsl_err("Cannot read from dummy pipe.");
			continue;
		}

		m = lws_service_fd_tsi(context, &pt->fds[n], tsi);
		if (m < 0)
			return -1;
		/* if something closed, retry this slot */
		if (m)
			n--;
	}

	return 0;
}

LWS_VISIBLE int
lws_plat_service(struct lws_context *context, int timeout_ms)
{
	return lws_plat_service_tsi(context, timeout_ms, 0);
}

LWS_VISIBLE int
lws_plat_set_socket_options(struct lws_context *context, int fd)
{
	int optval = 1;
	socklen_t optlen = sizeof(optval);

#if defined(__APPLE__) || \
    defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || \
    defined(__NetBSD__) || \
    defined(__OpenBSD__)
	struct protoent *tcp_proto;
#endif

	if (context->ka_time) {
		/* enable keepalive on this socket */
		optval = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
			       (const void *)&optval, optlen) < 0)
			return 1;

#if defined(__APPLE__) || \
    defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || \
    defined(__NetBSD__) || \
        defined(__CYGWIN__) || defined(__OpenBSD__)

		/*
		 * didn't find a way to set these per-socket, need to
		 * tune kernel systemwide values
		 */
#else
		/* set the keepalive conditions we want on it too */
		optval = context->ka_time;
		if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,
			       (const void *)&optval, optlen) < 0)
			return 1;

		optval = context->ka_interval;
		if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL,
			       (const void *)&optval, optlen) < 0)
			return 1;

		optval = context->ka_probes;
		if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,
			       (const void *)&optval, optlen) < 0)
			return 1;
#endif
	}

	/* Disable Nagle */
	optval = 1;
#if !defined(__APPLE__) && \
    !defined(__FreeBSD__) && !defined(__FreeBSD_kernel__) && \
    !defined(__NetBSD__) && \
    !defined(__OpenBSD__)
	if (setsockopt(fd, SOL_TCP, TCP_NODELAY, (const void *)&optval, optlen) < 0)
		return 1;
#else
	tcp_proto = getprotobyname("TCP");
	if (setsockopt(fd, tcp_proto->p_proto, TCP_NODELAY, &optval, optlen) < 0)
		return 1;
#endif

	/* We are nonblocking... */
	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
		return 1;

	return 0;
}

LWS_VISIBLE void
lws_plat_drop_app_privileges(struct lws_context_creation_info *info)
{
	if (info->uid != -1) {
		struct passwd *p = getpwuid(info->uid);

		if (p) {
			initgroups(p->pw_name, info->gid);
			if (setuid(info->uid))
				lwsl_warn("setuid: %s\n", strerror(LWS_ERRNO));
			else
				lwsl_notice(" Set privs to user '%s'\n", p->pw_name);
		} else
			lwsl_warn("getpwuid: unable to find uid %d", info->uid);
	}
	if (info->gid != -1)
		if (setgid(info->gid))
			lwsl_warn("setgid: %s\n", strerror(LWS_ERRNO));

}

static void
sigpipe_handler(int x)
{
}

LWS_VISIBLE int
lws_plat_context_early_init(void)
{
	sigset_t mask;

	signal(SIGUSR2, lws_sigusr2);
	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR2);

	sigprocmask(SIG_BLOCK, &mask, NULL);

	signal(SIGPIPE, sigpipe_handler);

	return 0;
}

LWS_VISIBLE void
lws_plat_context_early_destroy(struct lws_context *context)
{
}

LWS_VISIBLE void
lws_plat_context_late_destroy(struct lws_context *context)
{
	struct lws_context_per_thread *pt = &context->pt[0];
	int m = context->count_threads;

	if (context->lws_lookup)
		lws_free(context->lws_lookup);

	while (m--) {
		close(pt->dummy_pipe_fds[0]);
		close(pt->dummy_pipe_fds[1]);
		pt++;
	}
	close(context->fd_random);
}

/* cast a struct sockaddr_in6 * into addr for ipv6 */

LWS_VISIBLE int
lws_interface_to_sa(int ipv6, const char *ifname, struct sockaddr_in *addr, size_t addrlen)
{
	int rc = -1;

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
			if (ipv6) {
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

	if (rc == -1) {
		/* check if bind to IP adddress */
#ifdef LWS_USE_IPV6
		if (inet_pton(AF_INET6, ifname, &addr6->sin6_addr) == 1)
			rc = 0;
		else
#endif
		if (inet_pton(AF_INET, ifname, &addr->sin_addr) == 1)
			rc = 0;
	}

	return rc;
}

LWS_VISIBLE void
lws_plat_insert_socket_into_fds(struct lws_context *context, struct lws *wsi)
{
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

	lws_libev_io(wsi, LWS_EV_START | LWS_EV_READ);
	pt->fds[pt->fds_count++].revents = 0;
}

LWS_VISIBLE void
lws_plat_delete_socket_from_fds(struct lws_context *context,
						struct lws *wsi, int m)
{
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	pt->fds_count--;
}

LWS_VISIBLE void
lws_plat_service_periodic(struct lws_context *context)
{
	/* if our parent went down, don't linger around */
	if (context->started_with_parent &&
	    kill(context->started_with_parent, 0) < 0)
		kill(getpid(), SIGTERM);
}

LWS_VISIBLE int
lws_plat_change_pollfd(struct lws_context *context,
		      struct lws *wsi, struct lws_pollfd *pfd)
{
	return 0;
}

LWS_VISIBLE const char *
lws_plat_inet_ntop(int af, const void *src, char *dst, int cnt)
{
	return inet_ntop(af, src, dst, cnt);
}

static lws_filefd_type
_lws_plat_file_open(struct lws *wsi, const char *filename,
		    unsigned long *filelen, int flags)
{
	struct stat stat_buf;
	int ret = open(filename, flags, 0664);

	if (ret < 0)
		return LWS_INVALID_FILE;

	if (fstat(ret, &stat_buf) < 0) {
		close(ret);
		return LWS_INVALID_FILE;
	}
	*filelen = stat_buf.st_size;
	return ret;
}

static int
_lws_plat_file_close(struct lws *wsi, lws_filefd_type fd)
{
	return close(fd);
}

unsigned long
_lws_plat_file_seek_cur(struct lws *wsi, lws_filefd_type fd, long offset)
{
	return lseek(fd, offset, SEEK_CUR);
}

static int
_lws_plat_file_read(struct lws *wsi, lws_filefd_type fd, unsigned long *amount,
		    unsigned char *buf, unsigned long len)
{
	long n;

	n = read((int)fd, buf, len);
	if (n == -1) {
		*amount = 0;
		return -1;
	}

	*amount = n;

	return 0;
}

static int
_lws_plat_file_write(struct lws *wsi, lws_filefd_type fd, unsigned long *amount,
		     unsigned char *buf, unsigned long len)
{
	long n;

	n = write((int)fd, buf, len);
	if (n == -1) {
		*amount = 0;
		return -1;
	}

	*amount = n;

	return 0;
}

LWS_VISIBLE int
lws_plat_init(struct lws_context *context,
	      struct lws_context_creation_info *info)
{
	struct lws_context_per_thread *pt = &context->pt[0];
	int n = context->count_threads, fd;

	/* master context has the global fd lookup array */
	context->lws_lookup = lws_zalloc(sizeof(struct lws *) *
					 context->max_fds);
	if (context->lws_lookup == NULL) {
		lwsl_err("OOM on lws_lookup array for %d connections\n",
			 context->max_fds);
		return 1;
	}

	lwsl_notice(" mem: platform fd map: %5u bytes\n",
		    sizeof(struct lws *) * context->max_fds);
	fd = open(SYSTEM_RANDOM_FILEPATH, O_RDONLY);

	context->fd_random = fd;
	if (context->fd_random < 0) {
		lwsl_err("Unable to open random device %s %d\n",
			 SYSTEM_RANDOM_FILEPATH, context->fd_random);
		return 1;
	}

	if (!lws_libev_init_fd_table(context)) {
		/* otherwise libev handled it instead */

		while (n--) {
			if (pipe(pt->dummy_pipe_fds)) {
				lwsl_err("Unable to create pipe\n");
				return 1;
			}

			/* use the read end of pipe as first item */
			pt->fds[0].fd = pt->dummy_pipe_fds[0];
			pt->fds[0].events = LWS_POLLIN;
			pt->fds[0].revents = 0;
			pt->fds_count = 1;
			pt++;
		}
	}

	context->fops.open	= _lws_plat_file_open;
	context->fops.close	= _lws_plat_file_close;
	context->fops.seek_cur	= _lws_plat_file_seek_cur;
	context->fops.read	= _lws_plat_file_read;
	context->fops.write	= _lws_plat_file_write;

	return 0;
}
