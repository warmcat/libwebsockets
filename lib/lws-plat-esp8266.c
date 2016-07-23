#include "private-libwebsockets.h"

static struct lws_vhost *hacky_vhost;
static unsigned int time_high, ot;

/*
 * included from libwebsockets.c for esp8266 builds
 */

unsigned long long time_in_microseconds(void)
{
	unsigned int t = system_get_time();
	
	if (ot > t)
		time_high++;
	ot = t;
	
	return (((long long)time_high) << 32) | t;
}

int gettimeofday(struct timeval *tv, void *tz)
{
	unsigned long long t = time_in_microseconds();
	
	tv->tv_sec = t / 1000000;
	tv->tv_usec = t % 1000000;

	return 0;
}

time_t time(time_t *tloc)
{
	unsigned long long t = time_in_microseconds();

	if (tloc)
		*tloc = t / 1000000;

	return 0;
}

LWS_VISIBLE int
lws_get_random(struct lws_context *context, void *buf, int len)
{
//	return read(context->fd_random, (char *)buf, len);
	return 0;
}

LWS_VISIBLE int
lws_send_pipe_choked(struct lws *wsi)
{
	return wsi->pending_send_completion;
}

LWS_VISIBLE struct lws *
wsi_from_fd(const struct lws_context *context, lws_sockfd_type fd)
{
	return fd->reverse;
}

LWS_VISIBLE int
lws_ssl_capable_write_no_ssl(struct lws *wsi, unsigned char *buf, int len)
{
	//lwsl_notice("%s: wsi %p: len %d\n", __func__, wsi, len);	
	
	wsi->pending_send_completion++;
	espconn_send(wsi->sock, buf, len);
	
	return len;
}

void abort(void)
{
	while(1) ;
}

void exit(int n)
{
	abort();
}

void _sint(void *s)
{
}

LWS_VISIBLE int
insert_wsi(struct lws_context *context, struct lws *wsi)
{
	(void)context;
	(void)wsi;

	return 0;
}

LWS_VISIBLE int
delete_from_fd(struct lws_context *context, lws_sockfd_type fd)
{
	(void)context;
	(void)fd;

	return 1;
}

struct tm *localtime(const time_t *timep)
{
	return NULL;
}
struct tm *localtime_r(const time_t *timep, struct tm *t)
{
	return NULL;
}

int atoi(const char *s)
{
	int n = 0;

	while (*s && (*s >= '0' && *s <= '9'))
		n = (n * 10) + ((*s++) - '0');

	return n;
}

#undef isxdigit
int isxdigit(int c)
{
	if (c >= 'A' && c <= 'F')
		return 1;

	if (c >= 'a' && c <= 'f')
		return 1;

	if (c >= '0' && c <= '9')
		return 1;

	return 0;
}

int strcasecmp(const char *s1, const char *s2)
{
	char a, b;
	while (*s1 && *s2) {
		a = *s1++;
		b = *s2++;

		if (a == b)
			continue;

		if (a >= 'a' && a <= 'z')
			a -= 'a' - 'A';
		if (b >= 'a' && b <= 'z')
			b -= 'a' - 'A';

		if (a != b)
			return 1;
	}

	return 0;
}

LWS_VISIBLE int
lws_poll_listen_fd(struct lws_pollfd *fd)
{
#if 0
	return poll(fd, 1, 0);
#endif
	return 0;
}

LWS_VISIBLE void
lws_cancel_service_pt(struct lws *wsi)
{
#if 0
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	char buf = 0;

	if (write(pt->dummy_pipe_fds[1], &buf, sizeof(buf)) != 1)
		lwsl_err("Cannot write to dummy pipe");
#endif
}

LWS_VISIBLE void
lws_cancel_service(struct lws_context *context)
{
#if 0
	struct lws_context_per_thread *pt = &context->pt[0];
	char buf = 0, m = context->count_threads;

	while (m--) {
		if (write(pt->dummy_pipe_fds[1], &buf, sizeof(buf)) != 1)
			lwsl_err("Cannot write to dummy pipe");
		pt++;
	}
#endif
}

LWS_VISIBLE void lwsl_emit_syslog(int level, const char *line)
{
	extern void output_redirect(const char *str);
	output_redirect(line);
}

LWS_VISIBLE int
lws_plat_service_tsi(struct lws_context *context, int timeout_ms, int tsi)
{
#if 0
	struct lws_context_per_thread *pt = &context->pt[tsi];
	int n = -1, m, c;
	char buf;

	/* stay dead once we are dead */

	if (!context || !context->vhost_list)
		return 1;

	if (timeout_ms < 0)
		goto faked_service;

	lws_libev_run(context, tsi);
	lws_libuv_run(context, tsi);

	if (!context->service_tid_detected) {
		struct lws _lws;

		memset(&_lws, 0, sizeof(_lws));
		_lws.context = context;

		context->service_tid_detected =
			context->vhost_list->protocols[0].callback(
			&_lws, LWS_CALLBACK_GET_THREAD_ID, NULL, NULL, 0);
	}
	context->service_tid = context->service_tid_detected;

	timeout_ms = lws_service_adjust_timeout(context, timeout_ms, tsi);

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

faked_service:
	m = lws_service_flag_pending(context, tsi);
	if (m)
		c = -1; /* unknown limit */
	else
		if (n < 0) {
			if (LWS_ERRNO != LWS_EINTR)
				return -1;
			return 0;
		} else
			c = n;

	/* any socket with events to service? */
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
#endif
	return 0;
}

LWS_VISIBLE int
lws_plat_check_connection_error(struct lws *wsi)
{
	return 0;
}

LWS_VISIBLE int
lws_plat_service(struct lws_context *context, int timeout_ms)
{
//	return lws_plat_service_tsi(context, timeout_ms, 0);
	return 0;
}

static int
esp8266_find_free_conn(struct lws_context *context)
{
	int n;

	for (n = 0; n < context->max_fds; n++)
		if (!context->connpool[n]) {
			lwsl_info(" using connpool %d\n", n);
			return n;
		}
	
	lwsl_err("%s: no free conns\n", __func__);
	
	return -1;
}

lws_sockfd_type
esp8266_create_tcp_listen_socket(struct lws_vhost *vh)
{
	int n = esp8266_find_free_conn(vh->context);
	struct espconn *conn;
	
	if (n < 0)
		return NULL;
	
	conn = lws_zalloc(sizeof *conn);
	if (!conn)
		return NULL;
	
	vh->context->connpool[n] = conn;
	
	conn->type = ESPCONN_TCP;
	conn->state = ESPCONN_NONE;
	conn->proto.tcp = &vh->tcp;
	
	return conn;
}

LWS_VISIBLE int
lws_ssl_capable_read_no_ssl(struct lws *wsi, unsigned char *buf, int len)
{
	//lwsl_notice("%s\n", __func__);
	
	if (!wsi->context->rxd)
		return 0;

	if (len < wsi->context->rxd_len)
		lwsl_err("trunc read\n");
	else
		len = wsi->context->rxd_len;
	
	ets_memcpy(buf, wsi->context->rxd, len);
	
	wsi->context->rxd = NULL;
	
	return len;
}

static void
esp8266_cb_rx(void *arg, char *data, unsigned short len)
{
	struct espconn *conn = arg;
	struct lws *wsi = conn->reverse;
	struct lws_pollfd pollfd;

	//lwsl_err("%s: wsi %p. len %d\n", __func__, conn->reverse, len);

        pollfd.fd = arg;
        pollfd.events = LWS_POLLIN;
        pollfd.revents = LWS_POLLIN;
        
        wsi->context->rxd = data;
        wsi->context->rxd_len = len;

        lwsl_debug("%s: lws %p\n", __func__, wsi);

        lws_service_fd(lws_get_context(wsi), &pollfd);

}

static void
esp8266_cb_sent(void *arg)
{
	struct espconn *conn = arg;
	struct lws *wsi = conn->reverse;
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	
//	lwsl_err("%s: wsi %p (psc %d) wsi->position_in_fds_table=%d\n", __func__, wsi, wsi->pending_send_completion, wsi->position_in_fds_table);
	
	wsi->pending_send_completion--;
	if (wsi->close_is_pending_send_completion &&
	    !wsi->pending_send_completion &&
	    !lws_partial_buffered(wsi)) {
		lwsl_notice("doing delayed close\n");
		lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS);
	}
	
	if (pt->fds[wsi->position_in_fds_table].events & LWS_POLLOUT) {
		struct lws_pollfd pollfd;

	        pollfd.fd = arg;
	        pollfd.events = LWS_POLLOUT;
	        pollfd.revents = LWS_POLLOUT;

//	        lwsl_notice("informing POLLOUT\n");
	        
	        lws_service_fd(lws_get_context(wsi), &pollfd);
	}
}

static void
esp8266_cb_disconnected(void *arg)
{
	struct espconn *conn = arg;
	struct lws *wsi = conn->reverse;
	int n;

	lwsl_err("%s: %p\n", __func__, wsi);
	
	for (n = 0; n < hacky_vhost->context->max_fds; n++)
		if (hacky_vhost->context->connpool[n] == arg) {
			hacky_vhost->context->connpool[n] = NULL;
			lwsl_info(" freed connpool %d\n", n);
		}
	
	if (wsi) {
		conn->reverse = NULL;
		lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS);
	}
}

static void
esp8266_cb_recon(void *arg, signed char err)
{
	struct espconn *conn = arg;

	lwsl_err("%s: wsi %p. err %d\n", __func__, conn->reverse, err);

	conn->state = ESPCONN_CLOSE;		

	esp8266_cb_disconnected(arg);	
}

/*
 * there is no reliable indication of which listen socket we were accepted on.
 */

static void
esp8266_cb_connect(void *arg)
{
	struct espconn *cs = arg;
	struct lws *wsi;
	int n;

	lwsl_notice("%s: (wsi coming)\n", __func__);
	
	n = esp8266_find_free_conn(hacky_vhost->context);
	if (n < 0) {
		espconn_disconnect(cs);
		return;
	}
	
	hacky_vhost->context->connpool[n] = cs;
	
	wsi = lws_adopt_socket_vhost(hacky_vhost, cs);
	if (!wsi) {
		espconn_disconnect(cs);
		return;
	}
	
	lwsl_notice("%s: wsi %p\n", __func__, wsi);

	espconn_regist_recvcb(cs, esp8266_cb_rx);
	espconn_regist_reconcb(cs, esp8266_cb_recon);
	espconn_regist_disconcb(cs, esp8266_cb_disconnected);
	espconn_regist_sentcb(cs, esp8266_cb_sent);
	
	espconn_set_opt(cs, ESPCONN_NODELAY | ESPCONN_REUSEADDR);
	
	espconn_regist_time(cs, 7200, 1);
}

void
esp8266_tcp_stream_bind(lws_sockfd_type fd, int port, struct lws *wsi)
{
	fd->proto.tcp->local_port = port;
	fd->reverse = wsi;
	
	hacky_vhost = wsi->vhost;
	
	espconn_regist_connectcb(fd, esp8266_cb_connect);
	/* hmmm it means, listen() + accept() */
	espconn_accept(fd);

	espconn_tcp_set_max_con_allow(fd, 5);
}

void
esp8266_tcp_stream_accept(lws_sockfd_type fd, struct lws *wsi)
{
	fd->reverse = wsi;
}

LWS_VISIBLE int
lws_plat_set_socket_options(struct lws_vhost *vhost, lws_sockfd_type fd)
{
#if 0
	int optval = 1;
	socklen_t optlen = sizeof(optval);

#if defined(__APPLE__) || \
    defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || \
    defined(__NetBSD__) || \
    defined(__OpenBSD__)
	struct protoent *tcp_proto;
#endif

	if (vhost->ka_time) {
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
		optval = vhost->ka_time;
		if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,
			       (const void *)&optval, optlen) < 0)
			return 1;

		optval = vhost->ka_interval;
		if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL,
			       (const void *)&optval, optlen) < 0)
			return 1;

		optval = vhost->ka_probes;
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
#endif
	return 0;
}

LWS_VISIBLE void
lws_plat_drop_app_privileges(struct lws_context_creation_info *info)
{
}

LWS_VISIBLE int
lws_plat_context_early_init(void)
{
	espconn_tcp_set_max_con(12);

	return 0;
}

LWS_VISIBLE void
lws_plat_context_early_destroy(struct lws_context *context)
{
}

LWS_VISIBLE void
lws_plat_context_late_destroy(struct lws_context *context)
{
#if 0
	struct lws_context_per_thread *pt = &context->pt[0];
	int m = context->count_threads;

	if (context->lws_lookup)
		lws_free(context->lws_lookup);

	while (m--) {
		close(pt->dummy_pipe_fds[0]);
		close(pt->dummy_pipe_fds[1]);
		pt++;
	}
#endif
//	close(context->fd_random);
}

/* cast a struct sockaddr_in6 * into addr for ipv6 */

LWS_VISIBLE int
lws_interface_to_sa(int ipv6, const char *ifname, struct sockaddr_in *addr,
		    size_t addrlen)
{
	return 0;
}

LWS_VISIBLE void
lws_plat_insert_socket_into_fds(struct lws_context *context, struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];

	wsi->sock->reverse = wsi;
	pt->fds_count++;
}

LWS_VISIBLE void
lws_plat_delete_socket_from_fds(struct lws_context *context,
						struct lws *wsi, int m)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];	
	int n;
	
	for (n = 0; n < wsi->context->max_fds; n++)
		if (wsi->context->connpool[n] == wsi->sock) {
			wsi->context->connpool[n] = NULL;
			lwsl_notice(" freed connpool %d\n", n);
		}
	
	wsi->sock->reverse = NULL;
	pt->fds_count--;
}

LWS_VISIBLE void
lws_plat_service_periodic(struct lws_context *context)
{
#if 0
	/* if our parent went down, don't linger around */
	if (context->started_with_parent &&
	    kill(context->started_with_parent, 0) < 0)
		kill(getpid(), SIGTERM);
#endif
}

LWS_VISIBLE int
lws_plat_change_pollfd(struct lws_context *context,
		      struct lws *wsi, struct lws_pollfd *pfd)
{
//	lwsl_notice("%s: %p: wsi->pift=%d, events %d\n", __func__, wsi, wsi->position_in_fds_table, pfd->events);
	
	if (pfd->events & LWS_POLLIN)
		espconn_recv_unhold(wsi->sock);
	else
		espconn_recv_hold(wsi->sock);
	
	if (!(pfd->events & LWS_POLLOUT))
		return 0;
	
	if (!wsi->pending_send_completion) {
		pfd->revents |= LWS_POLLOUT;

//		lwsl_notice("doing POLLOUT\n");
		lws_service_fd(lws_get_context(wsi), pfd);
	} //else
		//lwsl_notice("pending sc\n");

	return 0;
}

LWS_VISIBLE const char *
lws_plat_inet_ntop(int af, const void *src, char *dst, int cnt)
{
//	return inet_ntop(af, src, dst, cnt);
	return 0;
}

LWS_VISIBLE int
lws_plat_init(struct lws_context *context,
	      struct lws_context_creation_info *info)
{
//	struct lws_context_per_thread *pt = &context->pt[0];
//	int n = context->count_threads, fd;

	/* master context has the global fd lookup array */
	context->connpool = lws_zalloc(sizeof(struct espconn *) *
					 context->max_fds);
	if (context->connpool == NULL) {
		lwsl_err("OOM on lws_lookup array for %d connections\n",
			 context->max_fds);
		return 1;
	}

	lwsl_notice(" mem: platform fd map: %5u bytes\n",
		    sizeof(struct espconn *) * context->max_fds);
//	fd = open(SYSTEM_RANDOM_FILEPATH, O_RDONLY);

//	context->fd_random = fd;
//	if (context->fd_random < 0) {
//		lwsl_err("Unable to open random device %s %d\n",
//			 SYSTEM_RANDOM_FILEPATH, context->fd_random);
//		return 1;
//	}

	if (!lws_libev_init_fd_table(context) &&
	    !lws_libuv_init_fd_table(context)) {
		/* otherwise libev handled it instead */
#if 0
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
#endif
	}


#ifdef LWS_WITH_PLUGINS
	if (info->plugin_dirs)
		lws_plat_plugins_init(context, info->plugin_dirs);
#endif

	return 0;
}
